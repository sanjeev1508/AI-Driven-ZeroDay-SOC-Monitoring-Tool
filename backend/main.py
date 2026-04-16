"""
SOC Backend — FastAPI Server

Provides REST + SSE endpoints for:
  - Local log collection pipeline  (Agent 1 + Agent 4)
  - Threat intel pipeline trigger  (Agent 2 → 3)
  - Alerts CRUD                    (alerts.json)
  - Agent status reporting
  - Threat intel news + similarity search (Qdrant)

Serves frontend static files mounted at /static; root / returns index.html.
"""

import asyncio
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.parent          # d:\AI SOC\new
FRONTEND_DIR = BASE_DIR / "frontend"
ALERTS_FILE = BASE_DIR / "alerts.json"
FILTERED_CSV = BASE_DIR / "filtered_logs.csv"
RAW_CSV = BASE_DIR / "raw_logs.csv"

# Add parent to sys.path so agent imports work
sys.path.insert(0, str(BASE_DIR))

# ── App Setup ─────────────────────────────────────────────────────────────────
app = FastAPI(title="AI SOC API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount frontend static files
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

# ── Global State ──────────────────────────────────────────────────────────────
class AgentState:
    def __init__(self):
        self.agent1_proc: Optional[subprocess.Popen] = None
        self.agent4_thread: Optional[threading.Thread] = None
        self.agent4_running: bool = False

        # Fan-out queues for SSE clients (logs + alerts share one queue per client)
        self.local_log_queues: List[asyncio.Queue] = []
        self.local_alert_queues: List[asyncio.Queue] = []


state = AgentState()


# ── Pydantic Models ───────────────────────────────────────────────────────────
class AnalysisRequest(BaseModel):
    timeframe_hours: int = 5


# ── Helpers ───────────────────────────────────────────────────────────────────
def load_alerts() -> List[Dict]:
    if ALERTS_FILE.exists():
        try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


async def broadcast_to_queues(queues: List[asyncio.Queue], event: Dict):
    """Fan-out an event to all connected SSE clients."""
    dead = []
    for q in queues:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        try:
            queues.remove(q)
        except ValueError:
            pass


async def sse_event_stream(queue: asyncio.Queue) -> AsyncGenerator[str, None]:
    """Convert queue events to SSE-formatted strings."""
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
                if event is None:          # sentinel — close stream
                    break
                yield f"data: {json.dumps(event)}\n\n"
            except asyncio.TimeoutError:
                # Keep-alive ping
                yield f": ping\n\n"
    except asyncio.CancelledError:
        pass


# ── Background: Watch normalized_logs.csv and push rows to SSE queues ────────
def _tail_csv_for_sse(stop_event: threading.Event, main_loop: asyncio.AbstractEventLoop):
    """
    Background thread: tails filtered_logs.csv and pushes new rows
    to all connected SSE clients via the event loop.
    """
    file_pos = 0
    headers = None

    while not FILTERED_CSV.exists():
        if stop_event.is_set():
            return
        time.sleep(1)

    import csv, io as _io
    with open(FILTERED_CSV, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        headers = reader.fieldnames
        f.seek(0, 2)
        file_pos = f.tell()

    while not stop_event.is_set():
        try:
            with open(FILTERED_CSV, "r", encoding="utf-8", newline="") as f:
                if headers is None:
                    reader = csv.DictReader(f)
                    headers = reader.fieldnames
                    f.seek(0, 2)
                    file_pos = f.tell()
                    continue
                f.seek(file_pos)
                
                while True:
                    line = f.readline()
                    if not line:
                        break
                    if not line.endswith("\n") and not line.endswith("\r"):
                        # Incomplete line written, revert position and wait
                        f.seek(file_pos)
                        break
                    
                    file_pos = f.tell()
                    
                    if line.strip():
                        reader = csv.DictReader(_io.StringIO(line), fieldnames=headers)
                        for row in reader:
                            if row.get("timestamp") == "timestamp":
                                continue
                            event = {
                                "type": "log",
                                "data": dict(row),
                                "timestamp": row.get("timestamp", datetime.now().isoformat()),
                            }
                            # Schedule broadcast on the main event loop
                            future = asyncio.run_coroutine_threadsafe(
                                broadcast_to_queues(state.local_log_queues, event),
                                main_loop,
                            )
                            try:
                                future.result(timeout=2)
                            except Exception:
                                pass
        except Exception:
            pass
        time.sleep(1)


# ── Background: Watch alerts.json and push new alerts to queues ───────────────
_last_alert_count = 0


def _tail_alerts_for_sse(stop_event: threading.Event, main_loop: asyncio.AbstractEventLoop):
    global _last_alert_count
    while not stop_event.is_set():
        try:
            alerts = load_alerts()
            # If alerts were cleared/truncated, reset cursor so new alerts can stream again.
            if len(alerts) < _last_alert_count:
                _last_alert_count = 0
            if len(alerts) > _last_alert_count:
                new_alerts = alerts[_last_alert_count:]
                _last_alert_count = len(alerts)
                for alert in new_alerts:
                    event = {
                        "type": "alert",
                        "data": alert,
                        "timestamp": alert.get("timestamp", datetime.now().isoformat()),
                    }
                    future = asyncio.run_coroutine_threadsafe(
                        broadcast_to_queues(state.local_alert_queues, event),
                        main_loop,
                    )
                    try:
                        future.result(timeout=2)
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(2)


# ── Startup / Shutdown ────────────────────────────────────────────────────────
_stop_tail = threading.Event()
_stop_alert_tail = threading.Event()

def _start_agent4_if_needed(main_loop: asyncio.AbstractEventLoop) -> bool:
    """Start Agent 4 in a background thread if not already running."""
    if state.agent4_running:
        return False

    def _run_agent4():
        state.agent4_running = True
        try:
            from agent4_pattern_detector import PatternDetectorAgent

            def on_detection(detection):
                event = {
                    "type": "alert",
                    "data": detection,
                    "timestamp": detection.get("timestamp", datetime.now().isoformat()),
                }
                asyncio.run_coroutine_threadsafe(
                    broadcast_to_queues(state.local_alert_queues, event),
                    main_loop,
                )

            detector = PatternDetectorAgent()
            detector.run(poll_interval=2.0, on_detection=on_detection)
        except Exception as e:
            print(f"Agent 4 error: {e}")
        finally:
            state.agent4_running = False

    t = threading.Thread(target=_run_agent4, daemon=True, name="Agent4")
    t.start()
    state.agent4_thread = t
    return True


@app.on_event("startup")
async def on_startup():
    main_loop = asyncio.get_running_loop()
    t1 = threading.Thread(target=_tail_csv_for_sse, args=(_stop_tail, main_loop), daemon=True, name="csv-tailer")
    t1.start()
    t2 = threading.Thread(target=_tail_alerts_for_sse, args=(_stop_alert_tail, main_loop), daemon=True, name="alert-tailer")
    t2.start()
    # Ensure injected/mock CSV rows generate alerts even if the UI pipeline wasn't started.
    _start_agent4_if_needed(main_loop)


@app.on_event("shutdown")
async def on_shutdown():
    _stop_tail.set()
    _stop_alert_tail.set()
    if state.agent1_proc and state.agent1_proc.poll() is None:
        state.agent1_proc.terminate()


# ── Frontend ──────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def serve_root():
    index = FRONTEND_DIR / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>SOC Backend Running</h1><p>Frontend not found at /frontend/index.html</p>")


# ── Agent Status ──────────────────────────────────────────────────────────────
@app.get("/api/agents/status")
async def agents_status():
    alerts = load_alerts()
    return {
        "agent1": {
            "name": "Log Collector",
            "status": "running" if (state.agent1_proc and state.agent1_proc.poll() is None) else "stopped",
            "description": "Collects Windows Event Logs → CSV",
        },
        "agent2": {
            "name": "Threat Intel",
            "status": "manual",
            "description": "Scrapes threat intel → Qdrant (run manually)",
        },
        "agent3": {
            "name": "Synthetic Generator",
            "status": "manual",
            "description": "Generates synthetic log patterns → Qdrant (run manually)",
        },
        "agent4": {
            "name": "Pattern Detector",
            "status": "running" if state.agent4_running else "stopped",
            "description": "Reads CSV, detects zero-day patterns → alerts.json",
        },
        "alerts_count": len(alerts),
        "csv_exists": FILTERED_CSV.exists(),
        "alerts_file_exists": ALERTS_FILE.exists(),
    }


# ── Alerts ────────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
async def get_alerts(limit: int = 100, severity: Optional[str] = None):
    alerts = load_alerts()
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").upper() == severity.upper()]
    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return {"alerts": alerts[:limit], "total": len(alerts)}


@app.delete("/api/alerts")
async def clear_alerts():
    """Clear all alerts."""
    with open(ALERTS_FILE, "w") as f:
        json.dump([], f)
    return {"status": "cleared"}


# ── Local Analysis Pipeline ───────────────────────────────────────────────────
@app.post("/api/analyze/local")
async def start_local_analysis(req: AnalysisRequest, background_tasks: BackgroundTasks):
    """Start Agent 1 (log collection) and Agent 4 (pattern detection)."""
    main_loop = asyncio.get_running_loop()
    results = {"agent1": "skipped", "agent4": "skipped"}

    # Start Agent 1 if not running
    if state.agent1_proc is None or state.agent1_proc.poll() is not None:
        try:
            state.agent1_proc = subprocess.Popen(
                [sys.executable, str(BASE_DIR / "agent1_log_collector.py")],
                cwd=str(BASE_DIR),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            results["agent1"] = "started"
        except Exception as e:
            results["agent1"] = f"error: {e}"

    # Start Agent 4 in a background thread if not already running
    if _start_agent4_if_needed(main_loop):
        results["agent4"] = "started"

    return {"status": "pipeline_started", "agents": results}


@app.post("/api/analyze/stop")
async def stop_local_analysis():
    """Stop Agent 1."""
    if state.agent1_proc and state.agent1_proc.poll() is None:
        state.agent1_proc.terminate()
        return {"status": "Agent 1 stopped"}
    return {"status": "Agent 1 was not running"}


@app.get("/api/logs/recent")
async def get_recent_logs(limit: int = 50):
    """Fetch the latest N logs for immediate UI display."""
    if not FILTERED_CSV.exists():
        return {"logs": []}
    
    logs = []
    try:
        import csv
        with open(FILTERED_CSV, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
            # Get last N rows
            rows = reader[-limit:] if reader else []
            for row in rows:
                if row.get("timestamp") == "timestamp":
                    continue
                logs.append({
                    "type": "log",
                    "data": dict(row),
                    "timestamp": row.get("timestamp", datetime.now().isoformat()),
                })
        return {"logs": logs}
    except Exception as e:
        return {"logs": [], "error": str(e)}


# ── Local SSE Stream ──────────────────────────────────────────────────────────
@app.get("/api/stream/local")
async def stream_local():
    """
    Server-Sent Events stream of local log entries and alerts.
    Events:  { type: 'log'|'alert'|'status', data: {...}, timestamp: '...' }
    """
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    state.local_log_queues.append(queue)
    state.local_alert_queues.append(queue)

    async def cleanup_and_stream():
        try:
            yield f"data: {json.dumps({'type': 'status', 'data': {'message': 'Connected to local stream'}})}\n\n"
            async for chunk in sse_event_stream(queue):
                yield chunk
        finally:
            try:
                state.local_log_queues.remove(queue)
            except ValueError:
                pass
            try:
                state.local_alert_queues.remove(queue)
            except ValueError:
                pass

    return StreamingResponse(
        cleanup_and_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Run Threat Intel Pipeline (Agent 2 → 3) ───────────────────────────────────
@app.post("/api/pipeline/threat-intel")
async def run_threat_intel():
    """Run Agent 2 (scrape) then Agent 3 (synthetic gen) as background processes."""
    try:
        subprocess.Popen(
            [sys.executable, str(BASE_DIR / "agent2_threat_intel.py")],
            cwd=str(BASE_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return {"status": "started", "message": "Agent 2 → 3 pipeline started (check Qdrant for results)"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class CompareRequest(BaseModel):
    query: str

@app.get("/api/threat-intel/news")
async def get_threat_intel_news(limit: int = 50):
    """Fetch latest threat intelligence from Qdrant."""
    try:
        from qdrant_client import QdrantClient
        client = QdrantClient(url="http://localhost:6333")
        collection_name = "zero-day-intel"
        scroll_result = client.scroll(
            collection_name=collection_name,
            limit=limit,
            with_payload=True,
            with_vectors=False
        )
        points = scroll_result[0] if isinstance(scroll_result, tuple) else scroll_result
        news = [p.payload for p in points if hasattr(p, 'payload') and p.payload]
        news.sort(key=lambda x: x.get('published', x.get('timestamp', '')), reverse=True)
        return {"news": news}
    except Exception as e:
        return {"news": [], "error": str(e)}

@app.post("/api/threat-intel/compare")
async def compare_threat_intel(req: CompareRequest):
    """Compare an alert or log against stored Qdrant threat intel."""
    try:
        from agent2_threat_intel import ThreatIntelAgent
        agent = ThreatIntelAgent()
        matches = agent.search_similar_threats(req.query, n_results=5)
        # Format for frontend 
        formatted_matches = []
        for m in matches:
            threat = m.get('threat_data', {})
            formatted_matches.append({
                "score": round(m.get('score', 0) * 100, 1),
                "source": threat.get('source', 'Unknown'),
                "title": threat.get('title', 'Unknown Threat'),
                "cve": threat.get('cve', ''),
            })
        return {"matches": formatted_matches}
    except Exception as e:
        return {"matches": [], "error": str(e)}


# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
