# AI-Driven Zero-Day SOC Monitoring Tool

An AI-powered Security Operations Center (SOC) that collects Windows Event Logs in real time, matches them against scraped zero-day threat intelligence, and surfaces confirmed detections through a live web dashboard.  
The pipeline is Kafka-free — all inter-agent communication uses CSV files and a Qdrant vector database.

---

## System Architecture

```
Windows Event Logs
       │
       ▼  Agent 1 (every 5s)
 raw_logs.csv  ──►  filtered_logs.csv
                           │
                           ▼  Agent 4 (continuous tail)
              ┌────────────────────────────┐
              │   Three-layer detection    │
              │  1. Heuristic scoring      │
              │  2. Qdrant vector search ◄─┼── Agent 2 (zero-day-intel)
              │  3. LLM reasoning          │   Agent 3 (synthetic-logs)
              └────────────┬───────────────┘
                           │
                           ▼
                      alerts.json
                           │
                           ▼
              FastAPI backend (port 8001)
                           │
                           ▼
              Browser dashboard (/static/index.html)
```

---

## Agent Overview

| Agent | File | Trigger | Input | Output |
|---|---|---|---|---|
| **Agent 1 — Log Collector** | `agent1_log_collector.py` | Auto-started by backend or `main.py` | Windows Event Log API (`pywin32`) | `raw_logs.csv`, `filtered_logs.csv` |
| **Agent 2 — Threat Intel** | `agent2_threat_intel.py` | Manual (UI button or direct run) | SOCRadar, ISC SANS, ZDI, HackerNews via Selenium | Qdrant `zero-day-intel` collection |
| **Agent 3 — Synthetic Gen** | `agent3_synthetic_gen.py` | Chained from Agent 2 | Qdrant `zero-day-intel` | Qdrant `synthetic-logs` collection |
| **Agent 4 — Pattern Detector** | `agent4_pattern_detector.py` | Auto-started by backend on startup | `filtered_logs.csv` (tail) | `alerts.json` |

**Other files:**

| File | Purpose |
|---|---|
| `backend/main.py` | FastAPI server — serves frontend, exposes REST + SSE API |
| `main.py` | Alternative standalone orchestrator — spawns Agent 1 & 4 as OS processes |
| `add_mock_logs.py` | Dev utility — injects a guaranteed-alert test row into `filtered_logs.csv` |
| `requirements.txt` | Python dependencies |
| `.env` | Runtime configuration (Qdrant URL, Ollama settings, etc.) |

---

## Prerequisites

| Dependency | Purpose | Default |
|---|---|---|
| **Python 3.9+** | Runtime | — |
| **Windows OS** | Agent 1 requires `win32evtlog` for Event Log access | — |
| **Qdrant** | Vector store for threat intel and synthetic patterns | `localhost:6333` |
| **Ollama** | Local LLM inference + embeddings (Agent 2, 3, optional Agent 4) | `localhost:11434` |
| **Google Chrome** | Headless Selenium scraping in Agent 2 | — |

> Kafka is **not required**. The pipeline uses CSV files for Agent 1 → 4 transport.

---

## Setup

### 1. Create and activate a virtual environment

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

> If blocked by execution policy: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### 2. Install dependencies

```powershell
pip install -r requirements.txt
```

### 3. Pull Ollama models

```powershell
ollama pull nomic-embed-text:latest   # required for Agent 2 embeddings
ollama pull llama3.1:latest           # optional — only if ENABLE_OLLAMA_LLM=1
```

### 4. Start Qdrant

```powershell
docker run -p 6333:6333 -p 6334:6334 qdrant/qdrant
```

---

## Quick Start

### Terminal 1 — Start the backend (serves UI + API)

> Run as **Administrator** so Agent 1 can access the Security event log.

```powershell
venv\Scripts\python.exe -m uvicorn backend.main:app --host 0.0.0.0 --port 8001
```

- Dashboard: [http://localhost:8001](http://localhost:8001)  
- API docs: [http://localhost:8001/docs](http://localhost:8001/docs)

The backend **automatically starts Agent 1 and Agent 4** when you click **"Start Analysis"** in the dashboard.

### [Optional] Run the full threat intel pipeline

Either click **"Run Threat Update"** in the dashboard, or directly:

```powershell
venv\Scripts\python.exe agent2_threat_intel.py
```

This runs Agent 2 (scrape → Qdrant) then chains into Agent 3 (synthetic patterns → Qdrant).

### [Optional] Inject a test alert (dev)

```powershell
venv\Scripts\python.exe add_mock_logs.py
```

Appends a synthetic high-confidence row to `filtered_logs.csv`; Agent 4 will detect it within ~2 seconds.

---

## Dashboard Features

The HTML/JS dashboard at `http://localhost:8001` provides:

| Panel | Description |
|---|---|
| **Live Log Stream** | SSE-powered real-time feed of `filtered_logs.csv` entries. Shows timestamp, Event ID, log type, and description. Supports pause and clear. |
| **Security Alerts** | All detections from `alerts.json`, sorted newest-first. Filterable by severity (CRITICAL / HIGH / MEDIUM / LOW). Click any alert to expand reasoning and raw log JSON. |
| **Threat Intel Feed** | Latest threat items from the Qdrant `zero-day-intel` collection with source, CVE, severity, and summary. |
| **Agent Status** | Live status cards for all four agents, polled every 8 seconds. |

**Sidebar controls:**

| Button | Action |
|---|---|
| **Start Analysis** | Starts Agent 1 (log collection) if not running; ensures Agent 4 is tailing |
| **Stop** | Terminates Agent 1 process |
| **Run Threat Update** | Triggers `POST /api/pipeline/threat-intel` → Agent 2 → 3 |
| **Clear Alerts** | Deletes all entries from `alerts.json` |

---

## Configuration

All settings are read from `.env` (or the environment). The defaults work for a local development setup.

| Variable | Default | Used By |
|---|---|---|
| `QDRANT_URL` | `http://localhost:6333` | Agent 2, 3, 4 |
| `OLLAMA_API_URL` | `http://localhost:11434` | Agent 2, 3 |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text:latest` | Agent 2, 3 |
| `OLLAMA_GEN_MODEL` | `llama3.1:latest` | Agent 2 (severity estimation) |
| `LOCAL_LLM_MODEL` | `llama3.1:latest` | Agent 4 (Ollama fallback) |
| `ENABLE_OLLAMA_LLM` | `0` | Agent 4 — set to `1` to enable LLM analysis (slower) |
| `OPENAI_API_KEY` | *(unset)* | Agent 4 — LangChain/OpenAI path (optional) |

---

## Detection Pipeline (Agent 4)

Each row read from `filtered_logs.csv` passes through three layers:

1. **Heuristic scoring** — Behavioural feature weights extracted by Agent 1:

   | Feature | Weight |
   |---|---|
   | Privilege escalation (EID 4672) | 0.30 |
   | Suspicious process (EID 4688 + known LOLBin) | 0.25 |
   | Service installation (EID 4697) | 0.20 |
   | Scheduled task creation (EID 4698/4700/4702) | 0.15 |
   | Driver load (EID 6 / System log) | 0.10 |

2. **Vector similarity** — Qdrant cosine search over `zero-day-intel` embeddings (top-3 matches).

3. **LLM reasoning** — Skipped if heuristic score ≥ 0.7 (for responsiveness). Otherwise calls OpenAI (if `OPENAI_API_KEY` set) or Ollama (if `ENABLE_OLLAMA_LLM=1`).

**Final decision:** detection fires when `(llm_match OR heuristic > 0.6 OR synthetic_overlap > 0.35)` AND combined confidence > 0.5.

**Severity mapping:**

| Combined confidence | Severity |
|---|---|
| ≥ 0.80 | CRITICAL |
| ≥ 0.65 | HIGH |
| ≥ 0.50 | MEDIUM |
| < 0.50 | LOW |

---

## Data Flow (File Map)

```
Agent 1  →  raw_logs.csv          (all parsed events, unfiltered)
         →  filtered_logs.csv     (security-relevant events only, tailed by Agent 4)

Agent 2  →  Qdrant: zero-day-intel   (scraped + embedded threat articles)
Agent 3  →  Qdrant: synthetic-logs   (synthetic Windows event patterns)

Agent 4  →  alerts.json              (confirmed detections, appended atomically)

Backend  →  /api/stream/local        (SSE — tails filtered_logs.csv + alerts.json)
         →  /api/alerts              (REST GET/DELETE)
         →  /api/agents/status       (REST GET)
         →  /api/threat-intel/news   (REST GET — reads Qdrant)
```

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serve `frontend/index.html` |
| `GET` | `/api/agents/status` | Agent running state + alert counts |
| `GET` | `/api/alerts` | List alerts (optional `?severity=CRITICAL`) |
| `DELETE` | `/api/alerts` | Clear all alerts |
| `GET` | `/api/logs/recent` | Last N rows from `filtered_logs.csv` |
| `GET` | `/api/stream/local` | SSE stream of logs + alerts |
| `POST` | `/api/analyze/local` | Start Agent 1; ensure Agent 4 is running |
| `POST` | `/api/analyze/stop` | Terminate Agent 1 |
| `POST` | `/api/pipeline/threat-intel` | Run Agent 2 → 3 pipeline |
| `GET` | `/api/threat-intel/news` | Recent items from Qdrant `zero-day-intel` |
| `POST` | `/api/threat-intel/compare` | Semantic similarity search against Qdrant |

---

## Troubleshooting

**Agent 1 — "Access denied" or no logs collected**  
Run the terminal as **Administrator**. The Security event log requires elevated access.

**Qdrant — connection refused**  
Confirm Docker container is up: `docker ps`. Health check: `http://localhost:6333/healthz`.

**Agent 2 — Selenium / ChromeDriver error**  
Ensure Google Chrome is installed. Selenium 4 auto-downloads a matching ChromeDriver via `webdriver-manager` — make sure you have internet access on first run.

**Ollama — model not found**  
Run `ollama list` to see installed models. Pull missing ones with `ollama pull <model>`.

**No alerts appearing**  
1. Confirm `filtered_logs.csv` is being written (Agent 1 must be running).  
2. Inject a test log: `python add_mock_logs.py` — an alert should appear within ~2 s.  
3. Check Agent 4 logs in the backend terminal output.

**LLM analysis not running**  
Agent 4 skips LLM by default (`ENABLE_OLLAMA_LLM=0`). Set it to `1` in `.env` and restart the backend, or set `OPENAI_API_KEY` for the OpenAI path.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | FastAPI + Uvicorn |
| Frontend | Vanilla HTML / CSS / JavaScript (SSE) |
| Vector database | Qdrant |
| Embeddings | Ollama `nomic-embed-text` |
| LLM (optional) | Ollama `llama3.1` / OpenAI via LangChain |
| Web scraping | Selenium 4 + headless Chrome |
| Windows Event Logs | `pywin32` (`win32evtlog`) |
| Log transport | CSV files (no Kafka) |

---

## License

For research and educational use in the field of AI-driven cybersecurity operations.