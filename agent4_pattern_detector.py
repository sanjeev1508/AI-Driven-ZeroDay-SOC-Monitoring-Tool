"""
Agent 4 - Zero-Day Pattern Detector

Tails filtered_logs.csv (written by Agent 1) for new entries and detects
zero-day patterns using a three-layer approach:

  1. Heuristic scoring  — fast, rule-based behavioral feature weights.
  2. Vector similarity  — Qdrant search over Agent 2's threat-intel embeddings.
  3. LLM reasoning      — OpenAI (via LangChain) or Ollama fallback.
                          Set ENABLE_OLLAMA_LLM=1 to enable Ollama.
                          Set OPENAI_API_KEY to use OpenAI.

Writes confirmed detections to alerts.json.
Auto-started by the FastAPI backend (backend/main.py) on startup.
"""

import csv
import io
import json
import os
import re
import subprocess
import time
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).parent

# ── Optional LangChain ───────────────────────────────────────────────────────
LANGCHAIN_AVAILABLE = False
LANGCHAIN_NEW_API = False
try:
    try:
        from langchain_openai import ChatOpenAI
        from langchain.prompts import ChatPromptTemplate
        from langchain.chains import LLMChain
        LANGCHAIN_AVAILABLE = True
        LANGCHAIN_NEW_API = True
    except ImportError:
        try:
            from langchain.llms import OpenAI
            from langchain.prompts import PromptTemplate
            from langchain.chains import LLMChain
            LANGCHAIN_AVAILABLE = True
            LANGCHAIN_NEW_API = False
        except ImportError:
            pass
except Exception as e:
    logger.warning(f"LangChain import error: {e}. Will use Ollama fallback.")

if not LANGCHAIN_AVAILABLE:
    logger.warning("LangChain not available. LLM detection will use Ollama fallback.")


# ── Main Agent ───────────────────────────────────────────────────────────────
class PatternDetectorAgent:
    """Detects zero-day patterns by tailing normalized_logs.csv."""

    def __init__(
        self,
        filtered_csv_path: Optional[str] = None,
        alerts_json_path: Optional[str] = None,
    ):
        self.filtered_csv_path = (
            Path(filtered_csv_path) if filtered_csv_path
            else BASE_DIR / "filtered_logs.csv"
        )
        self.alerts_json_path = (
            Path(alerts_json_path) if alerts_json_path
            else BASE_DIR / "alerts.json"
        )

        # File-tail state
        self._file_pos: int = 0
        self._csv_headers: Optional[List[str]] = None

        # Threat intel vector agent (Agent 2)
        self.threat_intel_agent = None
        try:
            from agent2_threat_intel import ThreatIntelAgent
            self.threat_intel_agent = ThreatIntelAgent()
        except Exception as e:
            logger.warning(f"Could not import ThreatIntelAgent: {e}")

        # Prebuilt synthetic keyword patterns (from Qdrant)
        self.synthetic_patterns: List[Dict[str, Any]] = []
        self._load_synthetic_patterns()

        # LLM setup
        self.llm = None
        self.llm_chain = None
        self.local_llm_model = os.getenv("LOCAL_LLM_MODEL", "llama3.1:latest")
        self.enable_ollama_llm = str(os.getenv("ENABLE_OLLAMA_LLM", "0")).strip().lower() in {"1", "true", "yes", "on"}

        if LANGCHAIN_AVAILABLE:
            try:
                if os.getenv("OPENAI_API_KEY"):
                    if LANGCHAIN_NEW_API:
                        self.llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0.3)
                        self.prompt_template = ChatPromptTemplate.from_messages([
                            ("system",
                             "You are a cybersecurity expert analyzing Windows Event Logs "
                             "for zero-day exploit patterns. Compare log entries against "
                             "stored zero-day threat intelligence from the Qdrant database."),
                            ("human", """
STREAMING LOG ENTRY (to analyze):
{log_entry}

STORED ZERO-DAY THREAT INTELLIGENCE (from Qdrant database):
{similar_threats}

Compare the log entry against the stored threat patterns. Determine if it matches
any zero-day exploit behavior.

Consider:
1. Process creation patterns
2. Privilege escalation indicators
3. Unusual system modifications
4. Network activity patterns
5. File system changes
6. Behavioral similarity

Respond ONLY in JSON:
{{
    "matches_zero_day": true/false,
    "confidence": 0.0-1.0,
    "matched_pattern": "description",
    "reasoning": "detailed explanation"
}}"""),
                        ])
                    else:
                        self.llm = OpenAI(temperature=0.3)
                        self.prompt_template = PromptTemplate(
                            input_variables=["log_entry", "similar_threats"],
                            template="""You are a cybersecurity expert...
STREAMING LOG ENTRY: {log_entry}
THREAT INTELLIGENCE: {similar_threats}
Respond in JSON: {{"matches_zero_day": true/false, "confidence": 0.0-1.0,
"matched_pattern": "...", "reasoning": "..."}}""",
                        )
                    self.llm_chain = LLMChain(llm=self.llm, prompt=self.prompt_template)
                    logger.info("LangChain LLM initialized with OpenAI")
                else:
                    logger.warning("OPENAI_API_KEY not set. Will use Ollama fallback.")
            except Exception as e:
                logger.warning(f"Could not initialize LangChain LLM: {e}")

    # ── CSV Tail Helpers ─────────────────────────────────────────────────────

    def _init_file_position(self):
        """
        Initialize tail position.

        By default we tail from the end, but we also "rewind" slightly so that
        rows appended shortly before the detector thread finishes starting
        (e.g. during backend startup) still get processed.
        """
        if self.filtered_csv_path.exists():
            with open(self.filtered_csv_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                self._csv_headers = reader.fieldnames
                f.seek(0, 2)
                end_pos = f.tell()

                # Rewind a small window and align to the next newline so we start
                # at a clean record boundary.
                #
                # Keep this window small so we don't "backfill" huge historical batches
                # (which can delay real-time detections).
                rewind_bytes = min(8 * 1024, end_pos)  # 8KB window
                start_pos = max(0, end_pos - rewind_bytes)
                f.seek(start_pos)
                if start_pos > 0:
                    chunk = f.read(min(rewind_bytes, 64 * 1024))
                    nl = chunk.find("\n")
                    if nl != -1:
                        start_pos = start_pos + nl + 1
                self._file_pos = start_pos

            logger.info(f"Tailing {self.filtered_csv_path} from byte {self._file_pos} (end={end_pos})")
        else:
            logger.warning(f"CSV not found yet: {self.filtered_csv_path}")

    def _read_new_rows(self) -> List[Dict[str, Any]]:
        """Return rows appended to the CSV since last read."""
        rows: List[Dict[str, Any]] = []
        if not self.filtered_csv_path.exists():
            return rows
        try:
            with open(self.filtered_csv_path, "r", encoding="utf-8", newline="") as f:
                # Sniff headers on first read
                if self._csv_headers is None:
                    reader = csv.DictReader(f)
                    self._csv_headers = reader.fieldnames
                    f.seek(0, 2)
                    self._file_pos = f.tell()
                    return rows
                f.seek(self._file_pos)
                content = f.read()
                self._file_pos = f.tell()

            if not content.strip():
                return rows

            reader = csv.DictReader(io.StringIO(content), fieldnames=self._csv_headers)
            for row in reader:
                # Skip any stray header lines written on re-init
                if row.get("timestamp") == "timestamp":
                    continue
                try:
                    row["behavior_features"] = json.loads(row.get("behavior_features_json", "{}") or "{}")
                    kw_raw = row.get("keywords", "")
                    row["keywords"] = [k.strip() for k in kw_raw.split(",") if k.strip()]
                    row["event_id"] = int(row.get("event_id", 0) or 0)
                    rows.append(row)
                except Exception as parse_err:
                    logger.debug(f"Row parse error: {parse_err}")
        except Exception as e:
            logger.error(f"Error reading CSV: {e}")
        return rows

    # ── Alert Persistence ────────────────────────────────────────────────────

    def _load_alerts(self) -> List[Dict]:
        if self.alerts_json_path.exists():
            try:
                with open(self.alerts_json_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return []

    def _append_alert(self, detection: Dict):
        alerts = self._load_alerts()

        # Best-effort dedupe across restarts/rewinds.
        src = detection.get("log_source") or {}
        dedupe_key = (
            str(src.get("timestamp", "")),
            str(src.get("event_id", "")),
            str(src.get("record_number", "")),
            str(detection.get("event_description", "")),
        )
        for a in alerts[-500:]:
            a_src = a.get("log_source") or {}
            a_key = (
                str(a_src.get("timestamp", "")),
                str(a_src.get("event_id", "")),
                str(a_src.get("record_number", "")),
                str(a.get("event_description", "")),
            )
            if a_key == dedupe_key:
                return

        alerts.append(detection)
        with open(self.alerts_json_path, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=2, ensure_ascii=False)

    # ── Synthetic Pattern Cache ──────────────────────────────────────────────

    def _load_synthetic_patterns(self):
        if not self.threat_intel_agent:
            return
        try:
            scroll = self.threat_intel_agent.qdrant.scroll(
                collection_name=self.threat_intel_agent.collection_name,
                limit=200,
                with_payload=True,
                with_vectors=False,
            )
            points = scroll[0] if isinstance(scroll, tuple) else scroll
            patterns = []
            for p in points:
                if hasattr(p, "payload") and p.payload:
                    itm = p.payload
                    title = str(itm.get("title", ""))
                    summary = str(itm.get("summary", ""))
                    cve = str(itm.get("cve", ""))
                    src = str(itm.get("source", "Unknown"))
                    sev = str(itm.get("severity", "UNKNOWN")).upper()
                    keywords = []
                    for text in [title, summary, cve, src]:
                        keywords.extend([w.lower() for w in text.split() if len(w) > 2])
                    keywords = list(dict.fromkeys(keywords))
                    patterns.append({
                        "title": title, "summary": summary, "cve": cve,
                        "source": src, "severity": sev, "keywords": keywords, "raw": itm,
                    })
            self.synthetic_patterns = patterns
            logger.info(f"Loaded {len(self.synthetic_patterns)} synthetic patterns from Qdrant")
        except Exception as e:
            logger.warning(f"Failed to load synthetic patterns: {e}")

    # ── Scoring & Detection ──────────────────────────────────────────────────

    def calculate_heuristic_score(self, normalized_log: Dict[str, Any]) -> float:
        score = 0.0
        behavior_features = normalized_log.get("behavior_features", {})
        weights = {
            "privilege_escalation": 0.3,
            "suspicious_process": 0.25,
            "service_installation": 0.2,
            "scheduled_task_creation": 0.15,
            "driver_load": 0.1,
        }
        for feature, weight in weights.items():
            if behavior_features.get(feature, False):
                score += weight
        event_id = int(normalized_log.get("event_id", 0) or 0)
        if event_id in [4672, 4697, 4698, 4700, 4702]:
            score += 0.1
        return min(score, 1.0)

    def search_similar_threats(self, normalized_log: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.threat_intel_agent:
            return []
        try:
            query_parts = list(normalized_log.get("keywords", []))[:5]
            event_desc = normalized_log.get("event_description", "")
            if event_desc:
                query_parts.append(event_desc)
            active_features = [k for k, v in normalized_log.get("behavior_features", {}).items() if v]
            query_parts.extend(active_features)
            query_text = " ".join(query_parts)
            return self.threat_intel_agent.search_similar_threats(query_text, n_results=3)
        except AttributeError as e:
            # Qdrant client API mismatch in some environments; disable to avoid repeated slow failures.
            logger.warning(f"Disabling threat-intel vector search due to error: {e}")
            self.threat_intel_agent = None
            return []
        except Exception as e:
            logger.error(f"Error searching similar threats: {e}")
            return []

    def run_local_ollama(self, prompt: str) -> str:
        try:
            proc = subprocess.run(
                ["ollama", "run", self.local_llm_model, prompt],
                capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=90,
            )
            if proc.returncode == 0:
                return proc.stdout.strip()
            logger.error(f"Ollama failed (code {proc.returncode}): {proc.stderr[:300]}")
            return ""
        except FileNotFoundError:
            logger.error("ollama CLI not found in PATH.")
            return ""
        except subprocess.TimeoutExpired:
            logger.error("Ollama timed out after 90s.")
            return ""
        except Exception as e:
            logger.error(f"Unexpected Ollama error: {e}")
            return ""

    def llm_pattern_analysis(
        self,
        normalized_log: Dict[str, Any],
        similar_threats: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        try:
            threats_text = json.dumps(similar_threats, indent=2) if similar_threats else "No similar threats found"
            log_text = json.dumps(normalized_log, indent=2)
            result = ""

            if self.llm_chain:
                try:
                    if LANGCHAIN_NEW_API:
                        response = self.llm_chain.invoke({"log_entry": log_text, "similar_threats": threats_text})
                        result = response.content if hasattr(response, "content") else str(response)
                    else:
                        result = self.llm_chain.run(log_entry=log_text, similar_threats=threats_text)
                except Exception as e:
                    logger.warning(f"LangChain call failed: {e}. Falling back to Ollama.")

            if not result and self.local_llm_model and self.enable_ollama_llm:
                prompt = f"""You are a cybersecurity expert analyzing Windows Event Logs for zero-day exploit patterns.

STREAMING LOG ENTRY:
{log_text}

STORED ZERO-DAY THREAT INTELLIGENCE:
{threats_text}

Respond ONLY in JSON:
{{
    "matches_zero_day": true/false,
    "confidence": 0.0-1.0,
    "matched_pattern": "description of matching threat pattern",
    "reasoning": "detailed explanation"
}}"""
                result = self.run_local_ollama(prompt)
            elif not result and self.local_llm_model and not self.enable_ollama_llm:
                return {
                    "matches_zero_day": False,
                    "confidence": 0.0,
                    "matched_pattern": "LLM disabled",
                    "reasoning": "ENABLE_OLLAMA_LLM is not enabled; skipping Ollama LLM analysis.",
                }

            if not result:
                return {"matches_zero_day": False, "confidence": 0.0,
                        "matched_pattern": "LLM unavailable", "reasoning": "No LLM available"}

            # Parse JSON from LLM output
            json_text = result
            if "```json" in json_text:
                json_text = json_text.split("```json")[1].split("```")[0].strip()
            elif "```" in json_text:
                parts = json_text.split("```")
                if len(parts) >= 3:
                    json_text = parts[1].strip()
            start = json_text.find("{")
            end = json_text.rfind("}")
            if start != -1 and end != -1 and end > start:
                json_text = json_text[start:end + 1]

            analysis = json.loads(json_text)
            if not isinstance(analysis, dict):
                raise ValueError("Not a JSON object")
            analysis.setdefault("matches_zero_day", False)
            analysis.setdefault("confidence", 0.0)
            analysis.setdefault("matched_pattern", "")
            analysis.setdefault("reasoning", "")
            confidence = analysis.get("confidence", 0.0)
            if isinstance(confidence, str):
                try:
                    confidence = float(confidence)
                except ValueError:
                    confidence = 0.0
            analysis["confidence"] = max(0.0, min(1.0, float(confidence)))
            return analysis

        except json.JSONDecodeError as e:
            logger.warning(f"Could not parse LLM JSON: {e}")
            matches = any(kw in result.lower() for kw in ["true", "match", "zero-day", "exploit", "suspicious"])
            conf_match = re.search(r"[\"']?confidence[\"']?\s*[:=]\s*([0-9.]+)", result, re.IGNORECASE)
            confidence = float(conf_match.group(1)) if conf_match else 0.5
            return {"matches_zero_day": matches, "confidence": max(0.0, min(1.0, confidence)),
                    "matched_pattern": "LLM analysis (JSON parse failed)", "reasoning": result[:500]}
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            return {"matches_zero_day": False, "confidence": 0.0,
                    "matched_pattern": "Error", "reasoning": str(e)}

    def detect_pattern(self, filtered_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            event_id = filtered_log.get("event_id", "N/A")

            # Step 0: Heuristic score (fast path)
            heuristic_score = self.calculate_heuristic_score(filtered_log)

            # Step 1: Vector search
            similar_threats = self.search_similar_threats(filtered_log)

            # Step 1b: Synthetic keyword similarity
            synthetic_match = None
            synthetic_score = 0.0
            log_kw_set = set(k.lower() for k in filtered_log.get("keywords", []))
            if not log_kw_set and filtered_log.get("event_description"):
                log_kw_set = {w.lower() for w in str(filtered_log["event_description"]).split() if len(w) > 2}
            for pat in self.synthetic_patterns:
                pat_kw = set(pat.get("keywords", []))
                if not pat_kw:
                    continue
                overlap = log_kw_set.intersection(pat_kw)
                score = len(overlap) / max(len(pat_kw), 1)
                if score > synthetic_score:
                    synthetic_score = score
                    synthetic_match = pat

            # Step 3: LLM analysis (can be slow/unavailable). If heuristics are already strong,
            # skip LLM and rely on heuristic + synthetic to keep streaming responsive.
            if heuristic_score >= 0.7:
                llm_analysis = {
                    "matches_zero_day": False,
                    "confidence": 0.0,
                    "matched_pattern": "Heuristic trigger",
                    "reasoning": f"High heuristic score ({heuristic_score:.2f}) — skipped LLM for responsiveness.",
                }
                llm_matches = False
                llm_confidence = 0.0
            else:
                llm_analysis = self.llm_pattern_analysis(filtered_log, similar_threats)
                llm_matches = llm_analysis.get("matches_zero_day", False)
                llm_confidence = llm_analysis.get("confidence", 0.0)

            # Step 4: Combine
            matches_zero_day = llm_matches or heuristic_score > 0.6 or synthetic_score > 0.35
            
            # If LLM gives very low confidence, rely on heuristic and synthetic instead of tanking the score.
            combined_confidence = max(
                (llm_confidence * 0.6) + (heuristic_score * 0.3) + (synthetic_score * 0.1),
                (heuristic_score * 0.8) + (synthetic_score * 0.2)
            )

            if matches_zero_day and combined_confidence > 0.5:
                # Map confidence to severity
                if combined_confidence >= 0.8:
                    severity = "CRITICAL"
                elif combined_confidence >= 0.65:
                    severity = "HIGH"
                elif combined_confidence >= 0.5:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                detection = {
                    "timestamp": datetime.now().isoformat(),
                    "severity": severity,
                    "event_description": filtered_log.get("event_description", ""),
                    "log_source": filtered_log,
                    "detection_type": "zero_day_pattern",
                    "confidence": combined_confidence,
                    "heuristic_score": heuristic_score,
                    "synthetic_match_score": synthetic_score,
                    "llm_analysis": llm_analysis,
                    "similar_threats": similar_threats,
                    "matched_zero_day": (
                        similar_threats[0]["threat_data"] if similar_threats
                        else (synthetic_match.get("raw") if synthetic_match else None)
                    ),
                    "explanation": llm_analysis.get("reasoning", ""),
                }
                logger.info(
                    f"ALERT [{severity}] EventID {event_id}: "
                    f"confidence={combined_confidence:.2f}, heuristic={heuristic_score:.2f}"
                )
                return detection

            return None

        except Exception as e:
            logger.error(f"Error in pattern detection: {e}", exc_info=True)
            return None

    def run(self, poll_interval: float = 2.0, on_detection: Optional[Callable] = None):
        """
        Main loop: tail normalized_logs.csv and run detection on each new row.

        Args:
            poll_interval: Seconds between CSV polls.
            on_detection: Optional callback(detection_dict) called for each alert.
        """
        logger.info(f"Starting Pattern Detector — tailing: {self.filtered_csv_path}")

        # Wait for CSV to exist
        while not self.filtered_csv_path.exists():
            logger.debug("Waiting for CSV file...")
            time.sleep(2)

        self._init_file_position()

        try:
            while True:
                new_rows = self._read_new_rows()
                for row in new_rows:
                    detection = self.detect_pattern(row)
                    if detection:
                        self._append_alert(detection)
                        if on_detection:
                            on_detection(detection)
                time.sleep(poll_interval)
        except KeyboardInterrupt:
            logger.info("Pattern Detector stopped.")


if __name__ == "__main__":
    detector = PatternDetectorAgent()
    detector.run()
