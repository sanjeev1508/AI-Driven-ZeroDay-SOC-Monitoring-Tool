"""
Agent 3 - Synthetic Log Generator
Reads new threat intelligence from Qdrant and generates synthetic log entries
that mimic the attack patterns. Stores these patterns in Qdrant for the Alert Manager to use.
Triggers Agent 4 upon completion.
"""

import sys
import time
import logging
import json
import random
import subprocess
from datetime import datetime
from typing import List, Dict, Any
import requests

try:
    from qdrant_client import QdrantClient
    from qdrant_client.models import Distance, VectorParams, PointStruct
except ImportError:
    print("Error: qdrant-client not installed.")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("Agent3-SyntheticGen")

class SyntheticGeneratorAgent:
    def __init__(self):
        self.qdrant_url = "http://localhost:6333"
        self.client = QdrantClient(url=self.qdrant_url)
        self.source_collection = "zero-day-intel"
        self.target_collection = "synthetic-logs"
        self.vector_size = 768
        self.embedding_model = "nomic-embed-text:latest"

    def get_embeddings(self, text: str) -> List[float]:
        """Get embeddings for text using Ollama (consistent with Agent 2)."""
        try:
            url = "http://localhost:11434/api/embeddings"
            payload = {"model": self.embedding_model, "prompt": text}
            response = requests.post(url, json=payload, timeout=10)
            if response.status_code == 200:
                vector = response.json().get("embedding", [])
                if len(vector) == 0:
                    raise ValueError("Empty embedding returned")
                # Enforce exact dimension via truncation or padding
                if len(vector) != self.vector_size:
                    logger.warning(
                        f"Embedding size {len(vector)} != expected {self.vector_size}. "
                        f"Adjusting..."
                    )
                    if len(vector) > self.vector_size:
                        vector = vector[:self.vector_size]          # truncate
                    else:
                        vector = vector + [0.0] * (self.vector_size - len(vector))  # pad
                return vector
        except Exception as e:
            logger.warning(f"Ollama embedding failed: {e}")
        # Fallback: deterministic mock vector seeded on text length
        import random
        random.seed(len(text))
        return [random.uniform(-1, 1) for _ in range(self.vector_size)]

    def _init_target_collection(self):
        """Initialize synthetic logs collection (idempotent — does not delete existing data)."""
        try:
            if self.client.collection_exists(self.target_collection):
                logger.info(f"Collection '{self.target_collection}' already exists. Keeping existing data.")
                return
            logger.info(f"Creating collection '{self.target_collection}' with size {self.vector_size}...")
            self.client.create_collection(
                collection_name=self.target_collection,
                vectors_config=VectorParams(size=self.vector_size, distance=Distance.COSINE),
            )
        except Exception as e:
            logger.error(f"Qdrant init failed: {e}")

    def fetch_recent_threats(self) -> List[Dict[str, Any]]:
        """Fetch threat intel from Qdrant."""
        try:
            # Scroll through the source collection
            response = self.client.scroll(
                collection_name=self.source_collection,
                limit=50,
                with_payload=True,
                with_vectors=False
            )
            points = response[0]
            threats = [p.payload for p in points if p.payload]
            logger.info(f"Fetched {len(threats)} threats from {self.source_collection}")
            return threats
        except Exception as e:
            logger.error(f"Failed to fetch threats: {e}")
            return []

    def generate_synthetic_log(self, threat: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a synthetic Windows Event Log JSON structure based on the threat.
        This simply maps known keywords to event fields.
        """
        indicators = threat.get("indicators", [])
        summary = threat.get("title", "") + " " + threat.get("summary", "")
        
        # Default Template
        log = {
            "timestamp": datetime.now().isoformat(),
            "event_id": 4688, # Default: Process Creation
            "log_type": "Security",
            "source_name": "Microsoft-Windows-Security-Auditing",
            "computer_name": "WORKSTATION-SIM",
            "event_data": {
                "SubjectUserName": "SYSTEM",
                "NewProcessName": "C:\\Windows\\System32\\unknown.exe",
                "CommandLine": ""
            },
            "raw_message": f"Synthetic log for {threat.get('cve')}: {summary}",
            "is_synthetic": True
        }
        
        # Simple heuristic to make it "realistic" based on keywords
        summary_lower = summary.lower()
        
        if "process" in summary_lower or "execution" in summary_lower:
            log["event_id"] = 4688
            
        if "logon" in summary_lower or "login" in summary_lower:
            log["event_id"] = 4624
            log["event_data"]["LogonType"] = "3"
            
        if "privilege" in summary_lower:
            log["event_id"] = 4672
            
        # Add keywords to process name or command line
        for ind in indicators:
            if ".exe" in ind:
                log["event_data"]["NewProcessName"] = f"C:\\Windows\\System32\\{ind}"
            else:
                log["event_data"]["CommandLine"] += f" {ind}"
                
        return log

    def run(self):
        logger.info("=== Starting Synthetic Log Generator (Agent 3) ===")
        self._init_target_collection()
        
        threats = self.fetch_recent_threats()
        if not threats:
            logger.warning("No threats found to generate logs for.")
            # Even if no threats, we might want to trigger Agent 4 or exit.
            # But let's trigger Agent 4 anyway to ensure pipeline continues.
        
        points = []
        for threat in threats:
            synthetic_log = self.generate_synthetic_log(threat)
            
            # Embed the SYNTHETIC LOG content (conceptually: what a log looks like)
            # so we can compare REAL logs against these vectors.
            # We embed the "raw_message" + event data values.
            text_to_embed = f"{synthetic_log['raw_message']} {json.dumps(synthetic_log['event_data'])}"
            vector = self.get_embeddings(text_to_embed)
            
            # Use a derived ID
            point_id = abs(hash(f"synth_{threat.get('cve')}")) % (2**63)
            
            points.append(PointStruct(
                id=point_id,
                vector=vector,
                payload={
                    "synthetic_log": synthetic_log,
                    "related_cve": threat.get("cve"),
                    "threat_title": threat.get("title")
                }
            ))
            
        if points:
            self.client.upsert(
                collection_name=self.target_collection,
                points=points,
                wait=True
            )
            logger.info(f"Generated and stored {len(points)} synthetic log patterns.")
            
        # Agent 4 is no longer triggered automatically.
        # It will be triggered manually by the user via the Dashboard.
        logger.info("Agent 3 completed. Ready for Agent 4 (Manual Trigger via Dashboard).")

if __name__ == "__main__":
    agent = SyntheticGeneratorAgent()
    agent.run()
