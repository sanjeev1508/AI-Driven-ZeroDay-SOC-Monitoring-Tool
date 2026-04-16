"""
Main entry point for the SOC system.
Starts all agents as separate processes/threads.
"""

import multiprocessing
import threading
import time
import logging
import signal
import sys

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Module-level process entrypoints (must be top-level for Windows spawn)
def start_agent1_process():
    from agent1_log_collector import LogCollectorAgent
    collector = LogCollectorAgent()
    collector.run(interval=5)


def start_agent4_process():
    from agent4_pattern_detector import PatternDetectorAgent
    detector = PatternDetectorAgent()
    detector.run()


class SOCSystem:
    """Main SOC system that manages all agents."""
    
    def __init__(self):
        self.processes = []
        self.threads = []
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info("Received shutdown signal. Stopping all agents...")
        self.running = False
        self.stop_all()
        sys.exit(0)
    
    def start_agent1(self):
        """Start Agent 1 - Log Collector."""
        try:
            from agent1_log_collector import LogCollectorAgent
            collector = LogCollectorAgent()
            collector.run(interval=5)
        except Exception as e:
            logger.error(f"Agent 1 error: {e}")
    
    def start_agent4(self):
        """Start Agent 4 - Pattern Detector (CSV-based)."""
        try:
            from agent4_pattern_detector import PatternDetectorAgent
            detector = PatternDetectorAgent()
            detector.run()
        except Exception as e:
            logger.error(f"Agent 4 error: {e}")
    
    def start_all(self):
        """Start Agent 1 (log collection) and Agent 4 (pattern detection)."""
        logger.info("Starting SOC System...")

        # Agent 1 — Unified Log Collector/Normalizer
        p1 = multiprocessing.Process(target=start_agent1_process, name="Agent1-LogCollector")
        p1.start()
        self.processes.append(p1)
        logger.info("Started Agent 1 - Log Collector (writing CSV outputs)")

        # Agent 4 — Pattern Detector (CSV-based)
        p4 = multiprocessing.Process(target=start_agent4_process, name="Agent4-PatternDetector")
        p4.start()
        self.processes.append(p4)
        logger.info("Started Agent 4 - Pattern Detector (tailing CSV, writing alerts.json)")

        logger.info("SOC system running. Use the dashboard or backend API to view alerts.")
    
    def stop_all(self):
        """Stop all agents."""
        logger.info("Stopping all agents...")
        
        # Terminate all processes
        for process in self.processes:
            if process.is_alive():
                process.terminate()
                process.join(timeout=5)
                if process.is_alive():
                    process.kill()
        
        logger.info("All agents stopped.")
    
    def run(self):
        """Run the SOC system."""
        try:
            self.start_all()
            
            # Keep main process alive
            while self.running:
                time.sleep(1)
                
                # Check if any process died
                for i, process in enumerate(self.processes):
                    if not process.is_alive():
                        logger.error(f"Agent {i+1} died unexpectedly. Restarting...")
                        # In production, implement restart logic
                        self.running = False
                        break
            
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt")
        finally:
            self.stop_all()


if __name__ == "__main__":
    soc_system = SOCSystem()
    soc_system.run()

