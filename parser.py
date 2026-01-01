import json
import time
import os
from datetime import datetime

class SIEMParser:
    def __init__(self, log_path, alert_path):
        self.log_path = log_path
        self.alert_path = alert_path
        self.failed_logins = {}  # Tracks failed login attempts by IP address
        self.threshold = 5       # Alert threshold for security events
        
        # Initialize directory structure if not present
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        os.makedirs(os.path.dirname(self.alert_path), exist_ok=True)

    def log_alert(self, message):
        """Writes security alerts to the specified log file and stdout."""
        timestamp = datetime.now().isoformat()
        alert_entry = f"[{timestamp}] ALERT: {message}\n"
        with open(self.alert_path, "a") as f:
            f.write(alert_entry)
        # Console output for real-time monitoring
        print(f"\033[91m{alert_entry.strip()}\033[0m")

    def process_line(self, line):
        """Parses log entries and applies detection heuristics."""
        try:
            data = json.loads(line)
            ip = data.get("ip")
            event = data.get("event")
            value = data.get("value", 0)

            # Rule: Detect brute force attempts
            if event == "login_failed":
                self.failed_logins[ip] = self.failed_logins.get(ip, 0) + 1
                if self.failed_logins[ip] >= self.threshold:
                    self.log_alert(f"Brute force detected from IP: {ip}")
                    self.failed_logins[ip] = 0 

            # Rule: Detect high value transactions
            if event == "transaction" and value > 10000:
                self.log_alert(f"High value transaction flagged: ${value} from IP: {ip}")

        except json.JSONDecodeError:
            # Skip malformed lines
            pass

    def monitor(self):
        """Continuously monitors the log file for new entries."""
        print(f"--- Monitoring {self.log_path} ---")
        if not os.path.exists(self.log_path):
            with open(self.log_path, 'w') as f:
                f.write("")

        with open(self.log_path, "r") as f:
            # Seek to the end of file to monitor only new entries
            f.seek(0, 2)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                self.process_line(line)

if __name__ == "__main__":
    parser = SIEMParser("log-parser/logs/access.log", "log-parser/alerts/security.log")
    parser.monitor()