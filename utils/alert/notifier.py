import logging
import threading
import psutil

class AlertManager:
    def __init__(self):
        self.alert_lock = threading.Lock()
        self.alerted = []

    def cleanup(self):
        with self.alert_lock:
            self.alerted[:] = [pid for pid in self.alerted if psutil.pid_exists(pid)]

    def send(self, alert_data: dict, severity="normal"):
        with self.alert_lock:
            pid = alert_data.get("process_id")
            if pid and pid in self.alerted:
                return
            if pid:
                self.alerted.append(pid)

            alert_data["severity"] = severity
            logging.info(f"{alert_data}")
            print(f"{alert_data}")

    def clear(self):
        with self.alert_lock:
            self.alerted.clear()

    def check_alert(self, pid: int):
        with self.alert_lock:
            return pid in self.alerted
