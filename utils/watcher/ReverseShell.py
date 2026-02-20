from utils.defs import current_user
import os
import threading
import time
import traceback
import platform


from utils.alert.notifier import AlertManager
from utils.memory import ScanMemory
from utils.network.network import Network
from utils.process.process import Process


class RerverseShell():
    def __init__(self):
        self.user = current_user
        self.computer_name = os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'Unknown'))
        self.alert_manager = AlertManager()

    def ReverseShellWorker(self):
        print(f"[{threading.current_thread().name}] started.")

        while True:
            self.alert_manager.cleanup()
            try:
                for connection in Network.get_connections():
                    pid = connection.pid
                    if self.alert_manager.check_alert(pid):
                        continue

                    appliaction = Process(pid)
                    is_suspicious, reason = appliaction.check_process()

                    if is_suspicious:
                        result = {
                            'message': 'Security action found',
                            'computer': self.computer_name,
                            'time': time.ctime(),
                            'process_name': appliaction.info["name"],
                            'process_path': appliaction.info["exe"],
                            'process_id': appliaction.pid,
                            'remote_ip': connection.raddr.ip
                        }

                        severity = "high" if reason == "highly risky" else "normal"
                        self.alert_manager.send(result, severity=severity)

                        # Won't kill the process that highly risky because shellcode injection already killing it
                        if reason != "highly risky":
                            ScanMemory(appliaction.pid)._disconnect()
                            appliaction.kill()
            except Exception as e:
                    print(f"Error happend in worker [{threading.current_thread().name}] - {e}")
                    traceback.print_exc()
                    continue
            time.sleep(0.01)

    def ReverseShellWorkerLinux(self):
        print(f"[{threading.current_thread().name}] started.")

        while True:
            self.alert_manager.cleanup()
            try:
                for connection in Network.get_connections():
                    pid = connection.pid
                    if self.alert_manager.check_alert(pid):
                        continue

                    appliaction = Process(pid)
                    is_suspicious, reason = appliaction.check_process()

                    if is_suspicious:
                        result = {
                            'message': 'Security action found',
                            'computer': self.computer_name,
                            'time': time.ctime(),
                            'process_name': appliaction.info["name"],
                            'process_path': appliaction.info["exe"],
                            'process_id': appliaction.pid,
                            'remote_ip': connection.raddr.ip
                        }

                        severity = "high" if reason == "highly risky" else "normal"
                        self.alert_manager.send(result, severity=severity)

                        appliaction.kill()
            except Exception as e:
                    print(f"Error happend in worker [{threading.current_thread().name}] - {e}")
                    traceback.print_exc()
                    continue
            time.sleep(0.01)

    def initialize(self):
        if platform.system() == "Windows":
            name = f"ReverseShell Worker (Windows)"
            target = self.ReverseShellWorker
        else:
            name = f"ReverseShell Worker (Linux)"
            target = self.ReverseShellWorkerLinux

        threading.Thread(target=target, name=name, daemon=True).start()



