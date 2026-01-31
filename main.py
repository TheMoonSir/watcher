# Import defs
from utils.defs import *

class Monitor():
    def __init__(self):
        self.user = current_user
        self.computer_name = os.environ.get('COMPUTERNAME', 'Unknown')
        self.alert_lock = threading.Lock()
        self.last_checked = defaultdict(float)
        self.check_interval = 0.03
        self.alerted = []

    def RevereShellWorker(self, alerted):
        print(f"[+] Started worker: {threading.current_thread().name}")

        from utils.check_cert import verify_microsft
        current_time = time.time()

        while True:
            with self.alert_lock:
                alerted[:] = [
                    pid for pid in alerted
                    if isinstance(pid, int) and pid > 0 and psutil.pid_exists(pid)
                ]

            ## Reverse Shell
            ## Please check if the appliaction that was terminate is not your appliaction.. Because sometimes it can get wrong. Add to processes_suspicious to skip those appliaction
            try:
                for connection in psutil.net_connections(kind="tcp"):
                    if connection.status != 'ESTABLISHED':
                        continue

                    if connection.pid == os.getpid():
                        continue

                    if not connection.raddr:
                        continue

                    if connection.raddr.ip == "127.0.0.1" or connection.laddr.ip == "127.0.0.1":
                        continue

                    """
                    if is_private_ip(connection.raddr.ip):
                        continue
                    """

                    if not connection.pid:
                        continue

                    if not psutil.pid_exists(connection.pid):
                        continue

                    if connection.pid in alerted:
                        continue
                
                    if current_time - self.last_checked.get(connection.pid, 0) < self.check_interval:
                        continue

                    try:
                        process = psutil.Process(connection.pid)
                        if not process.is_running(): continue
                        if not psutil.pid_exists(process.pid): continue
                        process_name = process.name().lower()


                        try:
                            process_path = process.exe()
                            if not process_path or not os.path.exists(process_path):
                                continue
                                
                            process_path = process_path.lower()
                        except (psutil.AccessDenied, psutil.NoSuchProcess) as e:
                            continue           

                        found, message = ScanMemory(process.pid).ScanShellcode()

                        if found:
                            with self.alert_lock:
                                alerted.append(connection.pid)
                                
                            result = {
                                'message': 'Security action found - highly risky',
                                'computer': {self.computer_name},
                                'time': {time.ctime()},
                                'process_name': {process_name},
                                'process_path': {process.exe()},
                                'process_id': {process.pid},
                                'remote_ip': {connection.raddr.ip},
                                'type': 'reverse_shell',
                                'function_return': {message}
                            }

                            print(result)
                            logging.info(result)
                            
            

                        self.last_checked[connection.pid] = current_time
                        kill = False
                        is_signed = verify_microsft(process_path)
                        command_line = " ".join(process.cmdline()).lower()



                        if (not any(process_path.startswith(path.lower()) for path in skip_paths)) and (not is_signed):
                            kill = True
                        elif process_name in "python":
                            if any(key in command_line for key in python_commands_suspicious) or ("-c" in command_line or "exec(" in command_line):
                                kill = True
                            if not kill:
                                for child in process.children(recursive=True):
                                    if child.name().lower() in ["cmd.exe", "powershell.exe", "sh", "bash"]:
                                        kill = True
                                        break
                        elif process_name in "powershell":
                            found, message = ScanMemory(process.pid).ScanShellcode()

                            if found:
                                with self.alert_lock:
                                    alerted.append(connection.pid)
                                    
                                result = {
                                    'message': 'Security action found - highly risky',
                                    'computer': {self.computer_name},
                                    'time': {time.ctime()},
                                    'process_name': {process_name},
                                    'process_path': {process.exe()},
                                    'process_id': {process.pid},
                                    'remote_ip': {connection.raddr.ip},
                                    'type': 'reverse_shell',
                                    'function_return': {message}
                                }
                                process.kill()
                                print(result)
                                logging.info(result)
                            if "conpty" in command_line or "rawui" in command_line:
                                kill = True

                            for child in process.children():
                                if child.name().lower() == "conhost.exe": ## if you using PayloadsAllTheThings method powershell then Search up -> conhost and you will understand
                                    child_cmd = " ".join(child.cmdline()).lower()
                                    if "--headless" in child_cmd or "token" in command_line:
                                        kill = True
                        elif process_name in skip_browsers:
                            #TODO Check if brower being injected
                            for child in process.children():
                                if child.name().lower() in ["cmd.exe", "powershell.exe"]:
                                    kill = True
                        elif not kill:
                            if process_name in processes_suspicious or any(arg in command_line for arg in commands_suspicious):
                                kill = True

                        if kill:
                            with self.alert_lock:
                                alerted.append(connection.pid)

                            result = {
                                'message': 'Security action found',
                                'computer': {self.computer_name},
                                'time': {time.ctime()},
                                'process_name': {process_name},
                                'process_path': {process.exe()},
                                'process_id': {process.pid},
                                'remote_ip': {connection.raddr.ip}
                            }

                            print(result)
                            logging.info(result)
                            self.last_checked[connection.pid] = current_time
                            process.kill()
                            print("Successfully terminate the process that reverse shell the coumpter")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
            except OverflowError:
                continue
            except Exception as e:
                    print(f"Error happend on worker [{threading.current_thread().name}] - {e}")
                    traceback.print_exc()
                    continue


            time.sleep(0.01)

    def RemoteDesktopWorker(self):
            hand = win32evtlog.OpenEventLog(server, type)
            IGNORE_ACCOUNTS = [self.user.lower(), "system", "anonymous logon", "local service", "network service", "defaultuser0", "dwm-1", "umfd-0", "umfd-1", "dwm-2", "umfd-2", "dwm-0"]
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            print(f"Monitoring started for user: {self.user}")

            while True:
                events = win32evtlog.ReadEventLog(hand, flags, 0)

                if not events:
                    continue

                for event in events:
                    event_id = event.EventID & 0xFFFF
                    description = event.StringInserts

                    ## Remote Desktop
                    if event_id in EVENT_IDS:
                        account_log = event.StringInserts[5].lower() if event.StringInserts and len(event.StringInserts) > 5 else ""
                        if account_log and not any(ignored in account_log for ignored in IGNORE_ACCOUNTS):                            
                            gen_time = event.TimeGenerated.Format()
                            message = f"""
                            - Security action found -

                            Type: Remote Desktop
                            Computer: {event.ComputerName}
                            Event ID: {event_id}
                            Time:     {gen_time}
                            Account:  {account_log}
                            Description: {description}
                            """
                            print(message)
                            logging.info(message)

                    
                time.sleep(2)

    def initialize(self):
        #shortcut
        workers = [
            (self.RevereShellWorker, "ReverseShell Worker", (self.alerted,)),
            (self.RemoteDesktopWorker, "RemoteDesktop Worker", ())
        ]

        """
        x = target
        y = name
        z = args
        """
        for x, y, z in workers:
            threading.Thread(
                target=x,
                name=y,
                args=z,
                daemon=True
            ).start()


if __name__ == "__main__":
    logging.basicConfig(filename='Monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')
    Monitor().initialize()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Threads and exiting...")