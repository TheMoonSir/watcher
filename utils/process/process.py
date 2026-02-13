# This file is for checking process for suspicious behavior
import platform
import psutil
from utils.certificate.check_cert import verify_microsft
from utils.memory.ScanMemory import ScanMemory
from utils.defs import skip_paths, skip_browsers, python_commands_suspicious, commands_suspicious, linux_commands_suspicious, linux_python_suspicious

class Process:
    def __init__(self, pid: int):
        self.pid = pid
        self.process = None
        self.info = None

        try:
            vaild = psutil.pid_exists(pid)
            if vaild:
                self.process = psutil.Process(pid)
                self.info = {
                    "name": self.process.name().lower(),
                    "exe": self.process.exe(),
                    "cmdline": " ".join(self.process.cmdline()).lower(),
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.process = None
            pass
        
    def __str__(self):
        return self.info

    def check_process(self) -> bool:
        if platform.system() == "Windows":
            return self.check_process_windows()
        else:
            return self.check_process_linux()

    def check_process_windows(self) -> bool:
        if self.process is None:
            return False, "not risky"

        # Check if the process being injected
        found, _ = ScanMemory(self.process.pid).ScanShellcode()
        
        if found:
            return True, "highly risky"
        
        # Check if the process is signed by microsoft and if the path is in the skip list (Won't whitelist if the process is in skip list but not signed by microsoft)
        check_path = any(self.info["exe"].startswith(path.lower()) for path in skip_paths)

        # Waring: The verify_microsft is huge file the paython may load slower but will keep checking the certificate the process
        check_sign = verify_microsft(self.info["exe"])

        if not check_path and not check_sign:
            return True, "normal risky"
                
        if "python" in self.info["name"]:
            check_command = any(key in self.info["cmdline"] for key in python_commands_suspicious) or ("-c" in self.info["cmdline"] or "exec(" in self.info["cmdline"])

            if check_command:
                return True, "normal risky"
            else:
                for child in self.process.children(recursive=True):
                    if child.name().lower() in ["cmd.exe", "powershell.exe", "sh", "bash"]:
                        return True, "normal risky"
                    
        elif "powershell" in self.info["name"]:
            found, _ = ScanMemory(self.process.pid).ScanShellcode()

            if found:
                return True, "highly risky"
            
            check_command_suspicious = any(key in self.info["cmdline"] for key in commands_suspicious)
            if check_command_suspicious:
                return True, "normal risky"
            
            # Checking if using PayloadsAlltheThings method powershell execution
            for child in self.process.children(recursive=True):
                if child.name().lower() == "conhost.exe":
                    child_command = " ".join(child.cmdline()).lower()
                    if "--headless" in child_command or "token" in child_command:
                        return True, "normal risky"
                    
        #TODO: Check if open image is not making reverse shell (image.png --image open reverse shell)
        #TODO: Check if the process is using some kind of obfuscation (like renaming cmd.exe to something else) - But will cause false positive a little bit

        if self.info["name"] in skip_browsers:
            found, _ = ScanMemory(self.process.pid).ScanShellcode()

            if found:
                return True, "highly risky"

        
        return False, "not risky"
        
    def check_process_linux(self) -> bool:
        if self.process is None:
            return False, "not risky"
        
        if any(cmd in self.info["cmdline"] for cmd in linux_commands_suspicious):
            return True, "highly risky"
        
        if "python" in self.info["name"]:
            if any(cmd in self.info["cmdline"] for cmd in linux_python_suspicious):
                return True, "highly risky"

    def kill(self):
        if self.process is not None:
            try:
                self.process.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass