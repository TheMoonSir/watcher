import os
import ctypes
import logging
import subprocess
import sys
import shutil
import uuid
import requests
import psutil
from packaging import version
from dotenv import load_dotenv
from resend import api_url
from colorama import init, Fore, Style

init()
load_dotenv()


class Watcher:
    def __init__(self):
        self.current_version = os.getenv("version")

    def check_update(self):
        try:
            response = requests.get(api_url, timeout=5)
            response.raise_for_status()
            releases = response.json()

            if len(releases) == 0 or not isinstance(releases, list):
                print(f" [{Fore.RED}✗{Style.RESET_ALL}] no releases found.")
                return
            
            release = releases[0]
            get_tag = release.get('tag_name', '0')

            if get_tag == '0':
                print(f" [{Fore.RED}✗{Style.RESET_ALL}] no tag found in release.")
                return

            clean_version = get_tag.lstrip('v')

            get_verison = version.parse(clean_version)
            get_env_version = version.parse(self.current_version)


            if get_verison > get_env_version:
                print(f" [{Fore.YELLOW}⚠{Style.RESET_ALL}] new verison available, do you want to update? (y/n)")
                choice = input().lower()
                if choice == 'y':
                    os.system("title Watcher - updating")
                    exe = sys.executable
                    path = os.path.dirname(exe)
                    
                    temp_name = f"{uuid.uuid4().hex()}.tmp"
                    temp = os.path.join(path, temp_name)

                    assets = release.get('assets', [])
                    if not assets:
                        print(f" [{Fore.RED}✗{Style.RESET_ALL}] Couldn't update, no assets found.")
                        return
                    
                    url = assets[0]['browser_download_url']

                    print(f" [{Fore.GREEN}✓{Style.RESET_ALL}] Installing update...", end=" ", flush=True)
                    spinner = ["|", "/", "-", "\\"]
                    spinner_index = 0

                    try:
                        with requests.get(url, stream=True, timeout=5) as r:
                            r.raise_for_status()
                            with open(temp, "wb") as f:
                                for chunk in r.iter_content(chunk_size=8192):
                                    f.write(chunk)
                                    print(f"\b{spinner[spinner_index % 4]}", end="", flush=True)
                                    spinner_index += 1
                            
                    except requests.RequestException as e:
                        print(f"[{Fore.RED}✗{Style.RESET_ALL}] Couldn't download update: {e}")
                        return

                    os.system("title Watcher - restarting")
                    print(f"\b [{Fore.GREEN}✓{Style.RESET_ALL}] Installed update done. closing current process for update.")

                    cmd = f'cmd /c "timeout /t 2 >nul & move /y "{temp}" "{exe}" >nul & start "" "{exe}" & exit"'
                    subprocess.Popen(cmd, creationflags=subprocess.CREATE_NO_WINDOW)

                    sys.exit()
                    psutil.Process(os.getpid()).kill()
            else:
                print(f" [{Fore.YELLOW}⚠{Style.RESET_ALL}] already up to date.")
        except requests.RequestException as e:
            print(f" [{Fore.RED}✗{Style.RESET_ALL}] Could not check for updates: {e}")


    def ensure_watcher(self):
        if getattr(sys, 'frozen', False):
            path = sys.executable
        else:
            path = os.path.abspath(__file__)

        current_dir = os.path.dirname(path)
        name = "watcher"

        if os.path.basename(current_dir).lower() != name:
            target = os.path.join(current_dir, name)

            if not os.path.exists(target):
                os.makedirs(target)

            target_path = os.path.join(target, os.path.basename(path))

            shutil.move(path, target_path)

            os.startfile(target_path)

            print(f"\b [{Fore.GREEN}✓{Style.RESET_ALL}] Moved to {target} and restarted.")
            
            sys.exit()
            psutil.Process(os.getpid()).kill()
        
        os.system("title Watcher - running")
        print(f"\b [{Fore.GREEN}✓{Style.RESET_ALL}] Running from correct location.")
        os.chdir(current_dir)

    def initialize(self):
        os.system("title Watcher - initializing")
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0

        if not is_admin:
            os.system("title Watcher - administrative privileges required")
            print(f"[{Fore.RED}✗{Style.RESET_ALL}] This script requires administrative privileges, please run as administrator/root.")
            input("Press Enter to exit...")
            sys.exit()
            

        self.ensure_watcher()
        self.check_update()

        logging.basicConfig(filename='Monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')
        print(f" [{Fore.GREEN}✓{Style.RESET_ALL}] Watcher initialized.")
