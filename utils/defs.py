import win32evtlog
import time
import logging
import os
import getpass
import psutil
import ipaddress
import re
import multiprocessing
import threading
import subprocess
import ctypes
from ctypes import wintypes
import re
import struct
import winreg
import traceback
from collections import defaultdict
from utils.ReadWriteMemory import ReadWriteMemory, ReadWriteMemoryError
from utils.ScanMemory import ScanMemory



current_user = getpass.getuser()
server = 'localhost'
type = 'Security'
EVENT_IDS = [4624, 4625, 21, 22, 24, 25, 39, 4778, 4779, 23, 4634, 4647, 9009]
EVENT_DESCRIPTIONS = [
    "User authentication succeeded",
    "An account was successfully logged on",
    "An account failed to log on",
    "Remote Desktop Services: Session logon succeeded",
    "Remote Desktop Services: Shell start notification received",
    "Remote Desktop Services: Session has been disconnected",
    "Remote Desktop Services: Session reconnection succeeded",
    "Session <X> has been disconnected by session <Y>",
    "A session was reconnected to a Window Station",
    "A session was disconnected from a Window Station",
    "Remote Desktop Services: Session logoff succeeded",
    "An account was logged off",
    "User initiated logoff",
    "The Desktop Window Manager has exited with code"
]
processes_suspicious = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "python.exe",
    "mshta.exe"
]

skip_browsers = ["msedge.exe", "chrome.exe", "firefox.exe", "brave.exe"] ## Bruh.

skip_paths = [
    r"c:\windows",
    r"c:\windows\system32",
    r"c:\windows\systemapps",
    r""
]

commands_suspicious = [
    "-enc",
    "-nop",
    "-w hidden",
    "-ep bypass"
]

python_commands_suspicious = ["socket", "subprocess", "connect", "sp.PIPE"]

MAX_DWORD = 0xFFFFFFFF



# Functions
def is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private or
            addr.is_loopback or
            addr.is_link_local or
            addr.is_reserved or
            addr.is_multicast
        )
    except ValueError:
        return False

    if pid is None:
        return False

    if not isinstance(pid, int):
        return False

    if pid <= 0:
        return False

    return psutil.pid_exists(pid)