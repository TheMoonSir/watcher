# Deleted all imported modules because they are not used in this file and it is just a definitions file (I dont know why i put those imports here in the first place XD)

import getpass


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


skip_browsers = ["msedge.exe", "chrome.exe", "firefox.exe", "brave.exe"] ## Bruh.

skip_paths = [
    r"c:\windows",
    r"c:\windows\system32",
    r"c:\windows\systemapps",
    r""
]

commands_suspicious = [
    "conpty",
    "rawui"
    "-enc",
    "-nop",
    "-w hidden",
    "-ep bypass"
]

python_commands_suspicious = ["socket", "subprocess", "connect", "sp.PIPE"]


# Linux verison 

linux_commands_suspicious = [
    "-lvp",
    "-lvnp",
    "-lvrp",
    "-e /bin/sh",
    "-e /bin/bash",
    "dev/tcp/",
    "dev/udp/",
    "mkfifo",
    "socat exec",
    "pty,link"
]

linux_python_suspicious = [
    "pty.spawn",
    "os.dup2",
    "resource.setrlimit",
    "os.execl('/bin/sh'"
]