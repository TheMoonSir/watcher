# Anti Reverse Shell / Remote Desktop Monitor

Hello my name is themoon (also known shalev), i made this project for people that using Servers with lower secuity.
You can use the project to be protect from attackers that reverse shell your computer.

# Informations on this projects

### Reverse Shell
- Detect suspicious processes and command execution
- Scan process memory for detect shellcode injection model
- Logging all actions that found

### Remote Desktop
- Detect any action by Windows Security Event Logs (only way to detect)
- Log all actions that found

Note: Remote desktop is still not ready yet so you can't you use it for now.

### OS support
- Windows users (currently)
- Linux (coming soon)

# Requirements
1. You need 3.12.4 verison python
2. Must run on Administrator / root

# Installation

1. git clone the project to where you want
2. cd project folder
3. Install requirements.txt - (pip -r install requirements.txt)
4. Open Command prompt as admin
5. Use Path where the project is
6. py main.py

# Warning
Some programs might be detected as suspicious.
If this happens, you can whitelist them inside on utils/defs.py:

```python
processes_suspicious = [
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "python.exe",
    "mshta.exe"
]
```

The project does not ignore private IP connections.  
If you want to skip private IP, remove the comment from this code:

```python
"""
if is_private_ip(connection.raddr.ip):
    continue
"""
```

The project created to protect system from attackers not to damage your system!
Use carefuly and always read the code before running anything.