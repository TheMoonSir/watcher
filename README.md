# Anti Reverse Shell / Remote Desktop Monitor

<img src="https://i.postimg.cc/R0HYvT6W/5Srg-PWU.png" />

Hello my name is themoon (also known shalev), i created this project to help people who run servers with lower security.
You can use this project to protect your computer from attackers who may try to reverse shell your computer or remote desktop access without your permission.

# Informations on this project

### You can view how this porject work here
https://miro.com/app/board/uXjVGAn3Ml8=/?share_link_id=431140843238

### Reverse Shell
- Detect suspicious processes and command execution
- Scan process memory for detect shellcode injection model
- Logging all actions that found

### Remote Desktop
- Detect any action by Windows Security Event Logs (only way to detect)
- Log all actions that found
- Will Come soon

### OS support
- Windows users
- Linux

# Requirements
1. You need 3.12.4 verison python
2. Must run on Administrator / root

# Installation

1. git clone the project to where you want
2. cd project folder
3. Install requirements.txt | ```pip install -r requirements.txt```
4. Open Command prompt as admin
5. Use Path where the project is
6. py main.py

# Warning
The project does not ignore private IP connections.  
If you want to skip private IP, remove the comment from inside on network/network.py this code:

```python
"""
if is_private_ip(connection.raddr.ip):
    continue
"""
```

The project created to protect system from attackers not to damage your system!
Use carefuly and always read the code before running anything.