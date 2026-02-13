import psutil
import socket
import ipaddress
import os


class Network:
    def __init__(self):
        pass

    def is_private_ip(self, ip: str) -> bool:
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
        
    def get_connections():
        for connection in psutil.net_connections(kind='tcp'):
            if connection.status != 'ESTABLISHED':
                continue

            if connection.pid == os.getpid():
                continue

            if not connection.raddr:
                continue

            if connection.raddr.ip == "127.0.0.1" or connection.laddr.ip == "127.0.0.1":
                continue

            """
            if self.is_private_ip(connection.raddr.ip):
                continue
            """

            if not connection.pid:
                continue

            if not psutil.pid_exists(connection.pid):
                continue

            yield connection