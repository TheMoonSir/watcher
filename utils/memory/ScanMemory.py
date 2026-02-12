from utils.defs import *
import ctypes
from ctypes import wintypes
import re
import struct

MEM_RELEASE = 0x8000
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_EXECUTE_READWRITE = 0x40 
PAGE_EXECUTE_READ = 0x20
MIB_TCP_STATE_DELETE_TCB = 12 
TCP_TABLE_OWNER_PID_ALL = 5 

Shellcode = [
    re.compile(b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00", re.DOTALL),
    re.compile(b"\x49\xbe\x77\x73\x32\x5f\x33\x32", re.DOTALL),
    re.compile(b"\x49\xb8\x63\x6d\x64\x00\x00\x00", re.DOTALL)
]

class MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", wintypes.DWORD),
        ("dwLocalAddr", wintypes.DWORD),
        ("dwLocalPort", wintypes.DWORD),
        ("dwRemoteAddr", wintypes.DWORD),
        ("dwRemotePort", wintypes.DWORD),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]

class ScanMemory:
    def __init__(self, pid=None):
        # going mad for this anyways use -1 pid which shouldn't work
        if not isinstance(pid, int) or pid <= 0:
            self.pid = None
            self.process = None
            return
        self.pid = pid
        self.rwm = ReadWriteMemory() 
        self.process = self.rwm.get_process_by_id(self.pid)
        if not self.process:
            return
        self.kernel32 = ctypes.windll.kernel32
        self.iphlpapi = ctypes.windll.iphlpapi
        

        ## Fixed Issue "int too long to covert"
        self.kernel32.VirtualQueryEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, 
            ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t
        ]
        self.kernel32.ReadProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, 
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.WriteProcessMemory.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, 
            ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
        ]
        self.kernel32.VirtualFreeEx.argtypes = [
            wintypes.HANDLE, ctypes.c_void_p, 
            ctypes.c_size_t, wintypes.DWORD
        ]

    def _disconnect(self):
        size = wintypes.DWORD(0)
        self.iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), True, 2, TCP_TABLE_OWNER_PID_ALL, 0)
        buffer = ctypes.create_string_buffer(size.value)

        if self.iphlpapi.GetExtendedTcpTable(buffer, ctypes.byref(size), True, 2, TCP_TABLE_OWNER_PID_ALL, 0) == 0:
            num_entries = struct.unpack("<I", buffer[:4])[0]
            entry_size = 24 

            for i in range(num_entries):
                offset = 4 + (i * entry_size)
                row_pid = struct.unpack("<I", buffer[offset + 20 : offset + 24])[0]
                
                if row_pid == self.pid:
                    row_data = buffer[offset : offset + 20]
                    row = MIB_TCPROW.from_buffer_copy(row_data)
                    
                    if row.dwState != MIB_TCP_STATE_DELETE_TCB:
                        row.dwState = MIB_TCP_STATE_DELETE_TCB
                        self.iphlpapi.SetTcpEntry(ctypes.byref(row))
            return True
        return False

    def ScanShellcode(self):
        if not self.process:
            return None, None
        self.process.open()
        
        addr = 0x10000
        max_addr = 0x7FFFFFFEFFFF
        detected = False

        while addr < max_addr:
            mbi = MEMORY_BASIC_INFORMATION()
            if not self.kernel32.VirtualQueryEx(self.process.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break

            if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_EXECUTE_READWRITE):
                buffer = ctypes.create_string_buffer(mbi.RegionSize)
                n_read = ctypes.c_size_t(0)
                
                if self.kernel32.ReadProcessMemory(self.process.handle, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(n_read)):
                    if any(p.search(buffer.raw) for p in Shellcode):
                        detected = True
                        
                        # Wipe memory
                        zero_fill = b'\x00' * mbi.RegionSize
                        self.kernel32.WriteProcessMemory(self.process.handle, mbi.BaseAddress, zero_fill, mbi.RegionSize, None)
                        
                        # Attempt to free the region
                        self.kernel32.VirtualFreeEx(self.process.handle, mbi.BaseAddress, 0, MEM_RELEASE)
                             
            elif mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE and (mbi.Protect in [PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ]):
                buffer = ctypes.create_string_buffer(mbi.RegionSize)
                n_read = ctypes.c_size_t(0)

                if self.kernel32.ReadProcessMemory(self.process.handle, mbi.BaseAddress, buffer, mbi.RegionSize, ctypes.byref(n_read)): 
                    if any(p.search(buffer.raw) for p in Shellcode):
                        detected = True

                        # Wipe memory
                        zero_fill = b'\x00' * mbi.RegionSize
                        self.kernel32.WriteProcessMemory(self.process.handle, mbi.BaseAddress, zero_fill, mbi.RegionSize, None)
                        
                        # Attempt to free the region
                        self.kernel32.VirtualFreeEx(self.process.handle, mbi.BaseAddress, 0, MEM_RELEASE)
            
            addr += mbi.RegionSize

        if detected:
            self._disconnect()
            self.process.close()
            return True, "Done"
        
        self.process.close()
        return False, "Clean"