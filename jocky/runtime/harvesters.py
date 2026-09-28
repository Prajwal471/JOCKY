"""Live Windows harvesters for JOCKY v0.1 (Block 4).

Each collector returns rows matching the ``DOMAIN_REGISTRY`` field sets so
the bound library (``jocky.runtime.builtins``) stays a pure seam.  Every
function degrades to ``[]`` on non-Windows platforms; callers that need
deterministic data should use the synthetic seam instead.

All data is read with the caller's own (least-privilege) process token --
no service escalation -- which matches Section 16's ``privileges: none``
requirement and the Phase-0 unelevated demo constraint.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import datetime as _dt
import os
import platform
import socket
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any

_win = sys.platform == "win32"

# --------------------------------------------------------------------------
# Windows process snapshot (Toolhelp32)
# --------------------------------------------------------------------------

_PROCESS_NAME_FALLBACK = "unknown.exe"

# state map


def _iso_utc(ts: int) -> str:
    if not ts:
        return ""
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).isoformat()


def _process_snapshot() -> dict[int, dict[str, Any]]:
    """Snapshot pids to (name, exe, ppid, threads, username, created)."""
    out: dict[int, dict[str, Any]] = {}
    if not _win:
        return out
    import ctypes

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.c_size_t),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    Process32FirstW = kernel32.Process32FirstW
    Process32NextW = kernel32.Process32NextW
    OpenProcess = kernel32.OpenProcess
    QueryFullProcessImageNameW = kernel32.QueryFullProcessImageNameW
    GetProcessTimes = kernel32.GetProcessTimes
    CloseHandle = kernel32.CloseHandle

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wt.DWORD), ("dwHighDateTime", wt.DWORD)]

    def _image_name(handle: int) -> str:
        buf = ctypes.create_unicode_buffer(4096)
        size = wt.DWORD(len(buf))
        if QueryFullProcessImageNameW(ctypes.c_void_p(handle), 0, buf, ctypes.byref(size)):
            return str(buf.value)
        return ""

    def _username(handle: int) -> str:
        try:
            htoken = wt.HANDLE()
            if not ctypes.WinDLL("advapi32").OpenProcessToken(
                ctypes.c_void_p(handle), 0x0008, ctypes.byref(htoken)
            ):
                return ""
            try:
                buflen = wt.DWORD(0)
                adv = ctypes.WinDLL("advapi32")
                adv.GetTokenInformation(htoken, 1, None, 0, ctypes.byref(buflen))
                buf = ctypes.create_string_buffer(buflen.value)
                adv.GetTokenInformation(htoken, 1, buf, buflen, ctypes.byref(buflen))
                sid_ptr = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
                name = ctypes.create_unicode_buffer(256)
                dom = ctypes.create_unicode_buffer(256)
                nl = wt.DWORD(256)
                dl = wt.DWORD(256)
                use = wt.DWORD()
                if adv.LookupAccountSidW(None, ctypes.c_void_p(sid_ptr), name, ctypes.byref(nl), dom, ctypes.byref(dl), ctypes.byref(use)):
                    return str(name.value)
            finally:
                ctypes.WinDLL("kernel32").CloseHandle(htoken)
        except Exception:
            return ""

    def _created(handle: int) -> str:
        try:
            ct, et, kt, ut = FILETIME(), FILETIME(), FILETIME(), FILETIME()
            if GetProcessTimes(ctypes.c_void_p(handle), ctypes.byref(ct), ctypes.byref(et), ctypes.byref(kt), ctypes.byref(ut)):
                ft = (ct.dwHighDateTime << 32) | ct.dwLowDateTime
                if ft:
                    secs = ft / 10_000_000 - 11644473600
                    return _iso_utc(int(secs))
        except Exception:
            pass
        return ""

    h = CreateToolhelp32Snapshot(0x00000002, 0)
    if not h:
        return out
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not Process32FirstW(ctypes.c_void_p(h), ctypes.byref(entry)):
            return out
        while True:
            pid = int(entry.th32ProcessID)
            ph = OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
            if ph:
                exe = _image_name(ph)
                uname = _username(ph)
                created = _created(ph)
                CloseHandle(ph)
            else:
                exe, uname, created = "", "", ""
            out[pid] = {
                "name": str(entry.szExeFile) or _PROCESS_NAME_FALLBACK,
                "exe": exe,
                "ppid": int(entry.th32ParentProcessID),
                "threads": int(entry.cntThreads),
                "username": uname,
                "created": created,
            }
            if not Process32NextW(ctypes.c_void_p(h), ctypes.byref(entry)):
                break
    finally:
        CloseHandle(ctypes.c_void_p(h))
    return out


# --------------------------------------------------------------------------
# TCP/UDP connection table (IP Helper API)
# --------------------------------------------------------------------------

_TCP_STATES = {
    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RECEIVED",
    5: "ESTABLISHED", 6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT",
    9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}


def _inet_addr_to_str(val: int) -> str:
    packed = struct.pack("<I", val & 0xFFFFFFFF)
    return ".".join(str(b) for b in packed)


def _inet6_addr_to_str(b16: bytes) -> str:
    return ":".join(f"{int.from_bytes(b16[i:i+2], 'big'):x}" for i in range(0, 16, 2))


def connection_rows(procs: dict[int, dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    if not _win:
        return []
    procs = procs if procs is not None else _process_snapshot()

    class MIB_TCPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwState", wt.DWORD),
            ("dwLocalAddr", wt.DWORD),
            ("dwLocalPort", wt.DWORD),
            ("dwRemoteAddr", wt.DWORD),
            ("dwRemotePort", wt.DWORD),
            ("dwOwningPid", wt.DWORD),
        ]

    class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("LocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", wt.DWORD),
            ("dwLocalPort", wt.DWORD),
            ("RemoteAddr", ctypes.c_ubyte * 16),
            ("dwRemoteScopeId", wt.DWORD),
            ("dwRemotePort", wt.DWORD),
            ("dwOwningPid", wt.DWORD),
        ]

    class MIB_UDPROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("dwLocalAddr", wt.DWORD),
            ("dwLocalPort", wt.DWORD),
            ("dwOwningPid", wt.DWORD),
        ]

    class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
        _fields_ = [
            ("LocalAddr", ctypes.c_ubyte * 16),
            ("dwLocalScopeId", wt.DWORD),
            ("dwLocalPort", wt.DWORD),
            ("dwOwningPid", wt.DWORD),
        ]

    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    GetExtendedTcpTable = iphlpapi.GetExtendedTcpTable
    GetExtendedUdpTable = iphlpapi.GetExtendedUdpTable
    GetExtendedTcpTable.restype = wt.DWORD
    GetExtendedTcpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL, wt.DWORD, wt.DWORD, wt.DWORD]
    GetExtendedUdpTable.restype = wt.DWORD
    GetExtendedUdpTable.argtypes = [ctypes.c_void_p, ctypes.POINTER(wt.DWORD), wt.BOOL, wt.DWORD, wt.DWORD]

    rows: list[dict[str, Any]] = []

    def _tcp_table(family: int, table_class: int, row_size: int) -> list[tuple]:
        needed = wt.DWORD(0)
        r = GetExtendedTcpTable(None, ctypes.byref(needed), False, family, table_class, 0)
        if r != 0x7A:  # ERROR_INSUFFICIENT_BUFFER
            return []
        buf = ctypes.create_string_buffer(needed.value + 8)
        r = GetExtendedTcpTable(buf, ctypes.byref(needed), False, family, table_class, 0)
        if r != 0:
            return []
        raw = buf.raw
        if len(raw) < 4:
            return []
        count = struct.unpack_from("<I", raw, 0)[0]
        out = []
        for i in range(count):
            o = 4 + i * row_size
            if o + row_size > len(raw):
                break
            if family == 2:
                state, la, lp, ra, rp, pid = struct.unpack_from("<6I", raw, o)
                out.append((state, la, lp, ra, rp, pid))
            else:
                raise NotImplementedError("tcp6 owner-pid layout untested")
        return out

    def _udp_table(family: int, table_class: int, row_size: int) -> list[tuple]:
        needed = wt.DWORD(0)
        r = GetExtendedUdpTable(None, ctypes.byref(needed), False, family, table_class)
        if r != 0x7A:
            return []
        buf = ctypes.create_string_buffer(needed.value + 8)
        r = GetExtendedUdpTable(buf, ctypes.byref(needed), False, family, table_class)
        if r != 0:
            return []
        raw = buf.raw
        if len(raw) < 4:
            return []
        count = struct.unpack_from("<I", raw, 0)[0]
        out = []
        for i in range(count):
            o = 4 + i * row_size
            if o + row_size > len(raw):
                break
            la, lp, pid = struct.unpack_from("<3I", raw, o)
            out.append((la, lp, pid))
        return out

    rows = []
    for (state, la, lp, ra, rp, pid) in _tcp_table(2, 5, 24):
        rows.append({
            "pid": int(pid),
            "process_name": procs.get(int(pid), {}).get("name", ""),
            "state": _TCP_STATES.get(int(state), str(int(state))),
            "local_addr": _inet_addr_to_str(la),
            "local_port": socket.ntohs(int(lp) & 0xFFFF),
            "remote_addr": _inet_addr_to_str(ra),
            "remote_port": socket.ntohs(int(rp) & 0xFFFF),
            "remote_hostname": "",
            "direction": "listen" if int(state) == 2 else "peer",
        })
    for (la, lp, pid) in _udp_table(2, 1, 12):
        rows.append({
            "pid": int(pid),
            "process_name": procs.get(int(pid), {}).get("name", ""),
            "state": "UDP",
            "local_addr": _inet_addr_to_str(la),
            "local_port": socket.ntohs(int(lp) & 0xFFFF),
            "remote_addr": "0.0.0.0",
            "remote_port": 0,
            "remote_hostname": "",
            "direction": "listen",
        })
    return rows


# --------------------------------------------------------------------------
# Service Control Manager enumeration
# --------------------------------------------------------------------------

def _service_rows(service_type: int) -> list[dict[str, Any]]:
    if not _win:
        return []

    class SERVICE_STATUS_PROCESS(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wt.DWORD), ("dwCurrentState", wt.DWORD),
            ("dwControlsAccepted", wt.DWORD), ("dwWin32ExitCode", wt.DWORD),
            ("dwServiceSpecificExitCode", wt.DWORD), ("dwCheckPoint", wt.DWORD),
            ("dwWaitHint", wt.DWORD), ("dwProcessId", wt.DWORD),
        ]

    class ENUM_SERVICE_STATUS_PROCESSW(ctypes.Structure):
        _fields_ = [
            ("lpServiceName", wt.LPWSTR),
            ("lpDisplayName", wt.LPWSTR),
            ("ServiceStatusProcess", SERVICE_STATUS_PROCESS),
        ]

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    OpenSCManagerW = advapi.OpenSCManagerW
    OpenSCManagerW.restype = ctypes.c_void_p
    OpenSCManagerW.argtypes = [wt.LPCWSTR, wt.LPCWSTR, wt.DWORD]
    EnumServicesStatusExW = advapi.EnumServicesStatusExW
    EnumServicesStatusExW.restype = wt.BOOL
    EnumServicesStatusExW.argtypes = [
        ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.DWORD, ctypes.c_void_p,
        wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD),
        ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
    ]
    QueryServiceConfigW = advapi.QueryServiceConfigW
    QueryServiceConfigW.restype = wt.BOOL
    QueryServiceConfigW.argtypes = [ctypes.c_void_p, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD)]
    OpenServiceW = advapi.OpenServiceW
    OpenServiceW.restype = ctypes.c_void_p
    OpenServiceW.argtypes = [ctypes.c_void_p, wt.LPCWSTR, wt.DWORD]
    CloseServiceHandle = advapi.CloseServiceHandle
    CloseServiceHandle.restype = wt.BOOL
    CloseServiceHandle.argtypes = [ctypes.c_void_p]

    class QUERY_SERVICE_CONFIGW(ctypes.Structure):
        _fields_ = [
            ("dwServiceType", wt.DWORD), ("dwStartType", wt.DWORD),
            ("dwErrorControl", wt.DWORD), ("lpBinaryPathName", wt.LPWSTR),
            ("lpLoadOrderGroup", wt.LPWSTR), ("dwTagId", wt.DWORD),
            ("lpDependencies", wt.LPWSTR), ("lpServiceStartName", wt.LPWSTR),
            ("lpDisplayName", wt.LPWSTR),
        ]

    sc_manager = OpenSCManagerW(None, "ServicesActive", 0x1 | 0x4)  # CONNECT | ENUMERATE_SERVICE
    if not sc_manager:
        return []
    try:
        needed = wt.DWORD(0)
        returned = wt.DWORD(0)
        resume = wt.DWORD(0)
        EnumServicesStatusExW(
            ctypes.c_void_p(sc_manager), 0, ctypes.c_uint32(service_type), 3,
            None, 0, ctypes.byref(needed), ctypes.byref(returned), ctypes.byref(resume), None,
        )
        buf = ctypes.create_string_buffer(max(needed.value, 64 * 1024) + 16)
        ok = EnumServicesStatusExW(
            ctypes.c_void_p(sc_manager), 0, ctypes.c_uint32(service_type), 3,
            buf, len(buf), ctypes.byref(needed), ctypes.byref(returned), ctypes.byref(resume), None,
        )
        if not ok:
            return []
        rows: list[dict[str, Any]] = []
        raw = buf.raw
        base = ctypes.addressof(buf)

        def _wstr(addr: int, rawbuf: bytes, base_addr: int) -> str:
            off = addr - base_addr
            if not 0 <= off < len(rawbuf):
                return ""
            tail = rawbuf[off:]
            end = tail.find(b"\x00\x00")
            if end == -1:
                end = len(tail)
            else:
                end += 1  # include the last char's NUL high byte
            end -= end % 2
            return tail[:end].decode("utf-16-le", "replace").rstrip("\x00")

        for i in range(returned.value):
            o = i * 48
            if o + 48 > len(raw):
                break
            name_addr, disp_addr = struct.unpack_from("<QQ", raw, o)
            pid = struct.unpack_from("<I", raw, o + 44)[0]
            state = struct.unpack_from("<I", raw, o + 20)[0]
            name = _wstr(name_addr, raw, base)
            path = ""
            hsvc = OpenServiceW(ctypes.c_void_p(sc_manager), name, 0x0001)  # QUERY_CONFIG
            if hsvc:
                need2 = wt.DWORD(0)
                QueryServiceConfigW(ctypes.c_void_p(hsvc), None, 0, ctypes.byref(need2))
                cb = ctypes.create_string_buffer(need2.value + 64)
                QueryServiceConfigW(ctypes.c_void_p(hsvc), cb, len(cb), ctypes.byref(need2))
                cbra = cb.raw
                start_type = struct.unpack_from("<I", cbra, 4)[0] if len(cbra) >= 8 else 0
                binptr = struct.unpack_from("<Q", cbra, 16)[0] if len(cbra) >= 24 else 0
                path_meta = (start_type, _wstr(binptr, cbra, ctypes.addressof(cb)))
                CloseServiceHandle(hsvc)
            else:
                path_meta = (0, "")
            rows.append({
                "name": name,
                "display": _wstr(disp_addr, raw, base),
                "state": {1: "STOPPED", 2: "START_PENDING", 3: "STOP_PENDING",
                          4: "RUNNING", 5: "CONTINUE_PENDING", 6: "PAUSE_PENDING",
                          7: "PAUSED"}.get(state, str(state)),
                "start_type": {0: "BOOT_START", 1: "SYSTEM_START", 2: "AUTO_START",
                               3: "DEMAND_START", 4: "DISABLED"}.get(path_meta[0], str(path_meta[0])),
                "path": path_meta[1],
                "pid": pid if state in (4, 5, 6) else -1,
            })
        return rows
    finally:
        CloseServiceHandle(sc_manager)


# --------------------------------------------------------------------------
# Authenticode signature / signer (WinVerifyTrust + CryptQueryObject)
# --------------------------------------------------------------------------

def autostart_rows() -> list[dict[str, Any]]:
    if not _win:
        return []
    import winreg

    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run", "SYSTEM"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce", "SYSTEM"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run", "user"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce", "user"),
    ]
    rows: list[dict[str, Any]] = []
    for hive, subkey, loc, owner in locations:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    rows.append({
                        "name": name,
                        "command": str(value),
                        "location": loc,
                        "enabled": True,
                        "user": owner,
                    })
                    i += 1
        except OSError:
            continue
    startup = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup")
    for f in (os.listdir(startup) if os.path.isdir(startup) else []):
        path = os.path.join(startup, f)
        rows.append({"name": f, "command": path, "location": "StartupFolder", "enabled": os.name == "nt", "user": "user"})
    return rows


# --------------------------------------------------------------------------
# Event logs (wevtutil, unelevated for Application/System)
# --------------------------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def event_rows(channels: list[str] | None = None, per_channel: int = 40) -> list[dict[str, Any]]:
    if not _win:
        return []
    channels = channels or ["Application", "System"]
    rows: list[dict[str, Any]] = []
    for ch in channels:
        try:
            cp = subprocess.run(
                ["wevtutil", "qe", ch, "/c:" + str(per_channel), "/rd:true", "/f:xml"],
                capture_output=True, text=True, timeout=30, errors="replace",
            )
            if cp.returncode != 0:
                continue
            text = cp.stdout
            text = text.split("?>", 1)[1] if "<?xml" in text else text
            root = ET.fromstring(f"<events>{text}</events>")

            def _child(parent, name):
                for c in parent:
                    if _local(c.tag) == name:
                        return c
                return None

            for ev in root:
                if _local(ev.tag) != "Event":
                    continue
                system = _child(ev, "System")
                if system is None:
                    continue
                eid_el = _child(system, "EventID")
                level_el = _child(system, "Level")
                provider_el = _child(system, "Provider")
                time_el = _child(system, "TimeCreated")
                parts = []
                for d in ev.iter():
                    if _local(d.tag) == "Data" and d.text and d.text.strip():
                        parts.append(d.text.strip())
                rows.append({
                    "channel": ch,
                    "event_id": int(eid_el.text) if eid_el is not None and eid_el.text else 0,
                    "level": int(level_el.text) if level_el is not None and level_el.text else 0,
                    "provider": provider_el.get("Name", "") if provider_el is not None else "",
                    "message": " | ".join(parts[:24]),
                    "observed_at": time_el.get("SystemTime", "") if time_el is not None else "",
                })
        except Exception:
            continue
    return rows


# --------------------------------------------------------------------------
# System / identities
# --------------------------------------------------------------------------

def system_info(endpoint: str = "") -> list[dict[str, Any]]:
    host = endpoint or platform.node()
    priv = ""
    if _win:
        try:
            priv = "administrator" if ctypes.windll.shell32.IsUserAnAdmin() else "none"
        except Exception:
            priv = "none"
    return [{
        "hostname": host,
        "platform": "windows" if _win else sys.platform,
        "os_version": platform.platform(),
        "collector_version": "ctypes-0.1.0",
        "privileges": priv,
    }]


__all__ = [
    "proc_rows",
    "connection_rows",
    "service_rows",
    "driver_rows",
    "autostart_rows",
    "event_rows",
    "system_info",
    "lotl_rows",
]


def proc_rows() -> list[dict[str, Any]]:
    return [{
        **info,
        "pid": pid,
        "name": info["name"],
        "exe": info["exe"],
        "ppid": info["ppid"],
        "threads": info["threads"],
        "username": info["username"],
        "created": info["created"],
    } for pid, info in sorted(_process_snapshot().items())]


def service_rows() -> list[dict[str, Any]]:
    return _service_rows(0x00000030)


def driver_rows() -> list[dict[str, Any]]:
    rows = _service_rows(0x0000000B)
    known_vuln = frozenset({"capcom.sys", "dbk64.sys", "Pidgin?nil", "IObitUnlocker.sys"})
    expanded: list[tuple[dict[str, Any], str]] = [
        (r, _expand_driver_path(r["path"])) for r in rows
    ]
    running = [path for r, path in expanded if r["state"] == "RUNNING" and path]
    sig = _signature_batch(running)
    out = []
    for r, path in expanded:
        name = r["name"].lower()
        signed, signer = sig.get(path, (False, "")) if r["state"] == "RUNNING" and path else (False, "")
        running_svc = r["state"] == "RUNNING"
        out.append({
            "name": r["name"],
            "path": path,
            "signed": signed,
            "signer": signer,
            "state": r["state"],
            "known_vulns": name in known_vuln or (running_svc and path and _signature_known_vulnerable(path)),
        })
    return out


def _signature_batch(paths: list[str]) -> dict[str, tuple[bool, str]]:
    """One-shot Authenticode check for a batch of files -> {path: (signed, signer)}."""
    if not _win or not paths:
        return {}
    unique = sorted({p for p in paths if p and os.path.isfile(p)})
    if not unique:
        return {}
    try:
        ps_script = (
            "$items = @(" + ", ".join("'" + p.replace("'", "''") + "'" for p in unique) + "); "
            "Get-AuthenticodeSignature -FilePath $items | ForEach-Object { "
            "Write-Output ($_.Path + '|' + $_.Status + '|' + $_.SignerCertificate.Subject) }"
        )
        cp = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script],
            capture_output=True, text=True, timeout=60, errors="replace",
        )
        result: dict[str, tuple[bool, str]] = {}
        for line in cp.stdout.splitlines():
            parts = line.split("|", 2)
            if len(parts) < 2:
                continue
            path, status = parts[0].strip(), parts[1].strip()
            subject = parts[2].strip() if len(parts) == 3 else ""
            result[path] = (status == "Valid", subject)
        return result
    except Exception:
        return {}


def _expand_driver_path(path: str) -> str:
    if not path:
        return ""
    if path.startswith("\\SystemRoot\\"):
        roots = os.environ.get("SystemRoot", "C:\\Windows")
        path = roots + path[len("\\SystemRoot"):]
    path = path.replace("\\SystemRoot\\", os.environ.get("SystemRoot", "C:\\Windows") + "\\")
    path = path[4:] if path.startswith("\\??\\") else path
    return path.replace("/", "\\")


def _signature_known_vulnerable(path: str) -> bool:
    base = os.path.basename(path or "").lower()
    return base in {"capcom.sys", "dbk64.sys", "truesight.sys", "IObitUnlocker.sys", "procmon.sys_old"}


def lotl_rows() -> list[dict[str, Any]]:
    vectors = [
        ("dual-use", "cmd.exe /c", r"C:\Windows\System32\cmd.exe", "documented LOTL chaining layer"),
        ("remote-transfer", "bitsadmin", r"C:\Windows\System32\bitsadmin.exe", "documented stager semantics"),
        ("signed-abuse", "rundll32.exe", r"C:\Windows\System32\rundll32.exe", "unsigned DLL invocation surface"),
        ("signed-abuse", "regsvr32.exe", r"C:\Windows\System32\regsvr32.exe", "COM registration abuse surface"),
        ("admin", "wmic.exe", r"C:\Windows\System32\wbem\wmic.exe", "deprecated but present"),
        ("admin", "powershell.exe -enc", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "encoded-command surface"),
        ("dual-use", "certutil -decode", r"C:\Windows\System32\certutil.exe", "encode/decode persistence"),
        ("network", "mshta.exe", r"C:\Windows\System32\mshta.exe", "HTML application surface"),
    ]
    rows = []
    for category, vector, path, detail in vectors:
        present = os.path.isfile(path)
        rows.append({
            "category": category,
            "vector": vector,
            "path": path,
            "exploitable": present,
            "detail": detail if present else "binary not present on this host",
        })
    return rows