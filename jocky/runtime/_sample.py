"""Deterministic synthetic rows used when JOCKY_SAMPLE_DATA=1 (tests)."""

from __future__ import annotations

SAMPLE_PROCESSES = [
    {"pid": 4, "ppid": 0, "name": "System", "exe": "ntoskrnl.exe",
     "username": "SYSTEM", "created": "2026-01-01T00:00:00Z", "threads": 45},
    {"pid": 452, "ppid": 4, "name": "svchost.exe", "exe": r"C:\Windows\System32\svchost.exe",
     "username": "SYSTEM", "created": "2026-01-01T00:00:05Z", "threads": 21},
    {"pid": 812, "ppid": 4, "name": "winlogon.exe", "exe": r"C:\Windows\System32\winlogon.exe",
     "username": "SYSTEM", "created": "2026-01-01T00:00:07Z", "threads": 6},
    {"pid": 1204, "ppid": 812, "name": "VBoxService.exe", "exe": r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe",
     "username": "SYSTEM", "created": "2026-01-01T00:00:08Z", "threads": 9},
    {"pid": 1488, "ppid": 452, "name": "dwm.exe", "exe": r"C:\Windows\System32\dwm.exe",
     "username": "DWM-1", "created": "2026-01-01T00:00:12Z", "threads": 12},
    {"pid": 1620, "ppid": 1204, "name": "VBoxTray.exe", "exe": r"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxTray.exe",
     "username": "Loq", "created": "2026-01-01T00:00:13Z", "threads": 5},
]

SAMPLE_NETWORK = [
    {"pid": 452, "process_name": "svchost.exe", "state": "ESTABLISHED",
     "local_addr": "10.0.2.15", "local_port": 50042,
     "remote_addr": "151.101.2.132", "remote_port": 443,
     "remote_hostname": "cdn.example-cdn.net", "direction": "outbound"},
    {"pid": 4, "process_name": "System", "state": "LISTEN",
     "local_addr": "0.0.0.0", "local_port": 445,
     "remote_addr": "0.0.0.0", "remote_port": 0,
     "remote_hostname": "", "direction": "inbound"},
    {"pid": 812, "process_name": "winlogon.exe", "state": "CLOSE_WAIT",
     "local_addr": "10.0.2.15", "local_port": 5041,
     "remote_addr": "8.8.8.8", "remote_port": 53,
     "remote_hostname": "dns.google", "direction": "outbound"},
]

SAMPLE_SERVICES = [
    {"name": "wuauserv", "display": "Windows Update", "state": "RUNNING",
     "start_type": "AUTO_START", "path": r"C:\Windows\system32\svchost.exe -k netsvcs", "pid": 452},
    {"name": "LanmanServer", "display": "Server", "state": "RUNNING",
     "start_type": "AUTO_START", "path": r"C:\Windows\system32\svchost.exe -k netsvcs", "pid": 452},
    {"name": "Spooler", "display": "Print Spooler", "state": "STOPPED",
     "start_type": "AUTO_START", "path": r"C:\Windows\System32\spoolsv.exe", "pid": -1},
]

SAMPLE_DRIVERS = [
    {"name": "VBoxGuest", "path": r"C:\Windows\System32\drivers\VBoxGuest.sys",
     "signed": True, "signer": "Oracle Corporation", "state": "RUNNING", "known_vulns": False},
    {"name": "Null", "path": r"C:\Windows\System32\drivers\Null.sys",
     "signed": True, "signer": "Microsoft Windows", "state": "RUNNING", "known_vulns": False},
]

SAMPLE_AUTOSTARTS = [
    {"name": "VBoxTray", "command": r'"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxTray.exe"',
     "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "enabled": True, "user": "Loq"},
    {"name": "OneDriveSetup", "command": r"C:\Windows\SysWOW64\OneDriveSetup.exe",
     "location": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "enabled": True, "user": "SYSTEM"},
]

SAMPLE_EVENTS = [
    {"channel": "Application", "event_id": 1001, "level": 4,
     "provider": "Windows Error Reporting", "message": "crash bucket", "observed_at": "2026-09-29T02:11:00Z"},
    {"channel": "System", "event_id": 7045, "level": 4,
     "provider": "Service Control Manager", "message": "A service was installed", "observed_at": "2026-09-29T03:40:00Z"},
]

SAMPLE_LOTL = [
    {"category": "dual-use", "vector": "cmd.exe", "path": r"C:\Windows\System32\cmd.exe",
     "exploitable": True, "detail": "present and unconstrained"},
    {"category": "remote", "vector": "bitsadmin", "path": r"C:\Windows\System32\bitsadmin.exe",
     "exploitable": True, "detail": "present and unconstrained"},
    {"category": "signed-abuse", "vector": "rundll32.exe", "path": r"C:\Windows\System32\rundll32.exe",
     "exploitable": True, "detail": "present and unconstrained"},
]

SAMPLE_REGISTRY = [
    {"hive": "HKCU", "path": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
     "name": "VBoxTray", "value": r'"C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxTray.exe"',
     "value_type": "REG_SZ"},
    {"hive": "HKLM", "path": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
     "name": "SecurityHealth", "value": r"C:\Windows\system32\SecurityHealthSystray.exe",
     "value_type": "REG_SZ"},
    {"hive": "HKLM", "path": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
     "name": "Shell", "value": "explorer.exe", "value_type": "REG_SZ"},
]

SAMPLE_SERVICECONFIG = [
    {"name": "wuauserv", "display": "Windows Update",
     "start_type": "AUTO_START", "path": r"C:\Windows\system32\svchost.exe -k netsvcs",
     "account": "LocalSystem", "binary_path": r"C:\Windows\system32\svchost.exe -k netsvcs"},
    {"name": "LanmanServer", "display": "Server",
     "start_type": "AUTO_START", "path": r"C:\Windows\system32\svchost.exe -k netsvcs",
     "account": "LocalSystem", "binary_path": r"C:\Windows\system32\svchost.exe -k netsvcs"},
]

SAMPLE_IDENTITY = [
    {"user": "lab-operator", "domain": "LAB", "sid": "S-1-5-21-1111111111-2222222222-3333333333-1001",
     "privileges": "none", "hostname": "jocky-lab"},
]