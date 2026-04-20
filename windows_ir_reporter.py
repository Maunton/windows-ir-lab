#!/usr/bin/env python3
"""
Windows Incident Response Reporter

Collects and analyzes Windows security-relevant evidence from live event logs and
browser artifacts, then writes a Markdown report and JSON output.

Works best when run from an elevated command prompt on Windows 10/11 with:
- Security auditing for process creation enabled (4688)
- Command-line process auditing enabled
- PowerShell script block logging enabled
- Sysmon installed and configured (optional, but strongly recommended)

The script intentionally uses only Python's standard library and built-in Windows
PowerShell, so you don't need third-party Python packages.
"""
from __future__ import annotations

import argparse
import ctypes
import csv
import datetime as dt
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
import urllib.parse
import html
import winreg

UTC = dt.timezone.utc

SUSPICIOUS_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "schtasks.exe", "msiexec.exe", "installutil.exe", "curl.exe",
    "ftp.exe", "tftp.exe", "hh.exe", "control.exe"
}

SUSPICIOUS_CMD_PATTERNS = [
    r"-enc(odedcommand)?\b",
    r"frombase64string",
    r"invoke-expression|\biex\b",
    r"downloadstring|downloadfile",
    r"invoke-webrequest|\biwr\b",
    r"start-bitstransfer",
    r"http://",
    r"\\\\[^\\]+\\",
    r"regsvr32.*scrobj\.dll",
    r"rundll32.*url\.dll",
    r"mshta\s+(http|https|javascript:)",
    r"certutil.*-urlcache",
    r"powershell.*-w\s+hidden",
]

SUSPICIOUS_PS_PATTERNS = [
    r"frombase64string",
    r"invoke-expression|\biex\b",
    r"downloadstring|downloadfile",
    r"invoke-webrequest|\biwr\b",
    r"new-object\s+net\.webclient",
    r"start-bitstransfer",
    r"add-mppreference",
    r"set-mppreference",
    r"amsi",
    r"reflection\.assembly",
    r"invoke-shellcode",
]

POWERSHELL_PARENT_NAMES = {"powershell.exe", "pwsh.exe", "powershell_ise.exe"}

SCRIPTBLOCK_NOISE_PATTERNS = [
    re.compile(r"^prompt$", re.I),
    re.compile(r"^\{\s*Set-StrictMode -Version 1; \$this\.DisplayHint\s*\}$", re.I),
    re.compile(r"^@\{\s*GUID\s*=.*Author\s*=.*CompanyName\s*=", re.I | re.S),
    re.compile(r"^\s*#requires -version 3\.0.*\$script:MyInvocation", re.I | re.S),
    re.compile(r"Cmdletization", re.I),
]

SELF_SCRIPTBLOCK_PATTERNS = [
    re.compile(r"windows_ir_reporter(?:_v\d+)?\.py", re.I),
    re.compile(r"\$ErrorActionPreference\s*=\s*'Stop'.*Get-WinEvent -ListLog", re.I | re.S),
    re.compile(r"\$ErrorActionPreference\s*=\s*'Stop'.*ConvertTo-Json -Depth", re.I | re.S),
    re.compile(r"Get-CimInstance\s+Win32_", re.I),
    re.compile(r"Get-MpComputerStatus", re.I),
    re.compile(r"Get-Service\s*\|\s*Where-Object\s*\{.*Bitdefender", re.I | re.S),
    re.compile(r"Get-Service\s*-ErrorAction\s+SilentlyContinue.*sysmon", re.I | re.S),
    re.compile(r"\$global:\\?", re.I),
    re.compile(r"Set-Alias -Name (gcls|ncso|gcms|rcms)", re.I),
]

USER_INTERACTIVE_PARENTS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "explorer.exe", "chrome.exe",
    "msedge.exe", "outlook.exe", "winword.exe", "excel.exe", "acrord32.exe",
    "code.exe", "python.exe"
}

BACKGROUND_PARENT_NAMES = {"svchost.exe", "services.exe", "searchindexer.exe", "taskhostw.exe"}

SUSPICIOUS_URL_EXTENSIONS = {
    ".exe", ".dll", ".js", ".jse", ".vbs", ".vbe", ".hta", ".ps1", ".psm1",
    ".bat", ".cmd", ".scr", ".msi", ".iso", ".img", ".lnk", ".zip", ".rar",
    ".7z", ".cab"
}

SUSPICIOUS_PATH_SUBSTRINGS = [
    r"\\users\\public\\",
    r"\\appdata\\local\\temp\\",
    r"\\appdata\\roaming\\",
    r"\\downloads\\",
    r"\\programdata\\",
    r"\\recycle\.bin\\",
    r"\\temp\\",
]

RUN_KEY_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]

BROWSER_HISTORY_PATHS = {
    "Edge": Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft/Edge/User Data/Default/History",
    "Chrome": Path(os.environ.get("LOCALAPPDATA", "")) / "Google/Chrome/User Data/Default/History",
}

SECURITY_IDS = [4688, 4689, 4624, 4625, 4648, 4697, 4698, 4702, 4719, 1102, 5156]
SYSTEM_IDS = [41, 1074, 6005, 6006, 6008, 7045]
DEFENDER_IDS = [1006, 1007, 1116, 1117, 1118, 1119]
POWERSHELL_IDS = [4103, 4104]
SYSMON_IDS = [1, 2, 3, 5, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 22, 25, 26, 29]
SYSMON_EXTENDED_IDS = [2, 5, 8, 10, 11, 12, 13, 14, 15, 17, 18, 19, 20, 21, 25, 26, 29]
SYSMON_EXTENDED_EVENT_NAMES = {
    2: "FileCreateTime",
    5: "ProcessTerminate",
    8: "CreateRemoteThread",
    10: "ProcessAccess",
    11: "FileCreate",
    12: "RegistryEvent",
    13: "RegistryEvent",
    14: "RegistryEvent",
    15: "FileCreateStreamHash",
    17: "PipeEvent",
    18: "PipeEvent",
    19: "WmiEvent",
    20: "WmiEvent",
    21: "WmiEvent",
    25: "ProcessTampering",
    26: "FileDeleteDetected",
    29: "FileExecutableDetected",
}
SYSMON_EXTENDED_REASON_MAP = {
    2: "File creation time change visibility",
    5: "Process termination visibility",
    8: "Remote thread creation / possible injection visibility",
    10: "Cross-process access visibility",
    11: "File creation visibility",
    12: "Registry create/delete visibility",
    13: "Registry value set visibility",
    14: "Registry rename visibility",
    15: "Alternate data stream / stream hash visibility",
    17: "Named pipe creation visibility",
    18: "Named pipe connection visibility",
    19: "WMI filter visibility",
    20: "WMI consumer visibility",
    21: "WMI binding visibility",
    25: "Process tampering visibility",
    26: "File delete detected visibility",
    29: "Executable file detected visibility",
}
SYSMON_EXTENDED_SCORE = {
    2: 1, 5: 1, 8: 5, 10: 4, 11: 2, 12: 2, 13: 2, 14: 2, 15: 2,
    17: 2, 18: 2, 19: 4, 20: 4, 21: 4, 25: 5, 26: 3, 29: 4,
}


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def powershell_available() -> bool:
    return shutil.which("powershell") is not None or shutil.which("pwsh") is not None


def run_powershell(script: str) -> str:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        raise RuntimeError("PowerShell was not found in PATH.")
    proc = subprocess.run(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or "PowerShell command failed")
    return proc.stdout


def to_jsonish(data: Any) -> Any:
    if isinstance(data, str):
        try:
            return json.loads(data)
        except Exception:
            return data
    return data


def ps_escape(s: str) -> str:
    return s.replace("'", "''")


def collect_event_log(log_name: str, event_ids: List[int], days: int, max_events: int) -> Dict[str, Any]:
    ids = ",".join(str(i) for i in event_ids)
    script = rf"""
$ErrorActionPreference = 'Stop'
$logName = '{ps_escape(log_name)}'
$start = (Get-Date).AddDays(-{days})
if (-not (Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue)) {{
  [PSCustomObject]@{{ log=$logName; exists=$false; events=@() }} | ConvertTo-Json -Depth 8 -Compress
  exit 0
}}
$events = Get-WinEvent -FilterHashtable @{{LogName=$logName; Id=@({ids}); StartTime=$start}} -ErrorAction SilentlyContinue |
  Select-Object -First {max_events} |
  ForEach-Object {{
    $xml = [xml]$_.ToXml()
    $data = [ordered]@{{}}
    foreach ($d in $xml.Event.EventData.Data) {{
      $key = if ($d.Name) {{ [string]$d.Name }} else {{ 'Data' }}
      $value = [string]$d.'#text'
      if ($data.Contains($key)) {{
        $data[$key] = [string]$data[$key] + '; ' + $value
      }} else {{
        $data[$key] = $value
      }}
    }}
    [PSCustomObject]@{{
      TimeCreated = $_.TimeCreated.ToString('o')
      Id = $_.Id
      ProviderName = $_.ProviderName
      RecordId = $_.RecordId
      LevelDisplayName = $_.LevelDisplayName
      MachineName = $_.MachineName
      Message = $_.Message
      Data = $data
    }}
  }}
[PSCustomObject]@{{ log=$logName; exists=$true; events=$events }} | ConvertTo-Json -Depth 8 -Compress
"""
    raw = run_powershell(script).strip()
    return to_jsonish(raw)


def collect_basic_system_info() -> Dict[str, Any]:
    script = r"""
$cs = Get-CimInstance Win32_ComputerSystem
$os = Get-CimInstance Win32_OperatingSystem
$bios = Get-CimInstance Win32_BIOS
$bd = Get-Service | Where-Object { $_.DisplayName -match 'Bitdefender' -or $_.Name -match '^bd' } | Select-Object Name,DisplayName,Status,StartType
$sysmonSvc = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'sysmon*' -or $_.DisplayName -like '*Sysmon*' } | Select-Object Name,DisplayName,Status,StartType
$defenderStatus = $null
if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) {
  try {
    $defenderStatus = Get-MpComputerStatus | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AMRunningMode,AntivirusSignatureLastUpdated
  } catch {}
}
[PSCustomObject]@{
  ComputerName = $env:COMPUTERNAME
  UserName = $env:USERNAME
  Domain = $env:USERDOMAIN
  Manufacturer = $cs.Manufacturer
  Model = $cs.Model
  OS = $os.Caption
  Version = $os.Version
  BuildNumber = $os.BuildNumber
  InstallDate = $os.InstallDate
  LastBootUpTime = $os.LastBootUpTime
  BIOSVersion = ($bios.SMBIOSBIOSVersion -join '; ')
  BitdefenderServices = $bd
  SysmonServices = $sysmonSvc
  DefenderStatus = $defenderStatus
} | ConvertTo-Json -Depth 6 -Compress
"""
    return to_jsonish(run_powershell(script).strip())


def parse_iso(ts: Optional[str]) -> Optional[dt.datetime]:
    if not ts:
        return None
    try:
        return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def normalize_list(obj: Any) -> List[Dict[str, Any]]:
    if obj is None:
        return []
    if isinstance(obj, list):
        return obj
    if isinstance(obj, dict):
        return [obj]
    return []


def safe_lower(value: Optional[str]) -> str:
    return (value or "").lower()


def suspicious_path(path: str) -> bool:
    p = safe_lower(path)
    return any(re.search(pattern, p) for pattern in SUSPICIOUS_PATH_SUBSTRINGS)


def suspicious_command_line(cmd: str) -> List[str]:
    hits = []
    for pat in SUSPICIOUS_CMD_PATTERNS:
        if re.search(pat, cmd, re.IGNORECASE):
            hits.append(pat)
    return hits


def suspicious_powershell(text: str) -> List[str]:
    hits = []
    for pat in SUSPICIOUS_PS_PATTERNS:
        if re.search(pat, text, re.IGNORECASE):
            hits.append(pat)
    return hits


def get_event_data(event: Dict[str, Any]) -> Dict[str, Any]:
    return event.get("Data") or {}


def get_process_fields(event: Dict[str, Any]) -> Dict[str, str]:
    data = get_event_data(event)
    image = data.get("Image") or data.get("NewProcessName") or ""
    command = data.get("CommandLine") or data.get("ProcessCommandLine") or ""
    parent = data.get("ParentImage") or data.get("CreatorProcessName") or data.get("ParentProcessName") or ""
    user = data.get("SubjectUserName") or data.get("User") or data.get("UserName") or ""
    parent_image = Path(parent).name.lower() if parent else ""
    image_name = Path(image).name.lower() if image else ""
    return {
        "image": image,
        "image_name": image_name,
        "command": command,
        "parent": parent,
        "parent_name": parent_image,
        "user": user,
    }


def extract_scriptblock_text(message: str) -> str:
    if not message:
        return ""
    m = re.search(r"Creating Scriptblock text \(\d+ of \d+\):\s*(.*?)\s*ScriptBlock ID:", message, re.S)
    if m:
        return m.group(1).strip()
    return message.strip()


def looks_like_user_scriptblock(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return False
    for pat in SCRIPTBLOCK_NOISE_PATTERNS:
        if pat.search(stripped):
            return False
    return True


def is_self_collection_scriptblock(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return False
    return any(pat.search(stripped) for pat in SELF_SCRIPTBLOCK_PATTERNS)


def is_machine_account(user: str) -> bool:
    return (user or "").endswith("$")


def is_reporter_self_process(fields: Dict[str, str]) -> bool:
    image_name = fields["image_name"]
    parent_name = fields["parent_name"]
    command = safe_lower(fields["command"])
    image = safe_lower(fields["image"])
    parent = safe_lower(fields["parent"])

    if "windows_ir_reporter.py" in command or "windows_ir_reporter_v2.py" in command or "windows_ir_reporter_v3.py" in command:
        return True
    if image_name in {"powershell.exe", "pwsh.exe"} and "get-winevent -listlog" in command:
        return True
    if image_name in {"powershell.exe", "pwsh.exe"} and "get-ciminstance win32_" in command:
        return True
    if image_name in {"powershell.exe", "pwsh.exe"} and "convertto-json -depth" in command:
        return True
    if image_name == "powershell.exe" and parent_name == "python.exe" and ("get-winevent" in command or "get-ciminstance" in command):
        return True
    if image_name == "pwsh.exe" and parent_name == "code.exe" and "-noexit" in command:
        return True
    if "windows-ir-lab" in image and image_name == "python.exe":
        return True
    if "windows-ir-lab" in parent and parent_name == "python.exe":
        return True
    return False


def process_interest_score(fields: Dict[str, str]) -> int:
    score = 0
    image_name = fields["image_name"]
    parent_name = fields["parent_name"]
    user = fields["user"]
    command = fields["command"]

    if is_reporter_self_process(fields):
        return -50
    if user and not is_machine_account(user):
        score += 4
    if parent_name in USER_INTERACTIVE_PARENTS:
        score += 3
    if image_name in SUSPICIOUS_PROCESS_NAMES:
        score += 3
    if image_name in {"notepad.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "python.exe", "chrome.exe", "msedge.exe"}:
        score += 2
    if command:
        score += 1
    if parent_name in BACKGROUND_PARENT_NAMES:
        score -= 3
    if image_name in {"backgroundtaskhost.exe", "runtimebroker.exe", "searchprotocolhost.exe", "dllhost.exe", "wermgr.exe", "conhost.exe"} and parent_name in BACKGROUND_PARENT_NAMES | {"hp-plugin-executor.exe"}:
        score -= 2
    return score


def is_devtool_noise_process(fields: Dict[str, str]) -> bool:
    image_name = fields["image_name"]
    parent_name = fields["parent_name"]
    command = safe_lower(fields["command"])
    image = safe_lower(fields["image"])

    if parent_name == "code.exe":
        if image_name == "cmd.exe" and ("wsl.exe -l -q" in command or "pyenv which python" in command):
            return True
        if image_name == "python.exe" and (
            ".vscode\\extensions" in command
            or "normalize = lambda p:" in command
            or "os.urandom(32).hex()" in command
            or "os.urandom(3" in command
        ):
            return True
        if image_name in {"pwsh.exe", "powershell.exe"} and "-noexit" in command:
            return True
    if image_name == "conhost.exe" and parent_name in {"python.exe", "pwsh.exe", "code.exe"} and "0xffffffff -forcev1" in command:
        return True
    if image_name == "python.exe" and ".vscode\\extensions" in command:
        return True
    if image_name == "cmd.exe" and parent_name == "code.exe" and "/d /s /c" in command:
        return True
    if "python312\\python.exe" in image and parent_name == "code.exe" and ".vscode" in command:
        return True
    return False


def is_background_scriptblock(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return True
    if is_self_collection_scriptblock(stripped):
        return True
    if not looks_like_user_scriptblock(stripped):
        return True
    if re.search(r"RootModule\s*=\s*'PSModule\.psm1'", stripped, re.I):
        return True
    if re.search(r"Set-Alias -Name (?:ncms|rcie|gcai|icim|rcim|ncim|scim|gcim|gcls|ncso|gcms|rcms)\b", stripped, re.I):
        return True
    if re.fullmatch(r"\$Host", stripped):
        return True
    if re.fullmatch(r"\$global:\\?", stripped):
        return True
    return False


def normalized_process_summary(fields: Dict[str, str]) -> str:
    image_name = Path(fields["image"]).name or fields["image_name"]
    parent_name = Path(fields["parent"]).name or fields["parent_name"]
    if fields["command"]:
        return f"{image_name} <= {parent_name} | {short(fields['command'], 180)}"
    return f"{image_name} <= {parent_name}"


def normalized_sysmon_network_summary(event: Dict[str, Any]) -> Tuple[str, str, str]:
    data = get_event_data(event)
    image = data.get("Image") or ""
    image_name = Path(image).name
    if int(event.get("Id", 0)) == 22:
        query = data.get("QueryName") or data.get("QueryResults") or ""
        summary = f"{image_name or 'process'} DNS {short(query, 180)}"
        detail = query
        kind = "dns"
    else:
        target = data.get("DestinationHostname") or data.get("DestinationIp") or ""
        port = data.get("DestinationPort") or ""
        extra = f":{port}" if port else ""
        summary = f"{image_name or 'process'} NET {short(str(target) + extra, 180)}"
        detail = f"{target}{extra}"
        kind = "network"
    return kind, summary, detail



def summarize_sysmon_extended_event(event: Dict[str, Any]) -> Tuple[str, str, str, str, int]:
    data = get_event_data(event)
    event_id = int(event.get("Id", 0))
    event_name = SYSMON_EXTENDED_EVENT_NAMES.get(event_id, f"Sysmon {event_id}")
    image = data.get("Image") or data.get("SourceImage") or data.get("ParentImage") or ""
    image_name = Path(image).name or "process"
    score = SYSMON_EXTENDED_SCORE.get(event_id, 1)
    reason = SYSMON_EXTENDED_REASON_MAP.get(event_id, "Extended Sysmon telemetry")

    if event_id == 2:
        target = data.get("TargetFilename") or ""
        summary = f"{image_name} changed file creation time for {short(target or 'a file', 140)}"
    elif event_id == 5:
        summary = f"{image_name} terminated"
    elif event_id == 8:
        src = Path(data.get("SourceImage") or image).name or image_name
        dst = Path(data.get("TargetImage") or "").name or "target process"
        start = data.get("StartModule") or data.get("StartFunction") or data.get("StartAddress") or ""
        extra = f" at {start}" if start else ""
        summary = f"{src} created remote thread in {dst}{extra}"
    elif event_id == 10:
        src = Path(data.get("SourceImage") or image).name or image_name
        dst = Path(data.get("TargetImage") or "").name or "target process"
        granted = data.get("GrantedAccess") or ""
        extra = f" (GrantedAccess {granted})" if granted else ""
        summary = f"{src} accessed {dst}{extra}"
    elif event_id == 11:
        target = data.get("TargetFilename") or ""
        summary = f"{image_name} created file {short(target or 'unknown file', 140)}"
    elif event_id in {12, 13, 14}:
        target = data.get("TargetObject") or ""
        etype = data.get("EventType") or event_name
        summary = f"Registry change ({etype}) {short(target or 'registry object', 140)}"
        if _is_cert_store_createkey_event(event_id, etype, target) and not _summary_mentions_thumbprint_like_subkey(target):
            score = 0
            reason = "Likely certificate trust-store initialization"
    elif event_id == 15:
        target = data.get("TargetFilename") or ""
        hashv = data.get("Hash") or ""
        extra = f" [{short(hashv, 40)}]" if hashv else ""
        summary = f"{image_name} created stream/hash for {short(target or 'file', 120)}{extra}"
    elif event_id in {17, 18}:
        pipe = data.get("PipeName") or ""
        action = "created" if event_id == 17 else "connected to"
        summary = f"{image_name} {action} pipe {short(pipe or 'unknown pipe', 140)}"
    elif event_id in {19, 20, 21}:
        name = data.get("Name") or data.get("Consumer") or data.get("Filter") or data.get("Destination") or ""
        summary = f"WMI activity ({event_name}) {short(name or 'WMI object', 140)}"
    elif event_id == 25:
        t = data.get("Type") or data.get("TamperType") or ""
        extra = f" ({t})" if t else ""
        summary = f"{image_name} process tampering detected{extra}"
    elif event_id == 26:
        target = data.get("TargetFilename") or ""
        summary = f"Deleted file detected: {short(target or 'unknown file', 140)}"
    elif event_id == 29:
        target = data.get("TargetFilename") or data.get("Image") or ""
        summary = f"Executable file detected: {short(target or 'unknown executable', 140)}"
    else:
        summary = f"{event_name}: {short(json.dumps(data, ensure_ascii=False), 160)}"

    detail = json.dumps(data, ensure_ascii=False)
    return event_name, image, summary, reason, score


def classify_activity_event(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    kind = item.get("kind")
    reasons: List[str] = []

    if kind == "process":
        fields = item.get("fields") or {}
        image_name = fields.get("image_name", "")
        parent_name = fields.get("parent_name", "")
        user = fields.get("user", "")
        command = fields.get("command", "")

        if is_reporter_self_process(fields):
            reasons.append("collector self-activity")
            return "background", reasons
        if is_devtool_noise_process(fields):
            reasons.append("development tool helper activity")
            return "background", reasons
        if user and not is_machine_account(user):
            reasons.append("interactive user account")
        if parent_name in POWERSHELL_PARENT_NAMES | {"cmd.exe", "explorer.exe"}:
            reasons.append(f"interactive parent: {parent_name}")
        if image_name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append("script host / LOLBin / admin tool")
        if command and suspicious_command_line(command):
            reasons.append("command line matches suspicious/admin patterns")
        if is_machine_account(user) or parent_name in BACKGROUND_PARENT_NAMES:
            reasons.append("service/background parent or machine account")
            return "background", reasons
        if parent_name in POWERSHELL_PARENT_NAMES | {"cmd.exe", "explorer.exe", "chrome.exe", "msedge.exe", "outlook.exe", "winword.exe", "excel.exe"}:
            return "likely_user", reasons
        if image_name in {"notepad.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "chrome.exe", "msedge.exe"} and user and not is_machine_account(user):
            return "likely_user", reasons
        if process_interest_score(fields) >= 7:
            return "likely_user", reasons
        return "background", reasons

    if kind == "scriptblock":
        text = item.get("detail", "")
        if is_background_scriptblock(text):
            reasons.append("module / helper / collector script block")
            return "background", reasons
        reasons.append("user-entered script block")
        if suspicious_powershell(text):
            reasons.append("contains dual-use or suspicious keywords")
        return "likely_user", reasons

    if kind in {"dns", "network"}:
        image_name = safe_lower(item.get("image_name"))
        detail = item.get("detail", "")
        if image_name in {"powershell.exe", "pwsh.exe", "cmd.exe", "chrome.exe", "msedge.exe", "outlook.exe", "winword.exe", "excel.exe"}:
            reasons.append(f"interactive process generated {kind}")
            return "likely_user", reasons
        if "example.com" in safe_lower(detail):
            reasons.append("manual test destination")
            return "likely_user", reasons
        reasons.append("background or service-generated network activity")
        return "background", reasons

    if kind == "other":
        image_name = safe_lower(item.get("image_name"))
        summary = safe_lower(item.get("summary", ""))
        detail = safe_lower(item.get("detail", ""))
        if _summary_mentions_cert_store_init(item.get("summary", "")) and not _summary_mentions_thumbprint_like_subkey(item.get("summary", "")):
            reasons.append("certificate trust-store initialization")
            return "background", reasons
        if image_name in {"powershell.exe", "pwsh.exe", "cmd.exe"}:
            reasons.append("interactive process generated extended sysmon telemetry")
            return "likely_user", reasons
        if "example.com" in summary or "example.com" in detail:
            reasons.append("manual test destination")
            return "likely_user", reasons
        reasons.append("extended sysmon telemetry")
        return "background", reasons

    reasons.append("uncategorized")
    return "background", reasons


def build_activity_views(
    security_events: List[Dict[str, Any]],
    ps_events: List[Dict[str, Any]],
    sysmon_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []

    for event in security_events:
        if int(event.get("Id", 0)) != 4688:
            continue
        fields = get_process_fields(event)
        items.append({
            "time": event.get("TimeCreated"),
            "source": "Security 4688",
            "kind": "process",
            "actor": fields.get("user", ""),
            "image": fields.get("image", ""),
            "image_name": fields.get("image_name", ""),
            "parent": fields.get("parent", ""),
            "summary": normalized_process_summary(fields),
            "detail": fields.get("command", "") or fields.get("image", ""),
            "fields": fields,
        })

    for event in ps_events:
        if int(event.get("Id", 0)) != 4104:
            continue
        text = extract_scriptblock_text(event.get("Message") or "")
        items.append({
            "time": event.get("TimeCreated"),
            "source": "PowerShell 4104",
            "kind": "scriptblock",
            "actor": "",
            "image": "powershell.exe",
            "image_name": "powershell.exe",
            "parent": "",
            "summary": short(text, 180),
            "detail": text,
            "fields": {},
        })

    for event in sysmon_events:
        event_id = int(event.get("Id", 0))
        data = get_event_data(event)
        if event_id in {3, 22}:
            kind, summary, detail = normalized_sysmon_network_summary(event)
            image = data.get("Image") or ""
        elif event_id in SYSMON_EXTENDED_IDS:
            event_name, image, summary, detail_reason, _score = summarize_sysmon_extended_event(event)
            kind = "other"
            detail = detail_reason + " :: " + json.dumps(data, ensure_ascii=False)
            if event_id in {25, 26, 29}:
                kind = "other"
        else:
            continue
        image_name = Path(image).name.lower() if image else ""
        items.append({
            "time": event.get("TimeCreated"),
            "source": f"Sysmon {event_id}",
            "kind": kind,
            "actor": "",
            "image": image,
            "image_name": image_name,
            "parent": "",
            "summary": summary,
            "detail": detail,
            "fields": data,
        })

    for item in items:
        category, reasons = classify_activity_event(item)
        item["category"] = category
        item["reasons"] = reasons

    likely_minutes = {
        minute_bucket(item.get("time"))
        for item in items
        if item.get("category") == "likely_user" and item.get("kind") in {"process", "scriptblock"}
    }
    for item in items:
        minute = minute_bucket(item.get("time"))
        if item.get("kind") in {"dns", "network"} and item.get("category") == "background" and minute in likely_minutes:
            item["reasons"] = item.get("reasons", []) + ["same-minute proximity to likely user activity"]
        item["minute"] = minute

    def sort_key(item: Dict[str, Any]) -> float:
        parsed = parse_iso(item.get("time"))
        return parsed.timestamp() if parsed else 0.0

    items.sort(key=sort_key, reverse=True)

    likely_user = [i for i in items if i.get("category") == "likely_user"]
    background = [i for i in items if i.get("category") != "likely_user"]

    return {
        "likely_user_actions": likely_user,
        "background_activity": background,
        "full_raw_timeline": items,
    }


def minute_bucket(ts: Optional[str]) -> Optional[str]:
    parsed = parse_iso(ts)
    if not parsed:
        return None
    return parsed.replace(second=0, microsecond=0).isoformat()


def flatten_event(log_blob: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(log_blob, dict):
        return []
    return normalize_list(log_blob.get("events"))


def collect_browser_history(days: int, max_rows: int) -> Dict[str, Any]:
    cutoff_utc = dt.datetime.now(UTC) - dt.timedelta(days=days)
    results: Dict[str, Any] = {}

    for browser, path in BROWSER_HISTORY_PATHS.items():
        browser_data = {"exists": False, "urls": [], "downloads": [], "error": None}
        if not path.exists():
            results[browser] = browser_data
            continue
        browser_data["exists"] = True
        temp_copy = None
        try:
            fd, temp_name = tempfile.mkstemp(prefix=f"{browser.lower()}_history_", suffix=".db")
            os.close(fd)
            temp_copy = Path(temp_name)
            shutil.copy2(path, temp_copy)
            con = sqlite3.connect(temp_copy)
            con.row_factory = sqlite3.Row

            url_query = """
                SELECT url, title, visit_count, last_visit_time
                FROM urls
                ORDER BY last_visit_time DESC
                LIMIT ?
            """
            download_query = """
                SELECT current_path, target_path, tab_url, referrer, start_time, received_bytes, total_bytes
                FROM downloads
                ORDER BY start_time DESC
                LIMIT ?
            """

            urls = []
            for row in con.execute(url_query, (max_rows,)):
                visited = chrome_time_to_iso(row["last_visit_time"])
                if visited and parse_iso(visited) and parse_iso(visited) >= cutoff_utc:
                    urls.append({
                        "url": row["url"],
                        "title": row["title"],
                        "visit_count": row["visit_count"],
                        "visited_at": visited,
                    })

            downloads = []
            try:
                for row in con.execute(download_query, (max_rows,)):
                    started = chrome_time_to_iso(row["start_time"])
                    if started and parse_iso(started) and parse_iso(started) >= cutoff_utc:
                        downloads.append({
                            "current_path": row["current_path"],
                            "target_path": row["target_path"],
                            "tab_url": row["tab_url"],
                            "referrer": row["referrer"],
                            "started_at": started,
                            "received_bytes": row["received_bytes"],
                            "total_bytes": row["total_bytes"],
                        })
            except sqlite3.Error:
                pass

            con.close()
            browser_data["urls"] = urls
            browser_data["downloads"] = downloads
        except Exception as e:
            browser_data["error"] = str(e)
        finally:
            if temp_copy and temp_copy.exists():
                try:
                    temp_copy.unlink()
                except Exception:
                    pass
        results[browser] = browser_data

    return results


def chrome_time_to_iso(value: Any) -> Optional[str]:
    try:
        micros = int(value)
        if micros <= 0:
            return None
        epoch = dt.datetime(1601, 1, 1, tzinfo=UTC)
        return (epoch + dt.timedelta(microseconds=micros)).isoformat()
    except Exception:
        return None


def collect_run_keys() -> List[Dict[str, str]]:
    entries = []
    for hive, path in RUN_KEY_PATHS:
        hive_name = {
            winreg.HKEY_CURRENT_USER: "HKCU",
            winreg.HKEY_LOCAL_MACHINE: "HKLM",
        }.get(hive, str(hive))
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        entries.append({
                            "location": f"{hive_name}\\{path}",
                            "name": name,
                            "value": str(value),
                        })
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
        except PermissionError:
            entries.append({
                "location": f"{hive_name}\\{path}",
                "name": "<permission denied>",
                "value": "",
            })
    return entries


def collect_startup_items() -> List[Dict[str, str]]:
    startup_dirs = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    items = []
    for d in startup_dirs:
        if d.exists():
            for p in sorted(d.iterdir()):
                items.append({
                    "location": str(d),
                    "name": p.name,
                    "value": str(p),
                })
    return items


def score_process_event(event: Dict[str, Any]) -> Tuple[int, List[str]]:
    score = 0
    reasons: List[str] = []
    fields = get_process_fields(event)
    if is_reporter_self_process(fields):
        return 0, []
    image = fields["image"]
    command = fields["command"]
    parent = fields["parent"]
    image_name = fields["image_name"]

    if image_name in SUSPICIOUS_PROCESS_NAMES:
        score += 2
        reasons.append(f"LOLBin or script host: {image_name}")
    if suspicious_path(image):
        score += 2
        reasons.append("Executed from a user/temp/downloads-type path")
    cmd_hits = suspicious_command_line(command)
    if cmd_hits:
        score += min(4, len(cmd_hits))
        reasons.append("Suspicious command line patterns")
    if parent and suspicious_path(parent):
        score += 1
        reasons.append("Parent process launched from suspicious path")
    return score, reasons


def score_persistence_entry(entry: Dict[str, str]) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    value = entry.get("value", "")
    if suspicious_path(value):
        score += 2
        reasons.append("Persistence points to user/temp/downloads-like location")
    if suspicious_command_line(value):
        score += 2
        reasons.append("Persistence command includes suspicious patterns")
    if Path(value.strip('"')).suffix.lower() in SUSPICIOUS_URL_EXTENSIONS:
        score += 1
        reasons.append("Persistence target uses a high-risk extension")
    return score, reasons


def score_url(url: str) -> Tuple[int, List[str]]:
    score = 0
    reasons = []
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""
        if parsed.scheme == "http":
            score += 1
            reasons.append("HTTP rather than HTTPS")
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
            score += 2
            reasons.append("Direct IP in URL")
        if host.startswith("xn--"):
            score += 1
            reasons.append("Punycode hostname")
        if Path(path).suffix.lower() in SUSPICIOUS_URL_EXTENSIONS:
            score += 2
            reasons.append("URL points to potentially risky download type")
        joined = f"{host}{path}?{parsed.query}"
        if re.search(r"(download|payload|update|invoice|urgent|security|signin|verify)", joined, re.I):
            score += 1
            reasons.append("URL contains phishing/malware-ish terms")
    except Exception:
        pass
    return score, reasons


def group_events_by_id(events: Iterable[Dict[str, Any]]) -> Dict[int, List[Dict[str, Any]]]:
    grouped: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for e in events:
        try:
            grouped[int(e.get("Id"))].append(e)
        except Exception:
            continue
    return grouped


def summarize_top(items: Iterable[str], limit: int = 10) -> List[Tuple[str, int]]:
    c = Counter(x for x in items if x)
    return c.most_common(limit)




def analyze(data: Dict[str, Any]) -> Dict[str, Any]:
    findings: Dict[str, Any] = {
        "high_signal_processes": [],
        "powershell_hits": [],
        "defender_hits": [],
        "persistence_hits": [],
        "browser_risks": [],
        "network_summary": {},
        "counts": {},
        "notes": [],
        "recent_4688_processes": [],
        "recent_4104_user_scriptblocks": [],
        "correlated_timeline": [],
        "likely_user_actions": [],
        "background_activity": [],
        "full_raw_timeline": [],
        "sysmon_extended_findings": [],
        "sysmon_extended_counts": [],
    }

    security_events = flatten_event(data.get("logs", {}).get("Security", {}))
    system_events = flatten_event(data.get("logs", {}).get("System", {}))
    defender_events = flatten_event(data.get("logs", {}).get("Defender", {}))
    ps_events = flatten_event(data.get("logs", {}).get("PowerShell", {})) + flatten_event(data.get("logs", {}).get("PowerShellCore", {}))
    sysmon_events = flatten_event(data.get("logs", {}).get("Sysmon", {}))

    findings["counts"] = {
        "security_events": len(security_events),
        "system_events": len(system_events),
        "defender_events": len(defender_events),
        "powershell_events": len(ps_events),
        "sysmon_events": len(sysmon_events),
        "run_key_entries": len(data.get("run_keys", [])),
        "startup_entries": len(data.get("startup_items", [])),
    }

    activity_views = build_activity_views(security_events, ps_events, sysmon_events)
    findings["likely_user_actions"] = activity_views["likely_user_actions"]
    findings["background_activity"] = activity_views["background_activity"]
    findings["full_raw_timeline"] = activity_views["full_raw_timeline"]

    process_4688 = [e for e in security_events if int(e.get("Id", 0)) == 4688]
    process_4688.sort(key=lambda e: e.get("TimeCreated") or "", reverse=True)

    recent_proc_rows: List[Dict[str, Any]] = []
    for item in findings["likely_user_actions"] + findings["background_activity"]:
        if item.get("kind") != "process":
            continue
        fields = item.get("fields") or {}
        recent_proc_rows.append({
            "time": item.get("time"),
            "user": item.get("actor") or fields.get("user", ""),
            "image": item.get("image", ""),
            "parent": item.get("parent", ""),
            "command_line": fields.get("command", "") or item.get("detail", ""),
            "interest": process_interest_score(fields) if fields else 0,
            "category": item.get("category", ""),
            "reasons": item.get("reasons", []),
        })
    findings["recent_4688_processes"] = recent_proc_rows[:40]

    recent_user_scriptblocks = []
    for item in findings["likely_user_actions"] + findings["background_activity"]:
        if item.get("kind") != "scriptblock":
            continue
        recent_user_scriptblocks.append({
            "time": item.get("time"),
            "provider": item.get("source"),
            "script_text": item.get("detail", ""),
            "interest": 5 if item.get("category") == "likely_user" else 1,
            "category": item.get("category", ""),
            "reasons": item.get("reasons", []),
        })
    findings["recent_4104_user_scriptblocks"] = recent_user_scriptblocks[:40]

    process_candidates = list(process_4688)
    process_candidates += [e for e in sysmon_events if int(e.get("Id", 0)) == 1]
    seen = set()
    for event in process_candidates:
        score, reasons = score_process_event(event)
        fields = get_process_fields(event)
        if is_devtool_noise_process(fields):
            continue
        if score < 3:
            continue
        key = (event.get("TimeCreated"), fields["image"], fields["command"])
        if key in seen:
            continue
        seen.add(key)
        findings["high_signal_processes"].append({
            "time": event.get("TimeCreated"),
            "event_id": event.get("Id"),
            "image": fields["image"],
            "command_line": fields["command"],
            "parent": fields["parent"],
            "score": score,
            "reasons": reasons,
        })

    findings["high_signal_processes"].sort(key=lambda x: (-x["score"], x.get("time") or ""))

    for event in ps_events:
        if int(event.get("Id", 0)) not in {4103, 4104}:
            continue
        msg = event.get("Message") or ""
        script_text = extract_scriptblock_text(msg) if int(event.get("Id", 0)) == 4104 else msg
        if int(event.get("Id", 0)) == 4104 and is_background_scriptblock(script_text):
            continue
        hits = suspicious_powershell(script_text)
        if not hits:
            continue
        findings["powershell_hits"].append({
            "time": event.get("TimeCreated"),
            "event_id": event.get("Id"),
            "provider": event.get("ProviderName"),
            "score": min(5, len(hits) + 1),
            "reasons": hits,
            "preview": script_text[:1200],
        })

    for event in defender_events:
        if int(event.get("Id", 0)) in {1006, 1116, 1117, 1118, 1119}:
            findings["defender_hits"].append({
                "time": event.get("TimeCreated"),
                "event_id": event.get("Id"),
                "message": (event.get("Message") or "")[:1500],
            })

    persistence_sources = []
    persistence_sources.extend(data.get("run_keys", []))
    persistence_sources.extend(data.get("startup_items", []))
    for entry in persistence_sources:
        if safe_lower(entry.get("name", "")) == "desktop.ini":
            continue
        score, reasons = score_persistence_entry(entry)
        if score >= 2:
            findings["persistence_hits"].append({
                "location": entry.get("location"),
                "name": entry.get("name"),
                "value": entry.get("value"),
                "score": score,
                "reasons": reasons,
            })

    for event in security_events:
        if int(event.get("Id", 0)) in {4697, 4698, 4702}:
            findings["persistence_hits"].append({
                "location": f"Security Event {event.get('Id')}",
                "name": (event.get("Data") or {}).get("TaskName") or (event.get("Data") or {}).get("ServiceName") or "Persistence-related event",
                "value": (event.get("Message") or "")[:1000],
                "score": 3,
                "reasons": ["Service or scheduled task creation/update event found"],
                "time": event.get("TimeCreated"),
            })

    browser_history = data.get("browser_history", {})
    for browser, browser_data in browser_history.items():
        for row in browser_data.get("urls", []):
            score, reasons = score_url(row.get("url", ""))
            if score >= 2:
                findings["browser_risks"].append({
                    "browser": browser,
                    "type": "url",
                    "time": row.get("visited_at"),
                    "value": row.get("url"),
                    "score": score,
                    "reasons": reasons,
                    "title": row.get("title"),
                })
        for row in browser_data.get("downloads", []):
            candidate = row.get("target_path") or row.get("current_path") or ""
            ext = Path(candidate).suffix.lower()
            score = 0
            reasons = []
            if ext in SUSPICIOUS_URL_EXTENSIONS:
                score += 2
                reasons.append("Downloaded potentially risky file type")
            if suspicious_path(candidate):
                score += 1
                reasons.append("Downloaded to a user-controlled path")
            if row.get("tab_url"):
                u_score, u_reasons = score_url(row["tab_url"])
                score += u_score
                reasons.extend(u_reasons)
            if score >= 2:
                findings["browser_risks"].append({
                    "browser": browser,
                    "type": "download",
                    "time": row.get("started_at"),
                    "value": candidate,
                    "source_url": row.get("tab_url"),
                    "score": score,
                    "reasons": reasons,
                })

    sysmon_grouped = group_events_by_id(sysmon_events)
    dns_queries = []
    remote_targets = []
    for ev in sysmon_grouped.get(22, []):
        d = ev.get("Data") or {}
        dns_queries.append(d.get("QueryName") or d.get("QueryResults") or "")
    for ev in sysmon_grouped.get(3, []):
        d = ev.get("Data") or {}
        remote_targets.append(d.get("DestinationHostname") or d.get("DestinationIp") or "")

    findings["network_summary"] = {
        "top_dns_queries": summarize_top(dns_queries, 15),
        "top_remote_targets": summarize_top(remote_targets, 15),
    }


    sysmon_extended_findings: List[Dict[str, Any]] = []
    sysmon_extended_counts: Counter = Counter()
    for event in sysmon_events:
        event_id = int(event.get("Id", 0))
        if event_id not in SYSMON_EXTENDED_IDS:
            continue
        event_name, image, summary, reason, score = summarize_sysmon_extended_event(event)
        sysmon_extended_counts[event_name] += 1
        sysmon_extended_findings.append({
            "time": event.get("TimeCreated"),
            "event_id": event_id,
            "event_name": event_name,
            "image": image,
            "score": score,
            "summary": summary,
            "reason": reason,
        })

    sysmon_extended_findings.sort(
        key=lambda x: (
            -int(x.get("score", 0)),
            -(parse_iso(x.get("time")).timestamp() if parse_iso(x.get("time")) else 0),
        )
    )
    findings["sysmon_extended_findings"] = sysmon_extended_findings[:80]
    findings["sysmon_extended_counts"] = [{"event_name": name, "count": count} for name, count in sysmon_extended_counts.most_common()]

    timeline_buckets: Dict[str, Dict[str, Any]] = {}
    for item in findings["full_raw_timeline"]:
        minute = item.get("minute") or minute_bucket(item.get("time"))
        if not minute:
            continue
        bucket = timeline_buckets.setdefault(
            minute,
            {"minute": minute, "likely": [], "background": [], "dns": [], "network": [], "score": 0},
        )
        rendered = short(item.get("summary") or item.get("detail", ""), 180)
        if item.get("kind") == "dns":
            if len(bucket["dns"]) < 6:
                bucket["dns"].append(rendered)
        elif item.get("kind") == "network":
            if len(bucket["network"]) < 6:
                bucket["network"].append(rendered)
        elif item.get("category") == "likely_user":
            if len(bucket["likely"]) < 6:
                bucket["likely"].append(rendered)
            bucket["score"] += 3
        else:
            if len(bucket["background"]) < 6:
                bucket["background"].append(rendered)
            bucket["score"] += 1

    timeline_rows = list(timeline_buckets.values())
    timeline_rows.sort(key=lambda x: (-x.get("score", 0), -(parse_iso(x["minute"]).timestamp() if parse_iso(x["minute"]) else 0)))
    findings["correlated_timeline"] = [
        {k: v for k, v in row.items() if k != "score"}
        for row in timeline_rows if row["likely"] or row["background"] or row["dns"] or row["network"]
    ][:25]

    if not data.get("logs", {}).get("Sysmon", {}).get("exists"):
        findings["notes"].append("Sysmon log not found. Install and configure Sysmon for better process, DNS, network, file, registry, and WMI visibility.")
    if len(process_4688) == 0:
        findings["notes"].append("No Security 4688 process creation events were collected. Enable Audit Process Creation and include command line auditing.")
    if len([e for e in ps_events if int(e.get("Id", 0)) == 4104]) == 0:
        findings["notes"].append("No PowerShell 4104 script block events were found. Enable PowerShell Script Block Logging for much better script visibility.")

    return findings

def render_table(headers: List[str], rows: List[List[str]]) -> str:
    out = ["| " + " | ".join(headers) + " |", "| " + " | ".join(["---"] * len(headers)) + " |"]
    for row in rows:
        safe = [str(x).replace("\n", " ").replace("|", "\\|") for x in row]
        out.append("| " + " | ".join(safe) + " |")
    return "\n".join(out)


def short(text: Any, limit: int = 180) -> str:
    s = str(text or "")
    return s if len(s) <= limit else s[: limit - 3] + "..."





def stakeholder_status_and_reasoning(sysinfo: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[str, List[str]]:
    reasons: List[str] = []
    score = 0

    defender_hits = analysis_results.get("defender_hits", [])
    high_signal = analysis_results.get("high_signal_processes", [])
    persistence_hits = analysis_results.get("persistence_hits", [])
    browser_risks = analysis_results.get("browser_risks", [])

    if defender_hits:
        score += 6
        reasons.append(f"Security tooling recorded {len(defender_hits)} detection/action event(s) that warrant validation.")
    else:
        reasons.append("No confirmed malware detections were identified from the collected review data.")
    if persistence_hits:
        score += 4
        reasons.append(f"{len(persistence_hits)} persistence-related finding(s) were flagged for review.")
    if high_signal:
        top_score = max(int(x.get("score", 0)) for x in high_signal)
        score += min(6, top_score)
        reasons.append(f"{len(high_signal)} high-signal execution finding(s) were identified.")
    if any(int(x.get("score", 0)) >= 4 for x in browser_risks):
        score += 2
        reasons.append("At least one browser download or URL was scored as higher risk and should be validated in context.")

    bitdefender_present = bool(sysinfo.get("BitdefenderServices"))
    defender_status = sysinfo.get("DefenderStatus") or {}
    if bitdefender_present and not defender_status.get("AntivirusEnabled", True):
        reasons.append("Microsoft Defender was not the primary active AV on this host; Bitdefender appears to be active.")

    if score >= 8:
        return "High", reasons
    if score >= 4:
        return "Medium", reasons
    return "Low", reasons


STAKEHOLDER_SCRIPTBLOCK_EXCLUDE_PATTERNS = [
    re.compile(r"RootModule\s*=\s*'PSModule\.psm1'", re.I),
    re.compile(r"^\s*@\{\s*GUID\s*=", re.I | re.S),
    re.compile(r"Copyright \(c\) Microsoft", re.I),
    re.compile(r"Update-ModuleManifest", re.I),
    re.compile(r"Set-Alias -Name", re.I),
    re.compile(r"\$global:\?", re.I),
    re.compile(r"Get-WinEvent -ListLog", re.I),
    re.compile(r"Get-CimInstance\s+Win32_", re.I),
    re.compile(r"ConvertTo-Json -Depth", re.I),
    re.compile(r"windows_ir_reporter", re.I),
    re.compile(r"\{\s*\$xml = \[xml\]\$_.ToXml\(\)", re.I),
    re.compile(r"\{ \$_.Name -like 'sysmon\*'", re.I),
    re.compile(r"\{ \$_.DisplayName -match 'Bitdefender'", re.I),
    re.compile(r"^[A-Za-z0-9+/=\r\n#\s.-]{180,}$"),
]


STAKEHOLDER_INTERESTING_PROCESS_NAMES = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "notepad.exe", "chrome.exe", "msedge.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
}



def normalize_inline(text: str, limit: int = 220) -> str:
    return short(" ".join(str(text or "").replace("\r", " ").replace("\n", " ").split()), limit)



def stakeholder_noise_scriptblock(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return True
    return any(p.search(stripped) for p in STAKEHOLDER_SCRIPTBLOCK_EXCLUDE_PATTERNS)



def extract_iwr_details(text: str) -> Tuple[str, str]:
    url = ""
    outfile = ""
    m = re.search(r"-Uri\s+['\"]?([^'\"\s]+)", text, re.I)
    if m:
        url = m.group(1)
    m = re.search(r"-OutFile\s+['\"]?([^'\"]+?)['\"]?(?:\s|$)", text, re.I)
    if m:
        outfile = m.group(1).strip()
    return url, outfile



SAFE_TEST_DOMAINS = {"example.com", "example.org", "example.net", "localhost", "127.0.0.1"}
SUSPICIOUS_WEBREQUEST_EXTENSIONS = {".exe", ".dll", ".ps1", ".psm1", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".hta", ".wsf", ".scr", ".msi", ".lnk"}

def webrequest_host(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url or "")
        return (parsed.hostname or "").lower()
    except Exception:
        return ""

def is_safe_test_domain(url: str) -> bool:
    host = webrequest_host(url)
    return host in SAFE_TEST_DOMAINS

def suspicious_webrequest_target(outfile: str) -> bool:
    lowered = safe_lower(outfile)
    ext = Path(lowered).suffix
    return suspicious_path(lowered) or ext in SUSPICIOUS_WEBREQUEST_EXTENSIONS

def _webrequest_context_score(ts: str, url: str, outfile: str, sec_procs: List[Dict[str, Any]], sysmon_ext: List[Dict[str, Any]]) -> Tuple[str, str, str]:
    if is_safe_test_domain(url):
        why = "PowerShell issued a web request command to a known safe/test destination often used for validation or expected administrative activity."
        action = "Validate that the destination and saved output were expected, then deprioritize unless other stronger signals are present."
        return "Low", why, action

    when = parse_iso(ts)
    suspicious_exec = False
    tamper_or_exec = False
    if when:
        for row in sec_procs:
            evt_time = parse_iso(row.get("event", {}).get("TimeCreated", ""))
            if not evt_time:
                continue
            delta = abs((evt_time - when).total_seconds())
            if delta > 120:
                continue
            fields = row.get("fields", {})
            if fields.get("parent_name") in POWERSHELL_PARENT_NAMES and fields.get("image_name") in (DETECTION_SHELL_CHILDREN | DETECTION_LOLBINS):
                suspicious_exec = True
                break
        for finding in sysmon_ext:
            evt_time = parse_iso(finding.get("time", ""))
            if not evt_time:
                continue
            delta = abs((evt_time - when).total_seconds())
            if delta > 120:
                continue
            if int(finding.get("id", 0)) in {8, 25, 29}:
                tamper_or_exec = True
                break

    suspicious_target = suspicious_webrequest_target(outfile)
    host = webrequest_host(url)

    if suspicious_exec or tamper_or_exec:
        why = "PowerShell issued a web request command and nearby telemetry suggests follow-on execution, tampering, or executable staging activity."
        action = "Treat as higher priority: review the destination, downloaded content, child processes, persistence, and adjacent Sysmon findings immediately."
        return "High", why, action

    if host or suspicious_target:
        why = "PowerShell issued a web request command to an unknown or non-test destination, which is commonly used for staging, downloads, or remote content retrieval."
        if suspicious_target:
            why += " The save target or extension also looks higher risk."
        action = "Validate the destination, downloaded content, save path, and surrounding process/network activity. Escalate if follow-on execution or persistence is present."
        return "Medium", why, action

    why = "PowerShell issued a web request command often used for staging, downloads, or remote content retrieval."
    action = "Validate whether the destination, downloaded content, and surrounding process/network activity were expected."
    return "Low", why, action


def stakeholder_format_time(ts: str) -> str:
    d = parse_iso(ts)
    if not d:
        return ts or ""
    return d.strftime("%Y-%m-%d %H:%M")



def stakeholder_scriptblock_observation(text: str) -> Optional[str]:
    stripped = (text or "").strip()
    lowered = stripped.lower()
    if stakeholder_noise_scriptblock(stripped):
        return None

    if lowered == "notepad.exe":
        return "User launched `notepad.exe` from PowerShell as part of validation testing."

    if lowered.startswith("invoke-webrequest"):
        url, outfile = extract_iwr_details(stripped)
        if url and outfile:
            return f"User executed a PowerShell web request to `{url}` and saved the output to `{outfile}`."
        if url:
            return f"User executed a PowerShell web request to `{url}`."
        return "User executed a PowerShell web request."

    if lowered.startswith("start-process"):
        if "cmd.exe" in lowered and "ir_test.txt" in lowered:
            return "User launched `cmd.exe` from PowerShell to create `ir_test.txt` on the Desktop."
        if "cmd.exe" in lowered:
            return "User launched `cmd.exe` from PowerShell."
        return "User launched a child process from PowerShell using `Start-Process`."

    exe_match = re.fullmatch(r"([A-Za-z0-9_.-]+\.exe)(?:\s+.*)?", stripped, re.I)
    if exe_match:
        return f"User launched `{exe_match.group(1)}` from PowerShell."

    return None



def stakeholder_process_observation(item: Dict[str, Any], allow_fallback: bool = False) -> Optional[str]:
    image = str(item.get("image", "")).strip()
    parent = str(item.get("parent", "")).strip()
    cmd = str(item.get("command_line", "")).strip()
    user = str(item.get("user", "")).strip()
    if not image or (user and is_machine_account(user)):
        return None
    fields = {
        "image": image,
        "image_name": Path(image).name.lower(),
        "parent": parent,
        "parent_name": Path(parent).name.lower() if parent else "",
        "command": cmd,
        "user": user,
    }
    if is_reporter_self_process(fields) or is_devtool_noise_process(fields):
        return None

    image_name = Path(image).name.lower()
    parent_name = Path(parent).name.lower() if parent else ""
    cmd_lower = cmd.lower()

    if image_name == "notepad.exe" and parent_name in POWERSHELL_PARENT_NAMES:
        return "User launched `notepad.exe` from PowerShell as part of validation testing."
    if image_name == "cmd.exe" and parent_name in POWERSHELL_PARENT_NAMES:
        if "ir_test.txt" in cmd_lower:
            return "Related process execution showed `cmd.exe` launched from PowerShell to create `ir_test.txt`."
        return "Related process execution showed `cmd.exe` launched from PowerShell."
    if parent_name in POWERSHELL_PARENT_NAMES and image_name in STAKEHOLDER_INTERESTING_PROCESS_NAMES:
        return f"Related process execution showed `{Path(image).name}` launched from `{Path(parent).name}`."
    if allow_fallback and image_name in {"chrome.exe", "msedge.exe"} and parent_name in {"explorer.exe", "powershell.exe", "cmd.exe"}:
        return f"User launched `{Path(image).name}` from `{Path(parent).name}`."
    if allow_fallback and image_name in {"powershell.exe", "pwsh.exe"} and parent_name in {"windowsterminal.exe", "explorer.exe"}:
        return "An interactive PowerShell session was opened by the user."
    return None



def _all_security_events(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return flatten_event(data.get("logs", {}).get("Security", {}))



def _all_powershell_events(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return flatten_event(data.get("logs", {}).get("PowerShell", {})) + flatten_event(data.get("logs", {}).get("PowerShellCore", {}))



def _all_sysmon_events(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    return flatten_event(data.get("logs", {}).get("Sysmon", {}))



def _stakeholder_command_priority(kind: str) -> int:
    return {
        "web_request": 1,
        "start_process": 2,
        "notepad": 3,
        "cmd": 4,
        "browser": 8,
        "other": 9,
    }.get(kind, 9)



def _interesting_scriptblock_kind(text: str) -> Optional[str]:
    stripped = (text or "").strip()
    lowered = stripped.lower()
    if not lowered or stakeholder_noise_scriptblock(stripped) or is_self_collection_scriptblock(stripped):
        return None
    if lowered.startswith("invoke-webrequest"):
        return "web_request"
    if lowered.startswith("start-process"):
        return "start_process"
    if re.fullmatch(r"notepad\.exe(?:\s+.*)?", lowered):
        return "notepad"
    if re.fullmatch(r"cmd\.exe(?:\s+.*)?", lowered):
        return "cmd"
    return None



def _collect_direct_command_events(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    for event in sorted(_all_powershell_events(data), key=lambda e: e.get("TimeCreated") or "", reverse=True):
        if int(event.get("Id", 0)) != 4104:
            continue
        text = extract_scriptblock_text(event.get("Message") or "")
        kind = _interesting_scriptblock_kind(text)
        if not kind:
            continue
        key = (kind, text.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        url, outfile = extract_iwr_details(text)
        rows.append({
            "time": event.get("TimeCreated", ""),
            "kind": kind,
            "text": text.strip(),
            "url": url,
            "outfile": outfile,
        })
    return rows



def _seconds_between(a: Optional[dt.datetime], b: Optional[dt.datetime]) -> float:
    if not a or not b:
        return float("inf")
    return abs((a - b).total_seconds())



def _find_matching_4688(data: Dict[str, Any], command_event: Dict[str, Any], within_seconds: int = 180) -> Optional[Dict[str, Any]]:
    target_time = parse_iso(command_event.get("time"))
    kind = command_event.get("kind")
    text = (command_event.get("text") or "").lower()
    best = None
    best_diff = float("inf")
    for event in _all_security_events(data):
        if int(event.get("Id", 0)) != 4688:
            continue
        fields = get_process_fields(event)
        if is_reporter_self_process(fields) or is_devtool_noise_process(fields):
            continue
        if fields.get("user") and is_machine_account(fields.get("user", "")):
            continue
        image_name = fields.get("image_name", "")
        parent_name = fields.get("parent_name", "")
        match = False
        if kind == "notepad" and image_name == "notepad.exe" and parent_name in POWERSHELL_PARENT_NAMES:
            match = True
        elif kind == "start_process" and "cmd.exe" in text and image_name == "cmd.exe" and parent_name in POWERSHELL_PARENT_NAMES:
            match = True
        elif kind == "cmd" and image_name == "cmd.exe" and parent_name in POWERSHELL_PARENT_NAMES:
            match = True
        elif kind == "web_request" and image_name in POWERSHELL_PARENT_NAMES:
            match = True
        if not match:
            continue
        diff = _seconds_between(parse_iso(event.get("TimeCreated")), target_time)
        if diff <= within_seconds and diff < best_diff:
            best = event
            best_diff = diff
    return best



def _find_correlated_dns_network(data: Dict[str, Any], anchor_time: str, domain: str = "", within_seconds: int = 180) -> Optional[str]:
    anchor = parse_iso(anchor_time)
    if not anchor:
        return None
    domain = (domain or "").strip().lower()
    if not domain:
        return None
    dns_hit = False
    net_hit = False
    for event in _all_sysmon_events(data):
        event_id = int(event.get("Id", 0))
        if event_id not in {3, 22}:
            continue
        ts = parse_iso(event.get("TimeCreated"))
        if _seconds_between(ts, anchor) > within_seconds:
            continue
        data_map = get_event_data(event)
        if event_id == 22:
            query = (data_map.get("QueryName") or data_map.get("QueryResults") or "").lower()
            if domain in query:
                dns_hit = True
        else:
            host = (data_map.get("DestinationHostname") or data_map.get("DestinationIp") or "").lower()
            if domain in host:
                net_hit = True
    if dns_hit and net_hit:
        return f"Related DNS and network activity for `{domain}` was captured in the same time window."
    if dns_hit or net_hit:
        return f"Related DNS/network activity for `{domain}` was captured in the same time window."
    return None



def _fallback_process_candidates(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for event in sorted(_all_security_events(data), key=lambda e: e.get("TimeCreated") or "", reverse=True):
        if int(event.get("Id", 0)) != 4688:
            continue
        fields = get_process_fields(event)
        if is_reporter_self_process(fields) or is_devtool_noise_process(fields):
            continue
        if fields.get("user") and is_machine_account(fields.get("user", "")):
            continue
        image_name = fields.get("image_name", "")
        parent_name = fields.get("parent_name", "")
        if image_name in {"chrome.exe", "msedge.exe"} and parent_name in {"explorer.exe", "powershell.exe", "cmd.exe"}:
            rows.append({
                "time": event.get("TimeCreated", ""),
                "type": "Process activity",
                "detail": f"User launched `{Path(fields.get('image') or image_name).name}` from `{Path(fields.get('parent') or parent_name).name}`.",
                "priority": _stakeholder_command_priority("browser"),
            })
        elif image_name in {"notepad.exe", "cmd.exe"} and parent_name in POWERSHELL_PARENT_NAMES:
            detail = stakeholder_process_observation({
                "image": fields.get("image", ""),
                "parent": fields.get("parent", ""),
                "command_line": fields.get("command", ""),
                "user": fields.get("user", ""),
            })
            if detail:
                rows.append({
                    "time": event.get("TimeCreated", ""),
                    "type": "Process activity",
                    "detail": detail,
                    "priority": 5,
                })
    return rows



def summarize_test_activity(data: Dict[str, Any], analysis_results: Dict[str, Any], limit: int = 6) -> List[Dict[str, str]]:
    items: List[Dict[str, Any]] = []
    seen_details = set()

    def add_item(time: str, typ: str, detail: str, priority: int):
        if not detail:
            return
        key = detail.lower()
        if key in seen_details:
            return
        seen_details.add(key)
        items.append({"time": time or "", "type": typ, "detail": detail, "priority": priority})

    direct_commands = _collect_direct_command_events(data)
    for cmd_evt in direct_commands:
        detail = stakeholder_scriptblock_observation(cmd_evt.get("text", ""))
        priority = _stakeholder_command_priority(cmd_evt.get("kind", "other"))
        if detail:
            add_item(cmd_evt.get("time", ""), "User test activity", detail, priority)

        matched_proc = _find_matching_4688(data, cmd_evt)
        if matched_proc:
            proc_fields = get_process_fields(matched_proc)
            proc_detail = stakeholder_process_observation({
                "image": proc_fields.get("image", ""),
                "parent": proc_fields.get("parent", ""),
                "command_line": proc_fields.get("command", ""),
                "user": proc_fields.get("user", ""),
            })
            if proc_detail and proc_detail != detail:
                add_item(matched_proc.get("TimeCreated", ""), "Process activity", proc_detail, priority + 1)

        if cmd_evt.get("kind") == "web_request" and cmd_evt.get("url"):
            domain = urllib.parse.urlparse(cmd_evt.get("url") or "").netloc or (cmd_evt.get("url") or "")
            corr = _find_correlated_dns_network(data, cmd_evt.get("time", ""), domain)
            if corr:
                add_item(cmd_evt.get("time", ""), "Correlated telemetry", corr, priority + 2)

    if not items:
        for row in _fallback_process_candidates(data):
            add_item(row.get("time", ""), row.get("type", "Process activity"), row.get("detail", ""), int(row.get("priority", 9)))
            if len(items) >= limit:
                break

    def sort_key(x: Dict[str, Any]):
        parsed = parse_iso(x.get("time"))
        return (int(x.get("priority", 99)), -(parsed.timestamp() if parsed else 0.0))

    items.sort(key=sort_key)
    return [{"time": x.get("time", ""), "type": x.get("type", ""), "detail": x.get("detail", "")} for x in items[:limit]]


def summarize_key_findings(sysinfo: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[str]:
    findings: List[str] = []

    if analysis_results.get("defender_hits"):
        findings.append(f"Security tooling recorded {len(analysis_results.get('defender_hits', []))} detection/action event(s) that should be validated by an analyst.")
    else:
        findings.append("No confirmed malware detections were identified from the collected review data.")

    if analysis_results.get("persistence_hits"):
        findings.append(f"{len(analysis_results.get('persistence_hits', []))} persistence-related item(s) should be validated in context.")
    else:
        findings.append("No suspicious persistence items were identified by the current checks.")

    recent_ps = analysis_results.get("recent_4104_user_scriptblocks", [])
    if any(str(item.get("script_text", "")).strip().lower().startswith("invoke-webrequest") and not stakeholder_noise_scriptblock(str(item.get("script_text", ""))) for item in recent_ps):
        findings.append("User-entered PowerShell web request activity was captured by Event ID 4104.")

    defender_status = sysinfo.get("DefenderStatus") or {}
    bd_present = bool(sysinfo.get("BitdefenderServices"))
    if bd_present and not defender_status.get("AntivirusEnabled"):
        findings.append("Microsoft Defender was not the primary active AV on this host; Bitdefender appears to be active.")

    return findings


def generate_stakeholder_summary(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    sysinfo = data.get("system_info", {})
    risk_level, reasons = stakeholder_status_and_reasoning(sysinfo, analysis_results)
    notable_activity = summarize_test_activity(data, analysis_results, limit=5)
    key_findings = summarize_key_findings(sysinfo, analysis_results)

    analyst_report_name = "windows_ir_analyst_report.md"
    lines: List[str] = []
    lines.append("# Windows Incident Response — Stakeholder Summary\n")
    lines.append(f"Generated: {dt.datetime.now().isoformat()}  ")
    lines.append(f"Time window analyzed: last **{days}** day(s)  ")
    lines.append(f"Host: **{sysinfo.get('ComputerName', '')}**  ")
    lines.append(f"User context: **{sysinfo.get('UserName', '')}**  ")
    lines.append(f"Overall risk assessment: **{risk_level}**\n")

    lines.append("## Executive Summary\n")
    if risk_level == "Low":
        lines.append("The investigation data shows **test activity and normal workstation behavior**, with no confirmed malware detections or suspicious persistence identified in the current review window. The analyst-facing report should still be retained for deeper validation and pivots if needed.\n")
    elif risk_level == "Medium":
        lines.append("The investigation data shows **activity that warrants analyst review**, but it does not by itself prove compromise. The analyst-facing report should be used to validate the flagged processes, script activity, and persistence/network context.\n")
    else:
        lines.append("The investigation data shows **multiple high-priority indicators** that should be treated as potentially malicious until analyst review confirms otherwise. Immediate containment and deeper review should be considered.\n")

    lines.append("## What Was Observed\n")
    obs_rows: List[List[str]] = []
    for x in notable_activity:
        obs_rows.append([stakeholder_format_time(x.get("time", "")), x.get("type", ""), x.get("detail", "")])

    if analysis_results.get("persistence_hits"):
        obs_rows.append(["Current review window", "Persistence", f"{len(analysis_results.get('persistence_hits', []))} persistence-related item(s) were identified and should be reviewed."])
    else:
        obs_rows.append(["Current review window", "Persistence", "No suspicious persistence items were identified by the current checks."])

    if analysis_results.get("defender_hits"):
        obs_rows.append(["Current review window", "AV/Detection", f"{len(analysis_results.get('defender_hits', []))} detection/action event(s) were identified and should be validated by an analyst."])
    else:
        obs_rows.append(["Current review window", "AV/Detection", "No confirmed malware detections were identified from the collected review data."])

    dedup_rows = []
    seen_rows = set()
    for row in obs_rows:
        key = tuple(row)
        if key in seen_rows:
            continue
        seen_rows.add(key)
        dedup_rows.append(row)

    if dedup_rows:
        lines.append(render_table(["Time", "Category", "Observation"], dedup_rows))
        lines.append("")
    else:
        lines.append("No concise user-driven activity summary could be built from the collected events.\n")

    if key_findings:
        lines.append("## Key Findings\n")
        for finding in key_findings:
            lines.append(f"- {finding}")
        lines.append("")

    lines.append("## Why This Assessment Was Reached\n")
    for reason in reasons:
        lines.append(f"- {reason}")
    lines.append("")

    lines.append("## Recommended Next Steps\n")
    if risk_level == "Low":
        lines.extend([
            "- Retain the analyst report and raw JSON as case evidence.",
            "- Use the analyst report for spot-checking exact times, parent processes, and command lines when needed.",
            "- Treat the stakeholder summary as a concise status update, not as a replacement for raw-event review.",
        ])
    elif risk_level == "Medium":
        lines.extend([
            "- Review the full analyst report for exact parent/child process chains and corresponding DNS/network activity.",
            "- Validate persistence, browser downloads, and any high-signal process findings with Autoruns and Process Explorer/TCPView.",
            "- Preserve the raw JSON output for follow-on triage or escalation.",
        ])
    else:
        lines.extend([
            "- Escalate to deeper analyst review immediately.",
            "- Validate the flagged process, persistence, and network activity against raw evidence.",
            "- Consider containment steps if the activity cannot be explained as expected administrative or test behavior.",
        ])
    lines.append("")
    lines.append("## Report Notes\n")
    lines.append(f"- The full technical report is written separately as **{analyst_report_name}**.")
    lines.append("- This summary is intentionally short and is not a replacement for raw-event review when a true incident is suspected.")
    lines.append("")
    return "\n".join(lines)



def html_escape(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def render_html_table(headers: List[str], rows: List[List[Any]], table_class: str = "") -> str:
    cls = f' class="{table_class}"' if table_class else ""
    out = [f"<table{cls}>", "<thead><tr>"]
    for h in headers:
        out.append(f"<th>{html_escape(h)}</th>")
    out.append("</tr></thead><tbody>")
    if not rows:
        out.append(f'<tr><td colspan="{len(headers)}"><em>No data</em></td></tr>')
    else:
        for row in rows:
            out.append("<tr>")
            for cell in row:
                if isinstance(cell, tuple) and len(cell) == 2:
                    display, full = cell
                    out.append(f'<td title="{html_escape(full)}">{html_escape(display)}</td>')
                else:
                    out.append(f"<td>{html_escape(cell)}</td>")
            out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def html_kv_table(rows: List[List[Any]]) -> str:
    return render_html_table(["Field", "Value"], rows, "kv-table")


def html_rows_activity(items: List[Dict[str, Any]], limit: Optional[int] = None) -> List[List[Any]]:
    rows: List[List[Any]] = []
    seq = items if limit is None else items[:limit]
    for item in seq:
        rows.append([
            item.get("time", ""),
            item.get("source", ""),
            item.get("kind", ""),
            item.get("actor", ""),
            (short(item.get("image", ""), 80), item.get("image", "")),
            (short(item.get("summary", ""), 160), item.get("summary", "")),
            (short("; ".join(item.get("reasons", [])), 110), "; ".join(item.get("reasons", []))),
        ])
    return rows


def html_details(summary: str, body: str, open_by_default: bool = False) -> str:
    open_attr = " open" if open_by_default else ""
    return f"<details{open_attr}><summary>{summary}</summary>{body}</details>"


def generate_analyst_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    sysinfo = data.get("system_info", {})
    risk = analysis_results.get("risk_level", "N/A")
    generated = dt.datetime.now().isoformat()

    host_rows = [
        ["Computer", sysinfo.get("ComputerName", "")],
        ["User", sysinfo.get("UserName", "")],
        ["OS", f"{sysinfo.get('OS', '')} ({sysinfo.get('Version', '')} build {sysinfo.get('BuildNumber', '')})"],
        ["Last Boot", sysinfo.get("LastBootUpTime", "")],
        ["Sysmon Service", short(json.dumps(sysinfo.get("SysmonServices", []), ensure_ascii=False), 250)],
        ["Bitdefender Services", short(json.dumps(sysinfo.get("BitdefenderServices", []), ensure_ascii=False), 250)],
        ["Defender Status", short(json.dumps(sysinfo.get("DefenderStatus", {}), ensure_ascii=False), 250)],
        ["Run as Admin", str(data.get("meta", {}).get("is_admin"))],
    ]

    visibility_rows = []
    for label, key in [
        ("Security", "Security"),
        ("System", "System"),
        ("Windows Defender", "Defender"),
        ("PowerShell", "PowerShell"),
        ("PowerShell Core", "PowerShellCore"),
        ("Sysmon", "Sysmon"),
    ]:
        blob = data.get("logs", {}).get(key, {})
        visibility_rows.append([label, str(blob.get("exists", False)), str(len(flatten_event(blob)))])

    count_rows = [[k, str(v)] for k, v in analysis_results.get("counts", {}).items()]

    likely_items = analysis_results.get("likely_user_actions", [])
    background_items = analysis_results.get("background_activity", [])
    raw_items = analysis_results.get("full_raw_timeline", [])

    recent_proc_rows = []
    for item in analysis_results.get("recent_4688_processes", [])[:40]:
        recent_proc_rows.append([
            item.get("time", ""),
            item.get("category", ""),
            item.get("user", ""),
            (short(item.get("image", ""), 85), item.get("image", "")),
            (short(item.get("parent", ""), 70), item.get("parent", "")),
            (short(item.get("command_line", ""), 140), item.get("command_line", "")),
            (short("; ".join(item.get("reasons", [])), 100), "; ".join(item.get("reasons", []))),
        ])

    recent_ps_rows = []
    for item in analysis_results.get("recent_4104_user_scriptblocks", [])[:25]:
        recent_ps_rows.append([
            item.get("time", ""),
            item.get("category", ""),
            (short(item.get("script_text", ""), 220), item.get("script_text", "")),
            (short("; ".join(item.get("reasons", [])), 100), "; ".join(item.get("reasons", []))),
        ])

    timeline_rows = []
    for item in analysis_results.get("correlated_timeline", [])[:30]:
        timeline_rows.append([
            item.get("minute", ""),
            (short(" || ".join(item.get("likely", [])), 220), " || ".join(item.get("likely", []))),
            (short(" || ".join(item.get("background", [])), 220), " || ".join(item.get("background", []))),
            (short(" || ".join(item.get("dns", [])), 180), " || ".join(item.get("dns", []))),
            (short(" || ".join(item.get("network", [])), 180), " || ".join(item.get("network", []))),
        ])

    proc_rows = []
    for item in analysis_results.get("high_signal_processes", [])[:50]:
        proc_rows.append([
            item.get("time", ""),
            str(item.get("score", "")),
            (short(item.get("image", ""), 90), item.get("image", "")),
            (short(item.get("parent", ""), 70), item.get("parent", "")),
            (short(item.get("command_line", ""), 140), item.get("command_line", "")),
            (short("; ".join(item.get("reasons", [])), 120), "; ".join(item.get("reasons", []))),
        ])

    ps_rows = []
    for item in analysis_results.get("powershell_hits", [])[:30]:
        ps_rows.append([
            item.get("time", ""),
            str(item.get("event_id", "")),
            str(item.get("score", "")),
            (short("; ".join(item.get("reasons", [])), 90), "; ".join(item.get("reasons", []))),
            (short(item.get("preview", ""), 160), item.get("preview", "")),
        ])

    def_rows = []
    for item in analysis_results.get("defender_hits", [])[:30]:
        def_rows.append([
            item.get("time", ""),
            str(item.get("event_id", "")),
            (short(item.get("message", ""), 170), item.get("message", "")),
        ])

    pers_rows = []
    for item in analysis_results.get("persistence_hits", [])[:50]:
        pers_rows.append([
            item.get("time", ""),
            str(item.get("score", "")),
            (short(item.get("location", ""), 70), item.get("location", "")),
            (short(item.get("name", ""), 55), item.get("name", "")),
            (short(item.get("value", ""), 120), item.get("value", "")),
            (short("; ".join(item.get("reasons", [])), 120), "; ".join(item.get("reasons", []))),
        ])

    browser_rows = []
    for item in analysis_results.get("browser_risks", [])[:50]:
        browser_rows.append([
            item.get("time", ""),
            item.get("browser", ""),
            item.get("type", ""),
            str(item.get("score", "")),
            (short(item.get("value", ""), 110), item.get("value", "")),
            (short(item.get("source_url", item.get("title", "")), 100), item.get("source_url", item.get("title", ""))),
            (short("; ".join(item.get("reasons", [])), 120), "; ".join(item.get("reasons", []))),
        ])

    dns_rows = [[q, str(c)] for q, c in analysis_results.get("network_summary", {}).get("top_dns_queries", [])]
    remote_rows = [[q, str(c)] for q, c in analysis_results.get("network_summary", {}).get("top_remote_targets", [])]

    notes_html = ""
    if analysis_results.get("notes"):
        notes_html = "<section id='notes'><h2>Gaps / Notes</h2><ul>" + "".join(
            f"<li>{html_escape(n)}</li>" for n in analysis_results["notes"]
        ) + "</ul></section>"

    html_parts: List[str] = []
    html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows IR Analyst Report</title>
<style>
:root{
  --bg:#0b1020; --panel:#121a2b; --panel2:#0f1726; --text:#e8edf7; --muted:#9fb0cc;
  --accent:#5ea1ff; --border:#26324a; --good:#2fbf71; --warn:#f0b44c; --bad:#ef6767;
}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI, Arial, sans-serif;background:var(--bg);color:var(--text);line-height:1.45}
a{color:var(--accent);text-decoration:none}
.layout{display:grid;grid-template-columns:280px 1fr;min-height:100vh}
.sidebar{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;background:var(--panel2);border-right:1px solid var(--border);padding:20px}
.sidebar h1{font-size:20px;margin:0 0 8px}
.sidebar .meta{color:var(--muted);font-size:13px;margin-bottom:16px}
.nav a{display:block;padding:8px 10px;border-radius:8px;color:var(--text);margin:3px 0}
.nav a:hover{background:#17223a}
.content{padding:24px 28px 40px}
.hero{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px;min-width:190px;box-shadow:0 6px 18px rgba(0,0,0,.18)}
.card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.card .value{font-size:20px;font-weight:700;margin-top:6px}
.card .sub{font-size:12px;color:var(--muted);margin-top:6px}
section{margin:18px 0 28px}
section h2{margin:0 0 12px;font-size:22px}
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
th,td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left;font-size:13px}
th{position:sticky;top:0;background:#19243d;z-index:1}
tr:nth-child(even) td{background:rgba(255,255,255,.01)}
details{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 14px;margin:14px 0}
summary{cursor:pointer;font-weight:700}
code{background:#1c2740;border:1px solid var(--border);padding:1px 5px;border-radius:6px}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700}
.badge.low{background:rgba(47,191,113,.12);color:#86efac;border:1px solid rgba(47,191,113,.35)}
.badge.medium{background:rgba(240,180,76,.12);color:#fcd34d;border:1px solid rgba(240,180,76,.35)}
.badge.high{background:rgba(239,103,103,.12);color:#fca5a5;border:1px solid rgba(239,103,103,.35)}
.small{font-size:12px;color:var(--muted)}
ul{padding-left:18px}
@media (max-width: 980px){.layout{grid-template-columns:1fr}.sidebar{position:static;height:auto;border-right:none;border-bottom:1px solid var(--border)}}
</style>
</head><body>""")

    risk_class = "low" if str(risk).lower() == "low" else "medium" if str(risk).lower() == "medium" else "high"

    html_parts.append("<div class='layout'>")
    html_parts.append("<aside class='sidebar'>")
    html_parts.append("<h1>Windows IR Analyst Report</h1>")
    html_parts.append(f"<div class='meta'>Generated: {html_escape(generated)}<br>Time window: last {days} day(s)<br>Host: {html_escape(sysinfo.get('ComputerName',''))}</div>")
    html_parts.append("<nav class='nav'>")
    for sec_id, sec_name in [
        ("overview","Overview"), ("host","Host Summary"), ("visibility","Visibility & Counts"),
        ("activity","Activity Views"), ("proc4688","Recent 4688"), ("ps4104","Recent 4104"),
        ("timeline","Correlated Timeline"), ("highsignal","High-Signal Findings"),
        ("psfindings","PowerShell Findings"), ("avfindings","AV Findings"),
        ("persistence","Persistence"), ("browser","Browser Risks"), ("sysmonnet","Sysmon Network"),
        ("checks","Suggested Checks")
    ]:
        html_parts.append(f"<a href='#{sec_id}'>{html_escape(sec_name)}</a>")
    html_parts.append("</nav></aside>")

    html_parts.append("<main class='content'>")
    html_parts.append(f"<section id='overview'><div class='hero'>"
                      f"<div class='card'><div class='label'>Risk</div><div class='value'><span class='badge {risk_class}'>{html_escape(str(risk).title())}</span></div><div class='sub'>Current heuristic assessment</div></div>"
                      f"<div class='card'><div class='label'>Security Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('security_events',0)))}</div><div class='sub'>4688 and related Windows Security events</div></div>"
                      f"<div class='card'><div class='label'>PowerShell Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('powershell_events',0)))}</div><div class='sub'>4104 and related PowerShell logs</div></div>"
                      f"<div class='card'><div class='label'>Sysmon Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('sysmon_events',0)))}</div><div class='sub'>Process, DNS, and network telemetry</div></div>"
                      f"<div class='card'><div class='label'>Likely User Actions</div><div class='value'>{html_escape(str(len(likely_items)))}</div><div class='sub'>Normalized events prioritized for triage</div></div>"
                      f"</div></section>")

    html_parts.append(f"<section id='host'><h2>Host Summary</h2>{html_kv_table(host_rows)}</section>")
    html_parts.append(f"<section id='visibility'><h2>Visibility & Counts</h2><div class='grid-2'><div class='panel'><h3>Visibility Check</h3>{render_html_table(['Log','Exists','Collected Events'], visibility_rows)}</div><div class='panel'><h3>Counts</h3>{render_html_table(['Artifact','Count'], count_rows)}</div></div></section>")
    if notes_html:
        html_parts.append(notes_html)

    html_parts.append("<section id='activity'><h2>Activity Views</h2>")
    html_parts.append(html_details(f"<strong>Likely User Actions</strong> ({len(likely_items)} events)",
                                  render_html_table(["Time","Source","Type","Actor","Image","Summary","Why"], html_rows_activity(likely_items), "data-table"), True))
    html_parts.append(html_details(f"<strong>Benign / Background Activity</strong> ({len(background_items)} events)",
                                  render_html_table(["Time","Source","Type","Actor","Image","Summary","Why"], html_rows_activity(background_items), "data-table"), False))
    raw_rows = [[item.get("time",""), item.get("category",""), item.get("source",""), item.get("kind",""),
                (short(item.get("summary",""),160), item.get("summary","")),
                (short(item.get("detail",""),180), item.get("detail",""))] for item in raw_items]
    html_parts.append(html_details(f"<strong>Full Raw Timeline</strong> ({len(raw_items)} normalized events)",
                                  render_html_table(["Time","Category","Source","Type","Summary","Detail"], raw_rows, "data-table"), False))
    html_parts.append("</section>")

    html_parts.append(f"<section id='proc4688'><h2>Recent 4688 Process Executions</h2>{render_html_table(['Time','View','User','Image','Parent','Command Line','Why'], recent_proc_rows)}</section>")
    html_parts.append(f"<section id='ps4104'><h2>Recent 4104 User-Entered Script Blocks</h2>{render_html_table(['Time','View','Script Block Text','Why'], recent_ps_rows)}</section>")
    html_parts.append(f"<section id='timeline'><h2>Correlated Timeline</h2>{render_html_table(['Minute','Likely User','Background','DNS','Network'], timeline_rows)}</section>")
    if proc_rows:
        html_parts.append(f"<section id='highsignal'><h2>High-Signal Process Findings</h2>{render_html_table(['Time','Score','Image','Parent','Command','Why Flagged'], proc_rows)}</section>")
    else:
        html_parts.append("<section id='highsignal'><h2>High-Signal Process Findings</h2><div class='panel'><p>No high-signal process findings were flagged by the current heuristics.</p></div></section>")
    html_parts.append(f"<section id='psfindings'><h2>PowerShell Findings</h2>{render_html_table(['Time','Event ID','Score','Matches','Preview'], ps_rows)}</section>")
    if def_rows:
        html_parts.append(f"<section id='avfindings'><h2>AV Findings</h2>{render_html_table(['Time','Event ID','Message'], def_rows)}</section>")
    else:
        html_parts.append("<section id='avfindings'><h2>AV Findings</h2><div class='panel'><p>No Microsoft Defender detection/action events were collected in the queried window.</p></div></section>")
    if pers_rows:
        html_parts.append(f"<section id='persistence'><h2>Persistence Findings</h2>{render_html_table(['Time','Score','Location','Name','Value','Why Flagged'], pers_rows)}</section>")
    else:
        html_parts.append("<section id='persistence'><h2>Persistence Findings</h2><div class='panel'><p>No persistence entries were flagged by the current heuristics.</p></div></section>")
    html_parts.append(f"<section id='browser'><h2>Browser Risks</h2>{render_html_table(['Time','Browser','Type','Score','Value','Context','Why Flagged'], browser_rows)}</section>")
    ext_count_rows = [[item.get('event_name',''), str(item.get('count',''))] for item in analysis_results.get('sysmon_extended_counts', [])[:20]]
    ext_rows = [[item.get('time',''), str(item.get('event_id','')), item.get('event_name',''), (short(item.get('image',''),85), item.get('image','')), str(item.get('score','')), (short(item.get('summary',''),160), item.get('summary','')), item.get('reason','')] for item in analysis_results.get('sysmon_extended_findings', [])[:40]]
    ext_html = ""
    if ext_count_rows:
        ext_html += "<div class='grid-2'><div class='panel'><h3>Event Counts</h3>" + render_html_table(['Event','Count'], ext_count_rows) + "</div></div>"
    if ext_rows:
        ext_html += render_html_table(['Time','Event ID','Event','Image','Score','Summary','Why It Matters'], ext_rows)
    else:
        ext_html += "<div class='panel'><p>No extended Sysmon findings were built from the configured event IDs.</p></div>"
    html_parts.append(f"<section id='sysmonx'><h2>Sysmon Extended Findings</h2>{ext_html}</section>")
    html_parts.append(f"<section id='sysmonnet'><h2>Sysmon Network Summary</h2><div class='grid-2'><div class='panel'><h3>Top DNS Queries</h3>{render_html_table(['Query','Count'], dns_rows)}</div><div class='panel'><h3>Top Remote Targets</h3>{render_html_table(['Target','Count'], remote_rows)}</div></div></section>")
    checks = [
        "Start with Likely User Actions, then expand Background Activity and Full Raw Timeline only when you need more context.",
        "Use the Correlated Timeline to align likely user actions with background activity and Sysmon DNS/network by minute.",
        "Review Sysmon Extended Findings for remote thread creation, process access, registry changes, WMI activity, process tampering, file deletion, and executable detection events.",
        "Pivot on any process by exact time, parent process, and command line.",
        "If a URL or download looks suspicious, locate the corresponding process creation and any Sysmon DNS/network events around that minute.",
        "Validate persistence with Autoruns and live processes with Process Explorer/TCPView.",
    ]
    html_parts.append("<section id='checks'><h2>Suggested Next Manual Checks</h2><div class='panel'><ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in checks) + "</ul><p class='small'>This report is heuristic and triage-oriented. Suppression in one section does not remove the event from the Full Raw Timeline or JSON output.</p></div></section>")
    html_parts.append("</main></div></body></html>")
    return "".join(html_parts)


def generate_markdown(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    sysinfo = data.get("system_info", {})
    lines: List[str] = []
    lines.append(f"# Windows Incident Response Report\n")
    lines.append(f"Generated: {dt.datetime.now().isoformat()}\n")
    lines.append(f"Time window analyzed: last **{days}** day(s)\n")

    lines.append("## Host Summary\n")
    lines.append(render_table(
        ["Field", "Value"],
        [
            ["Computer", sysinfo.get("ComputerName", "")],
            ["User", sysinfo.get("UserName", "")],
            ["OS", f"{sysinfo.get('OS', '')} ({sysinfo.get('Version', '')} build {sysinfo.get('BuildNumber', '')})"],
            ["Last Boot", sysinfo.get("LastBootUpTime", "")],
            ["Sysmon Service", short(json.dumps(sysinfo.get("SysmonServices", []), ensure_ascii=False), 250)],
            ["Bitdefender Services", short(json.dumps(sysinfo.get("BitdefenderServices", []), ensure_ascii=False), 250)],
            ["Defender Status", short(json.dumps(sysinfo.get("DefenderStatus", {}), ensure_ascii=False), 250)],
            ["Run as Admin", str(data.get("meta", {}).get("is_admin"))],
        ],
    ))
    lines.append("")

    lines.append("## Visibility Check\n")
    visibility_rows = []
    for label, key in [
        ("Security", "Security"),
        ("System", "System"),
        ("Windows Defender", "Defender"),
        ("PowerShell", "PowerShell"),
        ("PowerShell Core", "PowerShellCore"),
        ("Sysmon", "Sysmon"),
    ]:
        blob = data.get("logs", {}).get(key, {})
        visibility_rows.append([label, str(blob.get("exists", False)), str(len(flatten_event(blob)))])
    lines.append(render_table(["Log", "Exists", "Collected Events"], visibility_rows))
    lines.append("")

    lines.append("## Counts\n")
    count_rows = [[k, str(v)] for k, v in analysis_results.get("counts", {}).items()]
    lines.append(render_table(["Artifact", "Count"], count_rows))
    lines.append("")

    if analysis_results.get("notes"):
        lines.append("## Gaps / Notes\n")
        for note in analysis_results["notes"]:
            lines.append(f"- {note}")
        lines.append("")

    def activity_rows(items: List[Dict[str, Any]], limit: Optional[int] = None) -> List[List[str]]:
        rows: List[List[str]] = []
        seq = items if limit is None else items[:limit]
        for item in seq:
            rows.append([
                item.get("time", ""),
                item.get("source", ""),
                item.get("kind", ""),
                item.get("actor", ""),
                short(item.get("image", ""), 70),
                short(item.get("summary", ""), 150),
                short("; ".join(item.get("reasons", [])), 110),
            ])
        return rows

    likely_items = analysis_results.get("likely_user_actions", [])
    background_items = analysis_results.get("background_activity", [])
    raw_items = analysis_results.get("full_raw_timeline", [])

    lines.append("## Activity Views\n")
    lines.append("<details open>")
    lines.append(f"<summary><strong>Likely User Actions</strong> ({len(likely_items)} events)</summary>\n")
    likely_rows = activity_rows(likely_items)
    if likely_rows:
        lines.append("")
        lines.append(render_table(["Time", "Source", "Type", "Actor", "Image", "Summary", "Why"], likely_rows))
        lines.append("")
    else:
        lines.append("\nNo likely user actions were identified from the current event set.\n")
    lines.append("</details>\n")

    lines.append("<details>")
    lines.append(f"<summary><strong>Benign / Background Activity</strong> ({len(background_items)} events)</summary>\n")
    background_rows = activity_rows(background_items)
    if background_rows:
        lines.append("")
        lines.append(render_table(["Time", "Source", "Type", "Actor", "Image", "Summary", "Why"], background_rows))
        lines.append("")
    else:
        lines.append("\nNo background activity rows were built.\n")
    lines.append("</details>\n")

    lines.append("<details>")
    lines.append(f"<summary><strong>Full Raw Timeline</strong> ({len(raw_items)} normalized events)</summary>\n")
    raw_rows = []
    for item in raw_items:
        raw_rows.append([
            item.get("time", ""),
            item.get("category", ""),
            item.get("source", ""),
            item.get("kind", ""),
            short(item.get("summary", ""), 160),
            short(item.get("detail", ""), 180),
        ])
    if raw_rows:
        lines.append("")
        lines.append(render_table(["Time", "Category", "Source", "Type", "Summary", "Detail"], raw_rows))
        lines.append("")
    else:
        lines.append("\nNo raw timeline rows were built.\n")
    lines.append("</details>\n")

    lines.append("## Recent 4688 Process Executions\n")
    recent_proc_rows = []
    for item in analysis_results.get("recent_4688_processes", [])[:30]:
        recent_proc_rows.append([
            item.get("time", ""),
            item.get("category", ""),
            item.get("user", ""),
            short(item.get("image", ""), 85),
            short(item.get("parent", ""), 70),
            short(item.get("command_line", ""), 120),
            short("; ".join(item.get("reasons", [])), 80),
        ])
    if recent_proc_rows:
        lines.append(render_table(["Time", "View", "User", "Image", "Parent", "Command Line", "Why"], recent_proc_rows))
    else:
        lines.append("No recent Security 4688 process creation events were collected.\n")
    lines.append("")

    lines.append("## Recent 4104 User-Entered Script Blocks\n")
    recent_ps_rows = []
    for item in analysis_results.get("recent_4104_user_scriptblocks", [])[:20]:
        recent_ps_rows.append([
            item.get("time", ""),
            item.get("category", ""),
            short(item.get("script_text", ""), 220),
            short("; ".join(item.get("reasons", [])), 90),
        ])
    if recent_ps_rows:
        lines.append(render_table(["Time", "View", "Script Block Text", "Why"], recent_ps_rows))
    else:
        lines.append("No recent user-entered 4104 script blocks were identified.\n")
    lines.append("")

    lines.append("## Correlated Timeline (Likely User, Background, Sysmon DNS/Network)\n")
    timeline_rows = []
    for item in analysis_results.get("correlated_timeline", [])[:25]:
        timeline_rows.append([
            item.get("minute", ""),
            short(" || ".join(item.get("likely", [])), 220),
            short(" || ".join(item.get("background", [])), 220),
            short(" || ".join(item.get("dns", [])), 180),
            short(" || ".join(item.get("network", [])), 180),
        ])
    if timeline_rows:
        lines.append(render_table(["Minute", "Likely User", "Background", "DNS", "Network"], timeline_rows))
    else:
        lines.append("No correlated timeline entries were built from the collected events.\n")
    lines.append("")

    lines.append("## High-Signal Process Findings\n")
    proc_rows = []
    for item in analysis_results.get("high_signal_processes", [])[:50]:
        proc_rows.append([
            item.get("time", ""),
            str(item.get("score", "")),
            short(item.get("image", ""), 90),
            short(item.get("parent", ""), 70),
            short(item.get("command_line", ""), 120),
            short("; ".join(item.get("reasons", [])), 120),
        ])
    if proc_rows:
        lines.append(render_table(["Time", "Score", "Image", "Parent", "Command", "Why Flagged"], proc_rows))
    else:
        lines.append("No high-signal process findings were flagged by the current heuristics.\n")
    lines.append("")

    lines.append("## PowerShell Findings\n")
    ps_rows = []
    for item in analysis_results.get("powershell_hits", [])[:30]:
        ps_rows.append([
            item.get("time", ""),
            str(item.get("event_id", "")),
            str(item.get("score", "")),
            short("; ".join(item.get("reasons", [])), 90),
            short(item.get("preview", ""), 140),
        ])
    if ps_rows:
        lines.append(render_table(["Time", "Event ID", "Score", "Matches", "Preview"], ps_rows))
    else:
        lines.append("No suspicious PowerShell script block or module activity was flagged.\n")
    lines.append("")

    lines.append("## Defender / AV Findings\n")
    def_rows = []
    for item in analysis_results.get("defender_hits", [])[:30]:
        def_rows.append([
            item.get("time", ""),
            str(item.get("event_id", "")),
            short(item.get("message", ""), 160),
        ])
    if def_rows:
        lines.append(render_table(["Time", "Event ID", "Message"], def_rows))
    else:
        lines.append("No Microsoft Defender detection/action events were collected in the queried window.\n")
    lines.append("")

    lines.append("## Persistence Findings\n")
    pers_rows = []
    for item in analysis_results.get("persistence_hits", [])[:50]:
        pers_rows.append([
            item.get("time", ""),
            str(item.get("score", "")),
            short(item.get("location", ""), 70),
            short(item.get("name", ""), 55),
            short(item.get("value", ""), 120),
            short("; ".join(item.get("reasons", [])), 120),
        ])
    if pers_rows:
        lines.append(render_table(["Time", "Score", "Location", "Name", "Value", "Why Flagged"], pers_rows))
    else:
        lines.append("No persistence entries were flagged by the current heuristics.\n")
    lines.append("")

    lines.append("## Browser Risks\n")
    browser_rows = []
    for item in analysis_results.get("browser_risks", [])[:50]:
        browser_rows.append([
            item.get("time", ""),
            item.get("browser", ""),
            item.get("type", ""),
            str(item.get("score", "")),
            short(item.get("value", ""), 110),
            short(item.get("source_url", item.get("title", "")), 100),
            short("; ".join(item.get("reasons", [])), 120),
        ])
    if browser_rows:
        lines.append(render_table(["Time", "Browser", "Type", "Score", "Value", "Context", "Why Flagged"], browser_rows))
    else:
        lines.append("No browser URLs or downloads were flagged by the current heuristics.\n")
    lines.append("")


    lines.append("## Sysmon Extended Findings\n")
    ext_count_rows = []
    for item in analysis_results.get("sysmon_extended_counts", [])[:20]:
        ext_count_rows.append([item.get("event_name", ""), str(item.get("count", ""))])
    if ext_count_rows:
        lines.append("### Event Counts\n")
        lines.append(render_table(["Event", "Count"], ext_count_rows))
        lines.append("")
    ext_rows = []
    for item in analysis_results.get("sysmon_extended_findings", [])[:40]:
        ext_rows.append([
            item.get("time", ""),
            str(item.get("event_id", "")),
            item.get("event_name", ""),
            short(item.get("image", ""), 85),
            str(item.get("score", "")),
            short(item.get("summary", ""), 140),
            short(item.get("reason", ""), 80),
        ])
    if ext_rows:
        lines.append(render_table(["Time", "Event ID", "Event", "Image", "Score", "Summary", "Why It Matters"], ext_rows))
    else:
        lines.append("No extended Sysmon findings were built from the configured event IDs.\n")
    lines.append("")

    lines.append("## Sysmon Network Summary\n")
    net = analysis_results.get("network_summary", {})
    if net.get("top_dns_queries") or net.get("top_remote_targets"):
        if net.get("top_dns_queries"):
            lines.append("### Top DNS Queries\n")
            lines.append(render_table(["Query", "Count"], [[k, str(v)] for k, v in net["top_dns_queries"]]))
            lines.append("")
        if net.get("top_remote_targets"):
            lines.append("### Top Remote Targets\n")
            lines.append(render_table(["Target", "Count"], [[k, str(v)] for k, v in net["top_remote_targets"]]))
            lines.append("")
    else:
        lines.append("No Sysmon DNS or network summary data was available.\n")

    lines.append("## Suggested Next Manual Checks\n")
    lines.extend([
        "1. Start with the Activity Views section: Likely User Actions first, then expand Background Activity and Full Raw Timeline when you need more context.",
        "2. Use the Correlated Timeline to align likely user actions with background activity and Sysmon DNS/network by minute.",
        "2b. Review Sysmon Extended Findings for remote thread creation, process access, registry changes, WMI activity, process tampering, file deletion, and executable detection events.",
        "3. Pivot on any process by exact time, parent process, and command line.",
        "4. If a URL or download looks suspicious, locate the corresponding process creation and any Sysmon DNS/network events around that minute.",
        "5. Validate persistence with Autoruns and live processes with Process Explorer/TCPView.",
        "",
        "This report is heuristic and triage-oriented. Suppression in one section does not remove the event from the Full Raw Timeline or JSON output.",
    ])
    lines.append("")

    return "\n".join(lines)



def html_escape(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def render_html_table(headers: List[str], rows: List[List[Any]], table_class: str = "") -> str:
    cls = f' class="{table_class}"' if table_class else ""
    out = [f"<table{cls}>", "<thead><tr>"]
    for h in headers:
        out.append(f"<th>{html_escape(h)}</th>")
    out.append("</tr></thead><tbody>")
    if not rows:
        out.append(f'<tr><td colspan="{len(headers)}"><em>No data</em></td></tr>')
    else:
        for row in rows:
            out.append("<tr>")
            for cell in row:
                if isinstance(cell, tuple) and len(cell) == 2:
                    display, full = cell
                    out.append(f'<td title="{html_escape(full)}">{html_escape(display)}</td>')
                else:
                    out.append(f"<td>{html_escape(cell)}</td>")
            out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def html_kv_table(rows: List[List[Any]]) -> str:
    return render_html_table(["Field", "Value"], rows, "kv-table")


def html_rows_activity(items: List[Dict[str, Any]], limit: Optional[int] = None) -> List[List[Any]]:
    rows: List[List[Any]] = []
    seq = items if limit is None else items[:limit]
    for item in seq:
        rows.append([
            item.get("time", ""),
            item.get("source", ""),
            item.get("kind", ""),
            item.get("actor", ""),
            (short(item.get("image", ""), 80), item.get("image", "")),
            (short(item.get("summary", ""), 160), item.get("summary", "")),
            (short("; ".join(item.get("reasons", [])), 110), "; ".join(item.get("reasons", []))),
        ])
    return rows


def html_details(summary: str, body: str, open_by_default: bool = False) -> str:
    open_attr = " open" if open_by_default else ""
    return f"<details{open_attr}><summary>{summary}</summary>{body}</details>"


def generate_analyst_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    sysinfo = data.get("system_info", {})
    risk = analysis_results.get("risk_level", "N/A")
    generated = dt.datetime.now().isoformat()

    host_rows = [
        ["Computer", sysinfo.get("ComputerName", "")],
        ["User", sysinfo.get("UserName", "")],
        ["OS", f"{sysinfo.get('OS', '')} ({sysinfo.get('Version', '')} build {sysinfo.get('BuildNumber', '')})"],
        ["Last Boot", sysinfo.get("LastBootUpTime", "")],
        ["Sysmon Service", short(json.dumps(sysinfo.get("SysmonServices", []), ensure_ascii=False), 250)],
        ["Bitdefender Services", short(json.dumps(sysinfo.get("BitdefenderServices", []), ensure_ascii=False), 250)],
        ["Defender Status", short(json.dumps(sysinfo.get("DefenderStatus", {}), ensure_ascii=False), 250)],
        ["Run as Admin", str(data.get("meta", {}).get("is_admin"))],
    ]

    visibility_rows = []
    for label, key in [
        ("Security", "Security"),
        ("System", "System"),
        ("Windows Defender", "Defender"),
        ("PowerShell", "PowerShell"),
        ("PowerShell Core", "PowerShellCore"),
        ("Sysmon", "Sysmon"),
    ]:
        blob = data.get("logs", {}).get(key, {})
        visibility_rows.append([label, str(blob.get("exists", False)), str(len(flatten_event(blob)))])

    count_rows = [[k, str(v)] for k, v in analysis_results.get("counts", {}).items()]

    likely_items = analysis_results.get("likely_user_actions", [])
    background_items = analysis_results.get("background_activity", [])
    raw_items = analysis_results.get("full_raw_timeline", [])

    recent_proc_rows = []
    for item in analysis_results.get("recent_4688_processes", [])[:40]:
        recent_proc_rows.append([
            item.get("time", ""),
            item.get("category", ""),
            item.get("user", ""),
            (short(item.get("image", ""), 85), item.get("image", "")),
            (short(item.get("parent", ""), 70), item.get("parent", "")),
            (short(item.get("command_line", ""), 140), item.get("command_line", "")),
            (short("; ".join(item.get("reasons", [])), 100), "; ".join(item.get("reasons", []))),
        ])

    recent_ps_rows = []
    for item in analysis_results.get("recent_4104_user_scriptblocks", [])[:25]:
        recent_ps_rows.append([
            item.get("time", ""),
            item.get("category", ""),
            (short(item.get("script_text", ""), 220), item.get("script_text", "")),
            (short("; ".join(item.get("reasons", [])), 100), "; ".join(item.get("reasons", []))),
        ])

    timeline_rows = []
    for item in analysis_results.get("correlated_timeline", [])[:30]:
        timeline_rows.append([
            item.get("minute", ""),
            (short(" || ".join(item.get("likely", [])), 220), " || ".join(item.get("likely", []))),
            (short(" || ".join(item.get("background", [])), 220), " || ".join(item.get("background", []))),
            (short(" || ".join(item.get("dns", [])), 180), " || ".join(item.get("dns", []))),
            (short(" || ".join(item.get("network", [])), 180), " || ".join(item.get("network", []))),
        ])

    proc_rows = []
    for item in analysis_results.get("high_signal_processes", [])[:50]:
        proc_rows.append([
            item.get("time", ""),
            str(item.get("score", "")),
            (short(item.get("image", ""), 90), item.get("image", "")),
            (short(item.get("parent", ""), 70), item.get("parent", "")),
            (short(item.get("command_line", ""), 140), item.get("command_line", "")),
            (short("; ".join(item.get("reasons", [])), 120), "; ".join(item.get("reasons", []))),
        ])

    ps_rows = []
    for item in analysis_results.get("powershell_hits", [])[:30]:
        ps_rows.append([
            item.get("time", ""),
            str(item.get("event_id", "")),
            str(item.get("score", "")),
            (short("; ".join(item.get("reasons", [])), 90), "; ".join(item.get("reasons", []))),
            (short(item.get("preview", ""), 160), item.get("preview", "")),
        ])

    def_rows = []
    for item in analysis_results.get("defender_hits", [])[:30]:
        def_rows.append([
            item.get("time", ""),
            str(item.get("event_id", "")),
            (short(item.get("message", ""), 170), item.get("message", "")),
        ])

    pers_rows = []
    for item in analysis_results.get("persistence_hits", [])[:50]:
        pers_rows.append([
            item.get("time", ""),
            str(item.get("score", "")),
            (short(item.get("location", ""), 70), item.get("location", "")),
            (short(item.get("name", ""), 55), item.get("name", "")),
            (short(item.get("value", ""), 120), item.get("value", "")),
            (short("; ".join(item.get("reasons", [])), 120), "; ".join(item.get("reasons", []))),
        ])

    browser_rows = []
    for item in analysis_results.get("browser_risks", [])[:50]:
        browser_rows.append([
            item.get("time", ""),
            item.get("browser", ""),
            item.get("type", ""),
            str(item.get("score", "")),
            (short(item.get("value", ""), 110), item.get("value", "")),
            (short(item.get("source_url", item.get("title", "")), 100), item.get("source_url", item.get("title", ""))),
            (short("; ".join(item.get("reasons", [])), 120), "; ".join(item.get("reasons", []))),
        ])

    dns_rows = [[q, str(c)] for q, c in analysis_results.get("network_summary", {}).get("top_dns_queries", [])]
    remote_rows = [[q, str(c)] for q, c in analysis_results.get("network_summary", {}).get("top_remote_targets", [])]

    notes_html = ""
    if analysis_results.get("notes"):
        notes_html = "<section id='notes'><h2>Gaps / Notes</h2><ul>" + "".join(
            f"<li>{html_escape(n)}</li>" for n in analysis_results["notes"]
        ) + "</ul></section>"

    html_parts: List[str] = []
    html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows IR Analyst Report</title>
<style>
:root{
  --bg:#0b1020; --panel:#121a2b; --panel2:#0f1726; --text:#e8edf7; --muted:#9fb0cc;
  --accent:#5ea1ff; --border:#26324a; --good:#2fbf71; --warn:#f0b44c; --bad:#ef6767;
}
*{box-sizing:border-box}
body{margin:0;font-family:Segoe UI, Arial, sans-serif;background:var(--bg);color:var(--text);line-height:1.45}
a{color:var(--accent);text-decoration:none}
.layout{display:grid;grid-template-columns:280px 1fr;min-height:100vh}
.sidebar{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;background:var(--panel2);border-right:1px solid var(--border);padding:20px}
.sidebar h1{font-size:20px;margin:0 0 8px}
.sidebar .meta{color:var(--muted);font-size:13px;margin-bottom:16px}
.nav a{display:block;padding:8px 10px;border-radius:8px;color:var(--text);margin:3px 0}
.nav a:hover{background:#17223a}
.content{padding:24px 28px 40px}
.hero{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px;min-width:190px;box-shadow:0 6px 18px rgba(0,0,0,.18)}
.card .label{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
.card .value{font-size:20px;font-weight:700;margin-top:6px}
.card .sub{font-size:12px;color:var(--muted);margin-top:6px}
section{margin:18px 0 28px}
section h2{margin:0 0 12px;font-size:22px}
.grid-2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
th,td{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left;font-size:13px}
th{position:sticky;top:0;background:#19243d;z-index:1}
tr:nth-child(even) td{background:rgba(255,255,255,.01)}
details{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 14px;margin:14px 0}
summary{cursor:pointer;font-weight:700}
code{background:#1c2740;border:1px solid var(--border);padding:1px 5px;border-radius:6px}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;font-weight:700}
.badge.low{background:rgba(47,191,113,.12);color:#86efac;border:1px solid rgba(47,191,113,.35)}
.badge.medium{background:rgba(240,180,76,.12);color:#fcd34d;border:1px solid rgba(240,180,76,.35)}
.badge.high{background:rgba(239,103,103,.12);color:#fca5a5;border:1px solid rgba(239,103,103,.35)}
.small{font-size:12px;color:var(--muted)}
ul{padding-left:18px}
@media (max-width: 980px){.layout{grid-template-columns:1fr}.sidebar{position:static;height:auto;border-right:none;border-bottom:1px solid var(--border)}}
</style>
</head><body>""")

    risk_class = "low" if str(risk).lower() == "low" else "medium" if str(risk).lower() == "medium" else "high"

    html_parts.append("<div class='layout'>")
    html_parts.append("<aside class='sidebar'>")
    html_parts.append("<h1>Windows IR Analyst Report</h1>")
    html_parts.append(f"<div class='meta'>Generated: {html_escape(generated)}<br>Time window: last {days} day(s)<br>Host: {html_escape(sysinfo.get('ComputerName',''))}</div>")
    html_parts.append("<nav class='nav'>")
    for sec_id, sec_name in [
        ("overview","Overview"), ("host","Host Summary"), ("visibility","Visibility & Counts"),
        ("activity","Activity Views"), ("proc4688","Recent 4688"), ("ps4104","Recent 4104"),
        ("timeline","Correlated Timeline"), ("highsignal","High-Signal Findings"),
        ("psfindings","PowerShell Findings"), ("avfindings","AV Findings"),
        ("persistence","Persistence"), ("browser","Browser Risks"), ("sysmonnet","Sysmon Network"),
        ("checks","Suggested Checks")
    ]:
        html_parts.append(f"<a href='#{sec_id}'>{html_escape(sec_name)}</a>")
    html_parts.append("</nav></aside>")

    html_parts.append("<main class='content'>")
    html_parts.append(f"<section id='overview'><div class='hero'>"
                      f"<div class='card'><div class='label'>Risk</div><div class='value'><span class='badge {risk_class}'>{html_escape(str(risk).title())}</span></div><div class='sub'>Current heuristic assessment</div></div>"
                      f"<div class='card'><div class='label'>Security Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('security_events',0)))}</div><div class='sub'>4688 and related Windows Security events</div></div>"
                      f"<div class='card'><div class='label'>PowerShell Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('powershell_events',0)))}</div><div class='sub'>4104 and related PowerShell logs</div></div>"
                      f"<div class='card'><div class='label'>Sysmon Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('sysmon_events',0)))}</div><div class='sub'>Process, DNS, and network telemetry</div></div>"
                      f"<div class='card'><div class='label'>Likely User Actions</div><div class='value'>{html_escape(str(len(likely_items)))}</div><div class='sub'>Normalized events prioritized for triage</div></div>"
                      f"</div></section>")

    html_parts.append(f"<section id='host'><h2>Host Summary</h2>{html_kv_table(host_rows)}</section>")
    html_parts.append(f"<section id='visibility'><h2>Visibility & Counts</h2><div class='grid-2'><div class='panel'><h3>Visibility Check</h3>{render_html_table(['Log','Exists','Collected Events'], visibility_rows)}</div><div class='panel'><h3>Counts</h3>{render_html_table(['Artifact','Count'], count_rows)}</div></div></section>")
    if notes_html:
        html_parts.append(notes_html)

    html_parts.append("<section id='activity'><h2>Activity Views</h2>")
    html_parts.append(html_details(f"<strong>Likely User Actions</strong> ({len(likely_items)} events)",
                                  render_html_table(["Time","Source","Type","Actor","Image","Summary","Why"], html_rows_activity(likely_items), "data-table"), True))
    html_parts.append(html_details(f"<strong>Benign / Background Activity</strong> ({len(background_items)} events)",
                                  render_html_table(["Time","Source","Type","Actor","Image","Summary","Why"], html_rows_activity(background_items), "data-table"), False))
    raw_rows = [[item.get("time",""), item.get("category",""), item.get("source",""), item.get("kind",""),
                (short(item.get("summary",""),160), item.get("summary","")),
                (short(item.get("detail",""),180), item.get("detail",""))] for item in raw_items]
    html_parts.append(html_details(f"<strong>Full Raw Timeline</strong> ({len(raw_items)} normalized events)",
                                  render_html_table(["Time","Category","Source","Type","Summary","Detail"], raw_rows, "data-table"), False))
    html_parts.append("</section>")

    html_parts.append(f"<section id='proc4688'><h2>Recent 4688 Process Executions</h2>{render_html_table(['Time','View','User','Image','Parent','Command Line','Why'], recent_proc_rows)}</section>")
    html_parts.append(f"<section id='ps4104'><h2>Recent 4104 User-Entered Script Blocks</h2>{render_html_table(['Time','View','Script Block Text','Why'], recent_ps_rows)}</section>")
    html_parts.append(f"<section id='timeline'><h2>Correlated Timeline</h2>{render_html_table(['Minute','Likely User','Background','DNS','Network'], timeline_rows)}</section>")
    if proc_rows:
        html_parts.append(f"<section id='highsignal'><h2>High-Signal Process Findings</h2>{render_html_table(['Time','Score','Image','Parent','Command','Why Flagged'], proc_rows)}</section>")
    else:
        html_parts.append("<section id='highsignal'><h2>High-Signal Process Findings</h2><div class='panel'><p>No high-signal process findings were flagged by the current heuristics.</p></div></section>")
    html_parts.append(f"<section id='psfindings'><h2>PowerShell Findings</h2>{render_html_table(['Time','Event ID','Score','Matches','Preview'], ps_rows)}</section>")
    if def_rows:
        html_parts.append(f"<section id='avfindings'><h2>AV Findings</h2>{render_html_table(['Time','Event ID','Message'], def_rows)}</section>")
    else:
        html_parts.append("<section id='avfindings'><h2>AV Findings</h2><div class='panel'><p>No Microsoft Defender detection/action events were collected in the queried window.</p></div></section>")
    if pers_rows:
        html_parts.append(f"<section id='persistence'><h2>Persistence Findings</h2>{render_html_table(['Time','Score','Location','Name','Value','Why Flagged'], pers_rows)}</section>")
    else:
        html_parts.append("<section id='persistence'><h2>Persistence Findings</h2><div class='panel'><p>No persistence entries were flagged by the current heuristics.</p></div></section>")
    html_parts.append(f"<section id='browser'><h2>Browser Risks</h2>{render_html_table(['Time','Browser','Type','Score','Value','Context','Why Flagged'], browser_rows)}</section>")
    html_parts.append(f"<section id='sysmonnet'><h2>Sysmon Network Summary</h2><div class='grid-2'><div class='panel'><h3>Top DNS Queries</h3>{render_html_table(['Query','Count'], dns_rows)}</div><div class='panel'><h3>Top Remote Targets</h3>{render_html_table(['Target','Count'], remote_rows)}</div></div></section>")
    checks = [
        "Start with Likely User Actions, then expand Background Activity and Full Raw Timeline only when you need more context.",
        "Use the Correlated Timeline to align likely user actions with background activity and Sysmon DNS/network by minute.",
        "Pivot on any process by exact time, parent process, and command line.",
        "If a URL or download looks suspicious, locate the corresponding process creation and any Sysmon DNS/network events around that minute.",
        "Validate persistence with Autoruns and live processes with Process Explorer/TCPView.",
    ]
    html_parts.append("<section id='checks'><h2>Suggested Next Manual Checks</h2><div class='panel'><ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in checks) + "</ul><p class='small'>This report is heuristic and triage-oriented. Suppression in one section does not remove the event from the Full Raw Timeline or JSON output.</p></div></section>")
    html_parts.append("</main></div></body></html>")
    return "".join(html_parts)

def write_outputs(outdir: Path, analyst_report_md: str, analyst_report_html: str, stakeholder_summary_md: str, raw_data: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[Path, Path, Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    analyst_path = outdir / "windows_ir_analyst_report.md"
    analyst_html_path = outdir / "windows_ir_analyst_report.html"
    legacy_md_path = outdir / "windows_ir_report.md"
    stakeholder_path = outdir / "windows_ir_stakeholder_summary.md"
    json_path = outdir / "windows_ir_report.json"

    analyst_path.write_text(analyst_report_md, encoding="utf-8")
    analyst_html_path.write_text(analyst_report_html, encoding="utf-8")
    legacy_md_path.write_text(analyst_report_md, encoding="utf-8")
    stakeholder_path.write_text(stakeholder_summary_md, encoding="utf-8")
    json_path.write_text(json.dumps({"raw": raw_data, "analysis": analysis_results}, indent=2, ensure_ascii=False), encoding="utf-8")
    return analyst_path, analyst_html_path, stakeholder_path, json_path



# --- v15.2 focused tuning: detection dedupe, top-findings ranking, cert/WinTrust suppression ---

def _v15_2_is_cert_or_wintrust_path_text(value: str) -> bool:
    s = safe_lower(value)
    return (
        'systemcertificates' in s
        or 'enterprisecertificates' in s
        or 'wintrust\\trust providers\\software publishing' in s
    )


def _v15_2_is_cert_or_wintrust_noise_summary(summary: str) -> bool:
    s = safe_lower(summary)
    if 'registry change (createkey)' in s and _v15_2_is_cert_or_wintrust_path_text(s):
        return True
    if '__psscriptpolicytest_' in s:
        return True
    if 'powershell.exe created pipe \\pshost.' in s:
        return True
    if 'powershell.exe connected to pipe \\{' in s:
        return True
    return False


def _is_system_certificates_path(value: str) -> bool:
    return _v15_2_is_cert_or_wintrust_path_text(value)


def _summary_mentions_cert_store_init(summary: str) -> bool:
    s = safe_lower(summary)
    return 'registry change (createkey)' in s and _v15_2_is_cert_or_wintrust_path_text(s)


def _summary_mentions_cert_store_setvalue(summary: str) -> bool:
    s = safe_lower(summary)
    return 'registry change (setvalue)' in s and _v15_2_is_cert_or_wintrust_path_text(s)


def _classify_cert_store_cluster(sysmon_ext: List[Dict[str, Any]], sec_procs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    cert_events = [x for x in sysmon_ext if _v15_2_is_cert_or_wintrust_path_text(x.get('summary', ''))]
    if not cert_events:
        return None
    cert_events_sorted = sorted(cert_events, key=lambda x: x.get('time', ''))
    anchor_time = parse_iso(cert_events_sorted[0].get('time', ''))
    setvalue_hits = [x for x in cert_events if _summary_mentions_cert_store_setvalue(x.get('summary', ''))]
    thumbprint_hits = [x for x in cert_events if _summary_mentions_thumbprint_like_subkey(x.get('summary', ''))]
    tool_hits = _find_nearby_security_tool_events(sec_procs, anchor_time, seconds=300)
    createkey_hits = [x for x in cert_events if _summary_mentions_cert_store_init(x.get('summary', ''))]
    if setvalue_hits or thumbprint_hits or tool_hits:
        sample = (setvalue_hits or thumbprint_hits or cert_events_sorted)[0]
        evidence_parts = [sample.get('summary', '')]
        if thumbprint_hits:
            evidence_parts.append('thumbprint-like certificate subkey observed')
        if tool_hits:
            evidence_parts.append(f"nearby tool: {normalized_process_summary(tool_hits[0].get('fields') or {})}")
        return _make_detection(
            'Certificate Trust Store Modification',
            'Medium',
            sample.get('time', ''),
            ' | '.join([part for part in evidence_parts if part]),
            'Certificate or WinTrust store activity included stronger indicators such as SetValue operations, thumbprint-like certificate subkeys, or nearby certutil/reg.exe usage.',
            'Review the exact certificate-store path, any written values/subkeys, and nearby certutil/reg.exe or PowerShell activity to determine whether trust settings were intentionally modified.',
        )
    if len(createkey_hits) >= 3:
        first = createkey_hits[0]
        return _make_detection(
            'Trust Store Initialization (Likely Benign)',
            'Low',
            first.get('time', ''),
            f"{len(createkey_hits)} trust-store CreateKey events observed (example: {first.get('summary','')})",
            'Broad clusters of CreateKey operations under SystemCertificates, EnterpriseCertificates, or WinTrust paths commonly occur during certificate/trust-store initialization and policy evaluation when no SetValue writes, thumbprint subkeys, or certutil/reg.exe activity are nearby.',
            'Document and deprioritize unless additional certificate-store writes, thumbprint subkeys, or certificate-management tooling appear in the same window.',
        )
    return None


def classify_activity_event(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    kind = item.get('kind')
    reasons: List[str] = []

    if kind == 'process':
        fields = item.get('fields') or {}
        image_name = fields.get('image_name', '')
        parent_name = fields.get('parent_name', '')
        user = fields.get('user', '')
        command = fields.get('command', '')

        if is_reporter_self_process(fields):
            reasons.append('collector self-activity')
            return 'background', reasons
        if is_devtool_noise_process(fields):
            reasons.append('development tool helper activity')
            return 'background', reasons
        if user and not is_machine_account(user):
            reasons.append('interactive user account')
        if parent_name in POWERSHELL_PARENT_NAMES | {'cmd.exe', 'explorer.exe'}:
            reasons.append(f'interactive parent: {parent_name}')
        if image_name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append('script host / LOLBin / admin tool')
        if command and suspicious_command_line(command):
            reasons.append('command line matches suspicious/admin patterns')
        if is_machine_account(user) or parent_name in BACKGROUND_PARENT_NAMES:
            reasons.append('service/background parent or machine account')
            return 'background', reasons
        if parent_name in POWERSHELL_PARENT_NAMES | {'cmd.exe', 'explorer.exe', 'chrome.exe', 'msedge.exe', 'outlook.exe', 'winword.exe', 'excel.exe'}:
            return 'likely_user', reasons
        if image_name in {'notepad.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'chrome.exe', 'msedge.exe'} and user and not is_machine_account(user):
            return 'likely_user', reasons
        if process_interest_score(fields) >= 7:
            return 'likely_user', reasons
        return 'background', reasons

    if kind == 'scriptblock':
        text = item.get('detail', '')
        if is_background_scriptblock(text):
            reasons.append('module / helper / collector script block')
            return 'background', reasons
        reasons.append('user-entered script block')
        if suspicious_powershell(text):
            reasons.append('contains dual-use or suspicious keywords')
        return 'likely_user', reasons

    if kind in {'dns', 'network'}:
        image_name = safe_lower(item.get('image_name'))
        detail = item.get('detail', '')
        if image_name in {'powershell.exe', 'pwsh.exe', 'cmd.exe', 'chrome.exe', 'msedge.exe', 'outlook.exe', 'winword.exe', 'excel.exe'}:
            reasons.append(f'interactive process generated {kind}')
            return 'likely_user', reasons
        if 'example.com' in safe_lower(detail):
            reasons.append('manual test destination')
            return 'likely_user', reasons
        reasons.append('background or service-generated network activity')
        return 'background', reasons

    if kind == 'other':
        image_name = safe_lower(item.get('image_name'))
        summary = item.get('summary', '')
        summary_l = safe_lower(summary)
        detail = safe_lower(item.get('detail', ''))
        if _v15_2_is_cert_or_wintrust_noise_summary(summary):
            reasons.append('certificate / WinTrust / PowerShell initialization noise')
            return 'background', reasons
        if 'registry change (createkey)' in summary_l and _v15_2_is_cert_or_wintrust_path_text(summary_l):
            reasons.append('certificate trust-store initialization')
            return 'background', reasons
        if image_name in {'powershell.exe', 'pwsh.exe', 'cmd.exe'}:
            reasons.append('interactive process generated extended sysmon telemetry')
            return 'likely_user', reasons
        if 'example.com' in summary_l or 'example.com' in detail:
            reasons.append('manual test destination')
            return 'likely_user', reasons
        reasons.append('extended sysmon telemetry')
        return 'background', reasons

    reasons.append('uncategorized')
    return 'background', reasons


def _normalize_detection_evidence_key(name: str, evidence: str) -> str:
    s = safe_lower(evidence or '')
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'/session:[^\s"]+', '/session:<session>', s)
    s = re.sub(r'\{[0-9a-f\-]{16,}\}', '{guid}', s)
    s = re.sub(r'0x[0-9a-f]{8,}', '<hex>', s)
    if name.lower() in {'powershell to command shell', 'powershell web request', 'powershell to lolbin'}:
        s = s.replace('$env:userprofile', '%userprofile%')
    return s[:260]


def _dedupe_detections(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    counts: Dict[Tuple[str, str, str], int] = defaultdict(int)
    for d in detections:
        key = (
            str(d.get('name', '')).lower(),
            str(d.get('severity', '')).title(),
            _normalize_detection_evidence_key(str(d.get('name', '')), str(d.get('evidence', ''))),
        )
        counts[key] += 1
        existing = grouped.get(key)
        d_ts = parse_iso(d.get('time'))
        e_ts = parse_iso(existing.get('time')) if existing else None
        if existing is None or ((d_ts.timestamp() if d_ts else 0) > (e_ts.timestamp() if e_ts else 0)):
            grouped[key] = dict(d)
    out: List[Dict[str, Any]] = []
    for key, d in grouped.items():
        count = counts.get(key, 1)
        entry = dict(d)
        entry['occurrences'] = count
        if count > 1:
            entry['evidence'] = normalize_inline(f"[x{count}] {entry.get('evidence','')}", 260)
            if 'repeated' not in safe_lower(entry.get('why', '')):
                entry['why'] = normalize_inline(f"{entry.get('why','')} Repeated {count} time(s) in the reporting window.", 220)
        out.append(entry)
    out.sort(
        key=lambda x: (
            -_severity_rank(x.get('severity', '')),
            -(parse_iso(x.get('time')).timestamp() if parse_iso(x.get('time')) else 0.0),
            x.get('name', ''),
        )
    )
    return out


def _v15_2_is_useful_high_signal_process(item: Dict[str, Any]) -> bool:
    command = safe_lower(item.get('command_line') or '')
    image = safe_lower(item.get('image') or '')
    name = Path(image).name if image else Path((command.split()[0] if command else '')).name.lower()
    if name in {'hponeagent.exe', 'chrome.exe', 'msedge.exe', 'dllhost.exe', 'wmiprvse.exe', 'useroobebroker.exe'}:
        return False
    if 'package cache' in command and not suspicious_command_line(command):
        return False
    if name in SUSPICIOUS_PROCESS_NAMES:
        return True
    if suspicious_command_line(command):
        return True
    if any(x in command for x in ['\\appdata\\', '\\temp\\', '\\programdata\\']):
        return True
    return False


def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()

    # 1) Prefer unique named detections first, especially Medium/High.
    for det in analysis_results.get('detections', []):
        sev = str(det.get('severity', '')).title()
        name = str(det.get('name', '')).strip()
        if not name:
            continue
        if sev == 'Low' and ('likely benign' in safe_lower(name) or 'trust store initialization' in safe_lower(name)):
            continue
        detail = f"{name}: {short(det.get('evidence') or det.get('why') or '', 160)}"
        key = detail.lower()
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            'title': f"{sev} detection" if sev else 'Detection',
            'detail': detail,
            'time': stakeholder_format_time(det.get('time', '')),
        })
        if len(findings) >= 3:
            return findings

    # 2) Then prefer concise user-driven test activity.
    for item in summarize_test_activity(data, analysis_results, limit=8):
        detail = str(item.get('detail', '')).strip()
        if not detail:
            continue
        key = detail.lower()
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            'title': item.get('type', 'Finding'),
            'detail': detail,
            'time': stakeholder_format_time(item.get('time', '')),
        })
        if len(findings) >= 3:
            return findings

    # 3) Only then use filtered high-signal processes.
    for item in analysis_results.get('high_signal_processes', [])[:12]:
        if not _v15_2_is_useful_high_signal_process(item):
            continue
        detail = short(item.get('command_line') or item.get('image') or '', 160)
        label = 'High-signal process'
        key = f"{label}|{detail}".lower()
        if key in seen or not detail:
            continue
        seen.add(key)
        findings.append({
            'title': label,
            'detail': detail,
            'time': stakeholder_format_time(item.get('time', '')),
        })
        if len(findings) >= 3:
            return findings

    for finding in summarize_key_findings(data.get('system_info', {}), analysis_results):
        key = finding.lower()
        if key in seen:
            continue
        seen.add(key)
        findings.append({'title': 'Key finding', 'detail': finding, 'time': ''})
        if len(findings) >= 3:
            break
    return findings

def main() -> int:
    parser = argparse.ArgumentParser(description="Collect and analyze Windows incident-response evidence.")
    parser.add_argument("--days", type=int, default=3, help="How many days back to query (default: 3)")
    parser.add_argument("--max-events", type=int, default=400, help="Max events per log query (default: 400)")
    parser.add_argument("--outdir", default="ir_report_output", help="Output directory (default: ir_report_output)")
    args = parser.parse_args()

    if os.name != "nt":
        print("This script is intended to run on Windows.", file=sys.stderr)
        return 2
    if not powershell_available():
        print("PowerShell was not found. This script requires Windows PowerShell or PowerShell 7.", file=sys.stderr)
        return 2

    raw_data: Dict[str, Any] = {
        "meta": {
            "days": args.days,
            "max_events": args.max_events,
            "is_admin": is_admin(),
            "generated_at": dt.datetime.now().isoformat(),
        }
    }

    raw_data["system_info"] = collect_basic_system_info()
    raw_data["logs"] = {
        "Security": collect_event_log("Security", SECURITY_IDS, args.days, args.max_events),
        "System": collect_event_log("System", SYSTEM_IDS, args.days, args.max_events),
        "Defender": collect_event_log("Microsoft-Windows-Windows Defender/Operational", DEFENDER_IDS, args.days, args.max_events),
        "PowerShell": collect_event_log("Microsoft-Windows-PowerShell/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "PowerShellCore": collect_event_log("PowerShellCore/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "Sysmon": collect_event_log("Microsoft-Windows-Sysmon/Operational", SYSMON_IDS, args.days, args.max_events),
    }
    raw_data["browser_history"] = collect_browser_history(args.days, max_rows=max(50, args.max_events))
    raw_data["run_keys"] = collect_run_keys()
    raw_data["startup_items"] = collect_startup_items()

    analysis_results = analyze(raw_data)
    analyst_report_md = generate_markdown(raw_data, analysis_results, args.days)
    analyst_report_html = generate_analyst_html(raw_data, analysis_results, args.days)
    stakeholder_summary_md = generate_stakeholder_summary(raw_data, analysis_results, args.days)
    analyst_path, analyst_html_path, stakeholder_path, json_path = write_outputs(Path(args.outdir), analyst_report_md, analyst_report_html, stakeholder_summary_md, raw_data, analysis_results)

    print(f"Analyst report (Markdown) written to: {analyst_path}")
    print(f"Analyst report (HTML) written to:     {analyst_html_path}")
    print(f"Stakeholder summary written to:       {stakeholder_path}")
    print(f"JSON written to:                      {json_path}")
    if not raw_data["meta"]["is_admin"]:
        print("Tip: Run from an elevated prompt for best access to Security and other protected logs.")
    else:
        print("Admin check: elevated prompt confirmed.")
    return 0

# === v12 HTML polish overrides ===

def _v12_risk_badge_class(level: str) -> str:
    level = str(level or "").strip().lower()
    if level == "high":
        return "high"
    if level == "medium":
        return "medium"
    return "low"


def _v12_activity_tag(kind: str, source: str = "", image: str = "", summary: str = "") -> str:
    k = (kind or "").lower()
    src = (source or "").lower()
    img = Path(image or "").name.lower()
    text = f"{k} {src} {img} {summary or ''}".lower()
    if "dns" in text:
        return "dns"
    if "network" in text:
        return "network"
    if "scriptblock" in text:
        return "scriptblock"
    if "process" in text:
        return "process"
    if "browser" in text or img in {"chrome.exe", "msedge.exe", "firefox.exe"}:
        return "browser"
    return "other"


def _v12_render_filterable_table(headers: List[str], rows: List[Dict[str, Any]], table_class: str = "data-table") -> str:
    out = [f'<table class="{table_class}" data-filterable="1">', "<thead><tr>"]
    for h in headers:
        out.append(f"<th>{html_escape(h)}</th>")
    out.append("</tr></thead><tbody>")
    if not rows:
        out.append(f'<tr><td colspan="{len(headers)}"><em>No data</em></td></tr>')
    else:
        for row in rows:
            tag = html_escape(row.get("tag", "other"))
            searchable = html_escape(row.get("search", ""))
            out.append(f'<tr data-kind="{tag}" data-search="{searchable}">')
            for cell in row.get("cells", []):
                if isinstance(cell, tuple) and len(cell) == 2:
                    display, full = cell
                    out.append(f'<td title="{html_escape(full)}">{html_escape(display)}</td>')
                else:
                    out.append(f"<td>{html_escape(cell)}</td>")
            out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()

    for item in summarize_test_activity(data, analysis_results, limit=6):
        detail = str(item.get("detail", "")).strip()
        if not detail or detail.lower() in seen:
            continue
        seen.add(detail.lower())
        findings.append({
            "title": item.get("type", "Finding"),
            "detail": detail,
            "time": stakeholder_format_time(item.get("time", "")),
        })
        if len(findings) >= 3:
            return findings

    for item in analysis_results.get("high_signal_processes", [])[:6]:
        detail = short(item.get("command_line") or item.get("image") or "", 160)
        label = "High-signal process"
        key = f"{label}|{detail}".lower()
        if key in seen or not detail:
            continue
        seen.add(key)
        findings.append({
            "title": label,
            "detail": detail,
            "time": stakeholder_format_time(item.get("time", "")),
        })
        if len(findings) >= 3:
            return findings

    for finding in summarize_key_findings(data.get("system_info", {}), analysis_results):
        key = finding.lower()
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "title": "Key finding",
            "detail": finding,
            "time": "",
        })
        if len(findings) >= 3:
            break
    return findings


def generate_stakeholder_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    sysinfo = data.get("system_info", {})
    risk_level, reasons = stakeholder_status_and_reasoning(sysinfo, analysis_results)
    notable_activity = summarize_test_activity(data, analysis_results, limit=5)
    key_findings = summarize_key_findings(sysinfo, analysis_results)

    obs_rows: List[List[str]] = []
    for x in notable_activity:
        obs_rows.append([stakeholder_format_time(x.get("time", "")), x.get("type", ""), x.get("detail", "")])

    if analysis_results.get("persistence_hits"):
        obs_rows.append(["Current review window", "Persistence", f"{len(analysis_results.get('persistence_hits', []))} persistence-related item(s) were identified and should be reviewed."])
    else:
        obs_rows.append(["Current review window", "Persistence", "No suspicious persistence items were identified by the current checks."])

    if analysis_results.get("defender_hits"):
        obs_rows.append(["Current review window", "AV/Detection", f"{len(analysis_results.get('defender_hits', []))} detection/action event(s) were identified and should be validated by an analyst."])
    else:
        obs_rows.append(["Current review window", "AV/Detection", "No confirmed malware detections were identified from the collected review data."])

    dedup_rows = []
    seen_rows = set()
    for row in obs_rows:
        key = tuple(row)
        if key in seen_rows:
            continue
        seen_rows.add(key)
        dedup_rows.append(row)

    badge = _v12_risk_badge_class(risk_level)
    generated = dt.datetime.now().isoformat()

    parts = []
    parts.append(f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows IR Stakeholder Summary</title>
<style>
:root{{--bg:#f6f8fc;--panel:#ffffff;--panel2:#eef3fb;--text:#162033;--muted:#5c6b84;--accent:#2b6fff;--border:#d7deeb;--good:#2d9f5b;--warn:#d7952b;--bad:#c53e3e;}}
*{{box-sizing:border-box}} body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.5}}
.wrap{{max-width:1060px;margin:0 auto;padding:24px}}
.topbar{{position:sticky;top:0;z-index:20;background:rgba(246,248,252,.94);backdrop-filter:blur(8px);border-bottom:1px solid var(--border);padding:12px 0;margin:-24px 0 18px}}
.toolbar{{display:flex;gap:10px;flex-wrap:wrap;justify-content:flex-end}}
.btn{{appearance:none;border:1px solid var(--border);background:var(--panel);color:var(--text);padding:10px 14px;border-radius:10px;font-weight:600;cursor:pointer;text-decoration:none}}
.btn.primary{{background:var(--accent);border-color:var(--accent);color:#fff}}
.hero{{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px;margin:18px 0 22px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:18px;box-shadow:0 8px 22px rgba(17,24,39,.06)}}
.label{{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted)}}
.value{{font-size:28px;font-weight:800;margin-top:6px}}
.sub{{font-size:13px;color:var(--muted);margin-top:8px}}
.badge{{display:inline-block;padding:6px 10px;border-radius:999px;font-size:12px;font-weight:800;text-transform:uppercase;letter-spacing:.05em}}
.badge.low{{background:rgba(45,159,91,.12);color:var(--good);border:1px solid rgba(45,159,91,.25)}}
.badge.medium{{background:rgba(215,149,43,.12);color:var(--warn);border:1px solid rgba(215,149,43,.28)}}
.badge.high{{background:rgba(197,62,62,.12);color:var(--bad);border:1px solid rgba(197,62,62,.28)}}
section{{margin:0 0 20px}} h1{{margin:0 0 6px;font-size:30px}} h2{{margin:0 0 12px;font-size:22px}}
p,li{{font-size:15px}} .muted{{color:var(--muted)}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:14px;overflow:hidden}}
th,td{{padding:11px 12px;border-bottom:1px solid var(--border);text-align:left;vertical-align:top;font-size:14px}}
th{{background:var(--panel2)}}
ul{{margin:0;padding-left:18px}}
.footer-note{{font-size:12px;color:var(--muted)}}
@media (max-width: 860px){{.hero{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff;color:#000}} .topbar,.btn{{display:none !important}} .wrap{{max-width:none;padding:0}} .card,table{{box-shadow:none;border-color:#bbb}} a{{color:#000;text-decoration:none}}}}
</style>
</head><body>
<div class="topbar"><div class="wrap"><div class="toolbar">
<button class="btn primary" onclick="window.print()">Print / Save PDF</button>
<a class="btn" href="windows_ir_analyst_report.html">Open Analyst HTML</a>
<a class="btn" href="windows_ir_analyst_report.md">Open Analyst Markdown</a>
</div></div></div>
<div class="wrap">
<section>
<h1>Windows Incident Response — Stakeholder Summary</h1>
<div class="muted">Generated: {html_escape(generated)} · Time window: last {days} day(s) · Host: {html_escape(sysinfo.get('ComputerName',''))}</div>
</section>
<div class="hero">
  <div class="card">
    <div class="label">Executive Summary</div>
    <div class="sub">''')
    if risk_level == "Low":
        parts.append("The investigation data shows <strong>test activity and normal workstation behavior</strong>, with no confirmed malware detections or suspicious persistence identified in the current review window.")
    elif risk_level == "Medium":
        parts.append("The investigation data shows <strong>activity that warrants analyst review</strong>, but it does not by itself prove compromise.")
    else:
        parts.append("The investigation data shows <strong>multiple high-priority indicators</strong> that should be treated as potentially malicious until reviewed.")
    parts.append(f'''</div>
  </div>
  <div class="card"><div class="label">Overall Risk</div><div class="value"><span class="badge {badge}">{html_escape(risk_level)}</span></div><div class="sub">Stakeholder-facing assessment</div></div>
  <div class="card"><div class="label">User Context</div><div class="value">{html_escape(sysinfo.get("UserName",""))}</div><div class="sub">{html_escape(sysinfo.get("OS",""))}</div></div>
</div>''')

    parts.append("<section><h2>What Was Observed</h2>")
    parts.append(render_html_table(["Time", "Category", "Observation"], dedup_rows))
    parts.append("</section>")

    if key_findings:
        parts.append("<section><h2>Key Findings</h2><div class='card'><ul>")
        parts.extend(f"<li>{html_escape(x)}</li>" for x in key_findings)
        parts.append("</ul></div></section>")

    parts.append("<section><h2>Why This Assessment Was Reached</h2><div class='card'><ul>")
    parts.extend(f"<li>{html_escape(x)}</li>" for x in reasons)
    parts.append("</ul></div></section>")

    if risk_level == "Low":
        next_steps = [
            "Retain the analyst report and raw JSON as case evidence.",
            "Use the analyst report for spot-checking exact times, parent processes, and command lines when needed.",
            "Treat this summary as a concise status update, not as a replacement for raw-event review.",
        ]
    elif risk_level == "Medium":
        next_steps = [
            "Review the full analyst report for exact parent/child process chains and corresponding DNS/network activity.",
            "Validate persistence, browser downloads, and any high-signal process findings with Autoruns and Process Explorer/TCPView.",
            "Preserve the raw JSON output for follow-on triage or escalation.",
        ]
    else:
        next_steps = [
            "Escalate to deeper analyst review immediately.",
            "Validate the flagged process, persistence, and network activity against raw evidence.",
            "Consider containment steps if the activity cannot be explained as expected administrative or test behavior.",
        ]
    parts.append("<section><h2>Recommended Next Steps</h2><div class='card'><ul>")
    parts.extend(f"<li>{html_escape(x)}</li>" for x in next_steps)
    parts.append("</ul></div></section>")

    parts.append("<section><h2>Report Notes</h2><div class='card'><ul>")
    parts.append("<li>The full technical report is written separately as <code>windows_ir_analyst_report.html</code> and <code>windows_ir_analyst_report.md</code>.</li>")
    parts.append("<li>This summary is intentionally short and is not a replacement for raw-event review when a true incident is suspected.</li>")
    parts.append("</ul><div class='footer-note'>For export, use the Print / Save PDF button at the top of the page.</div></div></section>")
    parts.append("</div></body></html>")
    return "".join(parts)


def generate_analyst_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    sysinfo = data.get("system_info", {})
    risk_level, risk_reasons = stakeholder_status_and_reasoning(sysinfo, analysis_results)
    risk_class = _v12_risk_badge_class(risk_level)
    generated = dt.datetime.now().isoformat()

    host_rows = [
        ["Computer", sysinfo.get("ComputerName", "")],
        ["User", sysinfo.get("UserName", "")],
        ["OS", f"{sysinfo.get('OS', '')} ({sysinfo.get('Version', '')} build {sysinfo.get('BuildNumber', '')})"],
        ["Last Boot", sysinfo.get("LastBootUpTime", "")],
        ["Sysmon Service", short(json.dumps(sysinfo.get("SysmonServices", []), ensure_ascii=False), 250)],
        ["Bitdefender Services", short(json.dumps(sysinfo.get("BitdefenderServices", []), ensure_ascii=False), 250)],
        ["Defender Status", short(json.dumps(sysinfo.get("DefenderStatus", {}), ensure_ascii=False), 250)],
        ["Run as Admin", str(data.get("meta", {}).get("is_admin"))],
    ]

    visibility_rows = []
    for label, key in [("Security","Security"),("System","System"),("Windows Defender","Defender"),("PowerShell","PowerShell"),("PowerShell Core","PowerShellCore"),("Sysmon","Sysmon")]:
        blob = data.get("logs", {}).get(key, {})
        visibility_rows.append([label, str(blob.get("exists", False)), str(len(flatten_event(blob)))])

    count_rows = [[k, str(v)] for k, v in analysis_results.get("counts", {}).items()]
    likely_items = analysis_results.get("likely_user_actions", [])
    background_items = analysis_results.get("background_activity", [])
    raw_items = analysis_results.get("full_raw_timeline", [])

    def activity_rows(items: List[Dict[str, Any]], limit: Optional[int] = None):
        seq = items if limit is None else items[:limit]
        rows = []
        for item in seq:
            tag = _v12_activity_tag(item.get("kind",""), item.get("source",""), item.get("image",""), item.get("summary",""))
            search = " ".join(str(x or "") for x in [item.get("time"), item.get("source"), item.get("kind"), item.get("actor"), item.get("image"), item.get("summary"), "; ".join(item.get("reasons", []))])
            rows.append({
                "tag": tag,
                "search": search,
                "cells": [
                    item.get("time", ""),
                    item.get("source", ""),
                    item.get("kind", ""),
                    item.get("actor", ""),
                    (short(item.get("image", ""), 80), item.get("image", "")),
                    (short(item.get("summary", ""), 160), item.get("summary", "")),
                    (short("; ".join(item.get("reasons", [])), 110), "; ".join(item.get("reasons", []))),
                ]
            })
        return rows

    recent_proc_rows = []
    for item in analysis_results.get("recent_4688_processes", [])[:40]:
        search = " ".join(str(x or "") for x in [item.get("time"), item.get("user"), item.get("image"), item.get("parent"), item.get("command_line"), "; ".join(item.get("reasons", []))])
        recent_proc_rows.append({
            "tag": "process",
            "search": search,
            "cells": [
                item.get("time", ""), item.get("category", ""), item.get("user", ""),
                (short(item.get("image", ""), 85), item.get("image", "")),
                (short(item.get("parent", ""), 70), item.get("parent", "")),
                (short(item.get("command_line", ""), 140), item.get("command_line", "")),
                (short("; ".join(item.get("reasons", [])), 100), "; ".join(item.get("reasons", []))),
            ]
        })

    recent_ps_rows = []
    for item in analysis_results.get("recent_4104_user_scriptblocks", [])[:25]:
        text = item.get("script_text", "")
        tag = _v12_activity_tag("scriptblock", "PowerShell", "", text)
        search = " ".join(str(x or "") for x in [item.get("time"), item.get("category"), text, "; ".join(item.get("reasons", []))])
        recent_ps_rows.append({
            "tag": tag,
            "search": search,
            "cells": [
                item.get("time", ""), item.get("category", ""),
                (short(text, 220), text),
                (short("; ".join(item.get("reasons", [])), 100), "; ".join(item.get("reasons", []))),
            ]
        })

    timeline_rows = []
    for item in analysis_results.get("correlated_timeline", [])[:30]:
        row_text = " || ".join(item.get("likely", []) + item.get("background", []) + item.get("dns", []) + item.get("network", []))
        tag = "timeline"
        if item.get("dns"):
            tag = "dns"
        elif item.get("network"):
            tag = "network"
        elif item.get("likely"):
            tag = "process"
        timeline_rows.append({
            "tag": tag,
            "search": f"{item.get('minute','')} {row_text}",
            "cells": [
                item.get("minute", ""),
                (short(" || ".join(item.get("likely", [])), 220), " || ".join(item.get("likely", []))),
                (short(" || ".join(item.get("background", [])), 220), " || ".join(item.get("background", []))),
                (short(" || ".join(item.get("dns", [])), 180), " || ".join(item.get("dns", []))),
                (short(" || ".join(item.get("network", [])), 180), " || ".join(item.get("network", []))),
            ]
        })

    proc_rows = [[item.get("time",""), str(item.get("score","")), (short(item.get("image",""),90), item.get("image","")), (short(item.get("parent",""),70), item.get("parent","")), (short(item.get("command_line",""),140), item.get("command_line","")), (short("; ".join(item.get("reasons", [])),120), "; ".join(item.get("reasons", [])))] for item in analysis_results.get("high_signal_processes", [])[:50]]
    ps_rows = [[item.get("time",""), str(item.get("event_id","")), str(item.get("score","")), (short("; ".join(item.get("reasons", [])),90), "; ".join(item.get("reasons", []))), (short(item.get("preview",""),160), item.get("preview",""))] for item in analysis_results.get("powershell_hits", [])[:30]]
    def_rows = [[item.get("time",""), str(item.get("event_id","")), (short(item.get("message",""),170), item.get("message",""))] for item in analysis_results.get("defender_hits", [])[:30]]
    pers_rows = [[item.get("time",""), str(item.get("score","")), (short(item.get("location",""),70), item.get("location","")), (short(item.get("name",""),55), item.get("name","")), (short(item.get("value",""),120), item.get("value","")), (short("; ".join(item.get("reasons", [])),120), "; ".join(item.get("reasons", [])))] for item in analysis_results.get("persistence_hits", [])[:50]]
    browser_rows = [[item.get("time",""), item.get("browser",""), item.get("type",""), str(item.get("score","")), (short(item.get("value",""),110), item.get("value","")), (short(item.get("source_url", item.get("title", "")),100), item.get("source_url", item.get("title", ""))), (short("; ".join(item.get("reasons", [])),120), "; ".join(item.get("reasons", [])))] for item in analysis_results.get("browser_risks", [])[:50]]
    dns_rows = [[q, str(c)] for q, c in analysis_results.get("network_summary", {}).get("top_dns_queries", [])]
    remote_rows = [[q, str(c)] for q, c in analysis_results.get("network_summary", {}).get("top_remote_targets", [])]
    top_findings = _v12_top_findings(data, analysis_results)

    notes_html = ""
    if analysis_results.get("notes"):
        notes_html = "<section id='notes'><h2>Gaps / Notes</h2><ul>" + "".join(f"<li>{html_escape(n)}</li>" for n in analysis_results["notes"]) + "</ul></section>"

    html_parts = []
    html_parts.append(f'''<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Windows IR Analyst Report</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2b;--panel2:#0f1726;--text:#e8edf7;--muted:#9fb0cc;--accent:#5ea1ff;--border:#26324a;--good:#2fbf71;--warn:#f0b44c;--bad:#ef6767;}}
*{{box-sizing:border-box}} body{{margin:0;font-family:Segoe UI,Arial,sans-serif;background:var(--bg);color:var(--text);line-height:1.45}}
a{{color:var(--accent);text-decoration:none}} .layout{{display:grid;grid-template-columns:280px 1fr;min-height:100vh}}
.sidebar{{position:sticky;top:0;align-self:start;height:100vh;overflow:auto;background:var(--panel2);border-right:1px solid var(--border);padding:20px}}
.sidebar h1{{font-size:20px;margin:0 0 8px}} .sidebar .meta{{color:var(--muted);font-size:13px;margin-bottom:16px}}
.nav a{{display:block;padding:8px 10px;border-radius:8px;color:var(--text);margin:3px 0}} .nav a:hover{{background:#17223a}}
.content{{padding:24px 28px 40px}} .hero{{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:22px}}
.card{{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px;min-width:190px;box-shadow:0 6px 18px rgba(0,0,0,.18)}}
.card .label{{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}}
.card .value{{font-size:20px;font-weight:700;margin-top:6px}} .card .sub{{font-size:12px;color:var(--muted);margin-top:6px}}
section{{margin:18px 0 28px}} section h2{{margin:0 0 12px;font-size:22px}} .grid-2{{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}}
.grid-3{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}}
.panel{{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:16px}}
table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}}
th,td{{padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top;text-align:left;font-size:13px}}
th{{position:sticky;top:0;background:#19243d;z-index:1}}
tr:nth-child(even) td{{background:rgba(255,255,255,.01)}} details{{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:12px 14px;margin:14px 0}}
summary{{cursor:pointer;font-weight:700}} code{{background:#1c2740;border:1px solid var(--border);padding:1px 5px;border-radius:6px}}
.badge{{display:inline-block;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:800;letter-spacing:.05em;text-transform:uppercase}}
.badge.low{{background:rgba(47,191,113,.12);color:#86efac;border:1px solid rgba(47,191,113,.35)}}
.badge.medium{{background:rgba(240,180,76,.12);color:#fcd34d;border:1px solid rgba(240,180,76,.35)}}
.badge.high{{background:rgba(239,103,103,.12);color:#fca5a5;border:1px solid rgba(239,103,103,.35)}}
.small{{font-size:12px;color:var(--muted)}} ul{{padding-left:18px}}
.top-finding .title{{font-weight:700;margin-bottom:6px}} .top-finding .time{{color:var(--muted);font-size:12px;margin-top:8px}}
.toolbar{{position:sticky;top:0;z-index:30;display:flex;gap:10px;flex-wrap:wrap;align-items:center;background:rgba(11,16,32,.92);backdrop-filter:blur(8px);padding:12px;border:1px solid var(--border);border-radius:14px;margin:0 0 18px}}
.toolbar input,.toolbar select{{background:#10192b;color:var(--text);border:1px solid var(--border);border-radius:10px;padding:10px 12px;min-width:220px}}
.toolbar button,.toolbar a.btn{{background:#13203a;color:var(--text);border:1px solid var(--border);border-radius:10px;padding:10px 12px;cursor:pointer;text-decoration:none}}
.toolbar .hint{{font-size:12px;color:var(--muted);margin-left:auto}}
.hidden-row{{display:none !important}}
@media (max-width:980px){{.layout{{grid-template-columns:1fr}} .sidebar{{position:static;height:auto;border-right:none;border-bottom:1px solid var(--border)}} .toolbar{{top:auto}}}}
@media print{{.sidebar,.toolbar{{display:none !important}} .layout{{grid-template-columns:1fr}} .content{{padding:0}} body{{background:#fff;color:#000}} .panel,.card,table,details{{box-shadow:none;border-color:#bbb}} a{{color:#000}}}}
</style>
</head><body><div class='layout'><aside class='sidebar'><h1>Windows IR Analyst Report</h1><div class='meta'>Generated: {html_escape(generated)}<br>Time window: last {days} day(s)<br>Host: {html_escape(sysinfo.get('ComputerName',''))}</div><nav class='nav'><a href='#overview'>Overview</a><a href='#topfindings'>Top 3 Findings</a><a href='#host'>Host Summary</a><a href='#visibility'>Visibility &amp; Counts</a><a href='#activity'>Activity Views</a><a href='#proc4688'>Recent 4688</a><a href='#ps4104'>Recent 4104</a><a href='#timeline'>Correlated Timeline</a><a href='#highsignal'>High-Signal Findings</a><a href='#psfindings'>PowerShell Findings</a><a href='#avfindings'>AV Findings</a><a href='#persistence'>Persistence</a><a href='#browser'>Browser Risks</a><a href='#sysmonx'>Sysmon Extended</a><a href='#sysmonnet'>Sysmon Network</a><a href='#checks'>Suggested Checks</a><a href='windows_ir_stakeholder_summary.html'>Stakeholder HTML</a></nav></aside><main class='content'>''')
    html_parts.append("""<div class='toolbar'>
<input id='globalSearch' type='search' placeholder='Quick search across visible tables…'>
<select id='activityTypeFilter'>
  <option value='all'>All activity types</option>
  <option value='process'>Process</option>
  <option value='scriptblock'>Script block</option>
  <option value='dns'>DNS</option>
  <option value='network'>Network</option>
  <option value='browser'>Browser</option>
  <option value='other'>Other</option>
</select>
<button type='button' onclick='resetFilters()'>Reset</button>
<button type='button' onclick='toggleAllDetails(true)'>Expand all</button>
<button type='button' onclick='toggleAllDetails(false)'>Collapse all</button>
<a class='btn' href='windows_ir_stakeholder_summary.html'>Stakeholder view</a>
<button type='button' onclick='window.print()'>Print / Save PDF</button>
<div class='hint'>Filters apply to Activity Views, Recent 4688, Recent 4104, and Timeline. Sysmon Extended Findings are always shown as a dedicated section.</div>
</div>""")

    html_parts.append(f"<section id='overview'><div class='hero'>"
                      f"<div class='card'><div class='label'>Risk</div><div class='value'><span class='badge {risk_class}'>{html_escape(risk_level)}</span></div><div class='sub'>{html_escape(risk_reasons[0] if risk_reasons else 'Heuristic assessment')}</div></div>"
                      f"<div class='card'><div class='label'>Security Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('security_events',0)))}</div><div class='sub'>4688 and related Windows Security events</div></div>"
                      f"<div class='card'><div class='label'>PowerShell Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('powershell_events',0)))}</div><div class='sub'>4104 and related PowerShell logs</div></div>"
                      f"<div class='card'><div class='label'>Sysmon Events</div><div class='value'>{html_escape(str(analysis_results.get('counts',{}).get('sysmon_events',0)))}</div><div class='sub'>Process, DNS, and network telemetry</div></div>"
                      f"<div class='card'><div class='label'>Likely User Actions</div><div class='value'>{html_escape(str(len(likely_items)))}</div><div class='sub'>Normalized events prioritized for triage</div></div>"
                      f"</div></section>")

    html_parts.append("<section id='topfindings'><h2>Top 3 Findings</h2><div class='grid-3'>")
    if top_findings:
        for finding in top_findings:
            html_parts.append("<div class='card top-finding'>"
                              f"<div class='label'>{html_escape(finding.get('title','Finding'))}</div>"
                              f"<div class='title'>{html_escape(short(finding.get('detail',''), 180))}</div>"
                              f"<div class='time'>{html_escape(finding.get('time',''))}</div>"
                              "</div>")
    else:
        html_parts.append("<div class='card top-finding'><div class='label'>Finding</div><div class='title'>No prioritized findings were generated from the current dataset.</div></div>")
    html_parts.append("</div></section>")

    html_parts.append(f"<section id='host'><h2>Host Summary</h2>{html_kv_table(host_rows)}</section>")
    html_parts.append(f"<section id='visibility'><h2>Visibility & Counts</h2><div class='grid-2'><div class='panel'><h3>Visibility Check</h3>{render_html_table(['Log','Exists','Collected Events'], visibility_rows)}</div><div class='panel'><h3>Counts</h3>{render_html_table(['Artifact','Count'], count_rows)}</div></div></section>")
    if notes_html:
        html_parts.append(notes_html)

    html_parts.append("<section id='activity'><h2>Activity Views</h2>")
    html_parts.append(html_details(f"<strong>Likely User Actions</strong> ({len(likely_items)} events)", _v12_render_filterable_table(["Time","Source","Type","Actor","Image","Summary","Why"], activity_rows(likely_items)), True))
    html_parts.append(html_details(f"<strong>Benign / Background Activity</strong> ({len(background_items)} events)", _v12_render_filterable_table(["Time","Source","Type","Actor","Image","Summary","Why"], activity_rows(background_items)), False))
    raw_rows = []
    for item in raw_items:
        tag = _v12_activity_tag(item.get("kind",""), item.get("source",""), "", item.get("summary",""))
        search = " ".join(str(x or "") for x in [item.get("time"), item.get("category"), item.get("source"), item.get("kind"), item.get("summary"), item.get("detail")])
        raw_rows.append({
            "tag": tag,
            "search": search,
            "cells": [item.get("time",""), item.get("category",""), item.get("source",""), item.get("kind",""), (short(item.get("summary",""),160), item.get("summary","")), (short(item.get("detail",""),180), item.get("detail",""))]
        })
    html_parts.append(html_details(f"<strong>Full Raw Timeline</strong> ({len(raw_items)} normalized events)", _v12_render_filterable_table(["Time","Category","Source","Type","Summary","Detail"], raw_rows), False))
    html_parts.append("</section>")

    html_parts.append(f"<section id='proc4688'><h2>Recent 4688 Process Executions</h2>{_v12_render_filterable_table(['Time','View','User','Image','Parent','Command Line','Why'], recent_proc_rows)}</section>")
    html_parts.append(f"<section id='ps4104'><h2>Recent 4104 User-Entered Script Blocks</h2>{_v12_render_filterable_table(['Time','View','Script Block Text','Why'], recent_ps_rows)}</section>")
    html_parts.append(f"<section id='timeline'><h2>Correlated Timeline</h2>{_v12_render_filterable_table(['Minute','Likely User','Background','DNS','Network'], timeline_rows)}</section>")

    if proc_rows:
        html_parts.append(f"<section id='highsignal'><h2>High-Signal Process Findings</h2>{render_html_table(['Time','Score','Image','Parent','Command','Why Flagged'], proc_rows)}</section>")
    else:
        html_parts.append("<section id='highsignal'><h2>High-Signal Process Findings</h2><div class='panel'><p>No high-signal process findings were flagged by the current heuristics.</p></div></section>")
    html_parts.append(f"<section id='psfindings'><h2>PowerShell Findings</h2>{render_html_table(['Time','Event ID','Score','Matches','Preview'], ps_rows)}</section>")
    if def_rows:
        html_parts.append(f"<section id='avfindings'><h2>AV Findings</h2>{render_html_table(['Time','Event ID','Message'], def_rows)}</section>")
    else:
        html_parts.append("<section id='avfindings'><h2>AV Findings</h2><div class='panel'><p>No confirmed malware detections were identified from the collected review data.</p></div></section>")
    if pers_rows:
        html_parts.append(f"<section id='persistence'><h2>Persistence Findings</h2>{render_html_table(['Time','Score','Location','Name','Value','Why Flagged'], pers_rows)}</section>")
    else:
        html_parts.append("<section id='persistence'><h2>Persistence Findings</h2><div class='panel'><p>No persistence entries were flagged by the current heuristics.</p></div></section>")
    html_parts.append(f"<section id='browser'><h2>Browser Risks</h2>{render_html_table(['Time','Browser','Type','Score','Value','Context','Why Flagged'], browser_rows)}</section>")
    html_parts.append(f"<section id='sysmonnet'><h2>Sysmon Network Summary</h2><div class='grid-2'><div class='panel'><h3>Top DNS Queries</h3>{render_html_table(['Query','Count'], dns_rows)}</div><div class='panel'><h3>Top Remote Targets</h3>{render_html_table(['Target','Count'], remote_rows)}</div></div></section>")

    checks = [
        "Start with Top 3 Findings and Likely User Actions before expanding background sections.",
        "Use the Correlated Timeline to align likely user actions with background activity and Sysmon DNS/network by minute.",
        "Use the activity-type filter and quick search to reduce noise during triage.",
        "If a URL or download looks suspicious, locate the corresponding process creation and any Sysmon DNS/network events around that minute.",
        "Validate persistence with Autoruns and live processes with Process Explorer/TCPView.",
    ]
    html_parts.append("<section id='checks'><h2>Suggested Next Manual Checks</h2><div class='panel'><ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in checks) + "</ul><p class='small'>This report is heuristic and triage-oriented. Suppression in one section does not remove the event from the Full Raw Timeline or JSON output.</p></div></section>")

    html_parts.append("""<script>
function applyFilters(){
  const q = (document.getElementById('globalSearch').value || '').toLowerCase().trim();
  const type = document.getElementById('activityTypeFilter').value || 'all';
  document.querySelectorAll('table[data-filterable="1"] tbody tr').forEach(tr => {
    const kind = (tr.dataset.kind || 'other').toLowerCase();
    const search = ((tr.dataset.search || '') + ' ' + tr.innerText).toLowerCase();
    const matchesType = (type === 'all') || (kind === type);
    const matchesSearch = !q || search.includes(q);
    tr.classList.toggle('hidden-row', !(matchesType && matchesSearch));
  });
}
function resetFilters(){
  document.getElementById('globalSearch').value = '';
  document.getElementById('activityTypeFilter').value = 'all';
  applyFilters();
}
function toggleAllDetails(openState){
  document.querySelectorAll('details').forEach(d => d.open = openState);
}
document.getElementById('globalSearch').addEventListener('input', applyFilters);
document.getElementById('activityTypeFilter').addEventListener('change', applyFilters);
</script>""")
    html_parts.append("</main></div></body></html>")
    return "".join(html_parts)


def write_outputs(outdir: Path, analyst_report_md: str, analyst_report_html: str, stakeholder_summary_md: str, stakeholder_summary_html: str, raw_data: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[Path, Path, Path, Path, Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    analyst_path = outdir / "windows_ir_analyst_report.md"
    analyst_html_path = outdir / "windows_ir_analyst_report.html"
    legacy_md_path = outdir / "windows_ir_report.md"
    stakeholder_path = outdir / "windows_ir_stakeholder_summary.md"
    stakeholder_html_path = outdir / "windows_ir_stakeholder_summary.html"
    json_path = outdir / "windows_ir_report.json"

    analyst_path.write_text(analyst_report_md, encoding="utf-8")
    analyst_html_path.write_text(analyst_report_html, encoding="utf-8")
    legacy_md_path.write_text(analyst_report_md, encoding="utf-8")
    stakeholder_path.write_text(stakeholder_summary_md, encoding="utf-8")
    stakeholder_html_path.write_text(stakeholder_summary_html, encoding="utf-8")
    json_path.write_text(json.dumps({"raw": raw_data, "analysis": analysis_results}, indent=2, ensure_ascii=False), encoding="utf-8")
    return analyst_path, analyst_html_path, stakeholder_path, stakeholder_html_path, json_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect and analyze Windows incident-response evidence.")
    parser.add_argument("--days", type=int, default=3, help="How many days back to query (default: 3)")
    parser.add_argument("--max-events", type=int, default=400, help="Max events per log query (default: 400)")
    parser.add_argument("--outdir", default="ir_report_output", help="Output directory (default: ir_report_output)")
    args = parser.parse_args()

    if os.name != "nt":
        print("This script is intended to run on Windows.", file=sys.stderr)
        return 2
    if not powershell_available():
        print("PowerShell was not found. This script requires Windows PowerShell or PowerShell 7.", file=sys.stderr)
        return 2

    raw_data: Dict[str, Any] = {"meta": {"days": args.days, "max_events": args.max_events, "is_admin": is_admin(), "generated_at": dt.datetime.now().isoformat()}}
    raw_data["system_info"] = collect_basic_system_info()
    raw_data["logs"] = {
        "Security": collect_event_log("Security", SECURITY_IDS, args.days, args.max_events),
        "System": collect_event_log("System", SYSTEM_IDS, args.days, args.max_events),
        "Defender": collect_event_log("Microsoft-Windows-Windows Defender/Operational", DEFENDER_IDS, args.days, args.max_events),
        "PowerShell": collect_event_log("Microsoft-Windows-PowerShell/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "PowerShellCore": collect_event_log("PowerShellCore/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "Sysmon": collect_event_log("Microsoft-Windows-Sysmon/Operational", SYSMON_IDS, args.days, args.max_events),
    }
    raw_data["browser_history"] = collect_browser_history(args.days, max_rows=max(50, args.max_events))
    raw_data["run_keys"] = collect_run_keys()
    raw_data["startup_items"] = collect_startup_items()

    analysis_results = analyze(raw_data)
    analyst_report_md = generate_markdown(raw_data, analysis_results, args.days)
    analyst_report_html = generate_analyst_html(raw_data, analysis_results, args.days)
    stakeholder_summary_md = generate_stakeholder_summary(raw_data, analysis_results, args.days)
    stakeholder_summary_html = generate_stakeholder_html(raw_data, analysis_results, args.days)
    analyst_path, analyst_html_path, stakeholder_path, stakeholder_html_path, json_path = write_outputs(Path(args.outdir), analyst_report_md, analyst_report_html, stakeholder_summary_md, stakeholder_summary_html, raw_data, analysis_results)

    print(f"Analyst report (Markdown) written to: {analyst_path}")
    print(f"Analyst report (HTML) written to:     {analyst_html_path}")
    print(f"Stakeholder summary (Markdown) written to: {stakeholder_path}")
    print(f"Stakeholder summary (HTML) written to:     {stakeholder_html_path}")
    print(f"JSON written to:                      {json_path}")
    if not raw_data["meta"]["is_admin"]:
        print("Tip: Run from an elevated prompt for best access to Security and other protected logs.")
    else:
        print("Admin check: elevated prompt confirmed.")
    return 0



# ===== v14 detection layer =====
_old_generate_markdown = generate_markdown
_old_generate_analyst_html = generate_analyst_html
_old_generate_stakeholder_summary = generate_stakeholder_summary
_old_generate_stakeholder_html = generate_stakeholder_html
_old_stakeholder_status_and_reasoning = stakeholder_status_and_reasoning

DETECTION_LOLBINS = {"mshta.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe"}
DETECTION_OFFICE_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
DETECTION_BROWSER_PARENTS = {"chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe"}
DETECTION_SHELL_CHILDREN = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}
DETECTION_SERVICE_PROCESS_NAMES = {"svchost.exe", "wmiprvse.exe", "lsass.exe", "services.exe", "audiodg.exe"}
DETECTION_LOW_INFO_GRANTED_ACCESS = {"0x1000", "0x1400"}
SEVERITY_RANK = {"Low": 1, "Medium": 2, "High": 3}


DETECTION_CERT_TOOL_NAMES = {"certutil.exe", "reg.exe"}
DETECTION_CERT_STORE_NAMES = {"disallowed", "trustedpublisher", "trustedpeople", "trust", "root", "authroot", "smartcardroot"}

def _is_system_certificates_path(value: str) -> bool:
    s = safe_lower(value)
    return "systemcertificates" in s

def _is_cert_store_createkey_event(event_id: int, event_type: str, target: str) -> bool:
    return int(event_id or 0) == 12 and safe_lower(event_type) == "createkey" and _is_system_certificates_path(target)

def _summary_mentions_cert_store_init(summary: str) -> bool:
    s = safe_lower(summary)
    return "registry change (createkey)" in s and "systemcertificates" in s

def _summary_mentions_cert_store_setvalue(summary: str) -> bool:
    s = safe_lower(summary)
    return "registry change (setvalue)" in s and "systemcertificates" in s

def _summary_mentions_thumbprint_like_subkey(summary: str) -> bool:
    s = summary or ""
    return bool(re.search(r'\\(?:Certificates|CRLs|CTLs)\\[0-9A-Fa-f]{8,}', s))

def _find_nearby_security_tool_events(sec_procs: List[Dict[str, Any]], anchor_time: Optional[datetime], seconds: int = 300) -> List[Dict[str, Any]]:
    hits = []
    for row in sec_procs:
        fields = row.get("fields") or {}
        image_name = fields.get("image_name", "")
        command = fields.get("command", "")
        if image_name not in DETECTION_CERT_TOOL_NAMES and not re.search(r'\b(certutil|reg\.exe)\b', command or "", re.I):
            continue
        ts = parse_iso(row.get("event", {}).get("TimeCreated", "")) if row.get("event") else None
        if anchor_time and ts and _seconds_between(anchor_time, ts) <= seconds:
            hits.append(row)
    return hits

def _classify_cert_store_cluster(sysmon_ext: List[Dict[str, Any]], sec_procs: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    cert_events = [x for x in sysmon_ext if _is_system_certificates_path(x.get("summary", ""))]
    if not cert_events:
        return None
    cert_events_sorted = sorted(cert_events, key=lambda x: x.get("time", ""))
    anchor_time = parse_iso(cert_events_sorted[0].get("time", ""))
    setvalue_hits = [x for x in cert_events if _summary_mentions_cert_store_setvalue(x.get("summary", ""))]
    thumbprint_hits = [x for x in cert_events if _summary_mentions_thumbprint_like_subkey(x.get("summary", ""))]
    tool_hits = _find_nearby_security_tool_events(sec_procs, anchor_time, seconds=300)
    createkey_hits = [x for x in cert_events if _summary_mentions_cert_store_init(x.get("summary", ""))]
    if setvalue_hits or thumbprint_hits or tool_hits:
        sample = (setvalue_hits or thumbprint_hits or cert_events_sorted)[0]
        evidence_parts = [sample.get("summary", "")]
        if thumbprint_hits:
            evidence_parts.append("thumbprint-like certificate subkey observed")
        if tool_hits:
            evidence_parts.append(f"nearby tool: {normalized_process_summary(tool_hits[0].get('fields') or {})}")
        return _make_detection(
            "Certificate Trust Store Modification",
            "Medium",
            sample.get("time", ""),
            " | ".join([part for part in evidence_parts if part]),
            "SystemCertificates activity included stronger indicators such as SetValue operations, certificate-like thumbprint subkeys, or nearby certutil/reg.exe usage.",
            "Review the exact certificate-store path, any written values/subkeys, and nearby certutil/reg.exe or PowerShell activity to determine whether trust settings were intentionally modified.",
        )
    if len(createkey_hits) >= 3:
        first = createkey_hits[0]
        return _make_detection(
            "Trust Store Initialization (Likely Benign)",
            "Low",
            first.get("time", ""),
            f"{len(createkey_hits)} SystemCertificates CreateKey events observed (example: {first.get('summary','')})",
            "Broad clusters of CreateKey operations under SystemCertificates commonly occur during certificate/trust-store initialization and policy evaluation when no SetValue writes, thumbprint-like subkeys, or certutil/reg.exe activity are nearby.",
            "Document and deprioritize unless additional certificate-store writes, thumbprint subkeys, or certificate-management tooling appear in the same window.",
        )
    return None


def _severity_rank(level: str) -> int:
    return SEVERITY_RANK.get(str(level or "").title(), 0)


def _parse_process_access_summary(summary: str) -> Dict[str, str]:
    m = re.match(r"(?P<src>[^\s]+) accessed (?P<dst>.+?)(?: \(GrantedAccess (?P<ga>0x[0-9A-Fa-f]+)\))?$", summary or "")
    if not m:
        return {}
    return {
        "source_name": (m.group("src") or "").lower(),
        "target_name": (m.group("dst") or "").lower(),
        "granted_access": (m.group("ga") or "").lower(),
    }


def _classify_process_tamper_sample(sample: Dict[str, Any]) -> Tuple[str, str, str]:
    event_id = int(sample.get("event_id", 0) or 0)
    summary = sample.get("summary", "")
    if event_id == 10:
        parsed = _parse_process_access_summary(summary)
        src = parsed.get("source_name", "")
        ga = parsed.get("granted_access", "")
        if src in DETECTION_SERVICE_PROCESS_NAMES and ga in DETECTION_LOW_INFO_GRANTED_ACCESS:
            return (
                "Process Access (Likely Benign Service Query)",
                "Low",
                "Sysmon recorded limited-information process access from a common Windows service process. This often reflects routine inspection by Windows, management components, or security tooling rather than code injection.",
            )
    if event_id in {8, 25}:
        return (
            "Process Tampering / Injection-Adjacent Activity",
            "High",
            "Sysmon recorded remote thread creation or process tampering, which is more strongly associated with injection, tampering, or defense-evasion behavior.",
        )
    return (
        "Process Tampering / Injection-Adjacent Activity",
        "Medium",
        "Sysmon recorded activity associated with remote thread creation, process access, or process tampering, which can indicate injection or defense-evasion behavior.",
    )


def _dedupe_detections(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for d in detections:
        key = (
            str(d.get("name", "")).lower(),
            str(d.get("time", "")),
            str(d.get("evidence", ""))[:200].lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(d)
    out.sort(
        key=lambda x: (
            -_severity_rank(x.get("severity", "")),
            -(parse_iso(x.get("time")).timestamp() if parse_iso(x.get("time")) else 0.0),
            x.get("name", ""),
        )
    )
    return out


def _make_detection(name: str, severity: str, time: str, evidence: str, why: str, action: str) -> Dict[str, Any]:
    return {
        "name": name,
        "severity": severity.title(),
        "time": time or "",
        "evidence": normalize_inline(evidence, 260),
        "why": normalize_inline(why, 220),
        "action": normalize_inline(action, 220),
    }


def _all_4104_user_events(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for event in _all_powershell_events(data):
        if int(event.get("Id", 0)) != 4104:
            continue
        text = extract_scriptblock_text(event.get("Message") or "")
        if is_self_collection_scriptblock(text):
            continue
        if stakeholder_noise_scriptblock(text):
            continue
        rows.append({"time": event.get("TimeCreated", ""), "text": text})
    rows.sort(key=lambda x: x.get("time", ""), reverse=True)
    return rows


def _recent_security_processes(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for event in _all_security_events(data):
        if int(event.get("Id", 0)) != 4688:
            continue
        fields = get_process_fields(event)
        if is_reporter_self_process(fields) or is_devtool_noise_process(fields):
            continue
        rows.append({"event": event, "fields": fields})
    rows.sort(key=lambda x: x["event"].get("TimeCreated", ""), reverse=True)
    return rows


def _sysmon_by_ids(data: Dict[str, Any], ids: Iterable[int]) -> List[Dict[str, Any]]:
    target = set(int(x) for x in ids)
    rows = [e for e in _all_sysmon_events(data) if int(e.get("Id", 0)) in target]
    rows.sort(key=lambda x: x.get("TimeCreated", ""), reverse=True)
    return rows


def build_named_detections(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []
    ps4104 = _all_4104_user_events(data)
    sec_procs = _recent_security_processes(data)
    sysmon_ext = analysis_results.get("sysmon_extended_findings", [])

    # 1) PowerShell web request
    for row in ps4104:
        text = row["text"]
        lowered = text.lower()
        if re.search(r"\b(invoke-webrequest|iwr|curl|wget)\b", lowered):
            url, outfile = extract_iwr_details(text)
            details = []
            if url:
                details.append(url)
            if outfile:
                details.append(f"outfile={outfile}")
            extra = f" ({', '.join(details)})" if details else ""
            severity, why, action = _webrequest_context_score(row["time"], url, outfile, sec_procs, sysmon_ext)
            detections.append(_make_detection(
                "PowerShell Web Request",
                severity,
                row["time"],
                text,
                why + extra,
                action,
            ))

    # 2) PowerShell to command shell
    for row in sec_procs:
        event = row["event"]
        fields = row["fields"]
        if fields.get("image_name") == "cmd.exe" and fields.get("parent_name") in POWERSHELL_PARENT_NAMES:
            detections.append(_make_detection(
                "PowerShell to Command Shell",
                "Medium",
                event.get("TimeCreated", ""),
                normalized_process_summary(fields),
                "PowerShell launched cmd.exe, a common staging and execution pattern for administrative tooling and attacker tradecraft.",
                "Review the parent PowerShell command, child command line, created files, and nearby network activity.",
            ))

    # 3) PowerShell to LOLBin
    for row in sec_procs:
        event = row["event"]
        fields = row["fields"]
        if fields.get("image_name") in DETECTION_LOLBINS and fields.get("parent_name") in POWERSHELL_PARENT_NAMES:
            detections.append(_make_detection(
                "PowerShell to LOLBin",
                "High",
                event.get("TimeCreated", ""),
                normalized_process_summary(fields),
                "PowerShell launched a living-off-the-land binary commonly abused for script execution, proxy execution, or defense evasion.",
                "Validate intent immediately and pivot into parent PowerShell content, child command line, and related file/network telemetry.",
            ))

    # 4) Suspicious child from Office/browser
    for row in sec_procs:
        event = row["event"]
        fields = row["fields"]
        child = fields.get("image_name")
        parent = fields.get("parent_name")
        if child in DETECTION_SHELL_CHILDREN and parent in (DETECTION_OFFICE_PARENTS | DETECTION_BROWSER_PARENTS):
            severity = "High" if parent in DETECTION_OFFICE_PARENTS else "Medium"
            parent_label = "Office application" if parent in DETECTION_OFFICE_PARENTS else "browser"
            detections.append(_make_detection(
                "Suspicious Child Process from Office/Browser",
                severity,
                event.get("TimeCreated", ""),
                normalized_process_summary(fields),
                f"A {parent_label} spawned a shell/script-capable child process, which is commonly associated with phishing, macro abuse, or browser exploitation chains.",
                "Review the parent document/tab context, child command line, and any downloads, script blocks, or persistence created immediately afterward.",
            ))

    # 5) Persistence creation / persistence-related changes
    persistence_hits = analysis_results.get("persistence_hits", [])
    if persistence_hits:
        sample = persistence_hits[0]
        evidence = f"{sample.get('location','')} | {sample.get('name','')} | {sample.get('value','')}"
        detections.append(_make_detection(
            "Persistence-Related Change",
            "Medium",
            sample.get("time", ""),
            evidence,
            "Persistence locations or startup-related artifacts were flagged, indicating a change that could survive logon or reboot.",
            "Validate the referenced run key, startup entry, scheduled-task/service indicator, or WMI-related artifact in context.",
        ))
    else:
        wmi_like = [x for x in sysmon_ext if int(x.get("event_id", 0)) in {19, 20, 21}]
        if wmi_like:
            sample = wmi_like[0]
            detections.append(_make_detection(
                "WMI Persistence-Adjacent Activity",
                "Medium",
                sample.get("time", ""),
                sample.get("summary", ""),
                "WMI-related Sysmon activity was observed. WMI event filters, consumers, and bindings can be used for persistence or remote execution.",
                "Review WMI event registrations and confirm whether the observed WMI activity is expected administrative behavior.",
            ))

    # 5b) Certificate trust-store initialization / modification
    cert_store_detection = _classify_cert_store_cluster(sysmon_ext, sec_procs)
    if cert_store_detection:
        detections.append(cert_store_detection)

    # 6) Process tampering / injection-adjacent
    tamper = [x for x in sysmon_ext if int(x.get("event_id", 0)) in {8, 10, 25}]
    if tamper:
        tamper_sorted = sorted(
            tamper,
            key=lambda x: (
                0 if int(x.get("event_id", 0)) in {8, 25} else 1,
                0 if (_parse_process_access_summary(x.get("summary", "")).get("source_name", "") in DETECTION_SERVICE_PROCESS_NAMES and _parse_process_access_summary(x.get("summary", "")).get("granted_access", "") in DETECTION_LOW_INFO_GRANTED_ACCESS) else 1,
                x.get("time", ""),
            )
        )
        sample = tamper_sorted[0]
        det_name, det_severity, det_why = _classify_process_tamper_sample(sample)
        detections.append(_make_detection(
            det_name,
            det_severity,
            sample.get("time", ""),
            sample.get("summary", ""),
            det_why,
            "Validate the source/target processes and determine whether debugging, security tooling, or legitimate software can explain the behavior.",
        ))

    # 7) Executable dropped or detected
    exec_detected = [x for x in sysmon_ext if int(x.get("event_id", 0)) == 29]
    if exec_detected:
        sample = exec_detected[0]
        detections.append(_make_detection(
            "Executable Dropped / Detected",
            "Medium",
            sample.get("time", ""),
            sample.get("summary", ""),
            "Sysmon recorded a newly detected executable file, which may indicate a dropper, staged payload, or newly introduced binary on disk.",
            "Identify the file path, hash the file, and review nearby process, download, and script activity.",
        ))

    # 8) Delete-after-execution style behavior
    delete_detected = [x for x in sysmon_ext if int(x.get("event_id", 0)) == 26]
    suspicious_anchor_times = [
        parse_iso(x["time"]) for x in ps4104[:25]
        if re.search(r"\b(invoke-webrequest|iwr|curl|wget|start-process|cmd\.exe|notepad\.exe)\b", x["text"], re.I)
    ]
    for sample in delete_detected:
        ts = parse_iso(sample.get("time"))
        if ts and any(_seconds_between(ts, anchor) <= 300 for anchor in suspicious_anchor_times if anchor):
            detections.append(_make_detection(
                "Delete-After-Execution Style Activity",
                "Medium",
                sample.get("time", ""),
                sample.get("summary", ""),
                "A file-delete detection occurred close to notable execution or staging activity, which can indicate cleanup or evidence removal.",
                "Review the deleted path, surrounding process executions, and any dropped or executed files in the same time window.",
            ))
            break

    return _dedupe_detections(detections)


def _v14_detection_summary_lines(analysis_results: Dict[str, Any], limit: int = 3) -> List[str]:
    lines = []
    for det in analysis_results.get("detections", [])[:limit]:
        lines.append(f"{det.get('severity','')} — {det.get('name','')}: {det.get('why','')}")
    return lines


def stakeholder_status_and_reasoning(sysinfo: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[str, List[str]]:
    level, reasons = _old_stakeholder_status_and_reasoning(sysinfo, analysis_results)
    detections = analysis_results.get("detections", [])
    high_dets = [d for d in detections if d.get("severity") == "High"]
    med_dets = [d for d in detections if d.get("severity") == "Medium"]
    if high_dets:
        reasons.insert(0, f"{len(high_dets)} named detection(s) reached High severity and should be reviewed first.")
        if level == "Low":
            level = "Medium"
    elif med_dets:
        reasons.insert(0, f"{len(med_dets)} named detection(s) reached Medium severity and should be validated in context.")
    return level, reasons


def _render_detection_markdown(analysis_results: Dict[str, Any]) -> str:
    dets = analysis_results.get("detections", [])
    if not dets:
        return "## Detections\n\nNo named detections fired from the current rule set.\n"
    rows = []
    for d in dets[:25]:
        rows.append([
            d.get("time", ""),
            d.get("severity", ""),
            d.get("name", ""),
            short(d.get("evidence", ""), 120),
            short(d.get("why", ""), 120),
            short(d.get("action", ""), 120),
        ])
    parts = ["## Detections\n", render_table(["Time", "Severity", "Detection Name", "Evidence", "Why It Fired", "Recommended Analyst Action"], rows), ""]
    why_lines = _v14_detection_summary_lines(analysis_results, limit=5)
    if why_lines:
        parts.append("## Why This Matters\n")
        parts.extend([f"- {line}" for line in why_lines])
        parts.append("")
    return "\n".join(parts)


def _render_detection_html_section(analysis_results: Dict[str, Any]) -> str:
    dets = analysis_results.get("detections", [])
    if not dets:
        return "<section id='detections'><h2>Detections</h2><div class='panel'><p>No named detections fired from the current rule set.</p></div></section>"
    rows = []
    for d in dets[:25]:
        sev = d.get("severity", "")
        rows.append([
            d.get("time", ""),
            sev,
            d.get("name", ""),
            (short(d.get("evidence", ""), 130), d.get("evidence", "")),
            (short(d.get("why", ""), 140), d.get("why", "")),
            (short(d.get("action", ""), 140), d.get("action", "")),
        ])
    why_lines = _v14_detection_summary_lines(analysis_results, limit=5)
    why_html = ""
    if why_lines:
        why_html = "<div class='panel'><h3>Why This Matters</h3><ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in why_lines) + "</ul></div>"
    return f"<section id='detections'><h2>Detections</h2>{render_html_table(['Time','Severity','Detection Name','Evidence','Why It Fired','Recommended Analyst Action'], rows)}{why_html}</section>"


def generate_markdown(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_generate_markdown(data, analysis_results, days)
    section = _render_detection_markdown(analysis_results)
    if "## Host Summary" in base:
        return base.replace("## Host Summary", section + "\n## Host Summary", 1)
    return base + "\n\n" + section


def generate_stakeholder_summary(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_generate_stakeholder_summary(data, analysis_results, days)
    dets = analysis_results.get("detections", [])
    if not dets:
        return base
    rows = []
    for d in dets[:5]:
        rows.append([stakeholder_format_time(d.get("time", "")), d.get("severity", ""), d.get("name", ""), d.get("why", "")])
    section = "## Named Detections\n\n" + render_table(["Time", "Severity", "Detection", "Why It Matters"], rows) + "\n\n"
    if "## Key Findings" in base:
        return base.replace("## Key Findings\n", section + "## Key Findings\n", 1)
    return base + "\n\n" + section


def generate_stakeholder_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_generate_stakeholder_html(data, analysis_results, days)
    dets = analysis_results.get("detections", [])
    if not dets:
        return base
    rows = []
    for d in dets[:5]:
        rows.append([stakeholder_format_time(d.get("time", "")), d.get("severity", ""), d.get("name", ""), d.get("why", "")])
    section = "<section><h2>Named Detections</h2>" + render_html_table(["Time", "Severity", "Detection", "Why It Matters"], rows) + "</section>"
    return base.replace("<section><h2>Key Findings</h2>", section + "<section><h2>Key Findings</h2>", 1)


def generate_analyst_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_generate_analyst_html(data, analysis_results, days)
    section = _render_detection_html_section(analysis_results)
    base = base.replace("<a href='#host'>Host Summary</a>", "<a href='#detections'>Detections</a><a href='#host'>Host Summary</a>", 1)
    base = base.replace("<section id='host'>", section + "<section id='host'>", 1)
    return base


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect and analyze Windows incident-response evidence.")
    parser.add_argument("--days", type=int, default=3, help="How many days back to query (default: 3)")
    parser.add_argument("--max-events", type=int, default=400, help="Max events per log query (default: 400)")
    parser.add_argument("--outdir", default="ir_report_output", help="Output directory (default: ir_report_output)")
    args = parser.parse_args()

    if os.name != "nt":
        print("This script is intended to run on Windows.", file=sys.stderr)
        return 2
    if not powershell_available():
        print("PowerShell was not found. This script requires Windows PowerShell or PowerShell 7.", file=sys.stderr)
        return 2

    raw_data: Dict[str, Any] = {"meta": {"days": args.days, "max_events": args.max_events, "is_admin": is_admin(), "generated_at": dt.datetime.now().isoformat()}}
    raw_data["system_info"] = collect_basic_system_info()
    raw_data["logs"] = {
        "Security": collect_event_log("Security", SECURITY_IDS, args.days, args.max_events),
        "System": collect_event_log("System", SYSTEM_IDS, args.days, args.max_events),
        "Defender": collect_event_log("Microsoft-Windows-Windows Defender/Operational", DEFENDER_IDS, args.days, args.max_events),
        "PowerShell": collect_event_log("Microsoft-Windows-PowerShell/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "PowerShellCore": collect_event_log("PowerShellCore/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "Sysmon": collect_event_log("Microsoft-Windows-Sysmon/Operational", SYSMON_IDS, args.days, args.max_events),
    }
    raw_data["browser_history"] = collect_browser_history(args.days, max_rows=max(50, args.max_events))
    raw_data["run_keys"] = collect_run_keys()
    raw_data["startup_items"] = collect_startup_items()

    analysis_results = analyze(raw_data)
    analysis_results["detections"] = build_named_detections(raw_data, analysis_results)

    analyst_report_md = generate_markdown(raw_data, analysis_results, args.days)
    analyst_report_html = generate_analyst_html(raw_data, analysis_results, args.days)
    stakeholder_summary_md = generate_stakeholder_summary(raw_data, analysis_results, args.days)
    stakeholder_summary_html = generate_stakeholder_html(raw_data, analysis_results, args.days)
    analyst_path, analyst_html_path, stakeholder_path, stakeholder_html_path, json_path = write_outputs(Path(args.outdir), analyst_report_md, analyst_report_html, stakeholder_summary_md, stakeholder_summary_html, raw_data, analysis_results)

    print(f"Analyst report (Markdown) written to: {analyst_path}")
    print(f"Analyst report (HTML) written to:     {analyst_html_path}")
    print(f"Stakeholder summary (Markdown) written to: {stakeholder_path}")
    print(f"Stakeholder summary (HTML) written to:     {stakeholder_html_path}")
    print(f"JSON written to:                      {json_path}")
    if not raw_data["meta"]["is_admin"]:
        print("Tip: Run from an elevated prompt for best access to Security and other protected logs.")
    else:
        print("Admin check: elevated prompt confirmed.")
    return 0


# ===== v15 case workflow + triage playbooks =====
_old_v15_generate_markdown = generate_markdown
_old_v15_generate_analyst_html = generate_analyst_html
_old_v15_generate_stakeholder_summary = generate_stakeholder_summary
_old_v15_generate_stakeholder_html = generate_stakeholder_html
_old_v15_write_outputs = write_outputs


PLAYBOOKS: Dict[str, Dict[str, List[str]]] = {
    "PowerShell to Command Shell": {
        "triage": [
            "Review the parent PowerShell command and confirm whether the shell launch was intentional.",
            "Inspect the child command line and any files written or modified by the command.",
            "Check nearby DNS/network activity to determine whether the shell launch was part of a download or staging chain.",
        ],
        "evidence": [
            "4688 events for the parent and child processes",
            "4104 script block entries around the event time",
            "Sysmon DNS/network events within ±5 minutes",
            "Any files created by the command, including hashes and file metadata",
        ],
    },
    "PowerShell Web Request": {
        "triage": [
            "Validate whether the destination domain, URL, and saved file path were expected.",
            "Determine whether the downloaded content was opened, executed, or referenced by later commands.",
            "Review the PowerShell parent/child process chain and any network or file events around the request.",
        ],
        "evidence": [
            "4104 entry containing the web request command",
            "4688 process lineage for the invoking PowerShell session",
            "Sysmon DNS/network events for the destination domain and remote IPs",
            "The downloaded file on disk, including hash, size, path, and signer details",
        ],
    },
    "PowerShell to LOLBin": {
        "triage": [
            "Review the exact child process, arguments, and parent PowerShell command.",
            "Determine whether the LOLBin use is a normal admin action or a suspicious execution proxy.",
            "Check for follow-on persistence, downloads, or outbound network activity.",
        ],
        "evidence": [
            "4688 parent/child process records",
            "4104 PowerShell script block content",
            "Sysmon network, file-create, and registry events around the same time",
            "Any referenced scripts, URLs, DLLs, or HTA/JS content",
        ],
    },
    "Suspicious Child Process from Office/Browser": {
        "triage": [
            "Confirm whether the Office or browser parent process launching a shell/script tool was expected.",
            "Identify the document, page, or content the parent process was handling at the time.",
            "Review child process command lines and any follow-on execution or persistence.",
        ],
        "evidence": [
            "4688 process lineage from the parent Office/browser process to the child",
            "Browser history or recent document artifacts near the event time",
            "Downloaded files, temp files, and attachment artifacts",
            "Sysmon file, DNS, and network events around the launch time",
        ],
    },
    "Persistence-Related Change": {
        "triage": [
            "Validate whether the persistence location and written value/path were expected.",
            "Determine which process created or modified the entry and whether that process was user-driven.",
            "Check for matching files on disk, signer information, and recurrence mechanisms.",
        ],
        "evidence": [
            "Registry path or startup item details",
            "4688 process lineage for the creating process",
            "Sysmon registry/file events around the persistence time window",
            "Autoruns output or scheduled-task/service listings if available",
        ],
    },
    "Process Tampering / Injection-Adjacent Activity": {
        "triage": [
            "Validate the source and target processes and the requested access rights.",
            "Determine whether the behavior can be explained by security tools, WMI, debuggers, or Windows components.",
            "Escalate if the event is paired with remote thread creation, process tampering, or suspicious follow-on execution.",
        ],
        "evidence": [
            "Sysmon Event IDs 8, 10, and 25 around the event time",
            "GrantedAccess details and process lineage for both source and target",
            "Any follow-on child processes, DLL loads, or network activity",
            "Security tooling context or endpoint product activity on the host",
        ],
    },
    "Process Access (Likely Benign Service Query)": {
        "triage": [
            "Confirm that the source process is a normal Windows service process and the access rights are low-information only.",
            "Check whether the target process was being queried during expected system, security, or management activity.",
        ],
        "evidence": [
            "Sysmon Event ID 10 details for source, target, and GrantedAccess",
            "Nearby service/WMI activity and endpoint tooling context",
        ],
    },
    "Executable Dropped / Detected": {
        "triage": [
            "Locate the file on disk and determine whether it was recently introduced or executed.",
            "Review how the file arrived on the host and whether it matches a known installer, update, or payload.",
            "Check for signer information, hashes, and follow-on execution or deletion.",
        ],
        "evidence": [
            "Sysmon Event ID 29 details and any related file-create events",
            "File hash, signer, path, timestamps, and user context",
            "Parent process, browser/download, or PowerShell context tied to the file",
        ],
    },
    "Delete-After-Execution Style Activity": {
        "triage": [
            "Determine what file was deleted and whether it was a benign temp/policy artifact or part of execution cleanup.",
            "Review suspicious commands, downloads, and execution within the surrounding time window.",
        ],
        "evidence": [
            "Sysmon Event ID 26 details for the deleted path",
            "4104/4688 activity within ±5 minutes",
            "Any matching dropped files, temp files, or persistence mechanisms",
        ],
    },
    "Certificate Trust Store Modification": {
        "triage": [
            "Confirm which certificate store path was modified and whether the change was policy-driven or manual.",
            "Validate whether tools like certutil.exe or reg.exe were used nearby.",
            "Escalate if thumbprint-like certificate subkeys or SetValue operations are present.",
        ],
        "evidence": [
            "Sysmon registry events under SystemCertificates including SetValue/CreateKey details",
            "4688 events for certutil.exe, reg.exe, or other certificate-management tools",
            "Relevant Group Policy or certificate deployment context",
        ],
    },
    "Trust Store Initialization (Likely Benign)": {
        "triage": [
            "Confirm the burst is broad certificate-store initialization rather than a focused certificate modification.",
            "Check for SetValue operations or certificate thumbprint subkeys before escalating.",
        ],
        "evidence": [
            "Sysmon registry CreateKey cluster under SystemCertificates",
            "Any nearby certutil.exe/reg.exe usage",
            "PowerShell/WinTrust/certificate-policy activity in the same window",
        ],
    },
}

GENERAL_TRIAGE_STEPS = [
    "Confirm whether the activity aligns with a known admin, lab, or user action.",
    "Review the exact event time and process lineage before concluding maliciousness.",
]

GENERAL_EVIDENCE_ITEMS = [
    "Raw analyst report HTML/Markdown and JSON output",
    "Relevant EVTX exports or screenshots captured during review",
]


def _severity_rank(sev: str) -> int:
    return SEVERITY_RANK.get(sev, 0)


def _case_priority_from_detections(detections: List[Dict[str, Any]]) -> str:
    if any(d.get("severity") == "High" for d in detections):
        return "High"
    if any(d.get("severity") == "Medium" for d in detections):
        return "Medium"
    if detections:
        return "Low"
    return "Informational"


def _case_status_from_priority(priority: str) -> str:
    return {
        "High": "Needs immediate analyst review",
        "Medium": "Needs analyst validation",
        "Low": "Monitor / validate in context",
        "Informational": "No immediate action required",
    }.get(priority, "Needs analyst validation")


def _playbook_for_detection_name(name: str) -> Dict[str, List[str]]:
    return PLAYBOOKS.get(name, {"triage": [], "evidence": []})


def _dedupe_keep_order(items: Iterable[str], limit: Optional[int] = None) -> List[str]:
    out: List[str] = []
    seen = set()
    for item in items:
        item = (item or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
        if limit and len(out) >= limit:
            break
    return out


def build_case_workflow(raw_data: Dict[str, Any], analysis_results: Dict[str, Any], outdir: Optional[Path] = None) -> Dict[str, Any]:
    detections = sorted(
        analysis_results.get("detections", []),
        key=lambda d: (_severity_rank(d.get("severity", "")), d.get("time", "")),
        reverse=True,
    )
    generated_at = parse_iso(raw_data.get("meta", {}).get("generated_at")) or dt.datetime.now()
    hostname = raw_data.get("system_info", {}).get("computer_name") or platform.node() or "HOST"
    case_id = f"IR-{generated_at.strftime('%Y%m%d-%H%M%S')}-{hostname}"
    priority = _case_priority_from_detections(detections)
    status = _case_status_from_priority(priority)
    top_detections = detections[:5]
    triage_steps: List[str] = []
    evidence_items: List[str] = []
    for det in top_detections:
        pb = _playbook_for_detection_name(det.get("name", ""))
        triage_steps.extend(pb.get("triage", []))
        evidence_items.extend(pb.get("evidence", []))
    triage_steps.extend(GENERAL_TRIAGE_STEPS)
    evidence_items.extend(GENERAL_EVIDENCE_ITEMS)
    triage_steps = _dedupe_keep_order(triage_steps, limit=10)
    evidence_items = _dedupe_keep_order(evidence_items, limit=12)

    if top_detections:
        summary = f"{len(top_detections)} detection(s) were highlighted. Highest current detection priority is {priority}."
    else:
        summary = "No named detections fired. Use the analyst report for context and spot-checking."
    if priority == "High":
        summary += " Immediate analyst review is recommended."
    elif priority == "Medium":
        summary += " Analyst validation is recommended before closing the case."
    elif priority == "Low":
        summary += " Activity appears low priority but should still be validated in context."

    case = {
        "case_id": case_id,
        "generated_at": raw_data.get("meta", {}).get("generated_at", dt.datetime.now().isoformat()),
        "priority": priority,
        "status": status,
        "summary": summary,
        "top_detections": [
            {
                "time": d.get("time", ""),
                "severity": d.get("severity", ""),
                "name": d.get("name", ""),
                "evidence": d.get("evidence", ""),
                "why": d.get("why", ""),
                "action": d.get("action", ""),
            }
            for d in top_detections
        ],
        "triage_steps": triage_steps,
        "next_evidence_to_collect": evidence_items,
        "paths": {
            "case_root": str((Path(outdir) / "cases" / case_id) if outdir else Path("cases") / case_id),
            "evidence_dir": str(((Path(outdir) / "cases" / case_id / "evidence") if outdir else Path("cases") / case_id / "evidence")),
            "exports_dir": str(((Path(outdir) / "cases" / case_id / "exports") if outdir else Path("cases") / case_id / "exports")),
            "notes_dir": str(((Path(outdir) / "cases" / case_id / "notes") if outdir else Path("cases") / case_id / "notes")),
        },
    }
    return case


def _render_case_workflow_markdown(analysis_results: Dict[str, Any]) -> str:
    case = analysis_results.get("case", {})
    if not case:
        return ""
    parts = [
        "## Case Workflow\n",
        f"- **Case ID:** `{case.get('case_id','')}`",
        f"- **Priority:** **{case.get('priority','')}**",
        f"- **Status:** {case.get('status','')}",
        f"- **Summary:** {case.get('summary','')}",
        "",
    ]
    top = case.get("top_detections", [])
    if top:
        rows = []
        for d in top:
            rows.append([
                d.get("time", ""),
                d.get("severity", ""),
                d.get("name", ""),
                short(d.get("evidence", ""), 100),
            ])
        parts.append("### Top Detections\n")
        parts.append(render_table(["Time", "Severity", "Detection", "Evidence"], rows))
        parts.append("")
    triage = case.get("triage_steps", [])
    if triage:
        parts.append("### Recommended Triage Actions\n")
        parts.extend([f"{i+1}. {step}" for i, step in enumerate(triage)])
        parts.append("")
    evidence = case.get("next_evidence_to_collect", [])
    if evidence:
        parts.append("### Next Evidence to Collect\n")
        parts.extend([f"- {item}" for item in evidence])
        parts.append("")
    return "\n".join(parts)


def _render_case_workflow_html(analysis_results: Dict[str, Any]) -> str:
    case = analysis_results.get("case", {})
    if not case:
        return ""
    cards = [
        f"<div class='card'><div class='label'>Case ID</div><div class='value' style='font-size:18px'>{html_escape(case.get('case_id',''))}</div><div class='sub'>Automatic case package identifier</div></div>",
        f"<div class='card'><div class='label'>Case Priority</div><div class='value'><span class='badge {safe_lower(case.get('priority','informational')) if safe_lower(case.get('priority','')) in {'low','medium','high'} else 'low'}'>{html_escape(case.get('priority','Informational'))}</span></div><div class='sub'>{html_escape(case.get('status',''))}</div></div>",
        f"<div class='card'><div class='label'>Case Summary</div><div class='sub'>{html_escape(case.get('summary',''))}</div></div>",
    ]
    html_parts = [f"<section id='caseworkflow'><h2>Case Workflow</h2><div class='grid-3'>{''.join(cards)}</div>"]
    top = case.get("top_detections", [])
    if top:
        rows = []
        for d in top:
            rows.append([
                d.get("time", ""),
                d.get("severity", ""),
                d.get("name", ""),
                (short(d.get("evidence", ""), 120), d.get("evidence", "")),
            ])
        html_parts.append("<div class='panel'><h3>Top Detections</h3>" + render_html_table(["Time", "Severity", "Detection", "Evidence"], rows) + "</div>")
    triage = case.get("triage_steps", [])
    evidence = case.get("next_evidence_to_collect", [])
    if triage or evidence:
        html_parts.append("<div class='grid-2'>")
        if triage:
            html_parts.append("<div class='panel'><h3>Recommended Triage Actions</h3><ol>" + "".join(f"<li>{html_escape(x)}</li>" for x in triage) + "</ol></div>")
        if evidence:
            html_parts.append("<div class='panel'><h3>Next Evidence to Collect</h3><ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in evidence) + "</ul></div>")
        html_parts.append("</div>")
    html_parts.append("</section>")
    return "".join(html_parts)


def create_case_package(case: Dict[str, Any], analyst_md: Path, analyst_html: Path, stakeholder_md: Path, stakeholder_html: Path, json_path: Path) -> Path:
    case_root = Path(case["paths"]["case_root"])
    evidence_dir = Path(case["paths"]["evidence_dir"])
    exports_dir = Path(case["paths"]["exports_dir"])
    notes_dir = Path(case["paths"]["notes_dir"])
    for p in (case_root, evidence_dir, exports_dir, notes_dir):
        p.mkdir(parents=True, exist_ok=True)

    files_to_copy = [analyst_md, analyst_html, stakeholder_md, stakeholder_html, json_path]
    copied = []
    for src in files_to_copy:
        dst = case_root / src.name
        shutil.copy2(src, dst)
        copied.append(str(dst))

    manifest = {
        "case": case,
        "copied_reports": copied,
    }
    manifest_path = case_root / "case_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    readme_lines = [
        f"Case ID: {case.get('case_id','')}",
        f"Priority: {case.get('priority','')}",
        f"Status: {case.get('status','')}",
        "",
        "Summary:",
        case.get("summary",""),
        "",
        "Top detections:",
    ]
    for d in case.get("top_detections", []):
        readme_lines.append(f"- {d.get('severity','')} — {d.get('name','')} @ {d.get('time','')}")
    readme_lines.extend(["", "Recommended triage actions:"])
    for i, step in enumerate(case.get("triage_steps", []), 1):
        readme_lines.append(f"{i}. {step}")
    readme_lines.extend(["", "Next evidence to collect:"])
    for item in case.get("next_evidence_to_collect", []):
        readme_lines.append(f"- {item}")
    (case_root / "README_case_workflow.txt").write_text("\n".join(readme_lines), encoding="utf-8")
    return case_root


def generate_markdown(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_v15_generate_markdown(data, analysis_results, days)
    section = _render_case_workflow_markdown(analysis_results)
    if not section:
        return base
    if "## Detections" in base:
        return base.replace("## Detections", section + "\n## Detections", 1)
    if "## Host Summary" in base:
        return base.replace("## Host Summary", section + "\n## Host Summary", 1)
    return section + "\n" + base


def generate_stakeholder_summary(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_v15_generate_stakeholder_summary(data, analysis_results, days)
    case = analysis_results.get("case", {})
    if not case:
        return base
    rows = [
        ["Case ID", case.get("case_id", "")],
        ["Priority", case.get("priority", "")],
        ["Status", case.get("status", "")],
        ["Summary", case.get("summary", "")],
    ]
    if case.get("top_detections"):
        rows.append(["Top detection", f"{case['top_detections'][0].get('severity','')} — {case['top_detections'][0].get('name','')}"])
    triage = case.get("triage_steps", [])[:4]
    section = "## Case Summary\n\n" + render_table(["Field", "Value"], rows) + "\n\n"
    if triage:
        section += "## Recommended Triage Actions\n\n" + "\n".join(f"{i+1}. {step}" for i, step in enumerate(triage)) + "\n\n"
    if "## What Was Observed" in base:
        return base.replace("## What Was Observed", section + "## What Was Observed", 1)
    return section + base


def generate_stakeholder_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_v15_generate_stakeholder_html(data, analysis_results, days)
    case = analysis_results.get("case", {})
    if not case:
        return base
    rows = [
        ["Case ID", case.get("case_id", "")],
        ["Priority", case.get("priority", "")],
        ["Status", case.get("status", "")],
        ["Summary", case.get("summary", "")],
    ]
    if case.get("top_detections"):
        rows.append(["Top detection", f"{case['top_detections'][0].get('severity','')} — {case['top_detections'][0].get('name','')}"])
    section = "<section><h2>Case Summary</h2>" + render_html_table(["Field", "Value"], rows) + "</section>"
    triage = case.get("triage_steps", [])[:4]
    if triage:
        section += "<section><h2>Recommended Triage Actions</h2><div class='card'><ol>" + "".join(f"<li>{html_escape(x)}</li>" for x in triage) + "</ol></div></section>"
    return base.replace("<section><h2>What Was Observed</h2>", section + "<section><h2>What Was Observed</h2>", 1)


def generate_analyst_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _old_v15_generate_analyst_html(data, analysis_results, days)
    section = _render_case_workflow_html(analysis_results)
    if not section:
        return base
    base = base.replace("<a href='#topfindings'>Top 3 Findings</a>", "<a href='#topfindings'>Top 3 Findings</a><a href='#caseworkflow'>Case Workflow</a>", 1)
    base = base.replace("<section id='detections'>", section + "<section id='detections'>", 1)
    return base


def write_outputs(outdir: Path, analyst_report_md: str, analyst_report_html: str, stakeholder_summary_md: str, stakeholder_summary_html: str, raw_data: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[Path, Path, Path, Path, Path, Path]:
    analyst_path, analyst_html_path, stakeholder_path, stakeholder_html_path, json_path = _old_v15_write_outputs(
        outdir, analyst_report_md, analyst_report_html, stakeholder_summary_md, stakeholder_summary_html, raw_data, analysis_results
    )
    case_root = create_case_package(
        analysis_results.get("case", {}),
        analyst_path,
        analyst_html_path,
        stakeholder_path,
        stakeholder_html_path,
        json_path,
    )
    return analyst_path, analyst_html_path, stakeholder_path, stakeholder_html_path, json_path, case_root


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect and analyze Windows incident-response evidence.")
    parser.add_argument("--days", type=int, default=3, help="How many days back to query (default: 3)")
    parser.add_argument("--max-events", type=int, default=400, help="Max events per log query (default: 400)")
    parser.add_argument("--outdir", default="ir_report_output", help="Output directory (default: ir_report_output)")
    args = parser.parse_args()

    if os.name != "nt":
        print("This script is intended to run on Windows.", file=sys.stderr)
        return 2
    if not powershell_available():
        print("PowerShell was not found. This script requires Windows PowerShell or PowerShell 7.", file=sys.stderr)
        return 2

    raw_data: Dict[str, Any] = {"meta": {"days": args.days, "max_events": args.max_events, "is_admin": is_admin(), "generated_at": dt.datetime.now().isoformat()}}
    raw_data["system_info"] = collect_basic_system_info()
    raw_data["logs"] = {
        "Security": collect_event_log("Security", SECURITY_IDS, args.days, args.max_events),
        "System": collect_event_log("System", SYSTEM_IDS, args.days, args.max_events),
        "Defender": collect_event_log("Microsoft-Windows-Windows Defender/Operational", DEFENDER_IDS, args.days, args.max_events),
        "PowerShell": collect_event_log("Microsoft-Windows-PowerShell/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "PowerShellCore": collect_event_log("PowerShellCore/Operational", POWERSHELL_IDS, args.days, args.max_events),
        "Sysmon": collect_event_log("Microsoft-Windows-Sysmon/Operational", SYSMON_IDS, args.days, args.max_events),
    }
    raw_data["browser_history"] = collect_browser_history(args.days, max_rows=max(50, args.max_events))
    raw_data["run_keys"] = collect_run_keys()
    raw_data["startup_items"] = collect_startup_items()

    analysis_results = analyze(raw_data)
    analysis_results["detections"] = build_named_detections(raw_data, analysis_results)
    analysis_results["case"] = build_case_workflow(raw_data, analysis_results, Path(args.outdir))

    analyst_report_md = generate_markdown(raw_data, analysis_results, args.days)
    analyst_report_html = generate_analyst_html(raw_data, analysis_results, args.days)
    stakeholder_summary_md = generate_stakeholder_summary(raw_data, analysis_results, args.days)
    stakeholder_summary_html = generate_stakeholder_html(raw_data, analysis_results, args.days)
    analyst_path, analyst_html_path, stakeholder_path, stakeholder_html_path, json_path, case_root = write_outputs(
        Path(args.outdir),
        analyst_report_md,
        analyst_report_html,
        stakeholder_summary_md,
        stakeholder_summary_html,
        raw_data,
        analysis_results,
    )

    print(f"Analyst report (Markdown) written to: {analyst_path}")
    print(f"Analyst report (HTML) written to:     {analyst_html_path}")
    print(f"Stakeholder summary (Markdown) written to: {stakeholder_path}")
    print(f"Stakeholder summary (HTML) written to:     {stakeholder_html_path}")
    print(f"JSON written to:                      {json_path}")
    print(f"Case package written to:              {case_root}")
    if not raw_data["meta"]["is_admin"]:
        print("Tip: Run from an elevated prompt for best access to Security and other protected logs.")
    else:
        print("Admin check: elevated prompt confirmed.")
    return 0


# --- v15.3 focused quality patch: true dedupe, collector-noise suppression, refined top findings ---

V15_3_COLLECTOR_SCRIPTBLOCK_PATTERNS = [
    re.compile(r"foreach\s*\(\$d\s+in\s+\$xml\.Event\.EventData\.Data\)", re.I | re.S),
    re.compile(r"\[xml\]\$\_\.ToXml\(\)", re.I),
    re.compile(r"Export-ModuleMember\s+-Function\s+'?Get-MpPreference'?", re.I),
    re.compile(r"\{ \$\_.DisplayName -match 'Bitdefender' -or \$\_.Name -match '\^bd' \}", re.I),
    re.compile(r"\{ \$\_.Name -like 'sysmon\*' -or \$\_.DisplayName -like '\*Sysmon\*' \}", re.I),
    re.compile(r"^###\s*# ==\+\+==", re.I | re.S),
]

def _v15_3_looks_like_long_ms_blob(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return False
    if len(stripped) < 180:
        return False
    if stripped.count("#") >= 3 and re.search(r"[A-Za-z0-9+/]{80,}", stripped):
        return True
    if re.search(r"-----BEGIN CERTIFICATE-----", stripped, re.I):
        return True
    if re.search(r"microsoft corporation\. all rights reserved", stripped, re.I):
        return True
    return False

def is_background_scriptblock(text: str) -> bool:
    stripped = (text or "").strip()
    if not stripped:
        return True
    if is_self_collection_scriptblock(stripped):
        return True
    if any(p.search(stripped) for p in V15_3_COLLECTOR_SCRIPTBLOCK_PATTERNS):
        return True
    if _v15_3_looks_like_long_ms_blob(stripped):
        return True
    if not looks_like_user_scriptblock(stripped):
        return True
    if re.search(r"RootModule\s*=\s*'PSModule\.psm1'", stripped, re.I):
        return True
    if re.search(r"Set-Alias -Name (?:ncms|rcie|gcai|icim|rcim|ncim|scim|gcim|gcls|ncso|gcms|rcms)\b", stripped, re.I):
        return True
    if re.fullmatch(r"\$Host", stripped):
        return True
    if re.fullmatch(r"\$global:\\?", stripped):
        return True
    return False

def _normalize_detection_evidence_key(name: str, evidence: str) -> str:
    s = safe_lower(evidence or '')
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'/session:[^\s"]+', '/session:<session>', s)
    s = re.sub(r'\{[0-9a-f\-]{16,}\}', '{guid}', s)
    s = re.sub(r'0x[0-9a-f]{4,}', '<hex>', s)
    s = re.sub(r'\\users\\[^\\]+\\', r'\\users\\<user>\\', s)
    s = re.sub(r'ir_test_v\d+\.txt', 'ir_test_vX.txt', s)
    s = re.sub(r'example_test_v\d+\.html', 'example_test_vX.html', s)
    if name.lower() in {'powershell to command shell', 'powershell web request', 'powershell to lolbin'}:
        s = s.replace('$env:userprofile', '%userprofile%')
    return s[:260]

def _dedupe_detections(detections: List[Dict[str, Any]], rolling_hours: int = 8) -> List[Dict[str, Any]]:
    by_pattern: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    for d in detections:
        key = (
            str(d.get("name", "")).lower(),
            str(d.get("severity", "")).title(),
            _normalize_detection_evidence_key(str(d.get("name", "")), str(d.get("evidence", ""))),
        )
        by_pattern[key].append(dict(d))

    merged: List[Dict[str, Any]] = []
    max_gap = rolling_hours * 3600

    for (_name, _sev, _norm), rows in by_pattern.items():
        rows.sort(key=lambda x: (parse_iso(x.get("time")).timestamp() if parse_iso(x.get("time")) else 0.0))
        clusters: List[Dict[str, Any]] = []
        for row in rows:
            ts = parse_iso(row.get("time"))
            if not clusters:
                clusters.append({"latest": dict(row), "count": 1, "first_ts": ts, "last_ts": ts})
                continue
            last = clusters[-1]
            last_ts = last.get("last_ts")
            if ts and last_ts and abs((ts - last_ts).total_seconds()) <= max_gap:
                last["count"] += 1
                last["last_ts"] = ts
                last_latest_ts = parse_iso(last["latest"].get("time"))
                if not last_latest_ts or ts >= last_latest_ts:
                    last["latest"] = dict(row)
            else:
                clusters.append({"latest": dict(row), "count": 1, "first_ts": ts, "last_ts": ts})

        for cluster in clusters:
            entry = dict(cluster["latest"])
            count = int(cluster["count"])
            first_ts = cluster.get("first_ts")
            last_ts = cluster.get("last_ts")
            entry["occurrences"] = count
            if count > 1:
                base_name = str(entry.get("name", "")).strip()
                entry["name"] = f"{base_name} (x{count})"
                why = str(entry.get("why", "")).strip()
                if first_ts and last_ts:
                    window_note = f" Repeated {count} time(s) between {first_ts.strftime('%Y-%m-%d %H:%M')} and {last_ts.strftime('%Y-%m-%d %H:%M')}."
                else:
                    window_note = f" Repeated {count} time(s) in the reporting window."
                if "repeated" not in safe_lower(why):
                    entry["why"] = normalize_inline((why + window_note).strip(), 220)
            merged.append(entry)

    merged.sort(
        key=lambda x: (
            -_severity_rank(x.get("severity", "")),
            -(parse_iso(x.get("time")).timestamp() if parse_iso(x.get("time")) else 0.0),
            x.get("name", ""),
        )
    )
    return merged

def _v15_3_is_generic_browser_observation(detail: str) -> bool:
    lowered = safe_lower(detail or "")
    return (
        "user launched `chrome.exe` from `explorer.exe`" in lowered
        or "user launched `msedge.exe` from `explorer.exe`" in lowered
        or "user launched `firefox.exe` from `explorer.exe`" in lowered
    )

def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()

    def add_finding(title: str, detail: str, time: str = ""):
        norm = safe_lower(f"{title}|{detail}")
        if not detail or norm in seen:
            return False
        seen.add(norm)
        findings.append({
            "title": title,
            "detail": detail,
            "time": stakeholder_format_time(time or ""),
        })
        return True

    for det in analysis_results.get("detections", [])[:10]:
        name = str(det.get("name", "")).strip()
        severity = str(det.get("severity", "")).title()
        if name in {"Process Access (Likely Benign Service Query)", "Trust Store Initialization (Likely Benign)"}:
            continue
        detail = str(det.get("evidence", "")).strip()
        lname = name.lower()
        if lname.startswith("powershell to command shell"):
            detail = name
        elif lname.startswith("powershell web request"):
            detail = name
        elif not detail:
            detail = str(det.get("why", "")).strip()
        label = f"{severity} detection"
        if add_finding(label, detail, str(det.get("time", ""))):
            if len(findings) >= 3:
                return findings

    for item in summarize_test_activity(data, analysis_results, limit=8):
        detail = str(item.get("detail", "")).strip()
        if not detail or _v15_3_is_generic_browser_observation(detail):
            continue
        if add_finding(item.get("type", "Finding"), detail, str(item.get("time", ""))):
            if len(findings) >= 3:
                return findings

    for row in analysis_results.get("correlated_timeline", [])[:20]:
        if not (row.get("likely") or row.get("dns") or row.get("network")):
            continue
        likely = " || ".join(row.get("likely", [])[:2])
        dns = " || ".join(row.get("dns", [])[:1])
        net = " || ".join(row.get("network", [])[:1])
        detail_parts = [x for x in [likely, dns, net] if x]
        if not detail_parts:
            continue
        detail = " || ".join(detail_parts)
        if "chrome.exe <= explorer.exe" in safe_lower(detail):
            continue
        if add_finding("Correlated chain", detail, str(row.get("minute", ""))):
            if len(findings) >= 3:
                return findings

    for item in analysis_results.get("high_signal_processes", [])[:10]:
        detail = short(item.get("command_line") or item.get("image") or "", 160)
        if not _v15_2_is_useful_high_signal_process(item):
            continue
        if "chrome.exe" in safe_lower(detail) and "--single-argument" in safe_lower(detail):
            continue
        if add_finding("High-signal process", detail, str(item.get("time", ""))):
            if len(findings) >= 3:
                return findings

    for finding in summarize_key_findings(data.get("system_info", {}), analysis_results):
        if add_finding("Key finding", finding, ""):
            if len(findings) >= 3:
                break
    return findings



# --- v16 fresh patch on v15.3 baseline: risk consistency, better suppression, smarter top findings ---

V16_BROWSER_HELPER_PATTERNS = [
    re.compile(r'--type=(?:renderer|utility|crashpad-handler)\b', re.I),
    re.compile(r'--utility-sub-type=(?:quarantine\.mojom\.Quarantine|passage_embeddings\.mojom\.PassageEmbeddingsService|chrome\.mojom\.UtilWin|unzip\.mojom\.Unzipper|patch\.mojom\.FilePatcher)\b', re.I),
    re.compile(r'--single-argument\s+.*windows_ir_(?:analyst_report|stakeholder_summary)\.html', re.I),
]

V16_EXTRA_SCRIPTBLOCK_NOISE_PATTERNS = [
    re.compile(r'^\{\s*\$_\.Message\s*-match\s*\$pattern\s*\}$', re.I),
    re.compile(r'^\{\s*\$_\.(?:Message|Name|DisplayName)\b', re.I),
    re.compile(r'\$pattern\b', re.I),
]


def _v16_is_browser_helper_noise(fields: Dict[str, Any]) -> bool:
    image_name = safe_lower(fields.get('image_name') or '')
    command = str(fields.get('command') or '')
    if image_name not in {'chrome.exe', 'msedge.exe', 'firefox.exe'}:
        return False
    return any(p.search(command) for p in V16_BROWSER_HELPER_PATTERNS)


def _v16_looks_like_blobish_scriptblock(text: str) -> bool:
    stripped = (text or '').strip()
    if not stripped:
        return True
    if any(p.search(stripped) for p in V16_EXTRA_SCRIPTBLOCK_NOISE_PATTERNS):
        return True
    if _v15_3_looks_like_long_ms_blob(stripped):
        return True
    if len(stripped) > 160 and stripped.count('#') >= 2 and re.search(r'[A-Za-z0-9+/]{60,}', stripped):
        return True
    return False


def is_background_scriptblock(text: str) -> bool:
    stripped = (text or '').strip()
    if not stripped:
        return True
    if is_self_collection_scriptblock(stripped):
        return True
    if any(p.search(stripped) for p in V15_3_COLLECTOR_SCRIPTBLOCK_PATTERNS):
        return True
    if any(p.search(stripped) for p in V16_EXTRA_SCRIPTBLOCK_NOISE_PATTERNS):
        return True
    if _v16_looks_like_blobish_scriptblock(stripped):
        return True
    if not looks_like_user_scriptblock(stripped):
        return True
    if re.search(r"RootModule\s*=\s*'PSModule\.psm1'", stripped, re.I):
        return True
    if re.search(r"Set-Alias -Name (?:ncms|rcie|gcai|icim|rcim|ncim|scim|gcim|gcls|ncso|gcms|rcms)\b", stripped, re.I):
        return True
    if re.fullmatch(r"\$Host", stripped):
        return True
    if re.fullmatch(r"\$global:\\?", stripped):
        return True
    return False


def classify_activity_event(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    kind = item.get('kind')
    reasons: List[str] = []

    if kind == 'process':
        fields = item.get('fields') or {}
        image_name = fields.get('image_name', '')
        parent_name = fields.get('parent_name', '')
        user = fields.get('user', '')
        command = fields.get('command', '')

        if is_reporter_self_process(fields):
            reasons.append('collector self-activity')
            return 'background', reasons
        if _v16_is_browser_helper_noise(fields):
            reasons.append('browser helper/renderer noise')
            return 'background', reasons
        if is_devtool_noise_process(fields):
            reasons.append('development tool helper activity')
            return 'background', reasons
        if image_name == 'conhost.exe' and parent_name in POWERSHELL_PARENT_NAMES | {'cmd.exe'}:
            reasons.append('console host child of interactive shell')
            return 'background', reasons
        if user and not is_machine_account(user):
            reasons.append('interactive user account')
        if parent_name in POWERSHELL_PARENT_NAMES | {'cmd.exe', 'explorer.exe'}:
            reasons.append(f'interactive parent: {parent_name}')
        if image_name in SUSPICIOUS_PROCESS_NAMES:
            reasons.append('script host / LOLBin / admin tool')
        if command and suspicious_command_line(command):
            reasons.append('command line matches suspicious/admin patterns')
        if is_machine_account(user) or parent_name in BACKGROUND_PARENT_NAMES:
            reasons.append('service/background parent or machine account')
            return 'background', reasons
        if parent_name in POWERSHELL_PARENT_NAMES | {'cmd.exe', 'explorer.exe', 'chrome.exe', 'msedge.exe', 'outlook.exe', 'winword.exe', 'excel.exe'}:
            return 'likely_user', reasons
        if image_name in {'notepad.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe'} and user and not is_machine_account(user):
            return 'likely_user', reasons
        if image_name in {'chrome.exe', 'msedge.exe'} and user and not is_machine_account(user):
            if not _v16_is_browser_helper_noise(fields):
                return 'likely_user', reasons
        if process_interest_score(fields) >= 7:
            return 'likely_user', reasons
        return 'background', reasons

    if kind == 'scriptblock':
        text = item.get('detail', '')
        if is_background_scriptblock(text):
            reasons.append('module / helper / collector script block')
            return 'background', reasons
        reasons.append('user-entered script block')
        if suspicious_powershell(text):
            reasons.append('contains dual-use or suspicious keywords')
        return 'likely_user', reasons

    if kind in {'dns', 'network'}:
        image_name = safe_lower(item.get('image_name'))
        detail = item.get('detail', '')
        if image_name in {'powershell.exe', 'pwsh.exe', 'cmd.exe'}:
            reasons.append(f'interactive process generated {kind}')
            return 'likely_user', reasons
        if 'example.com' in safe_lower(detail):
            reasons.append('manual test destination')
            return 'likely_user', reasons
        if image_name in {'chrome.exe', 'msedge.exe'}:
            reasons.append('browser-generated network activity')
            return 'background', reasons
        reasons.append('background or service-generated network activity')
        return 'background', reasons

    if kind == 'other':
        image_name = safe_lower(item.get('image_name'))
        summary = item.get('summary', '')
        summary_l = safe_lower(summary)
        detail = safe_lower(item.get('detail', ''))
        if _v15_2_is_cert_or_wintrust_noise_summary(summary):
            reasons.append('certificate / WinTrust / PowerShell initialization noise')
            return 'background', reasons
        if 'registry change (createkey)' in summary_l and _v15_2_is_cert_or_wintrust_path_text(summary_l):
            reasons.append('certificate trust-store initialization')
            return 'background', reasons
        if image_name in {'powershell.exe', 'pwsh.exe', 'cmd.exe'}:
            reasons.append('interactive process generated extended sysmon telemetry')
            return 'likely_user', reasons
        if 'example.com' in summary_l or 'example.com' in detail:
            reasons.append('manual test destination')
            return 'likely_user', reasons
        reasons.append('extended sysmon telemetry')
        return 'background', reasons

    reasons.append('uncategorized')
    return 'background', reasons


def stakeholder_status_and_reasoning(sysinfo: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[str, List[str]]:
    level, reasons = _old_stakeholder_status_and_reasoning(sysinfo, analysis_results)
    detections = analysis_results.get('detections', [])
    high_dets = [d for d in detections if d.get('severity') == 'High']
    med_dets = [d for d in detections if d.get('severity') == 'Medium']
    if high_dets:
        reasons.insert(0, f"{len(high_dets)} named detection(s) reached High severity and should be reviewed first.")
        level = 'High'
    elif med_dets:
        reasons.insert(0, f"{len(med_dets)} named detection(s) reached Medium severity and should be validated in context.")
        if level != 'High':
            level = 'Medium'
    return level, reasons


def _v16_find_correlated_telemetry_item(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> Optional[Dict[str, str]]:
    # Prefer a human-readable summary built from the direct test activity correlation helper.
    for item in summarize_test_activity(data, analysis_results, limit=10):
        if safe_lower(item.get('type', '')) == 'correlated telemetry':
            return {
                'title': 'Correlated telemetry',
                'detail': item.get('detail', ''),
                'time': stakeholder_format_time(item.get('time', '')),
            }
    # Fallback: prefer timeline rows that actually include DNS/network, but sanitize aggressively.
    for row in analysis_results.get('correlated_timeline', [])[:25]:
        dns = [x for x in row.get('dns', []) if 'example.com' in safe_lower(x) or 'dns query' in safe_lower(x)]
        net = [x for x in row.get('network', []) if 'example.com' in safe_lower(x) or 'tcp' in safe_lower(x) or 'network connection' in safe_lower(x)]
        if dns or net:
            detail = '; '.join((dns + net)[:2])
            detail = normalize_inline(detail, 180)
            if detail:
                return {
                    'title': 'Correlated telemetry',
                    'detail': detail,
                    'time': stakeholder_format_time(row.get('minute', '')),
                }
    return None


def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()

    def add_finding(title: str, detail: str, time: str = '') -> bool:
        norm = safe_lower(f'{title}|{detail}')
        if not detail or norm in seen:
            return False
        if _v16_looks_like_blobish_scriptblock(detail):
            return False
        if '{ $_.Message -match $pattern }' in detail:
            return False
        seen.add(norm)
        findings.append({'title': title, 'detail': detail, 'time': stakeholder_format_time(time or '')})
        return True

    # 1) Prefer the top non-benign named detection.
    primary_detection = None
    for det in analysis_results.get('detections', [])[:10]:
        name = str(det.get('name', '')).strip()
        if name in {'Process Access (Likely Benign Service Query)', 'Trust Store Initialization (Likely Benign)'}:
            continue
        severity = str(det.get('severity', '')).title()
        detail = name if name else str(det.get('evidence', '')).strip()
        primary_detection = {'label': f'{severity} detection', 'detail': detail, 'time': str(det.get('time', ''))}
        break
    if primary_detection:
        add_finding(primary_detection['label'], primary_detection['detail'], primary_detection['time'])

    # 2) Prefer a readable user-action summary, not another detection.
    for item in summarize_test_activity(data, analysis_results, limit=10):
        typ = safe_lower(item.get('type', ''))
        detail = str(item.get('detail', '')).strip()
        if typ == 'correlated telemetry':
            continue
        if not detail or _v15_3_is_generic_browser_observation(detail):
            continue
        if add_finding(item.get('type', 'User activity'), detail, str(item.get('time', ''))):
            break

    # 3) Prefer correlated telemetry over another action summary.
    corr = _v16_find_correlated_telemetry_item(data, analysis_results)
    if corr:
        add_finding(corr['title'], corr['detail'], corr['time'])

    # Fallbacks only if still short.
    if len(findings) < 3:
        for det in analysis_results.get('detections', [])[:10]:
            name = str(det.get('name', '')).strip()
            severity = str(det.get('severity', '')).title()
            detail = name if name else str(det.get('evidence', '')).strip()
            if name in {'Process Access (Likely Benign Service Query)', 'Trust Store Initialization (Likely Benign)'} and findings:
                continue
            if add_finding(f'{severity} detection', detail, str(det.get('time', ''))):
                if len(findings) >= 3:
                    break

    if len(findings) < 3:
        for finding in summarize_key_findings(data.get('system_info', {}), analysis_results):
            if add_finding('Key finding', finding, ''):
                if len(findings) >= 3:
                    break

    return findings[:3]


# === v16.1 focused telemetry / focus-window overrides ===

def _v16_1_non_benign_detection_name(name: str) -> bool:
    name = (name or "").strip()
    return name not in {"", "Process Access (Likely Benign Service Query)", "Trust Store Initialization (Likely Benign)"}


def _v16_1_primary_focus_time(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> Optional[str]:
    detections = sorted(
        analysis_results.get("detections", []),
        key=lambda d: (_severity_rank(d.get("severity", "")), d.get("time", "")),
        reverse=True,
    )
    for det in detections:
        if _v16_1_non_benign_detection_name(str(det.get("name", ""))):
            return str(det.get("time", "")) or None

    direct_commands = _collect_direct_command_events(data)
    suspicious_order = {"start_process": 0, "cmd": 1, "web_request": 2, "notepad": 3}
    direct_commands.sort(
        key=lambda x: (
            suspicious_order.get(str(x.get("kind", "")), 99),
            -(parse_iso(x.get("time")).timestamp() if parse_iso(x.get("time")) else 0.0),
        )
    )
    for evt in direct_commands:
        if evt.get("time"):
            return str(evt.get("time"))
    return None


def _v16_1_focus_domain(data: Dict[str, Any], analysis_results: Dict[str, Any], focus_time: str = "") -> str:
    anchor = parse_iso(focus_time) if focus_time else None
    best_domain = ""
    best_diff = float("inf")

    for evt in _collect_direct_command_events(data):
        if evt.get("kind") != "web_request" or not evt.get("url"):
            continue
        domain = urllib.parse.urlparse(evt.get("url") or "").netloc or (evt.get("url") or "")
        domain = (domain or "").strip().lower()
        if not domain:
            continue
        if anchor:
            diff = _seconds_between(parse_iso(evt.get("time")), anchor)
            if diff < best_diff:
                best_domain = domain
                best_diff = diff
        elif not best_domain:
            best_domain = domain

    if best_domain:
        return best_domain

    for det in analysis_results.get("detections", []):
        if str(det.get("name", "")) != "PowerShell Web Request":
            continue
        evidence = str(det.get("evidence", ""))
        url, _outfile = extract_iwr_details(evidence)
        domain = urllib.parse.urlparse(url or "").netloc or (url or "")
        domain = (domain or "").strip().lower()
        if domain:
            return domain
    return ""


def _v16_1_within_focus(ts: Optional[str], anchor_time: Optional[str], within_seconds: int = 300) -> bool:
    if not ts or not anchor_time:
        return False
    return _seconds_between(parse_iso(ts), parse_iso(anchor_time)) <= within_seconds


def _v16_1_infer_focus_anchor_from_items(items: List[Dict[str, Any]]) -> Optional[str]:
    priority_patterns = [
        lambda i: i.get("kind") == "process" and "cmd.exe <= powershell.exe" in safe_lower(i.get("summary", "")),
        lambda i: i.get("kind") == "scriptblock" and "invoke-webrequest" in safe_lower(i.get("detail", "")),
        lambda i: i.get("kind") == "scriptblock" and "start-process cmd.exe" in safe_lower(i.get("detail", "")),
        lambda i: i.get("kind") == "process" and "notepad.exe <= powershell.exe" in safe_lower(i.get("summary", "")),
        lambda i: i.get("kind") == "process" and safe_lower(i.get("fields", {}).get("parent_name", "")) in POWERSHELL_PARENT_NAMES,
        lambda i: i.get("category") == "likely_user",
    ]
    ordered = sorted(items, key=lambda i: i.get("time") or "", reverse=True)
    for matcher in priority_patterns:
        for item in ordered:
            if matcher(item):
                return item.get("time")
    return None


def _v16_2_extract_ipv4_candidates(text: str) -> List[str]:
    if not text:
        return []
    return list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)))


def _v16_3_web_request_anchor(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[str, str, str]:
    focus_time = _v16_1_primary_focus_time(data, analysis_results) or ""
    anchor_dt = parse_iso(focus_time) if focus_time else None
    best_evt: Optional[Dict[str, Any]] = None
    best_diff = float("inf")

    for evt in _collect_direct_command_events(data):
        if evt.get("kind") != "web_request" or not evt.get("url"):
            continue
        evt_time = str(evt.get("time") or "")
        evt_dt = parse_iso(evt_time)
        diff = _seconds_between(evt_dt, anchor_dt) if anchor_dt else 0.0
        if best_evt is None or diff < best_diff:
            best_evt = evt
            best_diff = diff

    if not best_evt:
        domain = _v16_1_focus_domain(data, analysis_results, focus_time)
        return focus_time, domain, ""

    url = str(best_evt.get("url") or "")
    domain = urllib.parse.urlparse(url).netloc or url
    return str(best_evt.get("time") or focus_time or ""), (domain or "").strip().lower(), url


def _v16_3_focus_images(data: Dict[str, Any], anchor_time: str) -> List[str]:
    image_names = {"powershell.exe", "pwsh.exe", "cmd.exe"}
    web_evt = {"time": anchor_time, "kind": "web_request", "text": "invoke-webrequest"}
    proc = _find_matching_4688(data, web_evt, within_seconds=180)
    if proc:
        fields = get_process_fields(proc)
        for value in (fields.get("image_name", ""), fields.get("parent_name", "")):
            if value:
                image_names.add(str(value).lower())
    return sorted(image_names)


def _v16_2_focus_ip_candidates(data: Dict[str, Any], focus_domain: str, anchor_time: str, within_seconds: int = 600) -> List[str]:
    anchor = parse_iso(anchor_time)
    if not anchor:
        return []
    ips: List[str] = []
    for event in _all_sysmon_events(data):
        event_id = int(event.get("Id", 0))
        if event_id not in {3, 22}:
            continue
        ts = parse_iso(event.get("TimeCreated"))
        if _seconds_between(ts, anchor) > within_seconds:
            continue
        evt_data = get_event_data(event)
        if event_id == 22:
            query_name = (evt_data.get("QueryName") or "").strip().lower()
            query_results = (evt_data.get("QueryResults") or "").strip()
            if focus_domain and focus_domain in query_name:
                ips.extend(_v16_2_extract_ipv4_candidates(query_results))
        else:
            dest_host = (evt_data.get("DestinationHostname") or "").strip().lower()
            dest_ip = (evt_data.get("DestinationIp") or "").strip()
            image_name = Path(evt_data.get("Image") or "").name.lower()
            if focus_domain and focus_domain in dest_host and dest_ip:
                ips.append(dest_ip)
            elif image_name in {"powershell.exe", "pwsh.exe", "cmd.exe"} and abs(minute_bucket(event.get("TimeCreated")) - minute_bucket(anchor_time)) <= 1 and dest_ip:
                ips.append(dest_ip)
    return list(dict.fromkeys([ip for ip in ips if ip]))


def _v16_3_network_match_score(
    *,
    image_name: str,
    target_host: str,
    target_ip: str,
    query_name: str,
    query_results: str,
    event_time: str,
    anchor_time: str,
    focus_domain: str,
    focus_images: List[str],
    ip_candidates: List[str],
) -> int:
    score = 0
    target_host_l = safe_lower(target_host)
    target_ip_l = safe_lower(target_ip)
    query_name_l = safe_lower(query_name)
    query_results_l = safe_lower(query_results)
    image_name_l = safe_lower(image_name)
    event_min = minute_bucket(event_time)
    anchor_min = minute_bucket(anchor_time)
    ip_set = {safe_lower(ip) for ip in ip_candidates if ip}

    if focus_domain:
        if focus_domain in target_host_l or focus_domain in query_name_l or focus_domain in query_results_l:
            score += 5
    if target_ip_l and target_ip_l in ip_set:
        score += 5
    if image_name_l in focus_images:
        score += 2
    if abs(event_min - anchor_min) <= 1:
        score += 2
    if image_name_l in {"powershell.exe", "pwsh.exe", "cmd.exe"} and abs(event_min - anchor_min) <= 2:
        score += 1
    return score


def _v16_1_find_correlated_telemetry_item(data: Dict[str, Any], analysis_results: Dict[str, Any], within_seconds: int = 600) -> Dict[str, str]:
    anchor_time, focus_domain, _focus_url = _v16_3_web_request_anchor(data, analysis_results)
    if not anchor_time:
        anchor_time = _v16_1_primary_focus_time(data, analysis_results) or ""
    anchor = parse_iso(anchor_time)
    focus_images = _v16_3_focus_images(data, anchor_time) if anchor_time else ["powershell.exe", "pwsh.exe", "cmd.exe"]

    dns_hits: List[Dict[str, Any]] = []
    net_hits: List[Dict[str, Any]] = []
    ip_candidates: List[str] = []

    if anchor:
        # Step 1: explicit Sysmon 22 DNS join around the Invoke-WebRequest anchor.
        for event in _all_sysmon_events(data):
            if int(event.get("Id", 0)) != 22:
                continue
            ts = parse_iso(event.get("TimeCreated"))
            if _seconds_between(ts, anchor) > within_seconds:
                continue
            evt_data = get_event_data(event)
            query_name = (evt_data.get("QueryName") or "").strip()
            query_results = (evt_data.get("QueryResults") or "").strip()
            image_name = Path(evt_data.get("Image") or "").name.lower()
            score = _v16_3_network_match_score(
                image_name=image_name,
                target_host="",
                target_ip="",
                query_name=query_name,
                query_results=query_results,
                event_time=event.get("TimeCreated") or "",
                anchor_time=anchor_time,
                focus_domain=focus_domain,
                focus_images=focus_images,
                ip_candidates=[],
            )
            if score >= 5:
                ips = _v16_2_extract_ipv4_candidates(query_results)
                ip_candidates.extend(ips)
                detail = ""
                if query_name and ips:
                    detail = f"DNS query `{query_name}` returned {', '.join(ips[:3])}"
                elif query_name:
                    detail = f"DNS query observed for `{query_name}`"
                elif query_results:
                    detail = f"DNS query results observed: {normalize_inline(query_results, 120)}"
                if detail:
                    dns_hits.append({
                        "time": event.get("TimeCreated") or "",
                        "score": score + (1 if ips else 0),
                        "detail": detail,
                    })

        ip_candidates = list(dict.fromkeys([ip for ip in (ip_candidates + _v16_2_focus_ip_candidates(data, focus_domain, anchor_time, within_seconds=within_seconds)) if ip]))

        # Step 2: explicit Sysmon 3 network join from same image / same anchor minute / returned IPs.
        for event in _all_sysmon_events(data):
            if int(event.get("Id", 0)) != 3:
                continue
            ts = parse_iso(event.get("TimeCreated"))
            if _seconds_between(ts, anchor) > within_seconds:
                continue
            evt_data = get_event_data(event)
            image_name = Path(evt_data.get("Image") or "").name.lower()
            host = (evt_data.get("DestinationHostname") or "").strip()
            ip = (evt_data.get("DestinationIp") or "").strip()
            port = (evt_data.get("DestinationPort") or "").strip()
            score = _v16_3_network_match_score(
                image_name=image_name,
                target_host=host,
                target_ip=ip,
                query_name="",
                query_results="",
                event_time=event.get("TimeCreated") or "",
                anchor_time=anchor_time,
                focus_domain=focus_domain,
                focus_images=focus_images,
                ip_candidates=ip_candidates,
            )
            if score >= 5:
                target = host or ip or focus_domain
                if target:
                    detail = f"{image_name or 'process'} connected to `{target}`"
                    if port:
                        detail += f" on port {port}"
                    net_hits.append({
                        "time": event.get("TimeCreated") or "",
                        "score": score,
                        "detail": detail,
                    })

        # Step 3: fallback to any near-time PowerShell-related network event if the direct join misses.
        if not net_hits:
            for event in _all_sysmon_events(data):
                if int(event.get("Id", 0)) != 3:
                    continue
                ts = parse_iso(event.get("TimeCreated"))
                if _seconds_between(ts, anchor) > min(within_seconds, 180):
                    continue
                evt_data = get_event_data(event)
                image_name = Path(evt_data.get("Image") or "").name.lower()
                if image_name not in {"powershell.exe", "pwsh.exe", "cmd.exe"}:
                    continue
                host = (evt_data.get("DestinationHostname") or "").strip()
                ip = (evt_data.get("DestinationIp") or "").strip()
                port = (evt_data.get("DestinationPort") or "").strip()
                if not (host or ip):
                    continue
                detail = f"{image_name} made a nearby network connection to `{host or ip}`"
                if port:
                    detail += f" on port {port}"
                net_hits.append({
                    "time": event.get("TimeCreated") or "",
                    "score": 1,
                    "detail": detail,
                })

    dns_hits.sort(key=lambda x: (x.get("score", 0), x.get("time", "")), reverse=True)
    net_hits.sort(key=lambda x: (x.get("score", 0), x.get("time", "")), reverse=True)

    if dns_hits or net_hits:
        pieces = []
        if dns_hits:
            pieces.append(dns_hits[0]["detail"])
        if net_hits:
            pieces.append(net_hits[0]["detail"])
        detail = "; ".join([p for p in pieces if p])
        if not detail:
            detail = "Related DNS/network activity was captured in the focus window."
        return {
            "title": "Correlated telemetry",
            "detail": detail,
            "time": stakeholder_format_time(anchor_time),
        }

    # Secondary fallback from correlated timeline rows near the focus window.
    if anchor:
        for row in analysis_results.get("correlated_timeline", []):
            row_dt = parse_iso(row.get("minute"))
            if _seconds_between(row_dt, anchor) > within_seconds:
                continue
            dns = [normalize_inline(x, 120) for x in row.get("dns", []) if x]
            net = [normalize_inline(x, 120) for x in row.get("network", []) if x]
            if dns or net:
                pieces = []
                if dns:
                    pieces.append(dns[0])
                if net:
                    pieces.append(net[0])
                detail = "; ".join([p for p in pieces if p])
                if detail and not _v16_looks_like_blobish_scriptblock(detail):
                    return {
                        "title": "Correlated telemetry",
                        "detail": detail,
                        "time": stakeholder_format_time(row.get("minute", "")),
                    }

    return {
        "title": "Correlated telemetry",
        "detail": "No correlated DNS/network telemetry was surfaced in the focus window.",
        "time": stakeholder_format_time(anchor_time),
    }


def summarize_test_activity(data: Dict[str, Any], analysis_results: Dict[str, Any], limit: int = 6) -> List[Dict[str, str]]:
    items: List[Dict[str, Any]] = []
    seen_details = set()
    focus_time = _v16_1_primary_focus_time(data, analysis_results)

    def add_item(time: str, typ: str, detail: str, priority: int):
        if not detail:
            return
        key = detail.lower()
        if key in seen_details:
            return
        seen_details.add(key)
        items.append({"time": time or "", "type": typ, "detail": detail, "priority": priority})

    direct_commands = _collect_direct_command_events(data)
    for cmd_evt in direct_commands:
        detail = stakeholder_scriptblock_observation(cmd_evt.get("text", ""))
        priority = _stakeholder_command_priority(cmd_evt.get("kind", "other"))
        if detail:
            add_item(cmd_evt.get("time", ""), "User test activity", detail, priority)

        matched_proc = _find_matching_4688(data, cmd_evt)
        if matched_proc:
            proc_fields = get_process_fields(matched_proc)
            proc_detail = stakeholder_process_observation({
                "image": proc_fields.get("image", ""),
                "parent": proc_fields.get("parent", ""),
                "command_line": proc_fields.get("command", ""),
                "user": proc_fields.get("user", ""),
            })
            if proc_detail and proc_detail != detail:
                add_item(matched_proc.get("TimeCreated", ""), "Process activity", proc_detail, priority + 1)

        if cmd_evt.get("kind") == "web_request" and cmd_evt.get("url"):
            domain = urllib.parse.urlparse(cmd_evt.get("url") or "").netloc or (cmd_evt.get("url") or "")
            corr = _find_correlated_dns_network(data, cmd_evt.get("time", ""), domain)
            if corr:
                add_item(cmd_evt.get("time", ""), "Correlated telemetry", corr, priority + 2)

    if not items:
        for row in _fallback_process_candidates(data):
            add_item(row.get("time", ""), row.get("type", "Process activity"), row.get("detail", ""), int(row.get("priority", 9)))
            if len(items) >= limit:
                break

    def sort_key(x: Dict[str, Any]):
        parsed = parse_iso(x.get("time"))
        focus_rank = 0 if _v16_1_within_focus(x.get("time"), focus_time, 600) else 1
        return (focus_rank, int(x.get("priority", 99)), -(parsed.timestamp() if parsed else 0.0))

    items.sort(key=sort_key)
    return [{"time": x.get("time", ""), "type": x.get("type", ""), "detail": x.get("detail", "")} for x in items[:limit]]


def build_activity_views(
    security_events: List[Dict[str, Any]],
    ps_events: List[Dict[str, Any]],
    sysmon_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    items: List[Dict[str, Any]] = []

    for event in security_events:
        if int(event.get("Id", 0)) != 4688:
            continue
        fields = get_process_fields(event)
        items.append({
            "time": event.get("TimeCreated"),
            "source": "Security 4688",
            "kind": "process",
            "actor": fields.get("user", ""),
            "image": fields.get("image", ""),
            "image_name": fields.get("image_name", ""),
            "parent": fields.get("parent", ""),
            "summary": normalized_process_summary(fields),
            "detail": fields.get("command", "") or fields.get("image", ""),
            "fields": fields,
        })

    for event in ps_events:
        if int(event.get("Id", 0)) != 4104:
            continue
        sb_text = extract_scriptblock_text(event.get("Message") or "")
        items.append({
            "time": event.get("TimeCreated"),
            "source": "PowerShell 4104",
            "kind": "scriptblock",
            "actor": "",
            "image": "powershell.exe",
            "image_name": "powershell.exe",
            "parent": "",
            "summary": short(sb_text, 180),
            "detail": sb_text,
            "fields": {},
        })

    for event in sysmon_events:
        event_id = int(event.get("Id", 0))
        data_map = get_event_data(event)
        if event_id in {3, 22}:
            kind, summary, detail = normalized_sysmon_network_summary(event)
            image = data_map.get("Image") or ""
        elif event_id in SYSMON_EXTENDED_IDS:
            _event_name, image, summary, detail_reason, _score = summarize_sysmon_extended_event(event)
            kind = "other"
            detail = detail_reason + " :: " + json.dumps(data_map, ensure_ascii=False)
        else:
            continue
        image_name = Path(image).name.lower() if image else ""
        items.append({
            "time": event.get("TimeCreated"),
            "source": f"Sysmon {event_id}",
            "kind": kind,
            "actor": "",
            "image": image,
            "image_name": image_name,
            "parent": "",
            "summary": summary,
            "detail": detail,
            "fields": data_map,
        })

    for item in items:
        category, reasons = classify_activity_event(item)
        item["category"] = category
        item["reasons"] = reasons

    focus_time = _v16_1_infer_focus_anchor_from_items(items)
    likely_minutes = {
        minute_bucket(item.get("time"))
        for item in items
        if item.get("category") == "likely_user" and item.get("kind") in {"process", "scriptblock"}
    }

    for item in items:
        minute = minute_bucket(item.get("time"))
        if item.get("kind") in {"dns", "network"} and item.get("category") == "background" and minute in likely_minutes:
            item["reasons"] = item.get("reasons", []) + ["same-minute proximity to likely user activity"]
        if item.get("kind") in {"dns", "network"} and item.get("category") == "background" and _v16_1_within_focus(item.get("time"), focus_time, 600):
            item["category"] = "likely_user"
            item["reasons"] = item.get("reasons", []) + ["focus-window proximity to strongest detection chain"]
        item["minute"] = minute
        item["focus_boost"] = 0 if _v16_1_within_focus(item.get("time"), focus_time, 600) else 1

    def sort_key(item: Dict[str, Any]):
        parsed = parse_iso(item.get("time"))
        ts = parsed.timestamp() if parsed else 0.0
        category_rank = 0 if item.get("category") == "likely_user" else 1
        return (category_rank, int(item.get("focus_boost", 1)), -ts)

    items.sort(key=sort_key)

    likely_user = [i for i in items if i.get("category") == "likely_user"]
    background = [i for i in items if i.get("category") != "likely_user"]

    return {
        "likely_user_actions": likely_user,
        "background_activity": background,
        "full_raw_timeline": items,
    }


def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen = set()

    def add_finding(title: str, detail: str, time: str = '') -> bool:
        norm = safe_lower(f'{title}|{detail}')
        if not detail or norm in seen:
            return False
        if _v16_looks_like_blobish_scriptblock(detail):
            return False
        if '{ $_.Message -match $pattern }' in detail:
            return False
        seen.add(norm)
        findings.append({'title': title, 'detail': detail, 'time': stakeholder_format_time(time or '')})
        return True

    primary_detection = None
    for det in analysis_results.get('detections', [])[:10]:
        name = str(det.get('name', '')).strip()
        if not _v16_1_non_benign_detection_name(name):
            continue
        severity = str(det.get('severity', '')).title()
        detail = name if name else str(det.get('evidence', '')).strip()
        primary_detection = {'label': f'{severity} detection', 'detail': detail, 'time': str(det.get('time', ''))}
        break
    if primary_detection:
        add_finding(primary_detection['label'], primary_detection['detail'], primary_detection['time'])

    for item in summarize_test_activity(data, analysis_results, limit=10):
        typ = safe_lower(item.get('type', ''))
        detail = str(item.get('detail', '')).strip()
        if typ == 'correlated telemetry':
            continue
        if not detail or _v15_3_is_generic_browser_observation(detail):
            continue
        if primary_detection and safe_lower(detail) == safe_lower(primary_detection['detail']):
            continue
        if add_finding(item.get('type', 'User activity'), detail, str(item.get('time', ''))):
            break

    corr = _v16_1_find_correlated_telemetry_item(data, analysis_results, within_seconds=600)
    add_finding(corr['title'], corr['detail'], corr['time'])

    if len(findings) < 3:
        for finding in summarize_key_findings(data.get('system_info', {}), analysis_results):
            if add_finding('Key finding', finding, ''):
                if len(findings) >= 3:
                    break

    return findings[:3]



# ---- v16.4 focused quality patch ----
_V16_3_ANALYZE = analyze
_V16_3_GENERATE_MARKDOWN = generate_markdown
_V16_3_GENERATE_ANALYST_HTML = generate_analyst_html
_V16_3_IS_BACKGROUND_SCRIPTBLOCK = is_background_scriptblock
_V16_3_CLASSIFY_ACTIVITY_EVENT = classify_activity_event


def _v16_4_powershell_count_breakdown(data: Dict[str, Any]) -> Tuple[int, int, int]:
    ps_win = len(flatten_event(data.get("logs", {}).get("PowerShell", {})))
    ps_core = len(flatten_event(data.get("logs", {}).get("PowerShellCore", {})))
    return ps_win, ps_core, ps_win + ps_core


_V16_4_PARAMETER_METADATA_PATTERNS = [
    r"\[ValidateNotNull\s*\(\s*\)\]",
    r"\[ValidateNotNullOrEmpty\s*\(\s*\)\]",
    r"ParameterSetName\s*=",
    r"RemediationScheduleDay",
    r"\[Alias\(['\"]rst['\"]\)\]",
    r"\[switch\]\s*\$\{?RemediationScheduleDay\}?",
]


def _v16_4_is_parameter_metadata_block(text: str) -> bool:
    sample = (text or "")[:1200]
    if not sample.strip():
        return False
    hits = sum(1 for pat in _V16_4_PARAMETER_METADATA_PATTERNS if re.search(pat, sample, re.I))
    return hits >= 2



def _v16_4_is_browser_updater_process(fields: Dict[str, str]) -> bool:
    image_name = safe_lower(fields.get("image_name", ""))
    parent_name = safe_lower(fields.get("parent_name", ""))
    image = safe_lower(fields.get("image", ""))
    command = safe_lower(fields.get("command", ""))
    if image_name != "updater.exe":
        return False
    if parent_name not in {"chrome.exe", "msedge.exe"}:
        return False
    browser_updater_markers = [
        "googleupdater",
        "google updater",
        "google\\googleupdater",
        "google\\google updater",
        "--wake-all --system",
    ]
    blob = f"{image} {command}"
    return any(marker in blob for marker in browser_updater_markers)



def is_background_scriptblock(text: str) -> bool:
    stripped = (text or "").strip()
    if _v16_4_is_parameter_metadata_block(stripped):
        return True
    return _V16_3_IS_BACKGROUND_SCRIPTBLOCK(stripped)



def classify_activity_event(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    kind = item.get("kind")
    if kind == "process":
        fields = item.get("fields") or {}
        if _v16_4_is_browser_updater_process(fields):
            return "background", ["browser updater / maintenance activity"]
    if kind == "scriptblock":
        text = item.get("detail", "")
        if _v16_4_is_parameter_metadata_block(text):
            return "background", ["module / parameter metadata helper block"]
    return _V16_3_CLASSIFY_ACTIVITY_EVENT(item)



def analyze(data: Dict[str, Any]) -> Dict[str, Any]:
    results = _V16_3_ANALYZE(data)
    counts = results.setdefault("counts", {})
    ps_win, ps_core, ps_total = _v16_4_powershell_count_breakdown(data)
    counts["powershell_windows_events"] = ps_win
    counts["powershell_core_events"] = ps_core
    counts["powershell_events_total"] = ps_total
    counts["powershell_events"] = ps_total
    return results



def _v16_4_render_overview_markdown(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
    counts = analysis_results.get("counts", {})
    likely_count = len(analysis_results.get("likely_user_actions", []))
    detections = analysis_results.get("detections", [])
    risk = _case_priority_from_detections(detections)
    ps_win = int(counts.get("powershell_windows_events", 0) or 0)
    ps_core = int(counts.get("powershell_core_events", 0) or 0)
    ps_total = int(counts.get("powershell_events_total", counts.get("powershell_events", 0)) or 0)
    rows = [
        ["Risk", risk],
        ["Security Events", str(counts.get("security_events", 0))],
        ["PowerShell Events", f"{ps_total} total ({ps_win} Windows PowerShell + {ps_core} PowerShell Core)"],
        ["Sysmon Events", str(counts.get("sysmon_events", 0))],
        ["Likely User Actions", str(likely_count)],
    ]
    return "## Overview\n\n" + render_table(["Field", "Value"], rows) + "\n\n"



def _v16_4_render_top_findings_markdown(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> str:
    findings = _v12_top_findings(data, analysis_results)
    if not findings:
        return ""
    rows = []
    for finding in findings[:3]:
        rows.append([
            finding.get("title", ""),
            finding.get("detail", ""),
            finding.get("time", ""),
        ])
    return "## Top 3 Findings\n\n" + render_table(["Category", "Observation", "Time"], rows) + "\n\n"



def generate_markdown(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _V16_3_GENERATE_MARKDOWN(data, analysis_results, days)
    insertion = _v16_4_render_overview_markdown(data, analysis_results) + _v16_4_render_top_findings_markdown(data, analysis_results)
    if not insertion.strip():
        return base
    if "## Overview" in base:
        return base
    if "## Case Workflow" in base:
        return base.replace("## Case Workflow", insertion + "## Case Workflow", 1)
    if "## Detections" in base:
        return base.replace("## Detections", insertion + "## Detections", 1)
    return base + "\n\n" + insertion



def generate_analyst_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    html = _V16_3_GENERATE_ANALYST_HTML(data, analysis_results, days)
    ps_win, ps_core, ps_total = _v16_4_powershell_count_breakdown(data)
    subtitle = f"{ps_win} Windows PowerShell + {ps_core} PowerShell Core logs"
    return html.replace("4104 and related PowerShell logs", html_escape(subtitle), 1)




# ---- v16.4.1 focused supportive-scriptblock patch ----
_V16_4_BUILD_NAMED_DETECTIONS = build_named_detections
_V16_4_CLASSIFY_ACTIVITY_EVENT = classify_activity_event
_V16_4_INTERESTING_SCRIPTBLOCK_KIND = _interesting_scriptblock_kind


def _v16_4_1_is_supportive_focus_scriptblock(text: str) -> bool:
    sample = (text or '').strip()
    if not sample:
        return False
    lowered = sample.lower()
    if re.search(r"\binvoke-webrequest\b", lowered):
        return True
    if re.search(r"\bstart-process\s+cmd\.exe\b", lowered):
        return True
    if re.fullmatch(r"notepad\.exe(?:\s+.*)?", lowered):
        return True
    return False


def _interesting_scriptblock_kind(text: str) -> Optional[str]:
    stripped = (text or '').strip()
    lowered = stripped.lower()
    if not lowered or stakeholder_noise_scriptblock(stripped) or is_self_collection_scriptblock(stripped):
        return None
    if re.search(r"\binvoke-webrequest\b", lowered):
        return 'web_request'
    if re.search(r"\bstart-process\s+cmd\.exe\b", lowered):
        return 'start_process'
    if re.fullmatch(r"notepad\.exe(?:\s+.*)?", lowered):
        return 'notepad'
    if re.fullmatch(r"cmd\.exe(?:\s+.*)?", lowered):
        return 'cmd'
    return _V16_4_INTERESTING_SCRIPTBLOCK_KIND(text)


def classify_activity_event(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    if item.get('kind') == 'scriptblock':
        text = item.get('detail', '') or ''
        if _v16_4_1_is_supportive_focus_scriptblock(text):
            reasons = ['focused supportive scriptblock tied to strongest chain']
            if suspicious_powershell(text):
                reasons.append('contains dual-use or suspicious keywords')
            return 'likely_user', reasons
    return _V16_4_CLASSIFY_ACTIVITY_EVENT(item)


def build_named_detections(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections = list(_V16_4_BUILD_NAMED_DETECTIONS(data, analysis_results))
    has_web_request = any((d.get('name') or '') == 'PowerShell Web Request' for d in detections)
    if has_web_request:
        return detections

    sec_procs = _recent_security_processes(data)
    sysmon_ext = analysis_results.get('sysmon_extended_findings', [])

    for row in _collect_direct_command_events(data):
        if row.get('kind') != 'web_request':
            continue
        text = (row.get('text') or '').strip()
        if not re.search(r"\binvoke-webrequest\b", text, re.I):
            continue
        url, outfile = extract_iwr_details(text)
        details = []
        if url:
            details.append(url)
        if outfile:
            details.append(f'outfile={outfile}')
        extra = f" ({', '.join(details)})" if details else ''
        severity, why, action = _webrequest_context_score(row.get('time', ''), url, outfile, sec_procs, sysmon_ext)
        detections.append(_make_detection(
            'PowerShell Web Request',
            severity,
            row.get('time', ''),
            text,
            why + extra,
            action,
        ))
        break

    return _dedupe_detections(detections)


# ---- v16.6 Bitdefender/browser-helper + VS Code noise suppression patch ----
_V16_4_1_BUILD_NAMED_DETECTIONS = build_named_detections


def _v16_6_strip_repeat_suffix(name: str) -> str:
    return re.sub(r"\s+\(x\d+\)$", "", (name or "").strip())


def _playbook_for_detection_name(name: str) -> Dict[str, List[str]]:
    normalized = _v16_6_strip_repeat_suffix(name)
    return PLAYBOOKS.get(normalized, {"triage": [], "evidence": []})


PLAYBOOKS["Browser-Launched Bitdefender Helper Activity"] = {
    "triage": [
        "Confirm the browser launched a Bitdefender helper from the expected Bitdefender install path.",
        "Validate signer/path context and check whether the activity aligns with Chrome update, extension, or web-protection behavior.",
        "Deprioritize if the executable, extension context, and timing match expected Bitdefender browser-security activity.",
    ],
    "evidence": [
        "4688 lineage from chrome.exe to cmd.exe to the Bitdefender helper",
        "Executable path and signer details for the Bitdefender helper process",
        "Chrome extension and browser-update context near the event time",
        "Any Bitdefender product logs or UI timeline entries related to browser protection",
    ],
}


def _v16_6_is_module_manifest_noise(text: str) -> bool:
    sample = (text or "").strip()
    if not sample:
        return False
    lowered = sample.lower()
    if sample.startswith('@{'):
        manifest_markers = [
            'guid =', 'guid=', 'author =', 'author=', 'companyname', 'moduleversion',
            'rootmodule', 'nestedmodules', 'formatsToProcess'.lower(), 'cmdletsToExport'.lower(),
            'functionstoexport'.lower(), 'aliastoexport'.lower(), 'copyright',
        ]
        hits = sum(1 for m in manifest_markers if m in lowered)
        if hits >= 2:
            return True
    if lowered.startswith('$erroractionpreference') and 'get-winevent' in lowered and 'listlog' in lowered:
        return True
    if lowered.startswith('{') and 'toxml()' in lowered and 'event.eventdata.data' in lowered:
        return True
    if lowered in {'$global:?', '$host'}:
        return True
    if _v16_4_is_parameter_metadata_block(sample):
        return True
    return False


_EXACT_SUPPORTIVE_PATTERNS = [
    re.compile(r'^invoke-webrequest\b', re.I),
    re.compile(r'^start-process\s+cmd\.exe\b', re.I),
    re.compile(r'^notepad\.exe(?:\s+.*)?$', re.I),
]


def _v16_6_is_exact_supportive_scriptblock(text: str) -> bool:
    sample = (text or '').strip()
    if not sample or _v16_6_is_module_manifest_noise(sample) or stakeholder_noise_scriptblock(sample) or is_self_collection_scriptblock(sample):
        return False
    return any(p.search(sample) for p in _EXACT_SUPPORTIVE_PATTERNS)


def _v16_6_is_vscode_dev_noise_process(fields: Dict[str, str]) -> bool:
    image_name = safe_lower(fields.get('image_name', ''))
    parent_name = safe_lower(fields.get('parent_name', ''))
    image = safe_lower(fields.get('image', ''))
    parent = safe_lower(fields.get('parent', ''))
    command = safe_lower(fields.get('command', ''))
    blob = ' '.join(x for x in [image_name, parent_name, image, parent, command] if x)

    if image_name == 'code.exe' and (' --version' in blob or '.vscode\\extensions\\' in blob):
        return True
    if parent_name == 'code.exe' and image_name in {'reg.exe', 'conhost.exe', 'wsl.exe', 'pet.exe'}:
        return True
    if image_name == 'reg.exe' and parent_name == 'code.exe' and '\\software\\python' in blob:
        return True
    if image_name == 'conhost.exe' and parent_name == 'code.exe' and '--headless' in blob:
        return True
    if image_name == 'wsl.exe' and parent_name in {'cmd.exe', 'code.exe'} and ' -l -q' in blob:
        return True
    if '.vscode\\extensions\\ms-python' in blob or 'pylance' in blob or 'python-env-tools\\bin\\pet.exe' in blob:
        return True
    return False



def _v16_6_is_bitdefender_browser_helper_process(fields: Dict[str, str]) -> bool:
    image_name = safe_lower(fields.get('image_name', ''))
    parent_name = safe_lower(fields.get('parent_name', ''))
    image = safe_lower(fields.get('image', ''))
    command = safe_lower(fields.get('command', ''))
    blob = ' '.join(x for x in [image_name, parent_name, image, command] if x)
    if parent_name not in {'chrome.exe', 'msedge.exe', 'cmd.exe'}:
        return False
    if 'bitdefender' not in blob and 'bdtrackersnmh.exe' not in blob:
        return False
    if 'chrome-extension://' in blob or 'bitdefender security app' in blob or 'bdtrackersnmh.exe' in blob:
        return True
    return False





def _v16_6_is_browser_updater_process(fields: Dict[str, str]) -> bool:
    return _v16_4_is_browser_updater_process(fields)


def _v16_6_is_benign_service_dns(item: Dict[str, Any]) -> bool:
    if item.get('kind') != 'dns':
        return False
    summary = safe_lower(item.get('summary', ''))
    image_name = safe_lower(item.get('image_name', ''))
    if image_name == 'svchost.exe' and 'www.msftncsi.com' in summary:
        return True
    return False



def classify_activity_event(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    kind = item.get('kind')
    fields = item.get('fields') or {}
    if kind == 'scriptblock':
        text = item.get('detail', '') or ''
        if _v16_6_is_module_manifest_noise(text):
            return 'background', ['module / manifest / collector helper block']
        if _v16_6_is_exact_supportive_scriptblock(text):
            reasons = ['exact supportive scriptblock tied to strongest chain']
            if suspicious_powershell(text):
                reasons.append('contains dual-use or suspicious keywords')
            return 'likely_user', reasons
    if kind == 'process':
        if _v16_6_is_vscode_dev_noise_process(fields):
            return 'background', ['VS Code / Python extension helper activity']
        if _v16_4_is_browser_updater_process(fields):
            return 'background', ['browser updater / maintenance activity']
        if _v16_6_is_bitdefender_browser_helper_process(fields):
            return 'likely_user', ['browser-launched Bitdefender helper activity']
    if kind in {'dns', 'network'} and _v16_6_is_benign_service_dns(item):
        return 'background', ['service connectivity / NCSI check']
    return _V16_4_CLASSIFY_ACTIVITY_EVENT(item)



def build_named_detections(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections = list(_V16_4_1_BUILD_NAMED_DETECTIONS(data, analysis_results))
    out: List[Dict[str, Any]] = []
    for d in detections:
        entry = dict(d)
        base_name = _v16_6_strip_repeat_suffix(str(entry.get('name', '')))
        evidence_blob = safe_lower(entry.get('evidence', ''))
        suffix_match = re.search(r'(\s+\(x\d+\))$', str(entry.get('name', '')))
        suffix = suffix_match.group(1) if suffix_match else ''
        if base_name == 'Suspicious Child Process from Office/Browser' and ('bitdefender' in evidence_blob or 'bdtrackersnmh.exe' in evidence_blob):
            entry['name'] = 'Browser-Launched Bitdefender Helper Activity' + suffix
            entry['severity'] = 'Low'
            entry['why'] = normalize_inline(
                'A browser spawned a Bitdefender helper from the expected Bitdefender install path. This commonly reflects legitimate browser-protection or extension integration activity rather than malware by itself.',
                220,
            )
            entry['action'] = 'Validate the helper path, signer, and browser/extension context, then deprioritize if it matches expected Bitdefender activity.'
        out.append(entry)
    return _dedupe_detections(out)


# ---- v17 risk consistency + cleaner VS Code noise + clearer Bitdefender wording ----
_V16_6_1_CLASSIFY_ACTIVITY_EVENT = classify_activity_event
_V16_6_1_STAKEHOLDER_STATUS_AND_REASONING = stakeholder_status_and_reasoning
_V16_6_1_STAKEHOLDER_PROCESS_OBSERVATION = stakeholder_process_observation
_V16_6_1_SUMMARIZE_TEST_ACTIVITY = summarize_test_activity
_V16_6_1_TOP_FINDINGS = _v12_top_findings


def _v17_case_priority_level(analysis_results: Dict[str, Any]) -> str:
    case = analysis_results.get('case') or {}
    level = safe_lower(case.get('priority', ''))
    if level in {'low', 'medium', 'high'}:
        return level.title()
    dets = analysis_results.get('detections', []) or []
    severities = [safe_lower(d.get('severity', '')) for d in dets]
    if 'high' in severities:
        return 'High'
    if 'medium' in severities:
        return 'Medium'
    if 'low' in severities:
        return 'Low'
    return 'Low'


def stakeholder_status_and_reasoning(sysinfo: Dict[str, Any], analysis_results: Dict[str, Any]) -> Tuple[str, List[str]]:
    _old_level, old_reasons = _V16_6_1_STAKEHOLDER_STATUS_AND_REASONING(sysinfo, analysis_results)
    level = _v17_case_priority_level(analysis_results)

    filtered: List[str] = []
    for reason in old_reasons or []:
        lowered = safe_lower(reason)
        if 'named detection' in lowered:
            continue
        if 'high-signal execution finding' in lowered:
            continue
        filtered.append(reason)

    summary_reason = {
        'Low': 'Current named detections are low severity and appear consistent with expected tooling or user activity, but should still be validated in context.',
        'Medium': 'Current named detections include activity that warrants analyst review, but the collected evidence does not by itself prove compromise.',
        'High': 'Current named detections include high-priority indicators that should be reviewed immediately.',
    }.get(level, 'Current named detections should be validated in context.')

    reasons = [summary_reason]
    for reason in filtered:
        if reason not in reasons:
            reasons.append(reason)
    return level, reasons


def _v17_is_vscode_dev_noise_process(fields: Dict[str, str]) -> bool:
    image_name = safe_lower(fields.get('image_name', ''))
    parent_name = safe_lower(fields.get('parent_name', ''))
    image = safe_lower(fields.get('image', ''))
    parent = safe_lower(fields.get('parent', ''))
    command = safe_lower(fields.get('command', ''))
    blob = ' '.join(x for x in [image_name, parent_name, image, parent, command] if x)

    if '.vscode\\extensions\\' in blob or '\\microsoft vs code\\' in blob or 'resources\\app\\node_modules\\@vscode\\' in blob:
        return True
    if image_name in {'code.exe', 'rg.exe', 'code-tunnel.exe', 'pet.exe'} and (parent_name == 'code.exe' or '\\microsoft vs code\\' in blob):
        return True
    if image_name in {'reg.exe', 'conhost.exe', 'wsl.exe'} and parent_name == 'code.exe':
        return True
    if image_name == 'code.exe' and parent_name == 'code.exe':
        return True
    if 'pylance' in blob or 'python-env-tools\\bin\\pet.exe' in blob or 'node-pty\\lib\\conpty' in blob:
        return True
    return False


def stakeholder_process_observation(item: Dict[str, Any], allow_fallback: bool = False) -> Optional[str]:
    image = str(item.get("image", "")).strip()
    parent = str(item.get("parent", "")).strip()
    cmd = str(item.get("command_line", "")).strip()
    user = str(item.get("user", "")).strip()
    fields = {
        "image": image,
        "image_name": Path(image).name.lower() if image else "",
        "parent": parent,
        "parent_name": Path(parent).name.lower() if parent else "",
        "command": cmd,
        "user": user,
    }
    if _v16_6_is_bitdefender_browser_helper_process(fields):
        browser = Path(parent).name if parent else 'browser'
        return f"`{browser}` launched a Bitdefender helper process during expected browser-protection or extension activity."
    return _V16_6_1_STAKEHOLDER_PROCESS_OBSERVATION(item, allow_fallback)


def classify_activity_event(item: Dict[str, Any]) -> Tuple[str, List[str]]:
    kind = item.get('kind')
    fields = item.get('fields') or {}
    image_name = safe_lower(fields.get('image_name', ''))
    parent_name = safe_lower(fields.get('parent_name', ''))
    summary = safe_lower(item.get('summary', ''))
    detail = safe_lower(item.get('detail', ''))

    if kind == 'scriptblock':
        text = item.get('detail', '') or ''
        if _v16_6_is_module_manifest_noise(text):
            return 'background', ['module / manifest / collector helper block']
        if not _v16_6_is_exact_supportive_scriptblock(text) and ('.vscode\\extensions\\' in safe_lower(text) or _v16_6_is_module_manifest_noise(text)):
            return 'background', ['development / helper scriptblock']

    if kind == 'process':
        if _v17_is_vscode_dev_noise_process(fields):
            return 'background', ['VS Code / developer-tool helper activity']
        if image_name in {'code.exe', 'rg.exe', 'code-tunnel.exe', 'pet.exe'} or parent_name == 'code.exe':
            return 'background', ['VS Code / developer-tool helper activity']
        if _v16_4_is_browser_updater_process(fields):
            return 'background', ['browser updater / maintenance activity']
        if _v16_6_is_bitdefender_browser_helper_process(fields):
            return 'likely_user', ['browser-launched Bitdefender helper activity']
    if kind in {'dns', 'network'}:
        if _v16_6_is_benign_service_dns(item):
            return 'background', ['service connectivity / NCSI check']
        if image_name == 'code.exe' or parent_name == 'code.exe' or 'visual studio code' in summary or 'visual studio code' in detail:
            return 'background', ['VS Code / developer-tool network activity']
    return _V16_6_1_CLASSIFY_ACTIVITY_EVENT(item)


def summarize_test_activity(data: Dict[str, Any], analysis_results: Dict[str, Any], limit: int = 6) -> List[Dict[str, str]]:
    items = list(_V16_6_1_SUMMARIZE_TEST_ACTIVITY(data, analysis_results, limit=max(limit, 8)))
    existing = {safe_lower(x.get('detail', '')) for x in items}

    # Prefer a human-readable Bitdefender helper observation when present.
    for event in sorted(_all_security_events(data), key=lambda e: e.get('TimeCreated') or '', reverse=True):
        if int(event.get('Id', 0)) != 4688:
            continue
        fields = get_process_fields(event)
        if not _v16_6_is_bitdefender_browser_helper_process(fields):
            continue
        detail = stakeholder_process_observation({
            'image': fields.get('image', ''),
            'parent': fields.get('parent', ''),
            'command_line': fields.get('command', ''),
            'user': fields.get('user', ''),
        })
        if detail and safe_lower(detail) not in existing:
            items.append({
                'time': event.get('TimeCreated', ''),
                'type': 'Process activity',
                'detail': detail,
                'priority': 2,
            })
            existing.add(safe_lower(detail))
        break

    # Remove noisy fallback chrome-launch phrasing if a Bitdefender helper observation exists.
    helper_present = any('bitdefender helper process' in safe_lower(x.get('detail', '')) for x in items)
    if helper_present:
        items = [x for x in items if 'user launched `chrome.exe` from `explorer.exe`' not in safe_lower(x.get('detail', ''))]

    def sort_key(x: Dict[str, Any]):
        parsed = parse_iso(x.get("time"))
        return (int(x.get("priority", 99)), -(parsed.timestamp() if parsed else 0.0))

    items.sort(key=sort_key)
    return [{'time': x.get('time', ''), 'type': x.get('type', ''), 'detail': x.get('detail', '')} for x in items[:limit]]


def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen: set = set()

    def add_finding(title: str, detail: str, time: str = '') -> bool:
        norm = safe_lower(f'{title}|{detail}')
        if not detail or norm in seen:
            return False
        seen.add(norm)
        findings.append({'title': title, 'detail': detail, 'time': stakeholder_format_time(time or '')})
        return True

    detections = analysis_results.get('detections', []) or []
    for det in detections[:8]:
        name = str(det.get('name', '')).strip()
        if not name:
            continue
        add_finding(f"{str(det.get('severity', '')).title()} detection", name, str(det.get('time', '')))
        break

    for item in summarize_test_activity(data, analysis_results, limit=8):
        detail = item.get('detail', '')
        typ = item.get('type', 'Observation')
        if 'bitdefender helper process' in safe_lower(detail):
            add_finding('Process activity', detail, item.get('time', ''))
            break
    if len(findings) < 2:
        for item in summarize_test_activity(data, analysis_results, limit=8):
            if safe_lower(item.get('type', '')) == 'correlated telemetry':
                continue
            if add_finding(item.get('type', 'Observation'), item.get('detail', ''), item.get('time', '')):
                break

    corr = _v16_find_correlated_telemetry_item(data, analysis_results)
    if corr:
        add_finding(corr.get('title', 'Correlated telemetry'), corr.get('detail', ''), corr.get('time', ''))
    else:
        add_finding('Correlated telemetry', 'No correlated DNS/network telemetry was surfaced in the focus window.', '')

    if len(findings) < 3:
        for finding in summarize_key_findings(data.get('system_info', {}), analysis_results):
            if add_finding('Key finding', finding, ''):
                break
    return findings[:3]




# --- v17.1 polish patch: better low-severity ordering, cleaner repeated user actions,
# improved Bitdefender wording, and non-blank Top 3 telemetry fallback timing ---

_V17_1_BUILD_CASE_WORKFLOW = build_case_workflow
_V17_1_TOP_FINDINGS_BASE = _v12_top_findings
_V17_1_BUILD_ACTIVITY_VIEWS_BASE = build_activity_views
_V17_1_STAKEHOLDER_PROCESS_OBSERVATION_BASE = stakeholder_process_observation


def _v17_1_detection_sort_key(det: Dict[str, Any]) -> Tuple[int, int, float]:
    severity = str(det.get("severity", "")).strip()
    sev_rank = _severity_rank(severity)
    name = safe_lower(str(det.get("name", "")))
    # Among same-severity findings, prefer more human-meaningful detections over generic
    # benign service-query noise so the report tells the clearer story first.
    display_bias = 0
    if "browser-launched bitdefender helper activity" in name:
        display_bias = 30
    elif "powershell web request" in name:
        display_bias = 25
    elif "powershell to command shell" in name:
        display_bias = 35
    elif "process access (likely benign service query)" in name:
        display_bias = -20
    elif "trust store initialization" in name:
        display_bias = -30
    parsed = parse_iso(det.get("time"))
    ts = parsed.timestamp() if parsed else 0.0
    return (sev_rank, display_bias, ts)


def _v17_1_choose_display_detection(detections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    ordered = sorted(detections, key=_v17_1_detection_sort_key, reverse=True)
    return ordered[0] if ordered else None


def _v17_1_is_browser_child_noise(item: Dict[str, Any]) -> bool:
    if item.get("kind") != "process":
        return False
    fields = item.get("fields") or {}
    image_name = safe_lower(fields.get("image_name", ""))
    parent_name = safe_lower(fields.get("parent_name", ""))
    command = safe_lower(fields.get("command", ""))
    if image_name not in {"chrome.exe", "msedge.exe"}:
        return False
    if parent_name != image_name:
        return False
    noisy_tokens = [
        "--type=",
        "--gpu-process",
        "--renderer",
        "--crashpad-handler",
        "--utility-sub-type=",
        "--restart",
        "--origin-trial-disabled-features=",
    ]
    return any(tok in command for tok in noisy_tokens)


def _v17_1_is_repeat_user_scriptblock(item: Dict[str, Any]) -> bool:
    if item.get("kind") != "scriptblock":
        return False
    text = (item.get("detail") or "").strip()
    return text == "Get-StartApps"


def stakeholder_process_observation(item: Dict[str, Any], allow_fallback: bool = False) -> Optional[str]:
    image = str(item.get("image", "")).strip()
    parent = str(item.get("parent", "")).strip()
    cmd = str(item.get("command_line", "")).strip()
    user = str(item.get("user", "")).strip()
    fields = {
        "image": image,
        "image_name": Path(image).name.lower() if image else "",
        "parent": parent,
        "parent_name": Path(parent).name.lower() if parent else "",
        "command": cmd,
        "user": user,
    }
    if _v16_6_is_bitdefender_browser_helper_process(fields):
        browser = "Chrome" if "chrome-extension://" in safe_lower(cmd) or safe_lower(parent).endswith("chrome.exe") else "Browser"
        via = " via `cmd.exe`" if Path(parent).name.lower() == "cmd.exe" else ""
        return f"{browser} launched a Bitdefender helper process{via} during expected browser-protection or extension activity."
    return _V17_1_STAKEHOLDER_PROCESS_OBSERVATION_BASE(item, allow_fallback)


def build_activity_views(
    security_events: List[Dict[str, Any]],
    ps_events: List[Dict[str, Any]],
    sysmon_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    views = _V17_1_BUILD_ACTIVITY_VIEWS_BASE(security_events, ps_events, sysmon_events)
    likely = list(views.get("likely_user_actions", []) or [])
    background = list(views.get("background_activity", []) or [])

    cleaned_likely: List[Dict[str, Any]] = []
    moved_background: List[Dict[str, Any]] = []
    seen_scriptblocks: set = set()

    for item in likely:
        if _v17_1_is_browser_child_noise(item):
            item["category"] = "background"
            item["reasons"] = _dedupe_keep_order(list(item.get("reasons", [])) + ["browser self-child helper / renderer noise"])
            moved_background.append(item)
            continue
        if _v17_1_is_repeat_user_scriptblock(item):
            key = safe_lower((item.get("detail") or "").strip())
            if key in seen_scriptblocks:
                item["category"] = "background"
                item["reasons"] = _dedupe_keep_order(list(item.get("reasons", [])) + ["repeated user validation command"])
                moved_background.append(item)
                continue
            seen_scriptblocks.add(key)
        cleaned_likely.append(item)

    # Keep chronological prominence after adjustments.
    def sort_key(item: Dict[str, Any]):
        parsed = parse_iso(item.get("time"))
        return -(parsed.timestamp() if parsed else 0.0)

    cleaned_likely.sort(key=sort_key)
    background.extend(moved_background)
    background.sort(key=sort_key)
    views["likely_user_actions"] = cleaned_likely
    views["background_activity"] = background
    views["full_raw_timeline"] = cleaned_likely + background
    return views


def build_case_workflow(raw_data: Dict[str, Any], analysis_results: Dict[str, Any], outdir: Optional[Path] = None) -> Dict[str, Any]:
    case = _V17_1_BUILD_CASE_WORKFLOW(raw_data, analysis_results, outdir)
    dets = analysis_results.get("detections", []) or []
    ordered = sorted(dets, key=_v17_1_detection_sort_key, reverse=True)
    top_detections = ordered[:5]

    triage_steps: List[str] = []
    evidence_items: List[str] = []
    for det in top_detections:
        pb = _playbook_for_detection_name(det.get("name", ""))
        triage_steps.extend(pb.get("triage", []))
        evidence_items.extend(pb.get("evidence", []))
    triage_steps.extend(GENERAL_TRIAGE_STEPS)
    evidence_items.extend(GENERAL_EVIDENCE_ITEMS)

    case["top_detections"] = [
        {
            "time": d.get("time", ""),
            "severity": d.get("severity", ""),
            "name": d.get("name", ""),
            "evidence": d.get("evidence", ""),
            "why": d.get("why", ""),
            "action": d.get("action", ""),
        }
        for d in top_detections
    ]
    case["triage_steps"] = _dedupe_keep_order(triage_steps, limit=10)
    case["next_evidence_to_collect"] = _dedupe_keep_order(evidence_items, limit=12)
    return case


def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen: set = set()

    def add_finding(title: str, detail: str, time: str = '') -> bool:
        norm = safe_lower(f'{title}|{detail}')
        if not detail or norm in seen:
            return False
        seen.add(norm)
        display_time = stakeholder_format_time(time or '') if time else ""
        findings.append({'title': title, 'detail': detail, 'time': display_time})
        return True

    detections = analysis_results.get('detections', []) or []
    top_det = _v17_1_choose_display_detection(detections)
    if top_det:
        add_finding(f"{str(top_det.get('severity', '')).title()} detection", str(top_det.get('name', '')).strip(), str(top_det.get('time', '')))

    for item in summarize_test_activity(data, analysis_results, limit=8):
        detail = item.get('detail', '')
        if 'bitdefender helper process' in safe_lower(detail):
            add_finding('Process activity', detail, item.get('time', ''))
            break

    corr = _v16_find_correlated_telemetry_item(data, analysis_results)
    if corr:
        add_finding(corr.get('title', 'Correlated telemetry'), corr.get('detail', ''), corr.get('time', ''))
    else:
        anchor_time = ''
        focus_time = _v16_1_primary_focus_time(data, analysis_results)
        if focus_time:
            anchor_time = str(focus_time)
        elif top_det:
            anchor_time = str(top_det.get('time', ''))
        add_finding('Correlated telemetry', 'No correlated DNS/network telemetry was surfaced in the focus window.', anchor_time)

    if len(findings) < 3:
        for finding in summarize_key_findings(data.get('system_info', {}), analysis_results):
            if add_finding('Key finding', finding, ''):
                break
    return findings[:3]



# --- v17.2 balance patch: keep the calm low-risk output, but restore a little analyst/story context ---
_V17_2_BUILD_ACTIVITY_VIEWS_BASE = build_activity_views
_V17_2_SUMMARIZE_TEST_ACTIVITY_BASE = summarize_test_activity
_V17_2_TOP_FINDINGS_BASE = _v12_top_findings


def _v17_2_actor_is_interactive(fields: Dict[str, str]) -> bool:
    user = str(fields.get('user', '') or '').strip()
    lowered = safe_lower(user)
    if not lowered:
        return False
    if lowered.endswith('$'):
        return False
    if 'system' in lowered or 'local service' in lowered or 'network service' in lowered:
        return False
    return True


def _v17_2_is_user_app_launch(item: Dict[str, Any]) -> bool:
    if item.get('kind') != 'process':
        return False
    fields = item.get('fields') or {}
    image_name = safe_lower(fields.get('image_name', ''))
    parent_name = safe_lower(fields.get('parent_name', ''))
    if parent_name != 'explorer.exe':
        return False
    if not _v17_2_actor_is_interactive(fields):
        return False
    return image_name in {'chrome.exe', 'msedge.exe', 'firefox.exe', 'wireshark.exe', 'notepad.exe'}


def _v17_2_is_contextual_process(item: Dict[str, Any]) -> bool:
    if item.get('kind') != 'process':
        return False
    fields = item.get('fields') or {}
    image_name = safe_lower(fields.get('image_name', ''))
    parent_name = safe_lower(fields.get('parent_name', ''))
    detail = safe_lower(item.get('detail', ''))
    if _v16_6_is_bitdefender_browser_helper_process(fields):
        return True
    if image_name == 'cmd.exe' and parent_name in {'chrome.exe', 'msedge.exe'} and ('bitdefender' in detail or 'chrome-extension://' in detail):
        return True
    return False


def build_activity_views(
    security_events: List[Dict[str, Any]],
    ps_events: List[Dict[str, Any]],
    sysmon_events: List[Dict[str, Any]],
) -> Dict[str, Any]:
    views = _V17_2_BUILD_ACTIVITY_VIEWS_BASE(security_events, ps_events, sysmon_events)
    likely = list(views.get('likely_user_actions', []) or [])
    background = list(views.get('background_activity', []) or [])

    def ts(item: Dict[str, Any]) -> float:
        parsed = parse_iso(item.get('time'))
        return parsed.timestamp() if parsed else 0.0

    seen = {safe_lower(str(item.get('detail', ''))) for item in likely}
    moved: List[Dict[str, Any]] = []

    # If the top layer got too sparse, restore a couple of human-meaningful context items.
    if len(likely) < 4:
        for pred, reason in [
            (_v17_2_is_contextual_process, 'restored contextual process activity for analyst storyline'),
            (_v17_2_is_user_app_launch, 'restored contextual user application launch'),
        ]:
            for item in sorted(background, key=ts, reverse=True):
                detail_key = safe_lower(str(item.get('detail', '')))
                if detail_key in seen:
                    continue
                if not pred(item):
                    continue
                new_item = dict(item)
                new_item['category'] = 'likely_user'
                new_item['reasons'] = _dedupe_keep_order(list(new_item.get('reasons', [])) + [reason])
                likely.append(new_item)
                moved.append(item)
                seen.add(detail_key)
                break

    if moved:
        moved_ids = {id(x) for x in moved}
        background = [x for x in background if id(x) not in moved_ids]
        likely.sort(key=ts, reverse=True)
        background.sort(key=ts, reverse=True)
        views['likely_user_actions'] = likely
        views['background_activity'] = background
        views['full_raw_timeline'] = likely + background
    return views


def summarize_test_activity(data: Dict[str, Any], analysis_results: Dict[str, Any], limit: int = 6) -> List[Dict[str, str]]:
    items = list(_V17_2_SUMMARIZE_TEST_ACTIVITY_BASE(data, analysis_results, limit=max(limit, 6)))
    existing = {safe_lower(x.get('detail', '')) for x in items}
    activity = analysis_results.get('activity_views') or {}
    candidate_items = list(activity.get('likely_user_actions', []) or []) + list(activity.get('background_activity', []) or [])

    # Prefer the Bitdefender/browser helper story if it exists anywhere in the current activity views.
    for item in sorted(candidate_items, key=lambda x: (parse_iso(x.get('time')).timestamp() if parse_iso(x.get('time')) else 0.0), reverse=True):
        if not _v17_2_is_contextual_process(item):
            continue
        fields = item.get('fields') or {}
        detail = stakeholder_process_observation({
            'image': fields.get('image', ''),
            'parent': fields.get('parent', ''),
            'command_line': fields.get('command', ''),
            'user': fields.get('user', ''),
        })
        if detail and safe_lower(detail) not in existing:
            items.append({'time': item.get('time', ''), 'type': 'Process activity', 'detail': detail})
            existing.add(safe_lower(detail))
        break

    # If the summary is too sparse, add one simple user-launch observation for context.
    if len(items) < max(3, min(limit, 3)):
        for item in sorted(candidate_items, key=lambda x: (parse_iso(x.get('time')).timestamp() if parse_iso(x.get('time')) else 0.0), reverse=True):
            if not _v17_2_is_user_app_launch(item):
                continue
            fields = item.get('fields') or {}
            image_name = Path(str(fields.get('image', '') or '')).name or str(fields.get('image_name', '') or '')
            detail = f"User launched `{image_name}` from `explorer.exe`."
            if safe_lower(detail) in existing:
                continue
            items.append({'time': item.get('time', ''), 'type': 'Process activity', 'detail': detail})
            existing.add(safe_lower(detail))
            break

    def sort_key(x: Dict[str, Any]):
        parsed = parse_iso(x.get('time'))
        return -(parsed.timestamp() if parsed else 0.0)

    items.sort(key=sort_key)
    return items[:limit]


def _v12_top_findings(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, str]]:
    findings: List[Dict[str, str]] = []
    seen: set = set()

    def add_finding(title: str, detail: str, time: str = '') -> bool:
        norm = safe_lower(f'{title}|{detail}')
        if not detail or norm in seen:
            return False
        seen.add(norm)
        findings.append({'title': title, 'detail': detail, 'time': stakeholder_format_time(time or '')})
        return True

    detections = analysis_results.get('detections', []) or []
    top_det = _v17_1_choose_display_detection(detections)
    if top_det:
        add_finding(f"{str(top_det.get('severity', '')).title()} detection", str(top_det.get('name', '')).strip(), str(top_det.get('time', '')))

    # Try to add one human-readable process story before the telemetry fallback.
    for item in summarize_test_activity(data, analysis_results, limit=6):
        if safe_lower(item.get('type', '')) == 'correlated telemetry':
            continue
        detail = item.get('detail', '')
        if add_finding(item.get('type', 'Process activity'), detail, item.get('time', '')):
            break

    corr = _v16_find_correlated_telemetry_item(data, analysis_results)
    if corr:
        add_finding(corr.get('title', 'Correlated telemetry'), corr.get('detail', ''), corr.get('time', ''))
    else:
        anchor_time = ''
        focus_time = _v16_1_primary_focus_time(data, analysis_results)
        if focus_time:
            anchor_time = str(focus_time)
        elif top_det:
            anchor_time = str(top_det.get('time', ''))
        add_finding('Correlated telemetry', 'No correlated DNS/network telemetry was surfaced in the focus window.', anchor_time)

    if len(findings) < 3:
        for finding in summarize_key_findings(data.get('system_info', {}), analysis_results):
            if add_finding('Key finding', finding, ''):
                break
    return findings[:3]


# ---- v18 ATT&CK tagging phase ----
_V17_2_BUILD_NAMED_DETECTIONS = build_named_detections
_V17_2_GENERATE_MARKDOWN = generate_markdown
_V17_2_GENERATE_ANALYST_HTML = generate_analyst_html
_V17_2_RENDER_DETECTION_MARKDOWN = _render_detection_markdown
_V17_2_RENDER_DETECTION_HTML_SECTION = _render_detection_html_section

_ATTACK_CONFIDENCE_ORDER = {"Low": 1, "Medium": 2, "High": 3}


def _attack_tag(tactic: str, technique_id: str, technique_name: str, confidence: str = "Medium", notes: str = "") -> Dict[str, Any]:
    return {
        "tactic": tactic,
        "technique_id": technique_id,
        "technique_name": technique_name,
        "confidence": confidence.title() if confidence else "Medium",
        "notes": notes or "",
    }


def _attack_tags_for_detection(det: Dict[str, Any]) -> List[Dict[str, Any]]:
    name = str(det.get("name", "") or "")
    evidence = str(det.get("evidence", "") or "")
    lowered = f"{name} {evidence}".lower()
    tags: List[Dict[str, Any]] = []

    if name == "PowerShell to Command Shell":
        tags.extend([
            _attack_tag(
                "Execution",
                "T1059.001",
                "Command and Scripting Interpreter: PowerShell",
                "Medium",
                "Parent PowerShell activity is part of the observed execution chain.",
            ),
            _attack_tag(
                "Execution",
                "T1059.003",
                "Command and Scripting Interpreter: Windows Command Shell",
                "High",
                "The detection is driven by cmd.exe launched from PowerShell.",
            ),
        ])
    elif name == "PowerShell Web Request":
        tags.extend([
            _attack_tag(
                "Execution",
                "T1059.001",
                "Command and Scripting Interpreter: PowerShell",
                "High",
                "The observed behavior is a PowerShell command/script block.",
            ),
            _attack_tag(
                "Command and Control",
                "T1105",
                "Ingress Tool Transfer",
                "Medium",
                "Mapped when a PowerShell web request retrieves remote content or writes to disk.",
            ),
        ])
    elif name == "PowerShell to LOLBin":
        tags.extend([
            _attack_tag(
                "Execution",
                "T1059.001",
                "Command and Scripting Interpreter: PowerShell",
                "Medium",
                "PowerShell is the launching context for the observed LOLBin chain.",
            ),
            _attack_tag(
                "Defense Evasion",
                "T1218",
                "System Binary Proxy Execution",
                "High",
                "Living-off-the-land binaries are commonly used as trusted proxy execution tools.",
            ),
        ])
    elif name == "Suspicious Child Process from Office/Browser":
        if "office" in lowered:
            tags.append(_attack_tag(
                "Execution",
                "T1204.002",
                "User Execution: Malicious File",
                "Low",
                "Office-to-shell chains are commonly associated with user-opened malicious content, but this generic detection still needs context.",
            ))
        elif "browser" in lowered:
            tags.append(_attack_tag(
                "Execution",
                "T1204.001",
                "User Execution: Malicious Link",
                "Low",
                "Browser-to-shell chains can follow user execution of a malicious link, though this generic detection still needs context.",
            ))
    elif name == "Persistence-Related Change":
        if any(token in lowered for token in ["currentversion\\run", " startup", "startup folder", "startup\\"]):
            tags.append(_attack_tag(
                "Persistence",
                "T1547.001",
                "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
                "High",
                "The evidence references a Run key or Startup location.",
            ))
        if "schtasks" in lowered or "scheduled task" in lowered:
            tags.append(_attack_tag(
                "Execution, Persistence, Privilege Escalation",
                "T1053.005",
                "Scheduled Task/Job: Scheduled Task",
                "High",
                "The evidence references schtasks or a scheduled task path.",
            ))
    elif name == "WMI Persistence-Adjacent Activity":
        tags.append(_attack_tag(
            "Persistence, Privilege Escalation",
            "T1546.003",
            "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
            "Medium",
            "Mapped when WMI consumer/filter/binding activity suggests persistence-adjacent behavior.",
        ))
    elif name == "Process Tampering / Injection-Adjacent Activity":
        tags.append(_attack_tag(
            "Defense Evasion, Privilege Escalation",
            "T1055",
            "Process Injection",
            "Low",
            "This is an injection-adjacent mapping only; the current detection often requires analyst validation before confirming process injection.",
        ))
    elif name == "Executable Dropped / Detected":
        tags.append(_attack_tag(
            "Command and Control",
            "T1105",
            "Ingress Tool Transfer",
            "Low",
            "A newly observed executable can reflect a transferred tool or payload, but this detection alone is not enough to confirm it.",
        ))
    elif name == "Delete-After-Execution Style Activity":
        tags.append(_attack_tag(
            "Defense Evasion",
            "T1070.004",
            "Indicator Removal: File Deletion",
            "Medium",
            "This maps cleanup-like deletion behavior to ATT&CK's file deletion technique.",
        ))

    deduped: List[Dict[str, Any]] = []
    seen = set()
    for tag in tags:
        key = (tag.get("technique_id", ""), tag.get("technique_name", ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(tag)
    return deduped



def _attack_inline_text(tags: List[Dict[str, Any]]) -> str:
    if not tags:
        return ""
    return "; ".join(
        f"{t.get('technique_id','')} {t.get('technique_name','')} [{t.get('tactic','')}; {t.get('confidence','Medium')}]"
        for t in tags
    )



def _attack_coverage_rows(analysis_results: Dict[str, Any]) -> List[List[str]]:
    coverage: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for det in analysis_results.get("detections", []):
        for tag in det.get("attack_tags", []) or []:
            key = (tag.get("technique_id", ""), tag.get("technique_name", ""))
            bucket = coverage.setdefault(key, {
                "tactics": set(),
                "detections": set(),
                "confidence": "Low",
            })
            bucket["tactics"].add(tag.get("tactic", ""))
            bucket["detections"].add(det.get("name", ""))
            current = bucket.get("confidence", "Low")
            proposed = tag.get("confidence", "Low")
            if _ATTACK_CONFIDENCE_ORDER.get(proposed, 1) > _ATTACK_CONFIDENCE_ORDER.get(current, 1):
                bucket["confidence"] = proposed
    rows: List[List[str]] = []
    for (technique_id, technique_name), bucket in sorted(coverage.items(), key=lambda kv: kv[0][0]):
        rows.append([
            ", ".join(sorted(x for x in bucket["tactics"] if x)),
            technique_id,
            technique_name,
            ", ".join(sorted(x for x in bucket["detections"] if x)),
            bucket.get("confidence", "Low"),
        ])
    return rows



def _render_attack_coverage_markdown(analysis_results: Dict[str, Any]) -> str:
    rows = _attack_coverage_rows(analysis_results)
    if not rows:
        return ""
    parts = ["## ATT&CK Coverage\n"]
    parts.append(render_table(["Tactic(s)", "Technique ID", "Technique Name", "Mapped Detection(s)", "Confidence"], rows))
    parts.append("")
    return "\n".join(parts)



def _render_attack_coverage_html_section(analysis_results: Dict[str, Any]) -> str:
    rows = _attack_coverage_rows(analysis_results)
    if not rows:
        return ""
    return (
        "<section id='attackcoverage'><h2>ATT&amp;CK Coverage</h2>" +
        render_html_table(["Tactic(s)", "Technique ID", "Technique Name", "Mapped Detection(s)", "Confidence"], rows) +
        "<div class='panel'><p class='small'>ATT&amp;CK mappings are analyst-facing tags attached to named detections. They describe likely tradecraft alignment without changing the underlying event evidence or the core severity logic.</p></div>" +
        "</section>"
    )



def build_named_detections(data: Dict[str, Any], analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
    detections = _V17_2_BUILD_NAMED_DETECTIONS(data, analysis_results)
    enriched: List[Dict[str, Any]] = []
    for det in detections:
        item = dict(det)
        tags = _attack_tags_for_detection(item)
        item["attack_tags"] = tags
        item["attack_display"] = _attack_inline_text(tags)
        enriched.append(item)
    return enriched



def _render_detection_markdown(analysis_results: Dict[str, Any]) -> str:
    dets = analysis_results.get("detections", [])
    if not dets:
        return "## Detections\n\nNo named detections fired from the current rule set.\n"
    rows = []
    for d in dets[:25]:
        rows.append([
            d.get("time", ""),
            d.get("severity", ""),
            d.get("name", ""),
            short(d.get("attack_display", ""), 95) if d.get("attack_display") else "—",
            short(d.get("evidence", ""), 120),
            short(d.get("why", ""), 120),
            short(d.get("action", ""), 120),
        ])
    parts = [
        "## Detections\n",
        render_table(["Time", "Severity", "Detection Name", "ATT&CK", "Evidence", "Why It Fired", "Recommended Analyst Action"], rows),
        "",
    ]
    why_lines = _v14_detection_summary_lines(analysis_results, limit=5)
    if why_lines:
        parts.append("## Why This Matters\n")
        parts.extend([f"- {line}" for line in why_lines])
        parts.append("")
    return "\n".join(parts)



def _render_detection_html_section(analysis_results: Dict[str, Any]) -> str:
    dets = analysis_results.get("detections", [])
    if not dets:
        return "<section id='detections'><h2>Detections</h2><div class='panel'><p>No named detections fired from the current rule set.</p></div></section>"
    rows = []
    for d in dets[:25]:
        sev = d.get("severity", "")
        attack_text = d.get("attack_display", "") or "—"
        rows.append([
            d.get("time", ""),
            sev,
            d.get("name", ""),
            (short(attack_text, 110), attack_text),
            (short(d.get("evidence", ""), 130), d.get("evidence", "")),
            (short(d.get("why", ""), 140), d.get("why", "")),
            (short(d.get("action", ""), 140), d.get("action", "")),
        ])
    why_lines = _v14_detection_summary_lines(analysis_results, limit=5)
    why_html = ""
    if why_lines:
        why_html = "<div class='panel'><h3>Why This Matters</h3><ul>" + "".join(f"<li>{html_escape(x)}</li>" for x in why_lines) + "</ul></div>"
    return f"<section id='detections'><h2>Detections</h2>{render_html_table(['Time','Severity','Detection Name','ATT&CK','Evidence','Why It Fired','Recommended Analyst Action'], rows)}{why_html}</section>"



def generate_markdown(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    base = _V17_2_GENERATE_MARKDOWN(data, analysis_results, days)
    section = _render_attack_coverage_markdown(analysis_results)
    if not section.strip():
        return base
    if "## ATT&CK Coverage" in base:
        return base
    if "## Host Summary" in base:
        return base.replace("## Host Summary", section + "\n## Host Summary", 1)
    return base + "\n\n" + section



def generate_analyst_html(data: Dict[str, Any], analysis_results: Dict[str, Any], days: int) -> str:
    html = _V17_2_GENERATE_ANALYST_HTML(data, analysis_results, days)
    section = _render_attack_coverage_html_section(analysis_results)
    if not section:
        return html
    if "#attackcoverage" not in html:
        html = html.replace("<a href='#detections'>Detections</a>", "<a href='#detections'>Detections</a><a href='#attackcoverage'>ATT&amp;CK Coverage</a>", 1)
    if "<section id='attackcoverage'>" not in html:
        html = html.replace("<section id='host'>", section + "<section id='host'>", 1)
    return html


if __name__ == "__main__":
    raise SystemExit(main())
