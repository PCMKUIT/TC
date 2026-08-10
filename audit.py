"""
Windows Security Audit Automation Framework (WSAAF)
Single-File Standalone Edition
"""

import os
import sys
import time
import json
import re
import math
import hashlib
import threading
import subprocess
import concurrent.futures
from abc import ABC, abstractmethod
from typing import Optional, List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

try:
    import psutil
except ImportError:
    print("[-] Error: 'psutil' is not installed. Please run: pip install psutil")
    sys.exit(1)

# Platform check
if os.name != 'nt':
    print("[-] Error: This framework is designed exclusively for Windows.")
    sys.exit(1)

import winreg
import ctypes
from ctypes import wintypes


# ============================================================================
# 1. CORE MODELS (Normalization Layer)
# ============================================================================

class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class FileTrust:
    path: str
    exists: bool = False
    sha256: str = ""
    is_signed: bool = False
    signer: str = ""
    company: str = ""
    entropy: float = 0.0

@dataclass
class NetworkConnection:
    protocol: str
    laddr: str
    lport: int
    raddr: str
    rport: int
    status: str

@dataclass
class PersistenceItem:
    mechanism: str
    location: str
    target_path: str
    target_args: str = ""
    user_context: str = "SYSTEM"
    is_signed: bool = False
    signer: str = ""
    sha256: str = ""

@dataclass
class DLLInfo:
    pid: int
    name: str
    path: str
    company: str = ""
    is_signed: bool = False
    signer: str = ""
    sha256: str = ""
    is_suspicious_location: bool = False
    is_hijack_risk: bool = False

@dataclass
class HandleInfo:
    pid: int
    process_name: str
    handle_type: str
    handle_name: str
    is_deleted_file: bool = False
    is_suspicious_location: bool = False

@dataclass
class DriverInfo:
    name: str
    display_name: str
    path: str
    start_type: str
    is_signed: bool = False
    publisher: str = ""
    sha256: str = ""
    is_test_signed: bool = False
    exists: bool = True

@dataclass
class EventLogEntry:
    log_name: str
    event_id: int
    time_generated: str
    provider: str
    message: str
    pid: Optional[int] = None
    user: str = ""
    extracted_iocs: List[str] = field(default_factory=list)

@dataclass
class IOCMatch:
    ioc_type: str
    value: str
    context: str

@dataclass
class Process:
    pid: int
    ppid: int
    name: str
    exe_path: str
    cmdline: List[str]
    username: str
    connections: List[NetworkConnection] = field(default_factory=list)
    loaded_dlls: List[DLLInfo] = field(default_factory=list)
    handles: List[HandleInfo] = field(default_factory=list)

@dataclass
class CorrelatedEntity:
    entity_id: str
    exe_path: str
    sha256: str = ""
    signer: str = ""
    is_signed: bool = False
    processes: List[Process] = field(default_factory=list)
    persistence: List[PersistenceItem] = field(default_factory=list)
    dlls: List[DLLInfo] = field(default_factory=list)
    handles: List[HandleInfo] = field(default_factory=list)
    event_logs: List[EventLogEntry] = field(default_factory=list)
    iocs: List[IOCMatch] = field(default_factory=list)

@dataclass
class Finding:
    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    risk_score: int
    confidence_score: float
    entity_id: str
    evidence: Dict[str, Any]
    trigger_trace: List[str]
    explanation: str
    recommendation: str
    category: str


# ============================================================================
# 2. UTILITIES & CACHING
# ============================================================================

class FileCacheManager:
    """Thread-safe cache for expensive disk hashing, entropy, and signature queries."""
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(FileCacheManager, cls).__new__(cls)
                cls._instance.cache: Dict[str, Tuple[float, FileTrust]] = {}
        return cls._instance

    @staticmethod
    def calculate_sha256(path: str) -> str:
        h = hashlib.sha256()
        try:
            with open(path, 'rb') as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        except Exception:
            return ""

    @staticmethod
    def calculate_entropy(path: str) -> float:
        try:
            with open(path, 'rb') as f:
                data = f.read()
            if not data: return 0.0
            entropy = 0.0
            for x in range(256):
                p_x = data.count(x) / len(data)
                if p_x > 0:
                    entropy -= p_x * math.log2(p_x)
            return round(entropy, 4)
        except Exception:
            return 0.0

    @staticmethod
    def verify_digital_signature(path: str) -> Tuple[bool, str]:
        """Simplified WinVerifyTrust stub. In production, maps full WINTRUST_DATA structures."""
        if not os.path.exists(path):
            return False, ""
        path_lower = path.lower()
        if "system32" in path_lower or "syswow64" in path_lower or "program files\\windows" in path_lower:
            return True, "Microsoft Windows (Heuristic Match)"
        return False, ""

    def get_file_trust(self, path: str) -> FileTrust:
        if not path or not os.path.exists(path):
            return FileTrust(path=path, exists=False)

        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return FileTrust(path=path, exists=False)

        with self._lock:
            if path in self.cache:
                cached_mtime, trust_obj = self.cache[path]
                if cached_mtime == mtime:
                    return trust_obj

        sha256 = self.calculate_sha256(path)
        entropy = self.calculate_entropy(path)
        is_signed, signer = self.verify_digital_signature(path)

        trust_obj = FileTrust(
            path=path, exists=True, sha256=sha256,
            is_signed=is_signed, signer=signer, entropy=entropy
        )

        with self._lock:
            self.cache[path] = (mtime, trust_obj)

        return trust_obj


# ============================================================================
# 3. IOC SCANNER
# ============================================================================

class IOCScanner:
    PATTERNS = {
        "IPv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        "URL": r"https?://[^\s/$.?#].[^\s]*",
        "Base64": r"(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "PowerShell_Enc": r"(?i)-e(?:ncod(?:edcommand|ing))?\s+([A-Za-z0-9+/=]+)",
        "LOLBin": r"(?i)\b(certutil|bitsadmin|mshta|rundll32|cscript|wmic|regsvr32|powershell)\.exe\b",
        "Suspicious_API": r"\b(VirtualAlloc|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection)\b"
    }

    @classmethod
    def scan_text(cls, text: str, context: str) -> List[IOCMatch]:
        matches: List[IOCMatch] = []
        if not text: return matches

        for ioc_type, pattern in cls.PATTERNS.items():
            for m in re.finditer(pattern, text):
                val = m.group(0)
                if ioc_type == "IPv4" and (val.startswith("127.") or val.startswith("0.")):
                    continue
                matches.append(IOCMatch(ioc_type=ioc_type, value=val[:100], context=context))
        return matches


# ============================================================================
# 4. COLLECTORS
# ============================================================================

class BaseCollector(ABC):
    @property
    @abstractmethod
    def name(self) -> str: pass

    @abstractmethod
    def collect(self) -> Any: pass

class ProcessNetworkCollector(BaseCollector):
    @property
    def name(self) -> str: return "ProcessNetworkCollector"

    def collect(self) -> List[Process]:
        processes = []
        for p in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'connections']):
            try:
                info = p.info
                if not info.get('exe'): continue
                
                conns = []
                for c in (info.get('connections') or []):
                    if c.status in ('ESTABLISHED', 'LISTEN'):
                        conns.append(NetworkConnection(
                            protocol="TCP" if c.type == 1 else "UDP",
                            laddr=c.laddr.ip if c.laddr else "",
                            lport=c.laddr.port if c.laddr else 0,
                            raddr=c.raddr.ip if c.raddr else "",
                            rport=c.raddr.port if c.raddr else 0,
                            status=c.status
                        ))

                processes.append(Process(
                    pid=info['pid'],
                    ppid=info.get('ppid', 0),
                    name=info['name'],
                    exe_path=info['exe'],
                    cmdline=info.get('cmdline') or [],
                    username=info.get('username') or "UNKNOWN",
                    connections=conns
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

class ComprehensivePersistenceCollector(BaseCollector):
    @property
    def name(self) -> str: return "ComprehensivePersistenceCollector"
    
    def __init__(self):
        self.cache = FileCacheManager()

    def collect(self) -> List[PersistenceItem]:
        items: List[PersistenceItem] = []
        items.extend(self._audit_startup_folders())
        items.extend(self._audit_registry_run())
        items.extend(self._audit_services())
        items.extend(self._audit_scheduled_tasks())
        return items

    def _audit_startup_folders(self) -> List[PersistenceItem]:
        items = []
        paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
        ]
        for folder in paths:
            if os.path.exists(folder):
                for f in os.listdir(folder):
                    full = os.path.join(folder, f)
                    trust = self.cache.get_file_trust(full)
                    items.append(PersistenceItem(
                        mechanism="StartupFolder", location=folder, target_path=full,
                        is_signed=trust.is_signed, signer=trust.signer, sha256=trust.sha256
                    ))
        return items

    def _audit_registry_run(self) -> List[PersistenceItem]:
        items = []
        run_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, key_path in run_keys:
            try:
                with winreg.OpenKey(hive, key_path) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        name, val, _ = winreg.EnumValue(key, i)
                        clean_path = str(val).split(" -")[0].split(" /")[0].strip('"')
                        trust = self.cache.get_file_trust(clean_path)
                        items.append(PersistenceItem(
                            mechanism="RegistryRun", location=key_path, target_path=clean_path, target_args=str(val),
                            is_signed=trust.is_signed, signer=trust.signer, sha256=trust.sha256
                        ))
            except Exception:
                continue
        return items

    def _audit_services(self) -> List[PersistenceItem]:
        items = []
        cmd = 'powershell -NoProfile -Command "Get-CimInstance Win32_Service | Where-Object {$_.StartMode -eq \'Auto\'} | Select-Object Name, PathName, StartUser | ConvertTo-Json"'
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                data = data if isinstance(data, list) else [data]
                for s in data:
                    pathname = str(s.get("PathName", ""))
                    clean_path = pathname.split(" -")[0].strip('"')
                    trust = self.cache.get_file_trust(clean_path)
                    items.append(PersistenceItem(
                        mechanism="WindowsService", location=s.get("Name", "Unknown"), target_path=clean_path, target_args=pathname,
                        user_context=s.get("StartUser", "SYSTEM"), is_signed=trust.is_signed, signer=trust.signer, sha256=trust.sha256
                    ))
        except Exception: pass
        return items

    def _audit_scheduled_tasks(self) -> List[PersistenceItem]:
        items = []
        cmd = 'powershell -NoProfile -Command "Get-ScheduledTask | Where-Object {$_.State -ne \'Disabled\'} | Select-Object TaskName, TaskPath, Actions | ConvertTo-Json"'
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout)
                data = data if isinstance(data, list) else [data]
                for task in data:
                    actions = task.get("Actions", [])
                    exec_path = actions[0].get("Execute", "") if isinstance(actions, list) and actions else (actions.get("Execute", "") if isinstance(actions, dict) else "")
                    if exec_path:
                        trust = self.cache.get_file_trust(exec_path)
                        items.append(PersistenceItem(
                            mechanism="ScheduledTask", location=task.get("TaskPath", "\\"), target_path=exec_path,
                            is_signed=trust.is_signed, signer=trust.signer, sha256=trust.sha256
                        ))
        except Exception: pass
        return items

class DLLAndHandleCollector(BaseCollector):
    @property
    def name(self) -> str: return "DLLAndHandleCollector"
    
    def __init__(self):
        self.cache = FileCacheManager()
        self.SUSPICIOUS_PATHS = [r"\\appdata\\", r"\\temp\\", r"\\public\\", r"\\programdata\\"]

    def collect(self) -> Tuple[List[DLLInfo], List[HandleInfo]]:
        dlls, handles = [], []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                for mm in proc.memory_maps():
                    path = mm.path.lower()
                    if path.endswith(".dll"):
                        is_susp = any(re.search(p, path) for p in self.SUSPICIOUS_PATHS)
                        trust = self.cache.get_file_trust(mm.path)
                        dlls.append(DLLInfo(
                            pid=proc.info['pid'], name=path.split("\\")[-1], path=mm.path,
                            is_signed=trust.is_signed, signer=trust.signer, sha256=trust.sha256, is_suspicious_location=is_susp
                        ))
            except (psutil.AccessDenied, psutil.NoSuchProcess): pass
        return dlls, handles

class KernelDriverCollector(BaseCollector):
    @property
    def name(self) -> str: return "KernelDriverCollector"
    def __init__(self): self.cache = FileCacheManager()

    def collect(self) -> List[DriverInfo]:
        drivers = []
        cmd = 'powershell -NoProfile -Command "Get-CimInstance Win32_SystemDriver | Select-Object Name, DisplayName, PathName, StartMode | ConvertTo-Json"'
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, shell=True, timeout=15)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout) if isinstance(json.loads(res.stdout), list) else [json.loads(res.stdout)]
                for d in data:
                    raw_path = str(d.get("PathName", "")).replace("\\SystemRoot\\", "C:\\Windows\\").strip('"')
                    trust = self.cache.get_file_trust(raw_path)
                    drivers.append(DriverInfo(
                        name=d.get("Name", ""), display_name=d.get("DisplayName", ""), path=raw_path,
                        start_type=d.get("StartMode", "Unknown"), is_signed=trust.is_signed, publisher=trust.signer, sha256=trust.sha256
                    ))
        except Exception: pass
        return drivers

class WindowsEventLogCollector(BaseCollector):
    @property
    def name(self) -> str: return "WindowsEventLogCollector"

    def collect(self) -> List[EventLogEntry]:
        entries = []
        ps = """
        $Filter = @{ LogName = @('Security', 'System'); StartTime = (Get-Date).AddDays(-1); Id = @(4624, 4688, 7045) }
        Get-WinEvent -FilterHashtable $Filter -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object LogName, Id, TimeCreated, ProviderName, Message, ProcessId | ConvertTo-Json
        """
        try:
            res = subprocess.run(f'powershell -NoProfile -Command "{ps}"', capture_output=True, text=True, shell=True, timeout=20)
            if res.returncode == 0 and res.stdout.strip():
                data = json.loads(res.stdout) if isinstance(json.loads(res.stdout), list) else [json.loads(res.stdout)]
                for ev in data:
                    entries.append(EventLogEntry(
                        log_name=str(ev.get("LogName", "")), event_id=int(ev.get("Id", 0)), time_generated=str(ev.get("TimeCreated", "")),
                        provider=str(ev.get("ProviderName", "")), message=str(ev.get("Message", ""))[:200], pid=ev.get("ProcessId")
                    ))
        except Exception: pass
        return entries


# ============================================================================
# 5. CORRELATION ENGINE
# ============================================================================

class MultiIdentifierCorrelationEngine:
    def __init__(self):
        self.cache = FileCacheManager()
        self.entities: Dict[str, CorrelatedEntity] = {}
        self.path_to_id: Dict[str, str] = {}
        self.pid_to_id: Dict[int, str] = {}

    def _get_or_create(self, path: str, pid: int = None) -> CorrelatedEntity:
        norm_path = path.lower().strip() if path else "unknown"
        eid = self.pid_to_id.get(pid) or self.path_to_id.get(norm_path)
        
        if not eid:
            trust = self.cache.get_file_trust(norm_path)
            eid = trust.sha256 if trust.sha256 else norm_path
            self.entities[eid] = CorrelatedEntity(
                entity_id=eid, exe_path=norm_path, sha256=trust.sha256, signer=trust.signer, is_signed=trust.is_signed
            )
        if norm_path != "unknown": self.path_to_id[norm_path] = eid
        if pid: self.pid_to_id[pid] = eid
        return self.entities[eid]

    def ingest_processes(self, processes: List[Process]):
        for p in processes:
            entity = self._get_or_create(p.exe_path, p.pid)
            entity.processes.append(p)
            entity.iocs.extend(IOCScanner.scan_text(" ".join(p.cmdline), f"Cmdline PID {p.pid}"))

    def ingest_persistence(self, items: List[PersistenceItem]):
        for i in items:
            entity = self._get_or_create(i.target_path)
            entity.persistence.append(i)
            entity.iocs.extend(IOCScanner.scan_text(i.target_args, f"Persistence {i.mechanism}"))

    def ingest_dlls_handles(self, dlls: List[DLLInfo], handles: List[HandleInfo]):
        for d in dlls: self._get_or_create(d.path).dlls.append(d)

    def ingest_events(self, events: List[EventLogEntry]):
        for ev in events:
            if ev.pid and ev.pid in self.pid_to_id:
                self.entities[self.pid_to_id[ev.pid]].event_logs.append(ev)

    def get_all(self) -> List[CorrelatedEntity]:
        return list(self.entities.values())


# ============================================================================
# 6. RULE ENGINE & DEFAULT RULES
# ============================================================================

DEFAULT_RULES = [
    {
        "id": "R-2001",
        "name": "Unsigned Binary with Persistence and Network Activity",
        "severity": "CRITICAL",
        "weight": 90,
        "category": "Persistence & Egress",
        "description": "An unsigned executable was detected running with network connections and a persistence mechanism.",
        "recommendation": "Isolate the host immediately, terminate the process, and submit the executable SHA256 for triage.",
        "conditions": {
            "AND": [
                { "field": "is_signed", "op": "equals", "value": False },
                { "field": "persistence_count", "op": "greater_than", "value": 0 },
                { "field": "has_network", "op": "equals", "value": True }
            ]
        }
    },
    {
        "id": "R-2002",
        "name": "Execution from User AppData or Temp Directory",
        "severity": "MEDIUM",
        "weight": 40,
        "category": "Suspicious Location",
        "description": "Process is executing from user-writable directories (AppData/Temp). Malware commonly drops payloads here.",
        "recommendation": "Verify binary authenticity, review digital signatures, and check parent processes.",
        "conditions": {
            "OR": [
                { "field": "exe_path", "op": "regex", "value": "(?i).*\\\\AppData\\\\.*" },
                { "field": "exe_path", "op": "regex", "value": "(?i).*\\\\Temp\\\\.*" }
            ]
        }
    },
    {
        "id": "R-2003",
        "name": "Suspicious IOCs Detected in Context",
        "severity": "HIGH",
        "weight": 75,
        "category": "Indicator Match",
        "description": "Known dangerous patterns (Base64, LOLBins, Suspicious APIs) were extracted from the entity's arguments or memory.",
        "recommendation": "Review the extracted IOCs in the raw data to determine if execution was malicious.",
        "conditions": { "field": "ioc_count", "op": "greater_than", "value": 0 }
    }
]

class AdvancedRuleEngine:
    def __init__(self, rules_config: List[Dict]):
        self.rules = rules_config
        self.executed_rules = set()

    def evaluate_all(self, entities: List[CorrelatedEntity]) -> List[Finding]:
        findings = []
        for entity in entities:
            for rule in self.rules:
                matched, trace = self._evaluate_cond(rule["conditions"], entity)
                if matched:
                    self.executed_rules.add(rule["id"])
                    conf = self._calc_confidence(entity)
                    findings.append(Finding(
                        finding_id=f"FIND-{rule['id']}-{abs(hash(entity.entity_id)) % 10000}",
                        rule_id=rule['id'], title=rule['name'], severity=Severity(rule['severity']),
                        risk_score=int(rule.get("weight", 10) * conf), confidence_score=conf,
                        entity_id=entity.entity_id, evidence={"exe_path": entity.exe_path},
                        trigger_trace=trace, explanation=rule['description'], recommendation=rule['recommendation'],
                        category=rule.get("category", "General")
                    ))
        return findings

    def _evaluate_cond(self, cond: Dict, entity: CorrelatedEntity) -> Tuple[bool, List[str]]:
        trace = []
        if "AND" in cond:
            for c in cond["AND"]:
                m, t = self._evaluate_cond(c, entity)
                trace.extend(t)
                if not m: return False, []
            return True, trace
        if "OR" in cond:
            for c in cond["OR"]:
                m, t = self._evaluate_cond(c, entity)
                if m: return True, t
            return False, []

        f_name, op, val = cond.get("field"), cond.get("op"), cond.get("value")
        actual = self._get_val(f_name, entity)

        if op == "equals": res = actual == val
        elif op == "regex": res = bool(re.search(str(val), str(actual)))
        elif op == "greater_than": res = float(actual or 0) > float(val)
        else: res = False

        if res: trace.append(f"Field '{f_name}' satisfied [{op} {val}]")
        return res, trace

    def _get_val(self, field: str, e: CorrelatedEntity):
        if field == "is_signed": return e.is_signed
        if field == "exe_path": return e.exe_path
        if field == "persistence_count": return len(e.persistence)
        if field == "has_network": return any(len(p.connections) > 0 for p in e.processes)
        if field == "ioc_count": return len(e.iocs)
        return None

    def _calc_confidence(self, e: CorrelatedEntity) -> float:
        c = 0.5
        if e.is_signed: c -= 0.2
        if len(e.persistence) > 0: c += 0.2
        if any(len(p.connections) > 0 for p in e.processes): c += 0.15
        if len(e.iocs) > 0: c += 0.15
        return min(max(round(c, 2), 0.1), 1.0)


# ============================================================================
# 7. HTML DASHBOARD REPORTER
# ============================================================================

class InteractiveHTMLDashboardReporter:
    @staticmethod
    def generate(findings: List[Finding], entities: List[CorrelatedEntity], out: str):
        overall = max(0, 100 - sum([25 if f.severity=="CRITICAL" else 15 if f.severity=="HIGH" else 5 for f in findings]))
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>WSAAF Dashboard</title>
<style>
    body {{ font-family: 'Segoe UI', sans-serif; background: #1a1d20; color: #e1e6ed; padding: 20px; }}
    .header {{ display: flex; justify-content: space-between; border-bottom: 2px solid #2d3238; padding-bottom: 15px; }}
    .score {{ background: #22272e; padding: 20px; border-radius: 8px; border-left: 6px solid {'#e74c3c' if overall<70 else '#2ecc71'}; }}
    .metrics {{ display: flex; gap: 15px; margin-top: 20px; }}
    .metric-box {{ flex: 1; background: #22272e; padding: 15px; border-radius: 6px; text-align: center; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #22272e; }}
    th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2d3238; }} th {{ background: #2d3238; }}
    .CRITICAL {{ background: #e74c3c; color: white; padding: 3px 8px; border-radius: 4px; }}
    .HIGH {{ background: #e67e22; color: white; padding: 3px 8px; border-radius: 4px; }}
    .MEDIUM {{ background: #f1c40f; color: black; padding: 3px 8px; border-radius: 4px; }}
</style></head>
<body>
    <div class="header"><h1>WSAAF Security Dashboard</h1>
        <div class="score"><div>Security Score</div><div style="font-size: 24px; font-weight: bold;">{overall} / 100</div></div>
    </div>
    <div class="metrics">
        <div class="metric-box">Total Findings<br><b style="font-size:24px;">{len(findings)}</b></div>
        <div class="metric-box">Correlated Entities<br><b style="font-size:24px;">{len(entities)}</b></div>
    </div>
    <h2>Actionable Findings</h2>
    <table><tr><th>ID</th><th>Severity</th><th>Title / Explanation</th><th>Score</th><th>Target</th><th>Recommendation</th></tr>
"""
        for f in sorted(findings, key=lambda x: x.risk_score, reverse=True):
            html += f"""<tr><td>{f.finding_id}</td><td><span class="{f.severity}">{f.severity}</span></td>
                <td><b>{f.title}</b><br><span style="font-size:12px;color:#aaa;">{f.explanation}</span></td>
                <td>{f.risk_score}</td><td><code>{f.evidence.get('exe_path')}</code></td><td>{f.recommendation}</td></tr>"""
        html += "</table></body></html>"
        
        with open(out, 'w', encoding='utf-8') as file:
            file.write(html)


# ============================================================================
# 8. ORCHESTRATOR (MAIN)
# ============================================================================

def main():
    print("[*] Initializing Windows Security Audit Framework (WSAAF)...")
    start = time.time()

    colls = [
        ProcessNetworkCollector(),
        ComprehensivePersistenceCollector(),
        DLLAndHandleCollector(),
        KernelDriverCollector(),
        WindowsEventLogCollector()
    ]

    print("[*] Launching parallel data collectors (may take up to 20 seconds)...")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(c.collect): c.name for c in colls}
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    print(f"[*] Collection finished in {time.time() - start:.2f}s. Correlating data...")
    
    correlator = MultiIdentifierCorrelationEngine()
    correlator.ingest_processes(results[0])
    correlator.ingest_persistence(results[1])
    correlator.ingest_dlls_handles(*results[2])
    correlator.ingest_events(results[4])
    
    entities = correlator.get_all()
    print(f"[*] Correlated {len(entities)} unique artifacts. Evaluating rules...")

    engine = AdvancedRuleEngine(DEFAULT_RULES)
    findings = engine.evaluate_all(entities)

    out_file = "WSAAF_Report.html"
    InteractiveHTMLDashboardReporter.generate(findings, entities, out_file)
    print(f"[+] Audit complete! Found {len(findings)} actionable issues.")
    print(f"[+] Dashboard saved to: {os.path.abspath(out_file)}")

if __name__ == "__main__":
    main()
