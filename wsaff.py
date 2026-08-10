"""
WSAAF-NG — Windows Security Self-Audit Framework
A defensive security auditing tool inspired by Microsoft Sysinternals.
"""

import os
import sys
import time
import json
import logging
import argparse
import platform
import subprocess
import concurrent.futures
import winreg
import hashlib
import math
import re
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Set, Optional, Any
from datetime import datetime

# ============================================================================
# Environment Validation & Dependency Check
# ============================================================================
def validate_environment():
    if sys.platform != "win32":
        print("[!] FATAL: WSAAF-NG requires Windows.")
        sys.exit(1)
    
    try:
        import psutil
    except ImportError:
        print("[!] FATAL: Required dependency 'psutil' is not installed.")
        print("    Run: pip install psutil")
        sys.exit(1)

validate_environment()
import psutil
import ctypes

# ============================================================================
# Data Models
# ============================================================================
@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: List[str]
    username: str
    create_time: Optional[float]
    memory_rss: Optional[int]
    cpu_percent: Optional[float]

@dataclass
class NetworkConnection:
    pid: int
    protocol: str
    local_address: str
    local_port: Optional[int]
    remote_address: str
    remote_port: Optional[int]
    status: str
    process_name: str

@dataclass
class PersistenceItem:
    source: str  # e.g., 'HKCU Run', 'Service', 'Scheduled Task'
    name: str
    target_path: str
    enabled: bool
    extra_info: str = ""

@dataclass
class DLLRecord:
    path: str
    loaded_by_pids: List[int] = field(default_factory=list)
    loaded_by_names: List[str] = field(default_factory=list)

@dataclass
class DriverRecord:
    name: str
    display_name: str
    state: str
    start_mode: str
    path: str

@dataclass
class EventRecord:
    time: str
    event_id: int
    level: str
    source: str
    message: str

@dataclass
class FileAnalysis:
    path: str
    size: int
    creation_time: Optional[float]
    modification_time: Optional[float]
    sha256: Optional[str]
    entropy: Optional[float]
    signature_status: str
    signer: Optional[str]
    strings_iocs: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)
    priority_score: int = 0

@dataclass
class Finding:
    finding_id: str
    rule_id: str
    title: str
    severity: str  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int
    entity: str
    evidence: str
    reasons: List[str]
    recommendation: str

@dataclass
class CollectorResult:
    name: str = ""
    status: str = "NOT_AVAILABLE"  # Default values added to prevent TypeError
    duration: float = 0.0
    items: List[Any] = field(default_factory=list)
    errors: int = 0

@dataclass
class AuditResult:
    timestamp: str
    os_version: str
    architecture: str
    python_version: str
    is_admin: bool
    collectors: Dict[str, CollectorResult] = field(default_factory=dict)
    deep_analysis: Dict[str, FileAnalysis] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    security_score: int = 100
    audit_coverage: int = 100

# ============================================================================
# Utilities
# ============================================================================
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def get_file_metadata(path: str) -> dict:
    try:
        stat = os.stat(path)
        return {"size": stat.st_size, "ctime": stat.st_ctime, "mtime": stat.st_mtime}
    except Exception:
        return {"size": 0, "ctime": None, "mtime": None}

def calculate_sha256_and_entropy(path: str, max_size: int = 10 * 1024 * 1024) -> tuple:
    """Calculates SHA256 and Shannon entropy. Uses bounded sampling for massive files."""
    try:
        size = os.path.getsize(path)
        if size == 0:
            return None, 0.0

        sha256_hash = hashlib.sha256()
        counts = [0] * 256
        total_bytes = 0

        with open(path, "rb") as f:
            if size <= max_size:
                data = f.read()
                sha256_hash.update(data)
                for byte in data:
                    counts[byte] += 1
                total_bytes = len(data)
            else:
                chunk_size = 65536
                if size > 50 * 1024 * 1024:
                    return None, 0.0
                
                while chunk := f.read(chunk_size):
                    sha256_hash.update(chunk)
                    if total_bytes < max_size:
                        for byte in chunk:
                            counts[byte] += 1
                        total_bytes += len(chunk)

        entropy = 0.0
        if total_bytes > 0:
            for count in counts:
                if count > 0:
                    p = count / total_bytes
                    entropy -= p * math.log2(p)
        return sha256_hash.hexdigest(), entropy
    except Exception:
        return None, 0.0

def verify_signature_powershell(path: str) -> tuple:
    """Uses PowerShell Get-AuthenticodeSignature to verify file trust."""
    try:
        cmd = [
            "powershell", "-NoProfile", "-Command",
            f"(Get-AuthenticodeSignature -FilePath '{path}').Status.ToString() + '|' + (Get-AuthenticodeSignature -FilePath '{path}').SignerCertificate.Subject"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        out = result.stdout.strip()
        if "|" in out:
            status, signer = out.split("|", 1)
            if status == "Valid":
                return "VALID", signer
            elif status == "HashMismatch":
                return "INVALID", signer
            elif status == "NotSigned":
                return "UNSIGNED", None
            else:
                return "UNKNOWN", None
        return "UNKNOWN", None
    except Exception:
        return "UNAVAILABLE", None

def extract_strings_and_iocs(path: str) -> List[str]:
    """Lightweight string extraction looking for basic suspicious patterns."""
    iocs_found = set()
    patterns = [
        rb"powershell", rb"cmd\.exe", rb"wscript", rb"cscript", rb"rundll32",
        rb"regsvr32", rb"mshta", rb"certutil", rb"bitsadmin",
        rb"http://", rb"https://", rb"AppData", rb"Temp"
    ]
    try:
        size = os.path.getsize(path)
        if size > 25 * 1024 * 1024:
            return []
            
        with open(path, "rb") as f:
            data = f.read()
            for pat in patterns:
                if re.search(pat, data, re.IGNORECASE):
                    iocs_found.add(pat.decode('utf-8', errors='ignore'))
    except Exception:
        pass
    return list(iocs_found)

# ============================================================================
# Core Framework Class
# ============================================================================
class WSAAF:
    def __init__(self, debug: bool = False):
        self.debug = debug
        self.logger = self._setup_logger()
        self.is_admin = is_admin()
        self.audit_result = AuditResult(
            timestamp=datetime.now().isoformat(),
            os_version=platform.version(),
            architecture=platform.machine(),
            python_version=platform.python_version(),
            is_admin=self.is_admin
        )
        self.cache = {}

    def _setup_logger(self):
        logger = logging.getLogger("WSAAF")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter("[%(levelname)s] %(message)s")
        handler.setFormatter(formatter)
        if not logger.handlers:
            logger.addHandler(handler)
        return logger

    # --- Stage 1: Fast Collection -------------------------------------------
    
    def collect_processes(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0
        
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = proc.info
                mem = None
                cpu = None
                try:
                    mem = proc.memory_info().rss
                    cpu = proc.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                items.append(ProcessRecord(
                    pid=info['pid'],
                    ppid=info['ppid'],
                    name=info['name'] or "UNKNOWN",
                    exe=info['exe'] or "",
                    cmdline=info['cmdline'] or [],
                    username=info['username'] or "",
                    create_time=info['create_time'],
                    memory_rss=mem,
                    cpu_percent=cpu
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                errors += 1
            except Exception as e:
                errors += 1
                self.logger.debug(f"Process collector error on PID {proc.pid}: {e}")

        status = "LIMITED" if not self.is_admin and errors > 50 else "SUCCESS"
        return CollectorResult("Processes", status, time.time() - start_time, items, errors)

    def collect_network(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0
        
        try:
            pid_map = {p.pid: p.info['name'] for p in psutil.process_iter(['pid', 'name']) if p.info['name']}
            
            for conn in psutil.net_connections(kind="inet"):
                try:
                    protocol = "TCP" if conn.type == 1 else "UDP"
                    items.append(NetworkConnection(
                        pid=conn.pid if conn.pid else -1,
                        protocol=protocol,
                        local_address=conn.laddr.ip if conn.laddr else "",
                        local_port=conn.laddr.port if conn.laddr else None,
                        remote_address=conn.raddr.ip if conn.raddr else "",
                        remote_port=conn.raddr.port if conn.raddr else None,
                        status=conn.status,
                        process_name=pid_map.get(conn.pid, "UNKNOWN") if conn.pid else "UNKNOWN"
                    ))
                except Exception as e:
                    errors += 1
        except psutil.AccessDenied:
            self.logger.warning("Network collection requires Administrator privileges for full visibility.")
            return CollectorResult("Network", "LIMITED", time.time() - start_time, items, 1)
        except Exception as e:
            self.logger.error(f"Network collection failed: {e}")
            return CollectorResult("Network", "ERROR", time.time() - start_time, [], 1)

        return CollectorResult("Network", "SUCCESS", time.time() - start_time, items, errors)

    def collect_persistence(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0

        hives = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        ]

        for hive, subkey in hives:
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    for i in range(1024):
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            h_name = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
                            items.append(PersistenceItem(f"{h_name} {subkey.split('\\')[-1]}", name, str(value), True))
                        except OSError:
                            break
            except FileNotFoundError:
                pass
            except PermissionError:
                errors += 1

        try:
            for svc in psutil.win_service_iter():
                try:
                    s_info = svc.dict()
                    items.append(PersistenceItem(
                        "Service", s_info.get("name", "Unknown"),
                        s_info.get("binpath", ""),
                        s_info.get("start_type") != "disabled",
                        s_info.get("display_name", "")
                    ))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    errors += 1
        except Exception:
            errors += 1

        try:
            startup_path = os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup")
            if os.path.exists(startup_path):
                for file in os.listdir(startup_path):
                    items.append(PersistenceItem("Startup Folder", file, os.path.join(startup_path, file), True))
        except Exception:
            errors += 1

        status = "LIMITED" if errors > 10 else "SUCCESS"
        return CollectorResult("Persistence", status, time.time() - start_time, items, errors)

    def collect_dlls(self) -> CollectorResult:
        start_time = time.time()
        dll_map: Dict[str, DLLRecord] = {}
        errors = 0

        for proc in psutil.process_iter(['pid', 'name']):
            try:
                maps = proc.memory_maps()
                for m in maps:
                    path = m.path
                    if path:
                        path_lower = path.lower()
                        if path_lower not in dll_map:
                            dll_map[path_lower] = DLLRecord(path=path)
                        dll_map[path_lower].loaded_by_pids.append(proc.info['pid'])
                        dll_map[path_lower].loaded_by_names.append(proc.info['name'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                errors += 1
            except Exception:
                errors += 1

        for record in dll_map.values():
            record.loaded_by_pids = list(set(record.loaded_by_pids))
            record.loaded_by_names = list(set(record.loaded_by_names))

        status = "LIMITED" if not self.is_admin else "SUCCESS"
        return CollectorResult("DLLs", status, time.time() - start_time, list(dll_map.values()), errors)

    def collect_drivers(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0

        try:
            cmd = ["driverquery", "/v", "/fo", "csv"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) > 1:
                    for line in lines[1:]:
                        parts = [p.strip('"') for p in line.split('","')]
                        if len(parts) >= 12:
                            items.append(DriverRecord(
                                name=parts[0],
                                display_name=parts[1],
                                state=parts[3],
                                start_mode=parts[4],
                                path=parts[11]
                            ))
            else:
                errors += 1
        except Exception:
            errors += 1

        status = "SUCCESS" if len(items) > 0 else ("LIMITED" if not self.is_admin else "ERROR")
        return CollectorResult("Drivers", status, time.time() - start_time, items, errors)

    def collect_events(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0

        if not self.is_admin:
            return CollectorResult("Events", "LIMITED", time.time() - start_time, [], 0)

        try:
            cmd = [
                "powershell", "-NoProfile", "-Command",
                "Get-WinEvent -FilterHashtable @{LogName='System','Security'; Level=1,2,3} -MaxEvents 50 -ErrorAction SilentlyContinue | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | ConvertTo-Json -Compress"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.stdout.strip():
                try:
                    events = json.loads(result.stdout)
                    if isinstance(events, dict):
                        events = [events]
                    for e in events:
                        msg = (e.get("Message") or "")[:100].replace("\r", " ").replace("\n", " ")
                        items.append(EventRecord(
                            time=e.get("TimeCreated", ""),
                            event_id=e.get("Id", 0),
                            level=e.get("LevelDisplayName", "Unknown"),
                            source=e.get("ProviderName", "Unknown"),
                            message=msg
                        ))
                except json.JSONDecodeError:
                    errors += 1
        except Exception:
            errors += 1

        status = "SUCCESS" if errors == 0 else "LIMITED"
        return CollectorResult("Events", status, time.time() - start_time, items, errors)

    # --- Stage 4: Suspicion Prioritization ----------------------------------
    
    def prioritize_artifacts(self) -> List[dict]:
        """Scores collected artifacts and selects candidates for deep analysis."""
        candidates = {}

        def add_candidate(path, score, reason):
            if not path or not isinstance(path, str): return
            path = path.strip('"\'')
            if not os.path.exists(path): return
            path_lower = path.lower()
            
            if path_lower not in candidates:
                candidates[path_lower] = {"path": path, "score": 0, "reasons": set()}
            
            candidates[path_lower]["score"] += score
            candidates[path_lower]["reasons"].add(reason)

        # 1. Evaluate Processes
        for p in self.audit_result.collectors.get("Processes", CollectorResult()).items:
            exe = p.exe.lower()
            if "appdata" in exe: add_candidate(p.exe, 20, "+20 AppData executable")
            if "temp" in exe: add_candidate(p.exe, 25, "+25 Temp directory executable")
            if "system32" not in exe and "program files" not in exe and "windows" not in exe:
                add_candidate(p.exe, 10, "+10 Non-standard executable path")

        # 2. Evaluate Persistence
        for p in self.audit_result.collectors.get("Persistence", CollectorResult()).items:
            path = p.target_path.split(" -")[0].split(" /")[0].strip('"\'')
            add_candidate(path, 25, f"+25 Persistence target ({p.source})")
            if "appdata" in path.lower() or "temp" in path.lower():
                add_candidate(path, 15, "+15 Suspicious persistence location")

        # 3. Evaluate Network Processes
        net_procs = set([n.process_name.lower() for n in self.audit_result.collectors.get("Network", CollectorResult()).items])
        for path_lower, data in candidates.items():
            filename = os.path.basename(path_lower)
            if filename in net_procs:
                data["score"] += 15
                data["reasons"].add("+15 Network-associated process")

        # 4. Evaluate Drivers
        for d in self.audit_result.collectors.get("Drivers", CollectorResult()).items:
            path_lower = d.path.lower()
            if "system32\\drivers" not in path_lower and path_lower.endswith(".sys"):
                add_candidate(d.path, 30, "+30 Non-standard driver path")

        results = [{"path": v["path"], "score": v["score"], "reasons": list(v["reasons"])} for v in candidates.values()]
        results = sorted([r for r in results if r["score"] >= 20], key=lambda x: x["score"], reverse=True)[:20]
        return results

    # --- Stage 5: Deep Analysis ---------------------------------------------
    
    def perform_deep_analysis(self, candidates: List[dict]):
        self.logger.info(f"[*] Deep analysis selected {len(candidates)} candidates.")
        
        for cand in candidates:
            path = cand["path"]
            path_lower = path.lower()
            
            meta = get_file_metadata(path)
            cache_key = f"{path_lower}_{meta['size']}_{meta['mtime']}"
            
            if cache_key in self.cache:
                analysis = self.cache[cache_key]
                analysis.priority_score = cand["score"]
                analysis.reasons.extend(cand["reasons"])
                self.audit_result.deep_analysis[path_lower] = analysis
                continue

            sha256, entropy = calculate_sha256_and_entropy(path)
            sig_status, signer = verify_signature_powershell(path)
            iocs = extract_strings_and_iocs(path)

            analysis = FileAnalysis(
                path=path,
                size=meta["size"],
                creation_time=meta["ctime"],
                modification_time=meta["mtime"],
                sha256=sha256,
                entropy=entropy,
                signature_status=sig_status,
                signer=signer,
                strings_iocs=iocs,
                reasons=cand["reasons"],
                priority_score=cand["score"]
            )
            
            self.cache[cache_key] = analysis
            self.audit_result.deep_analysis[path_lower] = analysis

    # --- Stage 6: Detection / Risk Scoring ----------------------------------
    
    def evaluate_rules(self):
        findings = []
        score_deductions = 0

        for path, analysis in self.audit_result.deep_analysis.items():
            reasons_str = " | ".join(analysis.reasons)
            is_unsigned = analysis.signature_status in ["INVALID", "UNSIGNED"]
            
            # R-001: Suspicious Persistence
            if "Persistence target" in reasons_str and ("AppData" in reasons_str or "Temp" in reasons_str):
                findings.append(Finding(
                    finding_id=f"FND-{len(findings)+1:03d}",
                    rule_id="R-001",
                    title="Suspicious Persistence Mechanism",
                    severity="HIGH",
                    risk_score=85,
                    entity=path,
                    evidence=f"Entropy: {analysis.entropy:.2f}, Size: {analysis.size} bytes",
                    reasons=analysis.reasons,
                    recommendation="Investigate the executable and remove persistence entry if unauthorized."
                ))
                score_deductions += 15

            # R-003: Unsigned Persistence
            if "Persistence target" in reasons_str and is_unsigned:
                findings.append(Finding(
                    finding_id=f"FND-{len(findings)+1:03d}",
                    rule_id="R-003",
                    title="Unsigned Persistence Target",
                    severity="MEDIUM",
                    risk_score=70,
                    entity=path,
                    evidence=f"Signature: {analysis.signature_status}",
                    reasons=analysis.reasons + ["+20 Unsigned file in startup location"],
                    recommendation="Verify the publisher and intent of this startup file."
                ))
                score_deductions += 10

            # R-002: Suspicious Network Process
            if "Network-associated" in reasons_str and ("AppData" in reasons_str or "Temp" in reasons_str or is_unsigned):
                findings.append(Finding(
                    finding_id=f"FND-{len(findings)+1:03d}",
                    rule_id="R-002",
                    title="Suspicious Process with Network Activity",
                    severity="HIGH",
                    risk_score=80,
                    entity=path,
                    evidence=f"Signature: {analysis.signature_status}",
                    reasons=analysis.reasons,
                    recommendation="Investigate the remote network connections associated with this process."
                ))
                score_deductions += 15

            # R-006: IOC Match
            if analysis.strings_iocs:
                findings.append(Finding(
                    finding_id=f"FND-{len(findings)+1:03d}",
                    rule_id="R-006",
                    title="Suspicious Strings/IOCs Detected",
                    severity="LOW",
                    risk_score=40,
                    entity=path,
                    evidence=f"Found: {', '.join(analysis.strings_iocs[:3])}",
                    reasons=analysis.reasons,
                    recommendation="Review strings output to ensure administrative tools are not being abused."
                ))
                score_deductions += 5

            # R-005: Suspicious Driver
            if "Non-standard driver path" in reasons_str and is_unsigned:
                findings.append(Finding(
                    finding_id=f"FND-{len(findings)+1:03d}",
                    rule_id="R-005",
                    title="Unsigned / Non-Standard Driver",
                    severity="HIGH",
                    risk_score=85,
                    entity=path,
                    evidence=f"Signature: {analysis.signature_status}",
                    reasons=analysis.reasons,
                    recommendation="Ensure this driver is legitimate. Unsigned drivers are highly unusual on modern Windows."
                ))
                score_deductions += 15

        self.audit_result.findings = findings
        
        errs = sum(1 for c in self.audit_result.collectors.values() if c.status != "SUCCESS")
        total_collectors = len(self.audit_result.collectors)
        coverage = 100
        if total_collectors > 0:
            coverage = 100 - int((errs / total_collectors) * 35)
        if not self.is_admin:
            coverage = min(coverage, 65)

        self.audit_result.audit_coverage = max(0, coverage)
        self.audit_result.security_score = max(0, 100 - score_deductions)

    # --- Main Pipeline Execution --------------------------------------------
    
    def run_audit(self):
        print("\n==================================================")
        print(" WSAAF-NG SECURITY AUDIT INITIALIZING")
        print("==================================================")
        print(f"OS Version: {self.audit_result.os_version}")
        print(f"Admin Privileges: {'YES' if self.is_admin else 'NO (Limited Visibility)'}")
        print("--------------------------------------------------\n")

        # Stage 1-2: Parallel Collection
        self.logger.info("[+] Stage 1 & 2: Fast Collection & Normalization")
        collectors = {
            "Processes": self.collect_processes,
            "Network": self.collect_network,
            "Persistence": self.collect_persistence,
            "DLLs": self.collect_dlls,
            "Drivers": self.collect_drivers,
            "Events": self.collect_events
        }

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(collectors)) as executor:
            futures = {executor.submit(func): name for name, func in collectors.items()}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    res = future.result()
                    self.audit_result.collectors[name] = res
                    self.logger.info(f"    {name:.<15} {res.status} ({res.duration:.2f}s) - {len(res.items)} items, {res.errors} errors")
                except Exception as e:
                    self.logger.error(f"    {name:.<15} FAILED - {e}")
                    self.audit_result.collectors[name] = CollectorResult(name, "ERROR", errors=1)

        # Stage 3-4: Cross-Artifact Correlation & Suspicion Prioritization
        start_stage4 = time.time()
        candidates = self.prioritize_artifacts()
        self.logger.info(f"\n[+] Stage 3 & 4: Correlation & Prioritization ({(time.time() - start_stage4):.2f}s)")
        self.logger.info(f"    Deep-analysis candidates identified: {len(candidates)}")

        # Stage 5: Deep Analysis
        start_stage5 = time.time()
        self.logger.info(f"\n[+] Stage 5: Deep Analysis")
        self.perform_deep_analysis(candidates)
        self.logger.info(f"    Completed in {(time.time() - start_stage5):.2f}s")

        # Stage 6 & 7: Detection & Recommendations
        self.logger.info(f"\n[+] Stage 6 & 7: Detection & Risk Scoring")
        self.evaluate_rules()
        self.logger.info(f"    Findings generated: {len(self.audit_result.findings)}")

        # Output Summary
        self._print_summary()

    def _print_summary(self):
        c = self.audit_result.collectors
        fnds = self.audit_result.findings
        
        status_text = "PASS"
        if self.audit_result.security_score < 70: status_text = "ATTENTION REQUIRED"
        if self.audit_result.security_score < 40: status_text = "CRITICAL RISK"
        if not self.is_admin: status_text += " (LIMITED VISIBILITY)"

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in fnds:
            if f.severity in sev_counts: sev_counts[f.severity] += 1

        print("\n==================================================")
        print(" WSAAF-NG SECURITY AUDIT SUMMARY")
        print("==================================================")
        print(f"Overall Status: {status_text}")
        print(f"Security Score: {self.audit_result.security_score}/100")
        print(f"Audit Coverage: {self.audit_result.audit_coverage}%")
        print("\nArtifacts Collected:")
        print(f"  Processes:           {len(c.get('Processes', CollectorResult()).items)}")
        print(f"  Network Connections: {len(c.get('Network', CollectorResult()).items)}")
        print(f"  Persistence Items:   {len(c.get('Persistence', CollectorResult()).items)}")
        print(f"  Unique Loaded DLLs:  {len(c.get('DLLs', CollectorResult()).items)}")
        print(f"  Installed Drivers:   {len(c.get('Drivers', CollectorResult()).items)}")
        print(f"  Event Records:       {len(c.get('Events', CollectorResult()).items)}")
        
        print(f"\nDeep Analysis:")
        print(f"  Analyzed Files:      {len(self.audit_result.deep_analysis)}")
        
        print("\nFindings:")
        for k, v in sev_counts.items():
            print(f"  {k}:{' '*(9-len(k))} {v}")
        
        if fnds:
            print("\nTop Findings:")
            for f in sorted(fnds, key=lambda x: x.risk_score, reverse=True)[:5]:
                print(f"  - [{f.severity}] {f.title} (Score: {f.risk_score})")
                print(f"    Entity: {f.entity}")
        print("==================================================\n")

    # --- Stage 8: Reporting -------------------------------------------------

    def generate_json_report(self, filepath: str = "wsaaf_report.json"):
        def custom_encoder(obj):
            if hasattr(obj, '__dataclass_fields__'):
                return asdict(obj)
            raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
        
        try:
            with open(filepath, "w") as f:
                json.dump(self.audit_result, f, default=custom_encoder, indent=4)
            self.logger.info(f"[+] JSON report saved to {filepath}")
        except Exception as e:
            self.logger.error(f"[!] Failed to save JSON report: {e}")

    def generate_html_report(self, filepath: str = "wsaaf_report.html"):
        score = self.audit_result.security_score
        color = "#28a745" if score >= 80 else "#ffc107" if score >= 50 else "#dc3545"
        
        findings_html = ""
        for f in sorted(self.audit_result.findings, key=lambda x: x.risk_score, reverse=True):
            f_color = "#dc3545" if f.severity in ["HIGH", "CRITICAL"] else "#ffc107" if f.severity == "MEDIUM" else "#17a2b8"
            findings_html += f"""
            <div class="finding-card" style="border-left: 5px solid {f_color};">
                <h4>[{f.severity}] {f.title} (Score: {f.risk_score})</h4>
                <p><strong>Entity:</strong> {f.entity}</p>
                <p><strong>Evidence:</strong> {f.evidence}</p>
                <p><strong>Reasons:</strong> {', '.join(f.reasons)}</p>
                <p><strong>Recommendation:</strong> {f.recommendation}</p>
            </div>
            """
        if not findings_html:
            findings_html = "<p>No notable findings detected.</p>"

        analysis_html = "<table><tr><th>Path</th><th>Signature</th><th>Score</th><th>Reasons</th></tr>"
        for path, data in self.audit_result.deep_analysis.items():
            analysis_html += f"<tr><td>{path}</td><td>{data.signature_status}</td><td>{data.priority_score}</td><td>{', '.join(data.reasons)}</td></tr>"
        analysis_html += "</table>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSAAF-NG Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .header-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .stat-card {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); text-align: center; border: 1px solid #ddd; }}
        .score {{ font-size: 3em; font-weight: bold; color: {color}; }}
        .finding-card {{ background: #fdfdfd; padding: 15px; margin-bottom: 15px; border-radius: 4px; border: 1px solid #ddd; }}
        .finding-card h4 {{ margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 0.9em; word-break: break-all; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background-color: #f8f9fa; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>WSAAF-NG Security Audit Report</h1>
        <p>Generated: {self.audit_result.timestamp} | OS: {self.audit_result.os_version} | Admin: {self.audit_result.is_admin}</p>
        
        <div class="header-grid">
            <div class="stat-card">
                <h3>Security Score</h3>
                <div class="score">{self.audit_result.security_score}/100</div>
            </div>
            <div class="stat-card">
                <h3>Audit Coverage</h3>
                <div class="score" style="color:#007bff;">{self.audit_result.audit_coverage}%</div>
            </div>
            <div class="stat-card">
                <h3>Findings</h3>
                <div class="score" style="color:#6c757d;">{len(self.audit_result.findings)}</div>
            </div>
        </div>

        <h2>Security Findings</h2>
        {findings_html}

        <h2>Deep Analysis Targets</h2>
        {analysis_html}
    </div>
</body>
</html>
"""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html)
            self.logger.info(f"[+] HTML report saved to {filepath}")
        except Exception as e:
            self.logger.error(f"[!] Failed to save HTML report: {e}")

# ============================================================================
# CLI Entry Point
# ============================================================================
def main():
    parser = argparse.ArgumentParser(description="WSAAF-NG - Windows Security Self-Audit Framework")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose/debug logging")
    parser.add_argument("--json", action="store_true", help="Generate JSON report")
    parser.add_argument("--html", action="store_true", default=True, help="Generate HTML report (default)")
    parser.add_argument("--output-dir", type=str, default=".", help="Directory to save reports")
    
    args = parser.parse_args()

    app = WSAAF(debug=args.verbose)
    
    start_total = time.time()
    app.run_audit()
    app.logger.info(f"\n[+] Audit completed in {(time.time() - start_total):.2f} seconds.")

    json_path = os.path.join(args.output_dir, "wsaaf_report.json")
    html_path = os.path.join(args.output_dir, "wsaaf_report.html")

    if args.json:
        app.generate_json_report(json_path)
    if args.html:
        app.generate_html_report(html_path)

if __name__ == "__main__":
    main()
