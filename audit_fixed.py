"""
WSAAF-NG — Windows Security Self-Audit Framework
Defensive Windows security auditing tool inspired by Microsoft Sysinternals.

Design goals:
- Fast collection with graceful degradation when not running as Administrator.
- Separate artifact prioritization from actual risk scoring.
- Context-aware detection to reduce false positives from legitimate software.
- Conservative scoring: generic strings/network activity do not create HIGH findings.
- Evidence quality/confidence is explicit.
- Failed measurements are represented as UNAVAILABLE, never as valid zero values.
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
import html
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime


# ============================================================================
# Environment / dependencies
# ============================================================================

def validate_environment():
    if sys.platform != "win32":
        print("[!] FATAL: WSAAF-NG requires Windows.")
        sys.exit(1)

    try:
        import psutil  # noqa: F401
    except ImportError:
        print("[!] FATAL: Required dependency 'psutil' is not installed.")
        print("    Run: pip install psutil")
        sys.exit(1)


validate_environment()

import psutil
import ctypes


# ============================================================================
# Data models
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
    process_exe: str = ""


@dataclass
class PersistenceItem:
    source: str
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
    entropy_status: str
    signature_status: str
    signer: Optional[str]
    strings_iocs: List[str] = field(default_factory=list)
    strings_categories: Dict[str, List[str]] = field(default_factory=dict)
    priority_reasons: List[str] = field(default_factory=list)
    priority_score: int = 0
    trust_score: int = 0
    risk_score: int = 0
    confidence: str = "LOW"
    risk_reasons: List[str] = field(default_factory=list)


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    title: str
    severity: str
    risk_score: int
    entity: str
    evidence: str
    reasons: List[str]
    recommendation: str
    confidence: str = "MEDIUM"


@dataclass
class CollectorResult:
    name: str = ""
    status: str = "NOT_AVAILABLE"
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
    score_explanation: str = ""


# ============================================================================
# Constants / context
# ============================================================================

SEVERITY_WEIGHT = {
    "CRITICAL": 25,
    "HIGH": 12,
    "MEDIUM": 5,
    "LOW": 1,
    "INFO": 0,
}

SYSTEM_ROOTS = (
    os.environ.get("WINDIR", r"C:\Windows").lower(),
    os.environ.get("PROGRAMFILES", r"C:\Program Files").lower(),
    os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)").lower(),
)

KNOWN_GOOD_PATH_MARKERS = (
    r"\program files",
    r"\program files (x86)",
    r"\windows\system32",
    r"\windows\syswow64",
    r"\windows\winsxs",
)

USER_APP_PATH_MARKERS = (
    r"\appdata\local\programs",
    r"\appdata\local",
    r"\appdata\roaming",
    r"\programdata",
)

TEMP_MARKERS = (
    r"\appdata\local\temp",
    r"\windows\temp",
    r"\temp",
)

BENIGN_GENERIC_STRINGS = {
    "http://",
    "https://",
    "appdata",
    "temp",
}

SUSPICIOUS_TOOL_STRINGS = {
    "powershell": "LOLBIN",
    "cmd.exe": "LOLBIN",
    "wscript": "LOLBIN",
    "cscript": "LOLBIN",
    "rundll32": "LOLBIN",
    "regsvr32": "LOLBIN",
    "mshta": "LOLBIN",
    "certutil": "LOLBIN",
    "bitsadmin": "LOLBIN",
}

KNOWN_VENDOR_MARKERS = {
    "google",
    "microsoft",
    "signal messenger",
    "riot games",
    "openvpn",
    "realtek",
    "bluestacks",
    "discord",
    "python software foundation",
    "xmind",
}


# ============================================================================
# Utilities
# ============================================================================

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def normalize_path(path: str) -> str:
    if not path:
        return ""
    path = os.path.expandvars(str(path)).strip().strip('"\'')
    try:
        return os.path.normpath(path).lower()
    except Exception:
        return path.lower()


def safe_int(value, default=None):
    try:
        if value in (None, ""):
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def get_file_metadata(path: str) -> dict:
    try:
        stat = os.stat(path)
        return {
            "size": stat.st_size,
            "ctime": stat.st_ctime,
            "mtime": stat.st_mtime,
        }
    except Exception:
        return {"size": 0, "ctime": None, "mtime": None}


def extract_target_executable(command: str) -> str:
    """Best-effort extraction of an executable/script target from a persistence command."""
    if not command:
        return ""

    value = os.path.expandvars(str(command)).strip()

    # Quoted executable: "C:\Program Files\App\app.exe" args
    m = re.match(r'^\s*"([^"]+)"', value)
    if m:
        candidate = m.group(1)
        if os.path.splitext(candidate)[1].lower() in {
            ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsh", ".scr"
        }:
            return candidate

    # Unquoted executable/path.
    tokens = value.split()
    if tokens:
        first = tokens[0].strip('"\'')
        if first.lower().endswith((
            ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsh", ".scr"
        )):
            return first

    # Search the whole command for an absolute executable.
    m = re.search(
        r'([A-Za-z]:\\[^"\r\n]+?\.(?:exe|com|bat|cmd|ps1|vbs|js|wsh|scr))',
        value,
        re.IGNORECASE,
    )
    if m:
        return m.group(1).rstrip(" .")

    return value.strip('"\'').split(" -", 1)[0].split(" /", 1)[0].strip()


def calculate_sha256_and_entropy(
    path: str,
    entropy_sample_size: int = 10 * 1024 * 1024,
    full_hash_limit: int = 512 * 1024 * 1024,
) -> Tuple[Optional[str], Optional[float], str]:
    """
    Calculate SHA-256 and Shannon entropy.

    Important:
    - Entropy is calculated from an actual bounded sample.
    - A failed/unreadable calculation returns None + UNAVAILABLE.
    - We never represent "calculation failed" as entropy 0.0.
    """
    try:
        size = os.path.getsize(path)
        if size == 0:
            return hashlib.sha256(b"").hexdigest(), 0.0, "VALID_EMPTY"

        sha256_hash = hashlib.sha256()
        counts = [0] * 256
        sampled = 0

        with open(path, "rb") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break

                if size <= full_hash_limit:
                    sha256_hash.update(chunk)

                if sampled < entropy_sample_size:
                    take = min(len(chunk), entropy_sample_size - sampled)
                    sample = chunk[:take]
                    for byte in sample:
                        counts[byte] += 1
                    sampled += len(sample)

                # Avoid unnecessary reads for huge files once both tasks are done.
                if size > full_hash_limit and sampled >= entropy_sample_size:
                    break

        if size <= full_hash_limit:
            sha256 = sha256_hash.hexdigest()
        else:
            # Explicitly label this as a sampled hash rather than pretending it is full SHA-256.
            sample_hash = hashlib.sha256()
            with open(path, "rb") as f:
                remaining = entropy_sample_size
                while remaining > 0:
                    chunk = f.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    sample_hash.update(chunk)
                    remaining -= len(chunk)
            sha256 = f"SAMPLED:{sample_hash.hexdigest()}"

        if sampled == 0:
            return sha256, None, "UNAVAILABLE"

        entropy = 0.0
        for count in counts:
            if count:
                p = count / sampled
                entropy -= p * math.log2(p)

        return sha256, entropy, "VALID"

    except Exception:
        return None, None, "UNAVAILABLE"


def verify_signature_powershell(path: str) -> Tuple[str, Optional[str]]:
    """
    Verify Authenticode status.

    Uses a single PowerShell invocation and passes the path as an encoded argument
    to avoid quoting issues with paths containing apostrophes.
    """
    try:
        ps_script = r"""
param([string]$Target)
try {
    $s = Get-AuthenticodeSignature -FilePath $Target -ErrorAction Stop
    $subject = if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { "" }
    Write-Output ($s.Status.ToString() + "|" + $subject)
} catch {
    Write-Output "ERROR|"
}
"""
        encoded = ps_script.encode("utf-16le")
        import base64
        encoded_command = base64.b64encode(encoded).decode("ascii")

        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encoded_command,
                path,
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )

        out = result.stdout.strip()
        if "|" not in out:
            return "UNAVAILABLE", None

        status, signer = out.split("|", 1)
        status = status.strip()
        signer = signer.strip() or None

        if status == "Valid":
            return "VALID", signer
        if status == "HashMismatch":
            return "INVALID", signer
        if status == "NotSigned":
            return "UNSIGNED", None
        if status == "NotTrusted":
            return "NOT_TRUSTED", signer

        return "UNKNOWN", signer

    except Exception:
        return "UNAVAILABLE", None


def extract_strings_and_iocs(path: str) -> Tuple[List[str], Dict[str, List[str]]]:
    """
    Extract only meaningful indicators.

    Generic strings such as http://, https://, Temp and AppData are retained as
    metadata but are NOT treated as suspicious IOCs by themselves.
    """
    found = set()
    categories = {
        "LOLBIN": [],
        "NETWORK": [],
        "GENERIC": [],
    }

    try:
        size = os.path.getsize(path)

        # Keep this bounded. Deep analysis should never become a full-file strings scan.
        sample_limit = 25 * 1024 * 1024
        with open(path, "rb") as f:
            data = f.read(sample_limit)

        for raw, category in SUSPICIOUS_TOOL_STRINGS.items():
            if re.search(re.escape(raw.encode()), data, re.IGNORECASE):
                found.add(raw)
                categories[category].append(raw)

        if re.search(rb"https?://", data, re.IGNORECASE):
            categories["NETWORK"].append("URL")
        if re.search(rb"\b(?:cmd|powershell)\.exe\b", data, re.IGNORECASE):
            categories["LOLBIN"].append("shell")

        # Generic context markers are recorded but not elevated.
        for marker in ("http://", "https://", "AppData", "Temp"):
            if marker.encode().lower() in data.lower():
                categories["GENERIC"].append(marker)

        # A very large binary is not suspicious merely because it contains strings.
        _ = size

    except Exception:
        pass

    # De-duplicate while preserving order.
    for key in categories:
        categories[key] = list(dict.fromkeys(categories[key]))

    meaningful = []
    for key in ("LOLBIN", "NETWORK"):
        meaningful.extend(categories[key])

    return list(dict.fromkeys(meaningful)), categories


def is_known_good_path(path: str) -> bool:
    p = normalize_path(path)
    if not p:
        return False

    return any(marker in p for marker in KNOWN_GOOD_PATH_MARKERS)


def is_user_app_path(path: str) -> bool:
    p = normalize_path(path)
    return any(marker in p for marker in USER_APP_PATH_MARKERS)


def is_temp_path(path: str) -> bool:
    p = normalize_path(path)
    return any(marker in p for marker in TEMP_MARKERS)


def signer_looks_known(signer: Optional[str]) -> bool:
    if not signer:
        return False
    s = signer.lower()
    return any(marker in s for marker in KNOWN_VENDOR_MARKERS)


def is_executable_or_script(path: str) -> bool:
    return normalize_path(path).endswith((
        ".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsh", ".scr", ".dll"
    ))


# ============================================================================
# Core framework
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
            is_admin=self.is_admin,
        )

        self.cache = {}

    def _setup_logger(self):
        logger = logging.getLogger("WSAAF")
        logger.setLevel(logging.DEBUG if self.debug else logging.INFO)

        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
            logger.addHandler(handler)

        return logger

    # ----------------------------------------------------------------------
    # Stage 1: collection
    # ----------------------------------------------------------------------

    def collect_processes(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0

        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time"]
        ):
            try:
                info = proc.info
                mem = None
                cpu = None

                try:
                    mem = proc.memory_info().rss
                    cpu = proc.cpu_percent(interval=None)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

                items.append(
                    ProcessRecord(
                        pid=info["pid"],
                        ppid=info["ppid"],
                        name=info["name"] or "UNKNOWN",
                        exe=info["exe"] or "",
                        cmdline=info["cmdline"] or [],
                        username=info["username"] or "",
                        create_time=info.get("create_time"),
                        memory_rss=mem,
                        cpu_percent=cpu,
                    )
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                errors += 1
            except Exception as e:
                errors += 1
                self.logger.debug(f"Process collector error on PID {getattr(proc, 'pid', '?')}: {e}")

        status = "LIMITED" if not self.is_admin and errors > 50 else "SUCCESS"
        return CollectorResult("Processes", status, time.time() - start_time, items, errors)

    def collect_network(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0

        try:
            proc_map = {}
            for p in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    proc_map[p.info["pid"]] = (
                        p.info.get("name") or "UNKNOWN",
                        p.info.get("exe") or "",
                    )
                except Exception:
                    pass

            # net_connections is the current psutil API.
            for conn in psutil.net_connections(kind="inet"):
                try:
                    local_ip = conn.laddr.ip if conn.laddr else ""
                    local_port = safe_int(conn.laddr.port if conn.laddr else None)
                    remote_ip = conn.raddr.ip if conn.raddr else ""
                    remote_port = safe_int(conn.raddr.port if conn.raddr else None)

                    process_name, process_exe = proc_map.get(
                        conn.pid, ("UNKNOWN", "")
                    )

                    protocol = "TCP" if conn.type == getattr(psutil, "SOCK_STREAM", 1) else "UDP"

                    items.append(
                        NetworkConnection(
                            pid=conn.pid if conn.pid is not None else -1,
                            protocol=protocol,
                            local_address=local_ip,
                            local_port=local_port,
                            remote_address=remote_ip,
                            remote_port=remote_port,
                            status=conn.status or "",
                            process_name=process_name,
                            process_exe=process_exe,
                        )
                    )
                except Exception as e:
                    errors += 1
                    self.logger.debug(f"Network connection parse error: {e}")

        except psutil.AccessDenied:
            self.logger.warning(
                "Network collection requires Administrator privileges for full process visibility."
            )
            return CollectorResult("Network", "LIMITED", time.time() - start_time, items, errors + 1)
        except Exception as e:
            self.logger.error(f"Network collection failed: {e}")
            return CollectorResult("Network", "ERROR", time.time() - start_time, [], errors + 1)

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
                            source = f"{h_name} {subkey.split(chr(92))[-1]}"
                            items.append(
                                PersistenceItem(
                                    source=source,
                                    name=name,
                                    target_path=str(value),
                                    enabled=True,
                                )
                            )
                        except OSError:
                            break
            except FileNotFoundError:
                pass
            except PermissionError:
                errors += 1
            except Exception:
                errors += 1

        try:
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    items.append(
                        PersistenceItem(
                            source="Service",
                            name=info.get("name", "Unknown"),
                            target_path=info.get("binpath", "") or "",
                            enabled=info.get("start_type") != "disabled",
                            extra_info=info.get("display_name", "") or "",
                        )
                    )
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    errors += 1
                except Exception:
                    errors += 1
        except Exception:
            errors += 1

        try:
            startup_path = os.path.expandvars(
                r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
            )
            if os.path.exists(startup_path):
                for file_name in os.listdir(startup_path):
                    full = os.path.join(startup_path, file_name)
                    items.append(
                        PersistenceItem(
                            source="Startup Folder",
                            name=file_name,
                            target_path=full,
                            enabled=True,
                        )
                    )
        except Exception:
            errors += 1

        status = "LIMITED" if errors > 10 else "SUCCESS"
        return CollectorResult("Persistence", status, time.time() - start_time, items, errors)

    def collect_dlls(self) -> CollectorResult:
        start_time = time.time()
        dll_map: Dict[str, DLLRecord] = {}
        errors = 0

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                for mapping in proc.memory_maps():
                    path = mapping.path
                    if not path:
                        continue

                    lower = normalize_path(path)
                    if lower not in dll_map:
                        dll_map[lower] = DLLRecord(path=path)

                    dll_map[lower].loaded_by_pids.append(proc.info["pid"])
                    dll_map[lower].loaded_by_names.append(proc.info.get("name") or "UNKNOWN")

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                errors += 1
            except Exception:
                errors += 1

        for record in dll_map.values():
            record.loaded_by_pids = sorted(set(record.loaded_by_pids))
            record.loaded_by_names = sorted(set(record.loaded_by_names))

        status = "LIMITED" if not self.is_admin else "SUCCESS"
        return CollectorResult("DLLs", status, time.time() - start_time, list(dll_map.values()), errors)

    def collect_drivers(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0

        try:
            result = subprocess.run(
                ["driverquery", "/v", "/fo", "csv"],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0:
                # Use csv module rather than splitting on commas.
                import csv
                from io import StringIO

                rows = csv.reader(StringIO(result.stdout))
                rows = list(rows)

                if rows:
                    header = [h.strip().lower() for h in rows[0]]

                    def find_index(*names):
                        for n in names:
                            if n in header:
                                return header.index(n)
                        return None

                    i_name = find_index("module name")
                    i_display = find_index("display name")
                    i_state = find_index("state")
                    i_start = find_index("start mode")
                    i_path = find_index("path")

                    for row in rows[1:]:
                        try:
                            def col(index):
                                return row[index] if index is not None and index < len(row) else ""

                            items.append(
                                DriverRecord(
                                    name=col(i_name),
                                    display_name=col(i_display),
                                    state=col(i_state),
                                    start_mode=col(i_start),
                                    path=col(i_path),
                                )
                            )
                        except Exception:
                            errors += 1
            else:
                errors += 1

        except Exception:
            errors += 1

        status = "SUCCESS" if items else ("LIMITED" if not self.is_admin else "ERROR")
        return CollectorResult("Drivers", status, time.time() - start_time, items, errors)

    def collect_events(self) -> CollectorResult:
        start_time = time.time()
        items = []
        errors = 0

        if not self.is_admin:
            return CollectorResult("Events", "LIMITED", time.time() - start_time, [], 0)

        try:
            ps = (
                "Get-WinEvent -FilterHashtable "
                "@{LogName='System','Security'; Level=1,2,3} "
                "-MaxEvents 100 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message | "
                "ConvertTo-Json -Compress"
            )

            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True,
                text=True,
                timeout=20,
            )

            if result.stdout.strip():
                events = json.loads(result.stdout)
                if isinstance(events, dict):
                    events = [events]

                for e in events:
                    message = (e.get("Message") or "")[:500].replace("\r", " ").replace("\n", " ")
                    items.append(
                        EventRecord(
                            time=str(e.get("TimeCreated", "")),
                            event_id=safe_int(e.get("Id"), 0),
                            level=str(e.get("LevelDisplayName", "Unknown")),
                            source=str(e.get("ProviderName", "Unknown")),
                            message=message,
                        )
                    )

        except json.JSONDecodeError:
            errors += 1
        except Exception:
            errors += 1

        status = "SUCCESS" if errors == 0 else "LIMITED"
        return CollectorResult("Events", status, time.time() - start_time, items, errors)

    # ----------------------------------------------------------------------
    # Stage 3-4: prioritization
    # ----------------------------------------------------------------------

    def prioritize_artifacts(self) -> List[dict]:
        """
        Priority score answers:
            "Which files deserve expensive deep analysis?"

        It does NOT answer:
            "Is this file malicious?"
        """
        candidates = {}

        process_by_pid = {
            p.pid: p
            for p in self.audit_result.collectors.get(
                "Processes", CollectorResult()
            ).items
            if isinstance(p, ProcessRecord)
        }

        def add_candidate(path, score, reason):
            if not path or not isinstance(path, str):
                return

            path = path.strip('"\'')
            if not os.path.isfile(path):
                return

            lower = normalize_path(path)

            if lower not in candidates:
                candidates[lower] = {
                    "path": path,
                    "score": 0,
                    "reasons": set(),
                }

            candidates[lower]["score"] += score
            candidates[lower]["reasons"].add(reason)

        # Processes: suspicious location is only a prioritization signal.
        for p in self.audit_result.collectors.get(
            "Processes", CollectorResult()
        ).items:
            if not isinstance(p, ProcessRecord) or not p.exe:
                continue

            exe = normalize_path(p.exe)

            if is_temp_path(exe):
                add_candidate(p.exe, 30, "Temp executable")
            elif is_user_app_path(exe):
                add_candidate(p.exe, 8, "User-writable application path")

            if not is_known_good_path(exe) and not is_user_app_path(exe):
                add_candidate(p.exe, 8, "Non-standard executable path")

        # Persistence.
        for item in self.audit_result.collectors.get(
            "Persistence", CollectorResult()
        ).items:
            if not isinstance(item, PersistenceItem) or not item.enabled:
                continue

            target = extract_target_executable(item.target_path)
            if not target:
                continue

            if os.path.isfile(os.path.expandvars(target)):
                add_candidate(
                    target,
                    20,
                    f"Persistence target ({item.source})",
                )

                if is_temp_path(target):
                    add_candidate(target, 25, "Persistence target in Temp")
                elif is_user_app_path(target):
                    add_candidate(target, 8, "Persistence target in user-writable path")

        # Network: map by PID and executable path, not filename.
        for conn in self.audit_result.collectors.get(
            "Network", CollectorResult()
        ).items:
            if not isinstance(conn, NetworkConnection):
                continue

            proc = process_by_pid.get(conn.pid)
            if proc and proc.exe:
                add_candidate(proc.exe, 5, "Active network process")

        # Drivers.
        for driver in self.audit_result.collectors.get(
            "Drivers", CollectorResult()
        ).items:
            if not isinstance(driver, DriverRecord):
                continue

            path = driver.path
            if path and path.lower().endswith(".sys"):
                if not is_known_good_path(path):
                    add_candidate(path, 25, "Non-standard driver path")

        results = []
        for item in candidates.values():
            if item["score"] >= 15:
                results.append(
                    {
                        "path": item["path"],
                        "score": min(item["score"], 1000),
                        "reasons": sorted(item["reasons"]),
                    }
                )

        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:20]

    # ----------------------------------------------------------------------
    # Stage 5: deep analysis
    # ----------------------------------------------------------------------

    def perform_deep_analysis(self, candidates: List[dict]):
        self.logger.info(f"[*] Deep analysis selected {len(candidates)} candidates.")

        for cand in candidates:
            path = cand["path"]
            path_lower = normalize_path(path)
            meta = get_file_metadata(path)

            cache_key = f"{path_lower}_{meta['size']}_{meta['mtime']}"

            if cache_key in self.cache:
                analysis = self.cache[cache_key]
                analysis.priority_score = cand["score"]
                analysis.priority_reasons = list(cand["reasons"])
                self.audit_result.deep_analysis[path_lower] = analysis
                continue

            sha256, entropy, entropy_status = calculate_sha256_and_entropy(path)
            sig_status, signer = verify_signature_powershell(path)
            iocs, categories = extract_strings_and_iocs(path)

            analysis = FileAnalysis(
                path=path,
                size=meta["size"],
                creation_time=meta["ctime"],
                modification_time=meta["mtime"],
                sha256=sha256,
                entropy=entropy,
                entropy_status=entropy_status,
                signature_status=sig_status,
                signer=signer,
                strings_iocs=iocs,
                strings_categories=categories,
                priority_reasons=list(cand["reasons"]),
                priority_score=cand["score"],
            )

            self.cache[cache_key] = analysis
            self.audit_result.deep_analysis[path_lower] = analysis

    # ----------------------------------------------------------------------
    # Stage 6: contextual risk engine
    # ----------------------------------------------------------------------

    def _get_persistence_context(self, path: str):
        target = normalize_path(path)
        matches = []

        for item in self.audit_result.collectors.get(
            "Persistence", CollectorResult()
        ).items:
            if not isinstance(item, PersistenceItem) or not item.enabled:
                continue

            extracted = normalize_path(extract_target_executable(item.target_path))
            if extracted and extracted == target:
                matches.append(item)

        return matches

    def _get_network_context(self, path: str):
        target = normalize_path(path)
        matches = []

        for conn in self.audit_result.collectors.get(
            "Network", CollectorResult()
        ).items:
            if not isinstance(conn, NetworkConnection):
                continue

            if normalize_path(conn.process_exe) == target:
                matches.append(conn)

        return matches

    def _calculate_file_risk(self, analysis: FileAnalysis):
        path = normalize_path(analysis.path)
        reasons = []
        score = 0
        confidence_points = 0

        persistence = self._get_persistence_context(path)
        network = self._get_network_context(path)

        signed = analysis.signature_status == "VALID"
        unsigned = analysis.signature_status in {"UNSIGNED", "INVALID", "NOT_TRUSTED"}
        trusted_publisher = signer_looks_known(analysis.signer)
        known_good_location = is_known_good_path(path)
        user_writable = is_user_app_path(path)
        temp_path = is_temp_path(path)

        # Trust context.
        trust = 0
        if signed:
            trust += 30
            confidence_points += 2
        if trusted_publisher:
            trust += 25
            confidence_points += 2
        if known_good_location:
            trust += 20
            confidence_points += 1
        if user_writable:
            trust -= 5
        if temp_path:
            trust -= 15
        if unsigned:
            trust -= 25
            confidence_points += 1

        analysis.trust_score = max(0, min(100, trust))

        # ------------------------------------------------------------------
        # Persistence is meaningful, but not automatically malicious.
        # ------------------------------------------------------------------
        if persistence:
            for item in persistence:
                reasons.append(f"Persistence: {item.source}")

            # User startup locations are normal for many applications.
            if temp_path:
                score += 30
                reasons.append("Persistence points to a temporary/writable location")
            elif user_writable:
                score += 8
                reasons.append("Persistence points to a user-writable application location")
            else:
                score += 3

            if unsigned:
                score += 25
                reasons.append("Persistence target is unsigned or signature is not trusted")

            if analysis.signature_status == "INVALID":
                score += 25
                reasons.append("Authenticode signature is invalid")

            if not signed and temp_path:
                score += 20
                reasons.append("Unsigned executable persists from Temp")

        # ------------------------------------------------------------------
        # Network activity is contextual evidence only.
        # A browser + network is NOT suspicious.
        # ------------------------------------------------------------------
        if network:
            if temp_path:
                score += 20
                reasons.append("Temporary executable has network activity")
            elif unsigned and not known_good_location:
                score += 20
                reasons.append("Unsigned/non-trusted executable has network activity")
            elif not signed and user_writable:
                score += 10
                reasons.append("Unsigned user-writable executable has network activity")
            else:
                reasons.append("Network activity observed; no direct risk escalation")

        # ------------------------------------------------------------------
        # Suspicious LOLBin strings only matter when combined with context.
        # Generic URLs/AppData/Temp strings do not create a finding.
        # ------------------------------------------------------------------
        lolbins = analysis.strings_categories.get("LOLBIN", [])
        if lolbins:
            score += min(15, 5 * len(lolbins))
            reasons.append(f"Embedded administrative/LOLBIN references: {', '.join(lolbins[:4])}")

            if (unsigned or temp_path) and persistence:
                score += 20
                reasons.append("LOLBIN references combined with suspicious persistence")

        # ------------------------------------------------------------------
        # Entropy is informational unless the measurement is valid.
        # ------------------------------------------------------------------
        if analysis.entropy_status == "VALID" and analysis.entropy is not None:
            if analysis.entropy >= 7.5 and (unsigned or temp_path):
                score += 10
                reasons.append("High file entropy combined with weak trust context")

        # Valid signature + known vendor + expected path strongly suppresses
        # generic false positives.
        if signed and trusted_publisher and known_good_location:
            score = min(score, 20)
            reasons.append("Valid signature, recognized publisher, and expected system/vendor path")

        # Known vendor but user-local installation: still not automatically risky.
        if signed and trusted_publisher and user_writable and not temp_path:
            score = min(score, 25)
            reasons.append("Valid trusted signature offsets generic user-writable-path suspicion")

        analysis.risk_score = max(0, min(100, score))

        if confidence_points >= 5:
            confidence = "HIGH"
        elif confidence_points >= 3:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        analysis.confidence = confidence
        analysis.risk_reasons = list(dict.fromkeys(reasons))

    def evaluate_rules(self):
        findings = []

        for path, analysis in self.audit_result.deep_analysis.items():
            self._calculate_file_risk(analysis)

            persistence = self._get_persistence_context(path)
            network = self._get_network_context(path)
            unsigned = analysis.signature_status in {
                "UNSIGNED", "INVALID", "NOT_TRUSTED"
            }
            temp_path = is_temp_path(path)
            user_writable = is_user_app_path(path)
            known_vendor = signer_looks_known(analysis.signer)
            signed = analysis.signature_status == "VALID"
            reasons = analysis.risk_reasons

            # R-001: suspicious persistence only when context supports it.
            if persistence and analysis.risk_score >= 50:
                severity = "CRITICAL" if analysis.risk_score >= 85 else "HIGH"
                findings.append(
                    Finding(
                        finding_id=f"FND-{len(findings)+1:03d}",
                        rule_id="R-001",
                        title="High-Risk Persistence Mechanism",
                        severity=severity,
                        risk_score=analysis.risk_score,
                        entity=analysis.path,
                        evidence=self._build_evidence(analysis, persistence, network),
                        reasons=reasons,
                        recommendation=(
                            "Validate the persistence entry, publisher, file hash, and intended "
                            "startup behavior. Remove it only if unauthorized."
                        ),
                        confidence=analysis.confidence,
                    )
                )

            # R-003: unsigned persistence.
            if persistence and unsigned and (temp_path or not known_vendor):
                score = max(55, analysis.risk_score)
                findings.append(
                    Finding(
                        finding_id=f"FND-{len(findings)+1:03d}",
                        rule_id="R-003",
                        title="Untrusted Persistence Target",
                        severity="HIGH" if score >= 70 else "MEDIUM",
                        risk_score=min(100, score),
                        entity=analysis.path,
                        evidence=self._build_evidence(analysis, persistence, network),
                        reasons=[
                            "Persistence target has weak signature trust",
                            *reasons,
                        ],
                        recommendation=(
                            "Verify the publisher and SHA-256 hash. Confirm whether the "
                            "startup entry is expected before taking remediation action."
                        ),
                        confidence=analysis.confidence,
                    )
                )

            # R-002: network activity only becomes a finding with strong context.
            if network and analysis.risk_score >= 50 and (unsigned or temp_path):
                findings.append(
                    Finding(
                        finding_id=f"FND-{len(findings)+1:03d}",
                        rule_id="R-002",
                        title="Untrusted Process with Network Activity",
                        severity="HIGH" if analysis.risk_score >= 70 else "MEDIUM",
                        risk_score=analysis.risk_score,
                        entity=analysis.path,
                        evidence=self._build_evidence(analysis, persistence, network),
                        reasons=reasons,
                        recommendation=(
                            "Review the remote endpoints, process command line, signature, "
                            "parent process, and file hash. Network activity alone is not evidence of compromise."
                        ),
                        confidence=analysis.confidence,
                    )
                )

            # R-004: meaningful LOLBin evidence.
            lolbins = analysis.strings_categories.get("LOLBIN", [])
            if lolbins and (unsigned or temp_path) and analysis.risk_score >= 40:
                findings.append(
                    Finding(
                        finding_id=f"FND-{len(findings)+1:03d}",
                        rule_id="R-004",
                        title="Suspicious Administrative Tool References",
                        severity="MEDIUM",
                        risk_score=max(40, analysis.risk_score),
                        entity=analysis.path,
                        evidence=f"LOLBIN references: {', '.join(lolbins)}",
                        reasons=reasons,
                        recommendation=(
                            "Inspect command-line behavior and determine whether the referenced "
                            "administrative tools are part of legitimate software functionality."
                        ),
                        confidence=analysis.confidence,
                    )
                )

            # R-005: driver risk.
            if (
                analysis.path.lower().endswith(".sys")
                and unsigned
                and not known_vendor
                and analysis.risk_score >= 40
            ):
                findings.append(
                    Finding(
                        finding_id=f"FND-{len(findings)+1:03d}",
                        rule_id="R-005",
                        title="Untrusted Driver",
                        severity="HIGH" if analysis.risk_score >= 70 else "MEDIUM",
                        risk_score=analysis.risk_score,
                        entity=analysis.path,
                        evidence=self._build_evidence(analysis, persistence, network),
                        reasons=reasons,
                        recommendation=(
                            "Verify the driver publisher, service configuration, file hash, "
                            "and installation source. Do not remove drivers blindly."
                        ),
                        confidence=analysis.confidence,
                    )
                )

        # Deduplicate findings by rule + entity.
        unique = {}
        for finding in findings:
            key = (finding.rule_id, normalize_path(finding.entity))
            if key not in unique or finding.risk_score > unique[key].risk_score:
                unique[key] = finding

        self.audit_result.findings = sorted(
            unique.values(),
            key=lambda x: x.risk_score,
            reverse=True,
        )

        self._calculate_security_score()

    def _build_evidence(self, analysis, persistence, network) -> str:
        entropy_text = (
            f"{analysis.entropy:.2f}"
            if analysis.entropy_status == "VALID" and analysis.entropy is not None
            else analysis.entropy_status
        )

        parts = [
            f"Signature: {analysis.signature_status}",
            f"Signer: {analysis.signer or 'N/A'}",
            f"Size: {analysis.size} bytes",
            f"Entropy: {entropy_text}",
        ]

        if analysis.sha256:
            parts.append(f"SHA256: {analysis.sha256}")

        if persistence:
            parts.append(
                "Persistence: " + ", ".join(sorted({p.source for p in persistence}))
            )

        if network:
            remote = sorted({
                f"{n.remote_address}:{n.remote_port}"
                for n in network
                if n.remote_address
            })
            if remote:
                parts.append("Remote endpoints: " + ", ".join(remote[:8]))

        return " | ".join(parts)

    def _calculate_security_score(self):
        """
        Security score is a normalized system-level risk score.

        Important:
        - Finding.risk_score is NOT subtracted directly.
        - Findings are weighted by severity.
        - Duplicate evidence is deduplicated.
        - Coverage is reported separately and never makes a healthy host look healthy.
        """
        findings = self.audit_result.findings

        # Aggregate maximum risk per entity to prevent one file generating a huge penalty.
        entity_risk = {}
        for finding in findings:
            key = normalize_path(finding.entity)
            weighted = SEVERITY_WEIGHT.get(finding.severity, 0)

            # Confidence affects only the penalty, not the finding severity.
            confidence_factor = {
                "HIGH": 1.0,
                "MEDIUM": 0.75,
                "LOW": 0.5,
            }.get(finding.confidence, 0.5)

            penalty = weighted * confidence_factor * max(0.5, finding.risk_score / 100.0)
            entity_risk[key] = max(entity_risk.get(key, 0.0), penalty)

        raw_penalty = sum(entity_risk.values())
        score = round(max(0.0, 100.0 - min(100.0, raw_penalty)))

        # Coverage is separate. Do not arbitrarily set a healthy machine to 0.
        coverage = self._calculate_coverage()

        if coverage < 50:
            explanation = (
                "Risk score is based on observed evidence, but visibility is low. "
                "Run as Administrator for a more complete audit."
            )
        elif coverage < 80:
            explanation = (
                "Risk score is based on observed evidence with partial visibility. "
                "Some privileged telemetry was unavailable."
            )
        else:
            explanation = "Risk score is based on contextual findings and available telemetry."

        self.audit_result.security_score = score
        self.audit_result.audit_coverage = coverage
        self.audit_result.score_explanation = explanation

    def _calculate_coverage(self) -> int:
        collectors = self.audit_result.collectors
        if not collectors:
            return 0

        weights = {
            "Processes": 20,
            "Network": 15,
            "Persistence": 20,
            "DLLs": 15,
            "Drivers": 15,
            "Events": 15,
        }

        total = 0
        earned = 0

        for name, weight in weights.items():
            total += weight
            result = collectors.get(name)

            if not result:
                continue

            if result.status == "SUCCESS":
                earned += weight
            elif result.status == "LIMITED":
                earned += weight * 0.5
            elif result.status == "ERROR":
                earned += 0

        if total == 0:
            return 0

        return max(0, min(100, round((earned / total) * 100)))

    # ----------------------------------------------------------------------
    # Pipeline
    # ----------------------------------------------------------------------

    def run_audit(self):
        print("\n==================================================")
        print(" WSAAF-NG SECURITY AUDIT INITIALIZING")
        print("==================================================")
        print(f"OS Version: {self.audit_result.os_version}")
        print(f"Admin Privileges: {'YES' if self.is_admin else 'NO (Limited Visibility)'}")
        print("--------------------------------------------------\n")

        self.logger.info("[+] Stage 1 & 2: Fast Collection & Normalization")

        collectors = {
            "Processes": self.collect_processes,
            "Network": self.collect_network,
            "Persistence": self.collect_persistence,
            "DLLs": self.collect_dlls,
            "Drivers": self.collect_drivers,
            "Events": self.collect_events,
        }

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=len(collectors)
        ) as executor:
            futures = {
                executor.submit(func): name
                for name, func in collectors.items()
            }

            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    self.audit_result.collectors[name] = result
                    self.logger.info(
                        f"    {name:.<15} {result.status} "
                        f"({result.duration:.2f}s) - "
                        f"{len(result.items)} items, {result.errors} errors"
                    )
                except Exception as e:
                    self.logger.error(f"    {name:.<15} FAILED - {e}")
                    self.audit_result.collectors[name] = CollectorResult(
                        name=name,
                        status="ERROR",
                        errors=1,
                    )

        start = time.time()
        candidates = self.prioritize_artifacts()

        self.logger.info(
            f"\n[+] Stage 3 & 4: Correlation & Prioritization "
            f"({time.time() - start:.2f}s)"
        )
        self.logger.info(
            f"    Deep-analysis candidates identified: {len(candidates)}"
        )

        start = time.time()
        self.logger.info("\n[+] Stage 5: Deep Analysis")
        self.perform_deep_analysis(candidates)
        self.logger.info(
            f"    Completed in {time.time() - start:.2f}s"
        )

        self.logger.info("\n[+] Stage 6 & 7: Detection & Risk Scoring")
        self.evaluate_rules()
        self.logger.info(
            f"    Findings generated: {len(self.audit_result.findings)}"
        )

        self._print_summary()

    # ----------------------------------------------------------------------
    # Reporting
    # ----------------------------------------------------------------------

    def _print_summary(self):
        c = self.audit_result.collectors
        findings = self.audit_result.findings

        score = self.audit_result.security_score

        if score >= 90:
            status = "LOW RISK"
        elif score >= 75:
            status = "MODERATE RISK"
        elif score >= 50:
            status = "HIGH RISK"
        else:
            status = "CRITICAL RISK"

        if self.audit_result.audit_coverage < 70:
            status += " (LIMITED VISIBILITY)"

        sev_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for finding in findings:
            sev_counts[finding.severity] = sev_counts.get(finding.severity, 0) + 1

        print("\n==================================================")
        print(" WSAAF-NG SECURITY AUDIT SUMMARY")
        print("==================================================")
        print(f"Overall Status: {status}")
        print(f"Security Score: {score}/100")
        print(f"Audit Coverage: {self.audit_result.audit_coverage}%")
        print(f"Score Basis: {self.audit_result.score_explanation}")

        print("\nArtifacts Collected:")
        print(
            f"  Processes:           "
            f"{len(c.get('Processes', CollectorResult()).items)}"
        )
        print(
            f"  Network Connections: "
            f"{len(c.get('Network', CollectorResult()).items)}"
        )
        print(
            f"  Persistence Items:   "
            f"{len(c.get('Persistence', CollectorResult()).items)}"
        )
        print(
            f"  Unique Loaded DLLs:  "
            f"{len(c.get('DLLs', CollectorResult()).items)}"
        )
        print(
            f"  Installed Drivers:   "
            f"{len(c.get('Drivers', CollectorResult()).items)}"
        )
        print(
            f"  Event Records:       "
            f"{len(c.get('Events', CollectorResult()).items)}"
        )

        print("\nDeep Analysis:")
        print(
            f"  Analyzed Files:      "
            f"{len(self.audit_result.deep_analysis)}"
        )

        print("\nFindings:")
        for key, value in sev_counts.items():
            print(f"  {key}:{' ' * (9 - len(key))} {value}")

        if findings:
            print("\nTop Findings:")
            for finding in findings[:5]:
                print(
                    f"  - [{finding.severity}] {finding.title} "
                    f"(Risk: {finding.risk_score}/100, "
                    f"Confidence: {finding.confidence})"
                )
                print(f"    Entity: {finding.entity}")

        print("==================================================\n")

    def generate_json_report(self, filepath: str = "wsaaf_report.json"):
        def custom_encoder(obj):
            if hasattr(obj, "__dataclass_fields__"):
                return asdict(obj)
            raise TypeError(
                f"Object of type {type(obj)} is not JSON serializable"
            )

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(
                    self.audit_result,
                    f,
                    default=custom_encoder,
                    indent=4,
                    ensure_ascii=False,
                )
            self.logger.info(f"[+] JSON report saved to {filepath}")
        except Exception as e:
            self.logger.error(f"[!] Failed to save JSON report: {e}")

    def generate_html_report(self, filepath: str = "wsaaf_report.html"):
        score = self.audit_result.security_score

        if score >= 90:
            color = "#28a745"
        elif score >= 75:
            color = "#17a2b8"
        elif score >= 50:
            color = "#ffc107"
        else:
            color = "#dc3545"

        def esc(value):
            return html.escape(str(value), quote=True)

        findings_html = ""

        for finding in self.audit_result.findings:
            if finding.severity in ("HIGH", "CRITICAL"):
                f_color = "#dc3545"
            elif finding.severity == "MEDIUM":
                f_color = "#ffc107"
            else:
                f_color = "#17a2b8"

            findings_html += f"""
            <div class="finding-card" style="border-left: 5px solid {f_color};">
                <h4>[{esc(finding.severity)}] {esc(finding.title)}
                    — Risk {finding.risk_score}/100</h4>
                <p><strong>Entity:</strong> {esc(finding.entity)}</p>
                <p><strong>Confidence:</strong> {esc(finding.confidence)}</p>
                <p><strong>Evidence:</strong> {esc(finding.evidence)}</p>
                <p><strong>Reasons:</strong> {esc(", ".join(finding.reasons))}</p>
                <p><strong>Recommendation:</strong> {esc(finding.recommendation)}</p>
            </div>
            """

        if not findings_html:
            findings_html = "<p>No notable findings detected.</p>"

        analysis_html = """
        <table>
            <tr>
                <th>Path</th>
                <th>Signature</th>
                <th>Trust</th>
                <th>Priority</th>
                <th>Risk</th>
                <th>Confidence</th>
                <th>Reasons</th>
            </tr>
        """

        for path, data in sorted(
            self.audit_result.deep_analysis.items(),
            key=lambda x: x[1].risk_score,
            reverse=True,
        ):
            analysis_html += f"""
            <tr>
                <td>{esc(path)}</td>
                <td>{esc(data.signature_status)}</td>
                <td>{data.trust_score}</td>
                <td>{data.priority_score}</td>
                <td>{data.risk_score}</td>
                <td>{esc(data.confidence)}</td>
                <td>{esc(", ".join(data.risk_reasons))}</td>
            </tr>
            """

        analysis_html += "</table>"

        html_document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WSAAF-NG Security Audit Report</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background: #f4f6f8;
    margin: 0;
    padding: 30px;
    color: #222;
}}
.container {{
    max-width: 1400px;
    margin: auto;
}}
.header {{
    background: #1f2937;
    color: white;
    padding: 25px;
    border-radius: 12px;
}}
.header-grid {{
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 15px;
    margin-top: 20px;
}}
.stat-card {{
    background: white;
    padding: 20px;
    border-radius: 10px;
    text-align: center;
}}
.score {{
    font-size: 38px;
    font-weight: bold;
    color: {color};
}}
.finding-card {{
    background: white;
    margin: 14px 0;
    padding: 18px;
    border-radius: 8px;
    box-shadow: 0 1px 4px rgba(0,0,0,.08);
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
    font-size: 13px;
}}
th, td {{
    border: 1px solid #ddd;
    padding: 8px;
    text-align: left;
    vertical-align: top;
}}
th {{
    background: #e9ecef;
}}
.small {{
    color: #666;
}}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>WSAAF-NG Security Audit Report</h1>
    <p>Generated: {esc(self.audit_result.timestamp)}</p>
    <p>OS: {esc(self.audit_result.os_version)} |
       Architecture: {esc(self.audit_result.architecture)} |
       Administrator: {self.audit_result.is_admin}</p>
</div>

<div class="header-grid">
    <div class="stat-card">
        <h3>Security Score</h3>
        <div class="score">{score}/100</div>
    </div>
    <div class="stat-card">
        <h3>Audit Coverage</h3>
        <div class="score" style="color:#007bff;">
            {self.audit_result.audit_coverage}%
        </div>
    </div>
    <div class="stat-card">
        <h3>Findings</h3>
        <div class="score" style="color:#6c757d;">
            {len(self.audit_result.findings)}
        </div>
    </div>
</div>

<p class="small">{esc(self.audit_result.score_explanation)}</p>

<h2>Security Findings</h2>
{findings_html}

<h2>Deep Analysis</h2>
<p class="small">
Priority score selects files for analysis. Risk score estimates contextual security risk.
These values are intentionally separate.
</p>
{analysis_html}

</div>
</body>
</html>
"""

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(html_document)
            self.logger.info(f"[+] HTML report saved to {filepath}")
        except Exception as e:
            self.logger.error(f"[!] Failed to save HTML report: {e}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="WSAAF-NG - Windows Security Self-Audit Framework"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Generate JSON report",
    )
    parser.add_argument(
        "--html",
        action="store_true",
        default=True,
        help="Generate HTML report (default)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="Directory to save reports",
    )

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    app = WSAAF(debug=args.verbose)

    start_total = time.time()
    app.run_audit()

    app.logger.info(
        f"\n[+] Audit completed in {time.time() - start_total:.2f} seconds."
    )

    json_path = os.path.join(args.output_dir, "wsaaf_report.json")
    html_path = os.path.join(args.output_dir, "wsaaf_report.html")

    if args.json:
        app.generate_json_report(json_path)

    if args.html:
        app.generate_html_report(html_path)


if __name__ == "__main__":
    main()
