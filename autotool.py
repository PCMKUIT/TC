#!/usr/bin/env python3
"""
WSAAF-NG: Windows Security Self-Audit Framework (Next Generation)
================================================================
An evidence-first, defensive Windows security auditing framework.

Architecture:
  Python (Orchestration & Correlation Layer)
    ├── Sysinternals Integration (Sigcheck, Autoruns, TCPView)
    ├── Process Enumeration & Signature Verification Engine
    ├── Persistence & Network Collection Engine
    ├── Cross-Correlation & Evidence-Based Risk Engine
    └── Report Generation (JSON & Self-Contained HTML)

Design Principle:
  COLLECT → NORMALIZE → VERIFY → CORRELATE → CLASSIFY → REPORT

Author: Senior Security Tooling Engineer
Target OS: Windows 10 / 11 / Server 2016+
Python Version: 3.8+
"""

import os
import sys
import re
import csv
import io
import json
import math
import time
import ctypes
import logging
import subprocess
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set, Any
from pathlib import Path

# Third-party dependency check
try:
    import psutil
except ImportError:
    sys.exit("[FATAL] Required dependency 'psutil' is not installed. Install via: pip install psutil")

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("WSAAF-NG")

# Standard Configuration Constants
SYSINTERNALS_DIR = r"C:\tool"
SUBPROCESS_TIMEOUT = 120  # seconds per process call

# ============================================================================
# DATA MODELS & ENUMS
# ============================================================================

class CollectorStatus:
    SUCCESS = "SUCCESS"
    LIMITED = "LIMITED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    ERROR = "ERROR"

class SignatureStatus:
    VALID = "VALID"
    UNSIGNED = "UNSIGNED"
    INVALID = "INVALID"
    NOT_TRUSTED = "NOT_TRUSTED"
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"

class Severity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"

@dataclass
class ProcessRecord:
    pid: int
    ppid: int
    name: str
    path: str
    cmdline: str
    user: str
    create_time: str
    parent_name: str
    signature_status: str = SignatureStatus.UNKNOWN
    signer: str = "N/A"
    sha256: str = "N/A"
    entropy: float = 0.0
    is_temp_path: bool = False
    is_user_writable: bool = False
    risk_score: int = 0

@dataclass
class PersistenceRecord:
    location: str
    entry: str
    image_path: str
    launch_string: str
    category: str
    publisher: str
    signature_status: str = SignatureStatus.UNKNOWN
    user: str = "N/A"
    enabled: bool = True
    risk_score: int = 0

@dataclass
class NetworkRecord:
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    pid: int
    process_name: str
    signature_status: str = SignatureStatus.UNKNOWN

@dataclass
class Finding:
    finding_id: str
    rule_id: str
    severity: str
    risk_score: int
    entity: str
    evidence: List[str]
    reasons: List[str]
    recommendation: str

@dataclass
class SystemMetadata:
    audit_time: str
    hostname: str
    os_version: str
    is_admin: bool
    sysinternals_dir: str
    tools_available: Dict[str, str]

# ============================================================================
# SYSINTERNALS TOOL DISCOVERY & EXECUTION LAYER
# ============================================================================

class SysinternalsManager:
    """Manages discovery and safe execution of Sysinternals binaries from C:\\tool."""

    def __init__(self, base_dir: str = SYSINTERNALS_DIR):
        self.base_dir = Path(base_dir)
        self.discovered_tools: Dict[str, Optional[str]] = {}
        self._discover_tools()

    def _discover_tools(self):
        """Discovers 64-bit and 32-bit Sysinternals utilities."""
        tool_names = ["sigcheck", "autorunsc", "tcpvcon"]
        for tool in tool_names:
            resolved = self.find_tool(tool)
            self.discovered_tools[tool] = resolved
            if resolved:
                logger.info(f"Discovered Sysinternals tool '{tool}' -> {resolved}")
            else:
                logger.warning(f"Sysinternals tool '{tool}' NOT found in {self.base_dir}")

    def find_tool(self, name: str) -> Optional[str]:
        """Looks for name64.exe first, then name.exe under SYSINTERNALS_DIR."""
        if not self.base_dir.exists():
            return None

        candidates = [
            self.base_dir / f"{name}64.exe",
            self.base_dir / f"{name}.exe"
        ]

        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
        return None

    def execute(self, tool_key: str, args: List[str], timeout: int = SUBPROCESS_TIMEOUT) -> Tuple[bool, str, str]:
        """Safely executes a Sysinternals binary with explicit argument arrays."""
        tool_path = self.discovered_tools.get(tool_key)
        if not tool_path or not os.path.isfile(tool_path):
            return False, "", f"Tool '{tool_key}' not available in {self.base_dir}"

        cmd = [tool_path] + args
        try:
            # Accepts EULA automatically for command-line tools where supported
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=timeout,
                check=False
            )
            return True, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Execution of {tool_key} timed out after {timeout} seconds.")
            return False, "", "Execution timed out"
        except Exception as e:
            logger.error(f"Error executing {tool_key}: {e}")
            return False, "", str(e)

# ============================================================================
# HELPER FUNCTIONS (ENTROPY, PATHS, HASHES)
# ============================================================================

def is_admin() -> bool:
    """Checks if the script is running with elevated Administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def calculate_file_entropy(filepath: str) -> float:
    """Calculates Shannon Entropy of a binary file to detect packing/encryption."""
    if not os.path.isfile(filepath):
        return 0.0
    try:
        byte_counts = [0] * 256
        total_bytes = 0
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                total_bytes += len(chunk)
                for b in chunk:
                    byte_counts[b] += 1

        if total_bytes == 0:
            return 0.0

        entropy = 0.0
        for count in byte_counts:
            if count == 0:
                continue
            p = count / total_bytes
            entropy -= p * math.log2(p)
        return round(entropy, 3)
    except Exception:
        return 0.0

def is_suspicious_location(filepath: str) -> Tuple[bool, bool]:
    """
    Evaluates if a path resides in Temp or User-Writable directories.
    Returns: (is_temp, is_user_writable)
    """
    if not filepath or filepath == "N/A":
        return False, False

    path_lower = filepath.lower()
    temp_indicators = [r"\appdata\local\temp", r"\windows\temp", r"\temp\\"]
    writable_indicators = [r"\appdata\\", r"\users\public", r"\programdata\\"]

    is_temp = any(ind in path_lower for ind in temp_indicators)
    is_writable = is_temp or any(ind in path_lower for ind in writable_indicators)

    return is_temp, is_writable

# ============================================================================
# AUDIT COLLECTORS
# ============================================================================

class ProcessCollector:
    """Enumerates running processes using psutil."""

    @staticmethod
    def collect() -> Tuple[List[ProcessRecord], str]:
        records: List[ProcessRecord] = []
        status = CollectorStatus.SUCCESS

        for p in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = p.info
                pid = info['pid'] or 0
                ppid = info['ppid'] or 0
                name = info['name'] or "Unknown"
                exe = info['exe'] or ""
                cmdline = " ".join(info['cmdline']) if info['cmdline'] else ""
                user = info['username'] or "N/A"

                ctime = ""
                if info['create_time']:
                    ctime = datetime.fromtimestamp(info['create_time']).isoformat()

                # Get parent process name safely
                parent_name = "N/A"
                if ppid > 0:
                    try:
                        parent_proc = psutil.Process(ppid)
                        parent_name = parent_proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        parent_name = "Terminated/Inaccessible"

                is_temp, is_writable = is_suspicious_location(exe)

                record = ProcessRecord(
                    pid=pid,
                    ppid=ppid,
                    name=name,
                    path=exe if exe else "N/A",
                    cmdline=cmdline,
                    user=user,
                    create_time=ctime,
                    parent_name=parent_name,
                    is_temp_path=is_temp,
                    is_user_writable=is_writable
                )
                records.append(record)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                logger.debug(f"Error enumerating PID {p.pid}: {e}")
                status = CollectorStatus.LIMITED

        return records, status

class SignatureVerifier:
    """Performs batch signature verification using Sysinternals Sigcheck."""

    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def verify_paths(self, file_paths: List[str]) -> Dict[str, Dict[str, str]]:
        """
        Deduplicates file paths and verifies signatures using Sigcheck in batches.
        Returns: { path: { "status": ..., "signer": ..., "sha256": ... } }
        """
        results: Dict[str, Dict[str, str]] = {}
        unique_paths = list(set([p for p in file_paths if p and p != "N/A" and os.path.isfile(p)]))

        if not unique_paths:
            return results

        if not self.sys_mgr.discovered_tools.get("sigcheck"):
            logger.warning("Sigcheck is unavailable. Process signatures will mark as UNAVAILABLE.")
            for p in unique_paths:
                results[p] = {"status": SignatureStatus.UNAVAILABLE, "signer": "N/A", "sha256": "N/A"}
            return results

        # Process in batches of 50 to avoid command line length limits
        batch_size = 50
        for i in range(0, len(unique_paths), batch_size):
            batch = unique_paths[i:i + batch_size]
            # Sigcheck arguments: -c (CSV), -q (quiet), -h (hashes), -nobanner, -a (extended)
            args = ["-c", "-q", "-h", "-nobanner"] + batch
            success, stdout, stderr = self.sys_mgr.execute("sigcheck", args)

            if success and stdout.strip():
                try:
                    f = io.StringIO(stdout)
                    reader = csv.DictReader(f)
                    for row in reader:
                        # Extract and normalize path
                        path_key = row.get("Path") or row.get("path")
                        if not path_key:
                            continue

                        path_key_norm = os.path.normpath(path_key).lower()
                        verified = row.get("Verified", "").strip().lower()
                        publisher = row.get("Publisher", "").strip() or row.get("Company", "").strip() or "Unsigned/Unknown"
                        sha256 = row.get("SHA256", "").strip() or "N/A"

                        status = SignatureStatus.UNKNOWN
                        if "signed" in verified:
                            status = SignatureStatus.VALID
                        elif "unsigned" in verified:
                            status = SignatureStatus.UNSIGNED
                        elif "invalid" in verified:
                            status = SignatureStatus.INVALID
                        elif "not trusted" in verified:
                            status = SignatureStatus.NOT_TRUSTED

                        results[path_key_norm] = {
                            "status": status,
                            "signer": publisher,
                            "sha256": sha256
                        }
                except Exception as e:
                    logger.error(f"Error parsing Sigcheck output: {e}")

        # Map back results with normalized path matching
        final_mapping: Dict[str, Dict[str, str]] = {}
        for original_path in unique_paths:
            norm_p = os.path.normpath(original_path).lower()
            if norm_p in results:
                final_mapping[original_path] = results[norm_p]
            else:
                final_mapping[original_path] = {
                    "status": SignatureStatus.UNAVAILABLE,
                    "signer": "N/A",
                    "sha256": "N/A"
                }

        return final_mapping

class PersistenceCollector:
    """Enumerates Windows persistence using Sysinternals Autorunsc."""

    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def collect(self) -> Tuple[List[PersistenceRecord], str]:
        records: List[PersistenceRecord] = []
        if not self.sys_mgr.discovered_tools.get("autorunsc"):
            logger.warning("Autorunsc not available. Persistence collection skipped.")
            return records, CollectorStatus.NOT_AVAILABLE

        # Autorunsc flags: -a * (all entries), -c (CSV), -nobanner, -h (hashes)
        args = ["-a", "*", "-c", "-nobanner", "-h"]
        success, stdout, stderr = self.sys_mgr.execute("autorunsc", args, timeout=180)

        if not success or not stdout.strip():
            logger.error(f"Autorunsc failed or returned no data: {stderr}")
            return records, CollectorStatus.ERROR

        try:
            f = io.StringIO(stdout)
            reader = csv.DictReader(f)
            for row in reader:
                location = row.get("Entry Location", "Unknown")
                entry = row.get("Entry", "Unknown")
                image_path = row.get("ImagePath", "").strip()
                launch = row.get("Launch String", "").strip()
                publisher = row.get("Publisher", "Unknown").strip()
                category = row.get("Category", "General").strip()
                enabled_str = row.get("Enabled", "enabled").lower()

                # Extract signature status directly if reported by Autoruns
                sig_raw = row.get("Signer", "").lower()
                status = SignatureStatus.UNKNOWN
                if "(verified)" in sig_raw or "verified" in sig_raw:
                    status = SignatureStatus.VALID
                elif "(not verified)" in sig_raw or "unsigned" in sig_raw:
                    status = SignatureStatus.UNSIGNED

                record = PersistenceRecord(
                    location=location,
                    entry=entry,
                    image_path=image_path if image_path else "N/A",
                    launch_string=launch,
                    category=category,
                    publisher=publisher if publisher else "N/A",
                    signature_status=status,
                    enabled=("enabled" in enabled_str or "true" in enabled_str)
                )
                records.append(record)

            return records, CollectorStatus.SUCCESS
        except Exception as e:
            logger.error(f"Error parsing Autorunsc CSV output: {e}")
            return records, CollectorStatus.LIMITED

class NetworkCollector:
    """Enumerates network sockets using Sysinternals tcpvcon or psutil fallback."""

    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def collect(self) -> Tuple[List[NetworkRecord], str]:
        records: List[NetworkRecord] = []
        
        # Primary: TCPView Console (tcpvcon)
        if self.sys_mgr.discovered_tools.get("tcpvcon"):
            # Flags: -a (all), -n (numeric), -c (CSV), -nobanner
            success, stdout, stderr = self.sys_mgr.execute("tcpvcon", ["-a", "-n", "-c", "-nobanner"])
            if success and stdout.strip():
                try:
                    f = io.StringIO(stdout)
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) < 7:
                            continue
                        # Columns: Proto, Process, PID, State, Local, Remote
                        proto = row[0].strip()
                        proc_name = row[1].strip()
                        try:
                            pid = int(row[2].strip())
                        except ValueError:
                            continue
                        state = row[3].strip() if len(row) > 3 else "UNKNOWN"
                        local = row[4].strip() if len(row) > 4 else "0.0.0.0:0"
                        remote = row[5].strip() if len(row) > 5 else "0.0.0.0:0"

                        loc_addr, loc_port = self._split_addr_port(local)
                        rem_addr, rem_port = self._split_addr_port(remote)

                        records.append(NetworkRecord(
                            protocol=proto,
                            local_addr=loc_addr,
                            local_port=loc_port,
                            remote_addr=rem_addr,
                            remote_port=rem_port,
                            state=state,
                            pid=pid,
                            process_name=proc_name
                        ))
                    return records, CollectorStatus.SUCCESS
                except Exception as e:
                    logger.error(f"Error parsing tcpvcon output: {e}")

        # Secondary Fallback: psutil network connections
        logger.info("Falling back to psutil for network connection enumeration.")
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                pid = conn.pid or 0
                proc_name = "Unknown"
                if pid > 0:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except Exception:
                        pass

                loc_addr = conn.laddr.ip if conn.laddr else "0.0.0.0"
                loc_port = conn.laddr.port if conn.laddr else 0
                rem_addr = conn.raddr.ip if conn.raddr else "0.0.0.0"
                rem_port = conn.raddr.port if conn.raddr else 0

                records.append(NetworkRecord(
                    protocol="TCP" if conn.type == 1 else "UDP",
                    local_addr=loc_addr,
                    local_port=loc_port,
                    remote_addr=rem_addr,
                    remote_port=rem_port,
                    state=conn.status if conn.status else "ESTABLISHED",
                    pid=pid,
                    process_name=proc_name
                ))
            return records, CollectorStatus.LIMITED
        except Exception as e:
            logger.error(f"Failed to enumerate network connections via psutil: {e}")
            return records, CollectorStatus.ERROR

    @staticmethod
    def _split_addr_port(addr_str: str) -> Tuple[str, int]:
        if ":" in addr_str:
            parts = addr_str.rsplit(":", 1)
            try:
                return parts[0], int(parts[1])
            except ValueError:
                return parts[0], 0
        return addr_str, 0

# ============================================================================
# CORRELATION & RISK SCORING ENGINE
# ============================================================================

class AuditEngine:
    """Central correlation engine following the evidence-first paradigm."""

    def __init__(self, sys_mgr: SysinternalsManager):
        self.sys_mgr = sys_mgr

    def run_audit((self) -> Tuple[SystemMetadata, List[ProcessRecord], List[PersistenceRecord], List[NetworkRecord], List[Finding]]:
        logger.info("--- Phase 1: Collecting Operating System Metadata ---")
        meta = SystemMetadata(
            audit_time=datetime.now().isoformat(),
            hostname=os.getenv("COMPUTERNAME", "Unknown"),
            os_version=f"Windows {sys.getwindowsversion().major}.{sys.getwindowsversion().minor}",
            is_admin=is_admin(),
            sysinternals_dir=SYSINTERNALS_DIR,
            tools_available={k: (v if v else "NOT_AVAILABLE") for k, v in self.sys_mgr.discovered_tools.items()}
        )

        logger.info("--- Phase 2: Process Audit & Path Extraction ---")
        processes, proc_status = ProcessCollector.collect()

        logger.info("--- Phase 3: Batch Executable Signature Verification ---")
        verifier = SignatureVerifier(self.sys_mgr)
        unique_paths = [p.path for p in processes if p.path and p.path != "N/A"]
        sig_map = verifier.verify_paths(unique_paths)

        # Apply signature verification back to processes
        for p in processes:
            if p.path in sig_map:
                sig_data = sig_map[p.path]
                p.signature_status = sig_data["status"]
                p.signer = sig_data["signer"]
                p.sha256 = sig_data["sha256"]
                if os.path.isfile(p.path):
                    p.entropy = calculate_file_entropy(p.path)

        logger.info("--- Phase 4: Persistence Audit ---")
        persistence_collector = PersistenceCollector(self.sys_mgr)
        persistence, persist_status = persistence_collector.collect()

        # Fill missing signatures for persistence executables
        persist_paths = [p.image_path for p in persistence if p.image_path and p.image_path != "N/A"]
        persist_sig_map = verifier.verify_paths(persist_paths)
        for p in persistence:
            if p.image_path in persist_sig_map:
                p.signature_status = persist_sig_map[p.image_path]["status"]
                p.publisher = persist_sig_map[p.image_path]["signer"]

        logger.info("--- Phase 5: Network Audit ---")
        net_collector = NetworkCollector(self.sys_mgr)
        network, net_status = net_collector.collect()

        # Map process signature status to network sockets via PID
        pid_to_sig = {p.pid: p.signature_status for p in processes}
        for n in network:
            n.signature_status = pid_to_sig.get(n.pid, SignatureStatus.UNKNOWN)

        logger.info("--- Phase 6: Cross-Correlation & Evidence Scoring ---")
        findings = self._correlate_and_score(processes, persistence, network)

        return meta, processes, persistence, network, findings

    def _correlate_and_score(self,
                             processes: List[ProcessRecord],
                             persistence: List[PersistenceRecord],
                             network: List[NetworkRecord]) -> List[Finding]:
        findings: List[Finding] = []

        # Maps for quick cross-correlation lookup
        pids_with_network: Set[int] = {n.pid for n in network if n.remote_addr not in ("0.0.0.0", "127.0.0.1", "::1")}
        paths_in_persistence: Set[str] = {p.image_path.lower() for p in persistence if p.image_path and p.image_path != "N/A"}

        # 1. Evaluate Processes
        for p in processes:
            score = 0
            evidence = []
            reasons = []

            # Signature Signal
            if p.signature_status in (SignatureStatus.UNSIGNED, SignatureStatus.UNVERIFIED):
                score += 30
                evidence.append(f"Executable signature status: {p.signature_status}")
                reasons.append("Unsigned binary running in active process tree")
            elif p.signature_status in (SignatureStatus.INVALID, SignatureStatus.NOT_TRUSTED):
                score += 40
                evidence.append(f"Invalid/Untrusted signature: {p.signature_status}")
                reasons.append("Executable signature explicitly failed validation")
            elif p.signature_status == SignatureStatus.UNKNOWN:
                score += 10

            # Path Signal
            if p.is_temp_path:
                score += 15
                evidence.append(f"Path located in Temp directory: {p.path}")
                reasons.append("Execution from temporary directory")
            elif p.is_user_writable:
                score += 10
                evidence.append(f"Path in user-writable location: {p.path}")

            # Correlation: Persistence
            is_persistent = (p.path.lower() in paths_in_persistence)
            if is_persistent:
                score += 20
                evidence.append("Matching binary found in persistence mechanisms (Autoruns)")
                reasons.append("Configured for automatic execution")

            # Correlation: Active Network Activity
            has_net = (p.pid in pids_with_network)
            if has_net:
                score += 15
                evidence.append(f"Process PID {p.pid} maintains active remote network connections")
                reasons.append("Active external network communication")

            # Correlation: Unexpected Parent
            parent_lower = p.parent_name.lower()
            if parent_lower in ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe") and p.signature_status != SignatureStatus.VALID:
                score += 15
                evidence.append(f"Spawned by script interpreter parent: {p.parent_name}")
                reasons.append("Unexpected parent process execution chain")

            # Entropy Signal
            if p.entropy > 7.2:
                score += 10
                evidence.append(f"High file entropy ({p.entropy}), indicating potential packing/compression")

            p.risk_score = score

            # Generate Finding based on Evidence Correlation
            if score >= 50:
                findings.append(Finding(
                    finding_id=f"FIND-PROC-{p.pid}",
                    rule_id="CORRELATED_HIGH_RISK_PROCESS",
                    severity=Severity.HIGH,
                    risk_score=score,
                    entity=f"{p.name} (PID: {p.pid})",
                    evidence=evidence,
                    reasons=reasons,
                    recommendation="High priority investigation. Isolate network, examine parent command line, and analyze executable binary."
                ))
            elif score >= 25:
                findings.append(Finding(
                    finding_id=f"FIND-PROC-{p.pid}",
                    rule_id="UNVERIFIED_PROCESS_INVESTIGATION",
                    severity=Severity.MEDIUM,
                    risk_score=score,
                    entity=f"{p.name} (PID: {p.pid})",
                    evidence=evidence,
                    reasons=reasons,
                    recommendation="Review executable origins and verify validity with system administrator."
                ))

        # 2. Evaluate Persistence
        for idx, pers in enumerate(persistence):
            p_score = 0
            p_evidence = []
            p_reasons = []

            if pers.signature_status in (SignatureStatus.UNSIGNED, SignatureStatus.UNVERIFIED):
                p_score += 30
                p_evidence.append(f"Persistence binary signature: {pers.signature_status}")
                p_reasons.append("Unsigned persistence entry")

            is_temp, is_writable = is_suspicious_location(pers.image_path)
            if is_temp or is_writable:
                p_score += 15
                p_evidence.append(f"Persistence binary located in user-writable directory: {pers.image_path}")

            pers.risk_score = p_score

            if p_score >= 30:
                findings.append(Finding(
                    finding_id=f"FIND-PERSIST-{idx}",
                    rule_id="UNVERIFIED_PERSISTENCE_ENTRY",
                    severity=Severity.MEDIUM if p_score < 45 else Severity.HIGH,
                    risk_score=p_score,
                    entity=f"{pers.entry} ({pers.location})",
                    evidence=p_evidence,
                    reasons=p_reasons,
                    recommendation="Inspect autorun registry/service configuration and verify authenticity of target file."
                ))

        return findings

# ============================================================================
# REPORT GENERATORS (JSON & HTML)
# ============================================================================

class JSONReportGenerator:
    """Serializes audit results into clean machine-readable JSON."""

    @staticmethod
    def generate(metadata: SystemMetadata,
                 processes: List[ProcessRecord],
                 persistence: List[PersistenceRecord],
                 network: List[NetworkRecord],
                 findings: List[Finding],
                 output_path: str = "wsaaf_report.json"):
        
        # Summary metrics calculation
        summary = {
            "total_processes": len(processes),
            "verified_processes": sum(1 for p in processes if p.signature_status == SignatureStatus.VALID),
            "unsigned_processes": sum(1 for p in processes if p.signature_status in (SignatureStatus.UNSIGNED, SignatureStatus.UNVERIFIED)),
            "invalid_signature_processes": sum(1 for p in processes if p.signature_status in (SignatureStatus.INVALID, SignatureStatus.NOT_TRUSTED)),
            "total_persistence_entries": len(persistence),
            "unverified_persistence": sum(1 for p in persistence if p.signature_status in (SignatureStatus.UNSIGNED, SignatureStatus.UNVERIFIED)),
            "active_network_connections": len(network),
            "high_priority_findings": sum(1 for f in findings if f.severity == Severity.HIGH)
        }

        report_data = {
            "metadata": asdict(metadata),
            "summary": summary,
            "findings": [asdict(f) for f in findings],
            "processes": [asdict(p) for p in processes],
            "persistence": [asdict(p) for p in persistence],
            "network": [asdict(n) for n in network]
        }

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"JSON Security Report generated successfully: {output_path}")

class HTMLReportGenerator:
    """Generates a self-contained, responsive HTML report for security analysts."""

    @staticmethod
    def generate(metadata: SystemMetadata,
                 processes: List[ProcessRecord],
                 persistence: List[PersistenceRecord],
                 network: List[NetworkRecord],
                 findings: List[Finding],
                 output_path: str = "wsaaf_report.html"):

        verified_procs = [p for p in processes if p.signature_status == SignatureStatus.VALID]
        unverified_procs = [p for p in processes if p.signature_status != SignatureStatus.VALID]
        
        verified_pers = [p for p in persistence if p.signature_status == SignatureStatus.VALID]
        unverified_pers = [p for p in persistence if p.signature_status != SignatureStatus.VALID]

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WSAAF-NG Audit Report - {metadata.hostname}</title>
    <style>
        :root {{
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f8fafc;
            --text-secondary: #94a3b8;
            --accent-blue: #38bdf8;
            --accent-green: #22c55e;
            --accent-yellow: #eab308;
            --accent-red: #ef4444;
            --border-color: #334155;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background-color: var(--bg-primary);
            color: var(--text-primary);
            margin: 0;
            padding: 24px;
            line-height: 1.5;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
        }}
        .badge-success {{ background-color: var(--accent-green); color: #000; }}
        .badge-warning {{ background-color: var(--accent-yellow); color: #000; }}
        .badge-danger {{ background-color: var(--accent-red); color: #fff; }}
        
        .cards-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }}
        .card {{
            background: var(--bg-secondary);
            padding: 16px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .card-title {{ font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase; }}
        .card-value {{ font-size: 1.8rem; font-weight: bold; margin-top: 8px; }}

        section {{ margin-bottom: 40px; }}
        h2 {{ color: var(--accent-blue); border-bottom: 1px solid var(--border-color); padding-bottom: 8px; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--bg-secondary);
            border-radius: 8px;
            overflow: hidden;
            margin-top: 12px;
            font-size: 0.85rem;
        }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ background-color: #0f172a; color: var(--text-secondary); font-weight: 600; }}
        tr:hover {{ background-color: #26334d; }}

        .evidence-list {{ margin: 4px 0; padding-left: 16px; font-size: 0.8rem; color: var(--text-secondary); }}
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1 style="margin:0; font-size: 1.8rem;">WSAAF-NG Security Audit Report</h1>
            <div style="color: var(--text-secondary); font-size: 0.9rem; margin-top:4px;">
                Host: <strong>{metadata.hostname}</strong> | OS: {metadata.os_version} | Executed: {metadata.audit_time}
            </div>
        </div>
        <div>
            {'<span class="badge badge-success">Administrator: YES</span>' if metadata.is_admin else '<span class="badge badge-warning">Administrator: NO (LIMITED VISIBILITY)</span>'}
        </div>
    </div>

    <!-- Summary Metrics -->
    <div class="cards-grid">
        <div class="card">
            <div class="card-title">Total Running Processes</div>
            <div class="card-value">{len(processes)}</div>
        </div>
        <div class="card">
            <div class="card-title">Verified Processes</div>
            <div class="card-value" style="color: var(--accent-green);">{len(verified_procs)}</div>
        </div>
        <div class="card">
            <div class="card-title">Unverified/Unsigned Procs</div>
            <div class="card-value" style="color: var(--accent-yellow);">{len(unverified_procs)}</div>
        </div>
        <div class="card">
            <div class="card-title">Persistence Entries</div>
            <div class="card-value">{len(persistence)}</div>
        </div>
        <div class="card">
            <div class="card-title">Active Network Sockets</div>
            <div class="card-value">{len(network)}</div>
        </div>
        <div class="card">
            <div class="card-title">High Priority Findings</div>
            <div class="card-value" style="color: var(--accent-red);">{sum(1 for f in findings if f.severity == Severity.HIGH)}</div>
        </div>
    </div>

    <!-- Security Findings Section -->
    <section>
        <h2>Correlated Security Findings ({len(findings)})</h2>
        {"<p style='color: var(--text-secondary);'>No high or medium priority evidence correlations flagged.</p>" if not findings else ""}
        {''.join([f'''
        <div class="card" style="margin-bottom: 12px; border-left: 4px solid {'var(--accent-red)' if f.severity == 'HIGH' else 'var(--accent-yellow)'};">
            <div style="display: flex; justify-content: space-between;">
                <strong>[{f.rule_id}] {f.entity}</strong>
                <span class="badge {'badge-danger' if f.severity == 'HIGH' else 'badge-warning'}">{f.severity} (Risk Score: {f.risk_score})</span>
            </div>
            <div style="margin-top: 8px; font-size: 0.85rem;">
                <strong>Evidence Signals:</strong>
                <ul class="evidence-list">
                    {''.join([f'<li>{e}</li>' for e in f.evidence])}
                </ul>
                <strong>Recommendation:</strong> {f.recommendation}
            </div>
        </div>
        ''' for f in findings])}
    </section>

    <!-- Unverified Processes -->
    <section>
        <h2>Unverified / Unsigned Processes ({len(unverified_procs)})</h2>
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Name</th>
                    <th>Path</th>
                    <th>Signature</th>
                    <th>Signer</th>
                    <th>Parent</th>
                    <th>Risk</th>
                </tr>
            </thead>
            <tbody>
                {''.join([f'''
                <tr>
                    <td>{p.pid}</td>
                    <td><strong>{p.name}</strong></td>
                    <td style="word-break: break-all;">{p.path}</td>
                    <td><span class="badge badge-warning">{p.signature_status}</span></td>
                    <td>{p.signer}</td>
                    <td>{p.parent_name}</td>
                    <td>{p.risk_score}</td>
                </tr>
                ''' for p in unverified_procs])}
            </tbody>
        </table>
    </section>

    <!-- Persistence Mechanisms -->
    <section>
        <h2>Unverified Persistence Mechanisms ({len(unverified_pers)})</h2>
        <table>
            <thead>
                <tr>
                    <th>Location</th>
                    <th>Entry Name</th>
                    <th>Executable Path</th>
                    <th>Signature</th>
                    <th>Publisher</th>
                </tr>
            </thead>
            <tbody>
                {''.join([f'''
                <tr>
                    <td>{p.location}</td>
                    <td><strong>{p.entry}</strong></td>
                    <td style="word-break: break-all;">{p.image_path}</td>
                    <td><span class="badge badge-warning">{p.signature_status}</span></td>
                    <td>{p.publisher}</td>
                </tr>
                ''' for p in unverified_pers])}
            </tbody>
        </table>
    </section>

    <!-- Active Network Connections -->
    <section>
        <h2>Active Network Connections ({len(network)})</h2>
        <table>
            <thead>
                <tr>
                    <th>PID</th>
                    <th>Process</th>
                    <th>Protocol</th>
                    <th>Local Address</th>
                    <th>Remote Address</th>
                    <th>State</th>
                    <th>Proc Signature</th>
                </tr>
            </thead>
            <tbody>
                {''.join([f'''
                <tr>
                    <td>{n.pid}</td>
                    <td><strong>{n.process_name}</strong></td>
                    <td>{n.protocol}</td>
                    <td>{n.local_addr}:{n.local_port}</td>
                    <td>{n.remote_addr}:{n.remote_port}</td>
                    <td>{n.state}</td>
                    <td>{n.signature_status}</td>
                </tr>
                ''' for n in network])}
            </tbody>
        </table>
    </section>

    <!-- Verified Processes Transparency Section -->
    <section>
        <h2>Verified Processes ({len(verified_procs)})</h2>
        <details>
            <summary style="cursor: pointer; color: var(--text-secondary);">Click to expand verified software list</summary>
            <table>
                <thead>
                    <tr>
                        <th>PID</th>
                        <th>Name</th>
                        <th>Path</th>
                        <th>Signer</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join([f'''
                    <tr>
                        <td>{p.pid}</td>
                        <td>{p.name}</td>
                        <td style="word-break: break-all;">{p.path}</td>
                        <td>{p.signer}</td>
                    </tr>
                    ''' for p in verified_procs])}
                </tbody>
            </table>
        </details>
    </section>

</body>
</html>
"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        logger.info(f"HTML Security Report generated successfully: {output_path}")

# ============================================================================
# ENTRYPOINT & ORCHESTRATION
# ============================================================================

def main():
    logger.info("Starting WSAAF-NG — Windows Security Audit Framework")
    start_time = time.time()

    # Step 1: Discover Sysinternals tools
    sys_mgr = SysinternalsManager(SYSINTERNALS_DIR)

    # Step 2: Initialize Audit Engine & Run Collection
    engine = AuditEngine(sys_mgr)
    metadata, processes, persistence, network, findings = engine.run_audit()

    # Step 3: Export Artifacts
    JSONReportGenerator.generate(metadata, processes, persistence, network, findings, "wsaaf_report.json")
    HTMLReportGenerator.generate(metadata, processes, persistence, network, findings, "wsaaf_report.html")

    elapsed = round(time.time() - start_time, 2)
    logger.info(f"Audit completed successfully in {elapsed} seconds.")
    logger.info("Report files written: 'wsaaf_report.json' and 'wsaaf_report.html'")

if __name__ == "__main__":
    main()
