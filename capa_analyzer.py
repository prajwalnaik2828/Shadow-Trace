"""
=============================================================================
Shadow-Trace | capa_analyzer.py
Static capability analysis module using FLARE CAPA.

PURPOSE:
Executes static capability and behavior identification against executable
files (PE and ELF) using the CAPA library API.
Operates strictly offline/locally, never executes the file, never raises,
enforces hard execution timeouts, and performs all analysis on a temporary
working copy to preserve evidence integrity.
=============================================================================
"""

import os
import sys
import time
import shutil
import logging
import hashlib
import tempfile
import threading
import concurrent.futures
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set

# Optional config import
try:
    import config
except ImportError:
    config = None

# Optional CAPA imports
try:
    import capa
    import capa.main
    import capa.rules
    import capa.loader
    from capa.render.result_document import ResultDocument
    CAPA_AVAILABLE = True
except Exception:
    CAPA_AVAILABLE = False

# Silence verbose vivisect/envi/capa logs during disassembly
for log_name in ["vivisect", "vtrace", "envi", "capa", "capa.rules"]:
    logging.getLogger(log_name).setLevel(logging.ERROR)

# Thread-safe rules cache
_cached_rules: Optional[Any] = None
_rules_lock = threading.Lock()

# Thread-safe analysis results cache keyed by SHA-256
_analysis_cache: Dict[str, Dict[str, Any]] = {}
_cache_lock = threading.Lock()

LIMITATIONS_TEXT: str = (
    "Capabilities describe what the code CAN do based on static pattern matching and API sequence recognition, "
    "not that it was executed or definitively did so in this session. Packed, encrypted, or heavily obfuscated "
    "binaries may conceal their actual functionality and show few or no capabilities. The absence of findings "
    "is not proof of safety or absence of malicious intent."
)


def get_capa_version() -> str:
    """Return installed CAPA version string or fallback."""
    if not CAPA_AVAILABLE:
        return "UNAVAILABLE"
    try:
        import capa.version
        return getattr(capa.version, "__version__", "10.0.0")
    except Exception:
        return "10.0.0"


def get_rules_dir() -> Optional[Path]:
    """Locate the capa_rules directory."""
    # 1. config.CAPA_RULES_PATH or config.CAPA_RULES_DIR
    if config is not None:
        if hasattr(config, "CAPA_RULES_DIR"):
            p = Path(config.CAPA_RULES_DIR)
            if p.exists() and p.is_dir():
                return p
        if hasattr(config, "CAPA_RULES_PATH"):
            p = Path(config.CAPA_RULES_PATH)
            if not p.is_absolute() and hasattr(config, "BASE_DIR"):
                p = config.BASE_DIR / p
            if p.exists() and p.is_dir():
                return p

    # 2. Environment variable
    env_p = os.getenv("CAPA_RULES_PATH")
    if env_p:
        p = Path(env_p)
        if not p.is_absolute() and config and hasattr(config, "BASE_DIR"):
            p = config.BASE_DIR / p
        if p.exists() and p.is_dir():
            return p

    # 3. Default relative to project root
    base_dir = getattr(config, "BASE_DIR", Path(__file__).resolve().parent)
    cand = base_dir / "capa_rules"
    if cand.exists() and cand.is_dir():
        return cand

    return None


def get_signatures_dir() -> Optional[Path]:
    """Locate FLIRT signatures directory if available."""
    # Check site-packages/sigs
    try:
        site_sigs = Path(capa.__file__).resolve().parent.parent / "sigs"
        if site_sigs.exists() and site_sigs.is_dir():
            return site_sigs
    except Exception:
        pass

    base_dir = getattr(config, "BASE_DIR", Path(__file__).resolve().parent)
    cand = base_dir / "sigs"
    if cand.exists() and cand.is_dir():
        return cand

    return None


def get_rules_version(rules_dir: Path) -> Optional[str]:
    """Read version identifier from VERSION.txt in the rules folder."""
    version_file = rules_dir / "VERSION.txt"
    if version_file.exists():
        try:
            for line in version_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("CAPA Rules Version:"):
                    return line.split(":", 1)[1].strip()
            first = version_file.read_text(encoding="utf-8").splitlines()
            if first:
                return first[0].strip()
        except Exception:
            return None
    return None


def load_capa_rules(rules_dir: Path) -> Optional[Any]:
    """Thread-safe cached loader for CAPA rules."""
    global _cached_rules
    if not CAPA_AVAILABLE:
        return None

    with _rules_lock:
        if _cached_rules is None:
            try:
                base_dir = getattr(config, "BASE_DIR", Path(__file__).resolve().parent)
                cache_dir = base_dir / "logs" / "capa_cache"
                cache_dir.mkdir(parents=True, exist_ok=True)
                _cached_rules = capa.rules.get_rules([rules_dir], cache_dir=cache_dir)
            except Exception:
                try:
                    _cached_rules = capa.rules.get_rules([rules_dir], enable_cache=False)
                except Exception:
                    return None
        return _cached_rules


def detect_file_format(filepath: str, assume_shellcode: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """
    Detect format by magic bytes:
    - MZ -> ('PE', None)
    - 7F ELF -> ('ELF', None)
    - Raw blob if assume_shellcode -> ('SC', None)
    - Otherwise -> (None, 'Unsupported magic header')
    """
    try:
        with open(filepath, "rb") as f:
            header = f.read(512)

        if len(header) == 0:
            return None, "Empty file"

        if header.startswith(b"MZ"):
            return "PE", None
        elif header.startswith(b"\x7fELF"):
            return "ELF", None
        elif assume_shellcode and 0 < len(header) < 4096:
            return "SC", None
        else:
            magic_hex = header[:4].hex()
            return None, f"Unsupported magic bytes ({magic_hex})"
    except Exception as e:
        return None, str(e)


def map_risk_indicators(capabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Map capability namespaces and names to forensic risk categories and severity levels:
    - HIGH: ransomware, shadow copies, process injection, persistence, security tampering,
            credential theft, keylogging.
    - MEDIUM: network communication, dropper/downloader, anti-analysis/VM, data obfuscation/compression.
    - LOW: file system and registry activity, common OS operations.
    """
    indicators: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str]] = set()

    def add_ind(cat: str, detail: str, sev: str):
        key = (cat, detail, sev)
        if key not in seen:
            seen.add(key)
            indicators.append({"category": cat, "detail": detail, "severity": sev})

    for cap in capabilities:
        name = cap.get("name", "")
        ns = (cap.get("namespace") or "").lower()
        name_lower = name.lower()

        # HIGH SEVERITY
        if (
            any(k in name_lower for k in ["shadow cop", "vssadmin", "delete volume", "ransomware"])
            or ("encrypt" in name_lower and any(w in name_lower for w in ["file", "disk", "volume"]))
            or ns.startswith("impact/data-destruction")
            or ns.startswith("impact/data-encryption")
        ):
            add_ind("Ransomware / Data Destruction", name, "HIGH")

        elif (
            any(k in name_lower for k in ["inject into process", "process hollowing", "create remote thread", "inject code"])
            or "inject" in ns
        ):
            add_ind("Process Injection", name, "HIGH")

        elif (
            any(k in name_lower for k in ["persistence", "scheduled task", "run key", "startup folder", "autostart"])
            or ns.startswith("persistence")
        ):
            add_ind("Persistence Mechanism", name, "HIGH")

        elif (
            any(k in name_lower for k in ["disable security", "tamper", "disable defender", "disable antivirus", "stop service"])
            or "security-service" in ns
        ):
            add_ind("Defense Evasion (Security Tampering)", name, "HIGH")

        elif (
            any(k in name_lower for k in ["credential", "dump hashes", "steal credentials", "dump lsass", "mimikatz"])
            or "credential-access" in ns
        ):
            add_ind("Credential Theft", name, "HIGH")

        elif any(k in name_lower for k in ["keylog", "keystroke", "capture keys"]) or "keylog" in ns:
            add_ind("Keylogging", name, "HIGH")

        # MEDIUM SEVERITY
        elif any(k in name_lower for k in ["download and execute", "download file", "fetch payload", "drop and execute"]):
            add_ind("Dropper / Downloader", name, "MEDIUM")

        elif (
            any(k in name_lower for k in ["anti-debugging", "anti-vm", "detect vm", "detect debugger", "check for sandbox", "delay execution"])
            or ns.startswith("anti-analysis")
        ):
            add_ind("Anti-Analysis / Evasion", name, "MEDIUM")

        elif (
            any(k in name_lower for k in ["network", "socket", "http", "dns query", "connect to", "c2", "internet connectivity"])
            or ns.startswith("communication")
        ):
            add_ind("Network Communication", name, "MEDIUM")

        elif (
            any(k in name_lower for k in ["compress", "obfuscate", "encode data", "decode data", "xor"])
            or ns.startswith("data-manipulation")
        ):
            add_ind("Data Obfuscation / Encoding", name, "MEDIUM")

        # LOW SEVERITY
        elif (
            any(k in name_lower for k in ["read file", "write file", "create file", "delete file", "registry", "mutex", "clipboard"])
            or ns.startswith("host-interaction")
        ):
            add_ind("Host / Operating System Activity", name, "LOW")

    return indicators


def generate_plain_english(
    capabilities: List[Dict[str, Any]],
    risk_indicators: List[Dict[str, Any]],
    file_format: Optional[str],
    arch: Optional[str]
) -> str:
    """Generate 3-4 plain English sentences summarizing what the binary appears capable of."""
    cap_count = len(capabilities)
    high_count = sum(1 for r in risk_indicators if r["severity"] == "HIGH")
    med_count = sum(1 for r in risk_indicators if r["severity"] == "MEDIUM")

    fmt_desc = f"{file_format or 'Executable'} binary"
    if arch:
        fmt_desc += f" targeting {arch}"

    s1 = f"Static capability analysis of this {fmt_desc} identified {cap_count} distinct functional capability indicators."

    if high_count > 0:
        high_cats = list(dict.fromkeys(r["category"] for r in risk_indicators if r["severity"] == "HIGH"))
        s2 = f"Notably, the executable incorporates logic associated with high-risk behaviors, including {', '.join(high_cats[:3])}."
    elif med_count > 0:
        med_cats = list(dict.fromkeys(r["category"] for r in risk_indicators if r["severity"] == "MEDIUM"))
        s2 = f"The binary demonstrates moderate-risk capabilities, primarily related to {', '.join(med_cats[:3])}."
    else:
        s2 = "The detected capabilities predominantly encompass standard operating system facilities, runtime linking, and routine file operations."

    if high_count > 0:
        s3 = "These technical indicators suggest potential offensive, persistent, or evasive intent characteristic of malware payloads."
    elif med_count > 0:
        s3 = "These capabilities indicate deliberate system probing, communication, or data staging routines."
    else:
        s3 = "No explicit destructive, ransomware, or credential harvesting capabilities were identified in the static code structure."

    s4 = "These findings represent latent programmatic capabilities discovered in the file rather than verified execution history."

    return f"{s1} {s2} {s3} {s4}"


def _execute_capa_inner(
    sample_path: Path,
    ruleset: Any,
    sigs_dir: Optional[Path]
) -> Dict[str, Any]:
    """Internal execution running capa loader and rule matching."""
    input_format = capa.loader.get_format(sample_path)
    os_name = capa.loader.get_os(sample_path)
    arch = capa.loader.get_arch(sample_path)

    sigpaths = capa.loader.get_signatures(sigs_dir) if sigs_dir and sigs_dir.exists() else []

    extractor = capa.loader.get_extractor(
        sample_path,
        input_format,
        os_name,
        capa.loader.BACKEND_VIV,
        sigpaths,
        disable_progress=True
    )

    caps = capa.main.find_capabilities(ruleset, extractor, disable_progress=True)
    meta = capa.loader.collect_metadata(
        ["capa", str(sample_path)],
        sample_path,
        input_format,
        [],
        extractor,
        caps
    )
    doc = ResultDocument.from_capa(meta, ruleset, caps.matches)

    raw_capabilities: List[Dict[str, Any]] = []
    tactics_set: Set[str] = set()
    techniques_set: Set[str] = set()

    for rule_name, rule_match in doc.rules.items():
        rmeta = rule_match.meta

        attack_entries: List[Dict[str, Any]] = []
        for att in rmeta.attack:
            attack_entries.append({
                "tactic": att.tactic,
                "technique": att.technique,
                "id": att.id
            })
            if att.tactic:
                tactics_set.add(att.tactic)
            if att.id and att.technique:
                techniques_set.add(f"{att.id} {att.technique}")

        mbc_entries: List[Dict[str, Any]] = []
        for m in rmeta.mbc:
            mbc_entries.append({
                "objective": m.objective,
                "behavior": m.behavior,
                "method": m.method,
                "id": m.id
            })

        raw_capabilities.append({
            "name": rule_name,
            "namespace": rmeta.namespace,
            "attack": attack_entries,
            "mbc": mbc_entries,
            "match_count": len(rule_match.matches)
        })

    return {
        "architecture": arch,
        "capabilities": raw_capabilities,
        "attack_tactics": sorted(list(tactics_set)),
        "attack_techniques": sorted(list(techniques_set))
    }


def analyze_with_capa(
    filepath: str,
    timeout_seconds: int = 120,
    assume_shellcode: bool = False
) -> Dict[str, Any]:
    """
    Run static capability analysis on an executable file and return a normalised result.
    Never executes the file, never raises, and never blocks the pipeline.

    Args:
        filepath: Path to the target executable.
        timeout_seconds: Maximum seconds to wait before timing out (default 120).
        assume_shellcode: Treat small raw blobs as shellcode if True.

    Returns:
        Structured result dict conforming to specification.
    """
    start_time = time.time()
    capa_ver = get_capa_version()

    base_result: Dict[str, Any] = {
        "status": "ERROR",
        "file_format": None,
        "architecture": None,
        "capabilities": [],
        "attack_tactics": [],
        "attack_techniques": [],
        "capability_count": 0,
        "risk_indicators": [],
        "rules_version": None,
        "capa_version": capa_ver,
        "duration_seconds": 0.0,
        "plain_english": "",
        "limitations": LIMITATIONS_TEXT,
        "error": None
    }

    try:
        # STEP 1: Pre-checks
        if not CAPA_AVAILABLE:
            base_result.update({
                "status": "UNAVAILABLE",
                "plain_english": "CAPA capability analysis engine is not available in the current environment.",
                "error": "flare-capa library is not installed or failed to import."
            })
            return base_result

        rules_dir = get_rules_dir()
        if not rules_dir or not rules_dir.exists():
            base_result.update({
                "status": "NO_RULES",
                "plain_english": "CAPA rules directory is missing or unreadable.",
                "error": "capa_rules directory not found or unreadable."
            })
            return base_result

        rules_ver = get_rules_version(rules_dir)
        base_result["rules_version"] = rules_ver

        if not os.path.exists(filepath):
            base_result.update({
                "status": "SKIPPED",
                "plain_english": "File could not be found for analysis.",
                "error": f"File does not exist: {filepath}"
            })
            return base_result

        file_size = os.path.getsize(filepath)
        MAX_SIZE = 50 * 1024 * 1024  # 50 MB
        if file_size > MAX_SIZE:
            base_result.update({
                "status": "SKIPPED",
                "plain_english": f"File size ({file_size} bytes) exceeds the 50 MB threshold for static capability extraction.",
                "error": f"File size exceeds 50 MB limit: {file_size} bytes."
            })
            return base_result

        # STEP 2: Detect format by magic bytes
        fmt, reason = detect_file_format(filepath, assume_shellcode=assume_shellcode)
        if fmt is None:
            base_result.update({
                "status": "UNSUPPORTED_FORMAT",
                "plain_english": "File format is not supported by CAPA executable analysis (expected PE or ELF binary).",
                "error": reason or "Unsupported file format"
            })
            return base_result

        base_result["file_format"] = fmt

        # Check cache by file content SHA-256
        file_hash = None
        try:
            with open(filepath, "rb") as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
            with _cache_lock:
                if file_hash in _analysis_cache:
                    cached_copy = dict(_analysis_cache[file_hash])
                    return cached_copy
        except Exception:
            pass

        # Load rules
        ruleset = load_capa_rules(rules_dir)
        if ruleset is None:
            base_result.update({
                "status": "NO_RULES",
                "plain_english": "Failed to compile or load CAPA rules.",
                "error": "Unable to compile RuleSet from capa_rules."
            })
            return base_result

        sigs_dir = get_signatures_dir()

        # STEP 3: Run CAPA on a COPY in a temp directory
        temp_work_dir = Path(tempfile.mkdtemp(prefix="shadowtrace_capa_"))
        temp_copy = temp_work_dir / Path(filepath).name
        try:
            shutil.copy2(filepath, temp_copy)

            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = executor.submit(_execute_capa_inner, temp_copy, ruleset, sigs_dir)

            try:
                inner_result = future.result(timeout=timeout_seconds)
            except concurrent.futures.TimeoutError:
                executor.shutdown(wait=False, cancel_futures=True)
                duration = time.time() - start_time
                base_result.update({
                    "status": "TIMEOUT",
                    "duration_seconds": round(duration, 2),
                    "plain_english": f"Static capability analysis exceeded the timeout limit of {timeout_seconds} seconds.",
                    "error": f"Analysis timed out after {timeout_seconds}s"
                })
                return base_result
            finally:
                executor.shutdown(wait=False)

        finally:
            shutil.rmtree(temp_work_dir, ignore_errors=True)

        # STEP 4 & 5: Parse, map risk indicators, deduplicate and cap at 100
        duration = round(time.time() - start_time, 2)
        arch = inner_result.get("architecture")
        raw_caps = inner_result.get("capabilities", [])

        # Deduplicate capabilities by name
        unique_caps: List[Dict[str, Any]] = []
        seen_names: Set[str] = set()
        for cap in raw_caps:
            cname = cap.get("name")
            if cname and cname not in seen_names:
                seen_names.add(cname)
                unique_caps.append(cap)

        capped_caps = unique_caps[:100]
        risk_indicators = map_risk_indicators(capped_caps)
        plain_english = generate_plain_english(capped_caps, risk_indicators, fmt, arch)

        base_result.update({
            "status": "COMPLETE",
            "file_format": fmt,
            "architecture": arch,
            "capabilities": capped_caps,
            "attack_tactics": inner_result.get("attack_tactics", []),
            "attack_techniques": inner_result.get("attack_techniques", []),
            "capability_count": len(capped_caps),
            "risk_indicators": risk_indicators,
            "duration_seconds": duration,
            "plain_english": plain_english,
            "error": None
        })

        if file_hash:
            with _cache_lock:
                _analysis_cache[file_hash] = dict(base_result)

        return base_result

    except Exception as e:
        base_result.update({
            "status": "ERROR",
            "duration_seconds": round(time.time() - start_time, 2),
            "plain_english": "An unexpected error occurred during capability extraction.",
            "error": str(e)
        })
        return base_result


def capa_to_classifier_hint(capa_result: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    """
    Translate CAPA capabilities into normalized hints for malware_classifier.py:
    - 'encrypt files' / 'shadow copies' -> ransomware
    - 'keylog' / 'steal credentials' -> spyware/infostealer
    - 'download and execute' -> dropper/downloader
    - 'persistence' -> generic/unknown supporting evidence
    - 'backdoor' -> backdoor
    - 'miner' -> miner

    Returns:
        List of dicts: [{ 'source': 'CAPA', 'raw_label': str, 'category': str }]
    """
    if not capa_result or not isinstance(capa_result, dict):
        return []

    if capa_result.get("status") != "COMPLETE":
        return []

    hints: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str, str]] = set()

    def add_hint(raw_label: str, cat: str):
        entry = ("CAPA", raw_label, cat)
        if entry not in seen:
            seen.add(entry)
            hints.append({"source": "CAPA", "raw_label": raw_label, "category": cat})

    for cap in capa_result.get("capabilities", []):
        name = cap.get("name", "")
        ns = (cap.get("namespace") or "").lower()
        name_lower = name.lower()

        # 1. Ransomware
        if (
            any(k in name_lower for k in ["encrypt", "shadow cop", "vssadmin", "ransom"])
            or ns.startswith("impact/data-encryption")
            or ns.startswith("impact/data-destruction")
        ):
            add_hint(name, "ransomware")

        # 2. Spyware / Infostealer
        elif (
            any(k in name_lower for k in ["keylog", "steal credential", "credential", "clipboard", "keystroke", "dump hashes"])
            or ns.startswith("credential-access")
            or "keylog" in ns
        ):
            add_hint(name, "spyware/infostealer")

        # 3. Dropper / Downloader
        elif (
            any(k in name_lower for k in ["download and execute", "download", "drop and execute", "dropper"])
            or ns.startswith("load-code")
        ):
            add_hint(name, "dropper/downloader")

        # 4. Backdoor
        elif any(k in name_lower for k in ["backdoor", "reverse shell", "remcos"]):
            add_hint(name, "backdoor")

        # 5. Miner
        elif any(k in name_lower for k in ["miner", "coinminer", "monero"]):
            add_hint(name, "miner")

        # 6. Generic / Supporting evidence (Persistence, injection, evasion)
        elif (
            any(k in name_lower for k in ["persistence", "inject", "anti-analysis", "anti-debugging", "scheduled task"])
            or ns.startswith("persistence")
            or ns.startswith("anti-analysis")
        ):
            add_hint(name, "generic/unknown")

    return hints


# =============================================================================
# Verification / Test Suite Block
# =============================================================================
if __name__ == "__main__":
    print("=" * 70)
    print("Shadow-Trace CAPA Analyzer Verification Suite")
    print("=" * 70)

    notepad_src = Path(r"C:\Windows\System32\notepad.exe")
    temp_test_dir = Path(tempfile.mkdtemp(prefix="capa_test_run_"))
    notepad_copy = temp_test_dir / "notepad.exe"
    shutil.copy2(notepad_src, notepad_copy)

    # 1. Run on notepad.exe copy
    print("\n--- TEST 1: CAPA Analysis on notepad.exe Copy ---")
    res1 = analyze_with_capa(str(notepad_copy), timeout_seconds=180)
    print(f"Status:           {res1.get('status')}")
    print(f"File Format:      {res1.get('file_format')}")
    print(f"Architecture:     {res1.get('architecture')}")
    print(f"Capability Count: {res1.get('capability_count')}")
    print(f"Attack Tactics:   {res1.get('attack_tactics')}")
    print(f"Duration:         {res1.get('duration_seconds')}s")
    print(f"Plain English:    {res1.get('plain_english')}")

    # 2. Run on plain text file
    txt_file = temp_test_dir / "sample.txt"
    txt_file.write_text("Hello World. This is a text file.", encoding="utf-8")
    print("\n--- TEST 2: CAPA Analysis on Plain Text File ---")
    res2 = analyze_with_capa(str(txt_file))
    print(f"Status:           {res2.get('status')}")
    print(f"Error:            {res2.get('error')}")

    # 3. Run with timeout_seconds=1 to show TIMEOUT handling
    print("\n--- TEST 3: CAPA Analysis Timeout Handling (timeout_seconds=1) ---")
    res3 = analyze_with_capa(str(notepad_copy), timeout_seconds=1)
    print(f"Status:           {res3.get('status')}")
    print(f"Duration:         {res3.get('duration_seconds')}s")
    print(f"Error:            {res3.get('error')}")

    # 4. Show classify_malware output with mock CAPA ransomware result
    print("\n--- TEST 4: classify_malware with Mock CAPA Ransomware Capabilities ---")
    try:
        from malware_classifier import classify_malware

        mock_capa_ransomware = {
            "status": "COMPLETE",
            "file_format": "PE",
            "capabilities": [
                {"name": "encrypt files using AES", "namespace": "impact/data-encryption"},
                {"name": "delete volume shadow copies", "namespace": "impact/data-destruction"},
                {"name": "persist via registry run key", "namespace": "persistence/registry"}
            ]
        }

        # Run classification with empty Layer 1 result and CAPA ransomware result
        clf_result = classify_malware({}, capa_result=mock_capa_ransomware)
        print(f"Classified:       {clf_result.get('classified')}")
        print(f"Primary Category: {clf_result.get('primary_category')}")
        print(f"Confidence:       {clf_result.get('confidence')}")
        print(f"Sources:          {clf_result.get('sources')}")
        print(f"Plain English:    {clf_result.get('plain_english')}")
    except Exception as e:
        print(f"Classification test error: {e}")

    # Clean up
    shutil.rmtree(temp_test_dir, ignore_errors=True)
    print("\n" + "=" * 70)
