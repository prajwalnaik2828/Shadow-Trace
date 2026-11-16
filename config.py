# =============================================================================
# Shadow-Trace | config.py
# Central configuration — environment, paths, thresholds, constants
# =============================================================================

# ── Section 1: Imports ────────────────────────────────────────────────────────
import os
import sys
import platform
from pathlib import Path
from dotenv import load_dotenv

# ── Section 2: Load environment variables ────────────────────────────────────
load_dotenv()

VIRUSTOTAL_API_KEY  = os.getenv('VIRUSTOTAL_API_KEY', '')
HYBRID_ANALYSIS_KEY = os.getenv('HYBRID_ANALYSIS_KEY', '')
HMAC_SECRET_KEY     = os.getenv(
    'HMAC_SECRET_KEY',
    ''
).encode('utf-8')
VERSION = os.getenv('SHADOW_TRACE_VERSION', '1.0.0')
VT_MODE = os.getenv('VT_MODE', 'CHECK_ONLY')
VT_CACHE_HOURS = int(os.getenv('VT_CACHE_HOURS', 24))
OFFLINE_SCAN_MODE = os.getenv('OFFLINE_SCAN_MODE', 'false').lower() == 'true'
HYBRID_ANALYSIS_MODE = os.getenv('HYBRID_ANALYSIS_MODE', 'hash_only')

# ── Section 3: Base directory ─────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent.resolve()

# ── Section 4: All folder paths ───────────────────────────────────────────────
QUARANTINE_DIR    = BASE_DIR / 'quarantine'
REPORTS_DIR       = BASE_DIR / 'reports'
MODELS_DIR        = BASE_DIR / 'models'
LOGS_DIR          = BASE_DIR / 'logs'
THREAT_INTEL_DIR  = BASE_DIR / 'threat_intel'
YARA_RULES_DIR    = BASE_DIR / 'yara_rules'
SANDBOX_DIR       = BASE_DIR / 'sandbox'
CLAMAV_DIR        = THREAT_INTEL_DIR / 'clamav'

MONITORED_DIRS = [
    Path.home() / 'Downloads',
    Path.home() / 'Desktop',
    Path.home() / 'Documents',
]

DOWNLOADS_DIR = MONITORED_DIRS[0]

def get_monitored_dirs():
    active = []
    for d in MONITORED_DIRS:
        try:
            if d.exists() and d.is_dir():
                active.append(d)
        except OSError:
            pass
    return active
RECOVERY_DB       = BASE_DIR / 'shadowtrace_recovery.db'
COC_DB            = BASE_DIR / 'shadowtrace_coc.db'
URL_CACHE_FILE    = BASE_DIR / 'shadowtrace_url_cache.json'
LAST_UPDATE_FILE  = BASE_DIR / 'logs' / 'last_update.txt'
UPDATE_LOG        = BASE_DIR / 'logs' / 'updates.log'
ERROR_LOG         = BASE_DIR / 'logs' / 'shadowtrace_errors.log'
MAIN_LOG          = BASE_DIR / 'logs' / 'shadowtrace.log'

# ── Section 5: Create all directories ─────────────────────────────────────────
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
for _subfolder in ['clean', 'suspicious', 'stego', 'quarantine']:
    (REPORTS_DIR / _subfolder).mkdir(parents=True, exist_ok=True)
del _subfolder
MODELS_DIR.mkdir(parents=True, exist_ok=True)
LOGS_DIR.mkdir(parents=True, exist_ok=True)
THREAT_INTEL_DIR.mkdir(parents=True, exist_ok=True)
YARA_RULES_DIR.mkdir(parents=True, exist_ok=True)
SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
CLAMAV_DIR.mkdir(parents=True, exist_ok=True)

# ── Section 6: Scanning thresholds ────────────────────────────────────────────
ENTROPY_THRESHOLD_STANDARD = 7.2
ENTROPY_THRESHOLD_HIGH     = 7.95

HIGH_ENTROPY_MIMES = [
    'application/zip',
    'application/x-rar-compressed',
    'application/x-7z-compressed',
    'application/x-gzip',
    'application/x-bzip2',
    'video/mp4',
    'video/x-msvideo',
    'video/x-matroska',
    'audio/mpeg',
    'audio/mp4',
    'application/pdf',
    'application/encrypted',
    'application/octet-stream',
]

# ── Section 7: API URLs ───────────────────────────────────────────────────────
VIRUSTOTAL_BASE_URL  = 'https://www.virustotal.com/api/v3'
VIRUSTOTAL_FILES_URL = VIRUSTOTAL_BASE_URL + '/files'
HYBRID_ANALYSIS_URL  = 'https://www.hybrid-analysis.com/api/v2'
FREETSA_URL          = 'https://freetsa.org/tsr'

# ── Section 8: Confidence thresholds ──────────────────────────────────────────
CONFIDENCE_HIGH       = 0.85
CONFIDENCE_MEDIUM     = 0.65
CONFIDENCE_SUSPICIOUS = 0.50

# ── Section 9: ClamAV paths (OS-aware) ───────────────────────────────────────
_os = platform.system()
if _os == 'Windows':
    CLAMAV_PATH = Path('C:/Program Files/ClamAV')
elif _os == 'Linux':
    CLAMAV_PATH = Path('/usr/bin')
else:  # macOS / Darwin
    CLAMAV_PATH = Path('/opt/homebrew/bin')

CLAMSCAN_PATH  = CLAMAV_PATH / ('clamscan.exe'  if platform.system() == 'Windows' else 'clamscan')
CLAMD_PATH     = CLAMAV_PATH / ('clamd.exe'     if platform.system() == 'Windows' else 'clamd')
FRESHCLAM_PATH = CLAMAV_PATH / ('freshclam.exe' if platform.system() == 'Windows' else 'freshclam')

# ── Section 10: YARA patterns ────────────────────────────────────────────────
YARA_RULES_PATTERN      = str(YARA_RULES_DIR / '**' / '*.yar')
YARA_RULES_PATTERN_YARA = str(YARA_RULES_DIR / '**' / '*.yara')
YARA_RULES_PATH         = str(YARA_RULES_DIR)
INFORMATIONAL_RULES     = [
    'Big_Numbers1',
    'Big_Numbers2',
    'invalid_trailer_structure',
    'invalid_xref_numbers',
    'invalid_xref_entry',
    'invalid_pdf_structure',
    'pdf_structure_anomaly',
    'suspicious_xref',
    'malformed_pdf',
    'multiple_versions',
]
# ── Section 11: File locking constants ───────────────────────────────────────
LOCKED_EXTENSION   = '.shadowtrace_scanning'
LOCK_PERMISSIONS   = 0o000
NORMAL_PERMISSIONS = 0o644
URL_SERVER_PORT    = 8765
URL_SERVER_HOST    = 'localhost'

# ── Section 12: Rate limiting constants ──────────────────────────────────────
VIRUSTOTAL_CALLS_PER_MINUTE = 4
VIRUSTOTAL_CALLS_PER_DAY    = 500
HYBRID_CALLS_PER_DAY        = 200

# ── Section 13: Report constants ─────────────────────────────────────────────
REPORT_TITLE      = 'Shadow-Trace Forensic Report'
REPORT_VERSION    = VERSION
REPORT_COMPLIANCE = 'ISO/IEC 27037 and ACPO Good Practice Guide'

# ── Section 14: Examiner configuration ───────────────────────────────────────
EXAMINER_NAME = os.environ.get(
    'EXAMINER_NAME', 'Digital Forensic Examiner'
)
EXAMINER_ID = os.environ.get(
    'EXAMINER_ID', ''
)
EXAMINER_ORG = os.environ.get(
    'EXAMINER_ORG',
    'Digital Forensic Laboratory'
)

# ── Section 15: Startup verification ─────────────────────────────────────────
print(f"Shadow-Trace v{VERSION} loaded")
print(f"OS: {platform.system()} {platform.architecture()[0]}")
print(f"Monitored folders: {len(get_monitored_dirs())} active")
print(f"Project folder: {BASE_DIR}")
print(f"VirusTotal key loaded: {'YES' if VIRUSTOTAL_API_KEY else 'NO - CHECK .env FILE'}")
print(f"VirusTotal mode: {VT_MODE}")
print(f"Hybrid Analysis key loaded: {'YES' if HYBRID_ANALYSIS_KEY else 'NO - CHECK .env FILE'}")
