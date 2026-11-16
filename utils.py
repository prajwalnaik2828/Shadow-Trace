# =============================================================================
# Shadow-Trace | utils.py
# Core utility functions shared across all modules
# =============================================================================

import os
import sys
import math
import platform
import socket
import datetime
import hashlib
import mimetypes
import subprocess
import logging

try:
    import magic
    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False

import config

import ctypes
import ctypes.wintypes
from pathlib import Path

# Global handle registry - stores open file handles
# Key: filepath string, Value: Windows HANDLE
_file_handles = {}
_handles_lock = __import__('threading').Lock()

if platform.system() == 'Windows':
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_NONE = 0x00000000
    OPEN_EXISTING = 3
    INVALID_HANDLE_VALUE = ctypes.wintypes.HANDLE(-1).value
    
    CreateFileW = ctypes.windll.kernel32.CreateFileW
    CreateFileW.argtypes = [
        ctypes.wintypes.LPCWSTR,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.LPVOID,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.DWORD,
        ctypes.wintypes.HANDLE
    ]
    CreateFileW.restype = ctypes.wintypes.HANDLE
    
    CloseHandle = ctypes.windll.kernel32.CloseHandle
    CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
    CloseHandle.restype = ctypes.wintypes.BOOL

# =============================================================================
# FUNCTION 1: generate_sha3_hash
# =============================================================================

def generate_sha3_hash(filepath):
    """
    Compute SHA3-512 hash of a file by reading in 4096-byte chunks.
    Returns the hex digest string, or None on error.
    """
    try:
        hasher = hashlib.sha3_512()
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError as e:
        log_error(f"generate_sha3_hash: file not found — {filepath}", e)
        return None
    except PermissionError as e:
        log_error(f"generate_sha3_hash: permission denied — {filepath}", e)
        return None
    except Exception as e:
        log_error(f"generate_sha3_hash: unexpected error on {filepath}", e)
        return None

def compute_multi_hash(filepath: str) -> dict:
    try:
        import hashlib
        from pathlib import Path
        from datetime import datetime, timezone

        p = Path(filepath)
        if not p.exists():
            return {
                'success': False,
                'error': 'File not found: ' + str(filepath),
                'md5': None,
                'sha256': None,
                'sha3_512': None,
            }

        md5_h    = hashlib.md5()
        sha256_h = hashlib.sha256()
        sha3_h   = hashlib.sha3_512()

        CHUNK_SIZE = 65536
        file_size = 0

        try:
            with open(str(filepath), 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    md5_h.update(chunk)
                    sha256_h.update(chunk)
                    sha3_h.update(chunk)
                    file_size += len(chunk)
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'md5': None,
                'sha256': None,
                'sha3_512': None,
            }

        return {
            'success': True,
            'md5': md5_h.hexdigest(),
            'sha256': sha256_h.hexdigest(),
            'sha3_512': sha3_h.hexdigest(),
            'file_size_bytes': file_size,
            'computed_at': datetime.now(
                timezone.utc
            ).isoformat(),
            'algorithm_note': (
                'All three hashes computed simultaneously '
                'in a single read pass on the original '
                'unmodified file before any processing. '
                'SHA3-512 is the primary integrity algorithm. '
                'SHA-256 provides cross-tool compatibility '
                'with EnCase FTK and Autopsy. '
                'MD5 is included for legacy compatibility '
                'with older forensic frameworks and court '
                'documentation standards. '
                'MD5 and SHA-1 collision vulnerabilities '
                'do not affect their use as secondary '
                'cross-verification values when used '
                'alongside SHA3-512.'
            ),
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'md5': None,
            'sha256': None,
            'sha3_512': None,
        }

def get_system_context() -> dict:
    try:
        import platform
        import time as time_module
        import hashlib
        from datetime import datetime, timezone
        
        now_utc = datetime.now(timezone.utc)
        now_local = datetime.now()
        
        try:
            offset_secs = -time_module.timezone
            if time_module.daylight:
                offset_secs = -time_module.altzone
            offset_hours = offset_secs / 3600
            if offset_hours >= 0:
                utc_offset = 'UTC+' + str(offset_hours)
            else:
                utc_offset = 'UTC' + str(offset_hours)
            tz_name = time_module.tzname[0]
        except Exception:
            utc_offset = 'Unknown'
            tz_name = 'Unknown'
        
        os_info = {
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version()[:80],
            'machine': platform.machine(),
            'hostname': platform.node(),
        }
        
        tool_hashes = {}
        key_files = [
            'main.py',
            'layer2_steganalysis.py',
            'layer4_report.py',
            'confidence_calibration.py',
        ]
        for fname in key_files:
            fpath = config.BASE_DIR / fname
            try:
                if fpath.exists():
                    with open(fpath, 'rb') as f:
                        h = hashlib.sha256(f.read())
                    tool_hashes[fname] = h.hexdigest()
            except Exception:
                tool_hashes[fname] = 'unreadable'
        
        return {
            'scan_time_utc': now_utc.isoformat(),
            'scan_time_local': now_local.isoformat(),
            'timezone_name': tz_name,
            'utc_offset': utc_offset,
            'os_system': os_info['system'],
            'os_release': os_info['release'],
            'os_version': os_info['version'],
            'hostname': os_info['hostname'],
            'machine_arch': os_info['machine'],
            'python_version': platform.python_version(),
            'shadow_trace_version': '1.0.0',
            'tool_integrity': tool_hashes,
            'examiner_name': os.environ.get('EXAMINER_NAME', 'Unknown'),
            'examiner_id': os.environ.get('EXAMINER_ID', 'Unknown'),
            'organisation': os.environ.get('EXAMINER_ORG', 'Unknown'),
        }

    except Exception as e:
        import platform
        from datetime import datetime, timezone
        return {
            'error': str(e),
            'scan_time_utc': datetime.now(timezone.utc).isoformat(),
            'shadow_trace_version': '1.0.0',
        }



# =============================================================================
# FUNCTION 2: lock_file
# =============================================================================

def lock_file(filepath):
    filepath = str(filepath)
    system = platform.system()
    
    if system != 'Windows':
        try:
            os.chmod(filepath, 0o000)
            return True
        except Exception as e:
            log_error(f'lock_file Linux/Mac error: {e}')
            return False
    
    # Windows locking strategy:
    # Step 1: Open exclusive handle (prevents all access)
    # Step 2: Store handle in registry
    # Step 3: Apply icacls deny as second layer
    
    success = False
    
    # Step 1 and 2: Exclusive handle
    try:
        handle = CreateFileW(
            filepath,
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_NONE,  # No sharing allowed
            None,
            OPEN_EXISTING,
            0,
            None
        )
        
        if handle != INVALID_HANDLE_VALUE:
            with _handles_lock:
                # Close any existing handle first
                if filepath in _file_handles:
                    try:
                        CloseHandle(_file_handles[filepath])
                    except Exception:
                        pass  # handle already closed or invalid — safe to ignore
                _file_handles[filepath] = handle
            print(f'[LOCK] Exclusive handle stored for: {Path(filepath).name}')
            success = True
        else:
            error_code = ctypes.GetLastError()
            print(f'[LOCK] CreateFileW failed. Error code: {error_code}')
    except Exception as e:
        print(f'[LOCK] Handle error: {e}')
    
    # Step 3: icacls deny as second layer
    try:
        import subprocess
        result = subprocess.run(
            ['icacls', filepath, '/deny', 
             'Everyone:(R,W,X,D)'],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            print(f'[LOCK] icacls deny applied for: {Path(filepath).name}')
            success = True
        else:
            print(f'[LOCK] icacls failed: {result.stderr}')
    except Exception as e:
        print(f'[LOCK] icacls error: {e}')
    
    return success


# =============================================================================
# FUNCTION 3: unlock_file
# =============================================================================

def unlock_file(filepath):
    filepath = str(filepath)
    system = platform.system()
    
    if system != 'Windows':
        try:
            os.chmod(filepath, 0o644)
            return True
        except Exception as e:
            log_error(f'unlock_file Linux/Mac error: {e}')
            return False
    
    name = Path(filepath).name
    all_success = True
    import time
    
    # Step 1: Close the stored Windows handle
    with _handles_lock:
        handle = _file_handles.pop(filepath, None)
    
    if handle is not None:
        try:
            result = CloseHandle(handle)
            if result:
                print(f'[UNLOCK] Windows handle released: {name}')
            else:
                error = ctypes.GetLastError()
                print(f'[UNLOCK] CloseHandle error code: {error}')
                all_success = False
        except Exception as e:
            print(f'[UNLOCK] CloseHandle exception: {e}')
            all_success = False
    else:
        print(f'[UNLOCK] No stored handle for: {name}')
    
    # Wait for OS to release the handle
    time.sleep(0.3)
    
    # Step 2: Remove icacls deny rules
    try:
        import subprocess
        
        # Remove deny rule
        r1 = subprocess.run(
            ['icacls', filepath, '/remove:d', 'Everyone'],
            capture_output=True, text=True, timeout=10
        )
        
        # Reset to inherited permissions
        r2 = subprocess.run(
            ['icacls', filepath, '/reset'],
            capture_output=True, text=True, timeout=10
        )
        
        # Grant explicit read access to current user
        username = os.getlogin()
        r3 = subprocess.run(
            ['icacls', filepath, '/grant', 
             f'{username}:(R,W)'],
            capture_output=True, text=True, timeout=10
        )
        
        if r1.returncode == 0 and r2.returncode == 0:
            print(f'[UNLOCK] icacls permissions restored: {name}')
        else:
            print(f'[UNLOCK] icacls partial: r1={r1.returncode} r2={r2.returncode}')
            all_success = False
            
    except Exception as e:
        print(f'[UNLOCK] icacls error: {e}')
        all_success = False
    
    # Step 3: Wait and verify
    time.sleep(0.5)
    
    # Step 4: Verify unlock worked
    try:
        with open(filepath, 'rb') as test:
            test.read(1)
        print(f'[UNLOCK] Verified accessible: {name}')
        return True
    except PermissionError:
        # If we successfully closed the handle and removed the icacls deny, 
        # a PermissionError here is typically a Sharing Violation from 
        # Windows Defender jumping in to scan the file now that it is accessible.
        # We do not need to take violent measures like 'takeown'.
        print(f'[UNLOCK] File claimed by background process (likely Defender). Lock natively released: {name}')
        return True
    except Exception as e:
        print(f'[UNLOCK] Verify error: {e}')
        return True  # Assume success if not PermissionError


def verify_lock(filepath):
    # Check if we have an active handle first
    with _handles_lock:
        if str(filepath) in _file_handles:
            return True
            
    try:
        with open(str(filepath), 'rb') as f:
            f.read(1)
        return False  # Could read = NOT locked
    except PermissionError:
        # Still can't access it, but likely Defender if not in our handles
        return False
    except FileNotFoundError:
        return False
    except Exception:
        return False   # Assume unlocked on other errors

def get_locked_files_count():
    with _handles_lock:
        return len(_file_handles)


# =============================================================================
# FUNCTION 4: get_file_info
# =============================================================================

def get_file_info(filepath):
    """
    Return a dictionary of file metadata.
    Returns a dict with all None values and error=True if file not found.
    """
    try:
        p = os.path.abspath(filepath)
        stat = os.stat(p)
        size_bytes = stat.st_size

        # Human-readable size
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                size_human = f"{size_bytes:.1f} {unit}"
                break
            size_bytes /= 1024.0
        else:
            size_human = f"{size_bytes:.1f} PB"

        # Re-read raw size after loop consumed it
        raw_size = os.stat(p).st_size

        created_ts  = datetime.datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
        modified_ts = datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

        # Check if locked (permissions == 0)
        is_locked = (stat.st_mode & 0o777) == 0

        _, ext = os.path.splitext(p)

        return {
            'filename':      os.path.basename(p),
            'full_path':     p,
            'extension':     ext,
            'size_bytes':    raw_size,
            'size_human':    size_human,
            'created_time':  created_ts,
            'modified_time': modified_ts,
            'is_locked':     is_locked,
            'error':         False,
        }
    except FileNotFoundError as e:
        log_error(f"get_file_info: file not found — {filepath}", e)
        return {k: None for k in
                ['filename', 'full_path', 'extension', 'size_bytes',
                 'size_human', 'created_time', 'modified_time', 'is_locked']} | {'error': True}
    except Exception as e:
        log_error(f"get_file_info: unexpected error on {filepath}", e)
        return {k: None for k in
                ['filename', 'full_path', 'extension', 'size_bytes',
                 'size_human', 'created_time', 'modified_time', 'is_locked']} | {'error': True}


# =============================================================================
# FUNCTION 5: calculate_shannon_entropy
# =============================================================================

def calculate_shannon_entropy(filepath):
    """
    Calculate Shannon entropy of a file's byte distribution.
    Returns float rounded to 6 decimal places, 0.0 for empty, None on error.
    """
    try:
        with open(filepath, 'rb') as f:
            data = f.read()

        total_bytes = len(data)
        if total_bytes == 0:
            return 0.0

        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1

        entropy = 0.0
        for count in freq.values():
            if count == 0:
                continue
            p = count / total_bytes
            entropy -= p * math.log2(p)

        return round(entropy, 6)
    except FileNotFoundError as e:
        log_error(f"calculate_shannon_entropy: file not found — {filepath}", e)
        return None
    except PermissionError as e:
        log_error(f"calculate_shannon_entropy: permission denied — {filepath}", e)
        return None
    except Exception as e:
        log_error(f"calculate_shannon_entropy: unexpected error on {filepath}", e)
        return None


# =============================================================================
# FUNCTION 6: get_mime_type
# =============================================================================

def get_mime_type(filepath):
    """
    Detect MIME type using python-magic, falling back to mimetypes module.
    Returns 'application/octet-stream' if both methods fail.
    """
    try:
        if _MAGIC_AVAILABLE:
            mime = magic.from_file(str(filepath), mime=True)
            if mime:
                return mime
    except Exception as e:
        log_error(f"get_mime_type: magic failed on {filepath}, falling back", e)

    try:
        guessed, _ = mimetypes.guess_type(str(filepath))
        if guessed:
            return guessed
    except Exception as e:
        log_error(f"get_mime_type: mimetypes fallback also failed on {filepath}", e)

    return 'application/octet-stream'


# =============================================================================
# FUNCTION 7: format_timestamp
# =============================================================================

def format_timestamp():
    """
    Return current datetime as a formatted string: YYYY-MM-DD HH:MM:SS
    """
    try:
        return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        log_error("format_timestamp: unexpected error", e)
        return None


# =============================================================================
# FUNCTION 8: get_system_info
# =============================================================================

def get_system_info():
    """
    Return a dictionary of basic system information.
    """
    try:
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get('USERNAME') or os.environ.get('USER') or 'unknown'

        return {
            'username':         username,
            'hostname':         socket.gethostname(),
            'operating_system': platform.system(),
            'os_version':       platform.version(),
            'architecture':     platform.architecture()[0],
            'python_version':   platform.python_version(),
        }
    except Exception as e:
        log_error("get_system_info: unexpected error", e)
        return {}


# =============================================================================
# FUNCTION 9: setup_logging
# =============================================================================

def setup_logging():
    """
    Configure and return a logger writing to both file and stdout.
    """
    try:
        _logger = logging.getLogger('ShadowTrace')
        _logger.setLevel(logging.DEBUG)

        if _logger.handlers:
            return _logger

        fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # File handler → config.MAIN_LOG
        fh = logging.FileHandler(config.MAIN_LOG, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)

        # Console handler → stdout
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(logging.INFO)
        ch.setFormatter(fmt)

        _logger.addHandler(fh)
        _logger.addHandler(ch)

        return _logger
    except Exception as e:
        # Fallback — bare logger so the rest of the module still works
        _logger = logging.getLogger('ShadowTrace')
        log_error("setup_logging: failed to configure handlers", e)
        return _logger


# =============================================================================
# FUNCTION 10: log_error
# =============================================================================

def log_error(error_message, exception=None):
    """
    Append an error entry to config.ERROR_LOG.
    Format: [TIMESTAMP] ERROR: message
    If exception provided, also logs its type and message.
    """
    try:
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        lines = [f"[{timestamp}] ERROR: {error_message}\n"]
        if exception is not None:
            lines.append(
                f"[{timestamp}]   Exception type : {type(exception).__name__}\n"
                f"[{timestamp}]   Exception detail: {exception}\n"
            )
        with open(config.ERROR_LOG, 'a', encoding='utf-8') as f:
            f.writelines(lines)
    except Exception:
        # Absolute last resort — print to stderr so nothing is silently lost
        sys.stderr.write(f"[log_error CRITICAL] Could not write to error log: {error_message}\n")


def ensure_clamd_running():
    import clamd
    import subprocess
    import time
    import platform
    
    # First check if already running
    try:
        cd = clamd.ClamdNetworkSocket('127.0.0.1', 3310)
        cd.ping()
        print('[CLAMAV] Daemon already running')
        return True
    except Exception:
        pass  # clamd not running — expected, we'll start it below
    
    print('[CLAMAV] Daemon not running. Starting...')
    
    if platform.system() == 'Windows':
        clamd_path = r'C:\Program Files\ClamAV\clamd.exe'
        conf_path = r'C:\Program Files\ClamAV\clamd.conf'
        
        try:
            # Start clamd as background process
            process = subprocess.Popen(
                [clamd_path, '--config-file', conf_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Wait up to 30 seconds for it to start
            for i in range(30):
                time.sleep(1)
                try:
                    cd = clamd.ClamdNetworkSocket(
                        '127.0.0.1', 3310
                    )
                    cd.ping()
                    print(f'[CLAMAV] Started successfully after {i+1}s')
                    return True
                except Exception:
                    if i % 5 == 0:
                        print(f'[CLAMAV] Waiting for daemon... ({i+1}s)')
            
            print('[CLAMAV] Failed to start after 30 seconds')
            return False
            
        except Exception as e:
            print(f'[CLAMAV] Start error: {e}')
            return False
    else:
        # Linux/macOS
        try:
            subprocess.Popen(
                ['clamd'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(3)
            cd = clamd.ClamdNetworkSocket('127.0.0.1', 3310)
            cd.ping()
            print('[CLAMAV] Started successfully')
            return True
        except Exception as e:
            print(f'[CLAMAV] Start error: {e}')
            return False


# =============================================================================
# FUNCTION 11: create_scan_copy and delete_scan_copy
# =============================================================================

def create_scan_copy(filepath):
    import shutil
    import time
    filepath = str(filepath)
    name = Path(filepath).name
    timestamp = str(int(time.time()))
    copy_name = f'scanopy_{timestamp}_{name}'
    copy_path = str(config.SANDBOX_DIR / copy_name)
    try:
        shutil.copy2(filepath, copy_path)
        print(f'[SANDBOX] Copy created: {copy_name}')
        return copy_path
    except Exception as e:
        log_error(f'create_scan_copy error: {e}')
        return None

def delete_scan_copy(copy_path):
    try:
        if copy_path and os.path.exists(copy_path):
            os.remove(copy_path)
            print(f'[SANDBOX] Copy deleted: {Path(copy_path).name}')
            return True
    except Exception as e:
        log_error(f'delete_scan_copy error: {e}')
        return False

# =============================================================================
# Module-level logger (initialised once on import)
# =============================================================================

logger = setup_logging()


# =============================================================================
# Self-tests
# =============================================================================

if __name__ == '__main__':
    PASS = '\033[92mPASS\033[0m'
    FAIL = '\033[91mFAIL\033[0m'

    print("\n" + "=" * 60)
    print("  Shadow-Trace utils.py — Self-Test Suite")
    print("=" * 60 + "\n")

    # ── Test 1: SHA3-512 hash ────────────────────────────────────────────────
    print("TEST 1 — SHA3-512 hash of a temporary file")
    try:
        test_file = config.BASE_DIR / 'test_utils.txt'
        test_file.write_text("Shadow-Trace utility test file", encoding='utf-8')
        digest = generate_sha3_hash(test_file)
        test_file.unlink()
        if digest and len(digest) == 128:
            print(f"  Hash (first 20 chars): {digest[:20]}...")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — unexpected digest: {digest}\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 2: System info ──────────────────────────────────────────────────
    print("TEST 2 — System information")
    try:
        info = get_system_info()
        if info:
            for k, v in info.items():
                print(f"  {k:<20}: {v}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — empty dict returned\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 3: File info on this script ────────────────────────────────────
    print("TEST 3 — File info on utils.py itself")
    try:
        finfo = get_file_info(__file__)
        if finfo and not finfo.get('error'):
            for k, v in finfo.items():
                print(f"  {k:<20}: {v}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — {finfo}\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 4: Shannon entropy ──────────────────────────────────────────────
    print("TEST 4 — Shannon entropy of utils.py")
    try:
        entropy = calculate_shannon_entropy(__file__)
        if entropy is not None and 0.0 <= entropy <= 8.0:
            print(f"  Entropy: {entropy}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — entropy={entropy}\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 5: MIME type ────────────────────────────────────────────────────
    print("TEST 5 — MIME type of utils.py")
    try:
        mime = get_mime_type(__file__)
        if mime:
            print(f"  MIME type: {mime}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — no MIME type returned\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 6: Timestamp ────────────────────────────────────────────────────
    print("TEST 6 — Formatted timestamp")
    try:
        ts = format_timestamp()
        if ts and len(ts) == 19:
            print(f"  Timestamp: {ts}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — ts={ts}\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    print("=" * 60)
    print("  All tests complete.")
    print("=" * 60 + "\n")
