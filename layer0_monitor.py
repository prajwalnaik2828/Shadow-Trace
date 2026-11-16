# =============================================================================
# Shadow-Trace | layer0_monitor.py
# Real-time monitor for the Downloads folder. Intercepts files as soon as
# they finish downloading, locks them, and kicks off the scanning pipeline.
# =============================================================================

import os
import time
import platform
import threading
import traceback
import concurrent.futures
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from layer3_extraction import run_extraction
try:
    from layer4_explainability import run_explainability
except Exception:
    run_explainability = None
from layer4_report import generate_forensic_report

try:
    from plyer import notification
except ImportError:
    notification = None

import config
import utils
import recovery_database
import chain_of_custody
import url_server
import settings_manager

try:
    from layer1_malware import run_malware_screening
    _LAYER1_AVAILABLE = True
except Exception as _layer1_import_err:
    _LAYER1_AVAILABLE = False
    print(f'[WARNING] Layer 1 import failed - stub pipeline will be used: {_layer1_import_err}')

# =============================================================================
# Globals
# =============================================================================

currently_processing = set()
_processing_lock = threading.Lock()
known_files = set()
pipeline_callback = None
_observer_instance = None
_monitor_running = False
_event_handler = None
_active_watches = {}


# =============================================================================
# Helper Functions
# =============================================================================

def set_pipeline_callback(callback_function):
    """
    Called by main.py to connect the real scanning pipeline to Layer 0.
    """
    global pipeline_callback
    pipeline_callback = callback_function
    print("Pipeline connected to Layer 0 monitor")


def safe_coc_call(func, *args, timeout=5):
    """
    Guars against database calls hanging indefinitely and locking up the thread.
    """
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args)
            return future.result(timeout=timeout)
    except concurrent.futures.TimeoutError:
        print(f'[WARNING] Database call timed out: {func.__name__}')
        return None
    except Exception as e:
        print(f'[WARNING] Database call failed: {func.__name__} - {e}')
        return None


SKIP_EXTENSIONS = {
    '.tmp', '.crdownload', '.part', '.partial',
    '.opdownload', '.!ut', '.idt', '.aria2',
    '.download', '.dwnl', '.incomplete'
}

SKIP_PREFIXES = {'.', '~'}

def should_skip_file(filepath):
    name = Path(filepath).name
    suffix = Path(filepath).suffix.lower()
    
    # Skip temp extensions
    if suffix in SKIP_EXTENSIONS:
        print(f'[DEBUG] Skipping temp file: {name}')
        return True
    
    # Skip hidden files
    for prefix in SKIP_PREFIXES:
        if name.startswith(prefix):
            print(f'[DEBUG] Skipping hidden file: {name}')
            return True
    
    # Skip .shadowtrace_scanning files
    if '.shadowtrace_scanning' in name:
        return True
    
    # Do NOT skip PDF, JPG, PNG, MP4 or any 
    # real file extension
    return False


def _wait_for_download_complete(filepath, timeout=300):
    print(f'[DEBUG] Waiting for download to complete: {Path(filepath).name}')
    
    import time
    start_time = time.time()
    check_interval = 0.5
    last_print_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            if not os.path.exists(filepath):
                time.sleep(check_interval)
                continue
            
            current_size = os.path.getsize(filepath)
            
            if current_size == 0:
                time.sleep(check_interval)
                continue
            
            # Use longer intervals for large files
            if current_size > 50 * 1024 * 1024:  # >50MB
                check_interval = 3.0
            elif current_size > 10 * 1024 * 1024:  # >10MB
                check_interval = 1.0
            else:
                check_interval = 0.5
            
            # Print progress every 10 seconds
            if time.time() - last_print_time > 10:
                elapsed = time.time() - start_time
                name = Path(filepath).name
                print(f'[DEBUG] Still waiting for download: {name} ({elapsed:.0f}s elapsed, current size: {current_size} bytes)')
                last_print_time = time.time()
            
            time.sleep(check_interval)
            
            if not os.path.exists(filepath):
                return False
            
            new_size = os.path.getsize(filepath)
            
            if new_size == current_size and current_size > 0:
                print(f'[DEBUG] Download complete: {Path(filepath).name} ({current_size} bytes)')
                return True
                
        except Exception as e:
            time.sleep(0.5)

    print(f'[DEBUG] Wait timeout for: {Path(filepath).name}')
    return False


def _scan_worker_loop(first_filepath):
    import scan_tracker
    curr_file = first_filepath
    while curr_file:
        try:
            _process_new_file(curr_file)
        except Exception as e:
            print(f'[MONITOR] Worker error on {curr_file}: {e}')
        finally:
            with _processing_lock:
                currently_processing.discard(curr_file)
            curr_file = scan_tracker.finish_scan(curr_file)

def _dispatch_scan(filepath):
    import scan_tracker
    name = Path(filepath).name
    with _processing_lock:
        if filepath in currently_processing:
            print(f'[DEBUG] Already processing: {name}')
            return
        currently_processing.add(filepath)
    should_start = scan_tracker.enqueue(filepath)
    if should_start:
        thread = threading.Thread(
            target=_scan_worker_loop,
            args=(filepath,),
            name=f'scan_{name}',
            daemon=True
        )
        thread.start()
        print(f'[DEBUG] Scan thread started for: {name}')
    else:
        print(f'[DEBUG] Queued file for scan: {name}')

# =============================================================================
# Event Handlers and Polling
# =============================================================================

class ShadowTraceEventHandler(FileSystemEventHandler):

    def on_created(self, event):
        print(f'[DEBUG] Watchdog event: {event.src_path}')
        
        try:
            if event.is_directory:
                return

            filepath = event.src_path
            name = Path(filepath).name

            # Skip if file was already picked up by on_moved
            if filepath in currently_processing:
                print(f'[DEBUG] Skipping - already being processed by on_moved: {name}')
                return

            # For files that just appeared via move,
            # on_moved already handles them.
            # Wait briefly to see if on_moved claimed it.
            time.sleep(0.1)
            if filepath in currently_processing:
                print(f'[DEBUG] on_created: already claimed by on_moved: {name}')
                return

            if should_skip_file(filepath):
                return

            print(f'[DEBUG] on_created claimed: {name}')
            _dispatch_scan(filepath)

        except Exception as e:
            utils.log_error("ShadowTraceEventHandler.on_created error", e)

    def on_moved(self, event):
        try:
            if event.is_directory:
                return
            
            dest_path = event.dest_path
            name = Path(dest_path).name
            
            print(f'[DEBUG] Watchdog MOVE event: {name}')
            
            # Skip temp files
            if should_skip_file(dest_path):
                return
            
            # Also update known_files for polling
            global known_files
            known_files.add(dest_path)
            
            print(f'[STEP 1] Processing started for: {name} (via Save Dialog)')
            _dispatch_scan(dest_path)
        except Exception as e:
            utils.log_error("ShadowTraceEventHandler.on_moved error", e)

    def on_modified(self, event):
        try:
            if event.is_directory:
                return
                
            filepath = event.src_path
            
            if filepath not in currently_processing:
                return
                
            # With exclusive Windows API handles, the file is safely locked 
            # for the duration of processing. Relocking on_modified creates 
            # infinite loops because icacls fires modification events and 
            # os.access() ignores ACLs on Windows.
            pass
                
        except Exception as e:
            utils.log_error("ShadowTraceEventHandler.on_modified error", e)

    def on_deleted(self, event):
        try:
            filepath = event.src_path
            if filepath in currently_processing:
                currently_processing.remove(filepath)
        except Exception as e:
            utils.log_error("ShadowTraceEventHandler.on_deleted error", e)


def _polling_monitor():
    """
    Fallback monitor to catch any files missed by Watchdog events.
    """
    global known_files
    last_log_time = 0
    
    while True:
        try:
            now = time.time()
            if now - last_log_time >= 10:
                # Polling health log every 10 seconds
                last_log_time = now

            for directory in config.get_monitored_dirs():
                for filename in os.listdir(directory):
                    filepath = str(directory / filename)
                    
                    if filepath not in known_files:
                        # New file found by polling
                        known_files.add(filepath)
                        
                        if not os.path.exists(filepath):
                            continue
                            
                        if not os.path.isdir(filepath) and not should_skip_file(filepath):
                            try:
                                mtime = os.path.getmtime(filepath)
                                age_seconds = now - mtime
                                if age_seconds < 30:  # Only process files newer than 30 seconds
                                    print(f'[POLL] New recent file: {Path(filepath).name} (age: {age_seconds:.1f}s)')
                                    _dispatch_scan(filepath)
                            except Exception as e:
                                pass

        except Exception as e:
            utils.log_error("_polling_monitor error", e)

        time.sleep(3)


# =============================================================================
# Processing logic
# =============================================================================

def check_previous_scan(
    sha3_hash: str,
    db_path: str
) -> dict:
    import sqlite3
    from pathlib import Path
    
    try:
        if not Path(db_path).exists():
            return {'found': False}
        
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table'"
        )
        tables = [r[0] for r in cursor.fetchall()]
        
        previous = None
        for table in tables:
            try:
                cursor.execute(
                    f"PRAGMA table_info({table})"
                )
                cols = [
                    r[1] for r in cursor.fetchall()
                ]
                
                if ('sha3_hash' in cols
                        and 'status' in cols):
                    cursor.execute(
                        f"SELECT * FROM {table} "
                        f"WHERE sha3_hash=? "
                        f"AND status='COMPLETE' "
                        f"ORDER BY id DESC LIMIT 1",
                        (sha3_hash,)
                    )
                    row = cursor.fetchone()
                    if row:
                        previous = dict(row)
                        break
                
                elif 'sha3_hash' in cols:
                    cursor.execute(
                        f"SELECT * FROM {table} "
                        f"WHERE sha3_hash=? "
                        f"ORDER BY id DESC LIMIT 1",
                        (sha3_hash,)
                    )
                    row = cursor.fetchone()
                    if row:
                        previous = dict(row)
                        break
            except Exception:
                continue
        
        conn.close()
        
        if not previous:
            return {'found': False}
        
        return {
            'found': True,
            'session_id': previous.get(
                'session_id', ''
            ),
            'verdict': previous.get(
                'verdict',
                previous.get('status', 'UNKNOWN')
            ),
            'filepath': previous.get(
                'filepath', ''
            ),
            'scanned_at': previous.get(
                'created_at',
                previous.get('updated_at', '')
            ),
        }
    
    except Exception as e:
        print('[DEDUP] Check error: ' + str(e))
        return {'found': False}

def handle_duplicate_file(
    filepath,
    previous_scan: dict,
):
    from pathlib import Path
    
    filename = Path(filepath).name
    prev_verdict = previous_scan.get(
        'verdict', 'UNKNOWN'
    ).upper()
    prev_date = str(
        previous_scan.get('scanned_at', '')
    )[:16]
    prev_session = previous_scan.get(
        'session_id', ''
    )[:8]
    
    print('[LAYER0] DUPLICATE FILE DETECTED')
    print('[LAYER0] File: ' + filename)
    print('[LAYER0] Previously scanned: '
          + prev_date)
    print('[LAYER0] Previous verdict: '
          + prev_verdict)
    print('[LAYER0] Previous session: '
          + prev_session + '...')
    
    if prev_verdict in ['SUSPICIOUS',
                        'STEGO_DETECTED',
                        'THREAT']:
        print('[LAYER0] WARNING: This file was '
              'previously flagged as '
              + prev_verdict)
        print('[LAYER0] Opening previous report...')
        
        try:
            import subprocess
            subprocess.Popen([
                'powershell', '-Command',
                'Add-Type -AssemblyName '
                'System.Windows.Forms;'
                '[System.Windows.Forms.'
                'MessageBox]::Show('
                '"' + filename + ' was '
                'previously flagged as '
                + prev_verdict + ' on '
                + prev_date + '. '
                'Review previous report '
                'before proceeding.",'
                '"Shadow-Trace: Previously '
                'Flagged File Detected",'
                '"OK",'
                '"Warning")',
            ])
        except Exception:
            pass
        
        return True
    
    else:
        print('[LAYER0] Previously scanned '
              'as ' + prev_verdict)
        print('[LAYER0] Skipping rescan. '
              'Use manual scan to force rescan.')
        
        try:
            import subprocess
            subprocess.Popen([
                'powershell', '-Command',
                'Add-Type -AssemblyName '
                'System.Windows.Forms;'
                '[System.Windows.Forms.'
                'MessageBox]::Show('
                '"' + filename + ' was '
                'previously scanned on '
                + prev_date + ' (verdict: '
                + prev_verdict + '). '
                'No rescan needed.",'
                '"Shadow-Trace: Duplicate '
                'File",'
                '"OK",'
                '"Information")',
            ])
        except Exception:
            pass
        
        return False

_global_yara_rules = None
def _get_yara_rules():
    global _global_yara_rules
    if _global_yara_rules is None:
        try:
            from layer1_yara import get_compiled_rules
            _global_yara_rules = get_compiled_rules()
        except Exception:
            pass
    return _global_yara_rules

def _perform_hash_reconfirmation(filepath, session_id, sha3_hash, multi_hash, steg_result):
    print('[PIPELINE] Unlocking original file...')
    utils.unlock_file(filepath)
    print('[PIPELINE] File unlocked.')
    print('[PIPELINE] Running final hash reconfirmation...')
    print('[PIPELINE] Reconfirming across complete investigation period...')
    try:
        from utils import compute_multi_hash
        from datetime import datetime, timezone
        final_hashes = compute_multi_hash(str(filepath))
        
        init_sha3 = multi_hash.get('sha3_512') if multi_hash else sha3_hash
        init_sha256 = multi_hash.get('sha256') if multi_hash else None
        init_md5 = multi_hash.get('md5') if multi_hash else None

        if multi_hash and final_hashes.get('success'):
            sha3_match = (final_hashes['sha3_512'] == init_sha3)
            sha256_match = (final_hashes['sha256'] == init_sha256)
            md5_match = (final_hashes['md5'] == init_md5)
            all_match = (sha3_match and sha256_match and md5_match)
        elif sha3_hash and final_hashes.get('success'):
            sha3_match = (final_hashes['sha3_512'] == sha3_hash)
            sha256_match = None
            md5_match = None
            all_match = sha3_match
        else:
            all_match = False
            sha3_match = False
            sha256_match = None
            md5_match = None

        print('[PIPELINE] SHA3-512 (PRIMARY): ' + ('✓ CONFIRMED' if sha3_match else '✗ MISMATCH — CRITICAL'))
        if sha256_match is not None:
            print('[PIPELINE] SHA-256:            ' + ('✓ CONFIRMED' if sha256_match else '✗ MISMATCH'))
        if md5_match is not None:
            print('[PIPELINE] MD5:                ' + ('✓ CONFIRMED' if md5_match else '✗ MISMATCH'))

        reconfirmation = {
            'sha3_512_match': sha3_match,
            'sha256_match': sha256_match,
            'md5_match': md5_match,
            'all_match': all_match,
            'primary_confirmed': sha3_match,
            'status': ('CONFIRMED' if all_match else 'FAILED'),
            'initial_sha3_512': init_sha3,
            'initial_sha256': init_sha256,
            'initial_md5': init_md5,
            'final_sha3_512': final_hashes.get('sha3_512'),
            'final_sha256': final_hashes.get('sha256'),
            'final_md5': final_hashes.get('md5'),
            'reconfirmed_at': datetime.now(timezone.utc).isoformat(),
            'forensic_statement': (
                'SHA3-512 is the primary integrity algorithm. Hashes were computed on '
                'the original file before processing and recomputed after the file was '
                'unlocked following completion of all pipeline layers. Matching values '
                'confirm the original evidence file was not modified during investigation.'
                if all_match else
                'INTEGRITY FAILURE: Hash values do not match. The original file may '
                'have been modified. This result must not be used as forensic evidence.'
            ),
        }
        steg_result['hash_reconfirmation'] = reconfirmation
        try:
            import chain_of_custody as coc_module
            coc_module.log_action(session_id, filepath, sha3_hash, 'INTEGRITY_RECONFIRMED', 'SUCCESS' if all_match else 'CRITICAL', str(reconfirmation))
        except Exception:
            pass
        return reconfirmation
    except Exception as e:
        print('[PIPELINE] Reconfirmation error: ' + str(e))
        reconfirmation = {
            'status': 'ERROR',
            'error': str(e),
            'all_match': None,
            'primary_confirmed': None,
        }
        steg_result['hash_reconfirmation'] = reconfirmation
        return reconfirmation

def _process_new_file(filepath):
    session_id = None
    sha3_hash = None
    file_locked = False
    
    try:
        name = Path(filepath).name
        print(f'[STEP 1] Processing: {name}')
        try:
            import scan_tracker
            scan_tracker.update_stage(1, "Initialization", 15)
        except Exception:
            pass
        
        try:
            from ui.tray_agent import update_tray_status
            update_tray_status('scanning', name)
        except Exception:
            pass
        
        # STEP 2: Wait for download to complete FIRST
        completed = _wait_for_download_complete(filepath)
        if not completed:
            print(f'[SKIP] Download wait timeout: {name}')
            currently_processing.discard(filepath)
            return
        
        print('[LAYER0] Step 1: Computing initial hashes...')
        try:
            from utils import compute_multi_hash
            multi_hash = compute_multi_hash(str(filepath))
            sha3_hash = multi_hash.get('sha3_512') if multi_hash.get('success') else None
            if not sha3_hash:
                sha3_hash = 'HASH_UNAVAILABLE_' + str(time.time())
        except Exception as e:
            print(f'[LAYER0] Hash error: {e}')
            multi_hash = None
            sha3_hash = 'HASH_ERROR_' + str(time.time())

        print('[LAYER0] Checking for previous scan...')
        from config import BASE_DIR
        db_path = str(BASE_DIR / 'shadowtrace_recovery.db')
        previous = check_previous_scan(sha3_hash, db_path)
        
        if previous.get('found'):
            should_continue = handle_duplicate_file(filepath, previous)
            if not should_continue:
                print('[LAYER0] Skipping pipeline for duplicate clean file.')
                currently_processing.discard(filepath)
                return
            else:
                print('[LAYER0] Proceeding with pipeline for previously flagged file.')
        else:
            print('[LAYER0] New file confirmed. Proceeding with full pipeline.')

        print('[LAYER0] Step 2: Creating sandbox copy...')
        scan_copy_path = utils.create_scan_copy(filepath)

        print('[LAYER0] Step 3: Locking original file...')
        lock_success = utils.lock_file(filepath)
        if lock_success:
            file_locked = True
            time.sleep(0.5)
            if utils.verify_lock(filepath):
                print(f'[LAYER0] File locked and verified')
            else:
                print(f'[LAYER0] Lock applied but verification inconclusive')
                file_locked = True
        else:
            print(f'[LAYER0] Lock failed - continuing anyway')
        
        # STEP 5: Get source URL
        try:
            source_url = 'URL_NOT_CAPTURED'
            import re
            try:
                with open(filepath + ':Zone.Identifier', 'r', encoding='utf-8', errors='ignore') as zf:
                    z_content = zf.read()
                    m = re.search(r'HostUrl=(.+)', z_content)
                    if m and m.group(1).strip() != 'about:internet':
                        source_url = m.group(1).strip()
                    else:
                        m2 = re.search(r'ReferrerUrl=(.+)', z_content)
                        if m2:
                            source_url = m2.group(1).strip()
            except Exception:
                pass
                
            if source_url == 'URL_NOT_CAPTURED':
                cached_url = url_server.get_url_for_file(name)
                if cached_url and cached_url != 'URL_NOT_CAPTURED':
                    source_url = cached_url
                    
            print(f'[STEP 5] URL: {source_url}')
        except Exception as e:
            source_url = 'URL_NOT_CAPTURED'
            print(f'[STEP 5] URL error: {e}')
        
        # STEP 6: Open chain of custody session
        try:
            session_id = safe_coc_call(
                chain_of_custody.open_session,
                filepath, sha3_hash, source_url
            )
            if session_id:
                print(f'[STEP 6] CoC session: {session_id[:8]}...')
            else:
                session_id = 'EMERGENCY_' + str(int(time.time()))
                print(f'[STEP 6] CoC unavailable - emergency ID assigned')
        except Exception as e:
            session_id = 'EMERGENCY_' + str(int(time.time()))
            print(f'[STEP 6] CoC error: {e}')
            
        correlation_data = None
        try:
            # Network correlation first (URL/domain from DNS/TCP/extension)
            from network_monitor import correlate_file_to_url
            network_correlation = correlate_file_to_url(
                str(filepath), session_id
            )
            if network_correlation.get('detected_url'):
                print('[LAYER0] URL detected via '
                      + str(network_correlation.get('method'))
                      + ' (confidence: '
                      + str(network_correlation.get('confidence')) + ')')

            # File-metadata correlation (ADS zone, double-ext, etc.)
            from source_correlation import build_source_correlation
            file_correlation = build_source_correlation(
                str(filepath), session_id
            )

            # Merge: network result is authoritative for URL fields
            correlation_data = file_correlation
            correlation_data['network_correlation'] = network_correlation
            correlation_data['detected_url'] = (
                network_correlation.get('detected_url')
                or file_correlation.get('url_analysis', {}).get('url')
            )
            correlation_data['detected_domain'] = (
                network_correlation.get('detected_domain')
            )
            correlation_data['url_confidence'] = (
                network_correlation.get('confidence', 'NONE')
            )
            correlation_data['url_method'] = (
                network_correlation.get('method', 'none')
            )

            risk = correlation_data.get('correlation_risk', 'NONE')
            flags = correlation_data.get('total_flags', 0)

            if risk in ['HIGH', 'MEDIUM'] and flags > 0:
                print('[LAYER0] Source correlation risk: ' + risk)
                for flag in correlation_data.get('correlation_flags', []):
                    if flag.get('severity') in ['HIGH', 'MEDIUM']:
                        print('[LAYER0]   ['
                              + flag['severity'] + '] '
                              + flag['flag'])

            # Persist URL to chain-of-custody if found
            detected_url = correlation_data.get('detected_url')
            if detected_url:
                try:
                    import chain_of_custody as coc_module
                    if hasattr(coc_module, 'update_session_url'):
                        coc_module.update_session_url(
                            session_id, detected_url
                        )
                except Exception:
                    pass

        except Exception as e:
            print('[LAYER0] Correlation warning: ' + str(e))
            correlation_data = None

        
        # STEP 7: Update recovery database
        try:
            safe_coc_call(
                recovery_database.register_file,
                filepath, sha3_hash, 'LAYER_0_COMPLETE'
            )
            print(f'[STEP 7] Recovery DB updated')
        except Exception as e:
            print(f'[STEP 7] Recovery DB error: {e}')
        
        # STEP 8: Desktop notification
        try:
            if notification:
                notification.notify(
                    title='Shadow-Trace',
                    message=f'Scanning: {name}',
                    app_name='Shadow-Trace',
                    timeout=3
                )
                print(f'[STEP 8] Notification sent')
        except Exception as e:
            print(f'[STEP 8] Notification skipped: {e}')
        
        print(f'[STEP 9] Starting pipeline...')
        
    except Exception as e:
        print(f'[ERROR] Setup error: {e}')
        import traceback
        traceback.print_exc()
        try:
            from user_prompt import notify_error_popup
            notify_error_popup(
                title="Pipeline Setup Error",
                reason=str(e),
                filename=name,
                stage="Setup & Initial Hashing"
            )
        except Exception:
            pass
    
    finally:
        # ALWAYS run pipeline - file must always be unlocked
        try:
            if pipeline_callback is not None:
                try:
                    import scan_tracker
                    scan_tracker.update_stage(2, "Signature Analysis", 35)
                except Exception:
                    pass
                layer1_result = pipeline_callback(
                    filepath,
                    session_id or 'UNKNOWN',
                    sha3_hash or 'UNKNOWN',
                    scan_copy_path,
                    multi_hash=multi_hash if 'multi_hash' in locals() else None
                )
                
                if layer1_result and layer1_result.get('verdict') == 'ERROR':
                    try:
                        from user_prompt import notify_error_popup
                        notify_error_popup(
                            title="Malware Scan Error",
                            reason=str(layer1_result.get('error') or layer1_result.get('reason') or "Layer 1 scan failure"),
                            filename=name,
                            stage="Layer 1 Malware Screening"
                        )
                    except Exception:
                        pass

                if layer1_result and layer1_result.get('verdict') == 'CLEAN':
                    # LAYER 1.5
                    print('[LAYER0] Layer 1 clean. Calling Layer 1.5 LSB check...')
                    try:
                        import scan_tracker
                        scan_tracker.update_stage(3, "Heuristic Scanning", 55)
                    except Exception:
                        pass
                    from layer1_5_lsb_check import run_lsb_executable_check
                    yara_rules = _get_yara_rules()
                    lsb_result = run_lsb_executable_check(filepath, session_id or 'UNKNOWN', sha3_hash or 'UNKNOWN', scan_target=scan_copy_path, yara_rules=yara_rules)
                    
                    auto_escalate = lsb_result.get('auto_escalate', False)
                    lsb_verdict = lsb_result.get('verdict', 'CLEAN')
                    
                    if auto_escalate or lsb_verdict == 'EXECUTABLE_FOUND':
                        print(f'[LAYER0] THREAT DETECTED: Auto-escalating to Layer 2')
                        try:
                            import scan_tracker
                            scan_tracker.update_stage(4, "Steganography Detection", 75)
                        except Exception:
                            pass
                        from layer2_steganalysis import run_steganalysis
                        from user_prompt import notify_steg_result
                        steg_result = run_steganalysis(filepath, session_id or 'UNKNOWN', sha3_hash or 'UNKNOWN', scan_target=scan_copy_path)
                        steg_result['file_hashes'] = multi_hash if 'multi_hash' in locals() else None
                        if layer1_result:
                            reconf_res = layer1_result.get('stage1_hash')
                            if not reconf_res and layer1_result.get('all_scan_results'):
                                reconf_res = layer1_result['all_scan_results'].get('hash_reconfirmation')
                            if reconf_res:
                                steg_result['hash_reconfirmation'] = reconf_res
                        steg_result['lsb_check_result'] = lsb_result
                        
                        if correlation_data is not None:
                            steg_result['source_correlation'] = correlation_data
                            steg_result['source_url'] = (
                                correlation_data
                                .get('url_analysis', {})
                                .get('url', None)
                            )
                        
                        layer2_verdict = steg_result.get('verdict', 'CLEAN')
                        if layer2_verdict in ['STEGO_DETECTED', 'SUSPICIOUS']:
                            print('[LAYER3] Layer 2 flagged file. Starting payload extraction...')
                            try:
                                layer3_result = run_extraction(
                                    filepath=filepath,
                                    session_id=session_id or 'UNKNOWN',
                                    sha3_hash=sha3_hash or 'UNKNOWN',
                                    layer2_result=steg_result,
                                    roi_coords=None
                                )
                                steg_result['layer3_extraction'] = layer3_result
                                
                                is_exe = layer3_result.get(
                                    'extraction_results', {}
                                ).get('is_executable', False)
                                
                                if is_exe:
                                    print('[LAYER3] !!! EXECUTABLE PAYLOAD CONFIRMED !!!')
                                    print('[SHADOW-TRACE] CRITICAL THREAT: Hidden executable extracted')
                                else:
                                    payload_type = layer3_result.get(
                                        'extraction_results', {}
                                    ).get('payload_type', 'Unknown')
                                    print('[LAYER3] Payload type: ' + str(payload_type))
                                    
                            except Exception as e:
                                print('[LAYER3] Extraction error: ' + str(e))
                                steg_result['layer3_extraction'] = {'error': str(e)}
                        else:
                            print('[LAYER3] File clean, skipping payload extraction')
                            steg_result['layer3_extraction'] = None

                        if layer2_verdict in ['STEGO_DETECTED', 'SUSPICIOUS'] and settings_manager.get_setting('auto_quarantine_stego', False):
                            try:
                                import layer1_malware
                                q_path = layer1_malware.quarantine_file(
                                    filepath,
                                    session_id or 'UNKNOWN',
                                    sha3_hash or 'UNKNOWN',
                                    {'engine': 'Layer2_Steganalysis', 'verdict': layer2_verdict, 'score': steg_result.get('score')}
                                )
                                print(f'[STEGO-QUARANTINE] File quarantined to vault: {q_path}')
                                steg_result['quarantine_path'] = q_path
                            except Exception as q_err:
                                print(f'[STEGO-QUARANTINE] Quarantine error: {q_err}')
                            
                        print('[LAYER4] Starting explainability and report generation...')
                        try:
                            import scan_tracker
                            scan_tracker.update_stage(5, "Report Generation", 95)
                        except Exception:
                            pass
                        
                        layer3_data = steg_result.get('layer3_extraction')
                        
                        xai_result = run_explainability(
                            filepath=filepath,
                            layer2_result=steg_result,
                            layer3_result=layer3_data,
                            session_id=session_id
                        )
                        steg_result['layer4_xai'] = xai_result
                        
                        try:
                            import chain_of_custody as coc_module
                            coc_log = coc_module.get_session_log(session_id)
                        except Exception:
                            coc_log = None
                        
                        layer1_data = layer1_result
                        
                        calibration_data = None
                        try:
                            from confidence_calibration import calibrate_result
                            file_type = steg_result.get('file_type', 'IMAGE')
                            lsb_data = steg_result.get(
                                'lsb_check_result',
                                steg_result.get('lsb_result', None)
                            )
                            calibration_data = calibrate_result(
                                layer1_result=layer1_data,
                                layer2_result=steg_result,
                                layer3_result=layer3_data,
                                lsb_result=lsb_data,
                                file_type=file_type,
                            )
                            steg_result['calibration'] = calibration_data
                        except Exception as e:
                            print('[LAYER0] Calibration warning: ' + str(e))
                            calibration_data = None

                        print('[PIPELINE] Unlocking original file...')
                        utils.unlock_file(filepath)
                        print('[PIPELINE] File unlocked.')
                        print('[PIPELINE] Running final hash reconfirmation...')
                        print('[PIPELINE] Reconfirming across complete investigation period...')
                        
                        try:
                            from utils import compute_multi_hash
                            from datetime import datetime, timezone
                            final_hashes = compute_multi_hash(str(filepath))
                            
                            if multi_hash and final_hashes.get('success'):
                                sha3_match = (final_hashes['sha3_512'] == multi_hash.get('sha3_512'))
                                sha256_match = (final_hashes['sha256'] == multi_hash.get('sha256'))
                                md5_match = (final_hashes['md5'] == multi_hash.get('md5'))
                                all_match = (sha3_match and sha256_match and md5_match)
                                
                                print('[PIPELINE] SHA3-512 (PRIMARY): ' + ('✓ CONFIRMED' if sha3_match else '✗ MISMATCH — CRITICAL'))
                                print('[PIPELINE] SHA-256:            ' + ('✓ CONFIRMED' if sha256_match else '✗ MISMATCH'))
                                print('[PIPELINE] MD5:                ' + ('✓ CONFIRMED' if md5_match else '✗ MISMATCH'))
                                
                                if not sha3_match:
                                    print('[PIPELINE] CRITICAL: Primary integrity hash (SHA3-512) does not match.')
                                    print('[PIPELINE] Original file may have been modified during investigation.')
                                    print('[PIPELINE] This result must NOT be used as forensic evidence.')
                                elif sha3_match and not all_match:
                                    print('[PIPELINE] NOTE: Primary SHA3-512 confirmed. Secondary hash mismatch may indicate hash computation error.')
                                    
                                if all_match:
                                    print('[PIPELINE] ✓ FULL INTEGRITY CONFIRMED')
                                    print('[PIPELINE] Original file unchanged across complete investigation.')
                                    
                            elif sha3_hash and final_hashes.get('success'):
                                sha3_match = (final_hashes['sha3_512'] == sha3_hash)
                                sha256_match = None
                                md5_match = None
                                all_match = sha3_match
                                
                                print('[PIPELINE] SHA3-512 (PRIMARY): ' + ('✓ CONFIRMED' if sha3_match else '✗ MISMATCH — CRITICAL'))
                                print('[PIPELINE] SHA-256: Not available for comparison')
                                print('[PIPELINE] MD5: Not available for comparison')
                            else:
                                all_match = False
                                sha3_match = False
                                sha256_match = None
                                md5_match = None
                                print('[PIPELINE] No initial hash available for comparison.')
                                
                            reconfirmation = {
                                'sha3_512_match': sha3_match,
                                'sha256_match': sha256_match,
                                'md5_match': md5_match,
                                'all_match': all_match,
                                'primary_confirmed': sha3_match,
                                'status': ('CONFIRMED' if all_match else 'FAILED'),
                                'initial_sha3_512': (multi_hash.get('sha3_512') if multi_hash else sha3_hash),
                                'initial_sha256': (multi_hash.get('sha256') if multi_hash else None),
                                'initial_md5': (multi_hash.get('md5') if multi_hash else None),
                                'final_sha3_512': final_hashes.get('sha3_512'),
                                'final_sha256': final_hashes.get('sha256'),
                                'final_md5': final_hashes.get('md5'),
                                'reconfirmed_at': datetime.now(timezone.utc).isoformat(),
                                'forensic_statement': (
                                    'SHA3-512 is the primary integrity algorithm. Hashes were computed on '
                                    'the original file before processing and recomputed after the file was '
                                    'unlocked following completion of all pipeline layers. Matching values '
                                    'confirm the original evidence file was not modified during investigation.'
                                    if all_match else
                                    'INTEGRITY FAILURE: Hash values do not match. The original file may '
                                    'have been modified. This result must not be used as forensic evidence.'
                                ),
                            }
                            steg_result['hash_reconfirmation'] = reconfirmation
                            
                            try:
                                import chain_of_custody as coc_module
                                coc_module.log_action(session_id, filepath, sha3_hash, 'INTEGRITY_RECONFIRMED', 'SUCCESS' if all_match else 'CRITICAL', str(reconfirmation))
                            except Exception:
                                pass
                                
                        except Exception as e:
                            print('[PIPELINE] Reconfirmation error: ' + str(e))
                            steg_result['hash_reconfirmation'] = {
                                'status': 'ERROR',
                                'error': str(e),
                                'all_match': None,
                                'primary_confirmed': None,
                            }
                            
                        report_result = generate_forensic_report(
                            filepath=filepath,
                            session_id=session_id,
                            sha3_hash=sha3_hash,
                            layer1_result=layer1_data,
                            layer2_result=steg_result,
                            layer3_result=layer3_data,
                            layer4_xai_result=xai_result,
                            chain_of_custody_log=coc_log
                        )
                        steg_result['forensic_report'] = report_result
                        
                        if report_result.get('success'):
                            print('[LAYER4] Forensic report generated: '
                                  + report_result.get('report_path', ''))
                            print('[LAYER4] Cryptographic seal: '
                                  + report_result.get('hmac_seal', ''))
                        else:
                            err_detail = str(report_result.get('error', 'Report generation failed'))
                            print('[LAYER4] Report generation failed: ' + err_detail)
                            try:
                                from user_prompt import notify_error_popup
                                notify_error_popup(
                                    title="Report Generation Error",
                                    reason=err_detail,
                                    filename=name,
                                    stage="Layer 4 Forensic Report"
                                )
                            except Exception:
                                pass
                                  
                        notify_steg_result(name, steg_result.get('verdict', 'ERROR'), steg_result.get('score', 0.5), steg_result.get('confidence_tier', 'UNKNOWN'))
                    else:
                        from user_prompt import ask_user_steg_scan, notify_steg_result
                        import mimetypes
                        
                        def get_file_type(fp):
                            mime, _ = mimetypes.guess_type(str(fp))
                            ext = Path(fp).suffix.lower()
                            if mime and mime.startswith('image'): return 'IMAGE'
                            elif mime and mime.startswith('video'): return 'VIDEO'
                            elif ext in ['.pdf', '.docx', '.doc', '.txt']: return 'DOCUMENT'
                            elif ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp', '.tiff']: return 'IMAGE'
                            elif ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv']: return 'VIDEO'
                            else: return 'IMAGE'
                            
                        file_type = get_file_type(filepath)
                        print(f'[LAYER0] File clean: {name}')

                        auto_escalate_lsb = settings_manager.get_setting("auto_escalate_lsb", True)
                        ask_user_policy = settings_manager.get_setting("ask_user_before_steg", False)

                        if auto_escalate_lsb:
                            print(f'[POLICY] Auto-escalate on LSB executable ENABLED: Escalating {name} directly to full steg scan without asking user for permission.')
                            user_wants_scan = True
                        elif ask_user_policy:
                            print(f'[LAYER0] Asking user for optional steg scan...')
                            user_wants_scan = ask_user_steg_scan(name, file_type, 'Shadow-Trace Engine')
                        else:
                            user_wants_scan = True
                        
                        if user_wants_scan:
                            print(f'[LAYER0] User requested scan. Running Layer 2...')
                            try:
                                import scan_tracker
                                scan_tracker.update_stage(4, "Steganography Detection", 75)
                            except Exception:
                                pass
                            from layer2_steganalysis import run_steganalysis
                            steg_result = run_steganalysis(filepath, session_id or 'UNKNOWN', sha3_hash or 'UNKNOWN', scan_target=scan_copy_path)
                            steg_result['file_hashes'] = multi_hash if 'multi_hash' in locals() else None
                            if layer1_result:
                                reconf_res = layer1_result.get('stage1_hash')
                                if not reconf_res and layer1_result.get('all_scan_results'):
                                    reconf_res = layer1_result['all_scan_results'].get('hash_reconfirmation')
                                if reconf_res:
                                    steg_result['hash_reconfirmation'] = reconf_res
                            
                            layer2_verdict = steg_result.get('verdict', 'CLEAN')
                            if layer2_verdict in ['STEGO_DETECTED', 'SUSPICIOUS']:
                                print('[LAYER3] Layer 2 flagged file. Starting payload extraction...')
                                try:
                                    layer3_result = run_extraction(
                                        filepath=filepath,
                                        session_id=session_id or 'UNKNOWN',
                                        sha3_hash=sha3_hash or 'UNKNOWN',
                                        layer2_result=steg_result,
                                        roi_coords=None
                                    )
                                    steg_result['layer3_extraction'] = layer3_result
                                    
                                    is_exe = layer3_result.get(
                                        'extraction_results', {}
                                    ).get('is_executable', False)
                                    
                                    if is_exe:
                                        print('[LAYER3] !!! EXECUTABLE PAYLOAD CONFIRMED !!!')
                                        print('[SHADOW-TRACE] CRITICAL THREAT: Hidden executable extracted')
                                        
                                except Exception as e:
                                    print('[LAYER3] Extraction error: ' + str(e))
                                    steg_result['layer3_extraction'] = {'error': str(e)}
                            else:
                                print('[LAYER3] File clean, skipping payload extraction')
                                steg_result['layer3_extraction'] = None
                                
                            print('[LAYER4] Starting explainability and report generation...')
                            
                            layer3_data = steg_result.get('layer3_extraction')
                            
                            xai_result = run_explainability(
                                filepath=filepath,
                                layer2_result=steg_result,
                                layer3_result=layer3_data,
                                session_id=session_id
                            )
                            steg_result['layer4_xai'] = xai_result
                            
                            try:
                                import chain_of_custody as coc_module
                                coc_log = coc_module.get_session_log(session_id)
                            except Exception:
                                coc_log = None
                            
                            layer1_data = layer1_result
                            try:
                                import scan_tracker
                                scan_tracker.update_stage(5, "Report Generation", 95)
                            except Exception:
                                pass

                            _perform_hash_reconfirmation(filepath, session_id, sha3_hash, multi_hash if 'multi_hash' in locals() else None, steg_result)
                            
                            report_result = generate_forensic_report(
                                filepath=filepath,
                                session_id=session_id,
                                sha3_hash=sha3_hash,
                                layer1_result=layer1_data,
                                layer2_result=steg_result,
                                layer3_result=layer3_data,
                                layer4_xai_result=xai_result,
                                chain_of_custody_log=coc_log
                            )
                            steg_result['forensic_report'] = report_result
                            
                            if report_result.get('success'):
                                print('[LAYER4] Forensic report generated: '
                                      + report_result.get('report_path', ''))
                                print('[LAYER4] Cryptographic seal: '
                                      + report_result.get('hmac_seal', ''))
                            else:
                                err_detail = str(report_result.get('error', 'Report generation failed'))
                                print('[LAYER4] Report generation failed: ' + err_detail)
                                try:
                                    from user_prompt import notify_error_popup
                                    notify_error_popup(
                                        title="Report Generation Error",
                                        reason=err_detail,
                                        filename=name,
                                        stage="Layer 4 Forensic Report"
                                    )
                                except Exception:
                                    pass
                                      
                            notify_steg_result(name, steg_result.get('verdict', 'ERROR'), steg_result.get('score', 0.5), steg_result.get('confidence_tier', 'UNKNOWN'))
                        else:
                            print(f'[LAYER0] User declined scan. Unlocking file.')
                            if hasattr(recovery_database, 'mark_complete'):
                                recovery_database.mark_complete(filepath)
                            print(f'[LAYER0] File released: {name}')
                else:
                    # File was a threat in layer1, already quarantined.
                    try:
                        from ui.tray_agent import (
                            update_tray_status,
                            show_tray_notification
                        )
                        update_tray_status('threat', name)
                        show_tray_notification(
                            'THREAT DETECTED',
                            'Shadow-Trace found suspicious content in:\n'
                            + name
                        )
                    except Exception:
                        pass

                    try:
                        import json
                        from quarantine_report import generate_quarantine_report
                        print('[LAYER0] Generating quarantine report...')
                        q_path_val = layer1_result.get('quarantine_path') if isinstance(layer1_result, dict) else None
                        q_reason = None
                        try:
                            from user_prompt import format_quarantine_reason
                            q_reason = format_quarantine_reason(layer1_result)
                        except Exception:
                            pass
                        if not q_reason and isinstance(layer1_result, dict):
                            det_eng = layer1_result.get('detecting_engine', 'Layer 1')
                            th_name = layer1_result.get('threat_name', 'Threat detected')
                            q_reason = f"{det_eng} detected threat: {th_name}"

                        hash_reconf = None
                        if isinstance(layer1_result, dict):
                            hash_reconf = layer1_result.get('stage1_hash')
                            if not hash_reconf and layer1_result.get('all_scan_results'):
                                hash_reconf = layer1_result['all_scan_results'].get('hash_reconfirmation')

                        q_report = generate_quarantine_report(
                            filepath=str(filepath),
                            session_id=session_id or 'UNKNOWN',
                            layer1_result=layer1_result,
                            multi_hash=multi_hash if 'multi_hash' in locals() else None,
                            sha3_hash=sha3_hash or 'UNKNOWN',
                            quarantine_path=q_path_val,
                            quarantine_reason=q_reason or 'Malicious threat detected during Layer 1 screening',
                            correlation_data=correlation_data if 'correlation_data' in locals() else None,
                            hash_reconfirmation=hash_reconf,
                        )
                        if q_report.get('success'):
                            print('[LAYER0] Quarantine report: '
                                  + Path(q_report['report_path']).name)
                            try:
                                import chain_of_custody as coc_mod
                                coc_mod.log_action(
                                    session_id or 'UNKNOWN',
                                    str(filepath),
                                    sha3_hash or 'UNKNOWN',
                                    'QUARANTINE_REPORT_GENERATED',
                                    'SUCCESS',
                                    json.dumps({'report_file': Path(q_report['report_path']).name, 'report_path': q_report['report_path']})
                                )
                            except Exception as coc_err:
                                print(f'[LAYER0] CoC logging error: {coc_err}')
                        else:
                            print('[LAYER0] Quarantine report failed: '
                                  + str(q_report.get('error')))
                            try:
                                import chain_of_custody as coc_mod
                                coc_mod.log_action(
                                    session_id or 'UNKNOWN',
                                    str(filepath),
                                    sha3_hash or 'UNKNOWN',
                                    'QUARANTINE_REPORT_GENERATED',
                                    'WARNING',
                                    str(q_report.get('error'))
                                )
                            except Exception:
                                pass
                    except Exception as e:
                        print('[LAYER0] Quarantine report error: ' + str(e))
            else:
                _stub_pipeline(
                    filepath,
                    session_id or 'UNKNOWN',
                    sha3_hash or 'UNKNOWN',
                    scan_copy_path
                )
        except Exception as e:
            print(f'[ERROR] Pipeline error: {e}')
            import traceback
            traceback.print_exc()
            try:
                from user_prompt import notify_error_popup
                notify_error_popup(
                    title="Pipeline Execution Error",
                    reason=str(e),
                    filename=name,
                    stage="Pipeline Execution"
                )
            except Exception:
                pass
            # Emergency unlock
            try:
                utils.unlock_file(filepath)
                if hasattr(recovery_database, 'mark_complete'):
                    recovery_database.mark_complete(filepath)
                print(f'[EMERGENCY UNLOCK] {name}')
            except Exception as ue:
                print(f'[EMERGENCY UNLOCK FAILED] {ue}')
                # Absolute last resort
                try:
                    import subprocess
                    subprocess.run(
                        ['icacls', filepath, '/remove:d', 'Everyone'],
                        capture_output=True, timeout=5
                    )
                    subprocess.run(
                        ['icacls', filepath, '/reset'],
                        capture_output=True, timeout=5
                    )
                    print(f'[LAST RESORT UNLOCK] icacls reset applied')
                except Exception as e:
                    print(f'[UNLOCK] icacls reset failed: {e}')
        finally:
            if scan_copy_path:
                utils.delete_scan_copy(scan_copy_path)
                print('[LAYER0] Sandbox copy cleaned up')
                
            # Master file release: If the file was not quarantined (moved), unlock it now.
            if os.path.exists(filepath):
                try:
                    utils.unlock_file(filepath)
                    if hasattr(recovery_database, 'mark_complete'):
                        recovery_database.mark_complete(filepath)
                        
                    try:
                        from ui.tray_agent import update_tray_status
                        update_tray_status('monitoring')
                    except Exception:
                        pass
                except Exception as e:
                    print(f'[ERROR] Master unlock failed for {name}: {e}')
                    
            currently_processing.discard(filepath)


def _stub_pipeline(filepath, session_id, sha3_hash, scan_copy_path=None):
    """Fallback used only when Layer 1 import fails."""
    print('[STUB] Layer 1 not connected - using stub')
    time.sleep(1)
    utils.unlock_file(filepath)
    recovery_database.mark_complete(filepath)
    if scan_copy_path:
        utils.delete_scan_copy(scan_copy_path)
    print(f'[STUB] Complete: {Path(filepath).name}')


def is_actually_locked(filepath):
    try:
        with open(filepath, 'r+b') as f:
            return False
    except (PermissionError, IOError):
        return True
    except FileNotFoundError:
        return False

def resume_orphaned_pipeline(filepath, session_id):
    name = Path(filepath).name
    print(f'[RECOVERY] Starting pipeline resumption for: {name}')
    
    # STEP 1: Verify file exists on disk
    if not os.path.exists(filepath):
        print(f'[WARNING] Orphaned file not found: {filepath}')
        if hasattr(recovery_database, 'mark_complete'):
            recovery_database.mark_complete(filepath)
        return
        
    try:
        # STEP 2: Temporarily strip icacls restrictions
        print(f'[RECOVERY] Temporarily lifting icacls for: {name}')
        utils.unlock_file(filepath)
        
        # STEP 3: Create sandbox copy immediately
        scan_copy_path = utils.create_scan_copy(filepath)
        if not scan_copy_path:
            print(f'[ERROR] Failed to create sandbox copy for: {name}')
            utils.lock_file(filepath)
            return
        print(f'[RECOVERY] Sandbox copy created: {Path(scan_copy_path).name}')
        
        # STEP 4: Generate fresh SHA3 hash
        sha3_hash = utils.generate_sha3_hash(filepath) or 'HASH_UNAVAILABLE'
        
        try:
            from utils import compute_file_hashes
            multi_hash = compute_file_hashes(str(filepath))
        except Exception:
            multi_hash = {'sha3_512': sha3_hash}
        print(f'[RECOVERY] Fresh hash generated: {sha3_hash[:20]}...')
        
        # STEP 5: Re-apply icacls lock on original
        utils.lock_file(filepath)
        print(f'[RECOVERY] Original re-secured: {name}')
        
        # STEP 6: Create or reuse chain of custody session
        if session_id == 'RECOVERY' or not session_id:
            import uuid
            session_id = str(uuid.uuid4())
            
        chain_of_custody.log_action(
            session_id, filepath, sha3_hash,
            chain_of_custody.CRASH_RECOVERY if hasattr(chain_of_custody, 'CRASH_RECOVERY') else 'CRASH_RECOVERY',
            'SUCCESS',
            'CRASH_RECOVERY_RESUMED'
        )
        
        # STEP 7: Run full Layer 1 pipeline
        print(f'[RECOVERY] Running full Layer 1 scan...')
        if pipeline_callback is not None:
            layer1_result = pipeline_callback(
                filepath,
                session_id,
                sha3_hash,
                scan_copy_path,
                multi_hash=multi_hash if 'multi_hash' in locals() else None
            )
            
            if layer1_result and layer1_result.get('verdict') == 'THREAT':
                print(f'[RECOVERY] THREAT detected in recovered file')
                try:
                    import json
                    from quarantine_report import generate_quarantine_report
                    print('[LAYER0] Generating quarantine report...')
                    q_path_val = layer1_result.get('quarantine_path') if isinstance(layer1_result, dict) else None
                    q_reason = None
                    try:
                        from user_prompt import format_quarantine_reason
                        q_reason = format_quarantine_reason(layer1_result)
                    except Exception:
                        pass
                    if not q_reason and isinstance(layer1_result, dict):
                        det_eng = layer1_result.get('detecting_engine', 'Layer 1')
                        th_name = layer1_result.get('threat_name', 'Threat detected')
                        q_reason = f"{det_eng} detected threat: {th_name}"

                    hash_reconf = None
                    if isinstance(layer1_result, dict):
                        hash_reconf = layer1_result.get('stage1_hash')
                        if not hash_reconf and layer1_result.get('all_scan_results'):
                            hash_reconf = layer1_result['all_scan_results'].get('hash_reconfirmation')

                    q_report = generate_quarantine_report(
                        filepath=str(filepath),
                        session_id=session_id or 'UNKNOWN',
                        layer1_result=layer1_result,
                        multi_hash=multi_hash if 'multi_hash' in locals() else None,
                        sha3_hash=sha3_hash or 'UNKNOWN',
                        quarantine_path=q_path_val,
                        quarantine_reason=q_reason or 'Malicious threat detected during crash recovery',
                        correlation_data=None,
                        hash_reconfirmation=hash_reconf,
                    )
                    if q_report.get('success'):
                        print('[LAYER0] Quarantine report: '
                              + Path(q_report['report_path']).name)
                        try:
                            import chain_of_custody as coc_mod
                            coc_mod.log_action(
                                session_id or 'UNKNOWN',
                                str(filepath),
                                sha3_hash or 'UNKNOWN',
                                'QUARANTINE_REPORT_GENERATED',
                                'SUCCESS',
                                json.dumps({'report_file': Path(q_report['report_path']).name, 'report_path': q_report['report_path']})
                            )
                        except Exception as coc_err:
                            print(f'[LAYER0] CoC logging error: {coc_err}')
                    else:
                        print('[LAYER0] Quarantine report failed: '
                              + str(q_report.get('error')))
                        try:
                            import chain_of_custody as coc_mod
                            coc_mod.log_action(
                                session_id or 'UNKNOWN',
                                str(filepath),
                                sha3_hash or 'UNKNOWN',
                                'QUARANTINE_REPORT_GENERATED',
                                'WARNING',
                                str(q_report.get('error'))
                            )
                        except Exception:
                            pass
                except Exception as e:
                    print('[LAYER0] Quarantine report error: ' + str(e))
                return
                
            # STEP 8: Run Layer 1.5 LSB check
            if layer1_result and layer1_result.get('verdict') == 'CLEAN':
                from layer1_5_lsb_check import run_lsb_executable_check
                lsb_result = run_lsb_executable_check(filepath, session_id, sha3_hash, scan_target=scan_copy_path)
                
                # STEP 9: Handle result
                auto_escalate = lsb_result.get('auto_escalate', False)
                lsb_verdict = lsb_result.get('verdict', 'CLEAN')
                
                if auto_escalate or lsb_verdict == 'EXECUTABLE_FOUND':
                    from layer2_steganalysis import run_steganalysis
                    from user_prompt import notify_steg_result
                    steg_result = run_steganalysis(filepath, session_id, sha3_hash, scan_target=scan_copy_path)
                    steg_result['file_hashes'] = multi_hash if 'multi_hash' in locals() else None
                    if layer1_result:
                        reconf_res = layer1_result.get('stage1_hash')
                        if not reconf_res and layer1_result.get('all_scan_results'):
                            reconf_res = layer1_result['all_scan_results'].get('hash_reconfirmation')
                        if reconf_res:
                            steg_result['hash_reconfirmation'] = reconf_res
                    steg_result['lsb_check_result'] = lsb_result
                    
                    if 'correlation_data' in locals() and correlation_data is not None:
                        steg_result['source_correlation'] = correlation_data
                        steg_result['source_url'] = (
                            correlation_data
                            .get('url_analysis', {})
                            .get('url', None)
                        )
                    
                    layer2_verdict = steg_result.get('verdict', 'CLEAN')
                    if layer2_verdict in ['STEGO_DETECTED', 'SUSPICIOUS']:
                        print('[LAYER3] Layer 2 flagged file. Starting payload extraction...')
                        try:
                            layer3_result = run_extraction(
                                filepath=filepath,
                                session_id=session_id,
                                sha3_hash=sha3_hash,
                                layer2_result=steg_result,
                                roi_coords=None
                            )
                            steg_result['layer3_extraction'] = layer3_result
                            
                            is_exe = layer3_result.get(
                                'extraction_results', {}
                            ).get('is_executable', False)
                            
                            if is_exe:
                                print('[LAYER3] !!! EXECUTABLE PAYLOAD CONFIRMED !!!')
                                print('[SHADOW-TRACE] CRITICAL THREAT: Hidden executable extracted')
                            else:
                                payload_type = layer3_result.get(
                                    'extraction_results', {}
                                ).get('payload_type', 'Unknown')
                                print('[LAYER3] Payload type: ' + str(payload_type))
                                
                        except Exception as e:
                            print('[LAYER3] Extraction error: ' + str(e))
                            steg_result['layer3_extraction'] = {'error': str(e)}
                    else:
                        print('[LAYER3] File clean, skipping payload extraction')
                        steg_result['layer3_extraction'] = None
                        
                    print('[LAYER4] Starting explainability and report generation...')
                    
                    layer3_data = steg_result.get('layer3_extraction')
                    
                    xai_result = run_explainability(
                        filepath=filepath,
                        layer2_result=steg_result,
                        layer3_result=layer3_data,
                        session_id=session_id
                    )
                    steg_result['layer4_xai'] = xai_result
                    
                    try:
                        import chain_of_custody as coc_module
                        coc_log = coc_module.get_session_log(session_id)
                    except Exception:
                        coc_log = None
                    
                    layer1_data = layer1_result
                    
                    calibration_data = None
                    try:
                        from confidence_calibration import calibrate_result
                        file_type = steg_result.get('file_type', 'IMAGE')
                        lsb_data = steg_result.get(
                            'lsb_check_result',
                            steg_result.get('lsb_result', None)
                        )
                        calibration_data = calibrate_result(
                            layer1_result=layer1_data,
                            layer2_result=steg_result,
                            layer3_result=layer3_data,
                            lsb_result=lsb_data,
                            file_type=file_type,
                        )
                        steg_result['calibration'] = calibration_data
                    except Exception as e:
                        print('[LAYER0] Calibration warning: ' + str(e))
                        calibration_data = None

                    report_result = generate_forensic_report(
                        filepath=filepath,
                        session_id=session_id,
                        sha3_hash=sha3_hash,
                        layer1_result=layer1_data,
                        layer2_result=steg_result,
                        layer3_result=layer3_data,
                        layer4_xai_result=xai_result,
                        calibration=calibration_data,
                        chain_of_custody_log=coc_log
                    )
                    steg_result['forensic_report'] = report_result
                    
                    if report_result.get('success'):
                        print('[LAYER4] Forensic report generated: '
                              + report_result.get('report_path', ''))
                        print('[LAYER4] Cryptographic seal: '
                              + report_result.get('hmac_seal', ''))
                    else:
                        print('[LAYER4] Report generation failed: '
                              + str(report_result.get('error')))
                              
                    notify_steg_result(name, steg_result.get('verdict', 'ERROR'), steg_result.get('score', 0.5), steg_result.get('confidence_tier', 'UNKNOWN'))
                else:
                    from user_prompt import ask_user_steg_scan, notify_steg_result
                    import mimetypes
                    
                    def get_file_type(fp):
                        mime, _ = mimetypes.guess_type(str(fp))
                        ext = Path(fp).suffix.lower()
                        if mime and mime.startswith('image'): return 'IMAGE'
                        elif mime and mime.startswith('video'): return 'VIDEO'
                        elif ext in ['.pdf', '.docx', '.doc', '.txt']: return 'DOCUMENT'
                        elif ext in ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp', '.tiff']: return 'IMAGE'
                        elif ext in ['.mp4', '.avi', '.mkv', '.mov', '.wmv']: return 'VIDEO'
                        else: return 'IMAGE'
                        
                    file_type = get_file_type(filepath)

                    auto_escalate_lsb = settings_manager.get_setting("auto_escalate_lsb", True)
                    ask_user_policy = settings_manager.get_setting("ask_user_before_steg", False)

                    if auto_escalate_lsb:
                        print(f'[POLICY] Auto-escalate on LSB executable ENABLED: Escalating {name} directly to full steg scan without asking user for permission.')
                        user_wants_scan = True
                    elif ask_user_policy:
                        print(f'[LAYER0] Asking user for optional steg scan...')
                        user_wants_scan = ask_user_steg_scan(name, file_type, 'Shadow-Trace Engine')
                    else:
                        user_wants_scan = True
                    
                    if user_wants_scan:
                        from layer2_steganalysis import run_steganalysis
                        steg_result = run_steganalysis(filepath, session_id, sha3_hash, scan_target=scan_copy_path)
                        steg_result['file_hashes'] = multi_hash if 'multi_hash' in locals() else None
                        if layer1_result:
                            reconf_res = layer1_result.get('stage1_hash')
                            if not reconf_res and layer1_result.get('all_scan_results'):
                                reconf_res = layer1_result['all_scan_results'].get('hash_reconfirmation')
                            if reconf_res:
                                steg_result['hash_reconfirmation'] = reconf_res
                        
                        layer2_verdict = steg_result.get('verdict', 'CLEAN')
                        if layer2_verdict in ['STEGO_DETECTED', 'SUSPICIOUS']:
                            print('[LAYER3] Layer 2 flagged file. Starting payload extraction...')
                            try:
                                layer3_result = run_extraction(
                                    filepath=filepath,
                                    session_id=session_id,
                                    sha3_hash=sha3_hash,
                                    layer2_result=steg_result,
                                    roi_coords=None
                                )
                                steg_result['layer3_extraction'] = layer3_result
                                
                                is_exe = layer3_result.get(
                                    'extraction_results', {}
                                ).get('is_executable', False)
                                
                                if is_exe:
                                    print('[LAYER3] !!! EXECUTABLE PAYLOAD CONFIRMED !!!')
                                    print('[SHADOW-TRACE] CRITICAL THREAT: Hidden executable extracted')
                                else:
                                    payload_type = layer3_result.get(
                                        'extraction_results', {}
                                    ).get('payload_type', 'Unknown')
                                    print('[LAYER3] Payload type: ' + str(payload_type))
                                    
                            except Exception as e:
                                print('[LAYER3] Extraction error: ' + str(e))
                                steg_result['layer3_extraction'] = {'error': str(e)}
                        else:
                            print('[LAYER3] File clean, skipping payload extraction')
                            steg_result['layer3_extraction'] = None

                        if layer2_verdict in ['STEGO_DETECTED', 'SUSPICIOUS'] and settings_manager.get_setting('auto_quarantine_stego', False):
                            try:
                                import layer1_malware
                                q_path = layer1_malware.quarantine_file(
                                    filepath,
                                    session_id or 'UNKNOWN',
                                    sha3_hash or 'UNKNOWN',
                                    {'engine': 'Layer2_Steganalysis', 'verdict': layer2_verdict, 'score': steg_result.get('score')}
                                )
                                print(f'[STEGO-QUARANTINE] File quarantined to vault: {q_path}')
                                steg_result['quarantine_path'] = q_path
                            except Exception as q_err:
                                print(f'[STEGO-QUARANTINE] Quarantine error: {q_err}')
                            
                        print('[LAYER4] Starting explainability and report generation...')
                        
                        layer3_data = steg_result.get('layer3_extraction')
                        
                        xai_result = run_explainability(
                            filepath=filepath,
                            layer2_result=steg_result,
                            layer3_result=layer3_data,
                            session_id=session_id
                        )
                        steg_result['layer4_xai'] = xai_result
                        
                        try:
                            import chain_of_custody as coc_module
                            coc_log = coc_module.get_session_log(session_id)
                        except Exception:
                            coc_log = None
                        
                        layer1_data = layer1_result
                        
                        report_result = generate_forensic_report(
                            filepath=filepath,
                            session_id=session_id,
                            sha3_hash=sha3_hash,
                            layer1_result=layer1_data,
                            layer2_result=steg_result,
                            layer3_result=layer3_data,
                            layer4_xai_result=xai_result,
                            chain_of_custody_log=coc_log
                        )
                        steg_result['forensic_report'] = report_result
                        
                        if report_result.get('success'):
                            print('[LAYER4] Forensic report generated: '
                                  + report_result.get('report_path', ''))
                            print('[LAYER4] Cryptographic seal: '
                                  + report_result.get('hmac_seal', ''))
                        else:
                            err_detail = str(report_result.get('error', 'Report generation failed'))
                            print('[LAYER4] Report generation failed: ' + err_detail)
                            try:
                                from user_prompt import notify_error_popup
                                notify_error_popup(
                                    title="Report Generation Error",
                                    reason=err_detail,
                                    filename=name,
                                    stage="Layer 4 Forensic Report"
                                )
                            except Exception:
                                pass
                                  
                        notify_steg_result(name, steg_result.get('verdict', 'ERROR'), steg_result.get('score', 0.5), steg_result.get('confidence_tier', 'UNKNOWN'))
                    else:
                        pass
        else:
            _stub_pipeline(filepath, session_id, sha3_hash, scan_copy_path)
            
        print(f'[RECOVERY] Pipeline complete for: {name}')
        
    except Exception as e:
        print(f'[ERROR] Pipeline recovery error for {name}: {e}')
        utils.log_error(f'resume_orphaned_pipeline error for {name}', e)
        try:
            utils.lock_file(filepath)
        except Exception as lock_err:
            print(f'[PIPELINE] Could not re-lock {filepath} after error: {lock_err}')
            
    finally:
        # STEP 11: Delete sandbox copy
        if 'scan_copy_path' in locals() and scan_copy_path:
            utils.delete_scan_copy(scan_copy_path)
            
        # STEP 10: Mark complete and unlock
        if os.path.exists(filepath):
            try:
                utils.unlock_file(filepath)
                if hasattr(recovery_database, 'mark_complete'):
                    recovery_database.mark_complete(filepath)
                print(f'[RECOVERY] File unlocked after successful scan')
            except Exception as e:
                print(f'[ERROR] Master unlock failed for {name}: {e}')

def check_and_recover_orphaned_files():
    try:
        locked_files = recovery_database.get_all_active_files()
        
        if not locked_files:
            print('No orphaned files found. Clean startup.')
            return
            
        print(f'[STARTUP] Checking {len(locked_files)} database records...')
        rescanned = 0
        
        for filepath in locked_files:
            name = Path(filepath).name
            
            if is_actually_locked(filepath):
                print(f'[STARTUP] Resuming pipeline for locked file: {name}')
                record = recovery_database.get_file_record(filepath)
                session_id = record.get('session_id', 'RECOVERY') if record else 'RECOVERY'
                resume_orphaned_pipeline(filepath, session_id)
                rescanned += 1
            else:
                if hasattr(recovery_database, 'mark_complete'):
                    recovery_database.mark_complete(filepath)
                print(f'[STARTUP] Stale lock record cleaned: {name}')
                
        print(f'[STARTUP] Recovery complete. {rescanned} file(s) rescanned.')
    except Exception as e:
        utils.log_error("check_and_recover_orphaned_files error", e)


# =============================================================================
# Main Entry Point
# =============================================================================

def start_monitoring():
    try:
        print('=' * 50)
        print('  SHADOW-TRACE File Monitor Starting')
        print(f'  Version: {config.VERSION}')
        print(f'  Monitoring: Multiple Folders')
        print(f'  OS: {platform.system()}')
        print('=' * 50)

        # Confirm we are watching the right folders
        monitored = config.get_monitored_dirs()
        print(f'Active monitored paths: {len(monitored)}')
        for directory in monitored:
            if directory.exists():
                print(f' - {directory} (Files: {len(list(directory.iterdir()))})')

        recovery_database.initialize_recovery_db()
        chain_of_custody.initialize_coc_db()
        print('Databases initialized')

        # Connect real Layer 1 pipeline
        if _LAYER1_AVAILABLE:
            set_pipeline_callback(run_malware_screening)
            print('[STARTUP] Layer 1 malware screening pipeline connected')
        else:
            print('[STARTUP] WARNING: Layer 1 unavailable - stub pipeline active')

        # Start ClamAV daemon if not running
        from utils import ensure_clamd_running
        clamav_ready = ensure_clamd_running()
        if clamav_ready:
            print('[STARTUP] ClamAV daemon ready')
        else:
            print('[STARTUP] WARNING: ClamAV not available - will use YARA only')

        url_server.start_url_server()
        print('URL capture server started')

        check_and_recover_orphaned_files()

        try:
            from investigation_tools import (
                get_reprocess_queue,
                mark_reprocess_complete
            )
            pending = get_reprocess_queue('PENDING')
            if pending:
                print('[MONITOR] Found '
                      + str(len(pending))
                      + ' files queued for reprocessing')
                for item in pending:
                    filepath = item.get('filepath', '')
                    reason = item.get('reason', '')
                    queue_id = item.get('id')
                    print('[MONITOR] Reprocessing: '
                          + Path(filepath).name
                          + ' (reason: ' + reason + ')')
                    
                    if Path(filepath).exists():
                        try:
                            threading.Thread(target=_process_new_file, args=(filepath,), daemon=True).start()
                            mark_reprocess_complete(queue_id)
                        except Exception as e2:
                            print('[MONITOR] Reprocess error: '
                                  + str(e2))
                    else:
                        print('[MONITOR] File no longer exists: '
                              + Path(filepath).name)
                        mark_reprocess_complete(queue_id)
        except Exception as e:
            print('[MONITOR] Reprocess check warning: ' + str(e))

        # Start the Watchdog observer
        global _event_handler, _active_watches, _observer_instance, _monitor_running
        _event_handler = ShadowTraceEventHandler()
        observer = Observer()
        _active_watches = {}
        for directory in monitored:
            try:
                if directory.exists():
                    watch = observer.schedule(
                        _event_handler,
                        str(directory),
                        recursive=False
                    )
                    norm_k = str(directory.resolve()).lower() if platform.system() == 'Windows' else str(directory.resolve())
                    _active_watches[norm_k] = watch
                    print(f'Watching: {directory}')
            except Exception as w_err:
                print(f'[MONITOR] Could not watch {directory}: {w_err}')
        observer.start()
        
        # -- Pre-populate known_files from recovery DB -------------------------
        # Load COMPLETE and QUARANTINED paths so the polling monitor ignores
        # files that were already fully processed in a previous session.
        try:
            import sqlite3 as _sqlite3
            conn = _sqlite3.connect(str(config.RECOVERY_DB))
            cursor = conn.cursor()
            cursor.execute(
                "SELECT filepath FROM locked_files "
                "WHERE status IN ('COMPLETE', 'QUARANTINED')"
            )
            completed_files = cursor.fetchall()
            conn.close()
            for (fp,) in completed_files:
                known_files.add(fp)
            print(f'[STARTUP] Pre-loaded {len(completed_files)} completed files into known_files')
        except Exception as e:
            print(f'[STARTUP] Could not pre-load known files: {e}')

        # Also add all LOCKED files from the DB (currently being processed or
        # orphaned) so we don't accidentally double-process them either.
        try:
            for fp in recovery_database.get_all_active_files():
                known_files.add(fp)
        except Exception as e:
            print(f'[STARTUP] Could not pre-load active locked files: {e}')

        # Pre-populate with ALL files currently on disk in monitored dirs.
        # This ensures the polling monitor skips pre-existing files.
        for monitored_dir in config.get_monitored_dirs():
            try:
                for f in Path(monitored_dir).iterdir():
                    if f.is_file():
                        known_files.add(str(f))
            except Exception as e:
                print(f'[STARTUP] Error reading {monitored_dir}: {e}')

        print(f'[STARTUP] Total known files at startup: {len(known_files)}')

        # Start the fallback polling monitor
        polling_thread = threading.Thread(target=_polling_monitor, daemon=True)
        polling_thread.start()

        print('Shadow-Trace is ready. Waiting for downloads...')
        print('Press Ctrl+C to stop')

        global _observer_instance, _monitor_running
        _observer_instance = observer
        _monitor_running = True

        try:
            while _monitor_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print('Stopping Shadow-Trace...')
        finally:
            if _observer_instance:
                _observer_instance.stop()
                _observer_instance.join()
                _observer_instance = None
            print('Shadow-Trace stopped.')
            import os
            os._exit(0)
            
    except Exception as e:
        utils.log_error("start_monitoring error", e)
        print(f"Error starting monitor: {e}")

def sync_monitored_directories(directories_list):
    """
    Synchronizes currently active watchdog watches with the provided list of directories.
    Schedules watches for newly added directories and unschedules watches for removed ones.
    """
    global _observer_instance, _event_handler, _active_watches, known_files

    target_paths = []
    for d in directories_list:
        if d:
            try:
                p = Path(d)
                target_paths.append(p)
            except Exception:
                pass

    # Update config.MONITORED_DIRS so polling monitor also sees the new list
    config.MONITORED_DIRS = target_paths

    if _observer_instance is None or _event_handler is None:
        print(f"[MONITOR] Observer not active yet. Config MONITORED_DIRS updated ({len(target_paths)} paths).")
        return

    is_win = platform.system() == 'Windows'
    current_keys = set(_active_watches.keys())
    target_map = {}
    for p in target_paths:
        try:
            if p.exists() and p.is_dir():
                k = str(p.resolve()).lower() if is_win else str(p.resolve())
                target_map[k] = p
        except OSError:
            pass

    target_keys = set(target_map.keys())

    # 1. Unschedule removed folders
    to_remove = current_keys - target_keys
    for k in to_remove:
        watch = _active_watches.pop(k, None)
        if watch:
            try:
                _observer_instance.unschedule(watch)
                print(f"[MONITOR] Dynamic unschedule: stopped monitoring {watch.path}")
            except Exception as e:
                print(f"[MONITOR] Error unscheduling watch {k}: {e}")

    # 2. Schedule new folders
    to_add = target_keys - current_keys
    for k in to_add:
        p = target_map[k]
        try:
            watch = _observer_instance.schedule(_event_handler, str(p), recursive=False)
            _active_watches[k] = watch
            print(f"[MONITOR] Dynamic schedule: now monitoring {p}")
            # Pre-populate existing files so they are not treated as incoming new downloads
            try:
                for f in p.iterdir():
                    if f.is_file():
                        known_files.add(str(f))
            except Exception:
                pass
        except Exception as e:
            print(f"[MONITOR] Error scheduling watch on {p}: {e}")

def stop_monitoring():
    """
    Stop the watchdog observer cleanly.
    Does NOT unlock, release, or touch any locked files.
    Locked files remain on disk for crash recovery on next startup.
    """
    global _monitor_running, _observer_instance
    _monitor_running = False

    if _observer_instance is not None:
        try:
            _observer_instance.stop()
            _observer_instance.join(timeout=5)
            _observer_instance = None
            print('[MONITOR] Watchdog observer stopped.')
        except Exception as e:
            print('[MONITOR] Observer stop error: ' + str(e))

if __name__ == "__main__":
    start_monitoring()
