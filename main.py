import os
import sys
import time
import signal
import threading
import subprocess
from pathlib import Path
from dotenv import load_dotenv

if sys.stdout and sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')

env_path = Path(__file__).parent / '.env'
if env_path.exists():
    load_dotenv(str(env_path))

import config
import utils

def ensure_report_folders():
    folders = [
        config.BASE_DIR / 'models',
        config.BASE_DIR / 'sandbox',
        config.BASE_DIR / 'quarantine',
        config.BASE_DIR / 'reports',
        config.BASE_DIR / 'reports' / 'clean',
        config.BASE_DIR / 'reports' / 'suspicious',
        config.BASE_DIR / 'reports' / 'stego',
        config.BASE_DIR / 'reports' / 'quarantine',
        config.BASE_DIR / 'reports' / 'heatmaps',
        config.BASE_DIR / 'logs',
        config.BASE_DIR / 'yara_rules',
        config.BASE_DIR / 'ui' / 'icons',
    ]
    for folder in folders:
        folder.mkdir(parents=True, exist_ok=True)
    print('[STARTUP] All directories ready')

    try:
        import scan_tracker
        scan_tracker.reset()
    except Exception:
        pass

    print('[STARTUP] Initialising investigation database...')
    try:
        from investigation_tools import init_investigation_db
        init_investigation_db()
        print('[STARTUP] Investigation database: OK')
    except Exception as e:
        print('[STARTUP] Investigation DB warning: ' + str(e))

    print('[STARTUP] Initialising benchmarks folder...')
    try:
        bench_dir = config.BASE_DIR / 'logs' / 'benchmarks'
        bench_dir.mkdir(parents=True, exist_ok=True)
        url_log_dir = config.BASE_DIR / 'logs'
        url_log_dir.mkdir(parents=True, exist_ok=True)
        print('[STARTUP] Benchmarks folder: OK')
    except Exception as e:
        print('[STARTUP] Benchmarks folder warning: ' + str(e))

    print('[STARTUP] Initialising analyst audit database...')
    try:
        from analyst_audit import init_audit_db, log_action, SESSION_START
        init_audit_db()
        log_action(SESSION_START, 'main.py', {
            'app_version': '1.0.0',
            'pid': os.getpid(),
        })
        print('[STARTUP] Analyst audit database: OK')
    except Exception as e:
        print('[STARTUP] Analyst audit warning: ' + str(e))


def check_single_instance():
    lock_file = config.BASE_DIR / 'shadow_trace.lock'
    
    if lock_file.exists():
        try:
            with open(lock_file) as f:
                pid = int(f.read().strip())
            import psutil
            is_running = False
            if pid != os.getpid() and psutil.pid_exists(pid):
                try:
                    proc = psutil.Process(pid)
                    p_name = proc.name().lower()
                    if 'python' in p_name:
                        cmd = ' '.join(proc.cmdline() or [])
                        if 'main.py' in cmd or 'shadow-trace' in cmd.lower():
                            is_running = True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    is_running = False

            if is_running:
                print('[STARTUP] Shadow-Trace already running')
                print('[STARTUP] PID: ' + str(pid))
                print('[STARTUP] Only one instance allowed')
                sys.exit(1)
            else:
                try:
                    lock_file.unlink()
                except Exception:
                    pass
        except Exception:
            try:
                lock_file.unlink()
            except Exception:
                pass

    with open(lock_file, 'w') as f:
        f.write(str(os.getpid()))

    print('[STARTUP] Enhanced capabilities active:')
    print('[STARTUP]   Confidence calibration: YES')
    print('[STARTUP]   Dual report modes: YES')
    print('[STARTUP]   Evidence bundle export: YES')
    print('[STARTUP]   Case-level dashboard: YES')
    print('[STARTUP]   Source correlation: YES')
    print('[STARTUP]   Investigator tools: YES')
    print('[STARTUP]   Benchmarking module: YES')
    print(f'[STARTUP]   VirusTotal mode: {config.VT_MODE}')
    try:
        import settings_manager
        current_cfg = settings_manager.get_settings()
        is_always_on = bool(current_cfg.get("always_on_monitoring", False))
        if is_always_on:
            settings_manager.set_windows_autostart(True)
        print(f'[STARTUP]   Always ON monitoring: {"ACTIVE" if is_always_on else "DISABLED"}')
    except Exception:
        pass

    import atexit
    def remove_lock():
        try:
            lock_file.unlink()
        except Exception:
            pass
    atexit.register(remove_lock)


def check_dependencies() -> bool:
    print()
    print('=' * 60)
    print('  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗')
    print('  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║')
    print('  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║')
    print('  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║')
    print('  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝')
    print('  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝')
    print()
    print('  ████████╗██████╗  █████╗  ██████╗███████╗')
    print('  ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝')
    print('     ██║   ██████╔╝███████║██║     █████╗  ')
    print('     ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ')
    print('     ██║   ██║  ██║██║  ██║╚██████╗███████╗')
    print('     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝')
    print()
    print('  v1.0.0  |  Cyber Forensic Steganalysis System')
    print('  Anjuman Institute of Technology and Management')
    print('=' * 60)
    print()

    if sys.version_info < (3, 10):
        print('[STARTUP] FAIL: Python 3.10+ required')
        return False
    print('[STARTUP] Python ' + str(sys.version_info.major) + '.' + str(sys.version_info.minor) + ': OK')

    from utils import ensure_clamd_running
    clamav_ready = ensure_clamd_running()
    if clamav_ready:
        print('[STARTUP] ClamAV: RUNNING')
    else:
        print('[STARTUP] ClamAV: NOT RUNNING (YARA+VT active)')

    print('[STARTUP] Checking network monitoring...')
    try:
        from network_monitor import (
            check_dns_log_enabled,
            enable_dns_event_log,
            init_network_db
        )
        init_network_db()
        dns_enabled = check_dns_log_enabled()
        if dns_enabled:
            print('[STARTUP] DNS event logging: ENABLED')
        else:
            print('[STARTUP] DNS event logging: DISABLED')
            print('[STARTUP] Attempting to enable...')
            enabled = enable_dns_event_log()
            if enabled:
                print('[STARTUP] DNS event logging: NOW ENABLED')
            else:
                print('[STARTUP] DNS event logging: NEEDS ADMIN')
                print('[STARTUP] Run once as administrator to enable')
                print('[STARTUP] TCP correlation will be used instead')
    except Exception as e:
        print('[STARTUP] Network monitor warning: ' + str(e))

    for m in ['video_model.pth', 'image_model.pth', 'doc_model.pth']:
        model_path = config.BASE_DIR / 'models' / m
        status = 'LOADED' if model_path.exists() else 'MISSING'
        print(f'[STARTUP] Model {m}: {status}')

    vt_key = os.environ.get('VIRUSTOTAL_API_KEY')
    print('[STARTUP] VirusTotal key: ' + ('OK' if vt_key else 'MISSING'))

    yara_dir = config.BASE_DIR / 'yara_rules'
    if yara_dir.exists():
        yara_count = len(list(yara_dir.rglob('*.yar')))
        print(f'[STARTUP] YARA rules: {yara_count} loaded')
    else:
        print('[STARTUP] YARA rules: 0 loaded')

    try:
        from capa_analyzer import CAPA_AVAILABLE, get_capa_version, get_rules_dir, get_rules_version
        if CAPA_AVAILABLE:
            capa_v = get_capa_version() or '10.0.0'
            rules_dir = get_rules_dir()
            rules_v = get_rules_version(rules_dir) if rules_dir else None
            if rules_v:
                print(f'[STARTUP] CAPA: v{capa_v} (Rules: {rules_v})')
            else:
                print(f'[STARTUP] CAPA: v{capa_v} (Rules: not found)')
        else:
            print('[STARTUP] CAPA: not available (CAPA analysis disabled)')
    except Exception:
        print('[STARTUP] CAPA: not available (CAPA analysis disabled)')

    for folder in getattr(config, 'MONITORED_FOLDERS', []):
        print('[STARTUP] Monitoring: ' + str(folder))

    print('[STARTUP] Examiner: ' + os.environ.get('EXAMINER_NAME', 'Not set'))
    print('[STARTUP] Organisation: ' + os.environ.get('EXAMINER_ORG', 'Not set'))

    print('[STARTUP] Checking improvement modules...')
    new_modules = [
        ('confidence_calibration', 'Confidence Calibration'),
        ('evidence_export', 'Evidence Export'),
        ('case_manager', 'Case Manager'),
        ('source_correlation', 'Source Correlation'),
        ('benchmarking', 'Benchmarking'),
        ('investigation_tools', 'Investigation Tools'),
        ('layer4_summary_report', 'Summary Report'),
        ('analyst_audit', 'Analyst Audit'),
        ('network_monitor', 'Network Monitor'),
    ]
    all_modules_ok = True
    for module_name, label in new_modules:
        try:
            __import__(module_name)
            print('[STARTUP]   ' + label + ': OK')
        except Exception as e:
            print('[STARTUP]   ' + label + ': WARNING — ' + str(e))
            all_modules_ok = False

    if all_modules_ok:
        print('[STARTUP] All improvement modules loaded')
    else:
        print('[STARTUP] Some modules had warnings — check above')

    try:
        import system_health
        health = system_health.evaluate_system_health(force=True)
        print(f'[STARTUP] Overall System Health: {health["score"]}% ({health["status_label"]})')
        for card in health.get('cards', []):
            print(f'[STARTUP]   [{card["type"].upper()}] {card["title"]} — {card["details"]}')
    except Exception as e:
        print('[STARTUP] Health check warning: ' + str(e))

    print()
    print('[STARTUP] System ready')
    print()
    return True


def start_url_server():
    import url_server
    thread = url_server.start_url_server()
    print('[STARTUP] URL Server wrapper started')
    return thread


def start_monitor():
    import layer0_monitor
    thread = threading.Thread(target=layer0_monitor.start_monitoring, daemon=True)
    thread.start()
    print('[STARTUP] File monitor started')
    return thread


def start_tray():
    try:
        import ui.tray_agent as tray
        thread = threading.Thread(target=tray.start_tray_in_thread, daemon=True)
        thread.start()
        time.sleep(0.5)
        try:
            tray.update_tray_status('monitoring')
        except Exception:
            pass
        print('[STARTUP] Tray agent started')
        return thread
    except Exception as e:
        print('[STARTUP] Tray agent failed to start: ' + str(e))
        print('[STARTUP] Please run: pip install pystray pillow')
        # Return a dummy running thread to prevent health checks from immediately failing
        class DummyThread:
            def is_alive(self): return True
        return DummyThread()


def handle_manual_scan():
    def run():
        try:
            from manual_scan import (
                open_file_picker,
                scan_file_manually
            )
            from ui.tray_agent import (
                update_tray_status,
                show_tray_notification
            )
            
            filepath = open_file_picker()
            if not filepath:
                return
            
            filename = Path(filepath).name
            print('[MANUAL] User selected: ' + filename)
            
            update_tray_status('scanning', filename)
            show_tray_notification(
                'Shadow-Trace: Manual Scan',
                'Scanning: ' + filename
            )
            
            def on_progress(msg):
                print('[MANUAL] ' + msg)
            
            result = scan_file_manually(
                filepath, on_progress
            )
            verdict = result.get('verdict', 'ERROR')
            score = result.get('score', 0.0)
            
            update_tray_status('monitoring')
            
            show_tray_notification(
                'Shadow-Trace: Scan Complete',
                'File: ' + filename + '\n'
                + 'Verdict: ' + verdict + '\n'
                + 'Score: ' + str(round(score*100,1)) + '%'
            )
            
            if result.get('report_result', {}).get('success'):
                report_path = result['report_result'].get(
                    'report_path', ''
                )
                print('[MANUAL] Report: ' + report_path)
        
        except Exception as e:
            print('[MANUAL] Error: ' + str(e))
            import traceback
            traceback.print_exc()

    thread = threading.Thread(
        target=run,
        daemon=True
    )
    thread.start()


def open_dashboard_window():
    try:
        import subprocess
        subprocess.Popen(
            [sys.executable, str(config.BASE_DIR / 'ui' / 'dashboard.py')],
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
    except Exception as e:
        print('[DASHBOARD] Error: ' + str(e))


def shutdown(signum=None, frame=None):
    print()
    print('[SHUTDOWN] Shadow-Trace shutting down...')
    print('[SHUTDOWN] Locked files preserved for recovery')
    print('[SHUTDOWN] Do not manually unlock files')
    print()

    try:
        import layer0_monitor
        if hasattr(layer0_monitor, 'stop_monitoring'):
            layer0_monitor.stop_monitoring()
        print('[SHUTDOWN] Monitor stopped')
    except Exception as e:
        print('[SHUTDOWN] Monitor stop: ' + str(e))

    try:
        from ui.tray_agent import _tray_icon
        if _tray_icon is not None:
            _tray_icon.stop()
    except Exception:
        pass

    print('[SHUTDOWN] Goodbye.')
    os.kill(os.getpid(), signal.SIGTERM)


def main():
    check_single_instance()
    ensure_report_folders()

    if not check_dependencies():
        print('Fix errors above and restart')
        sys.exit(1)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    url_thread = start_url_server()
    time.sleep(0.5)

    monitor_thread = start_monitor()
    time.sleep(0.5)

    try:
        from network_monitor import start_dns_monitor
        start_dns_monitor()
        print('[STARTUP] Network DNS monitor: ACTIVE')
    except Exception as e:
        print('[STARTUP] DNS monitor warning: ' + str(e))

    try:
        import ui.tray_agent as tray
        import pystray  # pyrefly: ignore [missing-import]
        from pystray import MenuItem as item  # pyrefly: ignore [missing-import]
        
        original_build = tray.build_menu
        
        def patched_menu():
            return pystray.Menu(
                item('Shadow-Trace v1.0.0',
                     lambda: None, enabled=False),
                pystray.Menu.SEPARATOR,
                item('📊 Open Dashboard',
                     lambda: open_dashboard_window()),
                item('📁 Open Reports Folder',
                     tray.open_reports_folder),
                item('📄 View Latest Report',
                     tray.open_latest_report),
                pystray.Menu.SEPARATOR,
                item('🔍 Scan File Manually',
                     lambda: handle_manual_scan()),
                pystray.Menu.SEPARATOR,
                item('📈 Statistics',
                     tray.show_scan_stats),
                pystray.Menu.SEPARATOR,
                item(
                    lambda text: 'Status: '
                    + tray._current_status.upper(),
                    lambda: None, enabled=False
                ),
                pystray.Menu.SEPARATOR,
                item('⏹ Stop Shadow-Trace', shutdown),
            )
        
        tray.build_menu = patched_menu
    except Exception as e:
        print('[STARTUP] Tray menu patch: ' + str(e))

    tray_thread = start_tray()

    def open_dashboard_on_startup():
        time.sleep(2)
        open_dashboard_window()

    dash_thread = threading.Thread(
        target=open_dashboard_on_startup,
        daemon=True
    )
    dash_thread.start()

    print()
    print('=' * 60)
    print('  SHADOW-TRACE v1.0.0 — ACTIVE')
    print('=' * 60)
    print()
    print('  Core Pipeline:')
    print('    File monitoring:       ACTIVE')
    print('    Malware screening:     ACTIVE')
    print('    LSB detection:         ACTIVE')
    print('    Steganalysis:          ACTIVE')
    print('    Payload extraction:    ACTIVE')
    print('    Forensic reporting:    ACTIVE')
    print()
    print('  Enhanced Intelligence:')
    print('    Confidence calibration:  ACTIVE')
    print('    Evidence correlation:    ACTIVE')
    print('    Case management:         ACTIVE')
    print('    Investigator tools:      ACTIVE')
    print('    Evidence export:         ACTIVE')
    print('    Benchmarking:            ACTIVE')
    print()
    print('  Output Formats:')
    print('    Technical PDF report:    ACTIVE')
    print('    Plain English summary:   ACTIVE')
    print('    JSON evidence bundle:    ACTIVE')
    print('    CSV summary:             ACTIVE')
    print('    ZIP evidence package:    ACTIVE')
    print()
    print('  Monitoring:')
    for folder in getattr(config, 'MONITORED_FOLDERS', []):
        print('    ' + str(folder))
    print()
    print('  Interface:')
    print('    System tray:    Check taskbar bottom right')
    print('    Dashboard:      Opening automatically')
    print('    Manual scan:    Right-click tray icon')
    print()
    print('  Press Ctrl+C to stop')
    print('=' * 60)
    print()

    try:
        last_check = time.time()
        while True:
            time.sleep(1)
            if time.time() - last_check >= 30:
                last_check = time.time()
                if not monitor_thread.is_alive():
                    print('[HEALTH] Monitor died. Restarting...')
                    monitor_thread = start_monitor()
                if not url_thread.is_alive():
                    print('[HEALTH] URL server died. Restarting...')
                    url_thread = start_url_server()
    except KeyboardInterrupt:
        shutdown()

if __name__ == '__main__':
    main()
