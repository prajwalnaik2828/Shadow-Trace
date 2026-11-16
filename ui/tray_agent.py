import os
import sys
import threading
import time
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont
import pystray  # pyrefly: ignore [missing-import]
from pystray import MenuItem as item  # pyrefly: ignore [missing-import]

# Add project root to sys.path so we can import config and utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import utils

# === STATUS MANAGEMENT ===
_tray_icon = None
_current_status = 'idle'
_status_lock = threading.Lock()
_scan_count = 0
_threat_count = 0
_last_scan_file = ''
_last_verdict = ''

def create_tray_icon(status: str) -> Image.Image:
    icon_path = config.BASE_DIR / 'ui' / 'assets' / f'icon_{status}.png'
    if icon_path.exists():
        try:
            return Image.open(str(icon_path))
        except Exception:
            pass
            
    # Fallback if PNG fails to load
    img = Image.new('RGBA', (64, 64), (0,0,0,0))
    draw = ImageDraw.Draw(img)
    draw.ellipse([2,2,62,62], fill='#1a1a2e')
    return img

def update_tray_status(status: str, filename: str = '', verdict: str = ''):
    global _current_status, _last_scan_file, _last_verdict
    with _status_lock:
        _current_status = status
        if filename:
            _last_scan_file = filename
        if verdict:
            _last_verdict = verdict

    if _tray_icon is not None:
        try:
            new_icon = create_tray_icon(status)
            _tray_icon.icon = new_icon
            
            tooltips = {
                'monitoring': 'Shadow-Trace: Monitoring active',
                'scanning':   'Shadow-Trace: Scanning ' + filename,
                'threat':     'Shadow-Trace: THREAT DETECTED in ' + filename,
                'idle':       'Shadow-Trace: Idle',
            }
            _tray_icon.title = tooltips.get(status, 'Shadow-Trace')
        except Exception as e:
            pass

def open_dashboard():
    try:
        import subprocess
        subprocess.Popen(
            [sys.executable, str(config.BASE_DIR / 'ui' / 'dashboard.py')],
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )
    except Exception as e:
        print('[TRAY] Dashboard error: ' + str(e))

def open_reports_folder():
    try:
        reports_dir = config.BASE_DIR / 'reports'
        reports_dir.mkdir(parents=True, exist_ok=True)
        os.startfile(str(reports_dir))
    except Exception as e:
        print('[TRAY] Open reports error: ' + str(e))

def open_latest_report():
    try:
        reports_dir = config.BASE_DIR / 'reports'
        pdfs = sorted(
            reports_dir.glob('*.pdf'),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )
        if pdfs:
            os.startfile(str(pdfs[0]))
        else:
            show_tray_notification('No Reports', 'No forensic reports found yet.')
    except Exception as e:
        print('[TRAY] Open report error: ' + str(e))

def show_scan_stats():
    try:
        msg = (
            f'Files scanned: {_scan_count}\n'
            f'Threats found: {_threat_count}\n'
            f'Last scan: {_last_scan_file[:40]}\n'
            f'Last verdict: {_last_verdict}'
        )
        show_tray_notification('Shadow-Trace Statistics', msg)
    except Exception as e:
        print('[TRAY] Stats error: ' + str(e))

def show_tray_notification(title: str, message: str):
    try:
        if _tray_icon is not None:
            _tray_icon.notify(message, title)
    except Exception as e:
        print('[TRAY] Notification error: ' + str(e))

def quit_shadow_trace():
    try:
        show_tray_notification(
            'Shadow-Trace',
            'Stopping Shadow-Trace...\nLocked files will be processed on restart.'
        )
        time.sleep(1)
        if _tray_icon is not None:
            _tray_icon.stop()
        import signal
        import os
        os.kill(os.getpid(), signal.SIGTERM)
    except Exception as e:
        import sys
        sys.exit(0)

def build_menu() -> pystray.Menu:
    return pystray.Menu(
        item('Shadow-Trace v1.0.0', lambda: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item('📊 Open Dashboard', open_dashboard),
        item('📁 Open Reports Folder', open_reports_folder),
        item('📄 View Latest Report', open_latest_report),
        pystray.Menu.SEPARATOR,
        item('📈 Scan Statistics', show_scan_stats),
        pystray.Menu.SEPARATOR,
        item(lambda text: 'Status: ' + _current_status.upper(), lambda: None, enabled=False),
        pystray.Menu.SEPARATOR,
        item('⏹ Stop Shadow-Trace', quit_shadow_trace)
    )

def start_tray() -> None:
    global _tray_icon
    initial_icon = create_tray_icon('monitoring')
    menu = build_menu()
    
    _tray_icon = pystray.Icon(
        name='ShadowTrace',
        icon=initial_icon,
        title='Shadow-Trace: Active',
        menu=menu
    )
    
    print('[TRAY] System tray started')
    print('[TRAY] Right-click the tray icon for options')
    _tray_icon.run()

def start_tray_in_thread() -> threading.Thread:
    thread = threading.Thread(
        target=start_tray,
        name='TrayAgent',
        daemon=True
    )
    thread.start()
    time.sleep(1)
    return thread

if __name__ == '__main__':
    print('Testing Shadow-Trace tray agent...\n')
    
    print('Test 1: Icon generation')
    for status in ['monitoring', 'scanning', 'threat', 'idle']:
        icon = create_tray_icon(status)
        test_path = config.BASE_DIR / ('test_icon_' + status + '.png')
        icon.save(str(test_path))
        size = test_path.stat().st_size
        print('  ' + status + ': ' + str(size) + ' bytes')
        test_path.unlink()
    print('  Icon test: PASS\n')
    
    print('Test 2: Starting tray icon...')
    print('  Right-click the tray icon in the taskbar')
    print('  Click Stop Shadow-Trace to exit\n')
    start_tray()
