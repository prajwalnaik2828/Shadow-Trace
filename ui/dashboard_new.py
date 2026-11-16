import os
import sys
import json
import sqlite3
import threading
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
import config

from ui.report_viewer import fetch_all_reports, verify_report_seal

def get_dashboard_data() -> dict:
    stats = {
        'total_scanned': 0,
        'total_threats': 0,
        'total_clean': 0,
        'total_suspicious': 0,
    }
    
    db_path = config.BASE_DIR / 'shadowtrace_recovery.db'
    try:
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cursor.fetchall()]
        
        if 'files' in tables:
            cursor.execute("SELECT COUNT(*) FROM files")
            stats['total_scanned'] = cursor.fetchone()[0]
        else:
            cursor.execute("SELECT COUNT(*) FROM locked_files WHERE status='COMPLETE'")
            result = cursor.fetchone()
            stats['total_scanned'] = result[0] if result else 0
            
        conn.close()
    except Exception as e:
        print('[DASHBOARD] DB error: ' + str(e))

    all_reports = fetch_all_reports()
    
    for r in all_reports:
        v = r.get('category', '').upper()
        if v == 'STEGO' or v == 'THREAT':
            stats['total_threats'] += 1
        elif v == 'CLEAN':
            stats['total_clean'] += 1
        elif v == 'SUSPICIOUS':
            stats['total_suspicious'] += 1

    recent_reports = all_reports[:15]

    models_dir = config.BASE_DIR / 'models'
    model_status = []
    
    model_files = [
        ('image_model.pth', 'Image Analysis (YedroudjNetV3)', 'Detects spatial LSB steganography'),
        ('alaska2_tier2_model.pth', 'Adaptive Stego (ALASKA2)', 'Detects JMiPOD JUNIWARD UERD'),
        ('video_model.pth', 'Video Analysis (VideoStegNet)', 'Four-stream video steganalysis'),
        ('doc_model.pth', 'Document Analysis (DistilBERT)', 'Detects text steganography'),
    ]
    
    for filename, label, description in model_files:
        path = models_dir / filename
        model_status.append({
            'name': label,
            'description': description,
            'loaded': path.exists(),
            'size_mb': round(path.stat().st_size / 1e6, 1) if path.exists() else 0,
        })

    folders = []
    monitored = getattr(config, 'MONITORED_DIRS', [])
    for f in monitored:
        p = Path(f)
        folders.append({
            'path': str(p),
            'exists': p.exists(),
            'name': p.name,
        })

    benchmarks = []
    bench_dir = config.BASE_DIR / 'logs' / 'benchmarks'
    if bench_dir.exists():
        for b in bench_dir.glob('*.json'):
            try:
                with open(b, 'r') as f:
                    benchmarks.append(json.load(f))
            except:
                pass
    benchmarks.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    return {
        'stats': stats,
        'recent_reports': recent_reports,
        'all_reports': all_reports,
        'model_status': model_status,
        'monitored_folders': folders,
        'benchmarks': benchmarks,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'version': '1.0.0',
        'examiner': os.environ.get('EXAMINER_NAME', 'Digital Forensic Examiner'),
        'organisation': os.environ.get('EXAMINER_ORG', 'Anjuman Institute of Technology'),
    }

def generate_html(data: dict) -> str:
    with open(Path(__file__).parent / 'dashboard_ui.html', 'r', encoding='utf-8') as f:
        html = f.read()
    
    # Replace placeholders with JSON data payload
    html = html.replace('__INITIAL_DATA__', json.dumps(data))
    return html

class DashboardAPI:
    def open_report(self, path: str):
        try:
            os.startfile(path)
        except Exception as e:
            print('Open report error: ' + str(e))

    def open_reports_folder(self):
        reports_dir = config.BASE_DIR / 'reports'
        reports_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(reports_dir))
        except Exception as e:
            print('Open folder error: ' + str(e))

    def open_folder(self, path: str):
        try:
            import os
            os.startfile(path)
        except Exception as e:
            print('Open folder error: ' + str(e))

    def refresh_data(self):
        try:
            data = get_dashboard_data()
            return json.dumps(data)
        except Exception as e:
            print('Refresh error: ' + str(e))
            return "{}"

    def get_report_details(self, path: str) -> str:
        result = verify_report_seal(path)
        return json.dumps(result)

    def add_note(self, session_id: str, note_text: str, note_type: str = 'GENERAL') -> str:
        try:
            from investigation_tools import add_note
            result = add_note(session_id, note_text, note_type=note_type)
            return json.dumps(result)
        except Exception as e:
            return json.dumps({'error': str(e)})

    def add_tag(self, session_id: str, tag: str) -> str:
        try:
            from investigation_tools import add_tag
            result = add_tag(session_id, tag)
            return json.dumps(result)
        except Exception as e:
            return json.dumps({'error': str(e)})

    def get_session_investigation(self, session_id: str) -> str:
        try:
            from investigation_tools import get_full_session_view
            result = get_full_session_view(session_id)
            return json.dumps(result, default=str)
        except Exception as e:
            return json.dumps({'error': str(e)})

    def queue_reprocess(self, session_id: str, filepath: str, reason: str) -> str:
        try:
            from investigation_tools import queue_for_reprocess
            result = queue_for_reprocess(session_id, filepath, reason)
            return json.dumps(result)
        except Exception as e:
            return json.dumps({'error': str(e)})

    def open_evidence_package(self, session_id: str) -> str:
        try:
            import os
            from case_manager import find_reports_for_session
            reports = find_reports_for_session(session_id)
            for r in reports:
                if r.get('report_type') == 'EVIDENCE_PACKAGE':
                    os.startfile(r['path'])
                    return json.dumps({'success': True})
            return json.dumps({'success': False, 'error': 'No evidence package found'})
        except Exception as e:
            return json.dumps({'error': str(e)})

def open_dashboard():
    try:
        import webview  # pyrefly: ignore [missing-import]
    except ImportError:
        print('pywebview not installed')
        print('Run: pip install pywebview')
        return

    data = get_dashboard_data()
    html = generate_html(data)

    api = DashboardAPI()

    window = webview.create_window(
        title='Shadow-Trace Analysis Environment',
        html=html,
        js_api=api,
        width=1400,
        height=900,
        resizable=True,
        min_size=(1024, 768),
        background_color='#0f0f23',
    )

    webview.start(
        debug=False,
        private_mode=True,
    )

if __name__ == '__main__':
    print('Opening pywebview dashboard...')
    open_dashboard()
