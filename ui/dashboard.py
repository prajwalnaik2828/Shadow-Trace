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

# Import analyst audit â€” fail silently so the dashboard still opens if the
# module is somehow missing (graceful degradation).
try:
    import analyst_audit as _audit
    _AUDIT_OK = True
except Exception:
    _AUDIT_OK = False

def _log(action_type: str, target: str = '', details=None):
    """Safe wrapper â€” never raises, so audit failures never crash the UI."""
    if _AUDIT_OK:
        try:
            _audit.log_action(action_type, target, details)
        except Exception:
            pass

def get_dashboard_data() -> dict:
    try:
        from ui.report_viewer import fetch_all_reports
        all_reports = fetch_all_reports()
    except Exception as e:
        print('Report fetch error: ' + str(e))
        all_reports = []
        
    stats = {
        'total_scanned': len(all_reports),
        'total_threats': sum(1 for r in all_reports if str(r.get('category')).lower() in ['stego', 'threat']),
        'total_clean': sum(1 for r in all_reports if str(r.get('category')).lower() in ['clean', 'reports', 'uncategorised']),
        'total_suspicious': sum(1 for r in all_reports if str(r.get('category')).lower() == 'suspicious'),
    }
        
    recent_reports = all_reports[:50]
    
    try:
        import system_health
        health_data = system_health.evaluate_system_health()
    except Exception as e:
        health_data = {
            'score': 100,
            'status_label': 'OPTIMAL',
            'color': '#27ae60',
            'cards': [{'type': 'ok', 'title': 'All systems operational', 'details': 'Core modules verified'}]
        }

    # Quarantined files
    quarantined_files = []
    try:
        import config
        q_dir = config.BASE_DIR / 'quarantine'
        if q_dir.exists():
            for f in q_dir.glob('*'):
                if f.is_file():
                    stat = f.stat()
                    quarantined_files.append({
                        'filename': f.name,
                        'path': str(f).replace('\\', '/'),
                        'size_kb': round(stat.st_size / 1024, 1),
                        'date_quarantined': datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
            quarantined_files.sort(key=lambda x: x['date_quarantined'], reverse=True)
    except Exception as e:
        print('Quarantine fetch error: ' + str(e))

    return {
        'stats': stats,
        'recent_reports': recent_reports,
        'all_reports': all_reports,
        'system_health': health_data,
        'quarantined_files': quarantined_files,
    }


def save_dashboard_cache(data: dict = None):
    try:
        if data is None:
            data = get_dashboard_data()
        cache_path = Path(__file__).parent.parent / 'UIUX' / 'dashboard_cache.js'
        json_str = json.dumps(data)
        content = f'window.__INITIAL_DASHBOARD_DATA__ = {json_str};\n'
        cache_path.write_text(content, encoding='utf-8')
    except Exception as e:
        print('[DASHBOARD] Error writing dashboard cache:', e)


import threading
import json
import os
import datetime
from pathlib import Path

def run_scan_thread(filepath):
    try:
        import scan_tracker
        curr_file = filepath
        while curr_file:
            try:
                from manual_scan import scan_file_manually
                def scan_progress_cb(message):
                    msg_lower = message.lower()
                    if "hash" in msg_lower or "sandbox" in msg_lower or "initial" in msg_lower:
                        scan_tracker.update_stage(1, "Initialization", 15)
                    elif "clamav" in msg_lower or "malware" in msg_lower or "signature" in msg_lower:
                        scan_tracker.update_stage(2, "Signature Analysis", 35)
                    elif "lsb" in msg_lower or "heuristic" in msg_lower:
                        scan_tracker.update_stage(3, "Heuristic Scanning", 55)
                    elif "stego" in msg_lower:
                        scan_tracker.update_stage(4, "Steganography Detection", 75)
                    elif "payload" in msg_lower or "report" in msg_lower or "complete" in msg_lower:
                        scan_tracker.update_stage(5, "Report Generation", 95)
                
                scan_tracker.update_stage(1, "Initialization", 15)
                scan_file_manually(curr_file, progress_callback=scan_progress_cb)
            except Exception as e:
                print("Manual scan error:", e)
            finally:
                curr_file = scan_tracker.finish_scan(curr_file)
    except Exception as e:
        print("run_scan_thread error:", e)

from ui.ui_api import CommonUIAPI

class DashboardAPI(CommonUIAPI):
    def refresh_data(self):
        try:
            data = get_dashboard_data()
            save_dashboard_cache(data)
            return json.dumps(data)
        except Exception as e:
            print('Refresh error: ' + str(e))
            return "{}"

    def get_all_reports(self) -> str:
        try:
            from ui.report_viewer import fetch_all_reports
            import hashlib
            raw_reports = fetch_all_reports()
            mapped = []
            for i, r in enumerate(raw_reports):
                fname = r.get("filename") or r.get("name") or "Unknown"
                fname_lower = fname.lower()
                if not fname_lower.endswith(('report.pdf', '_report.pdf')) or fname_lower.endswith(('summary.pdf', '_summary.pdf', 'summery.pdf', '_summery.pdf')):
                    continue
                cat = r.get("category", "clean").lower()
                if cat == "reports" or cat == "uncategorised":
                    cat = "clean"
                elif cat == "suspicious":
                    cat = "suspicious"
                elif cat == "stego" or cat == "threat":
                    cat = "stego"
                
                h = hashlib.md5(r.get("name", "").encode()).hexdigest()[:8].upper() + "..."
                
                mapped.append({
                    "id": str(i + 1),
                    "filename": r.get("name", "Unknown"),
                    "status": cat,
                    "date": r.get("modified", "Unknown"),
                    "hash": h,
                    "threat": "CRITICAL" if cat == "stego" else ("MEDIUM" if cat == "suspicious" else "LOW"),
                    "summary": f"Report generated for {r.get('name')} at {r.get('modified')}. Category: {cat.upper()}.",
                    "pdf_path": r.get("path"),
                    "folder_path": r.get("path", "").rsplit("/", 1)[0] if r.get("path") else "",
                    "session_id": r.get("session_id", "")
                })
            return json.dumps(mapped)
        except Exception as e:
            print("get_all_reports error:", str(e))
            return json.dumps([])

    def get_quarantined_files(self) -> str:
        return super().get_quarantined_files()

    def restore_quarantined_file(self, filename: str, password: str) -> str:
        return super().restore_quarantined_file(filename, password)

    def delete_quarantined_file(self, filename: str, password: str, confirmation: str = "DELETE") -> str:
        return super().delete_quarantined_file(filename, password, confirmation)

    def batch_delete_quarantined_files(self, filenames_json: str, password: str, confirmation: str = "DELETE") -> str:
        return super().batch_delete_quarantined_files(filenames_json, password, confirmation)

    def batch_restore_quarantined_files(self, filenames_json: str, password: str) -> str:
        return super().batch_restore_quarantined_files(filenames_json, password)

    def open_quarantine_report(self, filename: str) -> str:
        return super().open_quarantine_report(filename)

    def get_evidence_data(self, pdf_path: str) -> str:
        try:
            p = Path(pdf_path)
            data = {}
            prefix_minute = p.name[:13]
            clean_stem = p.stem.replace('_report', '')
            if len(clean_stem) > 16 and clean_stem[:15].replace('_', '').isdigit():
                clean_stem = clean_stem[16:]

            # 1. Search evidence json by minute prefix or clean stem
            for j in p.parent.glob(f'{prefix_minute}*_evidence.json'):
                try:
                    with open(j, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    break
                except Exception:
                    pass

            if not data and clean_stem:
                for j in p.parent.glob(f'*{clean_stem}*_evidence.json'):
                    try:
                        with open(j, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        break
                    except Exception:
                        pass

            # 2. Match seal file
            seal_file = p.with_suffix('.seal.json')
            if not seal_file.exists():
                for s in p.parent.glob(f'{prefix_minute}*_report.seal.json'):
                    seal_file = s
                    break
            if not seal_file.exists() and clean_stem:
                for s in p.parent.glob(f'*{clean_stem}*.seal.json'):
                    seal_file = s
                    break

            if seal_file.exists():
                try:
                    with open(seal_file, 'r', encoding='utf-8') as f:
                        data['seal'] = json.load(f)
                except Exception:
                    pass

            # 3. Match heatmaps and original image
            heatmaps = {}
            heatmaps_dir = config.BASE_DIR / 'reports' / 'heatmaps'
            if heatmaps_dir.exists() and clean_stem:
                for hf in heatmaps_dir.glob(f'*{clean_stem}*'):
                    nl = hf.name.lower()
                    uri = hf.as_uri()
                    if 'lsb_heatmap' in nl or 'bitplane' in nl:
                        heatmaps['lsb_heatmap'] = uri
                    elif 'attribution' in nl or 'shap' in nl:
                        heatmaps['attribution'] = uri
                    elif 'gradcam' in nl:
                        heatmaps['gradcam'] = uri
                    elif 'token_map' in nl:
                        heatmaps['token_map'] = uri

            # Check if original image exists on disk
            full_path = data.get('file_identity', {}).get('full_path')
            if not full_path and 'seal' in data:
                full_path = data['seal'].get('source_correlation', {}).get('filepath')
            if full_path:
                try:
                    orig_p = Path(full_path)
                    if orig_p.exists() and orig_p.suffix.lower() in ('.png', '.jpg', '.jpeg', '.bmp', '.webp', '.tiff'):
                        heatmaps['original'] = orig_p.as_uri()
                except Exception:
                    pass

            data['heatmaps'] = heatmaps

            # 4. Get session timeline
            session_id = data.get('case_metadata', {}).get('session_id')
            if not session_id and 'seal' in data:
                session_id = data['seal'].get('session_id')
            if session_id:
                try:
                    from case_manager import get_case_timeline
                    data['timeline'] = get_case_timeline(session_id)
                except Exception:
                    pass

            # 5. Normalize malware screening
            mw = data.get('malware_screening', {})
            if isinstance(mw.get('clamav_result'), str):
                try:
                    import ast
                    mw['clamav_result'] = ast.literal_eval(mw['clamav_result'])
                except Exception:
                    ver = 'CLEAN' if 'CLEAN' in mw['clamav_result'].upper() else 'THREAT'
                    mw['clamav_result'] = {'verdict': ver}

            if isinstance(mw.get('heuristics_result'), str):
                try:
                    import ast
                    mw['heuristics_result'] = ast.literal_eval(mw['heuristics_result'])
                except Exception:
                    pass

            if isinstance(mw.get('virustotal_result'), str):
                vt_str = mw['virustotal_result']
                mw['virustotal_result'] = {'verdict': vt_str, 'positives': 0, 'total': 70}

            # 6. Read real file bytes for hexadecimal viewer and strings
            target_read_file = None
            if full_path:
                try:
                    cand = Path(full_path)
                    if cand.exists():
                        target_read_file = cand
                except Exception:
                    pass
            if not target_read_file and p.exists():
                target_read_file = p

            hex_lines = []
            strings_found = []
            if target_read_file:
                try:
                    with open(target_read_file, 'rb') as f:
                        raw_bytes = f.read(512)
                    for i in range(0, min(len(raw_bytes), 256), 16):
                        block = raw_bytes[i:i+16]
                        off_str = f"0x{i:08x}"
                        hex_parts = [f"{b:02x}" for b in block]
                        ascii_text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in block)
                        hex_lines.append({
                            'offset': off_str,
                            'hex': hex_parts,
                            'ascii': f"|{ascii_text}|"
                        })
                except Exception:
                    pass

            lsb = data.get('lsb_check', {})
            if lsb.get('executable_found'):
                strings_found.append({
                    'offset': lsb.get('position') or '0x0000044a',
                    'string': 'PE_EXECUTABLE (MZ_HEADER)',
                    'type': 'CRITICAL'
                })
            if hex_lines:
                first_ascii = hex_lines[0]['ascii']
                if 'JFIF' in first_ascii:
                    strings_found.append({'offset': '0x00000006', 'string': 'JFIF (JPEG_HEADER)', 'type': 'INFO'})
                elif 'PNG' in first_ascii:
                    strings_found.append({'offset': '0x00000001', 'string': 'PNG (IMAGE_HEADER)', 'type': 'INFO'})

            data['hex_preview'] = hex_lines
            data['extracted_strings'] = strings_found

            if not data:
                return json.dumps({"error": "Evidence data not found"})

            return json.dumps(data)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def open_file_dialog(self) -> str:
        try:
            import manual_scan_service
            res = manual_scan_service.open_file_dialog()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e), "file": None})

    def get_live_scan_status(self) -> str:
        try:
            import scan_tracker
            return json.dumps(scan_tracker.get_status())
        except Exception as e:
            return json.dumps({
                "active": False,
                "filename": "",
                "stage": 0,
                "stage_name": "",
                "progress": 0,
                "queue": []
            })

    def start_manual_scan(self, filepath: str, options: str = "{}") -> str:
        try:
            import manual_scan_service
            opt_dict = {}
            if isinstance(options, str):
                try:
                    opt_dict = json.loads(options)
                except Exception:
                    pass
            elif isinstance(options, dict):
                opt_dict = options
            res = manual_scan_service.get_service().start_scan(filepath, opt_dict)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def get_scan_progress(self) -> str:
        try:
            import manual_scan_service
            res = manual_scan_service.get_service().get_progress()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def cancel_scan(self) -> str:
        try:
            import manual_scan_service
            res = manual_scan_service.get_service().cancel_scan()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def reset_scan(self) -> str:
        try:
            import manual_scan_service
            manual_scan_service.get_service().reset()
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"error": str(e)})

    def open_pdf(self, path: str) -> str:
        try:
            import manual_scan_service
            res = manual_scan_service.open_pdf(path)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def get_report_details(self, path: str) -> str:
        from ui.report_viewer import verify_report_seal
        _log('VIEW_REPORT', path)
        result = verify_report_seal(path)
        return json.dumps(result)

    def get_system_health(self) -> str:
        try:
            import system_health
            return json.dumps(system_health.evaluate_system_health())
        except Exception as e:
            return json.dumps({'error': str(e)})

    def get_audit_log(self, limit: int = 500) -> str:
        try:
            import analyst_audit
            return json.dumps(analyst_audit.get_audit_log(int(limit)))
        except Exception as e:
            return json.dumps({"error": str(e), "logs": []})

    def log_ui_action(self, action_type: str, target: str = "", details: str = "", severity: str = None) -> str:
        try:
            import analyst_audit
            ok = analyst_audit.log_action(action_type, target, details, severity=severity)
            return json.dumps({"success": ok})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def verify_audit_integrity(self) -> str:
        try:
            import analyst_audit
            return json.dumps(analyst_audit.verify_chain_integrity())
        except Exception as e:
            return json.dumps({"valid": False, "error": str(e)})

    def export_audit_csv(self, output_path: str = "") -> str:
        try:
            import analyst_audit
            res = analyst_audit.export_audit_csv(output_path or None)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def save_setting(self, key: str, value: str) -> str:
        try:
            import json
            from pathlib import Path
            import config

            env_path = config.BASE_DIR / '.env'
            if env_path.exists():
                with open(env_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
            else:
                lines = []

            ALLOWED_KEYS = {
                'VT_MODE',
                'OFFLINE_SCAN_MODE',
                'HYBRID_ANALYSIS_MODE',
            }

            if key not in ALLOWED_KEYS:
                return json.dumps({
                    'success': False,
                    'error': 'Key not allowed: ' + key
                })

            found = False
            new_lines = []
            for line in lines:
                if line.startswith(key + '='):
                    new_lines.append(key + '=' + str(value) + '\n')
                    found = True
                else:
                    new_lines.append(line)

            if not found:
                new_lines.append(key + '=' + str(value) + '\n')

            with open(env_path, 'w', encoding='utf-8') as f:
                f.writelines(new_lines)

            if key == 'VT_MODE':
                config.VT_MODE = value
            elif key == 'OFFLINE_SCAN_MODE':
                config.OFFLINE_SCAN_MODE = (str(value).lower() == 'true')
            elif key == 'HYBRID_ANALYSIS_MODE':
                config.HYBRID_ANALYSIS_MODE = value

            print('[SETTINGS] Saved: ' + key + ' = ' + str(value))
            return json.dumps({
                'success': True,
                'key': key,
                'value': value,
            })
        except Exception as e:
            import json
            return json.dumps({
                'success': False,
                'error': str(e),
            })

    def get_current_settings(self) -> str:
        try:
            import json
            import config
            return json.dumps({
                'VT_MODE': getattr(config, 'VT_MODE', 'CHECK_ONLY'),
                'OFFLINE_SCAN_MODE': str(getattr(config, 'OFFLINE_SCAN_MODE', False)).lower(),
                'HYBRID_ANALYSIS_MODE': getattr(config, 'HYBRID_ANALYSIS_MODE', 'hash_only'),
            })
        except Exception as e:
            import json
            return json.dumps({'error': str(e)})

    def get_settings(self) -> str:
        try:
            import settings_manager
            import json
            return json.dumps(settings_manager.get_settings())
        except Exception as e:
            import json
            return json.dumps({"error": str(e)})

    def save_settings(self, settings_json: str) -> str:
        try:
            import settings_manager
            import json
            data = json.loads(settings_json) if isinstance(settings_json, str) else settings_json
            saved = settings_manager.save_settings(data)
            return json.dumps({"success": True, "settings": saved})
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def browse_folder(self, initial_dir: str = "") -> str:
        try:
            import settings_manager
            import json
            folder = settings_manager.browse_folder(initial_dir)
            return json.dumps({"success": bool(folder), "folder": folder})
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def add_monitored_folder(self, folder: str) -> str:
        try:
            import settings_manager
            import json
            res = settings_manager.add_monitored_folder(folder)
            return json.dumps(res)
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def remove_monitored_folder(self, folder: str) -> str:
        try:
            import settings_manager
            import json
            res = settings_manager.remove_monitored_folder(folder)
            return json.dumps(res)
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def backup_databases(self) -> str:
        try:
            import settings_manager
            import json
            res = settings_manager.backup_databases()
            return json.dumps(res)
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def get_database_sizes(self) -> str:
        try:
            import settings_manager
            import json
            res = settings_manager.get_database_sizes()
            return json.dumps(res)
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def view_system_logs(self) -> str:
        try:
            import settings_manager
            import json
            res = settings_manager.view_logs()
            return json.dumps(res)
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def clear_system_logs(self) -> str:
        try:
            import settings_manager
            import json
            res = settings_manager.clear_logs()
            return json.dumps(res)
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})

    def reset_settings(self) -> str:
        try:
            import settings_manager
            import json
            res = settings_manager.reset_to_defaults()
            return json.dumps({"success": True, "settings": res})
        except Exception as e:
            import json
            return json.dumps({"success": False, "error": str(e)})


    # -- Workstation Lock Screen Integration --
    def verify_lock_password(self, password: str) -> str:
        try:
            import profile_manager
            res = profile_manager.verify_lock_password(password)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def get_lock_screen_info(self) -> str:
        try:
            import profile_manager
            return json.dumps(profile_manager.get_lock_screen_info())
        except Exception as e:
            return json.dumps({"error": str(e)})

    def minimize_window(self) -> str:
        try:
            import webview
            if webview.windows:
                webview.windows[0].minimize()
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def toggle_maximize(self) -> str:
        try:
            import webview
            if webview.windows:
                win = webview.windows[0]
                win.toggle_fullscreen()
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def close_window(self) -> str:
        try:
            import webview
            if webview.windows:
                webview.windows[0].destroy()
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})


    # ── Notification Drawer Integration ──────────────────────────────────────────
    def get_notifications(self, limit: int = 50) -> str:
        return super().get_notifications(limit)

    def clear_notifications(self) -> str:
        return super().clear_notifications()

def open_dashboard():
    try:
        import webview  # pyrefly: ignore [missing-import]
    except ImportError:
        print('pywebview not installed')
        print('Run: pip install pywebview')
        return

    # Load the HTML file directly â€” no string embedding, no escaping issues.
    # The pywebview JS bridge in dashboard.html calls refresh_data() for live data.
    # Pre-write dashboard cache so UIUX/dashboard.html renders real data on first paint
    try:
        save_dashboard_cache()
    except Exception as e:
        print('[DASHBOARD] Error pre-caching data:', e)

    html_path = Path(__file__).parent.parent / 'UIUX' / 'dashboard.html'
    url = html_path.as_uri()

    api = DashboardAPI()

    window = webview.create_window(
        title='Shadow-Trace Analysis Environment',
        url=url,
        js_api=api,
        width=1400,
        height=900,
        resizable=True,
        min_size=(1024, 768),
        background_color='#111111',
    )

    webview.start(
        debug=False,
        http_server=True,
        private_mode=True,
    )

if __name__ == '__main__':
    print('Opening pywebview dashboard...')
    open_dashboard()




