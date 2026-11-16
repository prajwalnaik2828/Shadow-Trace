from datetime import datetime, timezone
import os
# =============================================================================
# Shadow-Trace | ui/ui_api.py
# Shared API bridge between pywebview frontend and Python forensic services.
# =============================================================================

import json
from pathlib import Path
import analyst_audit


def _format_notif_time_ago(dt: datetime) -> str:
    now = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    diff = (now - dt).total_seconds()
    if diff < 0:
        diff = 0
    if diff < 60:
        return "Just now"
    elif diff < 3600:
        mins = int(diff // 60)
        return f"{mins}m ago"
    elif diff < 86400:
        hrs = int(diff // 3600)
        return f"{hrs}h ago"
    elif diff < 172800:
        return "Yesterday"
    else:
        days = int(diff // 86400)
        if days < 30:
            return f"{days}d ago"
        return dt.strftime("%d %b %Y")

def _parse_notif_datetime(ts_str: str) -> datetime:
    if not ts_str:
        return datetime.now().astimezone()
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.astimezone()
        return dt
    except Exception:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            return dt.astimezone()
        except Exception:
            pass
    return datetime.now().astimezone()

def fetch_system_notifications(limit: int = 50) -> list:
    notifs = []
    seen = set()

    # 1. Audit logs (Security events, login failures, credential updates, locking)
    try:
        records = analyst_audit.get_audit_log(limit=100)
        for r in records:
            atype = (r.get('action_type') or r.get('action') or '').upper()
            if atype in ('NOTIFICATIONS_CLEARED', 'TAB_SWITCHED', 'NAVIGATE_PAGE'):
                continue
            target = r.get('target') or ''
            details = r.get('details') or ''
            dt = _parse_notif_datetime(r.get('timestamp') or r.get('date'))
            epoch = dt.timestamp()
            
            item = None
            if atype == 'LOGIN_FAILED':
                item = {
                    'id': f"audit_{r.get('id')}",
                    'tag': 'SECURITY ALERT',
                    'title': 'Unauthorized Access Attempt',
                    'message': details or 'Failed unlock attempt on workstation terminal (invalid password).',
                    'severity': 'error',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }
            elif atype == 'SETTINGS_CHANGE':
                if 'Password' in target or 'password' in details.lower():
                    item = {
                        'id': f"audit_{r.get('id')}",
                        'tag': 'CREDENTIALS UPDATED',
                        'title': 'Examiner Password Changed',
                        'message': details or 'Examiner workstation password was updated successfully.',
                        'severity': 'warning',
                        'timestamp': dt.isoformat(),
                        'epoch': epoch,
                        'time_ago': _format_notif_time_ago(dt)
                    }
                elif 'Email' in target or 'email' in details.lower() or 'OTP' in details:
                    item = {
                        'id': f"audit_{r.get('id')}",
                        'tag': 'PROFILE NOTICE',
                        'title': 'Email Security Notice',
                        'message': details or 'Registered examiner email was modified.',
                        'severity': 'warning',
                        'timestamp': dt.isoformat(),
                        'epoch': epoch,
                        'time_ago': _format_notif_time_ago(dt)
                    }
                else:
                    item = {
                        'id': f"audit_{r.get('id')}",
                        'tag': 'SETTINGS UPDATED',
                        'title': f'{target or "System"} Updated',
                        'message': details or 'Forensic workstation settings modified.',
                        'severity': 'warning',
                        'timestamp': dt.isoformat(),
                        'epoch': epoch,
                        'time_ago': _format_notif_time_ago(dt)
                    }
            elif atype == 'FILE_QUARANTINE':
                item = {
                    'id': f"audit_{r.get('id')}",
                    'tag': 'MALWARE QUARANTINED',
                    'title': 'Threat Isolated to Quarantine',
                    'message': details or f'Threat file secured in forensic quarantine vault: {target}',
                    'severity': 'error',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }
            elif atype == 'SYSTEM_ACCESS':
                item = {
                    'id': f"audit_{r.get('id')}",
                    'tag': 'TERMINAL ACCESS',
                    'title': 'Workstation Unlocked',
                    'message': details or 'Workstation unlocked successfully via password authentication.',
                    'severity': 'success',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }
            elif atype == 'SYSTEM_LOCK':
                item = {
                    'id': f"audit_{r.get('id')}",
                    'tag': 'SESSION LOCKED',
                    'title': 'Workstation Locked',
                    'message': details or 'Workstation terminal locked by analyst.',
                    'severity': 'info',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }
            elif atype in ('SCAN_FAILED', 'ERROR', 'SYSTEM_ERROR'):
                item = {
                    'id': f"audit_{r.get('id')}",
                    'tag': 'SYSTEM ERROR',
                    'title': 'System Diagnostic Warning',
                    'message': details or f'Execution error in {target}',
                    'severity': 'error',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }

            if item:
                dedup_key = (item['tag'], item['message'], int(epoch // 45))
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    notifs.append(item)
    except Exception as e:
        print("[NOTIFICATIONS] Error reading audit logs:", e)

    # 2. File Scan Reports (Stego, Threat/Malware, Suspicious, Clean)
    try:
        from ui.report_viewer import fetch_all_reports
        reports = fetch_all_reports()
        for rep in reports:
            cat = str(rep.get('category', '')).lower()
            fname = rep.get('name') or rep.get('filename') or 'Unknown File'
            clean_name = fname.replace('_report.pdf', '').replace('_summary.pdf', '')
            dt = _parse_notif_datetime(rep.get('modified'))
            epoch = dt.timestamp()
            
            item = None
            if cat in ['stego', 'threat']:
                item = {
                    'id': f"scan_{rep.get('session_id', fname)}_stego",
                    'tag': 'STEGO DETECTED' if cat == 'stego' else 'MALWARE FOUND',
                    'title': 'Stego Payload Confirmed' if cat == 'stego' else 'Malware Signature Detected',
                    'message': f'Steganographic payload detected in {clean_name}',
                    'severity': 'error',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }
            elif cat == 'suspicious':
                item = {
                    'id': f"scan_{rep.get('session_id', fname)}_susp",
                    'tag': 'SUSPICIOUS FILE',
                    'title': 'Heuristic Anomaly Flagged',
                    'message': f'Suspicious statistical anomaly identified in {clean_name}',
                    'severity': 'warning',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }
            elif cat in ['clean', 'reports', 'uncategorised']:
                item = {
                    'id': f"scan_{rep.get('session_id', fname)}_clean",
                    'tag': 'ANALYSIS COMPLETE',
                    'title': 'Scan Completed - Clean',
                    'message': f'File scan finished for {clean_name}. No threats found.',
                    'severity': 'success',
                    'timestamp': dt.isoformat(),
                    'epoch': epoch,
                    'time_ago': _format_notif_time_ago(dt)
                }

            if item:
                dedup_key = (item['tag'], item['message'], int(epoch // 60))
                if dedup_key not in seen:
                    seen.add(dedup_key)
                    notifs.append(item)
    except Exception as e:
        print("[NOTIFICATIONS] Error reading scan reports:", e)

    notifs.sort(key=lambda x: x.get('epoch', 0), reverse=True)
    return notifs[:limit]

class CommonUIAPI:
    """Shared pywebview JS API providing audit logging and verification across all UI pages."""

    def log_ui_action(self, action_type: str, target: str = "", details: str = "", severity: str = None) -> str:
        try:
            ok = analyst_audit.log_action(action_type, target, details, severity=severity)
            return json.dumps({"success": ok})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def get_audit_log(self, limit: int = 500) -> str:
        try:
            return json.dumps(analyst_audit.get_audit_log(int(limit)))
        except Exception as e:
            return json.dumps({"error": str(e), "logs": []})

    def verify_audit_integrity(self) -> str:
        try:
            return json.dumps(analyst_audit.verify_chain_integrity())
        except Exception as e:
            return json.dumps({"valid": False, "error": str(e)})

    def export_audit_csv(self, output_path: str = "") -> str:
        try:
            res = analyst_audit.export_audit_csv(output_path or None)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def export_limitations_report(self) -> str:
        try:
            analyst_audit.log_action('REPORT_EXPORT', 'SYSTEM_LIMITATIONS', 'Exported System Limitations documentation report', severity='normal')
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ── Settings Integration ─────────────────────────────────────────────────────
    def save_setting(self, key: str, value: str) -> str:
        try:
            import json
            from pathlib import Path
            import config

            env_path = config.BASE_DIR / '.env'

            # Read current .env content:
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

            # Update or add the key:
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

            # Also update config at runtime so change takes effect immediately without restart:
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
            return json.dumps(settings_manager.get_settings())
        except Exception as e:
            return json.dumps({"error": str(e)})

    def save_settings(self, settings_json: str) -> str:
        try:
            import settings_manager
            data = json.loads(settings_json) if isinstance(settings_json, str) else settings_json
            saved = settings_manager.save_settings(data)
            return json.dumps({"success": True, "settings": saved})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def add_monitored_folder(self, folder_path: str) -> str:
        try:
            import settings_manager
            res = settings_manager.add_monitored_folder(folder_path)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def remove_monitored_folder(self, folder_path: str) -> str:
        try:
            import settings_manager
            res = settings_manager.remove_monitored_folder(folder_path)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def toggle_auto_escalate(self, enabled: bool) -> str:
        try:
            import settings_manager
            res = settings_manager.toggle_auto_escalate(enabled)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def reset_settings(self) -> str:
        try:
            import settings_manager
            res = settings_manager.reset_to_defaults()
            return json.dumps({"success": True, "settings": res})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def open_file_dialog(self) -> str:
        try:
            import manual_scan_service
            res = manual_scan_service.open_file_dialog()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e), "file": None})

    def backup_databases(self) -> str:
        try:
            import settings_manager
            res = settings_manager.backup_databases()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def get_database_sizes(self) -> str:
        try:
            import settings_manager
            res = settings_manager.get_database_sizes()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def clear_system_logs(self) -> str:
        try:
            import settings_manager
            res = settings_manager.clear_logs()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def view_system_logs(self) -> str:
        try:
            import settings_manager
            res = settings_manager.view_logs()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def browse_folder(self, initial_dir: str = "") -> str:
        try:
            import settings_manager
            folder = settings_manager.browse_folder(initial_dir)
            return json.dumps({"folder": folder})
        except Exception as e:
            return json.dumps({"error": str(e), "folder": ""})

    def test_notification(self, event_type: str = "info") -> str:
        try:
            import settings_manager
            settings_manager.notify_user(
                title="System Test",
                message=f"Settings verification alert test ({event_type}).",
                alert_type=event_type
            )
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ── User Profile Integration ─────────────────────────────────────────────────
    def get_user_profile(self) -> str:
        try:
            import profile_manager
            return json.dumps(profile_manager.get_user_profile())
        except Exception as e:
            return json.dumps({"error": str(e)})

    def save_user_profile(self, profile_json: str) -> str:
        try:
            import profile_manager
            data = json.loads(profile_json) if isinstance(profile_json, str) else profile_json
            saved = profile_manager.save_user_profile(data)
            return json.dumps({"success": True, "profile": saved})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def upload_profile_photo(self, photo_data: str) -> str:
        try:
            import profile_manager
            res = profile_manager.upload_profile_photo(photo_data)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def remove_profile_photo(self) -> str:
        try:
            import profile_manager
            res = profile_manager.remove_profile_photo()
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ── Authentication & OTP Recovery ─────────────────────────────────────────────
    def check_old_password(self, password: str) -> str:
        try:
            import profile_manager
            valid = profile_manager.check_old_password(password)
            return json.dumps({"valid": valid})
        except Exception as e:
            return json.dumps({"valid": False, "error": str(e)})

    def update_password(self, old_password: str, new_password: str) -> str:
        try:
            import profile_manager
            res = profile_manager.update_password(old_password, new_password)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def request_password_reset(self, identifier: str) -> str:
        try:
            import profile_manager
            res = profile_manager.request_password_reset_otp(identifier)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def verify_password_reset_otp(self, identifier: str, otp: str) -> str:
        try:
            import profile_manager
            res = profile_manager.verify_password_reset_otp(identifier, otp)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def reset_password(self, identifier: str, otp: str, new_password: str) -> str:
        try:
            import profile_manager
            res = profile_manager.reset_password_with_otp(identifier, otp, new_password)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def request_email_change_otp(self, new_email: str) -> str:
        try:
            import profile_manager
            res = profile_manager.request_email_change_otp(new_email)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def verify_email_change_otp(self, new_email: str, otp: str) -> str:
        try:
            import profile_manager
            res = profile_manager.verify_email_change_otp(new_email, otp)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ── Workstation Lock Screen Integration ───────────────────────────────────────
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
        try:
            items = fetch_system_notifications(int(limit))
            return json.dumps(items)
        except Exception as e:
            return json.dumps({"error": str(e), "notifications": []})

    def clear_notifications(self) -> str:
        try:
            import time
            import settings_manager
            settings_manager.save_settings({'notifications_cleared_at': time.time()}, log_audit=False)
            return json.dumps({"success": True, "cleared_at": time.time()})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    # ── Quarantine Management Integration ─────────────────────────────────────────
    def get_quarantined_files(self) -> str:
        try:
            import config
            import sqlite3
            q_dir = config.BASE_DIR / 'quarantine'
            if not q_dir.exists():
                return json.dumps([])

            files = []
            rec_db = config.BASE_DIR / 'shadowtrace_recovery.db'
            db_conn = None
            if rec_db.exists():
                try:
                    db_conn = sqlite3.connect(rec_db)
                except Exception:
                    pass

            for f in q_dir.glob('*'):
                if f.is_file():
                    stat = f.stat()
                    clean_name = f.name
                    if len(f.name) > 16 and f.name[:15].replace('_', '').isdigit() and f.name[15] == '_':
                        clean_name = f.name[16:]

                    orig_loc = str(f).replace('\\', '/')
                    reason = "MALWARE"
                    detection = "Heuristic_L3"

                    if db_conn:
                        try:
                            cur = db_conn.cursor()
                            cur.execute(
                                "SELECT original_filepath, lock_reason, stage FROM locked_files WHERE filepath LIKE ? OR original_filepath LIKE ? ORDER BY id DESC LIMIT 1",
                                (f"%{clean_name}%", f"%{clean_name}%")
                            )
                            row = cur.fetchone()
                            if row:
                                if row[0]:
                                    orig_loc = str(row[0]).replace('\\', '/')
                                if row[1]:
                                    if 'STEGO' in row[1].upper():
                                        reason = 'STEGO'
                                        detection = 'Spatial_LSB'
                                    elif 'MALWARE' in row[1].upper() or 'THREAT' in row[1].upper():
                                        reason = 'MALWARE'
                                        detection = row[2] or 'Heuristic_L3'
                        except Exception:
                            pass

                    files.append({
                        'filename': f.name,
                        'clean_name': clean_name,
                        'path': orig_loc,
                        'quarantine_path': str(f).replace('\\', '/'),
                        'size_kb': round(stat.st_size / 1024, 1),
                        'date_quarantined': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                        'reason': reason,
                        'detection': detection
                    })

            if db_conn:
                try:
                    db_conn.close()
                except Exception:
                    pass

            files.sort(key=lambda x: x['date_quarantined'], reverse=True)
            return json.dumps(files)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def restore_quarantined_file(self, filename: str, password: str) -> str:
        try:
            import config
            import utils
            import shutil
            import sqlite3
            import profile_manager

            clean_pwd = (password or "").strip()
            is_valid = False
            try:
                auth_res = profile_manager.verify_lock_password(clean_pwd)
                is_valid = bool(auth_res.get('success'))
            except Exception:
                pass
            if not is_valid:
                is_valid = bool(clean_pwd and clean_pwd == os.environ.get('DEFAULT_EXAMINER_PASSWORD', getattr(profile_manager, 'DEFAULT_PASSWORD', '')))

            if not is_valid:
                try:
                    import analyst_audit
                    analyst_audit.log_action(
                        action_type='LOGIN_FAILED',
                        target=f'Quarantine Restore ({filename})',
                        details='Failed file restore authorization: Incorrect examiner password.',
                        severity='warning'
                    )
                except Exception:
                    pass
                return json.dumps({"success": False, "error": "Incorrect password. Authorization failed."})

            q_dir = config.BASE_DIR / 'quarantine'
            target_path = q_dir / filename
            if not target_path.exists():
                matches = list(q_dir.glob(f"*{filename}*"))
                if matches:
                    target_path = matches[0]
                else:
                    return json.dumps({"success": False, "error": f"File '{filename}' not found in quarantine vault."})

            raw_name = target_path.name
            clean_name = raw_name
            if len(raw_name) > 16 and raw_name[:15].replace('_', '').isdigit() and raw_name[15] == '_':
                clean_name = raw_name[16:]

            original_dest = None
            rec_db = config.BASE_DIR / 'shadowtrace_recovery.db'
            if rec_db.exists():
                try:
                    conn = sqlite3.connect(rec_db)
                    cur = conn.cursor()
                    cur.execute(
                        "SELECT original_filepath FROM locked_files WHERE filepath LIKE ? OR original_filepath LIKE ? ORDER BY id DESC LIMIT 1",
                        (f"%{clean_name}%", f"%{clean_name}%")
                    )
                    row = cur.fetchone()
                    if row and row[0]:
                        candidate = Path(row[0])
                        if candidate.parent.exists() or candidate.drive:
                            original_dest = candidate
                    conn.close()
                except Exception as e:
                    print("[RESTORE] Recovery DB query error:", e)

            if not original_dest:
                downloads = Path.home() / 'Downloads'
                if downloads.exists():
                    original_dest = downloads / clean_name
                else:
                    restored_dir = config.BASE_DIR / 'restored_files'
                    restored_dir.mkdir(parents=True, exist_ok=True)
                    original_dest = restored_dir / clean_name

            dest_file = None
            if original_dest:
                try:
                    original_dest.parent.mkdir(parents=True, exist_ok=True)
                    if original_dest.exists() and original_dest.resolve() != target_path.resolve():
                        dest_file = original_dest.parent / f"{original_dest.stem}_restored{original_dest.suffix}"
                    else:
                        dest_file = original_dest
                except Exception:
                    dest_file = None

            if not dest_file:
                fallback_dir = config.BASE_DIR / 'restored_files'
                fallback_dir.mkdir(parents=True, exist_ok=True)
                dest_file = fallback_dir / clean_name
                try:
                    if dest_file.exists() and dest_file.resolve() != target_path.resolve():
                        dest_file = fallback_dir / f"restored_{clean_name}"
                except Exception:
                    pass

            # Unlock handle and remove deny rules on quarantine file
            utils.unlock_file(str(target_path))

            # Move file out of quarantine folder
            try:
                shutil.move(str(target_path), str(dest_file))
            except Exception:
                fallback_dir = config.BASE_DIR / 'restored_files'
                fallback_dir.mkdir(parents=True, exist_ok=True)
                dest_file = fallback_dir / f"restored_{clean_name}"
                shutil.move(str(target_path), str(dest_file))

            # Ensure restored file has permissions completely unlocked and accessible
            utils.unlock_file(str(dest_file))

            # Update recovery database
            if rec_db.exists():
                try:
                    conn = sqlite3.connect(rec_db)
                    with conn:
                        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        conn.execute(
                            "UPDATE locked_files SET status='RESTORED', lock_reason='RESTORED_BY_EXAMINER', last_updated=? WHERE filepath LIKE ? OR original_filepath LIKE ?",
                            (now_str, f"%{clean_name}%", f"%{clean_name}%")
                        )
                    conn.close()
                except Exception as e:
                    print("[RESTORE] Recovery DB update error:", e)

            # Audit log
            try:
                import analyst_audit
                analyst_audit.log_action(
                    action_type='FILE_RESTORED',
                    target=clean_name,
                    details=f"File restored from quarantine to '{dest_file}'. File lock and deny ACLs removed.",
                    severity='warning'
                )
            except Exception:
                pass

            return json.dumps({
                "success": True,
                "message": f"File '{clean_name}' successfully restored and unlocked.",
                "filename": raw_name,
                "clean_name": clean_name,
                "restored_path": str(dest_file).replace('\\', '/')
            })
        except Exception as e:
            return json.dumps({"success": False, "error": f"Restore failed: {str(e)}"})

    def delete_quarantined_file(self, filename: str, password: str, confirmation: str = "DELETE") -> str:
        try:
            import config
            import utils
            import os
            import sqlite3
            import profile_manager

            if (confirmation or "").strip() != "DELETE":
                return json.dumps({"success": False, "error": "Please type DELETE in capital letters to confirm."})

            clean_pwd = (password or "").strip()
            is_valid = False
            try:
                auth_res = profile_manager.verify_lock_password(clean_pwd)
                is_valid = bool(auth_res.get('success'))
            except Exception:
                pass
            if not is_valid:
                is_valid = bool(clean_pwd and clean_pwd == os.environ.get('DEFAULT_EXAMINER_PASSWORD', getattr(profile_manager, 'DEFAULT_PASSWORD', '')))

            if not is_valid:
                try:
                    import analyst_audit
                    analyst_audit.log_action(
                        action_type='LOGIN_FAILED',
                        target=f'Quarantine Delete ({filename})',
                        details='Failed file deletion authorization: Incorrect examiner password.',
                        severity='warning'
                    )
                except Exception:
                    pass
                return json.dumps({"success": False, "error": "Incorrect password. Authorization failed."})

            q_dir = config.BASE_DIR / 'quarantine'
            target_path = q_dir / filename
            if not target_path.exists():
                matches = list(q_dir.glob(f"*{filename}*"))
                if matches:
                    target_path = matches[0]
                else:
                    return json.dumps({"success": False, "error": f"File '{filename}' not found in quarantine vault."})

            raw_name = target_path.name
            clean_name = raw_name
            if len(raw_name) > 16 and raw_name[:15].replace('_', '').isdigit() and raw_name[15] == '_':
                clean_name = raw_name[16:]

            # Unlock handle and remove file from disk
            utils.unlock_file(str(target_path))
            try:
                os.remove(str(target_path))
            except Exception as rem_err:
                import stat
                try:
                    os.chmod(str(target_path), stat.S_IWRITE)
                    os.remove(str(target_path))
                except Exception:
                    raise rem_err

            # Update recovery database
            rec_db = config.BASE_DIR / 'shadowtrace_recovery.db'
            if rec_db.exists():
                try:
                    conn = sqlite3.connect(rec_db)
                    with conn:
                        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        conn.execute(
                            "UPDATE locked_files SET status='DELETED', lock_reason='PURGED_PERMANENTLY', last_updated=? WHERE filepath LIKE ? OR original_filepath LIKE ?",
                            (now_str, f"%{clean_name}%", f"%{clean_name}%")
                        )
                    conn.close()
                except Exception as e:
                    print("[DELETE] Recovery DB update error:", e)

            # Audit log
            try:
                import analyst_audit
                analyst_audit.log_action(
                    action_type='FILE_DELETED',
                    target=clean_name,
                    details=f"Permanently purged quarantined file '{clean_name}' ({raw_name}) from disk.",
                    severity='critical'
                )
            except Exception:
                pass

            return json.dumps({
                "success": True,
                "message": f"File '{clean_name}' has been permanently deleted from the system.",
                "filename": raw_name
            })
        except Exception as e:
            return json.dumps({"success": False, "error": f"Delete failed: {str(e)}"})

    def batch_delete_quarantined_files(self, filenames_json: str, password: str, confirmation: str = "DELETE") -> str:
        try:
            if (confirmation or "").strip() != "DELETE":
                return json.dumps({"success": False, "error": "Please type DELETE in capital letters to confirm."})

            clean_pwd = (password or "").strip()
            is_valid = False
            try:
                import profile_manager
                auth_res = profile_manager.verify_lock_password(clean_pwd)
                is_valid = bool(auth_res.get('success'))
            except Exception:
                pass
            if not is_valid:
                is_valid = bool(clean_pwd and clean_pwd == os.environ.get('DEFAULT_EXAMINER_PASSWORD', getattr(profile_manager, 'DEFAULT_PASSWORD', '')))
            if not is_valid:
                return json.dumps({"success": False, "error": "Incorrect password. Authorization failed."})

            filenames = json.loads(filenames_json) if isinstance(filenames_json, str) else filenames_json
            if not filenames:
                return json.dumps({"success": False, "error": "No files selected for deletion."})

            deleted_count = 0
            for fname in filenames:
                res_str = self.delete_quarantined_file(fname, password, confirmation)
                res = json.loads(res_str)
                if res.get('success'):
                    deleted_count += 1

            return json.dumps({
                "success": deleted_count > 0,
                "deleted_count": deleted_count,
                "total_requested": len(filenames),
                "message": f"Successfully deleted {deleted_count} of {len(filenames)} files."
            })
        except Exception as e:
            return json.dumps({"success": False, "error": f"Batch delete failed: {str(e)}"})

    def batch_restore_quarantined_files(self, filenames_json: str, password: str) -> str:
        try:
            clean_pwd = (password or "").strip()
            is_valid = False
            try:
                import profile_manager
                auth_res = profile_manager.verify_lock_password(clean_pwd)
                is_valid = bool(auth_res.get('success'))
            except Exception:
                pass
            if not is_valid:
                is_valid = bool(clean_pwd and clean_pwd == os.environ.get('DEFAULT_EXAMINER_PASSWORD', getattr(profile_manager, 'DEFAULT_PASSWORD', '')))
            if not is_valid:
                return json.dumps({"success": False, "error": "Incorrect password. Authorization failed."})

            filenames = json.loads(filenames_json) if isinstance(filenames_json, str) else filenames_json
            if not filenames:
                return json.dumps({"success": False, "error": "No files selected for restoration."})

            restored_count = 0
            errors = []
            for fname in filenames:
                res_str = self.restore_quarantined_file(fname, password)
                res = json.loads(res_str)
                if res.get('success'):
                    restored_count += 1
                else:
                    errors.append(f"{fname}: {res.get('error')}")

            return json.dumps({
                "success": restored_count > 0,
                "restored_count": restored_count,
                "total_requested": len(filenames),
                "errors": errors,
                "message": f"Successfully restored and unlocked {restored_count} of {len(filenames)} files."
            })
        except Exception as e:
            return json.dumps({"success": False, "error": f"Batch restore failed: {str(e)}"})

    def open_quarantine_report(self, filename: str) -> str:
        try:
            import config
            import manual_scan_service

            raw_name = Path(filename).name
            clean_name = raw_name
            if len(raw_name) > 16 and raw_name[:15].replace('_', '').isdigit() and raw_name[15] == '_':
                clean_name = raw_name[16:]
            clean_stem = Path(clean_name).stem

            reports_dir = config.BASE_DIR / 'reports'
            found_report = None

            # 1. Search in reports/quarantine first
            q_rep_dir = reports_dir / 'quarantine'
            if q_rep_dir.exists():
                for p in q_rep_dir.glob(f"*{clean_stem}*.pdf"):
                    found_report = p
                    break

            # 2. Search anywhere in reports/
            if not found_report and reports_dir.exists():
                for p in reports_dir.rglob(f"*{clean_stem}*report.pdf"):
                    if 'summary' not in p.name.lower():
                        found_report = p
                        break
                if not found_report:
                    for p in reports_dir.rglob(f"*{clean_stem}*.pdf"):
                        found_report = p
                        break

            # 3. Check by timestamp prefix if available
            if not found_report and len(raw_name) >= 15:
                prefix = raw_name[:15]
                for p in reports_dir.rglob(f"*{prefix}*.pdf"):
                    found_report = p
                    break

            if found_report and found_report.exists():
                res = manual_scan_service.open_pdf(str(found_report.resolve()))
                if res.get('success'):
                    try:
                        import analyst_audit
                        analyst_audit.log_action(
                            action_type='REPORT_VIEW',
                            target=clean_name,
                            details=f"Viewed quarantine forensic report: {found_report.name}",
                            severity='normal'
                        )
                    except Exception:
                        pass
                    return json.dumps({
                        "success": True,
                        "report_path": str(found_report).replace('\\', '/'),
                        "report_name": found_report.name,
                        "filename": filename
                    })
                else:
                    return json.dumps({"success": False, "error": res.get('error', 'Failed to launch PDF viewer.')})

            return json.dumps({
                "success": False,
                "error": f"No quarantine report PDF found for '{clean_name}'. Note: Reports are generated automatically for newly quarantined files."
            })
        except Exception as e:
            return json.dumps({"success": False, "error": f"Error opening report: {str(e)}"})


