# =============================================================================
# Shadow-Trace | settings_manager.py
# Centralized settings persistence, runtime synchronization, database backup,
# log management, and notification orchestration.
# =============================================================================

import os
import sys
import json
import time
import shutil
import hashlib
import platform
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

import config
import analyst_audit

SETTINGS_FILE = config.BASE_DIR / 'settings.json'
ENV_FILE = config.BASE_DIR / '.env'

def get_default_settings() -> Dict[str, Any]:
    """Generates the factory default configuration."""
    home = Path.home()
    default_monitored = [
        str(home / 'Downloads'),
        str(home / 'Desktop'),
        str(home / 'Documents'),
    ]
    # Filter to valid dirs if available
    valid_monitored = []
    for p in default_monitored:
        try:
            if Path(p).exists():
                valid_monitored.append(p)
        except OSError:
            pass
    if not valid_monitored:
        valid_monitored = [str(config.BASE_DIR)]

    return {
        # 1. Monitoring Settings
        "monitored_folders": valid_monitored,

        # 2. Scan Settings
        "always_on_monitoring": False,
        "ask_user_before_steg": False,
        "auto_escalate_lsb": True,
        "offline_mode": False,
        "vt_scan_enabled": True,
        "vt_upload_mode": "hash_only",  # 'hash_only' or 'full_upload'
        "ha_scan_enabled": True,
        "ha_upload_mode": "hash_only",  # 'hash_only' or 'full_upload'
        "auto_quarantine_malware": True,
        "auto_quarantine_stego": False,

        # 3. Report Settings
        "report_output_folder": str(config.REPORTS_DIR),
        "auto_generate_summary_report": True,
        "auto_generate_evidence_package": False,
        "include_system_context": True,
        "examiner_signature": getattr(config, 'EXAMINER_NAME', "Senior Digital Forensic Examiner #402"),

        # 4. API Settings
        "vt_api_key": getattr(config, 'VIRUSTOTAL_API_KEY', ""),
        "ha_api_key": getattr(config, 'HYBRID_ANALYSIS_KEY', ""),
        "rfc3161_url": getattr(config, 'FREETSA_URL', "https://timestamp.digicert.com"),

        # 5. Notification Settings
        "desktop_notifications": True,
        "threat_detection_alert": True,
        "scan_complete_notification": True,
        "quarantine_activity_alert": True,
        "notification_sound": False,

        # 6. Storage & Retention
        "reports_location": str(config.REPORTS_DIR),
        "quarantine_location": str(config.QUARANTINE_DIR),
        "sandbox_location": str(config.SANDBOX_DIR),

        # 7. Advanced Settings
        "clamav_host_port": "127.0.0.1:3310",
        "log_level": "INFO",
        "recovery_db_path": str(config.RECOVERY_DB),
        "investigation_db_path": str(config.COC_DB),
    }

def get_settings() -> Dict[str, Any]:
    """Retrieves stored settings, merging them with default settings."""
    defaults = get_default_settings()
    if SETTINGS_FILE.exists():
        try:
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    defaults.update(saved)
        except Exception as e:
            print(f"[SETTINGS_MANAGER] Error reading {SETTINGS_FILE}: {e}")
    else:
        # Save defaults directly to disk so settings.json exists
        try:
            with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
                json.dump(defaults, f, indent=4)
        except Exception as e:
            print(f"[SETTINGS_MANAGER] Error initializing {SETTINGS_FILE}: {e}")
    
    return defaults

def get_setting(key: str, default: Any = None) -> Any:
    """Helper to fetch a single setting value directly."""
    current = get_settings()
    return current.get(key, default)

def set_windows_autostart(enable: bool = True) -> bool:
    """Configures or removes Windows automatic startup for background monitoring."""
    if platform.system() != 'Windows':
        return False

    success = False
    # Method 1: Windows Registry Run Key
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_name = "ShadowTrace"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                main_script = config.BASE_DIR / 'main.py'
                py_exe = Path(sys.executable)
                pyw_exe = py_exe.parent / 'pythonw.exe'
                target_exe = pyw_exe if pyw_exe.exists() else py_exe
                cmd = f'"{target_exe}" "{main_script}"'
                winreg.SetValueEx(key, app_name, 0, winreg.REG_SZ, cmd)
                print(f"[SETTINGS_MANAGER] Windows autostart registry set: {cmd}")
            else:
                try:
                    winreg.DeleteValue(key, app_name)
                    print("[SETTINGS_MANAGER] Windows autostart registry removed")
                except FileNotFoundError:
                    pass
        success = True
    except Exception as e:
        print(f"[SETTINGS_MANAGER] Autostart registry notice: {e}")

    # Method 2: Startup Folder Script (Fallback / redundancy)
    try:
        appdata = os.environ.get('APPDATA')
        if appdata:
            startup_dir = Path(appdata) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
            if startup_dir.exists():
                vbs_path = startup_dir / 'ShadowTraceAutoStart.vbs'
                if enable:
                    main_script = config.BASE_DIR / 'main.py'
                    py_exe = Path(sys.executable)
                    pyw_exe = py_exe.parent / 'pythonw.exe'
                    target_exe = pyw_exe if pyw_exe.exists() else py_exe
                    vbs_content = (
                        'Set WshShell = CreateObject("WScript.Shell")\r\n'
                        f'WshShell.Run """{target_exe}"" ""{main_script}""", 0, False\r\n'
                    )
                    vbs_path.write_text(vbs_content, encoding='utf-8')
                    print(f"[SETTINGS_MANAGER] Windows startup script created: {vbs_path}")
                else:
                    if vbs_path.exists():
                        try:
                            vbs_path.unlink()
                            print(f"[SETTINGS_MANAGER] Windows startup script removed: {vbs_path}")
                        except Exception:
                            pass
                success = True
    except Exception as e:
        print(f"[SETTINGS_MANAGER] Autostart folder notice: {e}")

    return success

def apply_runtime_config(settings: Dict[str, Any]):
    """Applies updated settings to in-memory config variables and environment."""
    try:
        # API Keys
        if "vt_api_key" in settings:
            val = str(settings["vt_api_key"]).strip()
            config.VIRUSTOTAL_API_KEY = val
            os.environ['VIRUSTOTAL_API_KEY'] = val
        if "ha_api_key" in settings:
            val = str(settings["ha_api_key"]).strip()
            config.HYBRID_ANALYSIS_KEY = val
            os.environ['HYBRID_ANALYSIS_KEY'] = val
        if "rfc3161_url" in settings:
            val = str(settings["rfc3161_url"]).strip()
            config.FREETSA_URL = val
            os.environ['FREETSA_URL'] = val
        if "examiner_signature" in settings:
            val = str(settings["examiner_signature"]).strip()
            config.EXAMINER_NAME = val
            os.environ['EXAMINER_NAME'] = val

        # Paths
        if "reports_location" in settings and settings["reports_location"]:
            p = Path(settings["reports_location"])
            p.mkdir(parents=True, exist_ok=True)
            config.REPORTS_DIR = p
        if "report_output_folder" in settings and settings["report_output_folder"]:
            p = Path(settings["report_output_folder"])
            p.mkdir(parents=True, exist_ok=True)

        if "quarantine_location" in settings and settings["quarantine_location"]:
            p = Path(settings["quarantine_location"])
            p.mkdir(parents=True, exist_ok=True)
            config.QUARANTINE_DIR = p

        if "sandbox_location" in settings and settings["sandbox_location"]:
            p = Path(settings["sandbox_location"])
            p.mkdir(parents=True, exist_ok=True)
            config.SANDBOX_DIR = p

        # Monitored Folders
        if "monitored_folders" in settings:
            dirs = [Path(d) for d in settings["monitored_folders"] if d]
            config.MONITORED_DIRS = dirs

        # Scan Mode / VT mode / Offline
        offline = bool(settings.get("offline_mode", False))
        config.OFFLINE_SCAN_MODE = offline

        if offline:
            config.VT_MODE = 'DISABLED'
            config.HYBRID_ANALYSIS_MODE = 'disabled'
        else:
            # VirusTotal
            if not settings.get("vt_scan_enabled", True):
                config.VT_MODE = 'DISABLED'
            elif settings.get("vt_upload_mode") == "full_upload":
                config.VT_MODE = 'UPLOAD_UNKNOWN'
            else:
                config.VT_MODE = 'CHECK_ONLY'

            # Hybrid Analysis
            if not settings.get("ha_scan_enabled", True):
                config.HYBRID_ANALYSIS_MODE = 'disabled'
            elif settings.get("ha_upload_mode") == "full_upload":
                config.HYBRID_ANALYSIS_MODE = 'full_upload'
            else:
                config.HYBRID_ANALYSIS_MODE = 'hash_only'

        # Always ON Background Monitoring & Startup Persistence
        if "always_on_monitoring" in settings:
            set_windows_autostart(bool(settings["always_on_monitoring"]))

    except Exception as e:
        print(f"[SETTINGS_MANAGER] Error syncing runtime config: {e}")

def update_env_file(settings: Dict[str, Any]):
    """Safely updates .env file with new API keys and examiner signature while preserving others."""
    try:
        lines = []
        if ENV_FILE.exists():
            with open(ENV_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        
        env_map = {}
        for line in lines:
            line_str = line.strip()
            if line_str and not line_str.startswith('#') and '=' in line_str:
                k, v = line_str.split('=', 1)
                env_map[k.strip()] = v.strip()

        if "vt_api_key" in settings:
            env_map['VIRUSTOTAL_API_KEY'] = settings["vt_api_key"].strip()
        if "ha_api_key" in settings:
            env_map['HYBRID_ANALYSIS_KEY'] = settings["ha_api_key"].strip()
        if "examiner_signature" in settings:
            env_map['EXAMINER_NAME'] = settings["examiner_signature"].strip()
        if "rfc3161_url" in settings:
            env_map['FREETSA_URL'] = settings["rfc3161_url"].strip()
        if "report_output_folder" in settings:
            env_map['REPORTS_DIR'] = settings["report_output_folder"].strip()
        if "always_on_monitoring" in settings:
            env_map['ALWAYS_ON_MONITORING'] = 'true' if bool(settings["always_on_monitoring"]) else 'false'
        
        # Offline, VT and HA Mode in .env
        offline = bool(settings.get("offline_mode", False))
        env_map['OFFLINE_SCAN_MODE'] = 'true' if offline else 'false'
        if offline:
            env_map['VT_MODE'] = 'DISABLED'
            env_map['HYBRID_ANALYSIS_MODE'] = 'disabled'
        else:
            if not settings.get("vt_scan_enabled", True):
                env_map['VT_MODE'] = 'DISABLED'
            elif settings.get("vt_upload_mode") == "full_upload":
                env_map['VT_MODE'] = 'UPLOAD_UNKNOWN'
            else:
                env_map['VT_MODE'] = 'CHECK_ONLY'

            if not settings.get("ha_scan_enabled", True):
                env_map['HYBRID_ANALYSIS_MODE'] = 'disabled'
            elif settings.get("ha_upload_mode") == "full_upload":
                env_map['HYBRID_ANALYSIS_MODE'] = 'full_upload'
            else:
                env_map['HYBRID_ANALYSIS_MODE'] = 'hash_only'

        with open(ENV_FILE, 'w', encoding='utf-8') as f:
            for k, v in env_map.items():
                f.write(f"{k}={v}\n")
    except Exception as e:
        print(f"[SETTINGS_MANAGER] Error updating .env: {e}")

def save_settings(new_settings: Dict[str, Any], log_audit: bool = True) -> Dict[str, Any]:
    """Persists settings to JSON, updates in-memory config & .env, and records audit trail."""
    current = get_settings()
    current.update(new_settings)

    # Write to settings.json
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(current, f, indent=4)
    except Exception as e:
        print(f"[SETTINGS_MANAGER] Failed to write settings.json: {e}")

    # Synchronize runtime
    apply_runtime_config(current)
    update_env_file(current)

    # Sync watchdog observer if layer0_monitor is active
    if "monitored_folders" in current:
        try:
            import layer0_monitor
            if hasattr(layer0_monitor, 'sync_monitored_directories'):
                layer0_monitor.sync_monitored_directories(current["monitored_folders"])
        except Exception as e:
            print(f"[SETTINGS_MANAGER] Monitor sync error: {e}")

    if log_audit:
        try:
            analyst_audit.log_action(
                action_type='SETTINGS_CHANGE',
                target='System Settings',
                details='Forensic system configuration parameters updated and synchronized.',
                severity='normal'
            )
        except Exception:
            pass

    return current

def add_monitored_folder(folder_path: str) -> Dict[str, Any]:
    """Dynamically adds a folder to active monitoring, updating settings and watchdog observer."""
    folder_path = folder_path.strip()
    if not folder_path:
        return {"success": False, "error": "Folder path cannot be empty"}

    p = Path(folder_path)
    try:
        p.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"[SETTINGS_MANAGER] Notice creating directory {p}: {e}")

    current = get_settings()
    folders = list(current.get("monitored_folders", []))
    
    # Check if folder already exists in list (case-insensitive on Windows)
    is_win = platform.system() == 'Windows'
    norm_new = str(p.resolve()).lower() if is_win else str(p.resolve())
    exists = any((str(Path(f).resolve()).lower() if is_win else str(Path(f).resolve())) == norm_new for f in folders)

    if not exists:
        folders.append(str(p))
        current["monitored_folders"] = folders
        save_settings(current, log_audit=False)
        try:
            analyst_audit.log_action(
                action_type='SETTINGS_CHANGE',
                target='Monitored Folders',
                details=f"Added directory to active real-time monitoring: {p}",
                severity='normal'
            )
        except Exception:
            pass
    else:
        # Still make sure watchdog is synchronized
        try:
            import layer0_monitor
            if hasattr(layer0_monitor, 'sync_monitored_directories'):
                layer0_monitor.sync_monitored_directories(folders)
        except Exception:
            pass

    return {"success": True, "monitored_folders": folders}

def remove_monitored_folder(folder_path: str) -> Dict[str, Any]:
    """Dynamically removes a folder from active monitoring, updating settings and unscheduling watchdog."""
    folder_path = folder_path.strip()
    current = get_settings()
    folders = list(current.get("monitored_folders", []))

    is_win = platform.system() == 'Windows'
    norm_target = str(Path(folder_path).resolve()).lower() if is_win else str(Path(folder_path).resolve())
    
    new_folders = []
    removed_any = False
    for f in folders:
        f_norm = str(Path(f).resolve()).lower() if is_win else str(Path(f).resolve())
        if f_norm == norm_target or f.strip() == folder_path:
            removed_any = True
        else:
            new_folders.append(f)

    current["monitored_folders"] = new_folders
    save_settings(current, log_audit=False)

    if removed_any:
        try:
            analyst_audit.log_action(
                action_type='SETTINGS_CHANGE',
                target='Monitored Folders',
                details=f"Removed directory from real-time monitoring: {folder_path}",
                severity='warning'
            )
        except Exception:
            pass

    return {"success": True, "monitored_folders": new_folders}

def toggle_auto_escalate(enabled: bool) -> Dict[str, Any]:
    """Toggles the auto_escalate_lsb setting and records audit trail."""
    current = get_settings()
    current["auto_escalate_lsb"] = bool(enabled)
    if "auto_escalate_detection" in current:
        del current["auto_escalate_detection"]
    save_settings(current, log_audit=False)

    try:
        details_msg = (
            "Auto-escalate on LSB executable ENABLED: Automated full steganography analysis without analyst permission prompt."
            if enabled else
            "Auto-escalate on LSB executable DISABLED: Analyst confirmation required before deep stego scan."
        )
        analyst_audit.log_action(
            action_type='SETTINGS_CHANGE',
            target='Auto-escalate on LSB executable',
            details=details_msg,
            severity='warning'
        )
    except Exception:
        pass

    return {"success": True, "auto_escalate_lsb": bool(enabled)}

def reset_to_defaults() -> Dict[str, Any]:
    """Resets all settings to original factory values and clears custom settings.json."""
    defaults = get_default_settings()
    try:
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(defaults, f, indent=4)
    except Exception as e:
        print(f"[SETTINGS_MANAGER] Error writing defaults: {e}")

    apply_runtime_config(defaults)
    update_env_file(defaults)

    try:
        analyst_audit.log_action(
            action_type='SETTINGS_CHANGE',
            target='Factory Reset',
            details='All system settings were reverted to factory defaults.',
            severity='warning'
        )
    except Exception:
        pass

    return defaults

def backup_databases() -> Dict[str, Any]:
    """Creates a timestamped backup directory of all SQLite databases with SHA-256 manifest."""
    ts = time.strftime('%Y%m%d_%H%M%S')
    backup_dir = config.BASE_DIR / 'backups' / f"backup_{ts}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    db_targets = [
        config.RECOVERY_DB,
        config.COC_DB,
        config.BASE_DIR / 'analyst_audit.db'
    ]

    backed_up = []
    manifest = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "backup_dir": str(backup_dir),
        "files": []
    }

    for db_path in db_targets:
        if db_path.exists():
            dest = backup_dir / db_path.name
            shutil.copy2(str(db_path), str(dest))
            
            # Compute SHA-256
            hasher = hashlib.sha256()
            with open(dest, 'rb') as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    hasher.update(chunk)
            sha256 = hasher.hexdigest()
            size = dest.stat().st_size

            file_info = {
                "filename": db_path.name,
                "size_bytes": size,
                "sha256": sha256
            }
            manifest["files"].append(file_info)
            backed_up.append(db_path.name)

    manifest_path = backup_dir / 'manifest.json'
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2)

    try:
        analyst_audit.log_action(
            action_type='BACKUP_DATABASE',
            target=backup_dir.name,
            details=f"Backed up {len(backed_up)} database(s) ({', '.join(backed_up)}) to {backup_dir.name}",
            severity='normal'
        )
    except Exception:
        pass

    return {
        "success": True,
        "backup_dir": str(backup_dir),
        "files": backed_up,
        "timestamp": manifest["timestamp"]
    }

def format_size(bytes_val: int) -> str:
    """Formats bytes into human readable KB / MB."""
    if bytes_val < 1024:
        return f"{bytes_val} B"
    elif bytes_val < 1024 * 1024:
        return f"{bytes_val / 1024:.2f} KB"
    else:
        return f"{bytes_val / (1024 * 1024):.2f} MB"

def get_database_sizes() -> Dict[str, Any]:
    """Calculates disk sizes for all forensic databases."""
    db_targets = {
        "Recovery Database": config.RECOVERY_DB,
        "Investigation / CoC Database": config.COC_DB,
        "Analyst Audit Database": config.BASE_DIR / 'analyst_audit.db'
    }

    result = {}
    total_bytes = 0

    for name, path in db_targets.items():
        if path.exists():
            size = path.stat().st_size
            total_bytes += size
            result[name] = {
                "path": str(path),
                "bytes": size,
                "formatted": format_size(size),
                "exists": True
            }
        else:
            result[name] = {
                "path": str(path),
                "bytes": 0,
                "formatted": "0 B (Not Created Yet)",
                "exists": False
            }

    return {
        "databases": result,
        "total_bytes": total_bytes,
        "total_formatted": format_size(total_bytes)
    }

def clear_logs() -> Dict[str, Any]:
    """Clears and truncates all system log files in the logs directory."""
    logs_dir = config.LOGS_DIR
    cleared = []
    if logs_dir.exists():
        for log_file in logs_dir.glob('*.log'):
            try:
                with open(log_file, 'w', encoding='utf-8') as f:
                    f.truncate(0)
                cleared.append(log_file.name)
            except Exception as e:
                print(f"[SETTINGS_MANAGER] Error clearing {log_file.name}: {e}")

    try:
        analyst_audit.log_action(
            action_type='SETTINGS_CHANGE',
            target='System Logs',
            details=f"Cleared {len(cleared)} log files: {', '.join(cleared)}",
            severity='warning'
        )
    except Exception:
        pass

    return {
        "success": True,
        "cleared_files": cleared,
        "count": len(cleared)
    }

def view_logs() -> Dict[str, Any]:
    """Opens the logs directory in Windows Explorer."""
    logs_dir = config.LOGS_DIR
    logs_dir.mkdir(parents=True, exist_ok=True)

    try:
        if platform.system() == 'Windows':
            os.startfile(str(logs_dir))
        else:
            subprocess.Popen(['xdg-open', str(logs_dir)])
        return {"success": True, "path": str(logs_dir)}
    except Exception as e:
        return {"success": False, "error": str(e), "path": str(logs_dir)}

def browse_folder(initial_dir: str = "") -> str:
    """Launches a native directory selection modal and returns the chosen folder."""
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        selected = filedialog.askdirectory(
            initialdir=initial_dir or str(config.BASE_DIR),
            title="Select Forensic Output Directory"
        )
        root.destroy()
        return selected or ""
    except Exception as e:
        print(f"[SETTINGS_MANAGER] Folder picker dialog error: {e}")
        return ""

def notify_user(title: str, message: str, alert_type: str = "info", popup: bool = False):
    """
    Sends desktop notifications, pop-up dialogs, and chime if allowed by current notification settings.
    alert_type can be 'threat', 'scan_complete', 'quarantine', 'error', or 'info'.
    """
    s = get_settings()
    if not s.get("desktop_notifications", True) and not popup and alert_type not in ("error", "quarantine"):
        return

    # Check alert-specific permissions for non-critical informational alerts
    if alert_type == "scan_complete" and not s.get("scan_complete_notification", True):
        return

    # Dispatch sound
    if platform.system() == 'Windows':
        try:
            import winsound
            if alert_type in ('threat', 'quarantine'):
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            elif alert_type == 'error':
                winsound.MessageBeep(winsound.MB_ICONHAND)
            elif s.get("notification_sound", False):
                winsound.MessageBeep(winsound.MB_ICONASTERISK)
        except Exception:
            pass

    # Dispatch pop-up dialog for quarantine or errors
    if popup or alert_type in ("error", "quarantine", "threat"):
        try:
            if alert_type == "error":
                from user_prompt import notify_error_popup
                notify_error_popup(title=title, reason=message)
            else:
                from user_prompt import notify_quarantine_popup
                notify_quarantine_popup(filename="", reason=message, threat_info={"engine": title})
        except Exception:
            pass

    # Dispatch toast notification
    try:
        from plyer import notification
        notification.notify(
            title=f"Shadow-Trace: {title}",
            message=message,
            app_name="Shadow-Trace",
            timeout=5
        )
    except Exception:
        # Fallback to PowerShell balloon on Windows if plyer is absent
        if platform.system() == 'Windows':
            try:
                ps_cmd = f'[reflection.assembly]::loadwithpartialname("System.Windows.Forms"); [reflection.assembly]::loadwithpartialname("System.Drawing"); $notify = new-object system.windows.forms.notifyicon; $notify.icon = [system.drawing.systemicons]::Information; $notify.visible = $true; $notify.showballoontip(10, "{title}", "{message}", [system.windows.forms.tooltipicon]::Info)'
                subprocess.Popen(["powershell", "-WindowStyle", "Hidden", "-Command", ps_cmd])
            except Exception:
                pass

# Initialize settings on module load
apply_runtime_config(get_settings())
