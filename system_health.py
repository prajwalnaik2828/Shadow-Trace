# =============================================================================
# Shadow-Trace | system_health.py
# Real-time system health evaluation module.
# Checks ClamAV, DNS monitor, AI models, YARA rules, Threat Intel, and
# core pipeline modules to compute a real health score and diagnostic cards.
# =============================================================================

import os
import sys
import time
import socket
from pathlib import Path
from typing import Dict, Any, List

sys.path.insert(0, str(Path(__file__).parent))
import config

_cached_health = None
_cached_time = 0

def check_clamd_quick() -> bool:
    """Quick non-blocking check to see if ClamAV daemon is listening on 3310."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        res = s.connect_ex(('127.0.0.1', 3310))
        s.close()
        return res == 0
    except Exception:
        return False

def evaluate_system_health(force: bool = False) -> Dict[str, Any]:
    """
    Evaluates real operational status of all system components.
    Returns:
    {
        'score': int (0-100),
        'status_label': 'OPTIMAL' | 'DEGRADED' | 'CRITICAL',
        'color': '#27ae60' | '#f39c12' | '#e74c3c',
        'cards': [
            {
                'type': 'ok' | 'warning' | 'error',
                'title': str,
                'details': str
            },
            ...
        ],
        'components': dict
    }
    """
    global _cached_health, _cached_time
    now = time.time()
    if not force and _cached_health is not None and (now - _cached_time < 5):
        return _cached_health

    penalties = 0
    issues: List[Dict[str, str]] = []
    operational_notes: List[str] = []
    components: Dict[str, Any] = {}

    # 1. ClamAV Daemon
    clamav_running = check_clamd_quick()
    components['clamav'] = {'running': clamav_running}
    if not clamav_running:
        penalties += 15
        issues.append({
            'type': 'warning',
            'title': 'ClamAV daemon offline',
            'details': 'Antivirus daemon not running — using YARA & VT fallback'
        })
    else:
        operational_notes.append('ClamAV daemon active')

    # 2. DNS Event Logging & Network Monitor
    dns_enabled = False
    try:
        from network_monitor import check_dns_log_enabled
        dns_enabled = bool(check_dns_log_enabled())
    except Exception:
        dns_enabled = False

    components['dns_monitor'] = {'enabled': dns_enabled}
    if not dns_enabled:
        penalties += 10
        issues.append({
            'type': 'warning',
            'title': 'DNS event logging disabled',
            'details': 'Needs Admin privileges — TCP correlation active'
        })
    else:
        operational_notes.append('DNS network monitor active')

    # 3. AI Steganalysis Models
    model_names = ['video_model.pth', 'image_model.pth', 'doc_model.pth']
    missing_models = []
    for m in model_names:
        m_path = config.BASE_DIR / 'models' / m
        if not m_path.exists():
            missing_models.append(m)

    components['models'] = {
        'total': len(model_names),
        'missing': missing_models,
        'loaded': len(model_names) - len(missing_models)
    }
    if missing_models:
        penalties += 10 * len(missing_models)
        issues.append({
            'type': 'warning',
            'title': f'AI models missing ({len(missing_models)}/{len(model_names)})',
            'details': f'Missing: {", ".join(missing_models)} — heuristic fallback'
        })
    else:
        operational_notes.append('All 3 AI stego models loaded')

    # 4. YARA Signature Rules
    yara_count = 0
    try:
        yara_dir = config.BASE_DIR / 'yara_rules'
        if yara_dir.exists():
            yara_count = len(list(yara_dir.rglob('*.yar')))
    except Exception:
        yara_count = 0

    components['yara'] = {'rule_count': yara_count}
    if yara_count == 0:
        penalties += 15
        issues.append({
            'type': 'warning',
            'title': 'YARA signatures missing',
            'details': '0 rules found in yara_rules directory'
        })
    else:
        operational_notes.append(f'{yara_count:,} YARA rules active')

    # 5. Threat Intelligence APIs
    vt_key = bool(os.environ.get('VIRUSTOTAL_API_KEY') or getattr(config, 'VIRUSTOTAL_API_KEY', ''))
    ha_key = bool(os.environ.get('HYBRID_ANALYSIS_KEY') or getattr(config, 'HYBRID_ANALYSIS_KEY', ''))
    components['threat_intel'] = {'virustotal': vt_key, 'hybrid_analysis': ha_key}

    if not vt_key and not ha_key:
        penalties += 10
        issues.append({
            'type': 'warning',
            'title': 'Threat Intel offline',
            'details': 'VirusTotal & Hybrid Analysis keys missing'
        })
    elif not vt_key:
        penalties += 5
        issues.append({
            'type': 'warning',
            'title': 'VirusTotal key missing',
            'details': 'Cloud signature lookups disabled'
        })
    elif not ha_key:
        penalties += 5
        issues.append({
            'type': 'warning',
            'title': 'Hybrid Analysis key missing',
            'details': 'Sandbox payload analysis disabled'
        })
    else:
        operational_notes.append('VirusTotal & Hybrid Analysis connected')

    # 6. Monitored Folders
    monitored_dirs = []
    try:
        monitored_dirs = config.get_monitored_dirs()
    except Exception:
        monitored_dirs = []

    components['monitored_dirs'] = {'count': len(monitored_dirs)}
    if not monitored_dirs:
        penalties += 15
        issues.append({
            'type': 'warning',
            'title': 'No folders monitored',
            'details': 'File watcher inactive — configure in Settings'
        })
    else:
        dir_names = [d.name for d in monitored_dirs]
        operational_notes.append(f'Monitoring {len(monitored_dirs)} folders ({", ".join(dir_names)})')

    # 7. Core Forensic Pipeline Modules
    core_modules = [
        ('layer0_monitor', 'File Interception (L0)'),
        ('layer1_malware', 'Malware Screening (L1)'),
        ('layer1_5_lsb_check', 'LSB Verification (L1.5)'),
        ('layer2_steganalysis', 'Steganalysis Engine (L2)'),
        ('layer3_extraction', 'Payload Extraction (L3)'),
        ('layer4_report', 'Forensic Reporting (L4)'),
        ('case_manager', 'Case Manager'),
        ('analyst_audit', 'Analyst Audit'),
        ('investigation_tools', 'Investigation Tools'),
    ]

    import importlib.util
    failed_modules = []
    for mod_name, label in core_modules:
        try:
            if mod_name in sys.modules:
                continue
            spec = importlib.util.find_spec(mod_name)
            if spec is None:
                failed_modules.append((label, "Module not found"))
        except Exception as err:
            failed_modules.append((label, str(err)))

    components['core_modules'] = {
        'total': len(core_modules),
        'failed': [m[0] for m in failed_modules]
    }
    if failed_modules:
        penalties += 20 * len(failed_modules)
        for label, err in failed_modules:
            issues.append({
                'type': 'error',
                'title': f'{label} failed to load',
                'details': str(err)[:60]
            })

    # Calculate final health score (clamped between 15% and 100%)
    score = max(15, min(100, 100 - penalties))

    if score >= 90:
        status_label = 'OPTIMAL'
        color = '#27ae60'  # Green
    elif score >= 70:
        status_label = 'DEGRADED'
        color = '#f39c12'  # Amber/Yellow
    else:
        status_label = 'CRITICAL'
        color = '#e74c3c'  # Red

    # Build final cards list
    cards: List[Dict[str, str]] = []

    # Include issues first
    for issue in issues:
        cards.append(issue)

    # If all systems operational or some operational
    if not issues:
        cards.append({
            'type': 'ok',
            'title': 'All systems operational',
            'details': 'Core forensic modules & AI models verified'
        })
        cards.append({
            'type': 'ok',
            'title': 'Security & Sensors active',
            'details': f'ClamAV, DNS Monitor, {yara_count:,} YARA rules active'
        })
    else:
        # Include summary card of what is working
        loaded_count = len(core_modules) - len(failed_modules)
        cards.append({
            'type': 'ok',
            'title': 'Operational subsystems',
            'details': f'{loaded_count}/{len(core_modules)} pipeline modules active'
        })

    _cached_health = {
        'score': score,
        'status_label': status_label,
        'color': color,
        'cards': cards,
        'components': components
    }
    _cached_time = time.time()
    return _cached_health

if __name__ == '__main__':
    res = evaluate_system_health(force=True)
    print(f"Health Score: {res['score']}% ({res['status_label']})")
    print(f"Color: {res['color']}")
    print("Cards:")
    for c in res['cards']:
        print(f"  [{c['type'].upper()}] {c['title']} - {c['details']}")
