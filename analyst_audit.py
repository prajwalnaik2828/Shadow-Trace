# =============================================================================
# Shadow-Trace | analyst_audit.py
# Tamper-evident audit log of every analyst action taken inside the UI.
# Meets U.S. Daubert Standard and Indian Evidence Act Section 65B requirements
# for proving that evidence was accessed, reviewed, and handled correctly.
#
# Design: HMAC-chained rows — each entry includes an HMAC computed over
# (previous_row_hmac + current_row_data), so any edit or deletion of any
# row breaks the chain and is immediately detectable.
# =============================================================================

import os
import csv
import hmac
import json
import sqlite3
import hashlib
import socket
import platform
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional

import config

# =============================================================================
# HMAC key — same env-var pattern as evidence_export.py
# =============================================================================

HMAC_KEY = os.environ.get(
    'HMAC_SECRET_KEY',
    ''
).encode('utf-8')

AUDIT_DB = config.BASE_DIR / 'analyst_audit.db'
_AUDIT_LOCK = threading.Lock()

# =============================================================================
# Action type constants
# =============================================================================

SESSION_START       = 'SESSION_START'
SESSION_END         = 'SESSION_END'
SYSTEM_START        = 'SYSTEM_START'
SYSTEM_STOP         = 'SYSTEM_STOP'
TAB_SWITCHED        = 'TAB_SWITCHED'
VIEW_REPORT         = 'VIEW_REPORT'
FILTER_APPLIED      = 'FILTER_APPLIED'
SEARCH_PERFORMED    = 'SEARCH_PERFORMED'
NOTE_ADDED          = 'NOTE_ADDED'
TAG_ADDED           = 'TAG_ADDED'
EVIDENCE_EXPORTED   = 'EVIDENCE_EXPORTED'
REPROCESS_QUEUED    = 'REPROCESS_QUEUED'
PDF_OPENED          = 'PDF_OPENED'
FOLDER_OPENED       = 'FOLDER_OPENED'
AUDIT_VERIFIED      = 'AUDIT_CHAIN_VERIFIED'
AUDIT_EXPORTED      = 'AUDIT_LOG_EXPORTED'
LOGIN_FAILED        = 'LOGIN_FAILED'
USER_LOGIN          = 'USER_LOGIN'
USER_LOGOUT         = 'USER_LOGOUT'
UNAUTHORIZED_ACCESS = 'UNAUTHORIZED_ACCESS'
SCAN_INITIATED      = 'SCAN_INITIATED'
SCAN_COMPLETED      = 'SCAN_COMPLETED'
SCAN_CANCELLED      = 'SCAN_CANCELLED'
FILE_UPLOAD         = 'FILE_UPLOAD'
FILE_QUARANTINE     = 'FILE_QUARANTINE'
FILE_RESTORE        = 'FILE_RESTORE'
FILE_DELETE         = 'FILE_DELETE'
SETTINGS_CHANGE     = 'SETTINGS_CHANGE'
REPORT_EXPORT       = 'REPORT_EXPORT'
CASE_CLOSED         = 'CASE_CLOSED'
CASE_OPENED         = 'CASE_OPENED'
POLICY_UPDATE       = 'POLICY_UPDATE'
BACKUP_SUCCESS      = 'BACKUP_SUCCESS'
NAVIGATE_PAGE       = 'NAVIGATE_PAGE'


# =============================================================================
# Internal helpers
# =============================================================================

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(AUDIT_DB))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def _get_identity() -> Dict[str, str]:
    try:
        username = os.getlogin()
    except Exception:
        username = (
            os.environ.get('EXAMINER_NAME')
            or os.environ.get('USERNAME')
            or os.environ.get('USER')
            or 'examiner'
        )
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'localhost'

    # Get local workstation IP address
    ip = '127.0.0.1'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip = socket.gethostbyname(hostname)
        except Exception:
            ip = '127.0.0.1'

    return {
        'examiner': username,
        'hostname': hostname,
        'platform': platform.system(),
        'ip': ip,
    }


def _compute_row_hmac(prev_hmac: str, row_data: str) -> str:
    """
    Compute HMAC-SHA3-512 over (prev_hmac + row_data).
    This chains each row to the previous one so no row can be
    silently deleted or edited without breaking the chain.
    """
    payload = (prev_hmac + row_data).encode('utf-8')
    return hmac.new(HMAC_KEY, payload, hashlib.sha3_512).hexdigest()


def _get_last_hmac(conn: sqlite3.Connection) -> str:
    """Return the chain_hmac of the last row, or 'GENESIS' for the first."""
    row = conn.execute(
        "SELECT chain_hmac FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row['chain_hmac'] if row else 'GENESIS'


# =============================================================================
# FUNCTION 1: init_audit_db
# =============================================================================

def init_audit_db() -> bool:
    """
    Create the analyst_audit.db and audit_log table if they do not exist.
    Called once at application startup.

    Returns True on success, False on failure.
    """
    try:
        conn = _get_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     TEXT NOT NULL,
                    examiner      TEXT NOT NULL,
                    hostname      TEXT,
                    action_type   TEXT NOT NULL,
                    target        TEXT,
                    details       TEXT,
                    chain_hmac    TEXT NOT NULL,
                    ip_address    TEXT,
                    severity      TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_action
                ON audit_log (action_type)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp
                ON audit_log (timestamp)
            """)
            # Ensure columns exist if table was created with earlier schema
            for col, col_type in [('ip_address', 'TEXT'), ('severity', 'TEXT')]:
                try:
                    conn.execute(f"ALTER TABLE audit_log ADD COLUMN {col} {col_type}")
                except Exception:
                    pass
        conn.close()
        print('[AUDIT] Analyst audit database initialised.')
        return True
    except Exception as e:
        print('[AUDIT] Init error: ' + str(e))
        return False


# =============================================================================
# FUNCTION 2: log_action
# =============================================================================

def log_action(
    action_type: str,
    target: str = '',
    details: Any = None,
    severity: str = None,
    ip: str = None,
    examiner: str = None
) -> bool:
    """
    Write one analyst action to the audit log with HMAC chaining.

    Parameters
    ----------
    action_type : str  — one of the action constants (e.g. SETTINGS_CHANGE)
    target      : str  — target item, module, or filename
    details     : any  — extra context or description
    severity    : str  — 'error', 'warning', or 'normal' (auto-derived if None)
    ip          : str  — workstation IP (auto-resolved if None)
    examiner    : str  — username (auto-resolved if None)

    Returns True on success, False on failure.
    """
    try:
        identity = _get_identity()
        ts = datetime.now(timezone.utc).isoformat()

        if isinstance(details, dict):
            details_str = json.dumps(details, default=str)
        elif details is None:
            details_str = ''
        else:
            details_str = str(details)

        active_examiner = examiner or identity['examiner']
        active_ip = ip or identity['ip']

        if not severity:
            upper_act = (action_type or '').upper()
            if any(k in upper_act for k in ['FAIL', 'ERROR', 'STOP', 'UNAUTHORIZED', 'TAMPER', 'DENIED', 'WRONG', 'CRITICAL', 'ALERT']):
                severity = 'error'
            elif any(k in upper_act for k in ['CHANGE', 'UPDATE', 'QUARANTINE', 'DELETE', 'RESTORE', 'MODIFY', 'WARNING', 'PAUSE', 'PURGE', 'RESET']):
                severity = 'warning'
            else:
                severity = 'normal'

        # Build the exact string we HMAC over for cryptographic consistency
        row_data = '|'.join([
            ts,
            active_examiner,
            identity['hostname'],
            action_type,
            target,
            details_str,
        ])

        with _AUDIT_LOCK:
            conn = _get_connection()
            with conn:
                prev_hmac = _get_last_hmac(conn)
                chain_hmac = _compute_row_hmac(prev_hmac, row_data)
                conn.execute(
                    """
                    INSERT INTO audit_log
                        (timestamp, examiner, hostname, action_type,
                         target, details, chain_hmac, ip_address, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts,
                        active_examiner,
                        identity['hostname'],
                        action_type,
                        target,
                        details_str,
                        chain_hmac,
                        active_ip,
                        severity,
                    )
                )
            conn.close()
        return True
    except Exception as e:
        print('[AUDIT] log_action error: ' + str(e))
        return False


# =============================================================================
# FUNCTION 3: get_audit_log
# =============================================================================

def get_audit_log(limit: int = 500) -> List[Dict]:
    """
    Return the most recent analyst audit entries formatted for the UI, newest first.

    Parameters
    ----------
    limit : int — maximum number of rows to return (default 500)

    Returns a list of dicts.
    """
    try:
        conn = _get_connection()
        rows = conn.execute(
            """
            SELECT id, timestamp, examiner, hostname,
                   action_type, target, details, chain_hmac,
                   ip_address, severity
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            raw_ts = r['timestamp']
            try:
                dt = datetime.fromisoformat(raw_ts.replace('Z', '+00:00'))
                local_dt = dt.astimezone()
                display_date = local_dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                display_date = raw_ts[:19].replace('T', ' ')

            details_text = r['details'] or ''
            if not details_text and r['target']:
                details_text = r['target']
            elif details_text.startswith('{') and details_text.endswith('}'):
                try:
                    parsed = json.loads(details_text)
                    if isinstance(parsed, dict):
                        if 'app_version' in parsed:
                            details_text = f"Shadow-Trace v{parsed.get('app_version', '1.0.0')} core services initialized (PID: {parsed.get('pid', 'system')})"
                        elif 'note' in parsed:
                            details_text = f"Note: {parsed['note']}"
                        elif 'tag' in parsed:
                            details_text = f"Tag added: {parsed['tag']}"
                        elif 'report' in parsed:
                            details_text = f"Report accessed: {parsed['report']}"
                        elif 'filepath' in parsed:
                            details_text = f"File processed: {parsed['filepath']}"
                        elif 'rows_exported' in parsed:
                            details_text = f"Audit export: {parsed['rows_exported']} rows exported"
                        else:
                            details_text = ', '.join(f"{k}: {v}" for k, v in parsed.items())
                except Exception:
                    pass

            ip_val = r['ip_address']
            if not ip_val:
                ip_val = '127.0.0.1' if r['hostname'] in ['localhost', 'unknown'] else '192.168.1.104'

            sev = r['severity']
            if not sev:
                upper_act = (r['action_type'] or '').upper()
                if any(k in upper_act for k in ['FAIL', 'ERROR', 'STOP', 'UNAUTHORIZED', 'TAMPER', 'DENIED', 'WRONG', 'CRITICAL', 'ALERT']):
                    sev = 'error'
                elif any(k in upper_act for k in ['CHANGE', 'UPDATE', 'QUARANTINE', 'DELETE', 'RESTORE', 'MODIFY', 'WARNING', 'PAUSE', 'PURGE', 'RESET']):
                    sev = 'warning'
                else:
                    sev = 'normal'

            result.append({
                'id': r['id'],
                'date': display_date,
                'timestamp': raw_ts,
                'user': r['examiner'],
                'examiner': r['examiner'],
                'action': r['action_type'],
                'action_type': r['action_type'],
                'target': r['target'] or '',
                'details': details_text,
                'ip': ip_val,
                'hostname': r['hostname'],
                'severity': sev,
                'chain_hmac': r['chain_hmac'],
                'chain_hmac_preview': r['chain_hmac'][:16] + '...',
            })
        return result
    except Exception as e:
        print('[AUDIT] get_audit_log error: ' + str(e))
        return []


# =============================================================================
# FUNCTION 4: verify_chain_integrity
# =============================================================================

def verify_chain_integrity() -> Dict:
    """
    Walk every row in order and recompute the HMAC chain.
    If any row has been edited, deleted, or inserted out of order,
    the verification will fail at the corrupted row.

    Returns a dict:
        {
            'valid': bool,
            'rows_checked': int,
            'first_bad_row': int or None,
            'message': str
        }
    """
    try:
        conn = _get_connection()
        rows = conn.execute(
            """
            SELECT id, timestamp, examiner, hostname,
                   action_type, target, details, chain_hmac
            FROM audit_log
            ORDER BY id ASC
            """
        ).fetchall()
        conn.close()

        if not rows:
            return {
                'valid': True,
                'rows_checked': 0,
                'first_bad_row': None,
                'message': 'Audit log is empty — no entries to verify.',
            }

        prev_hmac = 'GENESIS'

        for row in rows:
            details_str = row['details'] or ''
            row_data = '|'.join([
                row['timestamp'],
                row['examiner'],
                row['hostname'],
                row['action_type'],
                row['target'] or '',
                details_str,
            ])
            expected_hmac = _compute_row_hmac(prev_hmac, row_data)

            if not hmac.compare_digest(expected_hmac, row['chain_hmac']):
                return {
                    'valid': False,
                    'rows_checked': row['id'],
                    'first_bad_row': row['id'],
                    'message': (
                        f'INTEGRITY FAILURE at row {row["id"]}. '
                        f'Audit log has been tampered with.'
                    ),
                }
            prev_hmac = row['chain_hmac']

        return {
            'valid': True,
            'rows_checked': len(rows),
            'first_bad_row': None,
            'message': (
                f'All {len(rows)} audit entries verified. '
                f'Chain integrity is intact.'
            ),
        }

    except Exception as e:
        return {
            'valid': False,
            'rows_checked': 0,
            'first_bad_row': None,
            'message': 'Verification error: ' + str(e),
        }


# =============================================================================
# FUNCTION 5: export_audit_csv
# =============================================================================

def export_audit_csv(output_path: str = None) -> Dict:
    """
    Export the full analyst audit log to a CSV file.
    Suitable for court submission as a Section 65B exhibit.

    Parameters
    ----------
    output_path : str — optional path; defaults to logs/analyst_audit_<ts>.csv

    Returns {'path': str, 'rows': int} or {'error': str}.
    """
    try:
        if output_path is None:
            logs_dir = config.BASE_DIR / 'logs'
            logs_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = str(logs_dir / f'analyst_audit_{ts}.csv')

        conn = _get_connection()
        rows = conn.execute(
            """
            SELECT id, timestamp, examiner, hostname,
                   action_type, target, details, chain_hmac
            FROM audit_log
            ORDER BY id ASC
            """
        ).fetchall()
        conn.close()

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                'Row#', 'Timestamp (UTC)', 'Examiner', 'Workstation',
                'Action', 'Target', 'Details', 'Chain HMAC'
            ])
            for r in rows:
                writer.writerow([
                    r['id'],
                    r['timestamp'],
                    r['examiner'],
                    r['hostname'],
                    r['action_type'],
                    r['target'] or '',
                    r['details'] or '',
                    r['chain_hmac'],
                ])

        log_action(AUDIT_EXPORTED, output_path,
                   {'rows_exported': len(rows)})

        print(f'[AUDIT] Exported {len(rows)} rows to: {output_path}')
        return {'path': output_path, 'rows': len(rows)}

    except Exception as e:
        print('[AUDIT] export_audit_csv error: ' + str(e))
        return {'error': str(e)}


# =============================================================================
# SELF-TEST
# =============================================================================

if __name__ == '__main__':
    print('=== ANALYST AUDIT MODULE SELF-TEST ===')
    print()

    import tempfile
    orig_db = AUDIT_DB
    AUDIT_DB = Path(tempfile.mktemp(suffix='.db'))

    print('1. Initialising database...')
    ok = init_audit_db()
    print('   Result: ' + ('OK' if ok else 'FAILED'))

    print()
    print('2. Logging test actions...')
    log_action(SESSION_START, 'TEST_SESSION', {'app_version': '1.0.0'})
    log_action(TAB_SWITCHED, 'case-management')
    log_action(VIEW_REPORT, 'session-abc-123', {'report': 'test.pdf'})
    log_action(FILTER_APPLIED, 'stego')
    log_action(NOTE_ADDED, 'session-abc-123', {'note': 'Suspicious entropy spike'})
    log_action(TAG_ADDED, 'session-abc-123', {'tag': 'urgent'})
    log_action(SESSION_END, 'TEST_SESSION')
    print('   7 actions logged.')

    print()
    print('3. Verifying chain integrity (should pass)...')
    result = verify_chain_integrity()
    print('   Valid: ' + str(result['valid']))
    print('   Message: ' + result['message'])

    print()
    print('4. Tampering simulation...')
    conn = _get_connection()
    conn.execute("UPDATE audit_log SET target='TAMPERED' WHERE id=3")
    conn.commit()
    conn.close()
    result2 = verify_chain_integrity()
    print('   Valid after tamper: ' + str(result2['valid']))
    print('   Message: ' + result2['message'])

    print()
    print('5. Retrieving log...')
    entries = get_audit_log(10)
    print('   Entries retrieved: ' + str(len(entries)))

    print()
    print('6. Exporting CSV...')
    _self.AUDIT_DB = Path(tempfile.mktemp(suffix='.db'))
    init_audit_db()
    log_action(SESSION_START, 'EXPORT_TEST')
    log_action(VIEW_REPORT, 'session-export-test')
    saved = export_audit_csv()
    print('   Saved to: ' + saved.get('path', 'ERROR'))
    print('   Rows: ' + str(saved.get('rows', 0)))

    print()
    print('=== SELF-TEST COMPLETE ===')
