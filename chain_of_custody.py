# =============================================================================
# Shadow-Trace | chain_of_custody.py
# Forensic chain-of-custody logger — every action taken on every file is
# recorded here so the integrity of the analysis can be proven in court.
# =============================================================================

import sqlite3
import uuid
import os
import json
import socket
import platform
from datetime import datetime
from pathlib import Path

import config
import utils

# =============================================================================
# Action-name constants — import these from other modules
# =============================================================================

FILE_DETECTED      = 'FILE_DETECTED'
FILE_LOCKED        = 'FILE_LOCKED'
HASH_GENERATED     = 'SHA3_HASH_GENERATED'
HASH_RECONFIRMED   = 'SHA3_HASH_RECONFIRMED'
HASH_MISMATCH      = 'SHA3_HASH_MISMATCH_CRITICAL'
MIME_CHECKED       = 'MIME_TYPE_VALIDATED'
MIME_MISMATCH      = 'MIME_TYPE_MISMATCH_DETECTED'
CLAMAV_SCAN        = 'CLAMAV_SCAN_COMPLETED'
YARA_SCAN          = 'YARA_SCAN_COMPLETED'
ENTROPY_CHECK      = 'ENTROPY_ANALYSIS_COMPLETED'
OLETOOLS_SCAN      = 'OLETOOLS_SCAN_COMPLETED'
PE_HEADER_SCAN     = 'PE_HEADER_SCAN_COMPLETED'
VIRUSTOTAL_SCAN    = 'VIRUSTOTAL_SCAN_COMPLETED'
HYBRID_SCAN        = 'HYBRID_ANALYSIS_COMPLETED'
FILE_QUARANTINED   = 'FILE_QUARANTINED'
FILE_UNLOCKED      = 'FILE_UNLOCKED'
FILE_RESTORED      = 'FILE_RESTORED'
LSB_CHECK          = 'LSB_EXECUTABLE_CHECK_COMPLETED'
EXECUTABLE_FOUND   = 'EXECUTABLE_FOUND_IN_LSB'
STEG_TRIGGERED     = 'STEGANALYSIS_TRIGGERED'
STEG_COMPLETE      = 'STEGANALYSIS_COMPLETED'
PAYLOAD_EXTRACTED  = 'PAYLOAD_EXTRACTED'
GRADCAM_GENERATED  = 'GRADCAM_HEATMAP_GENERATED'
SHAP_COMPUTED      = 'SHAP_VALUES_COMPUTED'
NARRATIVE_WRITTEN  = 'DECISION_NARRATIVE_WRITTEN'
REPORT_GENERATED   = 'FORENSIC_REPORT_GENERATED'
REPORT_SEALED      = 'REPORT_SEALED_HMAC_SHA3_512'
TIMESTAMP_OBTAINED = 'RFC3161_TIMESTAMP_OBTAINED'
CRASH_RECOVERY     = 'CRASH_RECOVERY_DETECTED'
PIPELINE_RESUMED   = 'PIPELINE_RESUMED_FROM_CRASH'
MANUAL_UPLOAD      = 'FILE_MANUALLY_UPLOADED'


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_connection():
    """Return a WAL-mode sqlite3 connection to the CoC database."""
    conn = sqlite3.connect(str(config.COC_DB))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _row_to_dict(row):
    return dict(row) if row else None


def _to_json(value):
    """Convert dicts to JSON strings; leave strings untouched."""
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False, default=str)
    return value if value is not None else ''


def _get_identity():
    """Return (username, hostname) with safe fallbacks."""
    try:
        username = os.getlogin()
    except Exception:
        username = os.environ.get('USERNAME') or os.environ.get('USER') or 'unknown'
    try:
        hostname = socket.gethostname()
    except Exception:
        hostname = 'unknown'
    return username, hostname


# =============================================================================
# FUNCTION 1: initialize_coc_db
# =============================================================================

def initialize_coc_db():
    """
    Create the chain-of-custody SQLite database and coc_log table.
    Also creates an index on session_id for fast lookups.

    Returns True on success, False on failure.
    """
    try:
        conn = _get_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS coc_log (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id   TEXT NOT NULL,
                    filepath     TEXT NOT NULL,
                    sha3_hash    TEXT,
                    action       TEXT NOT NULL,
                    result       TEXT DEFAULT 'SUCCESS',
                    details      TEXT,
                    timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    username     TEXT,
                    hostname     TEXT,
                    stage_number INTEGER
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_coc_session_id
                ON coc_log (session_id)
            """)
        conn.close()
        utils.logger.info("CoC DB initialised at %s", config.COC_DB)
        return True
    except sqlite3.Error as e:
        utils.log_error("initialize_coc_db: SQLite error", e)
        return False
    except Exception as e:
        utils.log_error("initialize_coc_db: unexpected error", e)
        return False


# =============================================================================
# FUNCTION 2: open_session
# =============================================================================

def open_session(filepath, sha3_hash, source_url):
    """
    Start a new forensic session the moment a file is detected.

    Generates a unique session_id (UUID4), logs the first CoC entry
    (FILE_DETECTED) and returns the session_id string.

    Parameters
    ----------
    filepath   : str – path of the detected file
    sha3_hash  : str – SHA3-512 hex digest
    source_url : str – URL the file was downloaded from (or '' for local)

    Returns the session_id string, or None on error.
    """
    try:
        session_id = str(uuid.uuid4())
        username, hostname = _get_identity()

        file_info = utils.get_file_info(filepath)
        details = {
            'source_url': source_url,
            'filename':   file_info.get('filename') if file_info else os.path.basename(filepath),
            'file_size':  file_info.get('size_bytes') if file_info else None,
            'username':   username,
            'hostname':   hostname,
            'os':         f"{platform.system()} {platform.architecture()[0]}",
            'timestamp':  datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }

        success = log_action(
            session_id=session_id,
            filepath=filepath,
            sha3_hash=sha3_hash,
            action=FILE_DETECTED,
            result='SUCCESS',
            details=details,
        )

        if not success:
            utils.log_error(f"open_session: log_action failed for {filepath}")
            return None

        utils.logger.info("CoC session opened: %s for %s", session_id, filepath)
        return session_id
    except Exception as e:
        utils.log_error(f"open_session: unexpected error for {filepath}", e)
        return None


# =============================================================================
# FUNCTION 3: log_action
# =============================================================================

def log_action(session_id, filepath, sha3_hash,
               action, result='SUCCESS', details=None):
    """
    Insert a new entry into the chain-of-custody log.

    Stage number is assigned automatically as (current entry count + 1)
    for this session.

    Parameters
    ----------
    session_id : str
    filepath   : str
    sha3_hash  : str
    action     : str  – one of the ACTION constants at the top of this file
    result     : str  – e.g. 'SUCCESS', 'CLEAN', 'THREAT_FOUND', 'FAILED'
    details    : str or dict – freeform evidence details

    Returns True on success, False on failure.
    """
    try:
        username, hostname = _get_identity()
        timestamp    = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        details_json = _to_json(details)

        conn = _get_connection()
        with conn:
            # Auto-increment stage number per session
            row = conn.execute(
                "SELECT COUNT(*) FROM coc_log WHERE session_id = ?",
                (session_id,)
            ).fetchone()
            stage_number = (row[0] if row else 0) + 1

            conn.execute("""
                INSERT INTO coc_log
                    (session_id, filepath, sha3_hash, action, result,
                     details, timestamp, username, hostname, stage_number)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (session_id, filepath, sha3_hash, action, result,
                  details_json, timestamp, username, hostname, stage_number))
        conn.close()
        utils.logger.info(
            "CoC [%s] stage %d: %s -> %s", session_id[:8], stage_number, action, result
        )
        return True
    except sqlite3.Error as e:
        utils.log_error(f"log_action: SQLite error — action={action} session={session_id}", e)
        return False
    except Exception as e:
        utils.log_error(f"log_action: unexpected error — action={action}", e)
        return False


# =============================================================================
# FUNCTION 4: get_session_log
# =============================================================================

def get_session_log(session_id):
    """
    Return all log entries for a session ordered by timestamp ascending.

    Returns a list of dicts, or an empty list on error / no results.
    """
    try:
        conn = _get_connection()
        cur = conn.execute("""
            SELECT * FROM coc_log
            WHERE session_id = ?
            ORDER BY timestamp ASC, stage_number ASC
        """, (session_id,))
        rows = [_row_to_dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except sqlite3.Error as e:
        utils.log_error(f"get_session_log: SQLite error for session {session_id}", e)
        return []
    except Exception as e:
        utils.log_error(f"get_session_log: unexpected error for session {session_id}", e)
        return []


# =============================================================================
# FUNCTION 5: export_session_as_text
# =============================================================================

def export_session_as_text(session_id):
    """
    Return the complete session log as a formatted forensic plain-text string.

    Returns the formatted string, or an error message string on failure.
    """
    try:
        entries = get_session_log(session_id)
        if not entries:
            return f"[CoC Export] No entries found for session {session_id}"

        lines = [
            "CHAIN OF CUSTODY LOG",
            "====================",
            f"Session ID   : {session_id}",
            f"Total Actions: {len(entries)}",
            "",
        ]

        for entry in entries:
            lines.append(
                f"{entry['stage_number']}. {entry['timestamp']} | {entry['action']}"
            )
            lines.append(f"   Result              : {entry['result']}")
            lines.append(f"   File Hash at moment : {entry['sha3_hash'] or 'N/A'}")
            lines.append(f"   Details             : {entry['details'] or 'N/A'}")
            lines.append(
                f"   Recorded by         : {entry['username']} on {entry['hostname']}"
            )
            lines.append("")

        lines.append("End of Chain of Custody Log")
        lines.append(
            f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        return "\n".join(lines)
    except Exception as e:
        utils.log_error(f"export_session_as_text: error for session {session_id}", e)
        return f"[CoC Export ERROR] {e}"


# =============================================================================
# FUNCTION 6: get_all_sessions
# =============================================================================

def get_all_sessions():
    """
    Return a summary list of all unique sessions in the database.

    Each entry contains:
        session_id, filepath, started_at, total_actions, last_action

    Returns a list of dicts, or an empty list on error.
    """
    try:
        conn = _get_connection()
        cur = conn.execute("""
            SELECT
                session_id,
                filepath,
                MIN(timestamp)  AS started_at,
                COUNT(*)        AS total_actions,
                MAX(action)     AS last_action
            FROM coc_log
            GROUP BY session_id
            ORDER BY started_at DESC
        """)
        rows = [_row_to_dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except sqlite3.Error as e:
        utils.log_error("get_all_sessions: SQLite error", e)
        return []
    except Exception as e:
        utils.log_error("get_all_sessions: unexpected error", e)
        return []


# =============================================================================
# FUNCTION 7: verify_chain_integrity
# =============================================================================

def verify_chain_integrity(session_id):
    """
    Validate the forensic integrity of a session's chain of custody.

    Checks performed:
      1. Stage numbers are sequential with no gaps
      2. Timestamps are in ascending order (no backwards jumps)
      3. First entry is FILE_DETECTED

    Returns a dict:
        is_intact     : bool
        issues_found  : list of str
        total_entries : int
        session_id    : str
    """
    issues = []
    try:
        entries = get_session_log(session_id)
        total   = len(entries)

        if total == 0:
            return {
                'is_intact':     False,
                'issues_found':  [f"No entries found for session {session_id}"],
                'total_entries': 0,
                'session_id':    session_id,
            }

        # Check 1 — first action must be FILE_DETECTED
        if entries[0]['action'] != FILE_DETECTED:
            issues.append(
                f"First action is '{entries[0]['action']}', expected 'FILE_DETECTED'."
            )

        # Check 2 — sequential stage numbers with no gaps
        expected_stage = 1
        for entry in entries:
            sn = entry['stage_number']
            if sn != expected_stage:
                issues.append(
                    f"Stage number gap: expected {expected_stage}, found {sn} "
                    f"(action={entry['action']})."
                )
            expected_stage += 1

        # Check 3 — timestamps in ascending order
        prev_ts = None
        for entry in entries:
            try:
                ts = datetime.strptime(entry['timestamp'], '%Y-%m-%d %H:%M:%S')
                if prev_ts and ts < prev_ts:
                    issues.append(
                        f"Timestamp went backwards at stage {entry['stage_number']}: "
                        f"{entry['timestamp']} < previous."
                    )
                prev_ts = ts
            except ValueError:
                issues.append(
                    f"Unparseable timestamp at stage {entry['stage_number']}: "
                    f"'{entry['timestamp']}'."
                )

        is_intact = len(issues) == 0
        utils.logger.info(
            "verify_chain_integrity: session=%s intact=%s issues=%d",
            session_id[:8], is_intact, len(issues)
        )
        return {
            'is_intact':     is_intact,
            'issues_found':  issues,
            'total_entries': total,
            'session_id':    session_id,
        }
    except Exception as e:
        utils.log_error(f"verify_chain_integrity: unexpected error for {session_id}", e)
        return {
            'is_intact':     False,
            'issues_found':  [f"Exception during verification: {e}"],
            'total_entries': 0,
            'session_id':    session_id,
        }


# =============================================================================
# Self-tests
# =============================================================================

if __name__ == '__main__':
    PASS = '\033[92mPASS\033[0m'
    FAIL = '\033[91mFAIL\033[0m'
    TEST_FILE = 'C:/test/fake_file.jpg'
    TEST_HASH = 'abc123testhash'
    TEST_URL  = 'https://example.com/fake_file.jpg'

    print("\n" + "=" * 62)
    print("  Shadow-Trace chain_of_custody.py -- Self-Test Suite")
    print("=" * 62 + "\n")

    # ── Test 1: Initialise database ──────────────────────────────────────────
    print("TEST 1 -- Initialize CoC database")
    try:
        ok = initialize_coc_db()
        if ok:
            print(f"  Database ready at: {config.COC_DB}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- returned False\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 2: Open a session ───────────────────────────────────────────────
    print("TEST 2 -- Open a new forensic session")
    session = None
    try:
        session = open_session(TEST_FILE, TEST_HASH, TEST_URL)
        if session:
            print(f"  Session opened: {session}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- returned None\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 3: Log several actions ──────────────────────────────────────────
    print("TEST 3 -- Log multiple forensic actions")
    try:
        actions = [
            (FILE_LOCKED,       'SUCCESS',          'File permissions set to 0o000'),
            (HASH_GENERATED,    'SUCCESS',          {'hash': TEST_HASH, 'algorithm': 'SHA3-512'}),
            (CLAMAV_SCAN,       'CLEAN',            'No signatures matched'),
            (VIRUSTOTAL_SCAN,   'CLEAN',            {'engines_clean': 72, 'engines_total': 72}),
            (LSB_CHECK,         'NO_EXECUTABLE_FOUND', 'LSB plane analysis complete'),
        ]
        all_ok = True
        for action, result, details in actions:
            ok = log_action(session, TEST_FILE, TEST_HASH, action, result, details)
            if not ok:
                all_ok = False
                print(f"  WARN: log_action failed for {action}")

        if all_ok:
            print("  All 5 actions logged successfully")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- one or more log_action calls failed\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 4: Export as text ───────────────────────────────────────────────
    print("TEST 4 -- Export session as forensic text report")
    try:
        text = export_session_as_text(session)
        if text and 'CHAIN OF CUSTODY LOG' in text:
            print(text)
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- unexpected output:\n{text}\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 5: Verify integrity ─────────────────────────────────────────────
    print("TEST 5 -- Verify chain integrity")
    try:
        integrity = verify_chain_integrity(session)
        for k, v in integrity.items():
            print(f"  {k:<16}: {v}")
        if integrity.get('is_intact'):
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- chain not intact\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 6: Get all sessions ─────────────────────────────────────────────
    print("TEST 6 -- Get all sessions from database")
    try:
        sessions = get_all_sessions()
        print(f"  Total sessions in DB: {len(sessions)}")
        if sessions:
            print("  Most recent session:")
            for k, v in sessions[0].items():
                print(f"    {k:<16}: {v}")
        if sessions:
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- empty list returned\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    print("=" * 62)
    print("  All tests complete.")
    print("=" * 62 + "\n")
