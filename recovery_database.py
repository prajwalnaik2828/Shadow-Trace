# =============================================================================
# Shadow-Trace | recovery_database.py
# SQLite-backed crash-recovery tracker for files locked during scanning.
# If the app crashes mid-scan, locked files are detected on next startup
# and automatically restored using the records held in this database.
# =============================================================================

import sqlite3
import os
from datetime import datetime, timedelta

import config
import utils

# Valid status values enforced at the application layer
_VALID_STATUSES = {'LOCKED', 'COMPLETE', 'QUARANTINED', 'RESTORED', 'ERROR'}

# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _get_connection():
    """Return an sqlite3 connection to the recovery database."""
    conn = sqlite3.connect(str(config.RECOVERY_DB))
    conn.row_factory = sqlite3.Row          # rows accessible as dicts / by name
    conn.execute("PRAGMA journal_mode=WAL") # safer for concurrent access
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _row_to_dict(row):
    """Convert an sqlite3.Row to a plain Python dict."""
    return dict(row) if row else None


# =============================================================================
# FUNCTION 1: initialize_recovery_db
# =============================================================================

def initialize_recovery_db():
    """
    Create the recovery database and the locked_files table if they
    do not already exist.  Also creates an index on the filepath column.

    Returns True on success, False on failure.
    """
    try:
        conn = _get_connection()
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS locked_files (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    filepath          TEXT NOT NULL,
                    original_filepath TEXT NOT NULL,
                    sha3_hash         TEXT,
                    locked_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_updated      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    current_stage     TEXT DEFAULT 'LAYER_0_START',
                    status            TEXT DEFAULT 'LOCKED'
                                      CHECK(status IN ('LOCKED','COMPLETE',
                                                       'QUARANTINED','RESTORED',
                                                       'ERROR')),
                    lock_reason       TEXT DEFAULT 'SCANNING'
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_locked_files_filepath
                ON locked_files (filepath)
            """)
        conn.close()
        utils.logger.info("Recovery DB initialised at %s", config.RECOVERY_DB)
        return True
    except sqlite3.Error as e:
        utils.log_error("initialize_recovery_db: SQLite error", e)
        return False
    except Exception as e:
        utils.log_error("initialize_recovery_db: unexpected error", e)
        return False


# =============================================================================
# FUNCTION 2: register_file
# =============================================================================

def register_file(filepath, sha3_hash, stage):
    """
    Insert a new LOCKED record for *filepath*, or UPDATE the existing one.

    Parameters
    ----------
    filepath  : str  – path of the file being scanned / locked
    sha3_hash : str  – pre-computed SHA3-512 hex digest
    stage     : str  – current pipeline stage label (e.g. 'LAYER_0_START')

    Returns the row id (int) of the inserted/updated record, or None on error.
    """
    try:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = _get_connection()
        with conn:
            # Check for an existing record
            cur = conn.execute(
                "SELECT id FROM locked_files WHERE filepath = ?", (filepath,)
            )
            existing = cur.fetchone()

            if existing:
                conn.execute("""
                    UPDATE locked_files
                    SET sha3_hash         = ?,
                        current_stage     = ?,
                        status            = 'LOCKED',
                        lock_reason       = 'SCANNING',
                        last_updated      = ?
                    WHERE filepath = ?
                """, (sha3_hash, stage, now, filepath))
                row_id = existing['id']
            else:
                cur = conn.execute("""
                    INSERT INTO locked_files
                        (filepath, original_filepath, sha3_hash,
                         current_stage, status, lock_reason,
                         locked_at, last_updated)
                    VALUES (?, ?, ?, ?, 'LOCKED', 'SCANNING', ?, ?)
                """, (filepath, filepath, sha3_hash, stage, now, now))
                row_id = cur.lastrowid

        conn.close()
        utils.logger.info("register_file: registered %s (id=%s)", filepath, row_id)
        return int(row_id)
    except sqlite3.Error as e:
        utils.log_error(f"register_file: SQLite error for {filepath}", e)
        return None
    except Exception as e:
        utils.log_error(f"register_file: unexpected error for {filepath}", e)
        return None


# =============================================================================
# FUNCTION 3: update_stage
# =============================================================================

def update_stage(filepath, new_stage):
    """
    Update the current pipeline stage for *filepath*.

    Returns True on success, False on failure.
    """
    try:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = _get_connection()
        with conn:
            conn.execute("""
                UPDATE locked_files
                SET current_stage = ?,
                    last_updated  = ?
                WHERE filepath = ?
            """, (new_stage, now, filepath))
        conn.close()
        utils.logger.info("update_stage: %s -> %s", filepath, new_stage)
        return True
    except sqlite3.Error as e:
        utils.log_error(f"update_stage: SQLite error for {filepath}", e)
        return False
    except Exception as e:
        utils.log_error(f"update_stage: unexpected error for {filepath}", e)
        return False


# =============================================================================
# FUNCTION 4: mark_complete
# =============================================================================

def mark_complete(filepath):
    """
    Mark a file's scan record as COMPLETE.

    Returns True on success, False on failure.
    """
    try:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = _get_connection()
        with conn:
            conn.execute("""
                UPDATE locked_files
                SET status       = 'COMPLETE',
                    last_updated = ?
                WHERE filepath = ?
            """, (now, filepath))
        conn.close()
        utils.logger.info("mark_complete: %s", filepath)
        return True
    except sqlite3.Error as e:
        utils.log_error(f"mark_complete: SQLite error for {filepath}", e)
        return False
    except Exception as e:
        utils.log_error(f"mark_complete: unexpected error for {filepath}", e)
        return False


# =============================================================================
# FUNCTION 5: mark_quarantined
# =============================================================================

def mark_quarantined(filepath, quarantine_path):
    """
    Mark a file as QUARANTINED after a threat is detected.

    Parameters
    ----------
    filepath        : str – original scanned file path
    quarantine_path : str – destination path inside the quarantine folder

    Returns True on success, False on failure.
    """
    try:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = _get_connection()
        with conn:
            conn.execute("""
                UPDATE locked_files
                SET status       = 'QUARANTINED',
                    lock_reason  = 'THREAT_DETECTED_FILE_QUARANTINED',
                    last_updated = ?
                WHERE filepath = ?
            """, (now, filepath))
        conn.close()
        utils.logger.warning(
            "mark_quarantined: %s -> quarantine: %s", filepath, quarantine_path
        )
        return True
    except sqlite3.Error as e:
        utils.log_error(f"mark_quarantined: SQLite error for {filepath}", e)
        return False
    except Exception as e:
        utils.log_error(f"mark_quarantined: unexpected error for {filepath}", e)
        return False


# =============================================================================
# FUNCTION 6: mark_restored
# =============================================================================

def mark_restored(filepath):
    """
    Mark a previously locked file as RESTORED (scan done, access given back).

    Returns True on success, False on failure.
    """
    try:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = _get_connection()
        with conn:
            conn.execute("""
                UPDATE locked_files
                SET status       = 'RESTORED',
                    lock_reason  = 'SCAN_COMPLETE_RESTORED',
                    last_updated = ?
                WHERE filepath = ?
            """, (now, filepath))
        conn.close()
        utils.logger.info("mark_restored: %s", filepath)
        return True
    except sqlite3.Error as e:
        utils.log_error(f"mark_restored: SQLite error for {filepath}", e)
        return False
    except Exception as e:
        utils.log_error(f"mark_restored: unexpected error for {filepath}", e)
        return False


# =============================================================================
# FUNCTION 7: get_orphaned_files
# =============================================================================

def get_orphaned_files():
    """
    Return LOCKED records that were locked more than 60 seconds ago.
    Files locked very recently are likely still being actively processed,
    so they are excluded to avoid false-positive orphan detection on restart.

    Returns a list of dicts, or an empty list on error / no results.
    """
    try:
        conn = _get_connection()
        cur = conn.execute("""
            SELECT id, filepath, original_filepath, sha3_hash,
                   locked_at, current_stage, lock_reason
            FROM locked_files
            WHERE status = 'LOCKED'
              AND locked_at < datetime('now', '-60 seconds')
            ORDER BY locked_at ASC
        """)
        rows = [_row_to_dict(r) for r in cur.fetchall()]
        conn.close()
        utils.logger.info("get_orphaned_files: found %d orphaned record(s)", len(rows))
        return rows
    except sqlite3.Error as e:
        utils.log_error("get_orphaned_files: SQLite error", e)
        return []
    except Exception as e:
        utils.log_error("get_orphaned_files: unexpected error", e)
        return []


# =============================================================================
# FUNCTION 7b: get_all_active_files
# =============================================================================

def get_all_active_files():
    """
    Return the filepath of every record currently in LOCKED status,
    regardless of how recently it was locked.

    Used by the startup pre-population logic in layer0_monitor.py to
    ensure actively-tracked files are added to known_files and are
    not re-processed by the polling monitor.

    Returns a list of filepath strings, or an empty list on error.
    """
    try:
        conn = _get_connection()
        cur = conn.execute(
            "SELECT filepath FROM locked_files WHERE status = 'LOCKED'"
        )
        paths = [row[0] for row in cur.fetchall()]
        conn.close()
        utils.logger.info("get_all_active_files: found %d active LOCKED file(s)", len(paths))
        return paths
    except sqlite3.Error as e:
        utils.log_error("get_all_active_files: SQLite error", e)
        return []
    except Exception as e:
        utils.log_error("get_all_active_files: unexpected error", e)
        return []


# =============================================================================
# FUNCTION 8: get_file_record
# =============================================================================

def get_file_record(filepath):
    """
    Retrieve the full database record for a specific filepath.

    Returns a dict on success, None if not found or on error.
    """
    try:
        conn = _get_connection()
        cur = conn.execute(
            "SELECT * FROM locked_files WHERE filepath = ?", (filepath,)
        )
        row = _row_to_dict(cur.fetchone())
        conn.close()
        return row
    except sqlite3.Error as e:
        utils.log_error(f"get_file_record: SQLite error for {filepath}", e)
        return None
    except Exception as e:
        utils.log_error(f"get_file_record: unexpected error for {filepath}", e)
        return None


# =============================================================================
# FUNCTION 9: clear_old_completed_records
# =============================================================================

def clear_old_completed_records():
    """
    Delete COMPLETE and RESTORED records that are older than 7 days.
    Keeps the database lean over time.

    Returns the count of deleted rows, or 0 on error.
    """
    try:
        cutoff = (datetime.now() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')
        conn = _get_connection()
        with conn:
            cur = conn.execute("""
                DELETE FROM locked_files
                WHERE status IN ('COMPLETE', 'RESTORED')
                  AND last_updated < ?
            """, (cutoff,))
            deleted = cur.rowcount
        conn.close()
        utils.logger.info("clear_old_completed_records: deleted %d old record(s)", deleted)
        return deleted
    except sqlite3.Error as e:
        utils.log_error("clear_old_completed_records: SQLite error", e)
        return 0
    except Exception as e:
        utils.log_error("clear_old_completed_records: unexpected error", e)
        return 0


# =============================================================================
# FUNCTION 10: get_database_stats
# =============================================================================

def get_database_stats():
    """
    Return a summary dictionary of the current state of the recovery database.

    Returns a dict with record counts and file-system metadata.
    """
    try:
        conn = _get_connection()

        def _count(where_clause=''):
            sql = "SELECT COUNT(*) FROM locked_files"
            if where_clause:
                sql += f" WHERE {where_clause}"
            return conn.execute(sql).fetchone()[0]

        stats = {
            'total_records':      _count(),
            'locked_count':       _count("status = 'LOCKED'"),
            'complete_count':     _count("status = 'COMPLETE'"),
            'quarantined_count':  _count("status = 'QUARANTINED'"),
            'restored_count':     _count("status = 'RESTORED'"),
            'database_path':      str(config.RECOVERY_DB),
            'database_size_bytes': (
                os.path.getsize(str(config.RECOVERY_DB))
                if os.path.exists(str(config.RECOVERY_DB)) else 0
            ),
        }
        conn.close()
        return stats
    except sqlite3.Error as e:
        utils.log_error("get_database_stats: SQLite error", e)
        return {}
    except Exception as e:
        utils.log_error("get_database_stats: unexpected error", e)
        return {}


# =============================================================================
# Self-tests
# =============================================================================

if __name__ == '__main__':
    PASS = '\033[92mPASS\033[0m'
    FAIL = '\033[91mFAIL\033[0m'
    TEST_PATH = 'C:/test/fake_test_file.jpg'

    print("\n" + "=" * 60)
    print("  Shadow-Trace recovery_database.py — Self-Test Suite")
    print("=" * 60 + "\n")

    # ── Test 1: Initialise database ──────────────────────────────────────────
    print("TEST 1 — Initialize recovery database")
    try:
        ok = initialize_recovery_db()
        if ok:
            print(f"  Database created at: {config.RECOVERY_DB}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — initialize_recovery_db returned False\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 2: Register a fake file ─────────────────────────────────────────
    print("TEST 2 — Register a fake locked file")
    try:
        row_id = register_file(TEST_PATH, 'abc123hash', 'LAYER_0_START')
        if row_id is not None:
            print(f"  Inserted / updated row ID: {row_id}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — returned None\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 3: Update stage ─────────────────────────────────────────────────
    print("TEST 3 — Update pipeline stage")
    try:
        ok = update_stage(TEST_PATH, 'LAYER_1_CLAMAV')
        if ok:
            print("  Stage updated to LAYER_1_CLAMAV")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — update_stage returned False\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 4: Get the record ───────────────────────────────────────────────
    print("TEST 4 — Retrieve full record for the fake file")
    try:
        record = get_file_record(TEST_PATH)
        if record:
            for k, v in record.items():
                print(f"  {k:<22}: {v}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — returned None\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 5: Get orphaned files ───────────────────────────────────────────
    print("TEST 5 — Get orphaned (still LOCKED) files")
    try:
        orphans = get_orphaned_files()
        print(f"  Orphaned file count: {len(orphans)}")
        if orphans:
            print("  First orphan record:")
            for k, v in orphans[0].items():
                print(f"    {k:<22}: {v}")
        print(f"  Result: {PASS}\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 6: Mark complete ────────────────────────────────────────────────
    print("TEST 6 — Mark fake file as COMPLETE")
    try:
        ok = mark_complete(TEST_PATH)
        if ok:
            print("  Status updated to COMPLETE")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — mark_complete returned False\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    # ── Test 7: Database stats ───────────────────────────────────────────────
    print("TEST 7 — Database statistics")
    try:
        stats = get_database_stats()
        if stats:
            for k, v in stats.items():
                print(f"  {k:<24}: {v}")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} — returned empty dict\n")
    except Exception as exc:
        print(f"  Result: {FAIL} — {exc}\n")

    print("=" * 60)
    print("  All tests complete.")
    print("=" * 60 + "\n")
