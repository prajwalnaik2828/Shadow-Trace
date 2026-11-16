import os
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import config

DB_PATH = config.BASE_DIR / 'investigation.db'


def init_investigation_db():
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS investigator_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            filepath TEXT,
            note_text TEXT NOT NULL,
            examiner_name TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT,
            note_type TEXT DEFAULT 'GENERAL',
            is_flagged INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS case_tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            tag TEXT NOT NULL,
            created_at TEXT NOT NULL,
            created_by TEXT,
            UNIQUE(session_id, tag)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS evidence_bookmarks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            filepath TEXT,
            report_path TEXT,
            bookmark_label TEXT NOT NULL,
            bookmark_notes TEXT,
            evidence_type TEXT,
            created_at TEXT NOT NULL,
            created_by TEXT,
            is_primary INTEGER DEFAULT 0
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reprocess_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            filepath TEXT NOT NULL,
            reason TEXT,
            requested_at TEXT NOT NULL,
            requested_by TEXT,
            status TEXT DEFAULT 'PENDING',
            completed_at TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print('[INVESTIGATION] Database initialised: ' + DB_PATH.name)


def add_note(
    session_id: str,
    note_text: str,
    filepath: str = None,
    note_type: str = 'GENERAL',
    is_flagged: bool = False,
) -> Dict:
    try:
        init_investigation_db()
        now = datetime.now(timezone.utc).isoformat()
        examiner = os.environ.get('EXAMINER_NAME', 'Unknown')
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO investigator_notes
            (session_id, filepath, note_text, examiner_name,
             created_at, note_type, is_flagged)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session_id, filepath, note_text, examiner,
              now, note_type, 1 if is_flagged else 0))
        note_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return {
            'success': True,
            'note_id': note_id,
            'session_id': session_id,
            'note_type': note_type,
            'created_at': now,
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_notes(
    session_id: str,
    note_type: str = None,
) -> List[Dict]:
    try:
        init_investigation_db()
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if note_type:
            cursor.execute(
                'SELECT * FROM investigator_notes '
                'WHERE session_id=? AND note_type=? '
                'ORDER BY created_at ASC',
                (session_id, note_type)
            )
        else:
            cursor.execute(
                'SELECT * FROM investigator_notes '
                'WHERE session_id=? '
                'ORDER BY created_at ASC',
                (session_id,)
            )
        
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def update_note(
    note_id: int,
    new_text: str,
) -> Dict:
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE investigator_notes '
            'SET note_text=?, updated_at=? WHERE id=?',
            (new_text, now, note_id)
        )
        conn.commit()
        conn.close()
        return {'success': True, 'note_id': note_id}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def delete_note(note_id: int) -> Dict:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM investigator_notes WHERE id=?',
            (note_id,)
        )
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def add_tag(
    session_id: str,
    tag: str,
) -> Dict:
    try:
        init_investigation_db()
        now = datetime.now(timezone.utc).isoformat()
        examiner = os.environ.get('EXAMINER_NAME', 'Unknown')
        tag_clean = tag.lower().strip().replace(' ', '-')
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO case_tags '
                '(session_id, tag, created_at, created_by) '
                'VALUES (?, ?, ?, ?)',
                (session_id, tag_clean, now, examiner)
            )
            conn.commit()
            inserted = True
        except sqlite3.IntegrityError:
            inserted = False
        conn.close()
        return {
            'success': True,
            'tag': tag_clean,
            'already_existed': not inserted,
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def remove_tag(
    session_id: str,
    tag: str,
) -> Dict:
    try:
        tag_clean = tag.lower().strip().replace(' ', '-')
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM case_tags WHERE session_id=? AND tag=?',
            (session_id, tag_clean)
        )
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_tags(session_id: str) -> List[str]:
    try:
        init_investigation_db()
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            'SELECT tag FROM case_tags WHERE session_id=? '
            'ORDER BY created_at ASC',
            (session_id,)
        )
        tags = [r['tag'] for r in cursor.fetchall()]
        conn.close()
        return tags
    except Exception:
        return []


def get_sessions_by_tag(tag: str) -> List[str]:
    try:
        tag_clean = tag.lower().strip().replace(' ', '-')
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            'SELECT DISTINCT session_id FROM case_tags '
            'WHERE tag=? ORDER BY created_at DESC',
            (tag_clean,)
        )
        sessions = [r['session_id'] for r in cursor.fetchall()]
        conn.close()
        return sessions
    except Exception:
        return []


def get_all_tags_summary() -> List[Dict]:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            'SELECT tag, COUNT(*) as count '
            'FROM case_tags GROUP BY tag '
            'ORDER BY count DESC'
        )
        tags = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return tags
    except Exception:
        return []


def add_bookmark(
    session_id: str,
    bookmark_label: str,
    filepath: str = None,
    report_path: str = None,
    evidence_type: str = 'FILE',
    bookmark_notes: str = None,
    is_primary: bool = False,
) -> Dict:
    try:
        init_investigation_db()
        now = datetime.now(timezone.utc).isoformat()
        examiner = os.environ.get('EXAMINER_NAME', 'Unknown')
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO evidence_bookmarks
            (session_id, filepath, report_path,
             bookmark_label, bookmark_notes,
             evidence_type, created_at, created_by,
             is_primary)
            VALUES (?,?,?,?,?,?,?,?,?)
        ''', (session_id, filepath, report_path,
              bookmark_label, bookmark_notes,
              evidence_type, now, examiner,
              1 if is_primary else 0))
        bm_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return {
            'success': True,
            'bookmark_id': bm_id,
            'label': bookmark_label,
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_bookmarks(
    session_id: str,
    evidence_type: str = None,
) -> List[Dict]:
    try:
        init_investigation_db()
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if evidence_type:
            cursor.execute(
                'SELECT * FROM evidence_bookmarks '
                'WHERE session_id=? AND evidence_type=? '
                'ORDER BY is_primary DESC, created_at ASC',
                (session_id, evidence_type)
            )
        else:
            cursor.execute(
                'SELECT * FROM evidence_bookmarks '
                'WHERE session_id=? '
                'ORDER BY is_primary DESC, created_at ASC',
                (session_id,)
            )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def delete_bookmark(bookmark_id: int) -> Dict:
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            'DELETE FROM evidence_bookmarks WHERE id=?',
            (bookmark_id,)
        )
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def queue_for_reprocess(
    session_id: str,
    filepath: str,
    reason: str,
) -> Dict:
    try:
        init_investigation_db()
        now = datetime.now(timezone.utc).isoformat()
        examiner = os.environ.get('EXAMINER_NAME', 'Unknown')
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO reprocess_queue
            (session_id, filepath, reason,
             requested_at, requested_by, status)
            VALUES (?,?,?,?,?,?)
        ''', (session_id, filepath, reason,
              now, examiner, 'PENDING'))
        q_id = cursor.lastrowid
        conn.commit()
        conn.close()
        print('[INVESTIGATION] Queued for reprocess: ' + Path(filepath).name)
        return {
            'success': True,
            'queue_id': q_id,
            'status': 'PENDING',
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_reprocess_queue(
    status: str = 'PENDING',
) -> List[Dict]:
    try:
        init_investigation_db()
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            'SELECT * FROM reprocess_queue '
            'WHERE status=? ORDER BY requested_at ASC',
            (status,)
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []


def mark_reprocess_complete(
    queue_id: int,
) -> Dict:
    try:
        now = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE reprocess_queue '
            'SET status=?, completed_at=? WHERE id=?',
            ('COMPLETE', now, queue_id)
        )
        conn.commit()
        conn.close()
        return {'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}


def get_full_session_view(
    session_id: str,
) -> Dict:
    notes = get_notes(session_id)
    tags = get_tags(session_id)
    bookmarks = get_bookmarks(session_id)
    pending = [
        q for q in get_reprocess_queue('PENDING')
        if q.get('session_id') == session_id
    ]

    return {
        'session_id': session_id,
        'notes': notes,
        'note_count': len(notes),
        'flagged_notes': [n for n in notes if n.get('is_flagged')],
        'tags': tags,
        'tag_count': len(tags),
        'bookmarks': bookmarks,
        'bookmark_count': len(bookmarks),
        'primary_bookmarks': [b for b in bookmarks if b.get('is_primary')],
        'pending_reprocess': pending,
        'has_concerns': any(
            n.get('note_type') == 'CONCERN' for n in notes
        ),
        'has_legal_notes': any(
            n.get('note_type') == 'LEGAL' for n in notes
        ),
    }


if __name__ == '__main__':
    print('=== INVESTIGATION TOOLS TEST ===')
    init_investigation_db()
    test_session = 'test_session_' + str(uuid.uuid4())[:8]
    print(f'\nTesting with session: {test_session}')
    
    # 1. Test tags
    print('\nAdding tags...')
    add_tag(test_session, 'ransomware')
    add_tag(test_session, 'urgent')
    print('Tags:', get_tags(test_session))
    
    # 2. Test notes
    print('\nAdding notes...')
    add_note(test_session, 'Found suspicious payload in section 2.', note_type='FINDING')
    add_note(test_session, 'Needs further review by legal team.', note_type='LEGAL', is_flagged=True)
    notes = get_notes(test_session)
    for n in notes:
        print(f"[{n['note_type']}] {n['note_text']} (Flagged: {n['is_flagged']})")
    
    # 3. Test bookmarks
    print('\nAdding bookmark...')
    add_bookmark(test_session, 'Primary Malicious Dropper', evidence_type='FILE', is_primary=True)
    bms = get_bookmarks(test_session)
    for b in bms:
        print(f"Bookmark: {b['bookmark_label']} ({b['evidence_type']})")
        
    # 4. Test combined view
    print('\nFull Session View:')
    view = get_full_session_view(test_session)
    print(f"Note Count: {view['note_count']}")
    print(f"Tag Count: {view['tag_count']}")
    print(f"Bookmark Count: {view['bookmark_count']}")
    print(f"Has Legal Notes: {view['has_legal_notes']}")
    
    print('\n=== TEST COMPLETE ===')
