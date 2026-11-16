import os
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
import config


def find_reports_for_session(session_id: str) -> List[Dict]:
    reports = []
    reports_dir = config.BASE_DIR / 'reports'
    
    search_dirs = [
        reports_dir / 'clean',
        reports_dir / 'suspicious',
        reports_dir / 'stego',
        reports_dir,
    ]

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for pdf in search_dir.glob('*.pdf'):
            name_lower = pdf.name.lower()
            if not name_lower.endswith(('report.pdf', '_report.pdf')) or name_lower.endswith(('summary.pdf', '_summary.pdf', 'summery.pdf', '_summery.pdf')):
                continue
            seal_path = pdf.with_suffix('.seal.json')
            
            if seal_path.exists():
                try:
                    with open(seal_path) as f:
                        seal = json.load(f)
                    
                    if seal.get('session_id') == session_id or session_id[:8] in pdf.name:
                        reports.append({
                            'filename': pdf.name,
                            'path': str(pdf),
                            'category': search_dir.name,
                            'verdict': seal.get('verdict', 'UNKNOWN'),
                            'generated_at': seal.get('generated_at', ''),
                            'size_kb': round(pdf.stat().st_size/1024, 1),
                            'report_type': seal.get('report_type', 'TECHNICAL'),
                            'hmac_valid': True,
                        })
                except Exception:
                    pass
            else:
                if session_id[:8] in pdf.name:
                    reports.append({
                        'filename': pdf.name,
                        'path': str(pdf),
                        'category': search_dir.name,
                        'verdict': 'UNKNOWN',
                        'generated_at': '',
                        'size_kb': round(pdf.stat().st_size/1024, 1),
                        'report_type': 'TECHNICAL',
                        'hmac_valid': False,
                    })

    for search_dir in search_dirs:
        if not search_dir.exists():
            continue
        for zip_file in search_dir.glob('*.zip'):
            if session_id[:8] in zip_file.name:
                reports.append({
                    'filename': zip_file.name,
                    'path': str(zip_file),
                    'category': search_dir.name,
                    'verdict': 'N/A',
                    'generated_at': '',
                    'size_kb': round(zip_file.stat().st_size/1024, 1),
                    'report_type': 'EVIDENCE_PACKAGE',
                    'hmac_valid': True,
                })

    reports.sort(
        key=lambda x: x.get('generated_at', ''),
        reverse=True
    )
    return reports


def get_all_sessions() -> List[Dict]:
    db_path = config.BASE_DIR / 'shadowtrace_recovery.db'
    if not db_path.exists():
        # Also try the name 'recovery.db' just in case
        db_path = config.BASE_DIR / 'recovery.db'
        if not db_path.exists():
            return []

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = [r[0] for r in cursor.fetchall()]

    sessions = {}
    
    if 'files' in tables:
        cursor.execute("PRAGMA table_info(files)")
        columns = [r[1] for r in cursor.fetchall()]
        
        cursor.execute("SELECT * FROM files ORDER BY id DESC")
        rows = cursor.fetchall()
        
        for row in rows:
            row_dict = dict(row)
            session_id = row_dict.get('session_id', 'unknown')
            
            if session_id not in sessions:
                sessions[session_id] = {
                    'session_id': session_id,
                    'files': [],
                    'first_seen': row_dict.get('created_at', ''),
                    'last_updated': row_dict.get('updated_at', ''),
                    'file_count': 0,
                    'threat_count': 0,
                    'clean_count': 0,
                    'suspicious_count': 0,
                    'verdicts': [],
                }
            
            file_record = {
                'filepath': row_dict.get('filepath', ''),
                'filename': Path(
                    row_dict.get('filepath', 'unknown')
                ).name,
                'status': row_dict.get('status', 'UNKNOWN'),
                'stage': row_dict.get('stage', ''),
                'created_at': row_dict.get('created_at', ''),
                'updated_at': row_dict.get('updated_at', ''),
            }
            
            sessions[session_id]['files'].append(file_record)
            sessions[session_id]['file_count'] += 1
    
    conn.close()

    for session_id, session_data in sessions.items():
        reports = find_reports_for_session(session_id)
        session_data['reports'] = reports
        session_data['report_count'] = len(reports)
        
        if any(r.get('verdict') == 'STEGO_DETECTED' for r in reports):
            session_data['session_verdict'] = 'THREAT'
        elif any(r.get('verdict') == 'SUSPICIOUS' for r in reports):
            session_data['session_verdict'] = 'SUSPICIOUS'
        elif reports:
            session_data['session_verdict'] = 'CLEAN'
        else:
            session_data['session_verdict'] = 'IN_PROGRESS'

    result = list(sessions.values())
    result.sort(
        key=lambda x: x.get('last_updated', ''),
        reverse=True
    )
    return result


def get_case_timeline(session_id: str) -> Dict:
    db_path = config.BASE_DIR / 'shadowtrace_recovery.db'
    if not db_path.exists():
        db_path = config.BASE_DIR / 'recovery.db'

    timeline_events = []
    session_files = []
    
    coc_db = config.BASE_DIR / 'shadowtrace_coc.db'
    if not coc_db.exists():
        coc_db = config.BASE_DIR / 'chain_of_custody.db'

    if coc_db.exists():
        try:
            conn = sqlite3.connect(str(coc_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            coc_tables = [r[0] for r in cursor.fetchall()]
            
            for table_name in coc_tables:
                try:
                    cursor.execute(
                        f"SELECT * FROM {table_name} WHERE session_id=? ORDER BY id ASC",
                        (session_id,)
                    )
                    events = cursor.fetchall()
                    for event in events:
                        ev = dict(event)
                        timeline_events.append({
                            'timestamp': ev.get('timestamp', ''),
                            'stage': ev.get('stage', ev.get('action', '')),
                            'result': ev.get('result', ev.get('status', '')),
                            'details': ev.get('details', ev.get('notes', '')),
                            'source': 'chain_of_custody',
                        })
                except Exception:
                    continue
            conn.close()
        except Exception:
            pass

    if db_path.exists():
        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM files WHERE session_id=?",
                (session_id,)
            )
            rows = cursor.fetchall()
            for row in rows:
                r = dict(row)
                session_files.append({
                    'filepath': r.get('filepath', ''),
                    'filename': Path(
                        r.get('filepath', 'unknown')
                    ).name,
                    'status': r.get('status', ''),
                    'stage': r.get('stage', ''),
                })
                
                if r.get('created_at'):
                    timeline_events.append({
                        'timestamp': r.get('created_at', ''),
                        'stage': 'FILE_REGISTERED',
                        'result': 'SUCCESS',
                        'details': Path(
                            r.get('filepath', '')
                        ).name,
                        'source': 'recovery_db',
                    })
            conn.close()
        except Exception:
            pass

    timeline_events.sort(
        key=lambda x: x.get('timestamp', ''),
    )

    reports = find_reports_for_session(session_id)

    return {
        'session_id': session_id,
        'timeline_events': timeline_events,
        'event_count': len(timeline_events),
        'session_files': session_files,
        'reports': reports,
        'report_count': len(reports),
    }


def get_dashboard_cases(limit: int = 20) -> Dict:
    all_sessions = get_all_sessions()
    
    total_sessions = len(all_sessions)
    threat_sessions = sum(
        1 for s in all_sessions
        if s.get('session_verdict') == 'THREAT'
    )
    suspicious_sessions = sum(
        1 for s in all_sessions
        if s.get('session_verdict') == 'SUSPICIOUS'
    )
    clean_sessions = sum(
        1 for s in all_sessions
        if s.get('session_verdict') == 'CLEAN'
    )
    unresolved = sum(
        1 for s in all_sessions
        if s.get('session_verdict') == 'IN_PROGRESS'
    )

    high_priority = [
        s for s in all_sessions
        if s.get('session_verdict') in ['THREAT', 'SUSPICIOUS']
    ][:5]

    return {
        'total_sessions': total_sessions,
        'threat_sessions': threat_sessions,
        'suspicious_sessions': suspicious_sessions,
        'clean_sessions': clean_sessions,
        'unresolved_sessions': unresolved,
        'recent_sessions': all_sessions[:limit],
        'high_priority': high_priority,
        'generated_at': datetime.now().isoformat(),
    }


if __name__ == '__main__':
    print('=== CASE MANAGER TEST ===')
    print()

    print('Loading all sessions...')
    sessions = get_all_sessions()
    print('Total sessions found: ' + str(len(sessions)))
    print()

    if sessions:
        s = sessions[0]
        print('Most recent session:')
        print('  Session ID: ' + str(s.get('session_id','')))
        print('  Files: ' + str(s.get('file_count', 0)))
        print('  Reports: ' + str(s.get('report_count', 0)))
        print('  Verdict: ' + str(s.get('session_verdict', '')))
        print()
        
        print('Getting timeline for session...')
        timeline = get_case_timeline(
            s.get('session_id', '')
        )
        print('  Timeline events: '
              + str(timeline['event_count']))
        print('  Reports in session: '
              + str(timeline['report_count']))
        for r in timeline['reports'][:3]:
            print('    - ' + r['filename']
                  + ' [' + r['report_type'] + ']')
        print()

    print('Getting dashboard cases data...')
    dashboard = get_dashboard_cases()
    print('Dashboard stats:')
    print('  Total sessions: '
          + str(dashboard['total_sessions']))
    print('  Threat sessions: '
          + str(dashboard['threat_sessions']))
    print('  Suspicious: '
          + str(dashboard['suspicious_sessions']))
    print('  Clean: '
          + str(dashboard['clean_sessions']))
    print('  Unresolved: '
          + str(dashboard['unresolved_sessions']))
    print('  High priority: '
          + str(len(dashboard['high_priority'])))
    print()
    print('=== TEST COMPLETE ===')
