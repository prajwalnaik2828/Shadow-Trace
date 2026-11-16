import os
import json
import sqlite3
import socket
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional
import config


def get_url_for_session(session_id: str) -> Dict:
    coc_db = config.BASE_DIR / 'shadowtrace_coc.db'
    if not coc_db.exists():
        coc_db = config.BASE_DIR / 'chain_of_custody.db'
        
    if coc_db.exists():
        try:
            conn = sqlite3.connect(str(coc_db))
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = [r[0] for r in cursor.fetchall()]
            
            url_found = None
            for table in tables:
                try:
                    cursor.execute(
                        f"PRAGMA table_info({table})"
                    )
                    cols = [r[1] for r in cursor.fetchall()]
                    
                    if 'url' in cols or 'source_url' in cols:
                        url_col = 'url' if 'url' in cols else 'source_url'
                        cursor.execute(
                            f"SELECT {url_col} FROM {table} WHERE session_id=? LIMIT 1",
                            (session_id,)
                        )
                        row = cursor.fetchone()
                        if row and row[0] and row[0] not in ['', 'URL not captured', 'None']:
                            url_found = row[0]
                            break
                except Exception:
                    continue
            
            conn.close()
            
            if url_found:
                return analyse_url(url_found)
        except Exception:
            pass

    url_log = config.BASE_DIR / 'logs' / 'url_captures.json'
    if url_log.exists():
        try:
            with open(url_log) as f:
                entries = json.load(f)
            for entry in entries:
                if entry.get('session_id') == session_id:
                    return analyse_url(
                        entry.get('url', '')
                    )
        except Exception:
            pass

    return {
        'url': None,
        'captured': False,
        'domain': None,
        'protocol': None,
        'is_https': None,
        'risk_indicators': [],
        'note': (
            'Source URL was not captured. '
            'The browser extension may not be '
            'installed or was not active when '
            'this file was downloaded.'
        ),
    }


def analyse_url(url: str) -> Dict:
    if not url or url in ['', 'URL not captured', 'None']:
        return {
            'url': None,
            'captured': False,
            'domain': None,
            'protocol': None,
            'is_https': None,
            'risk_indicators': [],
            'note': (
                'Source URL was not captured. '
                'The browser extension may not be '
                'installed or was not active when '
                'this file was downloaded.'
            ),
        }

    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc
        protocol = parsed.scheme
        path = parsed.path
        query = parsed.query
    except Exception:
        domain = ''
        protocol = ''
        path = url
        query = ''

    risk_indicators = []
    
    import re
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):
        risk_indicators.append({
            'indicator': 'IP_ADDRESS_URL',
            'detail': (
                'File was downloaded from an IP address '
                'rather than a named domain. Legitimate '
                'services typically use domain names. '
                'This may indicate a temporary or '
                'suspicious server.'
            ),
            'severity': 'MEDIUM',
        })
    
    if ':' in domain:
        port = domain.split(':')[-1]
        if port not in ['80', '443', '8080', '8443']:
            risk_indicators.append({
                'indicator': 'NON_STANDARD_PORT',
                'detail': f'Non-standard port {port} used.',
                'severity': 'LOW',
            })
    
    if protocol == 'http':
        risk_indicators.append({
            'indicator': 'UNENCRYPTED_DOWNLOAD',
            'detail': (
                'File was downloaded over HTTP '
                '(unencrypted). The file content '
                'could have been modified in transit '
                'without detection.'
            ),
            'severity': 'LOW',
        })
    
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf',
                       '.gq', '.xyz', '.top', '.club',
                       '.work', '.download']
    for tld in suspicious_tlds:
        if domain.lower().endswith(tld):
            risk_indicators.append({
                'indicator': 'SUSPICIOUS_TLD',
                'detail': f'Domain uses TLD {tld} which is commonly associated with free hosting and phishing.',
                'severity': 'MEDIUM',
            })
    
    if len(url) > 200:
        risk_indicators.append({
            'indicator': 'LONG_URL',
            'detail': 'Unusually long URL may indicate obfuscation.',
            'severity': 'LOW',
        })
    
    if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', query):
        risk_indicators.append({
            'indicator': 'ENCODED_PARAMETERS',
            'detail': 'URL contains what appears to be base64 encoded parameters.',
            'severity': 'LOW',
        })

    return {
        'url': url,
        'captured': True,
        'domain': domain,
        'protocol': protocol.upper() if protocol else '',
        'path': path,
        'is_https': protocol == 'https',
        'risk_indicators': risk_indicators,
        'risk_count': len(risk_indicators),
        'url_length': len(url),
    }


def get_file_metadata(filepath: str) -> Dict:
    p = Path(filepath)
    if not p.exists():
        return {
            'error': 'File not found',
            'filepath': filepath,
        }

    stat = p.stat()
    
    created = datetime.fromtimestamp(
        stat.st_ctime
    ).isoformat()
    modified = datetime.fromtimestamp(
        stat.st_mtime
    ).isoformat()
    accessed = datetime.fromtimestamp(
        stat.st_atime
    ).isoformat()

    born_timestamp = None
    born_source = 'unavailable'
    try:
        import subprocess
        escaped = str(filepath).replace("'", "''")
        ps_cmd = (
            '(Get-Item -LiteralPath \''
            + escaped
            + '\').CreationTimeUtc.ToString("o")'
        )
        ps_result = subprocess.run(
            ['powershell', '-NoProfile',
             '-NonInteractive',
             '-Command', ps_cmd],
            capture_output=True,
            text=True,
            timeout=5
        )
        if (ps_result.returncode == 0
                and ps_result.stdout.strip()):
            born_timestamp = ps_result.stdout.strip()
            born_source = 'powershell_mft'
    except Exception:
        pass

    anomalies = []
    
    ctime = datetime.fromtimestamp(stat.st_ctime)
    mtime = datetime.fromtimestamp(stat.st_mtime)
    
    if mtime < ctime:
        anomalies.append({
            'anomaly': 'MODIFIED_BEFORE_CREATED',
            'detail': (
                'File modification timestamp is earlier '
                'than creation timestamp. This may indicate '
                'that timestamps have been manipulated or '
                'that the file was copied from another location.'
            ),
            'severity': 'MEDIUM',
        })
    
    for ts_name, ts_val in [('created', ctime), ('modified', mtime)]:
        if ts_val.second == 0 and ts_val.microsecond == 0:
            anomalies.append({
                'anomaly': 'ROUND_TIMESTAMP_' + ts_name.upper(),
                'detail': f'The {ts_name} timestamp is an exact round number (zero seconds). Natural file system timestamps rarely have exactly zero seconds.',
                'severity': 'LOW',
            })

    extension = p.suffix.lower()
    
    name_no_ext = p.stem
    EXECUTABLE_DOUBLE_EXT = {
        '.exe', '.dll', '.bat', '.cmd', '.ps1',
        '.vbs', '.js', '.jar', '.com', '.scr',
        '.pif', '.msi', '.reg', '.sh', '.elf',
    }
    inner_ext = Path(name_no_ext).suffix.lower()
    if inner_ext and inner_ext in EXECUTABLE_DOUBLE_EXT:
        anomalies.append({
            'anomaly': 'EXECUTABLE_DOUBLE_EXTENSION',
            'detail': (
                f'Filename "{p.name}" disguises an '
                f'executable file ({inner_ext}) as a '
                f'{extension} file. This is a very '
                f'common malware delivery technique '
                f'(e.g. invoice.pdf.exe).'
            ),
            'severity': 'HIGH',
        })

    return {
        'filepath': str(filepath),
        'filename': p.name,
        'size_bytes': stat.st_size,
        'size_kb': round(stat.st_size / 1024, 2),
        'extension': extension,
        'created_at': created,
        'modified_at': modified,
        'accessed_at': datetime.fromtimestamp(
            stat.st_atime
        ).isoformat(),
        'born_at': born_timestamp,
        'born_source': born_source,
        'macb_timestamps': {
            'M_modified':  modified,
            'A_accessed':  datetime.fromtimestamp(
                stat.st_atime
            ).isoformat(),
            'C_changed':   created,
            'B_born':      born_timestamp or 'Not available',
        },
        'macb_note': (
            'MACB timestamps represent four independent '
            'time references for this file. '
            'M=Modified (last content change), '
            'A=Accessed (last opened), '
            'C=Changed (metadata change including rename), '
            'B=Born (original creation, most reliable — '
            'cannot be changed by normal file operations). '
            'Timestamp inconsistencies may indicate '
            'deliberate manipulation.'
        ),
        'timestamp_anomalies': anomalies,
        'anomaly_count': len(anomalies),
    }


def get_neighboring_files(
    filepath: str,
    time_window_minutes: int = 5,
) -> Dict:
    p = Path(filepath)
    if not p.exists() and not p.parent.exists():
        return {
            'neighboring_files': [],
            'note': 'File or directory not found',
        }
    
    target_mtime = p.stat().st_mtime if p.exists() else 0
    target_dt = datetime.fromtimestamp(target_mtime)

    neighbors = []
    parent_dir = p.parent
    
    for sibling in parent_dir.iterdir():
        if sibling == p:
            continue
        if not sibling.is_file():
            continue
        
        try:
            sibling_mtime = sibling.stat().st_mtime
            sibling_dt = datetime.fromtimestamp(sibling_mtime)
            
            time_diff = abs(
                (sibling_dt - target_dt).total_seconds()
            )
            
            if time_diff <= time_window_minutes * 60:
                neighbors.append({
                    'filename': sibling.name,
                    'path': str(sibling),
                    'modified_at': sibling_dt.isoformat(),
                    'size_kb': round(
                        sibling.stat().st_size / 1024, 2
                    ),
                    'time_diff_seconds': round(time_diff, 1),
                    'extension': sibling.suffix.lower(),
                })
        except Exception:
            continue

    neighbors.sort(
        key=lambda x: x['time_diff_seconds']
    )

    return {
        'target_file': p.name,
        'time_window_minutes': time_window_minutes,
        'neighboring_files': neighbors[:20],
        'neighbor_count': len(neighbors),
        'note': (
            f'Files that arrived within {time_window_minutes} '
            f'minutes of the target file. These may be '
            f'related artifacts from the same download session.'
        ),
    }


def read_zone_identifier(filepath: str) -> Dict:
    try:
        zone_path = str(filepath) + ':Zone.Identifier'
        
        try:
            with open(zone_path, 'r',
                      encoding='utf-8',
                      errors='ignore') as f:
                content = f.read()
        except FileNotFoundError:
            return {
                'found': False,
                'zone_id': None,
                'host_url': None,
                'referrer_url': None,
                'from_internet': False,
                'note': (
                    'No Zone.Identifier stream found. '
                    'File may be local or from a '
                    'network share.'
                ),
            }
        
        zone_id = None
        host_url = None
        referrer_url = None
        
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('ZoneId='):
                try:
                    zone_id = int(
                        line.split('=', 1)[1]
                    )
                except ValueError:
                    pass
            elif line.lower().startswith('hosturl='):
                host_url = line.split('=', 1)[1].strip()
            elif line.lower().startswith('referrerurl='):
                referrer_url = (
                    line.split('=', 1)[1].strip()
                )
        
        zone_names = {
            0: 'Local Computer',
            1: 'Local Intranet',
            2: 'Trusted Sites',
            3: 'Internet',
            4: 'Restricted Sites',
        }
        zone_name = zone_names.get(
            zone_id, 'Unknown Zone'
        )
        from_internet = zone_id == 3
        
        return {
            'found': True,
            'zone_id': zone_id,
            'zone_name': zone_name,
            'from_internet': from_internet,
            'host_url': host_url,
            'referrer_url': referrer_url,
            'raw_content': content.strip(),
            'note': (
                'Zone.Identifier is automatically written '
                'by Windows for all internet downloads. '
                'This data is written by the operating '
                'system itself and is independent of any '
                'browser or application. It is considered '
                'highly reliable forensic evidence.'
                if from_internet else
                'File does not appear to be an internet '
                'download based on Zone.Identifier data.'
            ),
        }

    except Exception as e:
        return {
            'found': False,
            'error': str(e),
            'note': 'Zone.Identifier could not be read.',
        }

def _extract_domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower()
    except Exception:
        return ''

def build_source_correlation(
    filepath: str,
    session_id: str,
) -> Dict:
    print('[CORRELATION] Building source correlation...')
    print('[CORRELATION] File: ' + Path(filepath).name)

    zone_data = read_zone_identifier(str(filepath))

    if (zone_data.get('found')
            and zone_data.get('host_url')):
        url_data = {
            'url': zone_data['host_url'],
            'captured': True,
            'domain': _extract_domain(
                zone_data['host_url']
            ),
            'protocol': (
                zone_data['host_url'].split('://')[0].upper()
                if '://' in zone_data['host_url']
                else 'UNKNOWN'
            ),
            'is_https': zone_data[
                'host_url'
            ].startswith('https'),
            'risk_indicators': [],
            'confidence': 'VERY_HIGH',
            'source': 'zone_identifier',
            'note': (
                'URL obtained from Windows '
                'Zone.Identifier NTFS alternate data '
                'stream. Written automatically by Windows '
                'for all internet downloads. Independent '
                'of browser or application used.'
            ),
        }
        print('[CORRELATION] Zone.Identifier URL: '
              + zone_data['host_url'][:70])
    else:
        url_data = get_url_for_session(session_id)

    file_meta = get_file_metadata(filepath)
    neighbors = get_neighboring_files(filepath)

    correlation_flags = []
    
    if url_data.get('captured'):
        for risk in url_data.get('risk_indicators', []):
            correlation_flags.append({
                'source': 'URL_ANALYSIS',
                'flag': risk['indicator'],
                'detail': risk['detail'],
                'severity': risk['severity'],
            })
    else:
        correlation_flags.append({
            'source': 'URL_ANALYSIS',
            'flag': 'URL_NOT_CAPTURED',
            'detail': 'Source URL could not be determined.',
            'severity': 'INFO',
        })
    
    for anomaly in file_meta.get('timestamp_anomalies', []):
        correlation_flags.append({
            'source': 'FILE_METADATA',
            'flag': anomaly['anomaly'],
            'detail': anomaly['detail'],
            'severity': anomaly['severity'],
        })
    
    if neighbors.get('neighbor_count', 0) > 10:
        correlation_flags.append({
            'source': 'NEIGHBOR_ANALYSIS',
            'flag': 'MANY_SIMULTANEOUS_FILES',
            'detail': (
                f'{neighbors["neighbor_count"]} files arrived '
                f'within {neighbors["time_window_minutes"]} '
                f'minutes of this file. This may indicate '
                f'a bulk download or automated delivery.'
            ),
            'severity': 'LOW',
        })

    high_flags = sum(
        1 for f in correlation_flags
        if f['severity'] == 'HIGH'
    )
    medium_flags = sum(
        1 for f in correlation_flags
        if f['severity'] == 'MEDIUM'
    )
    
    if high_flags > 0:
        correlation_risk = 'HIGH'
    elif medium_flags > 1:
        correlation_risk = 'MEDIUM'
    elif medium_flags == 1:
        correlation_risk = 'LOW'
    else:
        correlation_risk = 'NONE'

    return {
        'session_id': session_id,
        'filepath': str(filepath),
        'filename': Path(filepath).name,
        'url_analysis': url_data,
        'zone_identifier': zone_data,
        'file_metadata': file_meta,
        'neighboring_files': neighbors,
        'correlation_flags': correlation_flags,
        'correlation_risk': correlation_risk,
        'high_risk_flags': high_flags,
        'medium_risk_flags': medium_flags,
        'total_flags': len(correlation_flags),
        'generated_at': datetime.now(
            timezone.utc
        ).isoformat(),
    }


if __name__ == '__main__':
    print('=== SOURCE CORRELATION TEST ===')
    print()

    import sys
    from pathlib import Path

    test_files = [
        Path.home() / 'Downloads',
    ]

    test_filepath = None
    for d in test_files:
        if d.exists():
            files = list(d.glob('*.*'))
            if files:
                test_filepath = str(files[0])
                break

    if not test_filepath:
        test_filepath = str(
            config.BASE_DIR / 'config.py'
        )

    print('Testing with file: ' + Path(test_filepath).name)
    print()

    print('URL analysis (no session URL expected):')
    url_result = get_url_for_session('test_session_123')
    print('  Captured: ' + str(url_result.get('captured')))
    print('  Note: ' + url_result.get('note', '')[:80])
    print()

    print('File metadata analysis:')
    meta = get_file_metadata(test_filepath)
    print('  Filename: ' + meta.get('filename', ''))
    print('  Size: ' + str(meta.get('size_kb', 0)) + ' KB')
    print('  Created: ' + str(meta.get('created_at', ''))[:19])
    print('  Modified: ' + str(meta.get('modified_at', ''))[:19])
    print('  Anomalies: ' + str(meta.get('anomaly_count', 0)))
    if meta.get('timestamp_anomalies'):
        for a in meta['timestamp_anomalies']:
            print('    [' + a['severity'] + '] ' + a['anomaly'])
    print()

    print('Neighboring files analysis:')
    neighbors = get_neighboring_files(test_filepath, 60)
    print('  Files in same folder within 60 min: '
          + str(neighbors.get('neighbor_count', 0)))
    if neighbors.get('neighboring_files'):
        for n in neighbors['neighboring_files'][:3]:
            print('    ' + n['filename']
                  + ' (' + str(n['time_diff_seconds'])
                  + 's apart)')
    print()

    print('Full correlation build:')
    correlation = build_source_correlation(
        test_filepath, 'test_session_123'
    )
    print('  Correlation risk: '
          + correlation.get('correlation_risk', 'NONE'))
    print('  Total flags: '
          + str(correlation.get('total_flags', 0)))
    print('  High flags: '
          + str(correlation.get('high_risk_flags', 0)))
    print('  Medium flags: '
          + str(correlation.get('medium_risk_flags', 0)))
    if correlation.get('correlation_flags'):
        for flag in correlation['correlation_flags'][:3]:
            print('  [' + flag['severity'] + '] '
                  + flag['flag'])
    print()
    print('=== TEST COMPLETE ===')
