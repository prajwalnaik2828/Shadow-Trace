"""
network_monitor.py — Shadow-Trace Network Activity Monitor
===========================================================
Provides universal URL and domain capture across ALL browsers
and ALL applications on Windows without a browser extension.

Three complementary methods:
  Method 1 — Windows DNS Event Log      (all apps, high accuracy)
  Method 2 — Active TCP connection scan  (all apps, medium accuracy)
  Method 3 — Chrome extension log        (extension users, highest accuracy)

All three run independently and their results are merged by the
correlation engine. The best available source wins per file.
"""

import os
import re
import json
import time
import socket
import sqlite3
import threading
import subprocess
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import config

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DNS_CACHE_SECONDS = 120
CORRELATION_WINDOW_SECONDS = 30
DB_PATH = config.BASE_DIR / 'logs' / 'network_events.db'


# ===========================================================================
# SECTION 1: NETWORK EVENT DATABASE
# ===========================================================================

def init_network_db():
    """Create SQLite database and tables for network events."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            resolved_ip TEXT,
            query_time TEXT NOT NULL,
            process_name TEXT,
            pid INTEGER,
            source TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tcp_connections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remote_ip TEXT NOT NULL,
            remote_port INTEGER,
            local_port INTEGER,
            process_name TEXT,
            pid INTEGER,
            observed_time TEXT NOT NULL,
            resolved_domain TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS file_url_map (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT,
            detected_domain TEXT,
            detected_url TEXT,
            confidence TEXT,
            method TEXT,
            session_id TEXT,
            mapped_at TEXT NOT NULL
        )
    ''')

    # Indexes for fast time-based queries
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_dns_time '
        'ON dns_queries(query_time)'
    )
    cursor.execute(
        'CREATE INDEX IF NOT EXISTS idx_tcp_time '
        'ON tcp_connections(observed_time)'
    )

    conn.commit()
    conn.close()


# ===========================================================================
# SECTION 2: METHOD 1 — WINDOWS DNS EVENT LOG
# ===========================================================================

def read_dns_from_event_log(minutes_back: int = 5) -> List[Dict]:
    """
    Read DNS query events from the Windows DNS-Client/Operational event log.
    Works for ALL applications on the system with no browser extension needed.

    Requires: DNS Client Operational log to be enabled (one-time admin step).
    """
    ps_command = (
        'Get-WinEvent -LogName "Microsoft-Windows-'
        'DNS-Client/Operational" -MaxEvents 500 '
        '-ErrorAction SilentlyContinue | '
        'Where-Object { $_.TimeCreated -gt '
        '(Get-Date).AddMinutes(-' + str(minutes_back) + ') } | '
        'Select-Object TimeCreated, Message | '
        'ConvertTo-Json -Compress'
    )

    try:
        result = subprocess.run(
            ['powershell', '-NoProfile',
             '-NonInteractive', '-Command', ps_command],
            capture_output=True, text=True, timeout=10
        )
    except Exception:
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        events_raw = json.loads(result.stdout)
        if not isinstance(events_raw, list):
            events_raw = [events_raw]
    except Exception:
        return []

    domain_pattern = re.compile(
        r'(?:queried|resolved|query).*?'
        r'((?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}'
        r'[a-zA-Z0-9])?\.)+[a-zA-Z]{2,})',
        re.IGNORECASE
    )
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    dns_events = []
    for event in events_raw:
        message = event.get('Message', '') or ''
        time_str = str(event.get('TimeCreated', ''))

        domains = domain_pattern.findall(message)
        ips = ip_pattern.findall(message)

        for domain in domains:
            if is_valid_domain(domain):
                dns_events.append({
                    'domain': domain.lower(),
                    'resolved_ip': ips[0] if ips else None,
                    'query_time': time_str,
                    'source': 'windows_event_log',
                })

    return dns_events


def is_valid_domain(domain: str) -> bool:
    """
    Filter out noise domains from DNS logs — Windows telemetry,
    Google/Microsoft advertising, local domains, raw IPs, etc.
    """
    SKIP_DOMAINS = {
        'localhost', 'local', 'internal',
        'microsoftedge.com', 'windowsupdate.com',
        'microsoft.com', 'msftconnecttest.com',
        'msftncsi.com', 'office.com', 'live.com',
        'hotmail.com', 'outlook.com', 'bing.com',
        'msn.com', 'windows.com', 'azure.com',
        'google.com', 'googleapis.com',
        'gstatic.com', 'googlevideo.com',
        'doubleclick.net', 'googleadservices.com',
        'googletagmanager.com',
    }

    if len(domain) < 4:
        return False

    for skip in SKIP_DOMAINS:
        if domain.endswith(skip):
            return False

    if domain.endswith('.local') or domain.endswith('.internal'):
        return False

    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False

    return True


# ===========================================================================
# SECTION 3: METHOD 2 — TCP CONNECTION MONITORING
# ===========================================================================

def get_active_connections() -> List[Dict]:
    """
    Get current active TCP connections using netstat.
    Works for ALL applications on Windows without elevation.
    Only returns HTTP/HTTPS connections (ports 80, 443, 8080, 8443).
    """
    try:
        result = subprocess.run(
            ['netstat', '-n', '-o'],
            capture_output=True, text=True, timeout=5
        )
    except Exception:
        return []

    if result.returncode != 0:
        return []

    connections = []
    lines = result.stdout.strip().split('\n')

    for line in lines:
        line = line.strip()
        if not line or line.startswith('Active') or line.startswith('Proto'):
            continue

        parts = line.split()
        if len(parts) < 4:
            continue

        proto = parts[0] if len(parts) > 0 else ''
        local = parts[1] if len(parts) > 1 else ''
        remote = parts[2] if len(parts) > 2 else ''
        state = parts[3] if len(parts) > 3 else ''
        pid = 0
        try:
            pid = int(parts[4]) if len(parts) > 4 else 0
        except ValueError:
            pass

        if state not in ['ESTABLISHED', 'TIME_WAIT', 'CLOSE_WAIT']:
            continue

        # Handle IPv6 bracket notation
        if remote.startswith('['):
            bracket_end = remote.find(']')
            if bracket_end == -1:
                continue
            remote_ip = remote[1:bracket_end]
            remote_port_str = remote[bracket_end + 2:]
        else:
            parts_remote = remote.rsplit(':', 1)
            remote_ip = parts_remote[0] if len(parts_remote) > 0 else ''
            remote_port_str = parts_remote[1] if len(parts_remote) > 1 else ''

        try:
            remote_port = int(remote_port_str)
        except ValueError:
            continue

        if remote_ip in ['127.0.0.1', '::1', '0.0.0.0']:
            continue

        if remote_port in [80, 443, 8080, 8443]:
            process_name = get_process_name(pid)
            connections.append({
                'remote_ip': remote_ip,
                'remote_port': remote_port,
                'pid': pid,
                'process_name': process_name,
                'state': state,
                'observed_time': datetime.now(timezone.utc).isoformat(),
            })

    return connections


def get_process_name(pid: int) -> str:
    """Resolve a PID to its process name using tasklist."""
    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'PID eq ' + str(pid),
             '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, timeout=3
        )
        if result.stdout:
            parts = result.stdout.strip().split(',')
            if parts:
                return parts[0].strip('"')
    except Exception:
        pass
    return 'unknown'


def reverse_lookup_ip(ip: str) -> Optional[str]:
    """Attempt a reverse DNS lookup for an IP address."""
    try:
        hostname = socket.gethostbyaddr(ip)
        return hostname[0] if hostname else None
    except Exception:
        return None


# ===========================================================================
# SECTION 4: METHOD 3 — CHROME EXTENSION DATA
# ===========================================================================

def get_url_from_extension_log(
    filename: str,
    time_window_seconds: int = 300,
) -> Optional[str]:
    """
    Check the url_captures.json log written by the Shadow-Trace Chrome/Edge
    extension for a download entry matching the given filename.

    Compatible with: Chrome, Edge, Brave, Opera, Vivaldi.
    """
    url_log = config.BASE_DIR / 'logs' / 'url_captures.json'
    if not url_log.exists():
        return None

    try:
        with open(url_log, 'r', encoding='utf-8') as f:
            entries = json.load(f)

        now = datetime.now(timezone.utc)

        for entry in entries:
            entry_filename = entry.get('filename', '')
            entry_time_str = entry.get(
                'received_at', entry.get('timestamp', '')
            )

            if entry_filename.lower() == filename.lower():
                try:
                    entry_time = datetime.fromisoformat(
                        entry_time_str.replace('Z', '+00:00')
                    )
                    age = abs((now - entry_time).total_seconds())
                    if age <= time_window_seconds:
                        return entry.get('url')
                except Exception:
                    # Can't parse timestamp — return the URL anyway
                    return entry.get('url')

        return None
    except Exception:
        return None


# ===========================================================================
# SECTION 5: CORRELATION ENGINE
# ===========================================================================

def correlate_file_to_url(
    filepath: str,
    session_id: str = None,
    correlation_window: int = CORRELATION_WINDOW_SECONDS,
) -> Dict:
    """
    Main correlation function. Uses all three methods to identify
    where a file was downloaded from. Returns the best available
    URL with a confidence level (HIGH / MEDIUM / LOW / NONE).
    """
    filename = Path(filepath).name
    print('[NET-MONITOR] Correlating: ' + filename)

    try:
        file_ctime = os.path.getctime(filepath)
        file_dt = datetime.fromtimestamp(file_ctime, tz=timezone.utc)
    except Exception:
        file_dt = datetime.now(timezone.utc)

    result = {
        'filename': filename,
        'filepath': str(filepath),
        'session_id': session_id,
        'detected_url': None,
        'detected_domain': None,
        'has_correlation': False,
        'confidence': 'NONE',
        'method': 'none',
        'all_candidates': [],
        'risk_indicators': [],
        'flags': [],
        'correlated_at': datetime.now(timezone.utc).isoformat(),
    }

    # ------------------------------------------------------------------
    # METHOD 3 FIRST — Chrome extension (highest confidence)
    # ------------------------------------------------------------------
    ext_url = get_url_from_extension_log(filename, correlation_window * 10)
    if ext_url:
        result['detected_url'] = ext_url
        result['detected_domain'] = extract_domain(ext_url)
        result['has_correlation'] = True
        result['confidence'] = 'HIGH'
        result['method'] = 'chrome_extension'
        result['all_candidates'].append({
            'url': ext_url,
            'method': 'chrome_extension',
            'confidence': 'HIGH',
        })
        print('[NET-MONITOR] URL from extension: ' + ext_url[:60])

    # ------------------------------------------------------------------
    # METHOD 1 — DNS event log
    # ------------------------------------------------------------------
    dns_events = read_dns_from_event_log(
        minutes_back=max(5, correlation_window // 60 + 2)
    )

    relevant_dns = []
    for event in dns_events:
        try:
            event_time = datetime.fromisoformat(
                str(event['query_time']).replace('Z', '+00:00')
            )
            diff = abs((file_dt - event_time).total_seconds())
            if diff <= correlation_window:
                relevant_dns.append({
                    'domain': event['domain'],
                    'time_diff_seconds': round(diff, 1),
                    'source': event['source'],
                })
        except Exception:
            pass

    relevant_dns.sort(key=lambda x: x['time_diff_seconds'])

    if relevant_dns and not result['detected_url']:
        best_dns = relevant_dns[0]
        result['detected_domain'] = best_dns['domain']
        result['detected_url'] = (
            'https://' + best_dns['domain'] + '/' + filename
        )
        result['has_correlation'] = True
        result['confidence'] = 'MEDIUM'
        result['method'] = 'dns_correlation'
        print('[NET-MONITOR] Domain from DNS: ' + best_dns['domain'])

    for d in relevant_dns[:5]:
        result['all_candidates'].append({
            'domain': d['domain'],
            'method': 'dns_event_log',
            'time_diff_seconds': d['time_diff_seconds'],
            'confidence': 'MEDIUM',
        })

    # ------------------------------------------------------------------
    # METHOD 2 — TCP connections (fallback)
    # ------------------------------------------------------------------
    if not result['detected_url']:
        connections = get_active_connections()

        BROWSER_PROCESSES = {
            'chrome.exe', 'msedge.exe', 'brave.exe',
            'firefox.exe', 'opera.exe', 'vivaldi.exe',
            'iexplore.exe', 'browser.exe', 'duckduckgo.exe',
        }

        browser_connections = [
            c for c in connections
            if c.get('process_name', '').lower() in BROWSER_PROCESSES
        ]

        for conn in browser_connections[:10]:
            domain = reverse_lookup_ip(conn['remote_ip'])
            if domain and is_valid_domain(domain):
                result['all_candidates'].append({
                    'domain': domain,
                    'ip': conn['remote_ip'],
                    'method': 'tcp_reverse_lookup',
                    'browser': conn['process_name'],
                    'confidence': 'LOW',
                })
                if not result['detected_url']:
                    result['detected_domain'] = domain
                    result['detected_url'] = (
                        'https://' + domain + '/' + filename
                    )
                    result['has_correlation'] = True
                    result['confidence'] = 'LOW'
                    result['method'] = 'tcp_correlation'
                break

    # ------------------------------------------------------------------
    # Risk analysis on detected domain
    # ------------------------------------------------------------------
    if result['detected_domain']:
        risks = analyse_domain_risk(
            result['detected_domain'],
            result.get('detected_url', '')
        )
        result['risk_indicators'] = risks
        # Expose as simple flags list for report rendering
        result['flags'] = [r['indicator'] for r in risks]

    # ------------------------------------------------------------------
    # Persist to database
    # ------------------------------------------------------------------
    try:
        save_correlation(result)
    except Exception:
        pass

    return result


def extract_domain(url: str) -> str:
    """Extract the domain (netloc) from a full URL string."""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return url


def analyse_domain_risk(domain: str, url: str = '') -> List[Dict]:
    """
    Score a domain against a set of forensic risk indicators.
    Returns a list of risk dicts with indicator, detail, severity.
    """
    risks = []

    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',
        '.xyz', '.top', '.club', '.work',
        '.download', '.zip', '.mov',
        '.icu', '.cyou', '.buzz',
    }

    for tld in SUSPICIOUS_TLDS:
        if domain.lower().endswith(tld):
            risks.append({
                'indicator': 'SUSPICIOUS_TLD',
                'detail': (
                    f'Domain uses TLD {tld} which is commonly associated '
                    f'with free hosting, phishing, and malware distribution.'
                ),
                'severity': 'MEDIUM',
            })

    if url.startswith('http://'):
        risks.append({
            'indicator': 'UNENCRYPTED_TRANSFER',
            'detail': (
                'File was transferred over HTTP without encryption. '
                'The file content could have been intercepted or '
                'modified in transit.'
            ),
            'severity': 'LOW',
        })

    if re.match(r'^\d+\.\d+\.\d+\.\d+', domain):
        risks.append({
            'indicator': 'IP_ADDRESS_HOST',
            'detail': (
                'File was downloaded directly from an IP address rather '
                'than a named domain. Legitimate services use domain names.'
            ),
            'severity': 'MEDIUM',
        })

    port_match = re.search(r':(\d+)(?:/|$)', url)
    if port_match:
        port = int(port_match.group(1))
        if port not in [80, 443, 8080, 8443]:
            risks.append({
                'indicator': 'NON_STANDARD_PORT',
                'detail': (
                    f'File served from non-standard port {port}. '
                    f'This is unusual for legitimate file hosting.'
                ),
                'severity': 'LOW',
            })

    parts = domain.split('.')
    if len(parts) > 4:
        risks.append({
            'indicator': 'DEEP_SUBDOMAIN',
            'detail': (
                f'Domain has {len(parts)} levels of subdomains which '
                f'is unusual for legitimate file hosting.'
            ),
            'severity': 'LOW',
        })

    return risks


def save_correlation(result: Dict):
    """Persist a file-URL correlation result to the network events DB."""
    init_network_db()
    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO file_url_map
        (filename, filepath, detected_domain,
         detected_url, confidence, method,
         session_id, mapped_at)
        VALUES (?,?,?,?,?,?,?,?)
    ''', (
        result.get('filename'),
        result.get('filepath'),
        result.get('detected_domain'),
        result.get('detected_url'),
        result.get('confidence'),
        result.get('method'),
        result.get('session_id'),
        result.get('correlated_at'),
    ))
    conn.commit()
    conn.close()


# ===========================================================================
# SECTION 6: BACKGROUND DNS MONITOR
# ===========================================================================

_dns_monitor_running = False
_dns_monitor_thread = None


def start_dns_monitor():
    """
    Start a background thread that reads DNS events from the Windows Event
    Log every 30 seconds and persists them to network_events.db.

    This ensures DNS entries are captured before they roll out of the
    short Windows in-memory event buffer.
    """
    global _dns_monitor_running, _dns_monitor_thread

    def monitor_loop():
        init_network_db()
        print('[NET-MONITOR] DNS monitor started')

        while _dns_monitor_running:
            try:
                events = read_dns_from_event_log(minutes_back=1)

                if events:
                    conn = sqlite3.connect(str(DB_PATH))
                    cursor = conn.cursor()

                    for event in events:
                        try:
                            cursor.execute('''
                                INSERT OR IGNORE INTO dns_queries
                                (domain, resolved_ip, query_time, source)
                                VALUES (?,?,?,?)
                            ''', (
                                event.get('domain'),
                                event.get('resolved_ip'),
                                event.get('query_time'),
                                event.get('source'),
                            ))
                        except Exception:
                            pass

                    conn.commit()
                    conn.close()

            except Exception:
                pass

            time.sleep(30)

        print('[NET-MONITOR] DNS monitor stopped')

    _dns_monitor_running = True
    _dns_monitor_thread = threading.Thread(
        target=monitor_loop,
        name='DNSMonitor',
        daemon=True,
    )
    _dns_monitor_thread.start()
    return _dns_monitor_thread


def stop_dns_monitor():
    """Signal the background DNS monitor thread to stop."""
    global _dns_monitor_running
    _dns_monitor_running = False


# ===========================================================================
# SECTION 7: ENABLE / CHECK DNS EVENT LOG
# ===========================================================================

def enable_dns_event_log() -> bool:
    """
    Enable the Windows DNS-Client/Operational event log.
    Requires administrator privileges — only needs to be run once.
    """
    try:
        ps_cmd = (
            'wevtutil sl '
            '"Microsoft-Windows-DNS-Client/Operational" /e:true'
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print('[NET-MONITOR] DNS event log enabled')
            return True
        else:
            print('[NET-MONITOR] Could not enable DNS log')
            print('[NET-MONITOR] Run as administrator once to enable')
            return False
    except Exception as e:
        print('[NET-MONITOR] DNS log enable error: ' + str(e))
        return False


def check_dns_log_enabled() -> bool:
    """Return True if the Windows DNS-Client/Operational log is enabled."""
    try:
        ps_cmd = (
            'wevtutil gl '
            '"Microsoft-Windows-DNS-Client/Operational" | '
            'Select-String "enabled: true"'
        )
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', ps_cmd],
            capture_output=True, text=True, timeout=5
        )
        return result.returncode == 0 and bool(result.stdout.strip())
    except Exception:
        return False


# ===========================================================================
# SELF-TEST
# ===========================================================================

if __name__ == '__main__':
    print('=== NETWORK MONITOR TEST ===')
    print()

    print('Initialising database...')
    init_network_db()
    print('Database: OK')
    print()

    print('Checking DNS event log status...')
    enabled = check_dns_log_enabled()
    print('DNS logging enabled: ' + str(enabled))
    if not enabled:
        print('Attempting to enable...')
        enable_dns_event_log()
    print()

    print('Reading recent DNS events (last 5 minutes)...')
    events = read_dns_from_event_log(minutes_back=5)
    print('DNS events found: ' + str(len(events)))
    if events:
        print('Sample domains:')
        for e in events[:5]:
            print('  ' + e['domain']
                  + ' (source: ' + e['source'] + ')')
    print()

    print('Reading active TCP connections...')
    connections = get_active_connections()
    print('Active HTTP/S connections: ' + str(len(connections)))
    if connections:
        for c in connections[:3]:
            print('  ' + c['remote_ip']
                  + ':' + str(c['remote_port'])
                  + ' (' + c['process_name'] + ')')
    print()

    print('Testing file correlation...')
    test_file = str(config.BASE_DIR / 'config.py')
    result = correlate_file_to_url(test_file, 'test_session')
    print('Correlation result:')
    print('  Detected URL:  ' + str(result.get('detected_url', 'None')))
    print('  Domain:        ' + str(result.get('detected_domain', 'None')))
    print('  Confidence:    ' + str(result.get('confidence', 'NONE')))
    print('  Method:        ' + str(result.get('method', 'none')))
    print('  Candidates:    ' + str(len(result.get('all_candidates', []))))
    print('  Risk flags:    ' + str(len(result.get('risk_indicators', []))))
    print()

    print('Starting DNS background monitor...')
    thread = start_dns_monitor()
    print('Monitor thread: ' + thread.name)
    time.sleep(3)
    stop_dns_monitor()
    print('Monitor stopped cleanly')
    print()
    print('=== TEST COMPLETE ===')
