import os
import requests
import time
import threading
import json
import hashlib
from collections import Counter
from pathlib import Path
import config
import utils

# PURPOSE:
# Sends file hashes to VirusTotal API to check against
# 70+ antivirus engines. Returns exact virus names and
# categories from each engine that flagged the file.
# Uses rate limiting to stay within the free tier.

VT_CACHE_FILE = Path(getattr(config, 'BASE_DIR', Path('.'))) / 'logs' / 'vt_cache.json'
_vt_cache = {}
_vt_cache_lock = threading.Lock()

def load_vt_cache():
    global _vt_cache
    try:
        if VT_CACHE_FILE.exists():
            with open(VT_CACHE_FILE, 'r') as f:
                _vt_cache = json.load(f)
    except Exception as e:
        print(f"[VT] Cache load error: {e}")
        _vt_cache = {}

def save_vt_cache():
    try:
        with open(VT_CACHE_FILE, 'w') as f:
            json.dump(_vt_cache, f)
    except Exception as e:
        print(f"[VT] Cache save error: {e}")

def get_cached_vt_result(sha256_hash):
    with _vt_cache_lock:
        if not _vt_cache:
            load_vt_cache()
        
        if sha256_hash in _vt_cache:
            entry = _vt_cache[sha256_hash]
            cache_time = entry.get('timestamp', 0)
            hours_allowed = getattr(config, 'VT_CACHE_HOURS', 24)
            
            if (time.time() - cache_time) < (hours_allowed * 3600):
                result = entry.get('result', {})
                result['source'] = 'local_cache'
                return result
            else:
                del _vt_cache[sha256_hash]
                save_vt_cache()
        return None

def cache_vt_result(sha256_hash, result):
    if result.get('verdict') in ['ERROR', 'RATE_LIMITED', 'UNKNOWN']:
        return
        
    with _vt_cache_lock:
        _vt_cache[sha256_hash] = {
            'timestamp': time.time(),
            'result': result
        }
        save_vt_cache()

class VirusTotalRateLimiter:
    def __init__(self):
        self.calls_this_minute = 0
        self.calls_today = 0
        self.minute_reset_time = time.time() + 60
        self.day_reset_time = time.time() + 86400
        self.lock = threading.Lock()
    
    def can_make_call(self):
        with self.lock:
            now = time.time()
            if now > self.minute_reset_time:
                self.calls_this_minute = 0
                self.minute_reset_time = now + 60
            if now > self.day_reset_time:
                self.calls_today = 0
                self.day_reset_time = now + 86400
                
            cpm = getattr(config, 'VIRUSTOTAL_CALLS_PER_MINUTE', 4)
            cpd = getattr(config, 'VIRUSTOTAL_CALLS_PER_DAY', 500)
            
            return (
                self.calls_this_minute < cpm
                and self.calls_today < cpd
            )
    
    def register_call(self):
        with self.lock:
            self.calls_this_minute += 1
            self.calls_today += 1
    
    def wait_for_slot(self, timeout=300):
        start = time.time()
        while not self.can_make_call():
            if time.time() - start > timeout:
                return False
            print('[VT] Rate limit reached. Waiting 15 seconds...')
            time.sleep(15)
        return True

rate_limiter = VirusTotalRateLimiter()

def extract_threat_family_type(threat_name):
    try:
        if not threat_name or threat_name == 'Unknown':
            return 'Unknown', 'Unknown'
            
        parts = threat_name.split('.')
        threat_family = threat_name
        if len(parts) > 1:
            if parts[0] in ['Win', 'Osx', 'Unix', 'Andr', 'JS', 'VBA', 'Doc', 'Win32', 'Win64', 'Suspicious', 'Trojan', 'Worm', 'Malware', 'Ransomware']:
                threat_family = '.'.join(parts[1:])
            else:
                threat_family = '.'.join(parts[1:]) if len(parts) > 1 else threat_name

        name_lower = threat_name.lower()
        if 'eicar' in name_lower or 'test' in name_lower:
            threat_type = 'Test'
        elif 'ransomware' in name_lower or 'ransom' in name_lower:
            threat_type = 'Ransomware'
        elif 'trojan' in name_lower:
            threat_type = 'Trojan'
        elif 'worm' in name_lower:
            threat_type = 'Worm'
        elif 'spy' in name_lower or 'spyware' in name_lower:
            threat_type = 'Spyware'
        elif 'adware' in name_lower or 'pua' in name_lower or 'pup' in name_lower:
            threat_type = 'Adware'
        elif 'rootkit' in name_lower:
            threat_type = 'Rootkit'
        elif 'backdoor' in name_lower:
            threat_type = 'Backdoor'
        elif 'exploit' in name_lower:
            threat_type = 'Exploit'
        elif 'virus' in name_lower:
            threat_type = 'Virus'
        elif 'suspicious' in name_lower:
            threat_type = 'Suspicious'
        else:
            threat_type = 'Malware'
            
        return threat_family, threat_type
    except Exception:
        return 'Unknown', 'Unknown'

def _parse_vt_data(data):
    attributes = data['data']['attributes']
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    last_analysis_results = attributes.get('last_analysis_results', {})
    
    malicious_count = last_analysis_stats.get('malicious', 0)
    suspicious_count = last_analysis_stats.get('suspicious', 0)
    total_engines = sum(last_analysis_stats.values()) if last_analysis_stats else 0
    
    flagging_engines = []
    names = []
    
    for engine_name, engine_result in last_analysis_results.items():
        cat = engine_result.get('category')
        if cat in ['malicious', 'suspicious']:
            t_name = engine_result.get('result', 'Unknown')
            flagging_engines.append({
                'engine_name': engine_name,
                'threat_name': t_name,
                'category': cat
            })
            if t_name and t_name != 'Unknown':
                names.append(t_name)
    
    most_common_threat_name = None
    threat_family = "Unknown"
    threat_type = "Unknown"
    
    if names:
        counted = Counter(names)
        most_common_threat_name = counted.most_common(1)[0][0]
        threat_family, threat_type = extract_threat_family_type(most_common_threat_name)
        
    verdict = "THREAT" if malicious_count > 0 else "CLEAN"
    
    if malicious_count > 5:
        severity = "CRITICAL"
    elif malicious_count > 0:
        severity = "HIGH"
    elif suspicious_count > 0:
        severity = "MEDIUM"
    else:
        severity = "CLEAN"
        
    return {
       'engine': "VirusTotal",
       'verdict': verdict,
       'malicious_count': malicious_count,
       'suspicious_count': suspicious_count,
       'total_engines_checked': total_engines,
       'flagging_engines': flagging_engines,
       'most_common_threat_name': most_common_threat_name,
       'threat_family': threat_family,
       'threat_type': threat_type,
       'severity': severity
    }

def check_hash_virustotal(sha3_hash):
    try:
        api_key = getattr(config, 'VIRUSTOTAL_API_KEY', '')
        if not api_key:
             return {'engine': 'VirusTotal', 'verdict': 'SKIPPED', 'reason': 'No API key configured'}
             
        if not rate_limiter.wait_for_slot():
            return {
                'engine': "VirusTotal",
                'verdict': "RATE_LIMITED",
                'reason': "API rate limits reached, wait timeout exceeded",
                'requires_upload': False
            }
            
        url = f"{config.VIRUSTOTAL_BASE_URL}/files/{sha3_hash}"
        headers = {"x-apikey": api_key}
        
        response = requests.get(url, headers=headers, timeout=30)
        rate_limiter.register_call()
        
        if response.status_code == 200:
            data = response.json()
            result = _parse_vt_data(data)
            result['source'] = "hash_lookup"
            return result
        elif response.status_code in [404, 400]:
            # VT returns 400 Invalid identifier if given string isn't standard MD5, SHA-1, SHA-256
            return {
                'engine': "VirusTotal",
                'verdict': "UNKNOWN",
                'reason': f"Hash not found or rejected ({response.status_code})",
                'source': "hash_lookup",
                'requires_upload': True
            }
        elif response.status_code == 429:
            return {
                'engine': "VirusTotal",
                'verdict': "RATE_LIMITED",
                'reason': "429 Too Many Requests response from VirusTotal"
            }
        else:
            return {
                'engine': "VirusTotal",
                'verdict': "ERROR",
                'reason': f"HTTP {response.status_code}: {response.text}"
            }
    except Exception as e:
        utils.log_error(f"Error in check_hash_virustotal for {sha3_hash}", e)
        return {
            'engine': "VirusTotal",
            'verdict': "ERROR",
            'reason': str(e)
        }

def upload_file_virustotal(filepath):
    try:
        api_key = getattr(config, 'VIRUSTOTAL_API_KEY', '')
        if not api_key:
             return {'engine': 'VirusTotal', 'verdict': 'SKIPPED', 'reason': 'No API key configured'}

        abs_path = os.path.abspath(filepath)
        if not os.path.exists(abs_path):
            return {
                'engine': "VirusTotal",
                'verdict': "ERROR",
                'reason': "File not found"
            }
            
        size = os.path.getsize(abs_path)
        if size > 32 * 1024 * 1024:
            return {
                'engine': "VirusTotal",
                'verdict': "ERROR",
                'reason': "File size > 32MB exceeds VirusTotal free tier limits"
            }
            
        if not rate_limiter.wait_for_slot():
            return {
                'engine': "VirusTotal",
                'verdict': "RATE_LIMITED",
                'reason': "API rate limits reached before upload"
            }
            
        url = f"{config.VIRUSTOTAL_BASE_URL}/files"
        headers = {"x-apikey": api_key}
        
        with open(abs_path, 'rb') as f:
            files = {"file": (Path(abs_path).name, f)}
            response = requests.post(url, headers=headers, files=files, timeout=60)
            
        rate_limiter.register_call()
        
        if response.status_code == 200:
            data = response.json()
            analysis_id = data.get('data', {}).get('id')
            if not analysis_id:
                return {
                    'engine': "VirusTotal",
                    'verdict': "ERROR",
                    'reason': "No analysis_id returned from VT upload"
                }
                
            poll_url = f"{config.VIRUSTOTAL_BASE_URL}/analyses/{analysis_id}"
            
            for attempt in range(8):
                if not rate_limiter.wait_for_slot():
                   return {
                       'engine': "VirusTotal",
                       'verdict': "RATE_LIMITED",
                       'reason': "Rate limit reached while polling"
                   }
                   
                time.sleep(15)
                poll_response = requests.get(poll_url, headers=headers, timeout=30)
                rate_limiter.register_call()
                
                if poll_response.status_code == 200:
                    poll_data = poll_response.json()
                    status = poll_data.get('data', {}).get('attributes', {}).get('status', '')
                    if status == 'completed':
                        result = _parse_vt_data(poll_data)
                        result['source'] = "file_upload"
                        return result
                    elif status in ['queued', 'in-progress']:
                        continue
                elif poll_response.status_code == 429:
                    return {'engine': 'VirusTotal', 'verdict': 'RATE_LIMITED'}
                else:
                    return {'engine': 'VirusTotal', 'verdict': 'ERROR', 'reason': f"Poll returned HTTP {poll_response.status_code}"}
                    
            return {
                'engine': "VirusTotal",
                'verdict': "UNKNOWN",
                'reason': "Analysis polling timed out after 8 attempts (file still analyzing in background)",
                'source': "file_upload"
            }
        elif response.status_code == 429:
            return {'engine': 'VirusTotal', 'verdict': 'RATE_LIMITED', 'reason': '429 heavily limited'}
        else:
            return {'engine': 'VirusTotal', 'verdict': 'ERROR', 'reason': f"Upload failed HTTP {response.status_code}: {response.text}"}
            
    except Exception as e:
        utils.log_error(f"Error in upload_file_virustotal for {filepath}", e)
        return {
            'engine': "VirusTotal",
            'verdict': "ERROR",
            'reason': str(e)
        }

def scan_virustotal(filepath, sha3_hash):
    try:
        if getattr(config, 'OFFLINE_SCAN_MODE', False):
            return {'engine': 'VirusTotal', 'verdict': 'SKIPPED', 'reason': 'Offline Scan Mode active (cloud disabled)'}
        vt_mode = getattr(config, 'VT_MODE', 'CHECK_ONLY')
        if str(vt_mode).upper() in ('DISABLED', 'DISABLE'):
            return {'engine': 'VirusTotal', 'verdict': 'SKIPPED', 'reason': 'VT_MODE is DISABLED'}

        import hashlib
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        sha256_hash = hasher.hexdigest()
        
        cached = get_cached_vt_result(sha256_hash)
        if cached:
            return cached
            
        result = check_hash_virustotal(sha256_hash)
        
        if result.get('verdict') == 'UNKNOWN' and result.get('requires_upload'):
            if str(vt_mode).upper() in ('UPLOAD_UNKNOWN', 'FULL_UPLOAD'):
                print("[VT] File unknown to VT - uploading for full scan")
                upload_result = upload_file_virustotal(filepath)
                cache_vt_result(sha256_hash, upload_result)
                return upload_result
            else:
                return {
                    'engine': 'VirusTotal',
                    'verdict': 'SKIPPED',
                    'reason': f"File unknown to VT. VT_MODE is {vt_mode} (no upload)"
                }
                
        cache_vt_result(sha256_hash, result)
        return result
    except Exception as e:
        utils.log_error(f"Error in scan_virustotal for {filepath}", e)
        return {
            'engine': "VirusTotal",
            'verdict': "ERROR",
            'reason': str(e)
        }

if __name__ == "__main__":
    print("Running layer1_virustotal tests...\n")
    
    # Test 1 - Hash lookup with fake hash (will return 404 or 400)
    try:
        result1 = check_hash_virustotal('fakehash123456789')
        print('Test 1 - Unknown hash:')
        print(' Verdict:', result1.get('verdict'))
        print(' Expected: UNKNOWN or ERROR')
        if result1.get('verdict') in ['UNKNOWN', 'ERROR', 'RATE_LIMITED']:
            print(' PASS\n')
        else:
            print(' FAIL\n')
    except Exception as e:
        print("Test 1 Error:", e)

    # Test 2 - Test rate limiter
    try:
        can_call = rate_limiter.can_make_call()
        print('Test 2 - Rate limiter:')
        print(' Can make call:', can_call)
        print(' PASS\n')
    except Exception as e:
        print("Test 2 Error:", e)

    # Test 3 - Test with this Python file hash
    try:
        hash_val = utils.generate_sha3_hash(__file__)
        print('Test 3 - Real file hash lookup:')
        print(' Hash:', hash_val[:20] if hash_val else 'None', '...')
        result3 = scan_virustotal(__file__, hash_val)
        print(' Verdict:', result3.get('verdict'))
        print(' Source:', result3.get('source', 'unknown'))
    except Exception as e:
        print("Test 3 Error:", e)
