import clamd
import os
import platform
import time
from pathlib import Path
import config
import utils
from utils import ensure_clamd_running

# PURPOSE:
# Scans files using the ClamAV antivirus engine.
# Returns exact virus name, family, type and category
# for every detection.

_last_clamd_check = 0
_clamd_available = False

def get_clamd_connection():
    global _last_clamd_check, _clamd_available
    now = time.time()
    # If checked recently and failed, skip immediately without stalling pipeline
    if not _clamd_available and (now - _last_clamd_check < 60):
        return None

    try:
        cd = clamd.ClamdNetworkSocket('127.0.0.1', 3310, timeout=1)
        cd.ping()
        _clamd_available = True
        return cd
    except Exception as e:
        _last_clamd_check = now
        _clamd_available = False
        return None

def extract_threat_details(threat_name):
    # E.g., "Win.Trojan.Agent-12345" or "Eicar-Test-Signature"
    try:
        # threat_family
        parts = threat_name.split('.')
        if len(parts) > 1:
            # Rule: first meaningful part before dots
            # e.g., "Win.Trojan.Agent" -> "Trojan.Agent"
            if parts[0] in ['Win', 'Osx', 'Unix', 'Andr', 'JS', 'VBA', 'Doc']:
                threat_family = '.'.join(parts[1:])
            else:
                threat_family = '.'.join(parts[1:]) if len(parts) > 1 else threat_name
        else:
            threat_family = threat_name
            
        name_lower = threat_name.lower()
        
        # threat_type
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
        elif 'adware' in name_lower:
            threat_type = 'Adware'
        elif 'rootkit' in name_lower:
            threat_type = 'Rootkit'
        elif 'backdoor' in name_lower:
            threat_type = 'Backdoor'
        elif 'exploit' in name_lower:
            threat_type = 'Exploit'
        elif 'virus' in name_lower:
            threat_type = 'Virus'
        else:
            threat_type = 'Malware'
            
        # threat_category
        if 'eicar' in name_lower:
            threat_category = 'Test'
        elif 'pua' in name_lower or 'pup' in name_lower:
            threat_category = 'PUA'
        else:
            threat_category = 'Malware'
            
        # severity
        if threat_type == 'Test' or threat_category == 'Test':
            severity = 'LOW'
        elif threat_type == 'Adware' or threat_category == 'PUA':
            severity = 'MEDIUM'
        elif threat_type in ['Trojan', 'Worm', 'Spyware']:
            severity = 'HIGH'
        elif threat_type in ['Ransomware', 'Rootkit', 'Backdoor', 'Exploit']:
            severity = 'CRITICAL'
        else:
            severity = 'HIGH' # Default fallback for other Malware
            
        return {
            'threat_family': threat_family,
            'threat_type': threat_type,
            'threat_category': threat_category,
            'severity': severity,
            'raw_name': threat_name
        }
            
    except Exception as e:
        utils.log_error(f"Error extracting threat details for {threat_name}: {e}")
        return {
            'threat_family': threat_name,
            'threat_type': 'Unknown',
            'threat_category': 'Unknown',
            'severity': 'MEDIUM',
            'raw_name': threat_name
        }

def scan_with_clamav(filepath):
    try:
        cd = get_clamd_connection()
        if cd is None:
            return {
                'engine': 'ClamAV',
                'verdict': 'SKIPPED',
                'reason': 'ClamAV daemon unavailable',
                'threat_name': None,
                'threat_family': None,
                'threat_type': None,
                'threat_category': None,
                'severity': None
            }
            
        # Resolve path to absolute since clamd expects absolute path if running as service
        abs_path = os.path.abspath(filepath)
        result = cd.scan(abs_path)
        
        # Parse result
        res_tuple = result.get(abs_path)
        if not res_tuple:
            # Fallback if path casing changed slightly
            if len(result) > 0:
                res_tuple = list(result.values())[0]
            else:
                return {
                    'engine': 'ClamAV',
                    'verdict': 'ERROR',
                    'reason': 'Empty response from ClamAV',
                    'threat_name': None,
                    'threat_family': None,
                    'threat_type': None,
                    'threat_category': None,
                    'severity': None
                }
                
        status = res_tuple[0]
        name = res_tuple[1]
        
        if status == 'FOUND':
            details = extract_threat_details(name)
            return {
                 'engine': 'ClamAV',
                 'verdict': 'THREAT',
                 'threat_name': name,
                 'threat_family': details['threat_family'],
                 'threat_type': details['threat_type'],
                 'threat_category': details['threat_category'],
                 'severity': details['severity'],
                 'raw_result': str(result)
            }
        elif status == 'OK':
             return {
                 'engine': 'ClamAV',
                 'verdict': 'CLEAN',
                 'threat_name': None,
                 'threat_family': None,
                 'threat_type': None,
                 'threat_category': None,
                 'severity': None,
                 'raw_result': 'CLEAN'
             }
        else:
             return {
                 'engine': 'ClamAV',
                 'verdict': 'ERROR',
                 'reason': f"Unexpected status from ClamAV: {status}",
                 'threat_name': None,
                 'threat_family': None,
                 'threat_type': None,
                 'threat_category': None,
                 'severity': None
             }
             
    except Exception as e:
        utils.log_error(f"Error scanning with ClamAV on {filepath}: {e}")
        return {
             'engine': 'ClamAV',
             'verdict': 'ERROR',
             'reason': str(e),
             'threat_name': None,
             'threat_family': None,
             'threat_type': None,
             'threat_category': None,
             'severity': None
        }

if __name__ == "__main__":
    print("Running layer1_clamav tests...\n")
    
    # Test 1 - Scan this script itself (should be CLEAN)
    try:
        result1 = scan_with_clamav(__file__)
        print('Test 1 - Clean file:')
        print(' Verdict:', result1.get('verdict'))
        print(' Expected: CLEAN')
        if result1.get('verdict') == 'CLEAN':
            print(' PASS\n')
        else:
            print(' FAIL\n')
    except Exception as e:
        print("Test 1 Error:", e)

    # Test 2 - Create EICAR test string and scan
    try:
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        with open('test_eicar.txt', 'wb') as f:
            f.write(eicar)
        result2 = scan_with_clamav('test_eicar.txt')
        print('Test 2 - EICAR test file:')
        print(' Verdict:', result2.get('verdict'))
        print(' Threat name:', result2.get('threat_name'))
        print(' Expected: THREAT')
        if os.path.exists('test_eicar.txt'):
            os.remove('test_eicar.txt')
            
        if result2.get('verdict') == 'THREAT':
            print(' PASS\n')
        else:
            print(' FAIL - ClamAV may not have detected EICAR\n')
            print(' Result was:', result2)
    except Exception as e:
        print("Test 2 Error:", e)
