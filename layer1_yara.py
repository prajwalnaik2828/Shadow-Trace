import yara
import glob
import os
import threading
from pathlib import Path
import config
import utils

from config import INFORMATIONAL_RULES

# PURPOSE:
# Scans files using YARA rules to detect malware families and variants 
# by matching structural patterns and string sequences. Catches modified
# malware that evades signature databases.

_compiled_rules = None
_rules_lock = threading.Lock()

def load_yara_rules():
    try:
        yar_files = glob.glob(config.YARA_RULES_PATTERN, recursive=True)
        yara_files = glob.glob(config.YARA_RULES_PATTERN_YARA, recursive=True)
        all_rule_files = list(set(yar_files + yara_files))
        
        if not all_rule_files:
            print(f"WARNING: No YARA rules found in {config.YARA_RULES_DIR}")
            return None
            
        successful_rules = []
        failed_count = 0
        
        for rule_file in all_rule_files:
            try:
                yara.compile(filepath=rule_file)
                successful_rules.append(rule_file)
            except yara.SyntaxError as e:
                failed_count += 1
                utils.log_error(f"YARA SyntaxError compiling {rule_file}", e)
                continue
            except Exception as e:
                failed_count += 1
                utils.log_error(f"Exception compiling YARA rule {rule_file}", e)
                continue
                
        print(f"Loaded {len(successful_rules)} YARA rules, {failed_count} failed to compile")
        
        if not successful_rules:
            return None
            
        filepaths_dict = {}
        for i, rule_file in enumerate(successful_rules):
            namespace = f'rule_{i}'
            filepaths_dict[namespace] = rule_file
            
        compiled = yara.compile(filepaths=filepaths_dict)
        return compiled
        
    except Exception as e:
        utils.log_error("Critical error in load_yara_rules", e)
        return None

def get_compiled_rules():
    global _compiled_rules, _rules_lock
    try:
        with _rules_lock:
            if _compiled_rules is None:
                _compiled_rules = load_yara_rules()
            return _compiled_rules
    except Exception as e:
        utils.log_error("Error in get_compiled_rules", e)
        return None

def scan_with_yara(filepath):
    try:
        rules = get_compiled_rules()
        if rules is None:
            return {
                'engine': "YARA",
                'verdict': "SKIPPED",
                'reason': "No YARA rules loaded or Compilation failed",
                'threat_name': None,
                'threat_family': None,
                'threat_type': None,
                'threat_category': None,
                'severity': None,
                'matched_rules_count': 0,
                'all_matched_rules': [],
                'description': None,
                'raw_result': None
            }
            
        abs_path = os.path.abspath(filepath)
        matches = rules.match(abs_path, timeout=60)
        
        if matches:
            first_match = matches[0]
            rule_name = first_match.rule
            tags = first_match.tags
            meta = first_match.meta
            description = meta.get('description', rule_name)
            
            all_matched_rules = [m.rule for m in matches]
            informational_matches = [r for r in all_matched_rules if r in INFORMATIONAL_RULES]
            threat_matches = [r for r in all_matched_rules if r not in INFORMATIONAL_RULES]
            
            if threat_matches:
                verdict = "THREAT"
                severity = "HIGH"
                threat_category = "Malware"
                primary_threat_name = threat_matches[0]
            else:
                verdict = "WARNING"
                severity = "LOW"
                threat_category = "Anomaly"
                primary_threat_name = informational_matches[0]
            
            threat_family = meta.get('family', primary_threat_name)
            
            threat_type = "Unknown"
            if tags:
                threat_type = tags[0]
                
            return {
                'engine': "YARA",
                'verdict': verdict,
                'threat_name': primary_threat_name,
                'threat_family': threat_family,
                'threat_type': threat_type,
                'threat_category': threat_category,
                'severity': severity,
                'matched_rules_count': len(matches),
                'matched_rules': all_matched_rules,
                'yara_matched_rules': threat_matches,
                'informational_matches': informational_matches,
                'yara_warnings': informational_matches if verdict == "WARNING" else [],
                'rule_count': len(matches),
                'description': description,
                'raw_result': str([(m.rule, m.meta, m.tags) for m in matches])
            }
        else:
            return {
                'engine': "YARA",
                'verdict': "CLEAN",
                'threat_name': None,
                'threat_family': None,
                'threat_type': None,
                'threat_category': None,
                'severity': None,
                'matched_rules_count': 0,
                'matched_rules': [],
                'informational_matches': [],
                'threat_matches': [],
                'rule_count': 0,
                'description': None,
                'raw_result': "CLEAN"
            }
            
    except Exception as e:
        utils.log_error(f"Error scanning with YARA on {filepath}", e)
        return {
            'engine': "YARA",
            'verdict': "ERROR",
            'reason': str(e),
            'threat_name': None,
            'threat_family': None,
            'threat_type': None,
            'threat_category': None,
            'severity': None,
            'matched_rules_count': 0,
            'all_matched_rules': [],
            'description': None,
            'raw_result': None
        }

if __name__ == "__main__":
    print("Running layer1_yara tests...\n")
    
    # Test 1 - Load rules
    rules_obj = get_compiled_rules()
    if rules_obj:
        print('Test 1 - Rules loaded: PASS\n')
    else:
        print('Test 1 - Rules loaded: FAIL (No valid YARA rules found or compiled)\n')

    # Test 2 - Scan clean file
    try:
        with open('test_yara_clean.txt', 'w', encoding='utf-8') as f:
            f.write('Hello World 12345')
        result_clean = scan_with_yara('test_yara_clean.txt')
        print('Test 2 - Clean file:')
        print(' Verdict:', result_clean.get('verdict'))
        if result_clean.get('verdict') in ['CLEAN', 'SKIPPED']:
            print(' PASS\n')
        else:
            print(' FAIL - Result:', result_clean, '\n')
            
        if os.path.exists('test_yara_clean.txt'):
            os.remove('test_yara_clean.txt')
    except Exception as e:
        print("Test 2 Error:", e)

    # Test 3 - Scan file with suspicious pattern
    try:
        with open('test_yara_sample.txt', 'w', encoding='utf-8') as f:
            f.write('This contains ' + 'po' + 'wer' + 'shell ' + 'In' + 'voke-Ex' + 'pression test')
        result_susp = scan_with_yara('test_yara_sample.txt')
        print('Test 3 - Suspicious pattern:')
        print(' Verdict:', result_susp.get('verdict'))
        print(' Matched rules:', result_susp.get('matched_rules_count', 0))
        if os.path.exists('test_yara_sample.txt'):
            os.remove('test_yara_sample.txt')
    except Exception as e:
        print("Test 3 Error:", e)
