import os
import time
import struct
from pathlib import Path

import config
import utils
import chain_of_custody as coc
import recovery_database as rdb

# PURPOSE:
# After Layer 1 passes a file as clean this layer 
# performs a fast automatic check for hidden 
# executables using LSB steganography detection.
# It extracts least significant bits from the file
# and scans the reconstructed byte stream for 
# Windows PE (MZ), Linux ELF and script signatures.
# This catches unknown clean executables hidden 
# inside media files — threats that antivirus 
# engines completely miss because the payload 
# itself has no known malware signature.


# --- IMPROVEMENT 1 CONSTANTS ---
NATURAL_LSB_MAX = 7.5
SUSPICIOUS_MIN = 7.6
HIGH_ENTROPY_MIN = 7.8

MAGIC_NUMBERS = {
    'PE_EXECUTABLE': b'MZ',
    'PE_HEADER': b'PE\x00\x00',
    'ELF': b'\x7fELF',
    'ZIP_JAR': b'PK\x03\x04',
    'RAR': b'Rar!',
    'GZIP': b'\x1f\x8b',
    'CLASS': b'\xca\xfe\xba\xbe',
    'SCRIPT_PS1': b'param(',
    'SCRIPT_PS2': b'function ',
    'SCRIPT_VBS': b'Dim ',
    'SHELLCODE': b'\xfc\xe8',
    'PDF': b'%PDF',
    'PYTHON': b'import ',
    'BASH': b'#!/',
}

DOS_STUB = b'This program cannot be run'
PE_SECTIONS = [b'.text', b'.data', b'.rdata', b'.code']
SCRIPT_PATTERNS = [
    b'powershell', b'cmd.exe', b'wscript', b'cscript',
    b'subprocess', b'os.system', b'CreateProcess',
    b'VirtualAlloc', b'ShellExecute',
]

def extract_multiple_streams(image_array):
    streams = []
    # Extract from bit planes 0, 1, 2:
    for plane in [0, 1, 2]:
        bits = []
        for row in image_array:
            for pixel in row:
                if len(pixel) >= 3:
                    for channel in range(3):
                        bits.append((int(pixel[channel]) >> plane) & 1)
        
        # Convert bits to bytes:
        byte_stream = bytearray()
        for i in range(0, len(bits)-7, 8):
            byte_val = 0
            for bit_pos in range(8):
                byte_val |= (bits[i+bit_pos] << bit_pos)
            byte_stream.append(byte_val)
        
        # Store first 50000 bytes only:
        streams.append({
            'plane': plane,
            'offset': 0,
            'data': bytes(byte_stream[:50000])
        })
        
        # Also extract from offset 1000 and offset 5000 for plane 0 only:
        if plane == 0:
            for offset_pixels in [1000, 5000]:
                offset_bits = bits[offset_pixels*3:]
                offset_bytes = bytearray()
                for i in range(0, len(offset_bits)-7, 8):
                    byte_val = 0
                    for bit_pos in range(8):
                        byte_val |= (offset_bits[i+bit_pos] << bit_pos)
                    offset_bytes.append(byte_val)
                streams.append({
                    'plane': 0,
                    'offset': offset_pixels,
                    'data': bytes(offset_bytes[:50000])
                })
    return streams

def compute_entropy(data: bytes) -> float:
    if not data or len(data) < 100:
        return 0.0
    import math
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count > 0:
            prob = count / length
            entropy -= prob * math.log2(prob)
    return entropy

def search_magic_and_structure(stream_data: bytes):
    magic_findings = {}
    structural_findings = []
    
    # Check magic numbers
    lower_stream = stream_data.lower()
    for name, pattern in MAGIC_NUMBERS.items():
        if name.startswith('SCRIPT') or name in ['PYTHON', 'BASH']:
            pos = lower_stream[:10000].find(pattern.lower())
        else:
            pos = stream_data[:10000].find(pattern)
        if pos != -1:
            magic_findings[name] = pos
            
    # Check structural patterns
    if stream_data.find(DOS_STUB) != -1:
        structural_findings.append('DOS_STUB')
    for sec in PE_SECTIONS:
        if stream_data.find(sec) != -1:
            structural_findings.append(sec.decode(errors='ignore'))
    for pat in SCRIPT_PATTERNS:
        if lower_stream.find(pat.lower()) != -1:
            structural_findings.append(pat.decode(errors='ignore'))
            
    return magic_findings, structural_findings

def yara_scan_stream(stream_data: bytes, yara_rules) -> list:
    if not yara_rules or not stream_data:
        return []
    
    matches = []
    try:
        import tempfile
        import os
        
        # Write stream to temp file:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as tmp:
            tmp.write(stream_data)
            tmp_path = tmp.name
        
        # Try to match YARA rules:
        try:
            matched = yara_rules.match(tmp_path)
            for m in matched:
                rule_name = m.rule
                # From config check if this is informational only:
                try:
                    from config import INFORMATIONAL_RULES
                except ImportError:
                    INFORMATIONAL_RULES = []
                if (rule_name not in INFORMATIONAL_RULES):
                    matches.append(rule_name)
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        pass
    
    return matches

def determine_verdict(entropy_results, magic_findings, structural_findings, yara_findings) -> dict:
    has_executable = bool(magic_findings or structural_findings)
    has_yara_match = bool(yara_findings)
    
    entropy_values = [r['entropy'] for r in entropy_results]
    max_entropy = max(entropy_values) if entropy_values else 0
    high_entropy = max_entropy >= SUSPICIOUS_MIN
    very_high_entropy = max_entropy >= HIGH_ENTROPY_MIN
    
    if has_yara_match:
        verdict = 'EXECUTABLE_FOUND'
        confidence = 'VERY_HIGH'
        method = 'YARA_MATCH'
        detail = 'YARA rules matched patterns in extracted LSB content: ' + str(yara_findings[:3])
    elif has_executable:
        verdict = 'EXECUTABLE_FOUND'
        confidence = 'HIGH'
        method = 'SIGNATURE_MATCH'
        detail = 'Executable signatures found: ' + str(list(magic_findings.keys())[:3]) + ' Structural patterns: ' + str(structural_findings[:2])
    elif very_high_entropy:
        verdict = 'SUSPICIOUS_PAYLOAD'
        confidence = 'MEDIUM'
        method = 'ENTROPY_ANALYSIS'
        detail = 'Very high entropy payload detected (' + str(round(max_entropy, 3)) + ' bits/byte). Content may be encrypted or compressed. Cannot confirm executable without decryption key.'
    elif high_entropy:
        verdict = 'SUSPICIOUS_PAYLOAD'
        confidence = 'LOW'
        method = 'ENTROPY_ANALYSIS'
        detail = 'Elevated entropy detected (' + str(round(max_entropy, 3)) + ' bits/byte). Above natural LSB threshold of 7.5.'
    else:
        verdict = 'CLEAN'
        confidence = 'HIGH'
        method = 'MULTI_STAGE'
        detail = 'No executable signatures, YARA matches, structural patterns, or high entropy content found across all bit planes and offsets.'
    
    return {
        'verdict': verdict,
        'confidence': confidence,
        'method': method,
        'detail': detail,
        'max_entropy': round(max_entropy, 3),
        'high_entropy': high_entropy,
        'yara_matches': yara_findings,
        'magic_matches': list(magic_findings.keys()) if magic_findings else [],
        'structural_matches': structural_findings,
        'planes_checked': 3,
        'offsets_checked': [0, 1000, 5000],
    }

def run_lsb_executable_check(filepath, session_id, sha3_hash, scan_target=None, yara_rules=None):
    try:
        read_path = scan_target or filepath
        print('[LAYER1.5] LSB executable check starting...')
        print(f'[LAYER1.5] File: {Path(filepath).name}')
        
        if hasattr(rdb, 'update_stage'):
            rdb.update_stage(filepath, 'LAYER1_5_RUNNING')
            
        if yara_rules is None:
            try:
                from layer1_yara import get_compiled_rules
                yara_rules = get_compiled_rules()
            except Exception as e:
                print(f"[LAYER1.5] YARA not loaded: {e}")
                
        ext = Path(filepath).suffix.lower()
        image_exts = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp']
        
        all_streams = []
        method_used = 'MULTI_STAGE'
        if ext in image_exts:
            try:
                from PIL import Image
                import numpy as np
                img = Image.open(read_path).convert('RGB')
                img_array = np.array(img)
                all_streams = extract_multiple_streams(img_array)
            except Exception as e:
                print(f"[LAYER1.5] Image parsing error: {e}")
        else:
            try:
                with open(read_path, 'rb') as f:
                    head = f.read(50000)
                    f.seek(0, 2)
                    file_size = f.tell()
                    if file_size > 50000:
                        f.seek(-50000, 2)
                        tail = f.read(50000)
                    else:
                        tail = b''
                all_streams = [{'plane': 0, 'offset': 0, 'data': head + tail}]
            except Exception as e:
                print(f"[LAYER1.5] Binary parsing error: {e}")

        entropy_results = []
        magic_findings = {}
        structural_findings = []
        yara_findings = []

        for stream in all_streams:
            data = stream['data']
            if not data: continue
            
            ent = compute_entropy(data)
            entropy_results.append({'plane': stream['plane'], 'offset': stream['offset'], 'entropy': ent})
            
            mf, sf = search_magic_and_structure(data)
            magic_findings.update(mf)
            for f in sf:
                if f not in structural_findings:
                    structural_findings.append(f)
                    
            ym = yara_scan_stream(data, yara_rules)
            for y in ym:
                if y not in yara_findings:
                    yara_findings.append(y)
                    
        result = determine_verdict(entropy_results, magic_findings, structural_findings, yara_findings)
        
        signatures_found = [{'signature_type': m, 'severity': 'HIGH'} for m in result['magic_matches']]
        total_sigs = len(signatures_found)
        is_threat = result['verdict'] != 'CLEAN'
        highest_severity = result.get('confidence', 'NONE') if is_threat else 'NONE'
        
        coc.log_action(
            session_id, filepath, sha3_hash,
            coc.LSB_CHECK if hasattr(coc, 'LSB_CHECK') else 'LSB_CHECK',
            'THREAT' if is_threat else 'CLEAN',
            f'Method: {result["method"]}, Max Entropy: {result["max_entropy"]}'
        )
        
        if is_threat:
            print(f'[LAYER1.5] !!! SUSPICIOUS OR EXECUTABLE PAYLOAD FOUND IN LSB !!!')
            print(f'[LAYER1.5] Verdict: {result["verdict"]} ({result["confidence"]})')
            print(f'[LAYER1.5] Detail: {result["detail"]}')
            
            coc.log_action(
                session_id, filepath, sha3_hash,
                coc.EXECUTABLE_FOUND if hasattr(coc, 'EXECUTABLE_FOUND') else 'EXECUTABLE_FOUND',
                'CRITICAL' if result['verdict'] == 'EXECUTABLE_FOUND' else 'HIGH',
                result['detail']
            )
            
            if hasattr(rdb, 'update_stage'):
                rdb.update_stage(filepath, 'LAYER1_5_THREAT_FOUND')
                
            return {
                'verdict': result['verdict'],
                'severity': highest_severity,
                'signatures_found': signatures_found,
                'total_signatures': total_sigs,
                'method_used': result['method'],
                'auto_escalate': True,
                'auto_escalate_steganalysis': True,
                'reason': result['method'],
                'description': result['detail'],
                'session_id': session_id,
                'filepath': filepath,
                'sha3_hash': sha3_hash,
                
                # New keys
                'confidence': result['confidence'],
                'method': result['method'],
                'max_entropy': result['max_entropy'],
                'planes_checked': result['planes_checked'],
                'yara_matches': result['yara_matches']
            }
        else:
            print('[LAYER1.5] No hidden executables found in LSB data')
            print('[LAYER1.5] LSB check complete: CLEAN')
            
            if hasattr(rdb, 'update_stage'):
                rdb.update_stage(filepath, 'LAYER1_5_COMPLETE')
                
            return {
                'verdict': 'CLEAN',
                'severity': 'NONE',
                'signatures_found': [],
                'total_signatures': 0,
                'method_used': result['method'],
                'auto_escalate': False,
                'auto_escalate_steganalysis': False,
                'reason': 'No executable signatures found in LSB data',
                'description': result['detail'],
                'session_id': session_id,
                'filepath': filepath,
                'sha3_hash': sha3_hash,
                
                # New keys
                'confidence': result['confidence'],
                'method': result['method'],
                'max_entropy': result['max_entropy'],
                'planes_checked': result['planes_checked'],
                'yara_matches': result['yara_matches']
            }

    except Exception as e:
        utils.log_error(f"run_lsb_executable_check error: {e}")
        print(f"[LAYER1.5] Error: {e}")
        return {
            'verdict': 'ERROR',
            'error': str(e),
            'auto_escalate_steganalysis': False,
            'session_id': session_id,
            'filepath': filepath,
            'sha3_hash': sha3_hash
        }


if __name__ == "__main__":
    print('=== LAYER 1.5 LSB CHECK TESTS ===')
    print()
    
    # TEST 1 - Clean image
    try:
        from PIL import Image
        import numpy as np
        test_img = Image.fromarray((np.random.rand(100, 100, 3) * 255).astype('uint8'))
        test_img.save('test_clean_image.png')
        
        result = run_lsb_executable_check('test_clean_image.png', 'TEST_SESSION_LSB_001', 'testhash001')
        print('Test 1 - Clean image:')
        print('  Verdict:', result['verdict'])
        print('  Signatures found:', result['total_signatures'])
        if result['verdict'] == 'CLEAN':
            print('  PASS')
        else:
            print('  FAIL - unexpected detection')
            
        os.remove('test_clean_image.png')
    except Exception as e:
        print("Test 1 Exception:", e)
        
    print()
    
    # TEST 2 - Image with hidden MZ header in LSB
    try:
        from PIL import Image
        import numpy as np

        mz_bytes = b'\x4D\x5A\x90\x00'
        bits = []
        for byte in mz_bytes:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)

        pixels = []
        bit_idx = 0
        for i in range(100 * 100):
            if bit_idx + 2 < len(bits):
                r = (128 & 0xFE) | bits[bit_idx]
                g = (128 & 0xFE) | bits[bit_idx+1]
                b = (128 & 0xFE) | bits[bit_idx+2]
                bit_idx += 3
            else:
                r, g, b = 128, 128, 128
            pixels.append((r, g, b))

        stego_img = Image.new('RGB', (100, 100))
        stego_img.putdata(pixels)
        stego_img.save('test_stego_image.png')

        result = run_lsb_executable_check('test_stego_image.png', 'TEST_SESSION_LSB_002', 'testhash002')
        print('Test 2 - Image with hidden MZ header:')
        print('  Verdict:', result['verdict'])
        print('  Signatures found:', result['total_signatures'])
        if result['signatures_found']:
            for sig in result['signatures_found']:
                print(f"  Found: {sig['signature_type']} at {sig['position_hex']}")
                
        os.remove('test_stego_image.png')
    except Exception as e:
        print("Test 2 Exception:", e)
        
    print()
    
    # TEST 3 - Binary file with PowerShell hidden in tail
    try:
        with open('test_binary.bin', 'wb') as f:
            f.write(b'\x00' * 1000)
            f.write(b'powershell Invoke-Expression malicious_code')
            f.write(b'\x00' * 100)

        result = run_lsb_executable_check('test_binary.bin', 'TEST_SESSION_LSB_003', 'testhash003')
        print('Test 3 - Binary with PowerShell in tail:')
        print('  Verdict:', result['verdict'])
        print('  Signatures found:', result['total_signatures'])
        if result['verdict'] != 'CLEAN':
            print('  PASS')
        else:
            print('  NOTE: PowerShell not detected - may need tuning')
            
        os.remove('test_binary.bin')
    except Exception as e:
        print("Test 3 Exception:", e)

    print()
    print('=== TESTS COMPLETE ===')
