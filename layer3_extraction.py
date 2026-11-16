import os
import math
import struct
import numpy as np
import cv2
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from PIL import Image

# Dummy imports for utils, config, chain_of_custody, to make sure test block runs without failing
# if these aren't fully implemented or available in test context, though we will try importing them.
try:
    import utils
except ImportError:
    pass
try:
    import config
except ImportError:
    pass
try:
    import chain_of_custody as coc
except ImportError:
    pass

# === SECTION 1: ENTROPY SCANNER ===

def shannon_entropy(data: bytes) -> float:
    if len(data) == 0:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def classify_payload_entropy(data: bytes) -> Dict:
    entropy = shannon_entropy(data)
    if entropy > 7.9:
        payload_class = 'ENCRYPTED_OR_COMPRESSED'
        confidence = 'HIGH'
        note = 'Entropy above 7.9 indicates encrypted or compressed data'
    elif entropy > 7.2:
        payload_class = 'COMPRESSED'
        confidence = 'MEDIUM'
        note = 'Entropy 7.2-7.9 consistent with compressed data'
    elif entropy > 4.5:
        payload_class = 'BINARY_DATA'
        confidence = 'LOW'
        note = 'Entropy 4.5-7.2 consistent with binary data'
    elif entropy > 3.5:
        payload_class = 'NATURAL_LANGUAGE_OR_CODE'
        confidence = 'MEDIUM'
        note = 'Entropy 3.5-4.5 consistent with natural language or code'
    else:
        payload_class = 'STRUCTURED_DATA_OR_EMPTY'
        confidence = 'LOW'
        note = 'Entropy below 3.5 may indicate structured or sparse data'
        
    return {
        'entropy': entropy,
        'payload_class': payload_class,
        'confidence': confidence,
        'note': note
    }

# === SECTION 2: MAGIC NUMBER DETECTOR ===

def detect_magic_number(data: bytes) -> Dict:
    magic_map = {
        b'\x4d\x5a\x90\x00': 'Windows PE (detailed)',
        b'\x4d\x5a': 'Windows PE Executable (EXE/DLL)',
        b'\x7f\x45\x4c\x46': 'ELF Executable (Linux/Android)',
        b'\x89\x50\x4e\x47': 'PNG Image',
        b'\xff\xd8\xff': 'JPEG Image',
        b'\x47\x49\x46': 'GIF Image',
        b'\x25\x50\x44\x46': 'PDF Document',
        b'\x50\x4b\x03\x04': 'ZIP Archive',
        b'\x52\x61\x72\x21': 'RAR Archive',
        b'\x37\x7a\xbc\xaf': '7-Zip Archive',
        b'\x1f\x8b': 'GZIP Compressed',
        b'\x42\x5a\x68': 'BZIP2 Compressed',
        b'\xca\xfe\xba\xbe': 'Java Class File',
        b'\x23\x21': 'Script (shebang)',
        b'\x3c\x3f\x70\x68\x70': 'PHP Script',
        b'\x3c\x68\x74\x6d\x6c': 'HTML Document'
    }
    
    detected_type = None
    for magic, desc in magic_map.items():
        if data.startswith(magic):
            detected_type = desc
            break
            
    if not detected_type:
        printable_ratio = sum(1 for b in data[:256] if 32 <= b <= 126) / max(1, min(256, len(data)))
        if printable_ratio > 0.85:
            detected_type = 'Plain Text'
        else:
            detected_type = 'Unknown Binary'
            
    is_exec = detected_type in ('Windows PE Executable (EXE/DLL)', 'ELF Executable (Linux/Android)', 'Windows PE (detailed)')
    is_arch = detected_type in ('ZIP Archive', 'RAR Archive', '7-Zip Archive', 'GZIP Compressed', 'BZIP2 Compressed')
    is_img = detected_type in ('PNG Image', 'JPEG Image', 'GIF Image')
    is_scr = detected_type in ('Script (shebang)', 'PHP Script', 'HTML Document')
    is_txt = detected_type == 'Plain Text'
    
    return {
        'detected_type': detected_type,
        'magic_bytes': data[:8].hex(),
        'is_executable': is_exec,
        'is_archive': is_arch,
        'is_image': is_img,
        'is_script': is_scr,
        'is_text': is_txt
    }

# === SECTION 3: IMAGE PAYLOAD EXTRACTOR ===

def extract_lsb_bits(image_array: np.ndarray, bit_plane: int = 0, roi_coords: Optional[Tuple] = None) -> bytes:
    if roi_coords is not None:
        x1, y1, x2, y2 = roi_coords
        region = image_array[y1:y2, x1:x2]
    else:
        region = image_array
        
    bit_mask = 1 << bit_plane
    bits = (region & bit_mask) >> bit_plane
    bits = bits.flatten()
    
    n_bytes = len(bits) // 8
    result = bytearray()
    for i in range(n_bytes):
        byte_val = 0
        for j in range(8):
            byte_val |= (int(bits[i*8 + j]) << j)
        result.append(byte_val)
        
    return bytes(result)

def extract_image_payload(filepath: str, roi_coords: Optional[Tuple] = None) -> Dict[str, Any]:
    try:
        img = Image.open(filepath).convert('RGB')
        img_array = np.array(img, dtype=np.uint8)
        h, w, c = img_array.shape
        
        if roi_coords is not None:
            print(f"ROI extraction with coordinates {roi_coords}")
        else:
            print("Full image extraction")
            
        results_per_plane = {}
        for bit_plane in [0, 1, 2]:
            raw_bytes = extract_lsb_bits(img_array, bit_plane, roi_coords)
            magic = detect_magic_number(raw_bytes[:512])
            entropy_info = classify_payload_entropy(raw_bytes[:4096])
            
            results_per_plane[bit_plane] = {
                'raw_bytes_length': len(raw_bytes),
                'magic_detection': magic,
                'entropy_analysis': entropy_info,
                'first_32_bytes_hex': raw_bytes[:32].hex(),
            }
            
        best_plane = 0
        for plane, res in results_per_plane.items():
            if res['magic_detection']['is_executable']:
                best_plane = plane
                break
        else:
            for plane, res in results_per_plane.items():
                if res['magic_detection']['is_archive']:
                    best_plane = plane
                    break
            else:
                highest_entropy_plane = -1
                highest_entropy = -1
                for plane, res in results_per_plane.items():
                    ent = res['entropy_analysis']['entropy']
                    if ent > 7.0 and ent > highest_entropy:
                        highest_entropy = ent
                        highest_entropy_plane = plane
                if highest_entropy_plane != -1:
                    best_plane = highest_entropy_plane
                else:
                    best_plane = 0
                    
        best_result = results_per_plane[best_plane]
        best_bytes = extract_lsb_bits(img_array, best_plane, roi_coords)
        
        text_preview = None
        if best_result['magic_detection']['is_text'] or best_result['magic_detection']['detected_type'] == 'Unknown Binary':
            try:
                decoded = best_bytes[:200].decode('utf-8', errors='ignore')
                printable = ''.join(c for c in decoded if c.isprintable())
                if len(printable) > 20:
                    text_preview = printable[:200]
                else:
                    text_preview = None
            except Exception as e:
                pass  # bytes not valid utf-8 — normal for binary payloads
                
        return {
            'extracted': True,
            'method': 'multi_plane_lsb',
            'best_plane': best_plane,
            'plane_results': results_per_plane,
            'payload_type': best_result['magic_detection']['detected_type'],
            'payload_entropy': best_result['entropy_analysis']['entropy'],
            'payload_class': best_result['entropy_analysis']['payload_class'],
            'is_executable': best_result['magic_detection']['is_executable'],
            'is_archive': best_result['magic_detection']['is_archive'],
            'payload_size_bytes': len(best_bytes),
            'payload_bytes': best_bytes,
            'text_preview': text_preview,
            'first_32_bytes_hex': best_result['first_32_bytes_hex'],
            'roi_used': roi_coords is not None,
            'image_dimensions': (w, h),
            'total_pixels': w * h,
            'error': None
        }
    except Exception as e:
        return {'extracted': False, 'error': str(e)}

def attempt_adaptive_extraction(filepath: str) -> Dict:
    try:
        img = Image.open(filepath).convert('YCbCr')
        y_channel = np.array(img.split()[0], dtype=np.float32)
        h, w = y_channel.shape
        
        mid_freq_energy = []
        modified_coeff_count = 0
        total_blocks = 0
        
        for i in range(0, h-7, 8):
            for j in range(0, w-7, 8):
                block = y_channel[i:i+8, j:j+8]
                dct_block = cv2.dct(block.astype(np.float32))
                
                mid_coeffs = dct_block[2:6, 2:6].flatten()
                
                q = 8.0
                for coeff in mid_coeffs:
                    rounded = round(coeff / q) * q
                    if abs(coeff - rounded) < 0.5:
                        modified_coeff_count += 1
                        
                mid_freq_energy.append(float(np.sum(np.abs(mid_coeffs))))
                total_blocks += 1
                
        avg_mid_energy = np.mean(mid_freq_energy) if mid_freq_energy else 0
        modification_ratio = modified_coeff_count / max(1, total_blocks * 16)
        
        if modification_ratio > 0.6:
            adaptive_detected = True
            estimated_payload_bits = int(modification_ratio * total_blocks * 4)
            estimated_payload_bytes = estimated_payload_bits // 8
            confidence = 'MEDIUM'
        else:
            adaptive_detected = False
            estimated_payload_bytes = 0
            confidence = 'LOW'
            
        return {
            'adaptive_stego_detected': adaptive_detected,
            'modification_ratio': round(modification_ratio, 4),
            'estimated_payload_bytes': estimated_payload_bytes,
            'estimated_payload_kb': round(estimated_payload_bytes/1024, 2),
            'confidence': confidence,
            'note': 'Adaptive stego detected. Full extraction requires embedding key.' if adaptive_detected else 'No adaptive stego signature detected in DCT domain',
            'total_blocks_analysed': total_blocks,
            'error': None
        }
    except Exception as e:
        return {'error': str(e)}

# === SECTION 4: DOCUMENT PAYLOAD EXTRACTOR ===

def extract_document_payload(filepath: str, text: str = None) -> Dict[str, Any]:
    try:
        if text is None:
            # A stub for actually reading the file based on extension.
            # In real execution, might use fitz for PDF, python-docx for DOCX, etc.
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                text = f.read()
                
        ZW_MAP = {
            '\u200b': 0,
            '\u200c': 1,
            '\u200d': None,
        }
        bits = []
        for char in text:
            if char in ZW_MAP and ZW_MAP[char] is not None:
                bits.append(ZW_MAP[char])
                
        zw_payload_bytes = b''
        if len(bits) >= 8:
            n_bytes = len(bits) // 8
            result = bytearray()
            for i in range(n_bytes):
                byte_val = 0
                for j in range(8):
                    byte_val |= (bits[i*8 + j] << j)
                result.append(byte_val)
            zw_payload_bytes = bytes(result)
            
        CYRILLIC_TO_LATIN = {
            '\u0430': 'a', '\u0435': 'e', '\u043e': 'o',
            '\u0440': 'p', '\u0441': 'c', '\u0445': 'x',
            '\u0443': 'y', '\u0456': 'i',
        }
        homoglyph_positions = []
        for i, char in enumerate(text):
            if char in CYRILLIC_TO_LATIN:
                homoglyph_positions.append({
                    'position': i,
                    'found': char,
                    'latin_equivalent': CYRILLIC_TO_LATIN[char],
                    'unicode': hex(ord(char))
                })
                
        ws_bits = []
        words = text.split(' ')
        for i in range(len(words)-1):
            start = text.find(words[i]) + len(words[i])
            end = text.find(words[i+1], start)
            trailing = len(text[start:end])
            if trailing >= 2:
                ws_bits.append(1)
            else:
                ws_bits.append(0)
                
        ws_payload_bytes = b''
        if len(ws_bits) >= 8:
            n_bytes = len(ws_bits) // 8
            result = bytearray()
            for i in range(n_bytes):
                byte_val = 0
                for j in range(8):
                    byte_val |= (ws_bits[i*8+j] << j)
                result.append(byte_val)
            ws_payload_bytes = bytes(result)
            
        zw_preview = None
        if zw_payload_bytes:
            try:
                decoded = zw_payload_bytes.decode('utf-8', errors='ignore')
                printable = ''.join(c for c in decoded if c.isprintable())
                if len(printable) > 5:
                    zw_preview = printable[:200]
            except Exception as e:
                pass  # bytes not valid utf-8 — normal for binary payloads
                
        extracted = len(zw_payload_bytes) > 0 or len(homoglyph_positions) > 0 or len(ws_payload_bytes) > 0
        
        payload_type = 'Unknown'
        entropy = 0.0
        if zw_payload_bytes:
            payload_type = 'Zero-Width Characters'
            entropy_res = classify_payload_entropy(zw_payload_bytes)
            entropy = entropy_res['entropy'] if entropy_res else 0.0
        elif ws_payload_bytes:
            payload_type = 'Whitespace/Homoglyph'
            entropy_res = classify_payload_entropy(ws_payload_bytes)
            entropy = entropy_res['entropy'] if entropy_res else 0.0
        elif extracted:
            payload_type = 'Whitespace/Homoglyph'
            
        return {
            'extracted': extracted,
            'payload_type': payload_type,
            'payload_entropy': entropy,
            'is_executable': False,
            'zero_width_bits_found': len(bits),
            'zero_width_payload_bytes': len(zw_payload_bytes),
            'zero_width_preview': zw_preview,
            'zero_width_entropy': classify_payload_entropy(zw_payload_bytes) if zw_payload_bytes else None,
            'homoglyph_count': len(homoglyph_positions),
            'homoglyph_positions': homoglyph_positions[:20],
            'whitespace_bits_found': len(ws_bits),
            'whitespace_payload_bytes': len(ws_payload_bytes),
            'payload_bytes': zw_payload_bytes if zw_payload_bytes else (ws_payload_bytes if ws_payload_bytes else b''),
            'text_length_analysed': len(text),
            'error': None
        }
    except Exception as e:
        return {'extracted': False, 'error': str(e)}

# === SECTION 5: VIDEO PAYLOAD EXTRACTOR ===

def extract_video_payload(filepath: str) -> Dict:
    try:
        cap = cv2.VideoCapture(str(filepath))
        total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        fps = cap.get(cv2.CAP_PROP_FPS)
        
        if total_frames <= 8:
            indices = list(range(total_frames))
        else:
            step = total_frames // 8
            indices = [i * step for i in range(8)]
            
        frame_payloads = []
        frame_entropies = []
        
        for idx in indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ret, frame = cap.read()
            if not ret:
                continue
                
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img_array = np.array(rgb, dtype=np.uint8)
            
            lsb_bytes = extract_lsb_bits(img_array, 0, None)
            
            e = shannon_entropy(lsb_bytes[:2048])
            frame_entropies.append(e)
            frame_payloads.append(lsb_bytes[:512])
            
        cap.release()
        
        if len(frame_entropies) >= 2:
            entropy_variance = float(np.var(frame_entropies))
            avg_entropy = float(np.mean(frame_entropies))
            consistent_payload = entropy_variance < 0.1
        else:
            entropy_variance = 0.0
            avg_entropy = 0.0
            consistent_payload = False
            
        best_magic = detect_magic_number(frame_payloads[0][:512]) if frame_payloads else {'detected_type': 'Unknown', 'is_executable': False}
        
        return {
            'extracted': len(frame_payloads) > 0,
            'frames_analysed': len(frame_entropies),
            'total_video_frames': total_frames,
            'fps': fps,
            'average_lsb_entropy': round(avg_entropy, 4),
            'entropy_variance': round(entropy_variance, 4),
            'consistent_payload_across_frames': consistent_payload,
            'payload_type': best_magic['detected_type'],
            'is_executable': best_magic['is_executable'],
            'payload_bytes': frame_payloads[0] if frame_payloads else b'',
            'first_frame_entropy': frame_entropies[0] if frame_entropies else 0,
            'first_frame_hex': frame_payloads[0][:16].hex() if frame_payloads else '',
            'note': 'Consistent LSB payload detected across frames' if consistent_payload else 'LSB appears to be natural camera noise',
            'error': None
        }
    except Exception as e:
        return {'extracted': False, 'error': str(e)}

# === SECTION 6: MAIN ENTRY POINT ===

def run_extraction(filepath: str, session_id: str, sha3_hash: str, layer2_result: Dict = None, roi_coords: Tuple = None) -> Dict[str, Any]:
    try:
        name = Path(filepath).name
        print('[LAYER3] Payload extraction starting...')
        print('[LAYER3] File: ' + name)
        
        # Log to CoC: EXTRACTION_TRIGGERED
        try:
            if 'coc' in globals() and hasattr(coc, 'log_event'):
                coc.log_event(session_id, 'EXTRACTION_TRIGGERED', 'Layer 3 extraction started')
        except Exception as coc_err:
            print(f'[LAYER3] CoC log failed (extraction triggered): {coc_err}')
            
        file_type = None
        if layer2_result and 'file_type' in layer2_result:
            file_type = layer2_result['file_type']
        else:
            ext = Path(filepath).suffix.lower()
            if ext in ['.png', '.jpg', '.jpeg', '.gif']:
                file_type = 'IMAGE'
            elif ext in ['.mp4', '.avi', '.mkv']:
                file_type = 'VIDEO'
            else:
                file_type = 'DOCUMENT'
                
        if layer2_result and 'grad_cam_roi' in layer2_result and roi_coords is None:
            roi_coords = layer2_result['grad_cam_roi']
            print('[LAYER3] Using Grad-CAM ROI for targeted extraction')
        else:
            print('[LAYER3] No ROI available, full extraction mode')
            
        extraction_result = {}
        adaptive_result = {}
        
        if file_type == 'IMAGE':
            extraction_result = extract_image_payload(filepath, roi_coords)
            adaptive_result = attempt_adaptive_extraction(filepath)
        elif file_type == 'VIDEO':
            extraction_result = extract_video_payload(filepath)
        elif file_type == 'DOCUMENT':
            extraction_result = extract_document_payload(filepath, text=None)
            
        result = {
            'file_type': file_type,
            'extraction_results': extraction_result,
            'session_id': session_id,
            'filepath': filepath,
            'sha3_hash': sha3_hash,
        }
        
        if file_type == 'IMAGE':
            result['adaptive_analysis'] = adaptive_result
            
        payload_type = extraction_result.get('payload_type', 'Unknown')
        entropy = extraction_result.get('payload_entropy', 0.0)
        is_executable = extraction_result.get('is_executable', False)
        
        print('[LAYER3] Extraction complete')
        print('[LAYER3] Payload type: ' + str(payload_type))
        print('[LAYER3] Payload entropy: ' + str(entropy))
        if is_executable:
            print('[LAYER3] !!! EXECUTABLE PAYLOAD DETECTED !!!')
            
        # Log to CoC: EXTRACTION_COMPLETE with payload type
        try:
            if 'coc' in globals() and hasattr(coc, 'log_event'):
                coc.log_event(session_id, 'EXTRACTION_COMPLETE', f'Payload type: {payload_type}')
        except Exception as coc_err:
            print(f'[LAYER3] CoC log failed (extraction complete): {coc_err}')

        # HOOK A: CAPA static capability analysis on extracted executable payload
        payload_bytes = extraction_result.get('payload_bytes', b'')
        magic_hex = extraction_result.get('first_32_bytes_hex', '')
        is_pe_or_elf = (
            is_executable
            or magic_hex.startswith('4d5a')
            or magic_hex.startswith('7f454c46')
            or (isinstance(payload_bytes, (bytes, bytearray)) and (payload_bytes.startswith(b'MZ') or payload_bytes.startswith(b'\x7fELF')))
        )

        if is_pe_or_elf:
            import uuid
            try:
                from capa_analyzer import analyze_with_capa
            except Exception:
                analyze_with_capa = None

            data_to_write = payload_bytes
            if (not data_to_write or len(data_to_write) == 0) and filepath and os.path.exists(filepath):
                try:
                    with open(filepath, 'rb') as f:
                        hdr = f.read(4)
                        if hdr.startswith(b'MZ') or hdr.startswith(b'\x7fELF'):
                            f.seek(0)
                            data_to_write = f.read()
                except Exception:
                    pass

            sandbox_dir = getattr(config, 'SANDBOX_DIR', Path('sandbox'))
            if isinstance(sandbox_dir, str):
                sandbox_dir = Path(sandbox_dir)
            sandbox_dir.mkdir(parents=True, exist_ok=True)

            temp_payload_path = sandbox_dir / f"capa_extracted_{uuid.uuid4().hex}.bin"
            capa_res = None
            try:
                with open(temp_payload_path, 'wb') as f:
                    f.write(data_to_write or b'')

                if analyze_with_capa:
                    print(f"[LAYER3] Running CAPA capability analysis on extracted payload ({len(data_to_write or b'')} bytes)...")
                    capa_res = analyze_with_capa(str(temp_payload_path), timeout_seconds=120)
                else:
                    capa_res = {
                        'status': 'UNAVAILABLE',
                        'capability_count': 0,
                        'capabilities': [],
                        'attack_tactics': [],
                        'attack_techniques': [],
                        'risk_indicators': [],
                        'plain_english': 'CAPA capability analysis engine is not available.',
                        'error': 'capa_analyzer could not be imported.'
                    }
            except Exception as capa_err:
                print(f"[LAYER3] WARNING: CAPA analysis on payload failed: {capa_err}")
                capa_res = {
                    'status': 'ERROR',
                    'capability_count': 0,
                    'capabilities': [],
                    'attack_tactics': [],
                    'attack_techniques': [],
                    'risk_indicators': [],
                    'plain_english': f"CAPA analysis failed: {capa_err}",
                    'error': str(capa_err)
                }
            finally:
                if temp_payload_path.exists():
                    try:
                        temp_payload_path.unlink()
                    except Exception:
                        pass

            result['capa_analysis'] = capa_res
            st = capa_res.get('status', 'UNKNOWN') if capa_res else 'UNKNOWN'
            cnt = capa_res.get('capability_count', 0) if capa_res else 0
            print(f"[LAYER3] CAPA analysis complete: status={st}, capabilities={cnt}")

            # Log to CoC: CAPA_ANALYSIS with status and capability count
            try:
                if 'coc' in globals() and hasattr(coc, 'log_event'):
                    coc.log_event(session_id, 'CAPA_ANALYSIS', f"status={st}, capability_count={cnt}")
                if 'coc' in globals() and hasattr(coc, 'log_action'):
                    coc.log_action(
                        session_id,
                        filepath,
                        sha3_hash,
                        'CAPA_ANALYSIS',
                        'SUCCESS' if st == 'COMPLETE' else st,
                        f"status={st}, capability_count={cnt}"
                    )
            except Exception as coc_err:
                print(f"[LAYER3] CoC log failed (CAPA_ANALYSIS): {coc_err}")

        return result
    except Exception as e:
        try:
            if 'utils' in globals() and hasattr(utils, 'log_error'):
                utils.log_error(e)
            else:
                print(f"[LAYER3 ERROR] {e}")
        except Exception as log_err:
            print(f'[LAYER3 ERROR] Could not log error: {log_err}')
        return {'error': str(e)}

if __name__ == '__main__':
    print('=== LAYER 3 EXTRACTION TEST ===')
    print()

    print('Test 1: Entropy classification')
    test_cases = [
        (bytes([0]*100), 'STRUCTURED_DATA_OR_EMPTY'),
        (bytes(range(256))*4, 'BINARY_DATA'),
        (b'Hello world this is natural English text ' * 10, 'NATURAL_LANGUAGE_OR_CODE'),
        (os.urandom(1000), 'ENCRYPTED_OR_COMPRESSED'),
    ]
    for data, expected_class in test_cases:
        result = classify_payload_entropy(data)
        status = 'PASS' if result['payload_class'] == expected_class else 'FAIL'
        print(f'  {status}: entropy={result["entropy"]:.2f} class={result["payload_class"]}')
    print()

    print('Test 2: Magic number detection')
    test_magic = [
        (b'\x4d\x5a' + b'\x00'*100, True, False),
        (b'\x89\x50\x4e\x47' + b'\x00'*100, False, False),
        (b'\x50\x4b\x03\x04' + b'\x00'*100, False, True),
        (b'Hello world this is plain text', False, False),
    ]
    for data, expect_exe, expect_archive in test_magic:
        result = detect_magic_number(data)
        exe_ok = result['is_executable'] == expect_exe
        arc_ok = result['is_archive'] == expect_archive
        status = 'PASS' if exe_ok and arc_ok else 'FAIL'
        print(f'  {status}: {result["detected_type"]}')
    print()

    print('Test 3: Image LSB multi-plane extraction')
    from PIL import Image as PILImage
    import numpy as np
    import os
    test_arr = np.random.randint(50, 200, (64, 64, 3), dtype=np.uint8)
    payload = np.random.randint(0, 2, (64, 64, 3), dtype=np.uint8)
    test_arr = (test_arr & 0xFE) | payload
    PILImage.fromarray(test_arr).save('test_layer3_img.png')
    result = extract_image_payload('test_layer3_img.png')
    print(f'  Extracted: {result["extracted"]}')
    print(f'  Best plane: {result["best_plane"]}')
    print(f'  Payload size: {result["payload_size_bytes"]} bytes')
    print(f'  Payload class: {result["payload_class"]}')
    print(f'  Dimensions: {result["image_dimensions"]}')
    os.remove('test_layer3_img.png')
    print()

    print('Test 4: Document payload extraction')
    test_text = 'Hello\u200b world\u200c this\u200b is\u200c a\u200b test'
    result = extract_document_payload('dummy.txt', text=test_text)
    print(f'  ZW bits found: {result["zero_width_bits_found"]}')
    print(f'  ZW payload bytes: {result["zero_width_payload_bytes"]}')
    print(f'  Homoglyphs: {result["homoglyph_count"]}')
    print()

    print('=== ALL TESTS COMPLETE ===')
