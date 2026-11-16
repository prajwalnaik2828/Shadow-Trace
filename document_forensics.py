import re
import math
import struct
import zipfile
import os
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import utils
import config

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

def check_magic_number(filepath):
    try:
        MAGIC_NUMBERS = {
            b'\x25\x50\x44\x46': 'PDF',
            b'\x50\x4b\x03\x04': 'ZIP_DOCX',
            b'\xd0\xcf\x11\xe0': 'OLE_DOC',
            b'\x1f\x8b\x08':     'GZIP',
            b'\x4d\x5a':         'EXE_DLL',
            b'\x7f\x45\x4c\x46': 'ELF',
            b'\xff\xd8\xff':     'JPEG',
            b'\x89\x50\x4e\x47': 'PNG',
            b'\x52\x61\x72\x21': 'RAR',
            b'\x37\x7a\xbc\xaf': 'SEVENZIP'
        }
        with open(filepath, 'rb') as f:
            data = f.read(8)
        
        detected_type = 'UNKNOWN'
        for magic, t_str in sorted(MAGIC_NUMBERS.items(), key=lambda x: -len(x[0])):
            if data[:len(magic)] == magic:
                detected_type = t_str
                break
                
        ext = Path(filepath).suffix.lower()
        mismatch = False
        
        if detected_type == 'PDF' and ext != '.pdf':
            mismatch = True
        elif detected_type == 'ZIP_DOCX' and ext not in ['.docx', '.xlsx', '.zip']:
            mismatch = True
        elif detected_type == 'OLE_DOC' and ext not in ['.doc', '.xls', '.ppt']:
            mismatch = True
        elif detected_type == 'EXE_DLL' and ext not in ['.exe', '.dll']:
            mismatch = True
        elif detected_type == 'ELF' and ext not in ['.elf', '']:
            mismatch = True
        elif detected_type == 'JPEG' and ext not in ['.jpg', '.jpeg']:
            mismatch = True
        elif detected_type == 'PNG' and ext != '.png':
            mismatch = True
            
        return {
            'detected_type': detected_type,
            'claimed_extension': ext,
            'mismatch': mismatch,
            'description': f"Detected {detected_type} but claimed {ext}" if mismatch else "Match"
        }
    except Exception as e:
        utils.log_error(str(e))
        return {
            'detected_type': 'ERROR',
            'claimed_extension': 'ERROR',
            'mismatch': False,
            'description': str(e)
        }

def audit_pdf_structure(filepath):
    try:
        data = open(filepath, 'rb').read()
        obj_matches = re.findall(rb'\d+ \d+ obj', data)
        obj_count = len(obj_matches)
        
        xref_entries = re.findall(rb'(\d+) (\d+) (f|n)\s', data)
        xref_count = len(xref_entries)
        free_count = sum(1 for _,_,t in xref_entries if t==b'f')
        
        has_javascript = bool(re.search(rb'/JavaScript|/JS\b', data))
        has_embedded_file = bool(re.search(rb'/EmbeddedFile|/Filespec', data, re.IGNORECASE))
        stream_count = len(re.findall(rb'stream\r?\n', data))
        has_openaction = bool(re.search(rb'/OpenAction', data))
        
        score = 0.0
        if free_count > 5: score += 0.20
        if has_javascript: score += 0.50
        if has_embedded_file: score += 0.35
        if has_openaction: score += 0.25
        
        if obj_count > 0 and xref_count > 0:
            diff_ratio = abs(obj_count - xref_count) / max(obj_count, 1)
            if diff_ratio > 0.2:
                score += min(0.25, diff_ratio)
        score = min(1.0, score)
        
        if score > 0.65:
            verdict = 'STEGO_DETECTED'
        elif score > 0.35:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'CLEAN'
            
        return {
            'score': round(score, 4),
            'verdict': verdict,
            'obj_count': obj_count,
            'xref_count': xref_count,
            'free_obj_count': free_count,
            'has_javascript': has_javascript,
            'has_embedded_file': has_embedded_file,
            'has_openaction': has_openaction,
            'stream_count': stream_count,
            'error': None
        }
    except Exception as e:
        utils.log_error(str(e))
        return {
            'score': 0.0,
            'verdict': 'ERROR',
            'error': str(e)
        }

def audit_docx_structure(filepath):
    try:
        with zipfile.ZipFile(filepath, 'r') as zf:
            members = zf.namelist()
            
            EXPECTED_MEMBERS = {
                'word/document.xml', 'word/styles.xml',
                'word/settings.xml', '[Content_Types].xml',
                '_rels/.rels', 'word/_rels/document.xml.rels',
                'docProps/app.xml', 'docProps/core.xml',
                'word/theme/theme1.xml', 'word/fontTable.xml',
                'word/webSettings.xml', 'word/endnotes.xml',
                'word/footnotes.xml'
            }
            
            custom_xml = [m for m in members if 'custom' in m.lower()]
            unusual = [m for m in members
                       if m not in EXPECTED_MEMBERS
                       and not m.startswith('word/media/')
                       and not m.startswith('word/embeddings/')]
                       
            doc_xml = ""
            rsid_values = []
            unique_rsids = 0
            comments_in_doc = 0
            
            if 'word/document.xml' in members:
                doc_xml = zf.read('word/document.xml').decode('utf-8', errors='ignore')
                rsid_values = re.findall(r'rsid[A-Z]*="([A-F0-9]+)"', doc_xml)
                unique_rsids = len(set(rsid_values))
                comments_in_doc = len(re.findall(r'<w:comment\b', doc_xml))
                
            score = 0.0
            if len(custom_xml) > 0: score += 0.35
            if len(unusual) > 5: score += 0.20
            if unique_rsids > 100: score += 0.20
            if comments_in_doc > 20: score += 0.15
            score = min(1.0, score)
            
            if score > 0.55:
                verdict = 'STEGO_DETECTED'
            elif score > 0.30:
                verdict = 'SUSPICIOUS'
            else:
                verdict = 'CLEAN'
                
            return {
                'score': round(score, 4),
                'verdict': verdict,
                'total_members': len(members),
                'custom_xml_count': len(custom_xml),
                'unusual_members_count': len(unusual),
                'unique_rsid_count': unique_rsids,
                'hidden_comments_count': comments_in_doc,
                'error': None
            }
    except Exception as e:
        utils.log_error(str(e))
        return {
            'score': 0.0,
            'verdict': 'ERROR',
            'error': str(e)
        }

def analyse_entropy(filepath):
    try:
        data = open(filepath, 'rb').read()
        file_size = len(data)
        
        overall_entropy = shannon_entropy(data)
        stream_entropies = []
        
        pattern = re.compile(rb'stream\r?\n(.*?)endstream', re.DOTALL)
        streams = pattern.findall(data)
        for stream in streams:
            if len(stream) > 64:
                e = shannon_entropy(stream)
                stream_entropies.append(e)
                
        high_entropy_streams = [e for e in stream_entropies if e > 7.2]
        
        tail_entropy = shannon_entropy(data[-1024:]) if len(data) > 1024 else 0.0
        
        score = 0.0
        if overall_entropy > 7.5: score += 0.30
        if tail_entropy > 7.8: score += 0.40
        n_high = len(high_entropy_streams)
        if n_high > 0:
            score += min(0.40, n_high * 0.12)
        score = min(1.0, score)
        
        if score > 0.60:
            verdict = 'STEGO_DETECTED'
        elif score > 0.30:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'CLEAN'
            
        return {
            'score': round(score, 4),
            'verdict': verdict,
            'overall_entropy': round(overall_entropy, 4),
            'tail_entropy': round(tail_entropy, 4),
            'high_entropy_stream_count': n_high,
            'total_streams_analysed': len(stream_entropies),
            'error': None
        }
    except Exception as e:
        utils.log_error(str(e))
        return {
            'score': 0.0,
            'verdict': 'ERROR',
            'error': str(e)
        }

def detect_unicode_stego(text: str):
    try:
        ZW_CHARS = [
            ('\u200b', 'ZERO_WIDTH_SPACE'),
            ('\u200c', 'ZERO_WIDTH_NON_JOINER'),
            ('\u200d', 'ZERO_WIDTH_JOINER'),
            ('\u200e', 'LTR_MARK'),
            ('\u200f', 'RTL_MARK'),
            ('\ufeff', 'BOM'),
            ('\u2060', 'WORD_JOINER'),
            ('\u2062', 'INVISIBLE_TIMES'),
            ('\u2063', 'INVISIBLE_SEPARATOR'),
            ('\u2009', 'THIN_SPACE'),
            ('\u200a', 'HAIR_SPACE')
        ]
        
        zw_findings = {}
        total_zw = 0
        for char, name in ZW_CHARS:
            count = text.count(char)
            if count > 0:
                zw_findings[name] = count
                total_zw += count
                
        cyrillic_count = len(re.findall(r'[\u0400-\u04ff]', text))
        greek_count = len(re.findall(r'[\u0370-\u03ff]', text))
        double_spaces = len(re.findall(r'  +', text))
        
        score = 0.0
        if total_zw > 0: score += min(0.60, total_zw * 0.05)
        if cyrillic_count > 3: score += min(0.40, cyrillic_count * 0.04)
        if greek_count > 3: score += min(0.20, greek_count * 0.04)
        if double_spaces > 10: score += min(0.20, double_spaces * 0.01)
        score = min(1.0, score)
        
        if score > 0.40 or total_zw > 5:
            verdict = 'STEGO_DETECTED'
        elif score > 0.15 or total_zw > 0:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'CLEAN'
            
        return {
            'score': round(score, 4),
            'verdict': verdict,
            'zero_width_total': total_zw,
            'zero_width_findings': zw_findings,
            'cyrillic_count': cyrillic_count,
            'greek_count': greek_count,
            'double_spaces': double_spaces,
            'error': None
        }
    except Exception as e:
        utils.log_error(str(e))
        return {
            'score': 0.0,
            'verdict': 'ERROR',
            'error': str(e)
        }

def run_stream1_structural(filepath):
    try:
        ext = Path(filepath).suffix.lower()
        if ext == '.pdf':
            return audit_pdf_structure(filepath)
        elif ext in ['.docx', '.doc']:
            return audit_docx_structure(filepath)
        elif ext == '.txt':
            return {
                'score': 0.0,
                'verdict': 'CLEAN',
                'note': 'Plain text has no binary structure to audit',
                'error': None
            }
        else:
            return {
                'score': 0.0,
                'verdict': 'UNSUPPORTED',
                'note': f'Extension {ext} not supported for structural audit',
                'error': None
            }
    except Exception as e:
        utils.log_error(str(e))
        return {
            'score': 0.0,
            'verdict': 'ERROR',
            'error': str(e)
        }

def run_document_forensics(filepath, text=None):
    try:
        stream1 = run_stream1_structural(filepath)
        stream3 = analyse_entropy(filepath)
        magic_result = check_magic_number(filepath)
        
        stream4 = {
            'score': 0.7 if magic_result.get('mismatch') else 0.0,
            'verdict': 'STEGO_DETECTED' if magic_result.get('mismatch') else 'CLEAN',
            'magic_check': magic_result,
            'error': None
        }
        
        if text is not None:
            stream2b = detect_unicode_stego(text)
        else:
            stream2b = {
                'score': 0.0,
                'verdict': 'NO_TEXT',
                'note': 'No text provided',
                'error': None
            }
            
        contributions = []
        if stream1.get('error') is None and stream1.get('verdict') != 'UNSUPPORTED':
            contributions.append((stream1['score'], 0.30))
        if stream2b.get('error') is None and stream2b.get('verdict') != 'NO_TEXT':
            contributions.append((stream2b['score'], 0.25))
        if stream3.get('error') is None:
            contributions.append((stream3['score'], 0.25))
        if stream4.get('error') is None:
            contributions.append((stream4['score'], 0.20))
            
        if not contributions:
            combined_score = 0.0
        else:
            total_weight = sum(w for _, w in contributions)
            combined_score = sum(s * w for s, w in contributions) / total_weight
            combined_score = round(min(1.0, max(0.0, combined_score)), 4)
            
        if combined_score > 0.55:
            verdict = 'STEGO_DETECTED'
        elif combined_score > 0.30:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'CLEAN'
            
        return {
            'combined_score': combined_score,
            'verdict': verdict,
            'stream1_structural': stream1,
            'stream2b_unicode': stream2b,
            'stream3_entropy': stream3,
            'stream4_metadata': stream4,
            'filepath': str(filepath),
            'error': None
        }
    except Exception as e:
        utils.log_error(str(e))
        return {
            'combined_score': 0.0,
            'verdict': 'ERROR',
            'error': str(e)
        }

if __name__ == '__main__':
    print('=== DOCUMENT FORENSICS TEST ===')
    print()

    # Test 1: Shannon entropy on known inputs
    print('Test 1 - Shannon entropy:')
    import os
    import math
    # All same byte = entropy 0
    all_same = bytes([42] * 256)
    h_same = shannon_entropy(all_same)
    print(f'  All same bytes:   {h_same:.4f} (expected 0.0)')
    assert h_same < 0.001, f'Expected 0, got {h_same}'

    # All unique = entropy 8.0
    all_unique = bytes(range(256))
    h_unique = shannon_entropy(all_unique)
    print(f'  All unique bytes: {h_unique:.4f} (expected 8.0)')
    assert h_unique > 7.99, f'Expected 8.0, got {h_unique}'
    print('  Test 1: PASS')
    print()

    # Test 2: Magic number on a real file
    print('Test 2 - Magic number detection:')
    test_pdf_bytes = b'%PDF-1.4\ntest content'
    with open('test_magic.pdf', 'wb') as f:
        f.write(test_pdf_bytes)
    result = check_magic_number('test_magic.pdf')
    print(f'  Detected type: {result.get("detected_type")}')
    print(f'  Extension:     {result.get("claimed_extension")}')
    print(f'  Mismatch:      {result.get("mismatch")}')
    assert result.get('detected_type') == 'PDF', 'Should detect PDF'
    assert result.get('mismatch') == False, 'No mismatch expected'
    os.remove('test_magic.pdf')
    print('  Test 2: PASS')
    print()

    # Test 3: Magic number mismatch
    print('Test 3 - Magic number mismatch detection:')
    # PNG bytes saved with .pdf extension
    png_bytes = b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a' + b'\x00' * 100
    with open('test_mismatch.pdf', 'wb') as f:
        f.write(png_bytes)
    result2 = check_magic_number('test_mismatch.pdf')
    print(f'  Detected type: {result2.get("detected_type")}')
    print(f'  Extension:     {result2.get("claimed_extension")}')
    print(f'  Mismatch:      {result2.get("mismatch")}')
    assert result2.get('mismatch') == True, 'Mismatch expected'
    os.remove('test_mismatch.pdf')
    print('  Test 3: PASS')
    print()

    # Test 4: Unicode stego detection
    print('Test 4 - Unicode stego detection:')
    clean_text = 'The system processed all requests normally.'
    stego_text = 'The\u200b sys\u200ctem\u200d pro\u200bcessed all requests.'
    r_clean = detect_unicode_stego(clean_text)
    r_stego = detect_unicode_stego(stego_text)
    print(f'  Clean verdict: {r_clean["verdict"]}')
    print(f'  Clean ZW total: {r_clean["zero_width_total"]}')
    print(f'  Stego verdict: {r_stego["verdict"]}')
    print(f'  Stego ZW total: {r_stego["zero_width_total"]}')
    assert r_clean['zero_width_total'] == 0, 'Clean should have 0 ZW chars'
    assert r_stego['zero_width_total'] > 0, 'Stego should have ZW chars'
    assert r_stego['score'] > r_clean['score'], 'Stego should score higher'
    print('  Test 4: PASS')
    print()

    # Test 5: run_document_forensics on minimal PDF
    print('Test 5 - Full forensics pipeline:')
    minimal_pdf = (
        b'%PDF-1.4\n'
        b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n'
        b'2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n'
        b'3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n'
        b'xref\n0 4\n'
        b'0000000000 65535 f\r\n'
        b'0000000009 00000 n\r\n'
        b'0000000058 00000 n\r\n'
        b'0000000115 00000 n\r\n'
        b'trailer\n<< /Size 4 /Root 1 0 R >>\n'
        b'startxref\n190\n%%EOF'
    )
    with open('test_forensics.pdf', 'wb') as f:
        f.write(minimal_pdf)
    result3 = run_document_forensics(
        'test_forensics.pdf',
        text='The quick brown fox jumped over the lazy dog.'
    )
    print(f'  Stream 1 verdict: {result3["stream1_structural"]["verdict"]}')
    print(f'  Stream 2b verdict: {result3["stream2b_unicode"]["verdict"]}')
    print(f'  Stream 3 verdict: {result3["stream3_entropy"]["verdict"]}')
    print(f'  Stream 4 verdict: {result3["stream4_metadata"]["verdict"]}')
    print(f'  Combined score:   {result3["combined_score"]}')
    print(f'  Final verdict:    {result3["verdict"]}')
    os.remove('test_forensics.pdf')
    print('  Test 5: PASS')
    print()

    print('=== ALL TESTS COMPLETE ===')
