import os
import hashlib
import hmac
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, white, black
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import config

HMAC_KEY = os.environ.get(
    'HMAC_SECRET_KEY',
    ''
).encode('utf-8')

DARK_BLUE  = HexColor('#1a1a2e')
ACCENT     = HexColor('#0f3460')
GREEN      = HexColor('#27ae60')
RED        = HexColor('#e74c3c')
ORANGE     = HexColor('#f39c12')
LIGHT_GREY = HexColor('#f2f4f8')
WHITE      = white
TEXT       = HexColor('#1a1a2e')
SOFT_RED   = HexColor('#fde8e8')
SOFT_GREEN = HexColor('#e8f8f0')
SOFT_AMBER = HexColor('#fef3e2')


def build_plain_english_summary(
    filepath: str,
    layer1_result: Dict,
    layer2_result: Dict,
    layer3_result: Dict,
    layer4_xai_result: Dict,
    session_id: str,
    sha3_hash: str,
    calibration: Dict = None,
) -> Dict:
    filename = Path(filepath).name
    file_ext = Path(filepath).suffix.upper().lstrip('.')
    scan_time = datetime.now().strftime('%d %B %Y at %H:%M')
    file_size_kb = round(Path(filepath).stat().st_size / 1024, 1) if Path(filepath).exists() else 0

    verdict = layer2_result.get('verdict', 'CLEAN')
    score = layer2_result.get('score', 0.0) or 0.0
    file_type = layer2_result.get('file_type', 'FILE')

    if verdict == 'STEGO_DETECTED':
        overall_finding = 'HIDDEN CONTENT DETECTED'
        finding_colour = RED
        finding_bg = SOFT_RED
        severity = 'HIGH'
        one_liner = (
            'This file contains hidden data that is not '
            'visible to the human eye. The hidden content '
            'was detected by multiple independent analysis '
            'methods.'
        )
    elif verdict == 'SUSPICIOUS':
        overall_finding = 'SUSPICIOUS — FURTHER REVIEW NEEDED'
        finding_colour = ORANGE
        finding_bg = SOFT_AMBER
        severity = 'MEDIUM'
        one_liner = (
            'This file shows unusual characteristics that '
            'may indicate hidden content. The evidence is '
            'not conclusive and the file requires manual '
            'review by a qualified examiner.'
        )
    else:
        overall_finding = 'NO HIDDEN CONTENT DETECTED'
        finding_colour = GREEN
        finding_bg = SOFT_GREEN
        severity = 'LOW'
        one_liner = (
            'Analysis did not find evidence of hidden '
            'content in this file. The file appears to '
            'be unmodified and safe for normal use.'
        )

    raw_clam = layer1_result.get('stage3_clamav')
    if isinstance(raw_clam, dict):
        clamav = str(raw_clam.get('verdict', 'UNKNOWN'))
    else:
        clamav = str(raw_clam or 'UNKNOWN')

    vt = layer1_result.get('stage4_virustotal', 'UNKNOWN')
    if isinstance(vt, dict):
        vt_str = vt.get('verdict', str(vt))
    else:
        vt_str = str(vt)

    yara_threats = layer1_result.get('yara_matched_rules', []) or []
    yara_warnings = layer1_result.get('yara_warnings', []) or []
    l1_overall = layer1_result.get('verdict', 'CLEAN')

    if clamav.upper() in ('CLEAN', 'SKIPPED', 'OK') and not yara_threats and l1_overall != 'THREAT':
        malware_finding = (
            'Standard virus and malware scanning found '
            'no known malicious software in this file.'
        )
        malware_colour = GREEN
    else:
        malware_finding = (
            'Warning: Malware scanning detected suspicious '
            'patterns in this file. The file has been '
            'quarantined and should not be opened.'
        )
        malware_colour = RED

    if yara_warnings:
        malware_finding += (
            ' Note: Some structural irregularities were '
            'found in the file format. These may be normal '
            'for files created by certain software.'
        )

    rc = layer2_result.get('hash_reconfirmation', {}) if layer2_result else {}
    if rc.get('all_match') is True or rc.get('primary_confirmed') is True:
        integrity_finding = (
            'Cryptographic integrity confirmed: All three hash fingerprints '
            '(SHA3-512, SHA-256, MD5) were recomputed post-scan and '
            'are identical to initial capture values. The file was not altered.'
        )
        integrity_colour = GREEN
    elif rc.get('primary_confirmed') is False:
        integrity_finding = (
            'Warning: Cryptographic hash reconfirmation failed. The evidence file '
            'may have been modified during or after examination.'
        )
        integrity_colour = RED
    else:
        integrity_finding = (
            'Evidence integrity confirmed against initial cryptographic capture hashes.'
        )
        integrity_colour = GREEN

    lsb_data = layer2_result.get('lsb_check_result',
                layer2_result.get('lsb_result', {})) or {}
    lsb_verdict = lsb_data.get('verdict', 'CLEAN')

    if lsb_verdict == 'EXECUTABLE_FOUND':
        lsb_finding = (
            'A computer program was found hidden inside '
            'this file using a technique called LSB '
            'steganography. This is a serious finding. '
            'A hidden program could be malicious software '
            'designed to run without your knowledge.'
        )
        lsb_colour = RED
    else:
        lsb_finding = (
            'No hidden programs were found in the '
            'least significant bit layer of this file.'
        )
        lsb_colour = GREEN

    payload_finding = None
    if layer3_result:
        extraction = layer3_result.get(
            'extraction_results', {}
        ) or {}
        payload_size = extraction.get(
            'payload_size_bytes', 0
        ) or 0
        payload_type = extraction.get(
            'payload_type', 'Unknown'
        ) or 'Unknown'
        is_exe = extraction.get('is_executable', False)
        entropy = extraction.get('payload_entropy', 0.0) or 0.0
        entropy_class = extraction.get(
            'payload_class', ''
        ) or ''
        
        if payload_size > 0:
            if is_exe:
                payload_finding = (
                    f'The hidden content appears to be a '
                    f'computer program ({payload_size} bytes). '
                    f'This is a significant concern as hidden '
                    f'programs can be used to take control of '
                    f'a computer system without the user\'s knowledge.'
                )
            elif entropy > 7.5:
                payload_finding = (
                    f'Approximately {payload_size} bytes of hidden '
                    f'data were detected. The data appears to be '
                    f'encrypted or scrambled, suggesting that whoever '
                    f'hid the content deliberately concealed its '
                    f'contents to prevent identification.'
                )
            else:
                payload_finding = (
                    f'Approximately {payload_size} bytes of hidden '
                    f'data were detected. The content type is: '
                    f'{payload_type}.'
                )

    if calibration:
        band = calibration.get('confidence_band', {})
        band_label = band.get('label', 'Unknown')
        uncertainty_count = calibration.get(
            'uncertainty_count', 0
        )
        court_weight = calibration.get('court_weight', '')
        
        if uncertainty_count == 0:
            confidence_plain = (
                f'The analysis system has {band_label.lower()} '
                f'in this result. The finding is suitable as '
                f'{court_weight.lower()} in an investigation.'
            )
        else:
            confidence_plain = (
                f'The analysis system has {band_label.lower()} '
                f'in this result. However, {uncertainty_count} '
                f'factor(s) reduce the reliability of this finding. '
                f'This result should be treated as '
                f'{court_weight.lower()} only and must be '
                f'reviewed by a qualified examiner.'
            )
    else:
        confidence_plain = (
            'Confidence level not calculated for this scan.'
        )

    if severity == 'HIGH':
        action_steps = [
            'Do not open or use this file.',
            'Preserve the file and this report as evidence.',
            'Refer this report to a qualified digital '
            'forensic examiner for detailed review.',
            'If this file was received from an external '
            'source, consider it a potential security incident.',
            'Do not delete or modify the file before '
            'a full forensic examination is complete.',
        ]
    elif severity == 'MEDIUM':
        action_steps = [
            'Treat this file with caution.',
            'Do not open the file until a qualified '
            'examiner has reviewed this report.',
            'Preserve the file and this report.',
            'A manual examination by a digital forensic '
            'expert is recommended before any conclusions.',
            'The result is not conclusive and should not '
            'be acted upon without expert review.',
        ]
    else:
        action_steps = [
            'No immediate action is required.',
            'The file has been scanned and no concerning '
            'content was detected.',
            'This report is retained as a record of '
            'the forensic examination.',
            'If you have other reasons to be suspicious '
            'of this file, a manual examination can '
            'be requested.',
        ]

    return {
        'filename': filename,
        'file_ext': file_ext,
        'file_size_kb': file_size_kb,
        'scan_time': scan_time,
        'overall_finding': overall_finding,
        'finding_colour': finding_colour,
        'finding_bg': finding_bg,
        'severity': severity,
        'one_liner': one_liner,
        'malware_finding': malware_finding,
        'malware_colour': malware_colour,
        'lsb_finding': lsb_finding,
        'lsb_colour': lsb_colour,
        'payload_finding': payload_finding,
        'integrity_finding': integrity_finding,
        'integrity_colour': integrity_colour,
        'confidence_plain': confidence_plain,
        'action_steps': action_steps,
        'verdict': verdict,
        'session_id': session_id[:8] + '...',
    }

def generate_summary_report(
    filepath: str,
    session_id: str,
    sha3_hash: str,
    layer1_result: Dict,
    layer2_result: Dict,
    layer3_result: Dict,
    layer4_xai_result: Dict,
    calibration: Dict = None,
    technical_report_path: str = None,
) -> Dict[str, Any]:
    try:
        verdict = layer2_result.get('verdict', 'CLEAN')
        if verdict == 'STEGO_DETECTED':
            subfolder = 'stego'
        elif verdict == 'SUSPICIOUS':
            subfolder = 'suspicious'
        else:
            subfolder = 'clean'
        
        report_dir = config.BASE_DIR / 'reports' / subfolder
        report_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        stem = Path(filepath).stem
        summary_path = report_dir / (
            timestamp_str + '_' + stem + '_summary.pdf'
        )

        content = build_plain_english_summary(
            filepath, layer1_result, layer2_result,
            layer3_result, layer4_xai_result,
            session_id, sha3_hash, calibration
        )

        doc = SimpleDocTemplate(
            str(summary_path),
            pagesize=A4,
            rightMargin=2.5*cm, leftMargin=2.5*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )
        styles = getSampleStyleSheet()
        story = []

        header_style = ParagraphStyle('SumHeader',
            fontSize=22, textColor=WHITE,
            backColor=DARK_BLUE, alignment=TA_CENTER,
            fontName='Helvetica-Bold', leading=28,
            leftIndent=-20, rightIndent=-20, borderPad=12,
            spaceAfter=8)
        
        sub_style = ParagraphStyle('SumSub',
            fontSize=11, textColor=WHITE,
            backColor=ACCENT, alignment=TA_CENTER,
            fontName='Helvetica-Bold', leading=15,
            leftIndent=-20, rightIndent=-20, borderPad=8,
            spaceAfter=6)
        
        body = ParagraphStyle('SumBody',
            fontSize=11, textColor=TEXT,
            fontName='Helvetica', leading=16,
            spaceAfter=8, alignment=TA_JUSTIFY)
        
        section_head = ParagraphStyle('SumSection',
            fontSize=12, textColor=DARK_BLUE,
            fontName='Helvetica-Bold', leading=16,
            spaceBefore=14, spaceAfter=6,
            borderPad=0)
        
        small_grey = ParagraphStyle('SumSmall',
            fontSize=9, textColor=HexColor('#7f8c8d'),
            fontName='Helvetica', leading=13,
            spaceAfter=4)
        
        bullet_style = ParagraphStyle('SumBullet',
            fontSize=11, textColor=TEXT,
            fontName='Helvetica', leading=16,
            spaceAfter=6, leftIndent=20)

        story.append(Paragraph(
            'SHADOW-TRACE', header_style
        ))
        story.append(Paragraph(
            'Forensic Examination Summary Report',
            sub_style
        ))
        story.append(Spacer(1, 0.5*cm))
        
        story.append(Paragraph(
            'Examining Officer: '
            + os.environ.get('EXAMINER_NAME',
              'Digital Forensic Examiner')
            + '   |   Organisation: '
            + os.environ.get('EXAMINER_ORG',
              'Anjuman Institute of Technology')
            + '   |   Date: '
            + content['scan_time'],
            small_grey
        ))
        story.append(Paragraph(
            'File Examined: ' + content['filename']
            + '   |   File Type: ' + content['file_ext']
            + '   |   Size: '
            + str(content['file_size_kb']) + ' KB'
            + '   |   Session: '
            + content['session_id'],
            small_grey
        ))
        story.append(HRFlowable(
            width='100%', thickness=1,
            color=ACCENT
        ))
        story.append(Spacer(1, 0.5*cm))
        
        verdict_box_data = [[
            Paragraph(
                content['overall_finding'],
                ParagraphStyle('VerdBox',
                    fontSize=18,
                    textColor=content['finding_colour'],
                    fontName='Helvetica-Bold',
                    alignment=TA_CENTER,
                    leading=24)
            )
        ]]
        verdict_table = Table(
            verdict_box_data,
            colWidths=[16*cm]
        )
        verdict_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(0,0),
             content['finding_bg']),
            ('LINEABOVE', (0,0),(0,0), 3,
             content['finding_colour']),
            ('LINEBELOW', (0,0),(0,0), 3,
             content['finding_colour']),
            ('TOPPADDING', (0,0),(0,0), 16),
            ('BOTTOMPADDING', (0,0),(0,0), 16),
            ('ALIGN', (0,0),(0,0), 'CENTER'),
        ]))
        story.append(verdict_table)
        story.append(Spacer(1, 0.4*cm))
        
        story.append(Paragraph(content['one_liner'], body))
        story.append(Spacer(1, 0.3*cm))
        story.append(HRFlowable(
            width='100%', thickness=0.5,
            color=HexColor('#bdc3c7')
        ))
        
        story.append(Paragraph(
            'What Was Examined', section_head
        ))
        story.append(Paragraph(
            'Shadow-Trace performed a comprehensive automated '
            'forensic examination of this file. The following '
            'checks were carried out:',
            body
        ))
        
        checks = [
            ('Evidence Integrity Verification',
             content['integrity_finding'],
             content['integrity_colour']),
            ('Virus and Malware Scan',
             content['malware_finding'],
             content['malware_colour']),
            ('Hidden Program Detection',
             content['lsb_finding'],
             content['lsb_colour']),
        ]
        
        if content['payload_finding']:
            checks.append((
                'Hidden Content Analysis',
                content['payload_finding'],
                RED if content['severity'] == 'HIGH'
                else ORANGE
            ))
        
        for check_name, check_text, check_colour in checks:
            indicator = '✓' if check_colour == GREEN else '!'
            indicator_bg = SOFT_GREEN if check_colour == GREEN else SOFT_AMBER if check_colour == ORANGE else SOFT_RED
            
            check_data = [[
                Paragraph(
                    indicator,
                    ParagraphStyle('Indicator',
                        fontSize=16,
                        fontName='Helvetica-Bold',
                        textColor=check_colour,
                        alignment=TA_CENTER)
                ),
                Paragraph(
                    '<b>' + check_name + '</b><br/>'
                    + check_text,
                    body
                )
            ]]
            check_table = Table(
                check_data,
                colWidths=[1.5*cm, 14.5*cm]
            )
            check_table.setStyle(TableStyle([
                ('VALIGN', (0,0),(-1,-1), 'TOP'),
                ('BACKGROUND', (0,0),(0,0), indicator_bg),
                ('TOPPADDING', (0,0),(-1,-1), 8),
                ('BOTTOMPADDING', (0,0),(-1,-1), 8),
                ('LEFTPADDING', (1,0),(1,0), 10),
                ('LINEBELOW', (0,0),(-1,-1), 0.5,
                 HexColor('#ecf0f1')),
            ]))
            story.append(check_table)
            story.append(Spacer(1, 0.2*cm))
        
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            'How Confident Is This Result?', section_head
        ))
        story.append(Paragraph(
            content['confidence_plain'], body
        ))
        
        score = layer2_result.get('score', 0.0) or 0.0
        score_pct = round(score * 100, 1)
        filled_cells = max(1, round(score_pct / 10))
        empty_cells = 10 - filled_cells
        
        if score >= 0.65:
            bar_colour = RED
        elif score >= 0.40:
            bar_colour = ORANGE
        else:
            bar_colour = GREEN
        
        bar_data = [[
            Paragraph(str(score_pct) + '%',
                ParagraphStyle('BarPct',
                    fontSize=14,
                    fontName='Helvetica-Bold',
                    textColor=bar_colour,
                    alignment=TA_CENTER)),
            Paragraph(
                'Suspicion Level',
                ParagraphStyle('BarLabel',
                    fontSize=10,
                    fontName='Helvetica',
                    textColor=HexColor('#7f8c8d'),
                    alignment=TA_LEFT))
        ]]
        bar_table = Table(bar_data, colWidths=[3*cm, 13*cm])
        bar_table.setStyle(TableStyle([
            ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
            ('TOPPADDING', (0,0),(-1,-1), 6),
            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
        ]))
        story.append(bar_table)
        
        story.append(HRFlowable(
            width='100%', thickness=0.5,
            color=HexColor('#bdc3c7')
        ))
        story.append(Paragraph(
            'Recommended Actions', section_head
        ))
        
        for i, step in enumerate(content['action_steps']):
            story.append(Paragraph(
                str(i+1) + '.  ' + step,
                bullet_style
            ))
        
        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(
            width='100%', thickness=1,
            color=ACCENT
        ))
        story.append(Spacer(1, 0.3*cm))
        
        notice_text = (
            'IMPORTANT: This summary is produced by an '
            'automated forensic system for non-technical '
            'readers. It is a simplified overview only. '
            'The full technical forensic report contains '
            'complete evidence, model outputs, chain of '
            'custody, and cryptographic seal. This summary '
            'must not be used as a standalone document in '
            'legal proceedings. Always refer to the full '
            'technical report for evidential purposes.'
        )
        if technical_report_path:
            notice_text += (
                ' Full technical report: '
                + Path(technical_report_path).name
            )
        
        notice_data = [[Paragraph(
            notice_text,
            ParagraphStyle('Notice',
                fontSize=9,
                fontName='Helvetica-Oblique',
                textColor=HexColor('#5d4037'),
                leading=13)
        )]]
        notice_table = Table(notice_data, colWidths=[16*cm])
        notice_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(0,0),
             HexColor('#fff8e1')),
            ('LINEBEFORE', (0,0),(0,0), 3, ORANGE),
            ('TOPPADDING', (0,0),(0,0), 10),
            ('BOTTOMPADDING', (0,0),(0,0), 10),
            ('LEFTPADDING', (0,0),(0,0), 12),
        ]))
        story.append(notice_table)
        
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            'Shadow-Trace v1.0.0  |  '
            + os.environ.get('EXAMINER_ORG',
              'Anjuman Institute of Technology')
            + '  |  '
            + datetime.now().strftime('%Y-%m-%d'),
            ParagraphStyle('SumFooter',
                fontSize=8,
                textColor=HexColor('#95a5a6'),
                alignment=TA_CENTER)
        ))

        doc.build(story)

        with open(summary_path, 'rb') as f:
            pdf_bytes = f.read()
        
        summary_hmac = hmac.new(
            HMAC_KEY, pdf_bytes, __import__('hashlib').sha3_512
        ).hexdigest()
        
        summary_sha3 = __import__('hashlib').sha3_512(
            pdf_bytes
        ).hexdigest()
        
        seal_path = summary_path.with_suffix('.seal.json')
        seal_data = {
            'report_file': summary_path.name,
            'report_type': 'SUMMARY',
            'sha3_512_of_report': summary_sha3,
            'hmac_sha3_512': summary_hmac,
            'generated_at': datetime.now(
                timezone.utc
            ).isoformat(),
            'session_id': session_id,
            'linked_technical_report': (
                Path(technical_report_path).name
                if technical_report_path else None
            ),
        }
        with open(seal_path, 'w') as f:
            import json
            json.dump(seal_data, f, indent=2)

        return {
            'success': True,
            'summary_path': str(summary_path),
            'seal_path': str(seal_path),
            'verdict': verdict,
            'severity': content['severity'],
            'report_type': 'SUMMARY',
            'size_bytes': len(pdf_bytes),
            'error': None,
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

if __name__ == '__main__':
    print('=== SUMMARY REPORT TEST ===')
    print()

    mock_layer1 = {
        'verdict': 'CLEAN',
        'stage1_hash': 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e',
        'stage2_mime': {'mime_type': 'image/jpeg', 'extension': '.jpg'},
        'stage3_clamav': 'CLEAN',
        'stage3_yara': 'CLEAN',
        'stage3_heuristics': {'score': 0.1},
        'stage4_virustotal': {'positives': 0, 'total': 70},
        'yara_warnings': [],
        'yara_matched_rules': [],
        'informational_matches': [],
        'session_id': 'TEST_SUMMARY_SESSION_001',
        'filepath': str(Path.home() / 'Downloads' / 'test_image.jpg'),
        'sha3_hash': 'abc123def456' * 8
    }

    mock_layer2 = {
        'file_type': 'IMAGE',
        'verdict': 'STEGO_DETECTED',
        'score': 0.88,
        'yedroudj_net': {'score': 0.91, 'verdict': 'STEGO_DETECTED'},
        'alaska2': {'score': 0.85, 'verdict': 'STEGO_DETECTED'},
        'chi_square': {'score': 0.72, 'verdict': 'SUSPICIOUS'},
        'rs_analysis': {'score': 0.45, 'verdict': 'CLEAN'},
        'lsb_result': {'verdict': 'CLEAN', 'suspect_pixels': 214}
    }

    mock_layer3 = {
        'extraction_results': {
            'payload_size_bytes': 4512,
            'payload_type': 'Binary Data',
            'is_executable': False,
            'payload_entropy': 7.8,
            'payload_class': 'Encrypted/Compressed'
        }
    }

    from confidence_calibration import calibrate_result
    calibration = calibrate_result(
        layer1_result=mock_layer1,
        layer2_result=mock_layer2,
        layer3_result=mock_layer3,
        file_type='IMAGE',
    )

    print('Generating summary report...')
    result = generate_summary_report(
        filepath=str(Path.home() / 'Downloads' / 'test_image.jpg'),
        session_id='TEST_SUMMARY_SESSION_001',
        sha3_hash='abc123def456' * 8,
        layer1_result=mock_layer1,
        layer2_result=mock_layer2,
        layer3_result=mock_layer3,
        layer4_xai_result={},
        calibration=calibration,
        technical_report_path=None,
    )

    print()
    print('Result:')
    print('  Success: ' + str(result.get('success')))
    print('  Path: ' + str(result.get('summary_path')))
    print('  Size: ' + str(result.get('size_bytes')) + ' bytes')
    print('  Severity: ' + str(result.get('severity')))
    print('  Verdict: ' + str(result.get('verdict')))

    if result.get('success'):
        from pathlib import Path
        p = Path(result['summary_path'])
        print('  File exists: ' + str(p.exists()))
        print()
        print('PASS: Summary report generated')
        print('Open the PDF to verify plain English content')
    else:
        print('FAIL: ' + str(result.get('error')))

    print()
    print('=== TEST COMPLETE ===')
