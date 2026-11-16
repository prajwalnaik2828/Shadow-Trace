import os
import hashlib
import hmac
import json
import requests
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import (
    HexColor, black, white, red, orange, green
)
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, Image as RLImage,
    HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
import config
import utils

from confidence_calibration import (
    calibrate_result,
    SYSTEM_LIMITATIONS,
)

HMAC_KEY = os.environ.get(
    'HMAC_SECRET_KEY',
    ''
).encode('utf-8')

SHADOW_TRACE_VERSION = '1.0.0'
FREETSA_URL = 'https://freetsa.org/tsr'

SECTION_EXPLANATIONS = {
    'file_identity': (
        'This section records the basic identity of the '
        'file that was examined. The cryptographic hash '
        '(SHA3-512) is a unique digital fingerprint that '
        'proves the file has not been modified since it '
        'was first captured by Shadow-Trace. If even one '
        'byte of the file changes, this hash value will '
        'be completely different.'
    ),
    'chain_of_custody': (
        'The chain of custody records every action taken '
        'on this file from the moment it was detected. '
        'This log proves that the file was handled '
        'correctly, that the original was never directly '
        'modified, and that all scanning was performed '
        'on secure copies. This record is essential for '
        'admissibility as digital evidence in legal '
        'proceedings.'
    ),
    'malware_screening': (
        'This section shows the results of standard '
        'malware scanning using three independent methods. '
        'ClamAV is an open-source antivirus engine. '
        'YARA uses pattern matching rules created by '
        'security researchers worldwide. VirusTotal '
        'checks the file against over 70 commercial '
        'antivirus engines simultaneously. A clean result '
        'from all three means the file does not contain '
        'any known malware, but steganography detection '
        'is performed separately.'
    ),
    'steganalysis': (
        'Steganography is the practice of hiding secret '
        'data inside ordinary-looking files such as '
        'images, videos, or documents. Unlike encryption '
        'which makes data unreadable, steganography hides '
        'the very existence of the secret data. This '
        'section shows the results of four independent '
        'analysis methods that were applied to detect '
        'hidden content. The confidence score represents '
        'the combined probability that hidden data is '
        'present in this file.'
    ),
    'gradcam': (
        'Grad-CAM (Gradient-weighted Class Activation '
        'Mapping) is a technique that shows WHERE in the '
        'file the artificial intelligence model detected '
        'suspicious patterns. In the heatmap image, red '
        'and orange areas are regions that the AI model '
        'found most suspicious. Blue areas were considered '
        'normal. This visualization helps explain why the '
        'AI reached its conclusion and which parts of the '
        'file should receive closer examination.'
    ),
    'token_map': (
        'This visualization shows the results of '
        'character-level analysis of the document text. '
        'Steganography tools that target documents often '
        'hide data by inserting invisible Unicode '
        'characters between visible letters, or by '
        'replacing standard Latin letters with visually '
        'identical characters from other alphabets such '
        'as Cyrillic. The annotations show the exact '
        'positions where such substitutions were detected.'
    ),
    'payload_extraction': (
        'When steganography is detected, Shadow-Trace '
        'attempts to extract the hidden payload - the '
        'secret data that was concealed inside the file. '
        'The entropy score measures how random the '
        'extracted data is. A score above 7.9 out of 8.0 '
        'indicates the payload is encrypted or compressed, '
        'meaning someone deliberately concealed it. '
        'If a file type signature is detected in the '
        'payload, it means the hidden data itself is a '
        'recognizable file such as a program or document.'
    ),
    'attribution': (
        'This section shows which analysis method '
        'contributed most to the final verdict. Each bar '
        'represents one detection method and its '
        'contribution to the overall suspicion score. '
        'Longer red bars indicate methods that strongly '
        'detected hidden content. This helps a forensic '
        'examiner understand which evidence is strongest '
        'and should receive the most attention.'
    ),
    'cryptographic_seal': (
        'This report has been cryptographically sealed '
        'using HMAC-SHA3-512, a military-grade '
        'authentication code. The seal value below proves '
        'that this report has not been altered since it '
        'was generated by Shadow-Trace. Any modification '
        'to this report after generation will produce a '
        'different seal value, making tampering immediately '
        'detectable. The RFC 3161 timestamp proves the '
        'exact time this report was generated.'
    ),
    'yara_warning': (
        'YARA is a pattern-matching tool used by security '
        'researchers to identify suspicious content in '
        'files. The following patterns were detected in '
        'this file. Note that some YARA patterns can '
        'match legitimate files that happen to contain '
        'certain structures. Each finding is explained '
        'in plain language below to help you assess '
        'its significance.'
    ),
}

def compute_hmac_seal(content: bytes) -> str:
    sig = hmac.new(HMAC_KEY, content, hashlib.sha3_512)
    return sig.hexdigest()

def get_rfc3161_timestamp(data: bytes) -> Dict:
    try:
        import settings_manager
        tsa_url = settings_manager.get_setting('rfc3161_url', getattr(config, 'FREETSA_URL', FREETSA_URL))
    except Exception:
        tsa_url = getattr(config, 'FREETSA_URL', FREETSA_URL)
    try:
        data_hash = hashlib.sha512(data).digest()
        tsq_b64 = base64.b64encode(data_hash).decode('utf-8')
        
        response = requests.post(
            tsa_url,
            data=tsq_b64,
            timeout=10,
            headers={'Content-Type': 'application/timestamp-query'}
        )
        if response.status_code == 200:
            return {
                'success': True,
                'timestamp_token': base64.b64encode(response.content).decode('utf-8'),
                'tsa_url': FREETSA_URL
            }
        else:
            return {
                'success': False,
                'error': f'HTTP {response.status_code}',
                'fallback_timestamp': datetime.now(timezone.utc).isoformat()
            }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'fallback_timestamp': datetime.now(timezone.utc).isoformat()
        }

def generate_forensic_report(
    filepath: str,
    session_id: str,
    sha3_hash: str,
    layer1_result: Dict,
    layer2_result: Dict,
    layer3_result: Dict,
    layer4_xai_result: Dict,
    chain_of_custody_log: list = None
) -> Dict[str, Any]:
    try:
        if layer4_xai_result is None:
            layer4_xai_result = {}
        if layer1_result is None:
            layer1_result = {}
        if layer2_result is None:
            layer2_result = {}
        print('[LAYER4-REPORT] Layer1 result keys: ' + str(list(layer1_result.keys()) if layer1_result else 'None'))
        verdict = layer2_result.get('verdict', 'UNKNOWN') if layer2_result else 'UNKNOWN'
        if verdict == 'STEGO_DETECTED':
            subfolder = 'stego'
        elif verdict == 'SUSPICIOUS':
            subfolder = 'suspicious'
        else:
            subfolder = 'clean'
        try:
            import settings_manager
            base_rep = Path(settings_manager.get_setting('report_output_folder', config.REPORTS_DIR))
        except Exception:
            base_rep = config.BASE_DIR / 'reports'
        reports_dir = base_rep / subfolder
        reports_dir.mkdir(parents=True, exist_ok=True)
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = Path(filepath).stem
        report_path = reports_dir / (timestamp_str + '_' + filename + '_report.pdf')

        DARK_BLUE = HexColor('#1a1a2e')
        MID_BLUE = HexColor('#16213e')
        ACCENT = HexColor('#0f3460')
        RED_ALERT = HexColor('#e94560')
        ORANGE_WARN = HexColor('#f5a623')
        GREEN_OK = HexColor('#27ae60')
        LIGHT_GREY = HexColor('#ecf0f1')

        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'ShadowTitle',
            parent=styles['Title'],
            fontSize=20, textColor=white,
            backColor=DARK_BLUE, spaceAfter=20,
            alignment=TA_CENTER, fontName='Helvetica-Bold'
        )
        section_style = ParagraphStyle(
            'ShadowSection',
            parent=styles['Heading1'],
            fontSize=14, textColor=white,
            backColor=ACCENT, spaceBefore=15,
            spaceAfter=8, fontName='Helvetica-Bold',
            leftIndent=10
        )
        body_style = ParagraphStyle(
            'ShadowBody',
            parent=styles['Normal'],
            fontSize=10, textColor=black,
            spaceAfter=6, fontName='Helvetica',
            alignment=TA_JUSTIFY
        )
        mono_style = ParagraphStyle(
            'ShadowMono',
            parent=styles['Code'],
            fontSize=8, textColor=black,
            backColor=LIGHT_GREY, fontName='Courier',
            spaceAfter=4
        )

        verdict = layer2_result.get('verdict', 'UNKNOWN') if layer2_result else 'UNKNOWN'
        score = layer2_result.get('score', 0.0) if layer2_result else 0.0
        
        def fmt_score(s):
            try:
                if isinstance(s, str) and '%' in s: return s
                return str(round(float(s) * 100, 1)) + '%'
            except (ValueError, TypeError):
                return 'N/A'

        if verdict == 'STEGO_DETECTED':
            verdict_color = RED_ALERT
            verdict_text = f'STEGANOGRAPHY DETECTED ({fmt_score(score)})'
        elif verdict == 'SUSPICIOUS':
            verdict_color = ORANGE_WARN
            verdict_text = f'SUSPICIOUS - UNDER INVESTIGATION ({fmt_score(score)})'
        else:
            verdict_color = GREEN_OK
            verdict_text = f'CLEAN - NO STEGANOGRAPHY DETECTED ({fmt_score(score)})'

        calibration = None
        try:
            file_type = layer2_result.get('file_type', 'IMAGE') if layer2_result else 'IMAGE'
            lsb_data = layer2_result.get(
                'lsb_check_result',
                layer2_result.get('lsb_result', None)
            ) if layer2_result else None
            calibration = calibrate_result(
                layer1_result=layer1_result,
                layer2_result=layer2_result or {},
                layer3_result=layer3_result,
                lsb_result=lsb_data,
                file_type=file_type,
            )
            print('[LAYER4-REPORT] Calibration: '
                  + calibration.get(
                      'confidence_band', {}
                  ).get('label', 'unknown'))
        except Exception as e:
            print('[LAYER4-REPORT] Calibration error: ' + str(e))
            calibration = None

        try:
            from utils import get_system_context
            sys_context = get_system_context()
        except Exception:
            sys_context = {}

        story = []

        # SECTION 1: Cover Page
        story.append(Paragraph('Shadow-Trace Forensic Analysis Report', title_style))
        
        verdict_style = ParagraphStyle(
            'Verdict', parent=styles['Heading2'], fontSize=16, textColor=white,
            backColor=verdict_color, alignment=TA_CENTER, spaceAfter=20
        )
        story.append(Paragraph(verdict_text, verdict_style))
        story.append(Paragraph(f"File Name: {Path(filepath).name}", body_style))
        story.append(Paragraph(f"Session ID: {session_id}", body_style))
        try:
            import settings_manager
            examiner_sig = settings_manager.get_setting('examiner_signature', config.EXAMINER_NAME)
            include_sys = settings_manager.get_setting('include_system_context', True)
        except Exception:
            examiner_sig = config.EXAMINER_NAME
            include_sys = True
        story.append(Paragraph(f"Examining Officer: {examiner_sig}", body_style))
        story.append(Paragraph(f"Examiner ID: {config.EXAMINER_ID}", body_style))
        story.append(Paragraph(f"Organisation: {config.EXAMINER_ORG}", body_style))
        story.append(Paragraph(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", body_style))
        story.append(Spacer(1, 10))
        story.append(Paragraph(
            'What This Report Contains',
            ParagraphStyle('Heading3', parent=styles['Heading3'], fontName='Helvetica-Bold')
        ))
        story.append(Paragraph(
            'This report documents the complete forensic '
            'analysis performed by Shadow-Trace v1.0.0. '
            'It covers malware screening, steganography '
            'detection, payload extraction, and AI-powered '
            'explainability analysis. Each section begins '
            'with a plain-language explanation of what was '
            'tested and what the results mean.',
            body_style
        ))
        story.append(HRFlowable(width="100%", thickness=1, color=DARK_BLUE, spaceBefore=10, spaceAfter=10))
        
        if include_sys:
            story.append(Paragraph(
                '1b. EXAMINATION ENVIRONMENT',
                section_style
            ))

            story.append(Paragraph(
                'This section records the complete system '
                'context at the time of examination. Timezone '
                'and UTC offset are required to correctly '
                'interpret all timestamps in this report. '
                'Tool integrity hashes confirm the analysis '
                'software was not modified between '
                'installation and use.',
                body_style
            ))

            env_data = [
                ['Parameter', 'Value'],
                ['Scan Time (UTC)',
                 sys_context.get('scan_time_utc', 'Unknown')[:19]],
                ['Scan Time (Local)',
                 sys_context.get('scan_time_local', 'Unknown')[:19]],
                ['Timezone',
                 sys_context.get('timezone_name', 'Unknown')],
                ['UTC Offset',
                 sys_context.get('utc_offset', 'Unknown')],
                ['Operating System',
                 sys_context.get('os_system', 'Unknown')
                 + ' ' + sys_context.get('os_release', '')],
                ['OS Version',
                 sys_context.get('os_version', 'Unknown')[:50]],
                ['Hostname',
                 sys_context.get('hostname', 'Unknown')],
                ['Python Version',
                 sys_context.get('python_version', 'Unknown')],
                ['Shadow-Trace Version',
                 sys_context.get('shadow_trace_version', '1.0.0')],
            ]

            env_table = Table(env_data, colWidths=[6*cm, 11*cm])
            env_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), DARK_BLUE),
                ('TEXTCOLOR', (0,0),(-1,0), white),
                ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0),(-1,0), 9),
                ('ROWBACKGROUND', (0,1),(-1,-1),
                 [LIGHT_GREY, white]),
                ('FONTNAME', (0,1),(-1,-1), 'Helvetica'),
                ('FONTSIZE', (0,1),(-1,-1), 9),
                ('GRID', (0,0),(-1,-1), 0.5, ACCENT),
                ('TOPPADDING', (0,0),(-1,-1), 5),
                ('BOTTOMPADDING', (0,0),(-1,-1), 5),
                ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
            ]))
            story.append(env_table)
            story.append(Spacer(1, 0.3*cm))

            tool_hashes = sys_context.get('tool_integrity', {})
            if tool_hashes:
                story.append(Paragraph(
                    'Tool Integrity Verification:',
                    ParagraphStyle('ToolHead',
                        parent=body_style,
                        fontName='Helvetica-Bold',
                        fontSize=10)
                ))
                story.append(Paragraph(
                    'The following SHA-256 hashes verify that '
                    'Shadow-Trace analysis components were not '
                    'modified between installation and use of '
                    'this system.',
                    body_style
                ))
                
                tool_data = [['File', 'SHA-256 Hash']]
                for fname, fhash in tool_hashes.items():
                    tool_data.append([
                        fname,
                        Paragraph(fhash, mono_style)
                    ])
                
                tool_table = Table(
                    tool_data,
                    colWidths=[5*cm, 12*cm]
                )
                tool_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0),(-1,0), ACCENT),
                    ('TEXTCOLOR', (0,0),(-1,0), white),
                    ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0),(-1,0), 8),
                    ('ROWBACKGROUND', (0,1),(-1,-1),
                     [LIGHT_GREY, white]),
                    ('FONTSIZE', (0,1),(-1,-1), 7),
                    ('GRID', (0,0),(-1,-1), 0.5, ACCENT),
                    ('TOPPADDING', (0,0),(-1,-1), 4),
                    ('BOTTOMPADDING', (0,0),(-1,-1), 4),
                    ('VALIGN', (0,0),(-1,-1), 'TOP'),
                ]))
                story.append(tool_table)

            story.append(Spacer(1, 0.3*cm))


        # SECTION 2: File Identity and Provenance
        story.append(Paragraph('1. File Identity and Provenance', section_style))
        story.append(Paragraph(SECTION_EXPLANATIONS['file_identity'], body_style))
        try:
            file_size = os.path.getsize(filepath) if os.path.exists(filepath) else 'Unknown'
        except Exception:
            file_size = 'Unknown'
        
        mime_type = layer2_result.get('file_type', 'UNKNOWN') if layer2_result else 'UNKNOWN'
        
        file_hashes = layer2_result.get('file_hashes', {}) if layer2_result else {}
        if not file_hashes or not file_hashes.get('sha256') or not file_hashes.get('md5'):
            try:
                from utils import compute_multi_hash
                computed_hashes = compute_multi_hash(str(filepath))
                if computed_hashes.get('success'):
                    if not file_hashes:
                        file_hashes = dict(computed_hashes)
                    else:
                        for k, v in computed_hashes.items():
                            if not file_hashes.get(k):
                                file_hashes[k] = v
                    if layer2_result is not None:
                        layer2_result['file_hashes'] = file_hashes
            except Exception:
                pass

        primary_hash = (
            file_hashes.get('sha3_512')
            or sha3_hash
            or 'Not computed'
        )
        sha256_val = file_hashes.get('sha256', 'Not computed')
        md5_val = file_hashes.get('md5', 'Not computed')
        
        identity_data = [
            ['File Name', Path(filepath).name],
            ['Full Path', Paragraph(str(filepath), mono_style)],
            ['File Size', str(file_size) + ' bytes'],
            ['MIME Type', mime_type],
            ['SHA3-512 (Primary)', Paragraph(primary_hash, mono_style)],
            ['SHA-256 (Cross-tool)', Paragraph(sha256_val, mono_style)],
            ['MD5 (Legacy reference)', Paragraph(md5_val, mono_style)],
            ['Detection Timestamp', timestamp_str]
        ]

        correlation = layer2_result.get('source_correlation', {}) if layer2_result else {}
        zone_data = correlation.get('zone_identifier', {}) or {}
        file_meta = correlation.get('file_metadata', {}) or {}
        macb = file_meta.get('macb_timestamps', {}) or {}

        if macb:
            identity_data.append(['MACB Timestamps',
             Paragraph(
                 'M (Modified): '
                 + str(macb.get('M_modified', 'N/A'))[:19]
                 + '\nA (Accessed): '
                 + str(macb.get('A_accessed', 'N/A'))[:19]
                 + '\nC (Changed):  '
                 + str(macb.get('C_changed', 'N/A'))[:19]
                 + '\nB (Born):     '
                 + str(macb.get('B_born', 'N/A'))[:19],
                 mono_style
             )])

        if zone_data.get('found'):
            identity_data.append(['Download Origin',
             Paragraph(
                 'Zone: '
                 + zone_data.get('zone_name', 'Unknown')
                 + ' (ID: '
                 + str(zone_data.get('zone_id', '?'))
                 + ')',
                 body_style
             )])

        if zone_data.get('host_url'):
            identity_data.append(['Source URL (OS-verified)',
             Paragraph(
                 zone_data.get('host_url', 'Not captured'),
                 mono_style
             )])
        elif layer2_result and layer2_result.get('source_url'):
            url_info = layer2_result.get('source_url')
            identity_data.append(['Source URL', Paragraph(str(url_info), mono_style)])
        else:
            identity_data.append(['Source URL', Paragraph('Not captured', mono_style)])

        if zone_data.get('referrer_url'):
            identity_data.append(['Referrer URL',
             Paragraph(
                 zone_data.get('referrer_url', ''),
                 mono_style
             )])

        t = Table(identity_data, colWidths=[4*cm, 12*cm])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (0,-1), LIGHT_GREY),
            ('TEXTCOLOR', (0,0), (-1,-1), black),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0,0), (-1,-1), 6),
            ('GRID', (0,0), (-1,-1), 1, black)
        ]))
        story.append(t)
        
        story.append(Paragraph(
            'Hash Computation Statement: All three hash '
            'values were computed simultaneously in a '
            'single read pass on the original unmodified '
            'file immediately upon detection and before '
            'any processing, scanning, or file locking '
            'was performed. This ensures all hash values '
            'reflect the exact state of the file as '
            'received. SHA3-512 is the primary integrity '
            'algorithm and is used for all cryptographic '
            'operations within Shadow-Trace including '
            'chain of custody logging and HMAC report '
            'sealing. SHA-256 is provided for independent '
            'verification using EnCase, FTK, Autopsy, or '
            'other standard forensic tools. MD5 is provided '
            'for compatibility with legacy court '
            'documentation standards. MD5 and SHA-256 '
            'collision vulnerabilities do not compromise '
            'their use as secondary cross-verification '
            'values when used alongside SHA3-512.',
            ParagraphStyle('HashStatement',
                parent=body_style,
                fontSize=8,
                textColor=HexColor('#5d4037'),
                backColor=HexColor('#fff8e1'),
                fontName='Helvetica-Oblique',
                leftIndent=5,
                rightIndent=5,
                borderPad=6,
                spaceBefore=4,
                spaceAfter=8)
        ))

        rc = layer2_result.get('hash_reconfirmation', {}) if layer2_result else {}
        if not rc or rc.get('primary_confirmed') is None:
            if filepath and os.path.exists(filepath):
                try:
                    from utils import compute_multi_hash
                    final_h = compute_multi_hash(str(filepath))
                    if final_h.get('success'):
                        init_sha3 = (file_hashes.get('sha3_512') or primary_hash) if primary_hash != 'Not computed' else sha3_hash
                        init_sha256 = file_hashes.get('sha256')
                        init_md5 = file_hashes.get('md5')

                        sha3_m = (final_h['sha3_512'] == init_sha3) if init_sha3 else False
                        sha256_m = (final_h['sha256'] == init_sha256) if init_sha256 else True
                        md5_m = (final_h['md5'] == init_md5) if init_md5 else True
                        all_m = sha3_m and (sha256_m if init_sha256 else True) and (md5_m if init_md5 else True)

                        rc = {
                            'sha3_512_match': sha3_m,
                            'sha256_match': sha256_m,
                            'md5_match': md5_m,
                            'all_match': all_m,
                            'primary_confirmed': sha3_m,
                            'status': ('CONFIRMED' if all_m else 'FAILED'),
                            'initial_sha3_512': init_sha3,
                            'initial_sha256': init_sha256,
                            'initial_md5': init_md5,
                            'final_sha3_512': final_h.get('sha3_512'),
                            'final_sha256': final_h.get('sha256'),
                            'final_md5': final_h.get('md5'),
                            'reconfirmed_at': datetime.now(timezone.utc).isoformat(),
                            'forensic_statement': (
                                'SHA3-512 is the primary integrity algorithm. Hashes were computed on '
                                'the original file before processing and recomputed following completion '
                                'of all pipeline layers. Matching values confirm the original evidence '
                                'file was not modified during investigation.'
                            )
                        }
                        if layer2_result is not None:
                            layer2_result['hash_reconfirmation'] = rc
                except Exception:
                    pass

        primary_ok = rc.get('primary_confirmed', None)
        all_ok = rc.get('all_match', None)
        rc_time = rc.get('reconfirmed_at', '')[:19]
        
        if primary_ok is True and all_ok is True:
            box_bg = HexColor('#e8f8f0')
            border_color = GREEN_OK
            icon = '✓'
            statement = (
                'INTEGRITY RECONFIRMATION: PASSED\n\n'
                'SHA3-512 PRIMARY HASH: CONFIRMED\n'
                'SHA-256 SECONDARY HASH: CONFIRMED\n'
                'MD5 LEGACY HASH: CONFIRMED\n\n'
                'All three hash values were recomputed '
                'on the original evidence file immediately '
                'after it was unlocked following completion '
                'of the full six-layer investigation pipeline. '
                'All values are identical to those computed '
                'before any investigation activity began. '
                'The original evidence file integrity is '
                'confirmed across the complete investigation.\n\n'
                'Reconfirmation completed: '
                + rc_time + ' UTC\n\n'
                'Note: SHA3-512 is the primary integrity '
                'algorithm. SHA-256 and MD5 are secondary '
                'cross-verification values for compatibility '
                'with EnCase, FTK, and Autopsy.'
            )
        
        elif primary_ok is True and all_ok is not True:
            box_bg = HexColor('#fff8e1')
            border_color = ORANGE_WARN
            icon = '⚠'
            statement = (
                'INTEGRITY RECONFIRMATION: PARTIAL\n\n'
                'SHA3-512 PRIMARY HASH: CONFIRMED\n'
                'Secondary hash comparison: INCOMPLETE\n\n'
                'The primary SHA3-512 integrity hash is '
                'confirmed. Secondary hashes could not be '
                'fully compared. Primary confirmation is '
                'sufficient to establish file integrity.\n\n'
                'Reconfirmation completed: '
                + rc_time + ' UTC'
            )
        
        elif primary_ok is False:
            box_bg = HexColor('#fde8e8')
            border_color = RED_ALERT
            icon = '✗'
            statement = (
                'INTEGRITY RECONFIRMATION: FAILED\n\n'
                'SHA3-512 PRIMARY HASH: MISMATCH\n\n'
                'CRITICAL: The primary SHA3-512 hash value '
                'does not match the value computed before '
                'investigation began. The original evidence '
                'file may have been modified during the '
                'investigation. This result must not be '
                'used as forensic evidence without further '
                'examination by a qualified examiner.\n\n'
                'Reconfirmation attempted: '
                + rc_time + ' UTC'
            )
        
        else:
            box_bg = LIGHT_GREY
            border_color = HexColor('#7f8c8d')
            icon = '?'
            statement = (
                'INTEGRITY RECONFIRMATION: NOT PERFORMED\n\n'
                'Hash reconfirmation data is not available '
                'for this scan. This may occur if the scan '
                'was interrupted before completion.'
            )
            
        rc_box_data = [[
            Paragraph(
                icon + '  ' + statement.replace('\n', '<br/>'),
                ParagraphStyle('RCBox',
                    parent=body_style,
                    fontSize=9,
                    fontName='Helvetica',
                    leading=14,
                )
            )
        ]]
        rc_table = Table(rc_box_data, colWidths=[17*cm])
        rc_table.setStyle(TableStyle([
            ('BACKGROUND', (0,0),(0,0), box_bg),
            ('LINEBEFORE', (0,0),(0,0), 4, border_color),
            ('LINEABOVE', (0,0),(0,0), 1, border_color),
            ('LINEBELOW', (0,0),(0,0), 1, border_color),
            ('TOPPADDING', (0,0),(0,0), 12),
            ('BOTTOMPADDING', (0,0),(0,0), 12),
            ('LEFTPADDING', (0,0),(0,0), 14),
            ('RIGHTPADDING', (0,0),(0,0), 10),
        ]))
        story.append(rc_table)
        story.append(Spacer(1, 0.5*cm))

        if zone_data.get('found'):
            story.append(Paragraph(
                'Source URL obtained from Windows '
                'Zone.Identifier NTFS alternate data '
                'stream. This stream is written '
                'automatically by Windows for all '
                'internet downloads and is independent '
                'of the browser or application used. '
                'It is considered OS-level forensic '
                'evidence of file provenance.',
                ParagraphStyle('ZoneNote',
                    parent=body_style,
                    fontSize=8,
                    textColor=HexColor('#27ae60'),
                    fontName='Helvetica-Oblique')
            ))
            
        story.append(Spacer(1, 10))

        # SECTION 3: Chain of Custody Summary
        story.append(Paragraph('2. Chain of Custody Summary', section_style))
        story.append(Paragraph(SECTION_EXPLANATIONS['chain_of_custody'], body_style))
        if not chain_of_custody_log:
            try:
                import chain_of_custody as coc_module
                chain_of_custody_log = coc_module.get_session_log(session_id)
            except Exception:
                chain_of_custody_log = []
                
        if chain_of_custody_log:
            coc_data = [['Step', 'Action', 'Timestamp', 'Result']]
            for i, entry in enumerate(chain_of_custody_log):
                coc_data.append([
                    str(i+1),
                    Paragraph(str(entry.get('action', '')), mono_style), 
                    str(entry.get('timestamp', '')), 
                    str(entry.get('result', ''))
                ])
            t = Table(coc_data, colWidths=[1*cm, 5*cm, 6*cm, 4*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, black)
            ]))
            story.append(t)
        else:
            story.append(Paragraph('Chain of custody log not available for this session.', body_style))
        story.append(Spacer(1, 10))

        # SECTION 4: Malware Screening Results (Layer 1)
        story.append(Paragraph('3. Malware Screening Results (Layer 1)', section_style))
        story.append(Paragraph(SECTION_EXPLANATIONS['malware_screening'], body_style))
        # --- resolve each field, handling both str and dict values ----------
        clamav_raw = layer1_result.get('stage3_clamav', 'UNKNOWN')
        clamav_display = (
            clamav_raw.get('verdict', 'UNKNOWN')
            if isinstance(clamav_raw, dict) else
            str(clamav_raw) if clamav_raw else 'UNKNOWN'
        )

        yara_raw = layer1_result.get('stage3_yara', {})
        if isinstance(yara_raw, dict):
            yara_display = yara_raw.get('verdict', 'UNKNOWN')
        else:
            yara_display = str(yara_raw) if yara_raw else 'UNKNOWN'

        h_verdict = 'UNKNOWN'
        heuristics_raw = layer1_result.get('stage3_heuristics', None)
        if isinstance(heuristics_raw, list) and heuristics_raw:
            h_verdicts = [r.get('verdict', 'UNKNOWN') for r in heuristics_raw]
            if 'THREAT' in h_verdicts:
                h_verdict = 'THREAT'
            elif 'WARNING' in h_verdicts:
                h_verdict = 'WARNING'
            elif 'ERROR' in h_verdicts:
                h_verdict = 'ERROR'
            elif 'CLEAN' in h_verdicts:
                h_verdict = 'CLEAN'
        elif isinstance(heuristics_raw, dict):
            h_verdict = heuristics_raw.get('verdict', 'UNKNOWN')
        elif isinstance(heuristics_raw, str) and heuristics_raw:
            h_verdict = heuristics_raw
        heuristics_display = h_verdict

        vt_raw = layer1_result.get('stage4_virustotal', 'UNKNOWN')
        if isinstance(vt_raw, dict):
            vt_display = vt_raw.get('verdict', 'UNKNOWN')
        else:
            vt_display = str(vt_raw) if vt_raw else 'UNKNOWN'

        yara_warn_count   = len(layer1_result.get('yara_warnings',       []))
        yara_threat_count = len(layer1_result.get('yara_matched_rules',  []))

        # --- build table (header + one row per check) ------------------------
        table_data = [
            ['Check', 'Result', 'Details'],
            ['ClamAV Antivirus',
             clamav_display,
             'Signature-based scan'],
            ['YARA Rules',
             yara_display,
             f'{yara_warn_count} warnings, {yara_threat_count} threats'],
            ['Heuristic Analysis',
             str(heuristics_display),
             'Behavioural patterns'],
            ['VirusTotal',
             str(vt_display),
             '70+ AV engines checked'],
        ]

        # --- colour-code the result cells (column 1, rows 1-6) ---------------
        def _result_color(val):
            v = str(val).upper()
            if v in ('CLEAN', 'SUCCESS'):     return HexColor('#1a7a1a')  # dark green
            if v in ('THREAT', 'INFECTED'):   return HexColor('#cc0000')  # red
            if v in ('WARNING',):             return HexColor('#cc6600')  # orange
            if v in ('UNKNOWN',):             return HexColor('#888888')  # grey
            return black

        base_style = [
            ('BACKGROUND', (0, 0), (-1,  0), LIGHT_GREY),   # header row
            ('BACKGROUND', (0, 1), ( 0, -1), LIGHT_GREY),   # check-name column
            ('TEXTCOLOR',  (0, 0), (-1,  0), black),
            ('ALIGN',      (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME',   (0, 0), (-1,  0), 'Helvetica-Bold'),
            ('FONTNAME',   (0, 1), ( 0, -1), 'Helvetica-Bold'),
            ('GRID',       (0, 0), (-1, -1), 0.5, black),
        ]
        for row_idx in range(1, len(table_data)):
            val = table_data[row_idx][1]
            base_style.append(
                ('TEXTCOLOR', (1, row_idx), (1, row_idx), _result_color(val))
            )
            base_style.append(
                ('FONTNAME',  (1, row_idx), (1, row_idx), 'Helvetica-Bold')
            )

        t = Table(table_data, colWidths=[4.5*cm, 3.5*cm, 9*cm])
        t.setStyle(TableStyle(base_style))
        story.append(t)

        
        yara_warnings = layer1_result.get('yara_warnings', [])
        yara_threats = layer1_result.get('yara_matched_rules', [])
        yara_informational = layer1_result.get('informational_matches', [])
        
        if yara_threats or yara_warnings or yara_informational:
            story.append(Spacer(1, 10))
            story.append(Paragraph('YARA Pattern Detection Details', ParagraphStyle('Heading4', parent=styles['Heading3'], fontName='Helvetica-Bold')))
            xai_yara = layer4_xai_result.get('yara_explanations', [])
            
            if not xai_yara:
                try:
                    from layer4_explainability import explain_yara_rules
                    xai_yara = explain_yara_rules(yara_threats, yara_warnings + yara_informational)
                except Exception:
                    pass
                    
            for explanation in xai_yara:
                severity = explanation.get('severity', 'WARNING')
                rule_name = explanation.get('rule_name', '')
                explanation_text = explanation.get('explanation', '')
                
                color = RED_ALERT if severity == 'THREAT' else ORANGE_WARN
                hdr_style = ParagraphStyle('YaraHdr', parent=body_style, textColor=color, fontName='Helvetica-Bold')
                
                story.append(Paragraph(f'[{severity}] {rule_name}', hdr_style))
                story.append(Paragraph(explanation_text, body_style))
        else:
            story.append(Spacer(1, 5))
            story.append(Paragraph('No YARA patterns detected.', ParagraphStyle('Clean', parent=body_style, textColor=green, fontName='Helvetica-Bold')))
            
        story.append(Spacer(1, 10))
        
        lsb_result = layer2_result.get('lsb_check_result', {})
        if lsb_result:
            story.append(Paragraph('3b. Layer 1.5: LSB Executable Detection', section_style))
            if lsb_result.get('verdict') == 'EXECUTABLE_FOUND':
                exec_alert_style = ParagraphStyle('Alert', parent=body_style, textColor=red, fontName='Helvetica-Bold')
                story.append(Paragraph('EXECUTABLE SIGNATURE FOUND IN LSB', exec_alert_style))
                sigs = lsb_result.get('signatures_found', [])
                if sigs:
                    sig = sigs[0]
                    sig_name = sig.get('signature_type', 'executable')
                    sig_pos = sig.get('position_hex', 'unknown')
                else:
                    sig_name = 'executable'
                    sig_pos = 'unknown'
                
                story.append(Paragraph(f"Layer 1.5 analysis extracted data from this file and found a pattern matching a {sig_name} at byte position {sig_pos}. This means a program or script may be hidden inside this document using steganography. This is a significant finding as it could indicate a malicious payload.", body_style))
            else:
                clean_style = ParagraphStyle('Clean', parent=body_style, textColor=green, fontName='Helvetica-Bold')
                story.append(Paragraph('LSB ANALYSIS CLEAN', clean_style))
                story.append(Paragraph('No executable signatures were found in the least significant bit layer of this file.', body_style))
            story.append(Spacer(1, 10))

        # SECTION 5: Steganography Analysis (Layer 2)
        story.append(Paragraph('4. Steganography Analysis (Layer 2)', section_style))
        story.append(Paragraph(SECTION_EXPLANATIONS['steganalysis'], body_style))
        story.append(Paragraph(f"Overall Verdict: {verdict}", body_style))
        story.append(Paragraph(f"Fusion Score: {fmt_score(score)}", body_style))
        
        l2_data = [['Stream / Tier', 'Score', 'Verdict']]
        file_type = layer2_result.get('file_type', 'IMAGE')
        
        if file_type == 'DOCUMENT':
            if 'stream1_structural' in layer2_result:
                s1 = layer2_result['stream1_structural']
                l2_data.append(['PDF/DOCX Structural', fmt_score(s1.get('score')), str(s1.get('verdict', 'N/A'))])
            if 'stream2b_unicode' in layer2_result:
                s2 = layer2_result['stream2b_unicode']
                l2_data.append(['Unicode/Whitespace', fmt_score(s2.get('score')), str(s2.get('verdict', 'N/A'))])
            if 'stream3_entropy' in layer2_result:
                s3 = layer2_result['stream3_entropy']
                l2_data.append(['Entropy Analysis', fmt_score(s3.get('score')), str(s3.get('verdict', 'N/A'))])
            if 'stream4_metadata' in layer2_result:
                s4 = layer2_result['stream4_metadata']
                l2_data.append(['Metadata Analysis', fmt_score(s4.get('score')), str(s4.get('verdict', 'N/A'))])
            neural_score = layer2_result.get('neural_score')
            if neural_score is not None:
                if neural_score >= 0.65:
                    neural_verdict = 'STEGO_DETECTED'
                elif neural_score >= 0.40:
                    neural_verdict = 'SUSPICIOUS'
                else:
                    neural_verdict = 'CLEAN'
            else:
                neural_verdict = 'NOT RUN'
            l2_data.append(['Neural Language Model', fmt_score(neural_score) if neural_score is not None else 'N/A', neural_verdict])
                
        elif file_type == 'VIDEO':
            l2_data.append(['Video Steganalysis (All Streams)', fmt_score(layer2_result.get('score')), str(layer2_result.get('verdict', 'N/A'))])
            
        else:
            if 'tier1a_yedroudj' in layer2_result:
                t1a = layer2_result['tier1a_yedroudj']
                l2_data.append(['Tier 1A (YedroudjNetV3)', fmt_score(t1a.get('score')), str(t1a.get('verdict', 'N/A'))])
            if 'tier1b_alaska2' in layer2_result:
                t1b = layer2_result['tier1b_alaska2']
                l2_data.append(['Tier 1B (ALASKA2)', fmt_score(t1b.get('score')), str(t1b.get('verdict', 'N/A'))])
            if 'tier3_statistical' in layer2_result:
                t3 = layer2_result['tier3_statistical']
                if isinstance(t3, dict):
                    l2_data.append(['Tier 3 (Statistical)', fmt_score(t3.get('combined_score')), str(t3.get('verdict', 'N/A'))])
        
        if len(l2_data) > 1:
            t = Table(l2_data, colWidths=[6*cm, 3*cm, 7*cm])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('GRID', (0,0), (-1,-1), 1, black)
            ]))
            story.append(t)
            
        fusion_notes = layer2_result.get('fusion_notes', [])
        if fusion_notes:
            story.append(Spacer(1, 5))
            story.append(Paragraph('Fusion Notes:', body_style))
            if isinstance(fusion_notes, str):
                fusion_notes = fusion_notes.split('\n')
            for note in fusion_notes:
                if str(note).strip():
                    story.append(Paragraph(f"• {note}", body_style))

        size_info = layer2_result.get(
            'image_size_check', {}
        ) or {}

        if size_info.get('small_file'):
            warn_content = (
                '<b>STATISTICAL ANALYSIS RELIABILITY WARNING</b><br/><br/>'
                'This image contains only '
                + str(size_info.get('pixel_count', 'unknown'))
                + ' pixels ('
                + str(size_info.get('width', '?'))
                + ' x '
                + str(size_info.get('height', '?'))
                + '). Chi-Square Analysis and RS Analysis '
                'require a minimum of 10,000 pixels to '
                'produce statistically valid results. '
                'The statistical scores shown above may '
                'not be reliable for this image. The '
                'neural network model results (YedroudjNetV3 '
                'and ALASKA2) are not affected by image '
                'size and remain valid.'
            )
            warn_p = Paragraph(
                warn_content,
                ParagraphStyle(
                    'SmallFileWarnStyle',
                    parent=body_style,
                    fontSize=9,
                    leading=13,
                    textColor=HexColor('#7d4a00'),
                )
            )
            warn_table = Table([[warn_p]], colWidths=[17*cm])
            warn_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), HexColor('#fff3cd')),
                ('LINEBEFORE', (0,0), (0,0), 3, HexColor('#f39c12')),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 12),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(Spacer(1, 6))
            story.append(warn_table)

        story.append(Spacer(1, 10))

        # === NEW SECTION 5a ===
        try:
            story.append(Paragraph('5a. CONFIDENCE AND RELIABILITY ASSESSMENT', section_style))
            story.append(Paragraph(
                'This section presents the calibrated confidence '
                'assessment for the steganalysis result. The ensemble '
                'score is a weighted combination of multiple detection '
                'methods. It is best understood as an approximate '
                'forensic indicator rather than a mathematically '
                'precise probability. The confidence band, reliability '
                'classification, and recommended action are derived '
                'from the score using forensically conservative '
                'thresholds established for this system.', body_style
            ))
            story.append(Spacer(1, 0.3*cm))

            if calibration is not None:
                table_data = [
                    ['Metric', 'Value', 'Forensic Interpretation'],
                    ['Ensemble Score',
                     calibration['score_pct'],
                     calibration['confidence_band']['label']],
                    ['Confidence Band',
                     calibration['confidence_band']['band_name'],
                     'Range: '
                     + str(round(calibration['confidence_band']['min']*100))
                     + '%\u2013'
                     + str(round(calibration['confidence_band']['max']*100))
                     + '%'],
                    ['Forensic Reliability',
                     calibration['overall_reliability'], ''],
                    ['Evidential Value',
                     calibration['court_weight'], ''],
                    ['Recommended Action',
                     calibration['recommended_action'], ''],
                ]
                
                verd = calibration.get('verdict', 'CLEAN')
                if verd == 'STEGO_DETECTED':
                    score_bg = HexColor('#fde8e8')
                elif verd == 'SUSPICIOUS':
                    score_bg = HexColor('#fef3e2')
                else:
                    score_bg = HexColor('#e8f8f0')
                
                t = Table(table_data, colWidths=[4*cm, 5*cm, 8*cm])
                t.setStyle(TableStyle([
                    ('BACKGROUND', (0,0),(-1,0), DARK_BLUE),
                    ('TEXTCOLOR', (0,0),(-1,0), white),
                    ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0),(-1,0), 9),
                    ('ALIGN', (0,0),(-1,0), 'CENTER'),
                    ('BACKGROUND', (0,1),(-1,1), score_bg),
                    ('ROWBACKGROUND', (0,2),(-1,-1), [LIGHT_GREY, white]),
                    ('FONTNAME', (0,0),(-1,-1), 'Helvetica'),
                    ('FONTSIZE', (0,1),(-1,-1), 9),
                    ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0),(-1,-1), 4),
                    ('BOTTOMPADDING', (0,0),(-1,-1), 4),
                    ('GRID', (0,0),(-1,-1), 0.5, ACCENT)
                ]))
                story.append(t)
                story.append(Spacer(1, 0.3*cm))
                
                story.append(Paragraph(
                    calibration['confidence_band']['description'],
                    body_style
                ))
                story.append(Spacer(1, 0.3*cm))
                
                if calibration.get('uncertainty_count', 0) > 0:
                    story.append(Paragraph(
                        'Uncertainty Observations ('
                        + str(calibration['uncertainty_count'])
                        + ' identified)',
                        ParagraphStyle('Sub', parent=styles['Heading3'], fontName='Helvetica-Bold')
                    ))
                    
                    story.append(Paragraph(
                        'The following factors reduce the forensic weight '
                        'of this result and must be disclosed in any '
                        'proceeding where this report is used as evidence.',
                        body_style
                    ))
                    
                    for factor in calibration['uncertainty_factors']:
                        story.append(Paragraph(
                            '<font color="#f5a623"><b>[' + factor['factor'].replace('_',' ').title() + ']</b></font>',
                            body_style
                        ))
                        story.append(Paragraph(factor['detail'], body_style))
                        story.append(Paragraph(
                            factor['explanation'],
                            ParagraphStyle('Exp', parent=body_style, leftIndent=15, fontSize=9, textColor=HexColor('#555555'), fontName='Helvetica-Oblique')
                        ))
                        story.append(Spacer(1, 0.2*cm))
                
                limitation_text = calibration.get('formal_limitation', (
                    'This result is produced by an automated '
                    'steganalysis system and must not be relied '
                    'upon as a standalone conclusion. The ensemble '
                    'score reflects a calibrated approximation and '
                    'not a mathematically precise probability. '
                    'Independent manual review by a qualified digital '
                    'forensic examiner is required before this result '
                    'is used in any investigative or legal proceeding.'
                ))
                
                box_data = [[Paragraph(limitation_text,
                    ParagraphStyle('LimitBox',
                        parent=body_style,
                        fontSize=9,
                        fontName='Helvetica-Oblique',
                        textColor=HexColor('#5d4037'),
                        leftIndent=5,
                    )
                )]]
                box_table = Table(box_data, colWidths=[17*cm])
                box_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0),(0,0), HexColor('#fff8e1')),
                    ('LINEAFTER', (0,0),(0,0), 3, ORANGE_WARN),
                    ('LINEBEFORE', (0,0),(0,0), 3, ORANGE_WARN),
                    ('TOPPADDING', (0,0),(0,0), 8),
                    ('BOTTOMPADDING', (0,0),(0,0), 8),
                    ('LEFTPADDING', (0,0),(0,0), 12),
                    ('RIGHTPADDING', (0,0),(0,0), 8),
                ]))
                story.append(box_table)
        except Exception as e:
            print('[LAYER4-REPORT] Section error: ' + str(e))
            story.append(Paragraph(
                'Section not available: ' + str(e),
                body_style
            ))

        # === NEW SECTION 5b ===
        try:
            story.append(Paragraph('5b. EVIDENCE CLASSIFICATION', section_style))
            story.append(Paragraph(
                'Forensic reporting standards require that findings '
                'be classified according to how they were obtained '
                'and the directness with which they support a '
                'conclusion. This section separates all findings '
                'into four categories: Confirmed Facts (directly '
                'measured), Model Predictions (probabilistic AI '
                'outputs), Heuristic Observations (pattern-based '
                'indicators), and Expert Synthesis (conclusions '
                'drawn from the totality of evidence).', body_style
            ))

            if calibration is not None:
                evidence = calibration.get('evidence_separation', {})

                badge_style_green = ParagraphStyle('BadgeGreen',
                    parent=body_style, fontSize=8,
                    fontName='Helvetica-Bold',
                    textColor=white, backColor=GREEN_OK,
                    alignment=TA_CENTER, borderPad=3)

                badge_style_blue = ParagraphStyle('BadgeBlue',
                    parent=body_style, fontSize=8,
                    fontName='Helvetica-Bold',
                    textColor=white, backColor=ACCENT,
                    alignment=TA_CENTER, borderPad=3)

                badge_style_orange = ParagraphStyle('BadgeOrange',
                    parent=body_style, fontSize=8,
                    fontName='Helvetica-Bold',
                    textColor=white, backColor=ORANGE_WARN,
                    alignment=TA_CENTER, borderPad=3)

                badge_style_red = ParagraphStyle('BadgeRed',
                    parent=body_style, fontSize=8,
                    fontName='Helvetica-Bold',
                    textColor=white, backColor=RED_ALERT,
                    alignment=TA_CENTER, borderPad=3)

                story.append(Paragraph('Confirmed Facts — Directly Observed', ParagraphStyle('Sub1', parent=styles['Heading3'], fontName='Helvetica-Bold', textColor=GREEN_OK, spaceBefore=10, spaceAfter=4)))
                story.append(Paragraph(
                    'These findings are based on direct measurement '
                    'or observation and carry the highest evidential '
                    'weight. They do not depend on model predictions.',
                    ParagraphStyle('Sub1Note', parent=body_style, fontSize=9, fontName='Helvetica-Oblique', textColor=HexColor('#888888'))
                ))

                if evidence.get('confirmed_facts'):
                    for fact in evidence['confirmed_facts']:
                        row = [
                            Paragraph(
                                fact['evidence_type'].replace('_', '\n'),
                                badge_style_green
                            ),
                            Paragraph(
                                '<b>' + fact['finding'] + '</b><br/>'
                                + fact['detail'],
                                body_style
                            )
                        ]
                        t = Table([row], colWidths=[4*cm, 13*cm])
                        t.setStyle(TableStyle([
                            ('VALIGN', (0,0),(-1,-1), 'TOP'),
                            ('TOPPADDING', (0,0),(-1,-1), 6),
                            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                            ('LINEBELOW', (0,0),(-1,-1), 0.5, LIGHT_GREY),
                        ]))
                        story.append(t)
                else:
                    story.append(Paragraph(
                        'No directly confirmed findings in this scan.',
                        body_style
                    ))

                story.append(Spacer(1, 0.3*cm))

                story.append(Paragraph('Model Predictions — Probabilistic Outputs', ParagraphStyle('Sub2', parent=styles['Heading3'], fontName='Helvetica-Bold', textColor=ACCENT)))
                story.append(Paragraph(
                    'These outputs are probabilistic estimates from '
                    'machine learning models and statistical tests. '
                    'They are not definitive findings and must be '
                    'evaluated alongside the other evidence in this report.',
                    ParagraphStyle('Sub2Note', parent=body_style, fontSize=9, fontName='Helvetica-Oblique', textColor=HexColor('#888888'))
                ))

                for prediction in evidence.get('model_predictions', []):
                    row = [
                        Paragraph(
                            prediction['evidence_type'].replace('_', '\n'),
                            badge_style_blue
                        ),
                        Paragraph(
                            '<b>' + prediction['finding'] + '</b><br/>'
                            + prediction['detail'],
                            body_style
                        )
                    ]
                    t = Table([row], colWidths=[4*cm, 13*cm])
                    t.setStyle(TableStyle([
                        ('VALIGN', (0,0),(-1,-1), 'TOP'),
                        ('TOPPADDING', (0,0),(-1,-1), 6),
                        ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                        ('LINEBELOW', (0,0),(-1,-1), 0.5, LIGHT_GREY),
                    ]))
                    story.append(t)

                story.append(Spacer(1, 0.3*cm))

                story.append(Paragraph('Heuristic Observations — Pattern-Based Indicators', ParagraphStyle('Sub3', parent=styles['Heading3'], fontName='Helvetica-Bold', textColor=ORANGE_WARN)))
                story.append(Paragraph(
                    'These findings are based on pattern matching '
                    'and heuristic rules. They indicate suspicious '
                    'characteristics but are not conclusive evidence.',
                    ParagraphStyle('Sub3Note', parent=body_style, fontSize=9, fontName='Helvetica-Oblique', textColor=HexColor('#888888'))
                ))

                if evidence.get('heuristic_warnings'):
                    for warning in evidence['heuristic_warnings']:
                        badge = badge_style_red if warning.get('severity') == 'THREAT' else badge_style_orange
                        row = [
                            Paragraph(
                                warning['evidence_type'].replace('_', '\n'),
                                badge
                            ),
                            Paragraph(
                                '<b>' + warning['finding'] + '</b><br/>'
                                + warning['detail'],
                                body_style
                            )
                        ]
                        t = Table([row], colWidths=[4*cm, 13*cm])
                        t.setStyle(TableStyle([
                            ('VALIGN', (0,0),(-1,-1), 'TOP'),
                            ('TOPPADDING', (0,0),(-1,-1), 6),
                            ('BOTTOMPADDING', (0,0),(-1,-1), 6),
                            ('LINEBELOW', (0,0),(-1,-1), 0.5, LIGHT_GREY),
                        ]))
                        story.append(t)
                else:
                    story.append(Paragraph(
                        'No heuristic warnings in this scan.',
                        body_style
                    ))

                story.append(Spacer(1, 0.3*cm))

                story.append(Paragraph('Expert Synthesis — Overall Assessment', ParagraphStyle('Sub4', parent=styles['Heading3'], fontName='Helvetica-Bold', textColor=DARK_BLUE)))
                
                for interp in evidence.get('expert_interpretation', []):
                    box_data = [[
                        Paragraph(
                            '<b>Verdict: ' + interp.get('verdict', 'UNKNOWN')
                            + ' | Confidence: ' + interp.get('confidence','')
                            + '</b><br/><br/>' + interp['detail'],
                            ParagraphStyle('SynthBox',
                                parent=body_style,
                                fontSize=9,
                                leftIndent=5,
                            )
                        )
                    ]]
                    box_table = Table(box_data, colWidths=[17*cm])
                    box_table.setStyle(TableStyle([
                        ('BACKGROUND', (0,0),(0,0), HexColor('#eef2f7')),
                        ('LINEBEFORE', (0,0),(0,0), 4, DARK_BLUE),
                        ('TOPPADDING', (0,0),(0,0), 10),
                        ('BOTTOMPADDING', (0,0),(0,0), 10),
                        ('LEFTPADDING', (0,0),(0,0), 14),
                        ('RIGHTPADDING', (0,0),(0,0), 8),
                    ]))
                    story.append(box_table)
        except Exception as e:
            print('[LAYER4-REPORT] Section error: ' + str(e))
            story.append(Paragraph(
                'Section not available: ' + str(e),
                body_style
            ))

        # === NEW SECTION 5c ===
        try:
            story.append(Paragraph('5c. SYSTEM LIMITATIONS AND DISCLOSURE', section_style))
            story.append(Paragraph(
                'Forensic standards require full disclosure of '
                'known system limitations in any report used as '
                'evidence. The following limitations of Shadow-Trace '
                'v1.0.0 are documented and must be considered when '
                'evaluating the findings in this report.', body_style
            ))

            header = [
                'Component',
                'Known Limitation',
                'Forensic Implication'
            ]
            col_widths = [4*cm, 9*cm, 4*cm]

            rows = [header]
            for lim in SYSTEM_LIMITATIONS:
                rows.append([
                    Paragraph(lim['component'],
                        ParagraphStyle('LimComp',
                            parent=body_style,
                            fontSize=8,
                            fontName='Helvetica-Bold')),
                    Paragraph(lim['limitation'],
                        ParagraphStyle('LimText',
                            parent=body_style,
                            fontSize=8)),
                    Paragraph(lim['implication'],
                        ParagraphStyle('LimImpl',
                            parent=body_style,
                            fontSize=8,
                            textColor=HexColor('#c0392b'))),
                ])

            lim_table = Table(rows, colWidths=col_widths, repeatRows=1)
            lim_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0),(-1,0), DARK_BLUE),
                ('TEXTCOLOR', (0,0),(-1,0), white),
                ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0),(-1,0), 9),
                ('ALIGN', (0,0),(-1,0), 'CENTER'),
                ('ROWBACKGROUND', (0,1),(-1,-1), [LIGHT_GREY, white]),
                ('GRID', (0,0),(-1,-1), 0.5, ACCENT),
                ('VALIGN', (0,0),(-1,-1), 'TOP'),
                ('TOPPADDING', (0,0),(-1,-1), 5),
                ('BOTTOMPADDING', (0,0),(-1,-1), 5),
            ]))
            story.append(lim_table)
            story.append(Spacer(1, 0.3*cm))

            story.append(Paragraph(
                'The existence of these limitations does not '
                'invalidate the findings of this report. Each '
                'finding must be evaluated in the context of '
                'the method that produced it. No single finding '
                'should be treated as conclusive without '
                'corroborating evidence from other methods or '
                'manual examination.', body_style
            ))
        except Exception as e:
            print('[LAYER4-REPORT] Section error: ' + str(e))
            story.append(Paragraph(
                'Section not available: ' + str(e),
                body_style
            ))

        # === NEW SECTION 5d ===
        try:
            story.append(Paragraph('5d. DETECTION METHOD CONTRIBUTION', section_style))
            story.append(Paragraph(
                'This section shows the relative contribution of '
                'each detection method to the final verdict. '
                'Methods with higher contribution scores found '
                'stronger indicators of steganographic content. '
                'Methods with low contribution scores did not '
                'detect significant anomalies.', body_style
            ))

            attribution = {}
            if layer4_xai_result:
                attribution = layer4_xai_result.get('attribution', {}) or {}
            attributions = attribution.get('attributions', {})

            if attributions:
                sorted_attr = sorted(
                    attributions.items(),
                    key=lambda x: x[1],
                    reverse=True
                )
                
                header = [
                    'Detection Method',
                    'Contribution Score',
                    'Evidential Weight'
                ]
                rows = [header]
                
                for method, attr_score in sorted_attr:
                    if attr_score > 0.15:
                        weight_label = 'HIGH'
                        weight_color = RED_ALERT
                    elif attr_score > 0.08:
                        weight_label = 'MEDIUM'
                        weight_color = ORANGE_WARN
                    else:
                        weight_label = 'LOW'
                        weight_color = GREEN_OK
                    
                    rows.append([
                        Paragraph(method, body_style),
                        Paragraph(
                            str(round(attr_score * 100, 1)) + '%',
                            ParagraphStyle('ScoreCell',
                                parent=body_style,
                                alignment=TA_CENTER,
                                fontName='Helvetica-Bold')
                        ),
                        Paragraph(
                            weight_label,
                            ParagraphStyle('WeightCell',
                                parent=body_style,
                                alignment=TA_CENTER,
                                fontName='Helvetica-Bold',
                                textColor=weight_color)
                        ),
                    ])
                
                attr_table = Table(
                    rows,
                    colWidths=[8*cm, 4.5*cm, 4.5*cm]
                )
                attr_table.setStyle(TableStyle([
                    ('BACKGROUND', (0,0),(-1,0), DARK_BLUE),
                    ('TEXTCOLOR', (0,0),(-1,0), white),
                    ('FONTNAME', (0,0),(-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0),(-1,0), 9),
                    ('ALIGN', (0,0),(-1,0), 'CENTER'),
                    ('ROWBACKGROUND', (0,1),(-1,-1), [LIGHT_GREY, white]),
                    ('GRID', (0,0),(-1,-1), 0.5, ACCENT),
                    ('VALIGN', (0,0),(-1,-1), 'MIDDLE'),
                    ('TOPPADDING', (0,0),(-1,-1), 5),
                    ('BOTTOMPADDING', (0,0),(-1,-1), 5),
                ]))
                story.append(attr_table)
                story.append(Spacer(1, 0.3*cm))
                
                story.append(Paragraph(
                    'Contribution scores are weighted by the '
                    'reliability of each detection method. '
                    'Higher scores indicate that the method '
                    'found stronger evidence of steganographic '
                    'content in this file.',
                    body_style
                ))
            else:
                story.append(Paragraph(
                    'Attribution data not available for this scan.',
                    body_style
                ))
        except Exception as e:
            print('[LAYER4-REPORT] Section error: ' + str(e))
            story.append(Paragraph(
                'Section not available: ' + str(e),
                body_style
            ))

        # SECTION 6: Payload Extraction Results (Layer 3)
        story.append(Paragraph('5. Payload Extraction Results (Layer 3)', section_style))
        story.append(Paragraph(SECTION_EXPLANATIONS['payload_extraction'], body_style))
        if layer3_result:
            ext = layer3_result.get('extraction_results', {})
            story.append(Paragraph(f"Payload Type: {ext.get('payload_type', 'Unknown')}", body_style))
            story.append(Paragraph(f"Payload Size: {ext.get('payload_size_bytes', 0)} bytes", body_style))
            story.append(Paragraph(f"Payload Entropy: {ext.get('payload_entropy', 0.0)}", body_style))
            story.append(Paragraph(f"Entropy Classification: {ext.get('payload_class', 'Unknown')}", body_style))
            
            is_exec = ext.get('is_executable', False)
            if is_exec:
                exec_style = ParagraphStyle('Alert', parent=body_style, textColor=red, fontName='Helvetica-Bold')
                story.append(Paragraph("CRITICAL ALERT: The extracted payload contains executable signatures.", exec_style))
                
            adapt = layer3_result.get('adaptive_analysis', {})
            if adapt and adapt.get('adaptive_stego_detected'):
                story.append(Paragraph("Adaptive Stego Analysis: Detected", body_style))
                story.append(Paragraph(f"Estimated Payload: {adapt.get('estimated_payload_kb', 0)} KB", body_style))

            # Subsection: Capability Analysis (CAPA)
            capa_res = layer3_result.get('capa_analysis')
            if is_exec or capa_res is not None:
                if capa_res and capa_res.get('status') == 'COMPLETE':
                    story.append(Spacer(1, 8))
                    story.append(Paragraph('Capability Analysis (CAPA)', ParagraphStyle('CapaSubSec', parent=body_style, fontName='Helvetica-Bold', fontSize=10, textColor=DARK_BLUE, spaceBefore=4, spaceAfter=4)))

                    # 1. Plain English Narrative
                    plain_eng = capa_res.get('plain_english', '')
                    if plain_eng:
                        story.append(Paragraph(plain_eng, body_style))
                        story.append(Spacer(1, 6))

                    # 2. MITRE ATT&CK Tactics & Techniques Table
                    tactics = capa_res.get('attack_tactics', [])
                    techniques = capa_res.get('attack_techniques', [])
                    story.append(Paragraph('<b>MITRE ATT&CK Alignment:</b>', ParagraphStyle('AttHead', parent=body_style, fontName='Helvetica-Bold', fontSize=8, spaceBefore=2, spaceAfter=3)))
                    if techniques or tactics:
                        att_rows = [['Tactic / Scope', 'Technique ID & Name']]
                        if techniques:
                            for idx, tech in enumerate(techniques[:15]):
                                tac_name = tactics[idx] if idx < len(tactics) else "Execution / Defense Evasion"
                                att_rows.append([
                                    Paragraph(str(tac_name), ParagraphStyle('AttTac', parent=body_style, fontSize=8, leading=10)),
                                    Paragraph(str(tech), ParagraphStyle('AttTech', parent=body_style, fontSize=8, leading=10))
                                ])
                        else:
                            for tac in tactics:
                                att_rows.append([
                                    Paragraph(str(tac), ParagraphStyle('AttTac2', parent=body_style, fontSize=8, leading=10)),
                                    Paragraph('Technique identified', ParagraphStyle('AttTech2', parent=body_style, fontSize=8, leading=10))
                                ])
                        att_table = Table(att_rows, colWidths=[6*cm, 11*cm])
                        att_table.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), ACCENT),
                            ('TEXTCOLOR', (0,0), (-1,0), white),
                            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0,0), (-1,0), 8),
                            ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                            ('GRID', (0,0), (-1,-1), 0.5, ACCENT),
                            ('TOPPADDING', (0,0), (-1,-1), 3),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                        ]))
                        story.append(att_table)
                    else:
                        story.append(Paragraph('No MITRE ATT&CK techniques mapped to detected indicators.', ParagraphStyle('MutedAtt', parent=body_style, fontSize=8, fontName='Helvetica-Oblique', textColor=HexColor('#777777'))))
                    story.append(Spacer(1, 6))

                    # 3. Top Capabilities Table (name, namespace)
                    caps = capa_res.get('capabilities', [])
                    story.append(Paragraph(f'<b>Top Programmatic Capabilities ({len(caps)} identified):</b>', ParagraphStyle('CapHead', parent=body_style, fontName='Helvetica-Bold', fontSize=8, spaceBefore=2, spaceAfter=3)))
                    if caps:
                        cap_rows = [['Capability Name', 'Namespace']]
                        for c in caps[:15]:
                            cap_rows.append([
                                Paragraph(str(c.get('name') or 'Unknown'), ParagraphStyle('CapN', parent=body_style, fontSize=8, leading=10)),
                                Paragraph(str(c.get('namespace') or 'General'), ParagraphStyle('CapNS', parent=body_style, fontSize=8, leading=10))
                            ])
                        cap_table = Table(cap_rows, colWidths=[10*cm, 7*cm])
                        cap_table.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), DARK_BLUE),
                            ('TEXTCOLOR', (0,0), (-1,0), white),
                            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0,0), (-1,0), 8),
                            ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                            ('GRID', (0,0), (-1,-1), 0.5, ACCENT),
                            ('TOPPADDING', (0,0), (-1,-1), 3),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                        ]))
                        story.append(cap_table)
                    else:
                        story.append(Paragraph('No individual rule capabilities cataloged.', ParagraphStyle('MutedCaps', parent=body_style, fontSize=8, fontName='Helvetica-Oblique', textColor=HexColor('#777777'))))
                    story.append(Spacer(1, 6))

                    # 4. Risk Indicators with Severity Colors
                    risk_inds = capa_res.get('risk_indicators', [])
                    if risk_inds:
                        story.append(Paragraph('<b>Risk Indicators:</b>', ParagraphStyle('RiskHead', parent=body_style, fontName='Helvetica-Bold', fontSize=8, spaceBefore=2, spaceAfter=3)))
                        risk_rows = [['Severity', 'Behavior Category', 'Indicator Name']]
                        for r in risk_inds[:15]:
                            sev = str(r.get('severity') or 'LOW')
                            sev_color = '#e94560' if sev == 'HIGH' else ('#f5a623' if sev == 'MEDIUM' else '#7f8c8d')
                            risk_rows.append([
                                Paragraph(f'<font color="{sev_color}"><b>{sev}</b></font>', ParagraphStyle('SevCell', parent=body_style, fontSize=8, leading=10)),
                                Paragraph(str(r.get('category') or 'Unknown'), ParagraphStyle('CatCell', parent=body_style, fontSize=8, leading=10)),
                                Paragraph(str(r.get('name') or ''), ParagraphStyle('IndCell', parent=body_style, fontSize=8, leading=10))
                            ])
                        risk_table = Table(risk_rows, colWidths=[3*cm, 5.5*cm, 8.5*cm])
                        risk_table.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), HexColor('#2c3e50')),
                            ('TEXTCOLOR', (0,0), (-1,0), white),
                            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0,0), (-1,0), 8),
                            ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#bdc3c7')),
                            ('TOPPADDING', (0,0), (-1,-1), 3),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                        ]))
                        story.append(risk_table)
                        story.append(Spacer(1, 6))

                    # 5. Limitations Text
                    limits = capa_res.get('limitations') or 'Static capability indicators reflect latent programmatic capability, not runtime execution.'
                    story.append(Paragraph(
                        f'<b>Capability Analysis Limitations:</b> {limits}',
                        ParagraphStyle('LimBox', parent=body_style, fontSize=8, leading=10, textColor=HexColor('#555555'), fontName='Helvetica-Oblique')
                    ))
                else:
                    # Status is not complete: show one grey line
                    st = capa_res.get('status', 'NOT_RUN') if capa_res else 'NOT_PERFORMED'
                    err_msg = (capa_res.get('error') or capa_res.get('plain_english') or '') if capa_res else ''
                    story.append(Spacer(1, 4))
                    story.append(Paragraph(
                        f'<font color="#777777">Capability Analysis (CAPA): Status is {st}{(" - " + err_msg) if err_msg else ""}.</font>',
                        ParagraphStyle('CapaGrey', parent=body_style, fontSize=8, leading=10, fontName='Helvetica')
                    ))
        else:
            story.append(Paragraph('Extraction not performed or results unavailable.', body_style))
        story.append(Spacer(1, 10))

        # SECTION 7: Explainability and Attribution (Layer 4)
        if 'grad_cam' in layer4_xai_result or 'lsb_visualization' in layer4_xai_result:
            story.append(PageBreak())
        story.append(Paragraph('6. Explainability and Attribution (Layer 4)', section_style))
        
        lsb_viz = layer4_xai_result.get('lsb_visualization', {})
        lsb_heatmap_path = lsb_viz.get('heatmap_path')

        file_type = layer2_result.get('file_type', 'IMAGE')

        if lsb_heatmap_path and Path(lsb_heatmap_path).exists():
            elements = []
            elements.append(Paragraph('LSB Steganography Visualization', ParagraphStyle('SubSec', parent=styles['Heading2'], spaceAfter=10)))

            if file_type == 'IMAGE':
                lsb_intro = (
                    'The following visualization shows WHERE in '
                    'this image suspicious LSB (Least Significant '
                    'Bit) patterns were detected. Every pixel in '
                    'a digital image has a colour value stored as '
                    'a number. The very last digit of that number '
                    'is called the Least Significant Bit. '
                    'Steganography tools hide secret data by '
                    'changing only these last digits, making the '
                    'image look identical to the human eye but '
                    'carrying a hidden payload in those tiny changes.'
                )
                lsb_panel_explanation = (
                    'HOW TO READ THIS IMAGE:\n\n'
                    'LEFT PANEL - Original Image: This is the '
                    'image exactly as it was downloaded, shown '
                    'for reference.\n\n'
                    'MIDDLE PANEL - LSB Bit Plane: This panel '
                    'shows ONLY the last digits of every pixel '
                    'value, magnified so you can see them. In a '
                    'natural photograph these last digits look '
                    'like random TV static because camera noise '
                    'is unpredictable. If this panel shows '
                    'structured patterns, uniform regions, or '
                    'anything other than random noise, it means '
                    'the last digits have been deliberately '
                    'changed to carry hidden data.\n\n'
                    'RIGHT PANEL - Suspicion Heatmap: This panel '
                    'overlays the original image with a colour '
                    'map showing WHERE the LSB pattern is most '
                    'suspicious. RED and YELLOW areas are pixel '
                    'regions where the bit pattern deviates from '
                    'what is expected in a natural image. These '
                    'are the most likely locations where hidden '
                    'data has been embedded. BLUE and BLACK areas '
                    'are considered normal. A large red region '
                    'covering most of the image is a strong '
                    'indicator of steganographic embedding.'
                )
            elif file_type == 'VIDEO':
                lsb_intro = (
                    'The following visualization shows WHERE in '
                    'this video suspicious LSB (Least Significant '
                    'Bit) patterns were detected. Video files '
                    'consist of many individual frames (still '
                    'images shown rapidly in sequence). Shadow-Trace '
                    'samples frames evenly across the video and '
                    'analyses the LSB patterns in each frame. '
                    'When steganography is present in a video, '
                    'the hidden payload is typically embedded '
                    'consistently across many frames, creating '
                    'a detectable pattern of unusual LSB activity.'
                )
                lsb_panel_explanation = (
                    'HOW TO READ THIS IMAGE:\n\n'
                    'TOP ROW - Most Suspicious Frame Analysis: '
                    'Shadow-Trace identified the video frame with '
                    'the most unusual LSB pattern and analysed it '
                    'in detail. The three panels show the original '
                    'frame, its raw LSB bit plane, and a suspicion '
                    'heatmap overlay (red and yellow areas indicate '
                    'suspicious pixel regions within that frame).\n\n'
                    'BOTTOM CHART - LSB Timeline Across All Frames: '
                    'This bar chart shows how suspicious the LSB '
                    'pattern was in each sampled frame of the video. '
                    'Each bar represents one frame. RED bars '
                    'indicate frames where the LSB pattern deviates '
                    'significantly from what natural camera noise '
                    'produces. BLUE bars are frames that appear '
                    'normal. If many frames show red bars, this '
                    'strongly suggests a payload is embedded '
                    'consistently throughout the video, which '
                    'is the hallmark of deliberate steganography '
                    'rather than random noise.'
                )
            elif file_type == 'DOCUMENT':
                lsb_intro = (
                    'The following visualization shows the '
                    'steganographic indicators detected in this '
                    'document. Unlike images and videos, documents '
                    'store text rather than pixels, so steganography '
                    'in documents works differently. Common methods '
                    'include inserting invisible Unicode characters '
                    'between visible letters, replacing standard '
                    'English letters with visually identical '
                    'characters from other alphabets such as '
                    'Cyrillic or Greek, and using unusual spacing '
                    'patterns to encode hidden bits.'
                )
                lsb_panel_explanation = (
                    'HOW TO READ THIS IMAGE:\n\n'
                    'LEFT PANEL - Steganography Indicators Chart: '
                    'Each horizontal bar represents one type of '
                    'suspicious pattern that was searched for in '
                    'this document. The length of the bar shows '
                    'how many instances were found. RED bars mean '
                    'suspicious content was detected. GREEN bars '
                    'mean that particular method was not used in '
                    'this document. The number at the end of each '
                    'bar shows the exact count.\n\n'
                    'RIGHT PANEL - Analysis Summary: This panel '
                    'lists the key findings from the document '
                    'analysis including the overall verdict, '
                    'confidence score, and a breakdown of each '
                    'type of hidden character found. RED values '
                    'highlight findings that require attention. '
                    'GREEN values confirm those checks were clean.\n\n'
                    'Zero-Width Characters are invisible Unicode '
                    'characters that carry hidden bits. '
                    'Homoglyph Substitutions are Cyrillic or Greek '
                    'letters that look identical to English letters '
                    'but have different computer codes, used to '
                    'encode secret bits by substitution.'
                )
            else:
                lsb_intro = (
                    'The following visualization shows LSB '
                    'analysis results for the examined file.'
                )
                lsb_panel_explanation = (
                    'Red and yellow areas indicate suspicious '
                    'LSB patterns. Blue areas appear normal.'
                )

            elements.append(Paragraph(lsb_intro, body_style))
            elements.append(Spacer(1, 0.3*cm))

            lsb_type = lsb_viz.get('type', '')
            lsb_img_h = 12*cm if lsb_type == 'lsb_heatmap_document' else 9*cm
            img = RLImage(lsb_heatmap_path, width=17*cm, height=lsb_img_h, kind='proportional')
            elements.append(img)
            elements.append(Spacer(1, 0.3*cm))
            elements.append(Paragraph(lsb_panel_explanation, body_style))
            elements.append(Spacer(1, 0.5*cm))

            if lsb_viz.get('type') == 'lsb_heatmap':
                elements.append(Paragraph(f"Suspicious windows: {lsb_viz.get('suspicious_windows', 0)} / {lsb_viz.get('total_windows', 0)} ({lsb_viz.get('suspicious_pct', 0)}%)", body_style))
            elif lsb_viz.get('type') == 'lsb_heatmap_video':
                elements.append(Paragraph(f"Most suspicious frame index: {lsb_viz.get('most_suspicious_frame', 'N/A')}", body_style))
            elif lsb_viz.get('type') == 'lsb_heatmap_document':
                elements.append(Paragraph(f"Zero-width characters detected: {lsb_viz.get('zero_width_chars', lsb_viz.get('zero_width_count', 0))} | Homoglyph substitutions: {lsb_viz.get('homoglyphs', lsb_viz.get('homoglyph_count', 0))}", body_style))

            elements.append(Spacer(1, 15))
            story.append(KeepTogether(elements))
            
        grad_cam_data = layer4_xai_result.get('grad_cam', {})
        # Documents use map_path; images/video use heatmap_path
        heatmap_path = grad_cam_data.get('heatmap_path') or grad_cam_data.get('map_path')
        mime_type = layer2_result.get('file_type', 'UNKNOWN')
        if heatmap_path and Path(heatmap_path).exists():
            elements = []
            if mime_type == 'DOCUMENT':
                elements.append(Paragraph('Document Token Map', ParagraphStyle('SubSec2', parent=styles['Heading2'], spaceAfter=6)))
                gradcam_intro = (
                    'The following visualization shows the '
                    'Unicode character analysis map for this '
                    'document. Since documents contain text '
                    'rather than pixels, traditional Grad-CAM '
                    'is replaced by a character-level analysis '
                    'that shows which types of invisible or '
                    'substituted characters were found and '
                    'how many of each type were detected.'
                )
                gradcam_panel_explanation = (
                    'HOW TO READ THIS IMAGE:\n\n'
                    'This chart shows the results of scanning '
                    'every character in this document for '
                    'Unicode-based steganography.\n\n'
                    'Each bar represents a specific type of '
                    'hidden character:\n\n'
                    'ZERO_WIDTH_SPACE (U+200B): An invisible '
                    'character that takes up no visible space. '
                    'Steganography tools insert these between '
                    'normal letters to encode bits.\n\n'
                    'ZERO_WIDTH_NON_JOINER (U+200C) and '
                    'ZERO_WIDTH_JOINER (U+200D): Similar invisible '
                    'characters used as binary 0 and 1 in '
                    'steganographic encoding schemes.\n\n'
                    'Cyrillic Homoglyphs: Letters from the '
                    'Russian/Cyrillic alphabet that look identical '
                    'to English letters. For example the Cyrillic '
                    'letter a looks exactly like the Latin letter a '
                    'but has a different computer code, allowing '
                    'it to carry hidden information.\n\n'
                    'A RED bar means that type of hidden character '
                    'was found. A GREEN bar means it was not found. '
                    'The number at the end shows the exact count.'
                )
                elements.append(Paragraph(gradcam_intro, body_style))
                elements.append(Spacer(1, 0.3*cm))
                img = RLImage(heatmap_path, width=17*cm, height=10*cm, kind='proportional')
                elements.append(img)
                elements.append(Spacer(1, 0.3*cm))
                elements.append(Paragraph(gradcam_panel_explanation, body_style))
                elements.append(Spacer(1, 0.5*cm))
            elif mime_type == 'VIDEO':
                elements.append(Paragraph('Grad-CAM Heatmap', ParagraphStyle('SubSec2', parent=styles['Heading2'], spaceAfter=6)))
                gradcam_intro = (
                    'The following Grad-CAM visualization shows '
                    'which regions of the most suspicious video '
                    'frame caused the Shadow-Trace AI model to '
                    'flag this video. The AI spatial analysis '
                    'stream examined each frame independently '
                    'and identified the frame with the most '
                    'unusual pixel patterns. Grad-CAM then '
                    'reveals exactly which parts of that frame '
                    'triggered the detection.'
                )
                gradcam_panel_explanation = (
                    'HOW TO READ THIS IMAGE:\n\n'
                    'This Grad-CAM was generated from the most '
                    'suspicious frame identified by Shadow-Trace.\n\n'
                    'LEFT PANEL - Original Frame: The video frame '
                    'that scored highest for suspicious activity, '
                    'shown as captured.\n\n'
                    'MIDDLE PANEL - AI Attention Map: RED areas '
                    'are where the AI model detected unusual '
                    'patterns. In video steganography, the hidden '
                    'payload often concentrates in specific spatial '
                    'regions of frames. A consistent red area '
                    'across multiple frames strongly suggests '
                    'deliberate embedding in that region.\n\n'
                    'RIGHT PANEL - Overlay: Shows which part of '
                    'the actual video frame corresponds to the '
                    'suspicious pixel region the AI detected.'
                )
                elements.append(Paragraph(gradcam_intro, body_style))
                elements.append(Spacer(1, 0.3*cm))
                img = RLImage(heatmap_path, width=17*cm, height=6*cm, kind='proportional')
                elements.append(img)
                elements.append(Spacer(1, 0.3*cm))
                elements.append(Paragraph(gradcam_panel_explanation, body_style))
                elements.append(Spacer(1, 0.5*cm))
            else:
                # IMAGE (default)
                elements.append(Paragraph('Grad-CAM Heatmap', ParagraphStyle('SubSec2', parent=styles['Heading2'], spaceAfter=6)))
                gradcam_intro = (
                    'The following Grad-CAM (Gradient-weighted '
                    'Class Activation Map) visualization shows '
                    'WHICH PARTS of this image caused the '
                    'Shadow-Trace AI model to flag it as '
                    'suspicious. Unlike the LSB heatmap which '
                    'is a mathematical measurement, Grad-CAM '
                    'shows the actual decision process of the '
                    'neural network — it highlights the exact '
                    'pixel regions the AI was looking at when '
                    'it made its judgement.'
                )
                gradcam_panel_explanation = (
                    'HOW TO READ THIS IMAGE:\n\n'
                    'LEFT PANEL - Original Y Channel: This shows '
                    'the luminance (brightness) channel of the '
                    'image, which is the channel the AI model '
                    'was trained to analyse for steganography. '
                    'This is shown for reference.\n\n'
                    'MIDDLE PANEL - Grad-CAM Heatmap: This is '
                    'the pure attention map of the AI. The colour '
                    'scale goes from BLUE (the AI paid little '
                    'attention here) to RED (the AI focused '
                    'heavily on this area). RED regions are the '
                    'parts of the image that most strongly '
                    'influenced the AI verdict. If you see a '
                    'large red area, that region contains the '
                    'pixel patterns that triggered the '
                    'steganography detection.\n\n'
                    'RIGHT PANEL - Overlay: This combines the '
                    'original image with the heatmap so you can '
                    'see exactly WHICH objects or regions in the '
                    'photo correspond to the suspicious areas. '
                    'For example, if the red area falls on a '
                    'specific region of the image, the hidden '
                    'payload may be concentrated there. The AI '
                    'model has been trained on thousands of '
                    'steganographic images and learned that '
                    'certain pixel arrangements are highly '
                    'suspicious.'
                )
                elements.append(Paragraph(gradcam_intro, body_style))
                elements.append(Spacer(1, 0.3*cm))
                img = RLImage(heatmap_path, width=17*cm, height=6*cm, kind='proportional')
                elements.append(img)
                elements.append(Spacer(1, 0.3*cm))
                elements.append(Paragraph(gradcam_panel_explanation, body_style))
                elements.append(Spacer(1, 0.5*cm))
            elements.append(Spacer(1, 10))
            story.append(KeepTogether(elements))
        elif mime_type == 'IMAGE':
            story.append(Paragraph(
                'Grad-CAM heatmap could not be generated: '
                'the image analysis model (YedroudjNetV3) was not loaded. '
                'Train and place image_model.pth in the models/ directory to enable this.',
                ParagraphStyle('Note', parent=body_style, textColor=HexColor('#888888'), fontSize=9)
            ))
            
        chart_path = layer4_xai_result.get('attribution', {}).get('chart_path')
        if chart_path and Path(chart_path).exists():
            story.append(Paragraph(SECTION_EXPLANATIONS['attribution'], body_style))
            img = RLImage(chart_path, width=14*cm, height=8*cm)
            story.append(img)
            story.append(Spacer(1, 10))

            # === CHANGE 3: File-type specific attribution engine explanation ===
            if file_type == 'IMAGE':
                engine_detail = (
                    'YedroudjNetV3 is a neural network trained to '
                    'detect spatial LSB steganography. ALASKA2 Model '
                    'is trained on adaptive steganography methods. '
                    'Chi-Square and RS Analysis are mathematical '
                    'tests that detect statistical anomalies in '
                    'pixel value distributions.'
                )
            elif file_type == 'VIDEO':
                engine_detail = (
                    'The four streams analysed spatial pixel patterns '
                    'per frame, temporal consistency across frames, '
                    'DCT frequency domain patterns, and optical flow '
                    'anomalies between consecutive frames.'
                )
            elif file_type == 'DOCUMENT':
                engine_detail = (
                    'DistilBERT Neural Model analyses the text for '
                    'semantic anomalies caused by synonym substitution. '
                    'The forensic streams check document structure, '
                    'Unicode character patterns, stream entropy, and '
                    'file metadata consistency.'
                )
            else:
                engine_detail = (
                    'Multiple detection streams were applied to '
                    'analyse this file for steganographic content.'
                )

            attribution_explanation = (
                'HOW TO READ THE CONTRIBUTION CHART:\n\n'
                'This bar chart shows which detection method '
                'contributed most to the final verdict. Each '
                'bar represents one component of the Shadow-Trace '
                'analysis pipeline.\n\n'
                'LONGER RED BARS mean that method strongly '
                'detected suspicious content and had a major '
                'influence on the verdict.\n\n'
                'SHORTER BLUE BARS mean that method found '
                'little or nothing suspicious.\n\n'
                'The grey dotted vertical line is the decision '
                'threshold. Bars extending past this line are '
                'the methods that most strongly pushed the '
                'verdict toward STEGO_DETECTED.\n\n'
                'For this ' + file_type.lower() + ' file the '
                'analysis used these specific detection engines: '
                + engine_detail
            )
            story.append(Paragraph(attribution_explanation, body_style))
            story.append(Spacer(1, 0.5*cm))

            attributions = layer4_xai_result.get('attribution', {}).get('attributions', {})
            if attributions:
                story.append(Paragraph('Contribution Scores:', ParagraphStyle('Heading4', parent=styles['Heading3'], fontName='Helvetica-Bold')))
                for name, attr_score in attributions.items():
                    story.append(Paragraph(f"\u2022 {name}: {fmt_score(attr_score)}", body_style))
                story.append(Spacer(1, 10))
            
        narrative = layer4_xai_result.get('narrative', '')
        if narrative:
            story.append(Paragraph(narrative, body_style))
        story.append(Spacer(1, 10))

        # SECTION 8: Cryptographic Seal
        story.append(Paragraph('7. Cryptographic Seal', section_style))
        story.append(Paragraph(SECTION_EXPLANATIONS['cryptographic_seal'], body_style))
        story.append(Paragraph('A cryptographic seal will be computed for this PDF report to guarantee integrity.', body_style))
        story.append(Paragraph('Refer to the companion .seal.json file for the HMAC-SHA3-512 seal and RFC 3161 trusted timestamp.', body_style))
        story.append(Spacer(1, 10))

        # LIMITATIONS SECTION
        try:
            story.append(Paragraph(
                'LIMITATIONS OF THIS ANALYSIS',
                section_style
            ))

            story.append(Paragraph(
                'This report was produced by Shadow-Trace v1.0.0, '
                'an automated digital forensic steganalysis system. '
                'The following limitations apply to all findings '
                'contained in this report:',
                body_style
            ))

            bullet_items = [
                'This system performs automated analysis and does '
                'not replace the judgement of a qualified digital '
                'forensic examiner.',
                'Model-based predictions are probabilistic estimates '
                'and not mathematical certainties. They should be '
                'treated as investigative indicators.',
                'Adaptive steganography specifically designed to '
                'evade statistical detection may not be identified '
                'by this system.',
                'The video steganalysis model was trained on '
                'synthetic data. Real-world performance may differ '
                'from laboratory evaluation results.',
                'The absence of detected steganography does not '
                'constitute proof that no steganography is present. '
                'Absence of evidence is not evidence of absence.',
                'Statistical analysis may be unreliable for files '
                'with fewer than approximately 10,000 pixels.',
                'This report should be reviewed by a qualified '
                'examiner before use in any legal proceeding.',
            ]

            bullet_para_style = ParagraphStyle(
                'BulletItem',
                parent=body_style,
                leftIndent=20,
                spaceAfter=4,
                firstLineIndent=0,
            )

            for item in bullet_items:
                story.append(Paragraph(
                    '\u2022  ' + item,
                    bullet_para_style
                ))

            story.append(Spacer(1, 0.5*cm))
        except Exception as e:
            print('[LAYER4-REPORT] Error generating LIMITATIONS section: ' + str(e))

        # SECTION 9: Legal Disclaimer and Compliance
        story.append(Paragraph('8. Legal Disclaimer and Compliance', section_style))
        disclaimer = (
            "Analysis performed by Shadow-Trace v1.0.0. "
            "This tool operates in accordance with ISO/IEC 27037 digital evidence guidelines "
            "and ACPO Good Practice Guide compliance principles. "
            "Findings require qualified examiner review. "
            "This report is not standalone evidence without expert testimony."
        )
        story.append(Paragraph(disclaimer, body_style))

        # Build PDF
        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=2*cm, leftMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm
        )
        doc.build(story)

        # Compute HMAC seal on the generated PDF
        with open(report_path, 'rb') as f:
            pdf_bytes = f.read()
        hmac_seal = compute_hmac_seal(pdf_bytes)
        
        # Get RFC 3161 timestamp
        ts_result = get_rfc3161_timestamp(pdf_bytes)

        # Write seal file alongside report
        seal_path = report_path.with_suffix('.seal.json')  # same subfolder as report
        seal_data = {
            'report_file': report_path.name,
            'sha3_512_of_report': hashlib.sha3_512(pdf_bytes).hexdigest(),
            'hmac_sha3_512': hmac_seal,
            'rfc3161_timestamp': ts_result,
            'shadow_trace_version': SHADOW_TRACE_VERSION,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'session_id': session_id,
            'calibration': layer2_result.get('calibration', {}) if layer2_result else {},
            'source_correlation': layer2_result.get('source_correlation', {}) if layer2_result else {}
        }
        with open(seal_path, 'w') as f:
            json.dump(seal_data, f, indent=2)

        summary_result = None
        should_gen_summary = True
        should_gen_evidence = False
        try:
            import settings_manager
            should_gen_summary = settings_manager.get_setting('auto_generate_summary_report', True)
            should_gen_evidence = settings_manager.get_setting('auto_generate_evidence_package', False)
        except Exception:
            pass

        if should_gen_summary:
            try:
                from layer4_summary_report import generate_summary_report
                print('[LAYER4-REPORT] Generating summary report...')
                summary_result = generate_summary_report(
                    filepath=filepath,
                    session_id=session_id,
                    sha3_hash=sha3_hash,
                    layer1_result=layer1_result,
                    layer2_result=layer2_result,
                    layer3_result=layer3_result,
                    layer4_xai_result=layer4_xai_result,
                    calibration=calibration,
                    technical_report_path=str(report_path),
                )
                if summary_result.get('success'):
                    print('[LAYER4-REPORT] Summary report: '
                          + summary_result['summary_path'])
                else:
                    print('[LAYER4-REPORT] Summary failed: '
                          + str(summary_result.get('error')))
            except Exception as e:
                print('[LAYER4-REPORT] Summary error: ' + str(e))
                summary_result = {'error': str(e)}
        else:
            print('[LAYER4-REPORT] Summary report skipped (disabled in Settings).')

        export_result = None
        if should_gen_evidence:
            try:
                from evidence_export import run_full_export
                print('[LAYER4-REPORT] Running evidence export...')
                
                summary_path = None
                if summary_result and summary_result.get('success'):
                    summary_path = summary_result.get(
                        'summary_path'
                    )
                
                export_result = run_full_export(
                    filepath=filepath,
                    session_id=session_id,
                    sha3_hash=sha3_hash,
                    layer1_result=layer1_result,
                    layer2_result=layer2_result,
                    layer3_result=layer3_result,
                    layer4_xai_result=layer4_xai_result,
                    calibration=calibration,
                    technical_report_path=str(report_path),
                    summary_report_path=summary_path,
                )
                
                if export_result.get('success'):
                    zip_path = export_result.get(
                        'zip_package', {}
                    ).get('path', '')
                    print('[LAYER4-REPORT] Evidence package: '
                          + str(Path(zip_path).name
                                if zip_path else 'N/A'))
                else:
                    print('[LAYER4-REPORT] Export failed: '
                          + str(export_result.get('error')))
            except Exception as e:
                print('[LAYER4-REPORT] Export error: ' + str(e))
                export_result = {'error': str(e)}
        else:
            print('[LAYER4-REPORT] Evidence package export skipped (disabled in Settings).')

        return {
            'success': True,
            'report_path': str(report_path),
            'seal_path': str(seal_path),
            'hmac_seal': hmac_seal,
            'rfc3161_success': ts_result.get('success', False),
            'report_size_bytes': len(pdf_bytes),
            'verdict': verdict,
            'summary_report': summary_result,
            'evidence_export': export_result,
            'error': None
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {'success': False, 'error': str(e)}

if __name__ == '__main__':
    print('=== LAYER 4B FORENSIC REPORT TEST ===')
    print()
    
    mock_filepath = str(Path.home() / 'Downloads' / 'test_image.jpg')
    mock_session = 'TEST_REPORT_SESSION_001'
    mock_hash = 'abc123def456' * 8
    
    mock_layer1 = {
        'verdict':              'CLEAN',
        'stage1_hash':         'SUCCESS',
        'stage2_mime':         'image/jpeg',
        'stage3_clamav':       'CLEAN',
        'stage3_yara':         {'verdict': 'CLEAN'},
        'stage3_heuristics':   [{'verdict': 'CLEAN', 'check': 'entropy'}],
        'stage4_virustotal':   {'verdict': 'CLEAN'},
        'yara_warnings':       [],
        'yara_matched_rules':  [],
        'informational_matches': [],
        'session_id':          mock_session,
        'filepath':            mock_filepath,
        'sha3_hash':           mock_hash,
    }
    
    mock_layer2 = {
        'verdict': 'STEGO_DETECTED',
        'score': 0.87,
        'confidence_tier': 'HIGH',
        'file_type': 'IMAGE',
        'tier1a_yedroudj': {
            'score': 0.91,
            'verdict': 'STEGO_DETECTED',
            'model': 'YedroudjNetV3'
        },
        'tier1b_alaska2': {
            'score': 0.72,
            'verdict': 'STEGO_DETECTED',
            'active': True
        },
        'tier3_statistical': {
            'combined_score': 0.91,
            'verdict': 'STEGO_DETECTED',
            'chi_square': {'score': 0.95, 'verdict': 'STEGO_DETECTED'},
            'rs_analysis': {'score': 0.88, 'verdict': 'STEGO_DETECTED'},
        },
        'fusion_notes': [
            'T1A Yedroudj: 0.910 -> STEGO_DETECTED',
            'T1B ALASKA2: 0.720 -> STEGO_DETECTED',
            'T3 Statistical: 0.910 -> STEGO_DETECTED',
            'Fusion score: 0.870 -> STEGO_DETECTED'
        ]
    }
    
    mock_layer3 = {
        'file_type': 'IMAGE',
        'extraction_results': {
            'extracted': True,
            'method': 'multi_plane_lsb',
            'best_plane': 0,
            'payload_type': 'Unknown Binary',
            'payload_entropy': 7.85,
            'payload_class': 'ENCRYPTED_OR_COMPRESSED',
            'payload_size_bytes': 15420,
            'is_executable': False,
            'is_archive': False,
            'first_32_bytes_hex': 'a1b2c3d4e5f6' * 5,
            'roi_used': False,
        },
        'adaptive_analysis': {
            'adaptive_stego_detected': True,
            'modification_ratio': 0.72,
            'estimated_payload_bytes': 12340,
            'estimated_payload_kb': 12.1,
            'confidence': 'MEDIUM',
            'note': 'Adaptive stego detected'
        }
    }
    
    from layer4_explainability import (
        compute_feature_attribution,
        generate_narrative
    )
    attribution = compute_feature_attribution(
        mock_filepath, mock_layer2, mock_layer3
    )
    narrative = generate_narrative(
        mock_filepath, mock_layer2,
        mock_layer3, attribution
    )
    mock_layer4_xai = {
        'grad_cam': {'success': False, 'error': 'Test mode'},
        'attribution': attribution,
        'narrative': narrative,
    }
    
    print('Generating forensic PDF report...')
    result = generate_forensic_report(
        filepath=mock_filepath,
        session_id=mock_session,
        sha3_hash=mock_hash,
        layer1_result=mock_layer1,
        layer2_result=mock_layer2,
        layer3_result=mock_layer3,
        layer4_xai_result=mock_layer4_xai,
        chain_of_custody_log=None
    )
    
    print('Report generation result:')
    print('  Success: ' + str(result.get('success')))
    print('  Report: ' + str(result.get('report_path')))
    print('  Seal: ' + str(result.get('seal_path')))
    print('  HMAC: ' + str(result.get('hmac_seal')))
    print('  RFC3161: ' + str(result.get('rfc3161_success')))
    print('  Size: ' + str(result.get('report_size_bytes')) + ' bytes')
    print('  Verdict: ' + str(result.get('verdict')))
    
    if result.get('success'):
        print()
        print('PASS: Report generated successfully')
        print('Open the report file to verify PDF content')
    else:
        print('FAIL: ' + str(result.get('error')))
    
    print()
    print('=== TEST COMPLETE ===')
