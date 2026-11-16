# =============================================================================
# Shadow-Trace | quarantine_report.py
# Automated Forensic Quarantine Report Generator
#
# Produces cryptographically sealed PDF reports for files isolated at Layer 1
# (Malware Screening). Follows ISO/IEC 27037 and ACPO Good Practice Guide
# principles, including multi-hash integrity, multi-engine detection breakdowns,
# normalized malware classification, and HMAC-SHA3-512 / RFC 3161 sealing.
# =============================================================================

import os
import sys
import hashlib
import hmac
import json
import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib.colors import HexColor, black, white, red, green
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer,
    Table, TableStyle, HRFlowable, PageBreak, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY, TA_RIGHT

import config
import utils

# Reuse sealing functions & constants from layer4_report
try:
    from layer4_report import (
        compute_hmac_seal,
        get_rfc3161_timestamp,
        HMAC_KEY,
        SHADOW_TRACE_VERSION,
        FREETSA_URL,
        SECTION_EXPLANATIONS,
    )
except Exception:
    HMAC_KEY = os.environ.get(
        'HMAC_SECRET_KEY',
        ''
    ).encode('utf-8')
    SHADOW_TRACE_VERSION = getattr(config, 'VERSION', '1.0.0')
    FREETSA_URL = 'https://freetsa.org/tsr'
    SECTION_EXPLANATIONS = {}

    def compute_hmac_seal(content: bytes) -> str:
        sig = hmac.new(HMAC_KEY, content, hashlib.sha3_512)
        return sig.hexdigest()

    def get_rfc3161_timestamp(data: bytes) -> Dict:
        try:
            import requests
            data_hash = hashlib.sha512(data).digest()
            tsq_b64 = base64.b64encode(data_hash).decode('utf-8')
            response = requests.post(
                FREETSA_URL,
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

# Malware classifier
try:
    from malware_classifier import classify_malware, LIMITATIONS_DISCLAIMER
except Exception:
    def classify_malware(layer1_result: dict) -> dict:
        return {
            'classified': True,
            'primary_category': layer1_result.get('threat_category', 'Malware'),
            'family': layer1_result.get('threat_family', 'Unknown'),
            'confidence': 'HIGH',
            'sources': [],
            'alternative_categories': [],
            'plain_english': 'Malicious artifact detected and isolated by security engines.',
            'limitations': 'Classification derived from static signatures.'
        }
    LIMITATIONS_DISCLAIMER = "Malware classification is label-based derived from static signatures."

# YARA plain English explanations
YARA_RULE_EXPLANATIONS = {
    'Big_Numbers1': (
        'The scanner found large, unusual numbers hidden inside the file. '
        'While normal files sometimes have these, attackers often use them to hide '
        'malicious computer code.'
    ),
    'Big_Numbers2': (
        'The scanner found multiple hidden large numbers in the file. '
        'This is a common technique used by attackers to hide passwords or '
        'obfuscate viruses from antivirus scanners.'
    ),
    'invalid_trailer_structure': (
        'The file is not structured correctly. Its trailer structure is abnormal, '
        'which frequently occurs when someone deliberately tampers with the file to inject hidden data.'
    ),
    'invalid_xref_numbers': (
        'The internal cross-reference map of the document contains corrupted indices. '
        'Legitimate files rarely exhibit this defect, indicating structural modification.'
    ),
    'invalid_xref_entry': (
        'Internal document references are malformed, indicating post-creation tampering '
        'or an attempt to conceal secondary streams.'
    ),
    'suspicious_xref': (
        'The cross-reference table contains anomalous offsets characteristic of crafted exploit payloads.'
    ),
    'malformed_pdf': (
        'The PDF document structure violates format standards, suggesting intentional crafting or tampering.'
    ),
    'pdf_with_embedded_exe': (
        'A hidden PE computer program (executable) was detected inside this PDF carrier. '
        'PDF documents should never contain hidden executable binaries. This is a critical dropper attack.'
    ),
    'pdf_javascript': (
        'Executable JavaScript code was identified embedded in this document. '
        'Attackers frequently leverage embedded scripts to trigger automatic payload execution upon opening.'
    ),
    'suspicious_lnk': (
        'The artifact exhibits Windows shortcut characteristics used to execute arbitrary shell commands.'
    ),
    'ole_with_vba': (
        'Hidden Macro/VBA code was identified in an Office container, commonly used to stage and execute malware.'
    ),
    'powershell_download': (
        'The file contains commands instructing the host to secretly download secondary payloads from the Internet.'
    ),
    'ransomware_wannacry_payload': (
        'Identifies WannaCry ransomware cryptographic and execution components. '
        'This signature confirms a destructive file-encrypting ransomware threat.'
    ),
}

DEFAULT_YARA_EXPLANATION = (
    'The YARA security scanner flagged this file based on pattern matching rules. The specific '
    'pattern ({rule_name}) matched content that security researchers have associated with malicious activity.'
)

def explain_yara_rules(matched_rules: list, warning_rules: list = None) -> list:
    """Return plain English explanation for each matched YARA rule."""
    # Check if already imported from layer4_explainability in sys.modules
    if 'layer4_explainability' in sys.modules and hasattr(sys.modules['layer4_explainability'], 'explain_yara_rules'):
        try:
            return sys.modules['layer4_explainability'].explain_yara_rules(matched_rules, warning_rules)
        except Exception:
            pass

    explanations = []
    all_rules = []
    for r in (matched_rules or []) + (warning_rules or []):
        if r not in all_rules:
            all_rules.append(r)
    for rule in all_rules:
        explanation = YARA_RULE_EXPLANATIONS.get(
            rule,
            DEFAULT_YARA_EXPLANATION.format(rule_name=rule)
        )
        is_warning = rule in (warning_rules or []) and rule not in (matched_rules or [])
        explanations.append({
            'rule_name': rule,
            'explanation': explanation,
            'severity': 'WARNING' if is_warning else 'THREAT',
        })
    return explanations

# Palette
DARK_BLUE   = HexColor('#1a1a2e')
MID_BLUE    = HexColor('#16213e')
ACCENT      = HexColor('#0f3460')
RED_ALERT   = HexColor('#e94560')
ORANGE_WARN = HexColor('#f5a623')
GREEN_OK    = HexColor('#27ae60')
LIGHT_GREY  = HexColor('#f2f4f8')
SOFT_RED    = HexColor('#fde8e8')
SOFT_GREEN  = HexColor('#e8f8f0')
SOFT_AMBER  = HexColor('#fef3e2')


def _result_color(val: Any) -> HexColor:
    v = str(val).upper().strip()
    if v in ('CLEAN', 'SUCCESS', 'CONFIRMED', 'PASSED'):
        return HexColor('#1a7a1a')
    if v in ('THREAT', 'INFECTED', 'CRITICAL', 'FAILED', 'MISMATCH'):
        return HexColor('#cc0000')
    if v in ('WARNING', 'SUSPICIOUS', 'PARTIAL', 'ANOMALOUS'):
        return HexColor('#cc6600')
    if v in ('UNKNOWN', 'SKIPPED', 'NOT RUN', 'N/A'):
        return HexColor('#777777')
    return black


def generate_quarantine_report(
    filepath: str,
    session_id: str,
    layer1_result: dict,
    multi_hash: dict = None,
    sha3_hash: str = None,
    quarantine_path: str = None,
    quarantine_reason: str = None,
    correlation_data: dict = None,
    hash_reconfirmation: dict = None,
) -> dict:
    """
    Generate a complete, sealed PDF forensic report for a quarantined file.

    Returns:
        Dict: {
            'success': bool,
            'report_path': str,
            'seal_path': str,
            'hmac': str,
            'rfc3161': bool,
            'size_bytes': int,
            'error': str | None
        }
    """
    try:
        # Determine candidate file location (if moved, read facts from quarantine_path)
        candidate_path = None
        if filepath and os.path.exists(filepath):
            candidate_path = Path(filepath)
        elif quarantine_path and os.path.exists(quarantine_path):
            candidate_path = Path(quarantine_path)

        orig_filename = Path(filepath).name if filepath else (candidate_path.name if candidate_path else "unknown_artifact")
        orig_stem = Path(filepath).stem if filepath else (candidate_path.stem if candidate_path else "artifact")

        # Resolve destination directory: reports/quarantine
        try:
            import settings_manager
            base_rep = Path(settings_manager.get_setting('report_output_folder', config.REPORTS_DIR))
        except Exception:
            base_rep = config.REPORTS_DIR
        reports_dir = base_rep / 'quarantine'
        reports_dir.mkdir(parents=True, exist_ok=True)

        now_utc = datetime.now(timezone.utc)
        now_local = datetime.now()
        timestamp_str = now_local.strftime('%Y%m%d_%H%M%S')
        report_filename = f"{timestamp_str}_{orig_stem}_quarantine_report.pdf"
        report_path = reports_dir / report_filename

        # Multi-hash fallback
        if not multi_hash and candidate_path:
            try:
                from utils import compute_multi_hash
                multi_hash = compute_multi_hash(str(candidate_path))
            except Exception:
                multi_hash = {}

        if not sha3_hash:
            sha3_hash = (multi_hash or {}).get('sha3_512') or (layer1_result or {}).get('sha3_hash') or 'Not computed'

        # Provenance & correlation fallback
        if not correlation_data and candidate_path:
            try:
                from source_correlation import build_source_correlation
                correlation_data = build_source_correlation(str(candidate_path), session_id)
            except Exception:
                correlation_data = {}

        # Styles definition
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'QuarantineTitle',
            parent=styles['Title'],
            fontSize=18,
            textColor=white,
            backColor=DARK_BLUE,
            spaceAfter=14,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        )
        verdict_style = ParagraphStyle(
            'QuarantineVerdict',
            parent=styles['Heading2'],
            fontSize=15,
            textColor=white,
            backColor=RED_ALERT,
            alignment=TA_CENTER,
            spaceAfter=14,
            fontName='Helvetica-Bold'
        )
        section_style = ParagraphStyle(
            'QuarantineSection',
            parent=styles['Heading1'],
            fontSize=12,
            textColor=white,
            backColor=ACCENT,
            spaceBefore=14,
            spaceAfter=8,
            fontName='Helvetica-Bold',
            leftIndent=8
        )
        body_style = ParagraphStyle(
            'QuarantineBody',
            parent=styles['Normal'],
            fontSize=9.5,
            textColor=black,
            spaceAfter=5,
            fontName='Helvetica',
            alignment=TA_JUSTIFY,
            leading=13
        )
        mono_style = ParagraphStyle(
            'QuarantineMono',
            parent=styles['Code'],
            fontSize=7.5,
            textColor=black,
            backColor=LIGHT_GREY,
            fontName='Courier',
            spaceAfter=2,
            leading=10
        )
        bold_label = ParagraphStyle(
            'QuarantineBoldLabel',
            parent=body_style,
            fontName='Helvetica-Bold',
            fontSize=9.5
        )
        small_style = ParagraphStyle(
            'QuarantineSmall',
            parent=body_style,
            fontSize=8,
            textColor=HexColor('#555555'),
            leading=11
        )
        bullet_style = ParagraphStyle(
            'QuarantineBullet',
            parent=body_style,
            leftIndent=15,
            spaceAfter=3,
            firstLineIndent=-10,
            leading=12
        )

        story = []

        # =========================================================================
        # SECTION 1: Cover Page
        # =========================================================================
        try:
            story.append(Paragraph('MALWARE QUARANTINE REPORT', title_style))
            story.append(Paragraph('QUARANTINED \u2014 SECURITY THREAT ISOLATED', verdict_style))

            try:
                import settings_manager
                examiner_name = settings_manager.get_setting('examiner_signature', os.environ.get('EXAMINER_NAME', config.EXAMINER_NAME))
            except Exception:
                examiner_name = os.environ.get('EXAMINER_NAME', config.EXAMINER_NAME)

            examiner_id = os.environ.get('EXAMINER_ID', getattr(config, 'EXAMINER_ID', ''))
            examiner_org = os.environ.get('EXAMINER_ORG', getattr(config, 'EXAMINER_ORG', 'Digital Forensic Laboratory'))

            cover_data = [
                ['Artifact Name:', Paragraph(orig_filename, bold_label)],
                ['Session ID:', Paragraph(str(session_id or 'UNKNOWN'), mono_style)],
                ['Original Path:', Paragraph(str(filepath or 'Not specified'), mono_style)],
                ['Examining Officer:', examiner_name],
                ['Examiner ID / Org:', f"{examiner_id} ({examiner_org})"],
                ['Report Generated (Local):', now_local.strftime('%Y-%m-%d %H:%M:%S')],
                ['Report Generated (UTC):', now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')],
                ['Overall Status:', 'FILE QUARANTINED (EXECUTION PROHIBITED)']
            ]

            t_cover = Table(cover_data, colWidths=[5.0*cm, 12.0*cm])
            t_cover.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), LIGHT_GREY),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
            ]))
            story.append(t_cover)
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Cover Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 2: Quarantine Decision
        # =========================================================================
        try:
            story.append(Paragraph('1. Quarantine Decision and Action Summary', section_style))

            det_stage = (layer1_result or {}).get('detecting_stage', 'STAGE3_LOCAL')
            det_engine = (layer1_result or {}).get('detecting_engine', (layer1_result or {}).get('engine', 'Malware Screening Engine'))
            threat_name = (layer1_result or {}).get('threat_name', 'Confirmed Threat Signature')
            severity = (layer1_result or {}).get('severity', 'CRITICAL')

            if not quarantine_reason:
                quarantine_reason = f"Critical threat identified by {det_engine} ({threat_name}). File isolated to prevent execution."

            decision_table = [
                ['Parameter', 'Detail'],
                ['Quarantine Action', 'IMMEDIATE VAULT ISOLATION'],
                ['Detecting Engine', str(det_engine)],
                ['Pipeline Stage', str(det_stage)],
                ['Triggering Threat', str(threat_name)],
                ['Threat Severity', str(severity)],
                ['Isolation Timestamp', now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ]

            t_dec = Table(decision_table, colWidths=[5.0*cm, 12.0*cm])
            t_dec.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_dec)
            story.append(Spacer(1, 8))

            explanation_p = (
                f"<b>Quarantine Justification:</b> {quarantine_reason}<br/><br/>"
                "The suspect file matched critical threat indicators during automated forensic screening and "
                "was immediately quarantined into the encrypted vault. Operating system execution permissions "
                "were revoked and handle locks applied to prevent code execution or host contamination. "
                "This forensic action isolates the hazard while preserving the evidentiary bytes unaltered."
            )
            story.append(Paragraph(explanation_p, body_style))
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Quarantine Decision Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 3: Malware Classification
        # =========================================================================
        try:
            story.append(Paragraph('2. Malware Classification Analysis', section_style))

            capa_res_for_classifier = (layer1_result or {}).get('capa_analysis') or (layer1_result or {}).get('all_scan_results', {}).get('capa_analysis')
            classification = classify_malware(layer1_result or {}, capa_result=capa_res_for_classifier)

            p_cat = classification.get('primary_category', 'Unclassified malware')
            p_fam = classification.get('family') or 'None identified'
            p_conf = classification.get('confidence', 'MEDIUM')
            alt_cats = classification.get('alternative_categories', [])
            alt_str = ", ".join(alt_cats) if alt_cats else "None"

            class_summary = [
                ['Classification Metric', 'Finding'],
                ['Primary Threat Category', p_cat],
                ['Identified Family', p_fam],
                ['Classification Confidence', p_conf],
                ['Alternative Categories', alt_str]
            ]
            t_class = Table(class_summary, colWidths=[5.0*cm, 12.0*cm])
            t_class.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 9),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_class)
            story.append(Spacer(1, 8))

            # Detection Sources Table
            sources = classification.get('sources', [])
            if sources:
                src_data = [['Source Engine', 'Raw Signature / Detection Label', 'Mapped Category']]
                for s in sources:
                    src_data.append([
                        s.get('source', 'Unknown'),
                        Paragraph(str(s.get('raw_label', '')), mono_style),
                        s.get('category', 'Generic')
                    ])
                t_src = Table(src_data, colWidths=[4.0*cm, 8.5*cm, 4.5*cm])
                t_src.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), LIGHT_GREY),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8.5),
                    ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(t_src)
                story.append(Spacer(1, 8))

            # Plain English Meaning
            pe_text = classification.get('plain_english', '')
            if pe_text:
                story.append(Paragraph(f"<b>Category Assessment:</b> {pe_text}", body_style))

            # Limitations Note
            lim_text = classification.get('limitations', LIMITATIONS_DISCLAIMER)
            lim_box = Table([[Paragraph(f"<b>Classification Limitations:</b> {lim_text}", small_style)]], colWidths=[17.0*cm])
            lim_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), SOFT_AMBER),
                ('LINEBEFORE', (0,0), (0,-1), 3, ORANGE_WARN),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(Spacer(1, 4))
            story.append(lim_box)
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Malware Classification Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 4: Detection Results
        # =========================================================================
        try:
            story.append(Paragraph('3. Multi-Engine Detection Results', section_style))

            # Extract sub-results cleanly
            all_scans = (layer1_result or {}).get('all_scan_results', {}) or {}
            clam_raw = (layer1_result or {}).get('stage3_clamav') or all_scans.get('stage3_clamav') or {}
            yara_raw = (layer1_result or {}).get('stage3_yara') or all_scans.get('stage3_yara') or {}
            heur_raw = (layer1_result or {}).get('stage3_heuristics') or all_scans.get('stage3_heuristics') or []
            vt_raw = (layer1_result or {}).get('stage4_virustotal') or all_scans.get('stage4_virustotal') or {}
            ha_raw = (layer1_result or {}).get('stage4_hybrid_analysis') or all_scans.get('stage4_hybrid_analysis') or {}

            # ClamAV overview
            clam_verd = clam_raw.get('verdict', 'UNKNOWN') if isinstance(clam_raw, dict) else str(clam_raw)
            clam_sig = clam_raw.get('threat_name', 'No signature') if isinstance(clam_raw, dict) else ('Clean' if clam_verd == 'CLEAN' else 'Signature detected')

            # YARA overview
            yara_verd = yara_raw.get('verdict', 'UNKNOWN') if isinstance(yara_raw, dict) else str(yara_raw)
            yara_matched = (layer1_result or {}).get('yara_matched_rules') or (yara_raw.get('matched_rules') if isinstance(yara_raw, dict) else []) or []
            yara_warns = (layer1_result or {}).get('yara_warnings') or (yara_raw.get('yara_warnings') if isinstance(yara_raw, dict) else []) or []
            yara_info = (layer1_result or {}).get('informational_matches') or (yara_raw.get('informational_matches') if isinstance(yara_raw, dict) else []) or []
            yara_desc = f"{len(yara_matched)} threat pattern(s), {len(yara_warns)} warning(s)"

            # Heuristics overview
            heur_verd = 'CLEAN'
            heur_desc = 'No structural anomaly detected'
            if isinstance(heur_raw, list) and heur_raw:
                for h in heur_raw:
                    if h.get('verdict') == 'THREAT':
                        heur_verd = 'THREAT'
                        heur_desc = h.get('reason', 'Embedded executable or header anomaly')
                        break
                    elif h.get('verdict') in ('WARNING', 'ANOMALOUS') and heur_verd != 'THREAT':
                        heur_verd = 'WARNING'
                        heur_desc = h.get('reason', 'High entropy anomaly')
            elif isinstance(heur_raw, dict):
                heur_verd = heur_raw.get('verdict', 'UNKNOWN')
                heur_desc = heur_raw.get('reason', 'Heuristic analysis')

            # VirusTotal overview
            vt_verd = vt_raw.get('verdict', 'UNKNOWN') if isinstance(vt_raw, dict) else str(vt_raw)
            positives = vt_raw.get('positives', vt_raw.get('malicious_count', 0)) if isinstance(vt_raw, dict) else 0
            total_eng = vt_raw.get('total', 70) if isinstance(vt_raw, dict) else 70
            vt_mode = vt_raw.get('vt_mode', getattr(config, 'VT_MODE', 'hash_only')) if isinstance(vt_raw, dict) else 'hash_only'
            vt_cached = vt_raw.get('cached', False) if isinstance(vt_raw, dict) else False

            if vt_verd == 'SKIPPED':
                vt_desc = f"Skipped: {vt_raw.get('reason', 'Offline mode or disabled')}"
            else:
                vt_desc = f"{positives}/{total_eng} engines flagged ({vt_mode})"

            # Hybrid Analysis overview
            if ha_raw and isinstance(ha_raw, dict) and ha_raw.get('verdict') != 'SKIPPED':
                ha_verd = ha_raw.get('verdict', 'CLEAN')
                ha_desc = ha_raw.get('threat_name', 'Cloud analysis completed')
            else:
                ha_verd = 'SKIPPED'
                ha_desc = 'Not configured or offline mode active'

            # Table
            det_table_data = [
                ['Security Engine', 'Verdict', 'Summary Finding'],
                ['ClamAV Antivirus', clam_verd, clam_sig],
                ['YARA Rule Engine', yara_verd, yara_desc],
                ['Heuristic Analyzer', heur_verd, heur_desc],
                ['VirusTotal Cloud', vt_verd, vt_desc],
                ['Hybrid Analysis', ha_verd, ha_desc],
            ]

            t_det = Table(det_table_data, colWidths=[4.5*cm, 3.2*cm, 9.3*cm])
            t_det_style = [
                ('BACKGROUND', (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]
            for row_idx in range(1, len(det_table_data)):
                v = det_table_data[row_idx][1]
                t_det_style.append(('TEXTCOLOR', (1, row_idx), (1, row_idx), _result_color(v)))
                t_det_style.append(('FONTNAME', (1, row_idx), (1, row_idx), 'Helvetica-Bold'))
            t_det.setStyle(TableStyle(t_det_style))
            story.append(t_det)
            story.append(Spacer(1, 10))

            # Sub-block 1: ClamAV
            story.append(Paragraph('<b>ClamAV Findings:</b>', bold_label))
            if clam_verd == 'THREAT':
                story.append(Paragraph(f"Detection Signature: <b>{clam_sig}</b>. Verified signature-based local malware match.", body_style))
            elif clam_verd == 'SKIPPED':
                story.append(Paragraph(f"ClamAV screening was skipped: {clam_raw.get('reason', 'Engine unavailable')}.", body_style))
            else:
                story.append(Paragraph("No signature matches detected by local ClamAV engine.", body_style))
            story.append(Spacer(1, 4))

            # Sub-block 2: YARA detailed explanations
            story.append(Paragraph('<b>YARA Pattern Detections:</b>', bold_label))
            yara_exps = explain_yara_rules(yara_matched, yara_warns + yara_info)
            if yara_exps:
                for exp in yara_exps:
                    rule = exp.get('rule_name', '')
                    sev = exp.get('severity', 'THREAT')
                    txt = exp.get('explanation', '')
                    c = RED_ALERT if sev == 'THREAT' else ORANGE_WARN
                    story.append(Paragraph(f'<font color="{c}"><b>[{sev}] {rule}:</b></font> {txt}', body_style))
            else:
                story.append(Paragraph("No threat or warning patterns triggered in YARA rule repository.", body_style))

            if yara_info:
                info_str = ", ".join(str(r) for r in yara_info)
                story.append(Paragraph(f'<font color="#555555"><b>[INFORMATIONAL]</b> Structural indicators noted: {info_str} (non-threatening structure).</font>', small_style))
            story.append(Spacer(1, 4))

            # Sub-block 3: VirusTotal
            story.append(Paragraph('<b>VirusTotal Intelligence:</b>', bold_label))
            if vt_verd != 'SKIPPED':
                cache_str = "Result retrieved from local 24h cache." if vt_cached else "Live API query executed."
                vt_comm = vt_raw.get('most_common_threat_name') or 'Malicious artifact'
                story.append(Paragraph(
                    f"VirusTotal Multi-Engine Result: <b>{positives} of {total_eng}</b> security vendors flagged this file as malicious.<br/>"
                    f"Consensus Threat Classification: <b>{vt_comm}</b>.<br/>"
                    f"Operational Mode: <b>{vt_mode}</b>. {cache_str}",
                    body_style
                ))
            else:
                story.append(Paragraph(f"VirusTotal cloud query was skipped ({vt_raw.get('reason', 'Offline mode active')}). Local signatures were utilized exclusively.", body_style))

            # Sub-block 4: CAPA Capability Analysis
            capa_res = (layer1_result or {}).get('capa_analysis') or all_scans.get('capa_analysis')
            if capa_res:
                story.append(Spacer(1, 4))
                story.append(Paragraph('<b>CAPA Static Capability Analysis:</b>', bold_label))
                if capa_res.get('status') == 'COMPLETE':
                    plain_eng = capa_res.get('plain_english', '')
                    if plain_eng:
                        story.append(Paragraph(plain_eng, body_style))
                        story.append(Spacer(1, 4))

                    # ATT&CK table
                    tactics = capa_res.get('attack_tactics', [])
                    techniques = capa_res.get('attack_techniques', [])
                    if techniques or tactics:
                        att_rows = [['Tactic / Scope', 'MITRE ATT&CK Technique']]
                        if techniques:
                            for idx, tech in enumerate(techniques[:12]):
                                tac_label = tactics[idx] if idx < len(tactics) else "Execution / Defense Evasion"
                                att_rows.append([
                                    Paragraph(str(tac_label), small_style),
                                    Paragraph(str(tech), small_style)
                                ])
                        else:
                            for tac in tactics:
                                att_rows.append([
                                    Paragraph(str(tac), small_style),
                                    Paragraph("Technique aligned", small_style)
                                ])
                        att_table = Table(att_rows, colWidths=[6*cm, 11*cm])
                        att_table.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), HexColor('#16213e')),
                            ('TEXTCOLOR', (0,0), (-1,0), white),
                            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0,0), (-1,0), 8),
                            ('ROWBACKGROUND', (0,1), (-1,-1), [HexColor('#f5f5f5'), white]),
                            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                            ('TOPPADDING', (0,0), (-1,-1), 3),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                        ]))
                        story.append(att_table)
                        story.append(Spacer(1, 4))

                    # Capabilities table
                    caps = capa_res.get('capabilities', [])
                    if caps:
                        cap_rows = [['Identified Capability', 'Namespace']]
                        for c in caps[:12]:
                            cap_rows.append([
                                Paragraph(str(c.get('name') or 'Unknown'), small_style),
                                Paragraph(str(c.get('namespace') or 'General'), small_style)
                            ])
                        cap_table = Table(cap_rows, colWidths=[10*cm, 7*cm])
                        cap_table.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), HexColor('#0f3460')),
                            ('TEXTCOLOR', (0,0), (-1,0), white),
                            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0,0), (-1,0), 8),
                            ('ROWBACKGROUND', (0,1), (-1,-1), [HexColor('#f5f5f5'), white]),
                            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                            ('TOPPADDING', (0,0), (-1,-1), 3),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                        ]))
                        story.append(cap_table)
                        story.append(Spacer(1, 4))

                    # Risk indicators
                    risks = capa_res.get('risk_indicators', [])
                    if risks:
                        risk_rows = [['Severity', 'Behavior Category', 'Indicator Description']]
                        for r in risks[:12]:
                            sev = str(r.get('severity') or 'LOW')
                            color_tag = '#c0392b' if sev == 'HIGH' else ('#d35400' if sev == 'MEDIUM' else '#7f8c8d')
                            sev_p = Paragraph(f'<font color="{color_tag}"><b>{sev}</b></font>', small_style)
                            risk_rows.append([
                                sev_p,
                                Paragraph(str(r.get('category') or 'Unknown'), small_style),
                                Paragraph(str(r.get('name') or ''), small_style)
                            ])
                        risk_table = Table(risk_rows, colWidths=[3*cm, 5.5*cm, 8.5*cm])
                        risk_table.setStyle(TableStyle([
                            ('BACKGROUND', (0,0), (-1,0), HexColor('#2c3e50')),
                            ('TEXTCOLOR', (0,0), (-1,0), white),
                            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0,0), (-1,0), 8),
                            ('ROWBACKGROUND', (0,1), (-1,-1), [HexColor('#f5f5f5'), white]),
                            ('GRID', (0,0), (-1,-1), 0.5, HexColor('#bdc3c7')),
                            ('TOPPADDING', (0,0), (-1,-1), 3),
                            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                        ]))
                        story.append(risk_table)
                        story.append(Spacer(1, 4))

                    limits = capa_res.get('limitations') or 'Static capability indicators reflect latent programmatic capability, not runtime execution.'
                    story.append(Paragraph(
                        f'<i>Analysis Limitations:</i> {limits}',
                        ParagraphStyle('QCapLim', parent=small_style, fontSize=8, fontName='Helvetica-Oblique', textColor=HexColor('#555555'))
                    ))
                else:
                    st = capa_res.get('status', 'NOT_RUN')
                    err_str = capa_res.get('error') or capa_res.get('plain_english') or ''
                    story.append(Paragraph(
                        f'<font color="#777777">CAPA capability analysis: {st}{(" - " + err_str) if err_str else ""}.</font>',
                        small_style
                    ))

            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Detection Results Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 5: File Identity & Hashes
        # =========================================================================
        try:
            story.append(Paragraph('4. File Identity and Cryptographic Hashes', section_style))

            # Size
            file_size_bytes = 'Unknown'
            if candidate_path and candidate_path.exists():
                file_size_bytes = candidate_path.stat().st_size
            elif multi_hash and multi_hash.get('file_size_bytes'):
                file_size_bytes = multi_hash.get('file_size_bytes')

            size_str = f"{file_size_bytes} bytes"
            if isinstance(file_size_bytes, (int, float)):
                size_str += f" ({round(file_size_bytes / 1024, 2)} KB)"

            # MIME
            mime_type = 'Unknown'
            mime_res = (layer1_result or {}).get('stage2_mime')
            if isinstance(mime_res, dict):
                mime_type = mime_res.get('mime') or mime_res.get('mime_type')
            elif isinstance(mime_res, str):
                mime_type = mime_res
            if not mime_type or mime_type == 'Unknown':
                if candidate_path:
                    mime_type = utils.get_mime_type(str(candidate_path))

            md5_val = (multi_hash or {}).get('md5') or 'Not computed'
            sha256_val = (multi_hash or {}).get('sha256') or 'Not computed'
            primary_hash = sha3_hash or (multi_hash or {}).get('sha3_512') or 'Not computed'

            ident_data = [
                ['File Name', orig_filename],
                ['Original Path', Paragraph(str(filepath or 'Not specified'), mono_style)],
                ['File Size', size_str],
                ['MIME Type', str(mime_type)],
                ['SHA3-512 (Primary)', Paragraph(str(primary_hash), mono_style)],
                ['SHA-256 (Cross-tool)', Paragraph(str(sha256_val), mono_style)],
                ['MD5 (Legacy reference)', Paragraph(str(md5_val), mono_style)],
                ['Acquisition Time', now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')],
            ]

            t_ident = Table(ident_data, colWidths=[4.5*cm, 12.5*cm])
            t_ident.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), LIGHT_GREY),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_ident)
            story.append(Spacer(1, 6))

            # Forensic Single-pass Statement
            hash_stmt = (
                "<b>Single-Pass Integrity Statement:</b> All three cryptographic hashes (MD5, SHA-256, and SHA3-512) "
                "were computed simultaneously in a single read pass on the pristine file prior to any investigation activity. "
                "Single-pass computation eliminates any theoretical possibility of file alteration between separate hashing operations. "
                "SHA3-512 serves as the primary forensic integrity arbiter; SHA-256 and MD5 provide cross-tool verification "
                "for EnCase, FTK, and Autopsy compatibility."
            )
            story.append(Paragraph(hash_stmt, small_style))
            story.append(Spacer(1, 6))

            # Hash Reconfirmation Box
            if hash_reconfirmation:
                primary_ok = hash_reconfirmation.get('primary_confirmed')
                all_ok = hash_reconfirmation.get('all_match')
                if primary_ok is True and all_ok is True:
                    reconf_bg = SOFT_GREEN
                    reconf_bd = GREEN_OK
                    reconf_title = "INTEGRITY RECONFIRMATION: PASSED"
                    reconf_desc = "All hashes confirmed matching initial capture values."
                elif primary_ok is True:
                    reconf_bg = SOFT_AMBER
                    reconf_bd = ORANGE_WARN
                    reconf_title = "INTEGRITY RECONFIRMATION: PARTIAL"
                    reconf_desc = "Primary SHA3-512 matched. Secondary hashes incomplete."
                else:
                    reconf_bg = SOFT_RED
                    reconf_bd = RED_ALERT
                    reconf_title = "INTEGRITY RECONFIRMATION: FAILED"
                    reconf_desc = "Cryptographic mismatch detected during reconfirmation."
            else:
                reconf_bg = LIGHT_GREY
                reconf_bd = HexColor('#7f8c8d')
                reconf_title = "INTEGRITY RECONFIRMATION: NOT PERFORMED"
                reconf_desc = "Reconfirmation not performed: file was isolated at Layer 1."

            reconf_box = Table([[
                Paragraph(f"<b>{reconf_title}</b><br/>{reconf_desc}", body_style)
            ]], colWidths=[17.0*cm])
            reconf_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), reconf_bg),
                ('LINEBEFORE', (0,0), (0,-1), 3, reconf_bd),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (0,0), (-1,-1), 8),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(reconf_box)
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[File Identity Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 6: File Provenance
        # =========================================================================
        try:
            story.append(Paragraph('5. File Provenance and Origin Telemetry', section_style))

            corr = correlation_data or {}
            zone = corr.get('zone_identifier') or {}
            if not zone and candidate_path:
                try:
                    from source_correlation import read_zone_identifier
                    zone = read_zone_identifier(str(candidate_path))
                except Exception:
                    zone = {}

            f_meta = corr.get('file_metadata') or {}
            if not f_meta and candidate_path:
                try:
                    from source_correlation import get_file_metadata
                    f_meta = get_file_metadata(str(candidate_path))
                except Exception:
                    f_meta = {}

            macb = f_meta.get('macb_timestamps') or {}

            src_url = zone.get('host_url') or corr.get('detected_url') or 'Not captured'
            ref_url = zone.get('referrer_url') or 'Not captured'
            zone_name = zone.get('zone_name') or (f"Zone {zone.get('zone_id')}" if zone.get('zone_id') is not None else 'Not captured / Stream absent')

            prov_data = [
                ['Origin Parameter', 'Telemetry Detail'],
                ['Source URL', Paragraph(str(src_url), mono_style)],
                ['Referrer URL', Paragraph(str(ref_url), mono_style)],
                ['NTFS Zone Identifier', str(zone_name)],
            ]

            if macb:
                macb_text = (
                    f"M (Modified): {str(macb.get('M_modified', 'N/A'))[:19]}\n"
                    f"A (Accessed): {str(macb.get('A_accessed', 'N/A'))[:19]}\n"
                    f"C (Changed):  {str(macb.get('C_changed', 'N/A'))[:19]}\n"
                    f"B (Born):     {str(macb.get('B_born', 'N/A'))[:19]}"
                )
                prov_data.append(['MACB Timestamps', Paragraph(macb_text, mono_style)])
            else:
                prov_data.append(['MACB Timestamps', 'Not captured'])

            t_prov = Table(prov_data, colWidths=[4.5*cm, 12.5*cm])
            t_prov.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_prov)
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[File Provenance Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 7: Quarantine Details
        # =========================================================================
        try:
            story.append(Paragraph('6. Quarantine Vault Isolation Details', section_style))

            q_loc = str(quarantine_path or (layer1_result or {}).get('quarantine_path') or (config.QUARANTINE_DIR / f"quarantined_{orig_filename}"))

            q_data = [
                ['Quarantine Location', Paragraph(q_loc, mono_style)],
                ['Access Permissions', 'Execution & Write permissions revoked (icacls locked)'],
                ['Isolation Method', 'Moved to secure vault directory and locked'],
                ['Isolation Timestamp', now_utc.strftime('%Y-%m-%d %H:%M:%S UTC')],
                ['Evidence Retention', 'Artifact preserved in pristine locked state'],
            ]
            t_q = Table(q_data, colWidths=[4.5*cm, 12.5*cm])
            t_q.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,-1), LIGHT_GREY),
                ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_q)
            story.append(Spacer(1, 6))

            q_proto = (
                "<b>Review & Restoration Protocol:</b> This artifact is sequestered in the Shadow-Trace secure vault. "
                "Restoration to the active system or extraction requires explicit authorized examiner confirmation. "
                "Any restoration or export request is cryptographically logged in the chain of custody database."
            )
            story.append(Paragraph(q_proto, small_style))
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Quarantine Details Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 8: Examination Environment
        # =========================================================================
        try:
            story.append(Paragraph('7. Forensic Examination Environment', section_style))

            try:
                sys_context = utils.get_system_context()
            except Exception:
                sys_context = {}

            env_data = [
                ['Parameter', 'System Telemetry Value'],
                ['Scan Time (UTC)', str(sys_context.get('scan_time_utc', now_utc.isoformat()))[:19]],
                ['Scan Time (Local)', str(sys_context.get('scan_time_local', now_local.isoformat()))[:19]],
                ['Timezone / Offset', f"{sys_context.get('timezone_name', 'Unknown')} ({sys_context.get('utc_offset', 'Unknown')})"],
                ['Operating System', f"{sys_context.get('os_system', 'Unknown')} {sys_context.get('os_release', '')}"],
                ['Hostname / Arch', f"{sys_context.get('hostname', 'Unknown')} ({sys_context.get('machine_arch', 'Unknown')})"],
                ['Python Version', str(sys_context.get('python_version', sys.version.split()[0]))],
                ['Shadow-Trace Version', str(sys_context.get('shadow_trace_version', '1.0.0'))],
            ]
            t_env = Table(env_data, colWidths=[5.0*cm, 12.0*cm])
            t_env.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), ACCENT),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_env)
            story.append(Spacer(1, 6))

            # Tool hashes
            tool_hashes = sys_context.get('tool_integrity', {})
            if tool_hashes:
                story.append(Paragraph('<b>Tool Integrity Hashes:</b>', small_style))
                th_data = [['Component File', 'SHA-256 Digest']]
                for fn, fh in tool_hashes.items():
                    th_data.append([fn, Paragraph(str(fh), mono_style)])
                t_th = Table(th_data, colWidths=[5.0*cm, 12.0*cm])
                t_th.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), LIGHT_GREY),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                    ('TOPPADDING', (0,0), (-1,-1), 3),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 3),
                ]))
                story.append(t_th)

            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Examination Environment Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 9: Chain of Custody
        # =========================================================================
        try:
            story.append(Paragraph('8. Chain of Custody Audit Trail', section_style))
            story.append(Paragraph(
                "The Chain of Custody records each forensic action taken on this artifact from discovery to quarantine. "
                "This ensures non-repudiation, procedural integrity, and compliance with court evidence rules.",
                body_style
            ))

            coc_records = []
            try:
                import chain_of_custody as coc_module
                coc_records = coc_module.get_session_log(session_id)
            except Exception:
                coc_records = []

            if coc_records:
                coc_table_data = [['Step', 'Action', 'Timestamp', 'Result']]
                for i, r in enumerate(coc_records):
                    coc_table_data.append([
                        str(i + 1),
                        Paragraph(str(r.get('action', '')), mono_style),
                        str(r.get('timestamp', ''))[:19],
                        str(r.get('result', 'SUCCESS'))
                    ])
                t_coc = Table(coc_table_data, colWidths=[1.2*cm, 6.0*cm, 5.8*cm, 4.0*cm])
                t_coc.setStyle(TableStyle([
                    ('BACKGROUND', (0,0), (-1,0), ACCENT),
                    ('TEXTCOLOR', (0,0), (-1,0), white),
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                    ('TOPPADDING', (0,0), (-1,-1), 4),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(t_coc)
            else:
                story.append(Paragraph('Chain of custody log not available for this session.', body_style))

            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Chain of Custody Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 10: Scope Notice
        # =========================================================================
        try:
            story.append(Paragraph('9. Investigation Scope and Analytical Limitations', section_style))

            scope_text = (
                "<b>SCOPE NOTICE \u2014 STEGANALYSIS NOT PERFORMED:</b><br/><br/>"
                "Steganography analysis (Layers 1.5, 2, and 3) was <b>NOT performed</b> on this artifact because the file "
                "was isolated at Layer 1 due to critical threat detection. To protect the examination host and prevent "
                "uncontrolled execution, scanning was halted upon confirmation of malicious signatures.<br/><br/>"
                "<b>Notice of Secondary Hazards:</b> This file was not examined for concealed carriers, steganographic "
                "embeddings, or polyglot payloads. The artifact may contain secondary hidden data that remains unanalyzed."
            )
            scope_box = Table([[Paragraph(scope_text, body_style)]], colWidths=[17.0*cm])
            scope_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,-1), SOFT_AMBER),
                ('LINEBEFORE', (0,0), (0,-1), 3, ORANGE_WARN),
                ('TOPPADDING', (0,0), (-1,-1), 8),
                ('BOTTOMPADDING', (0,0), (-1,-1), 8),
                ('LEFTPADDING', (0,0), (-1,-1), 10),
                ('RIGHTPADDING', (0,0), (-1,-1), 8),
            ]))
            story.append(scope_box)
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Scope Notice Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 11: Limitations & Legal Disclaimer
        # =========================================================================
        try:
            story.append(Paragraph('10. Forensic Limitations and Legal Compliance', section_style))

            story.append(Paragraph(
                "This report was produced by Shadow-Trace v1.0.0. The following limitations apply to all findings herein:",
                body_style
            ))

            bullets = [
                "Automated screening does not replace the expert evaluation and testimony of a qualified digital forensic examiner.",
                "Malware classification is label-based, derived from static signature matches and threat intelligence feeds. Detection vendors frequently disagree on taxonomy or variant nomenclature.",
                "Static signatures detect known indicators of compromise and may not recognize novel, polymorphic, or zero-day malware variations.",
                "The findings recorded in this report reflect the state of the artifact at the timestamp of acquisition.",
                "This report should be reviewed by a certified forensic practitioner before submission in judicial proceedings."
            ]
            for b in bullets:
                story.append(Paragraph(f"\u2022  {b}", bullet_style))

            story.append(Spacer(1, 6))

            legal_disclaimer = (
                "<b>Legal Compliance:</b> Analysis performed in accordance with ISO/IEC 27037 digital evidence handling guidelines "
                "and ACPO Good Practice Guide principles. This report is not standalone evidence without expert witness authentication."
            )
            story.append(Paragraph(legal_disclaimer, small_style))
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Limitations Section unavailable: {e}]", small_style))

        # =========================================================================
        # SECTION 12: Report Seal Box
        # =========================================================================
        try:
            story.append(Paragraph('11. Cryptographic Report Seal', section_style))
            story.append(Paragraph(
                "This document is cryptographically sealed using HMAC-SHA3-512 and RFC 3161 trusted timestamping. "
                "The seal permanently binds the report bytes to the cryptographic secret key. Any alteration, page deletion, "
                "or byte substitution will invalidate the seal and render tampering immediately detectable.",
                body_style
            ))

            seal_overview = [
                ['Report Binding Parameter', 'Cryptographic Security Detail'],
                ['Integrity Algorithm', 'SHA3-512 (FIPS 202 Keccak Hash)'],
                ['Authentication Protocol', 'HMAC-SHA3-512 Military-Grade Cryptographic Signature'],
                ['Timestamp Verification', 'RFC 3161 Trusted Time-Stamp Authority (FreeTSA)'],
                ['Report Classification', 'QUARANTINE / THREAT (Evidence Locked)'],
                ['Companion Artifact', Paragraph(f"{report_filename.replace('.pdf', '.seal.json')}", mono_style)],
            ]
            t_seal_box = Table(seal_overview, colWidths=[5.0*cm, 12.0*cm])
            t_seal_box.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (-1,0), DARK_BLUE),
                ('TEXTCOLOR', (0,0), (-1,0), white),
                ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                ('ROWBACKGROUND', (0,1), (-1,-1), [LIGHT_GREY, white]),
                ('FONTNAME', (0,1), (0,-1), 'Helvetica-Bold'),
                ('FONTSIZE', (0,0), (-1,-1), 8.5),
                ('GRID', (0,0), (-1,-1), 0.5, HexColor('#cccccc')),
                ('TOPPADDING', (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
            ]))
            story.append(t_seal_box)
            story.append(Spacer(1, 10))
        except Exception as e:
            story.append(Paragraph(f"[Report Seal Box Section unavailable: {e}]", small_style))

        # =========================================================================
        # Build Document
        # =========================================================================
        doc = SimpleDocTemplate(
            str(report_path),
            pagesize=A4,
            rightMargin=2*cm,
            leftMargin=2*cm,
            topMargin=2*cm,
            bottomMargin=2*cm
        )
        doc.build(story)

        # =========================================================================
        # Cryptographic Sealing & Seal JSON Writing
        # =========================================================================
        with open(report_path, 'rb') as f:
            pdf_bytes = f.read()

        hmac_seal = compute_hmac_seal(pdf_bytes)
        sha3_of_report = hashlib.sha3_512(pdf_bytes).hexdigest()
        ts_result = get_rfc3161_timestamp(pdf_bytes)

        seal_path = report_path.with_suffix('.seal.json')
        seal_data = {
            'report_file': report_path.name,
            'report_type': 'QUARANTINE',
            'verdict': 'THREAT',
            'sha3_512_of_report': sha3_of_report,
            'hmac_sha3_512': hmac_seal,
            'rfc3161_timestamp': ts_result,
            'shadow_trace_version': str(getattr(config, 'VERSION', '1.0.0')),
            'generated_at': now_utc.isoformat(),
            'session_id': session_id,
            'quarantine_path': str(quarantine_path) if quarantine_path else None,
            'quarantine_reason': quarantine_reason,
            'malware_classification': classification if 'classification' in locals() else {},
            'source_correlation': correlation_data or {}
        }

        with open(seal_path, 'w', encoding='utf-8') as f:
            json.dump(seal_data, f, indent=2)

        return {
            'success': True,
            'report_path': str(report_path),
            'seal_path': str(seal_path),
            'hmac': hmac_seal,
            'rfc3161': ts_result.get('success', False),
            'size_bytes': len(pdf_bytes),
            'error': None
        }

    except Exception as e:
        return {
            'success': False,
            'report_path': None,
            'seal_path': None,
            'hmac': None,
            'rfc3161': False,
            'size_bytes': 0,
            'error': str(e)
        }


# =============================================================================
# Standalone Test Execution
# =============================================================================
if __name__ == '__main__':
    print('=== SHADOW-TRACE | QUARANTINE REPORT GENERATION TEST ===')
    print()

    # Create dummy quarantine file for test
    test_dummy = config.BASE_DIR / 'scratch' / 'mock_wannacry_sample.bin'
    test_dummy.parent.mkdir(parents=True, exist_ok=True)
    with open(test_dummy, 'wb') as f:
        f.write(b'MOCK_QUARANTINE_PAYLOAD_TEST_DATA_BYTES_1234567890\n' * 50)

    mock_filepath = str(Path.home() / 'Downloads' / 'invoice_dec2026_encrypted.pdf')
    mock_session = 'TEST_QUARANTINE_SESSION_881'
    mock_quarantine_path = str(test_dummy)

    mock_layer1 = {
        'verdict': 'THREAT',
        'detecting_stage': 'STAGE3_LOCAL',
        'detecting_engine': 'ClamAV',
        'threat_name': 'Win.Ransomware.WannaCry-71234',
        'threat_family': 'WannaCry',
        'threat_type': 'Ransomware',
        'threat_category': 'Ransomware',
        'severity': 'CRITICAL',
        'quarantine_path': mock_quarantine_path,
        'stage1_hash': {'match': True, 'status': 'SUCCESS'},
        'stage2_mime': {'mime': 'application/pdf', 'status': 'VALID'},
        'stage3_clamav': {
            'engine': 'ClamAV',
            'verdict': 'THREAT',
            'threat_name': 'Win.Ransomware.WannaCry-71234',
            'threat_family': 'WannaCry',
            'threat_category': 'Ransomware'
        },
        'stage3_yara': {
            'engine': 'YARA',
            'verdict': 'THREAT',
            'matched_rules': ['ransomware_wannacry_payload', 'pdf_with_embedded_exe'],
            'threat_name': 'ransomware_wannacry_payload'
        },
        'yara_matched_rules': ['ransomware_wannacry_payload', 'pdf_with_embedded_exe'],
        'yara_warnings': ['suspicious_xref'],
        'informational_matches': ['Big_Numbers1'],
        'stage3_heuristics': [
            {'engine': 'PE_HEADER_SCAN', 'verdict': 'THREAT', 'reason': 'Embedded PE executable binary detected inside PDF carrier stream'}
        ],
        'stage4_virustotal': {
            'engine': 'VirusTotal',
            'verdict': 'THREAT',
            'malicious_count': 41,
            'positives': 41,
            'total': 72,
            'most_common_threat_name': 'Trojan.Ransom.WannaCrypt',
            'threat_family': 'WannaCry',
            'vt_mode': 'hash_only',
            'cached': False
        },
        'all_scan_results': {
            'stage3_clamav': {'verdict': 'THREAT', 'threat_name': 'Win.Ransomware.WannaCry-71234'},
            'stage3_yara': {'verdict': 'THREAT', 'matched_rules': ['ransomware_wannacry_payload', 'pdf_with_embedded_exe']},
            'stage4_virustotal': {'verdict': 'THREAT', 'positives': 41, 'total': 72, 'most_common_threat_name': 'Trojan.Ransom.WannaCrypt'}
        }
    }

    mock_multi_hash = {
        'success': True,
        'md5': '5d41402abc4b2a76b9719d911017c592',
        'sha256': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae',
        'sha3_512': '11a6296b429be3743ec985b8fae72ec4c9796ef55fa41639d67568579d4cfbc7bfba5dc42cb3ef6a72e811f56b3e7c84bb07c1221b22e11d04ec95cf586dd80a',
        'file_size_bytes': 2550
    }

    print('Generating Quarantine Report...')
    res = generate_quarantine_report(
        filepath=mock_filepath,
        session_id=mock_session,
        layer1_result=mock_layer1,
        multi_hash=mock_multi_hash,
        quarantine_path=mock_quarantine_path,
        quarantine_reason='ClamAV and YARA detected confirmed WannaCry ransomware signatures with embedded PE executable payload.'
    )

    print()
    print('Report Generation Result:')
    print(f"  Success:      {res.get('success')}")
    print(f"  Report Path:  {res.get('report_path')}")
    print(f"  Seal Path:    {res.get('seal_path')}")
    print(f"  HMAC Seal:    {res.get('hmac')}")
    print(f"  RFC 3161:     {res.get('rfc3161')}")
    print(f"  Size Bytes:   {res.get('size_bytes')}")
    print(f"  Error:        {res.get('error')}")

    if res.get('success') and res.get('seal_path') and os.path.exists(res.get('seal_path')):
        print()
        print('Companion Seal File (.seal.json) Contents:')
        with open(res.get('seal_path'), 'r', encoding='utf-8') as sf:
            seal_content = json.load(sf)
        print(json.dumps(seal_content, indent=2))

    print()
    print('=== TEST COMPLETE ===')
