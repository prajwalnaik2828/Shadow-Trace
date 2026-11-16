# =============================================================================
# Shadow-Trace | confidence_calibration.py
# Adds calibrated confidence bands, uncertainty levels, and reliability
# explanations to every steganalysis result. Does NOT change any existing
# scoring or verdicts — only adds additional context fields.
# =============================================================================

from typing import Dict, Any, Tuple
from pathlib import Path


# =============================================================================
# SECTION 1: CONFIDENCE BAND DEFINITIONS
# =============================================================================

CONFIDENCE_BANDS = {
    'VERY_HIGH': {
        'min': 0.85, 'max': 1.00,
        'label': 'Very High Confidence',
        'reliability': 'Strong',
        'court_weight': 'Primary Forensic Evidence',
        'description': (
            'The ensemble detection score falls in the very high range '
            '(>= 0.85). Multiple independent detection methods are in '
            'agreement. Subject to qualified expert review, this result '
            'may be presented as primary forensic evidence in accordance '
            'with applicable evidentiary standards.'
        ),
        'action': 'Immediate escalation is indicated. '
                  'Preserve all forensic artifacts pending investigation.',
    },
    'HIGH': {
        'min': 0.65, 'max': 0.85,
        'label': 'High Confidence',
        'reliability': 'Substantial',
        'court_weight': 'Corroborating Forensic Evidence',
        'description': (
            'The ensemble detection score falls in the high range '
            '(0.65 – 0.85). The result indicates substantial grounds '
            'for suspicion of steganographic content. Independent '
            'manual examination by a qualified examiner is recommended '
            'before reliance as primary evidence.'
        ),
        'action': 'Manual examination by a qualified forensic examiner '
                  'is recommended. Preserve the file and all associated artifacts.',
    },
    'MEDIUM': {
        'min': 0.40, 'max': 0.65,
        'label': 'Medium Confidence — Indeterminate Zone',
        'reliability': 'Indeterminate',
        'court_weight': 'Limited',
        'description': (
            'The ensemble detection score falls in the indeterminate zone '
            '(0.40 – 0.65). The system is unable to make a reliable '
            'determination at this threshold. This result constitutes a '
            'flag for further investigation and must not be treated as '
            'confirmed evidence of steganography. Independent manual '
            'review by a qualified examiner is required before any '
            'conclusion is drawn.'
        ),
        'action': 'Further investigation is required. '
                  'This result is not a standalone conclusion and must not '
                  'be relied upon without independent manual review.',
    },
    'LOW': {
        'min': 0.20, 'max': 0.40,
        'label': 'Low Confidence — Likely Clean',
        'reliability': 'Minimal',
        'court_weight': 'Not Independently Evidential',
        'description': (
            'The ensemble detection score falls in the low range '
            '(0.20 – 0.40). Minor statistical anomalies were observed '
            'but these fall within normal variation for files of this '
            'type and format. This result does not constitute evidence '
            'of steganographic content.'
        ),
        'action': 'No forensic action required. '
                  'No steganographic indicators of significance were identified.',
    },
    'VERY_LOW': {
        'min': 0.00, 'max': 0.20,
        'label': 'Very Low Confidence — Clean',
        'reliability': 'None',
        'court_weight': 'Not Independently Evidential',
        'description': (
            'The ensemble detection score falls in the very low range '
            '(< 0.20). No steganographic indicators were detected. '
            'The file statistical properties are consistent with '
            'natural, unmodified content. This result is reliable '
            'for exclusion purposes within the scope of the detection '
            'methods applied.'
        ),
        'action': 'No forensic action required. File may be released for normal use.',
    },
}

UNCERTAINTY_FACTORS = {
    'model_disagreement': (
        'Individual detection models returned divergent scores. '
        'Where model outputs are in significant disagreement, '
        'the reliability of the weighted fusion score is reduced. '
        'This finding should not be treated as a standalone conclusion.'
    ),
    'borderline_score': (
        'The ensemble score falls within 5 percentage points of a '
        'band boundary. Results in proximity to a decision boundary '
        'are subject to increased sensitivity to minor variations in '
        'file content or preprocessing parameters. Independent review '
        'is warranted before reliance on this result.'
    ),
    'limited_file_size': (
        'The file does not contain sufficient data for statistically '
        'valid analysis. Chi-Square and RS Analysis require a minimum '
        'number of samples to produce reliable outputs. Statistical '
        'scores derived from undersized files may not be representative.'
    ),
    'model_not_loaded': (
        'One or more primary detection models were unavailable at the '
        'time of this scan. The ensemble result is based on a reduced '
        'set of detection methods. This may affect the completeness '
        'and reliability of the reported score.'
    ),
    'adaptive_stego_possible': (
        'The ALASKA2 adaptive steganography model returned a low score. '
        'Adaptive steganography is designed to minimise statistical '
        'detectability. A negative result from this model does not '
        'exclude the presence of adaptive steganographic content. '
        'The absence of a positive detection cannot be treated as '
        'confirmation of a clean file.'
    ),
    'synthetic_model': (
        'The video steganalysis model was trained exclusively on '
        'synthetically generated steganographic content. Generalisation '
        'to professionally produced real-world video has not been '
        'independently validated. Results should be treated as '
        'indicative and are subject to expert corroboration.'
    ),
    'document_tokenisation': (
        'Document steganography detection employs a hybrid methodology '
        'combining a neural component and a deterministic rule-based '
        'component. The neural component may not detect steganographic '
        'methods not represented in its training corpus. The '
        'deterministic component provides reliable detection for '
        'zero-width Unicode character and homoglyph substitution methods.'
    ),
}


SYSTEM_LIMITATIONS = [
    {
        'component': 'ALASKA2 Adaptive Steganography Model',
        'limitation': (
            'The ALASKA2 EfficientNet-B0 model achieves approximately '
            '0.54 AUC on adaptive steganography detection. This is '
            'near the performance ceiling achievable with limited '
            'training resources on this class of algorithms. Results '
            'from this model alone should be treated as indicative '
            'and not used as primary forensic evidence.'
        ),
        'implication': 'Adaptive stego may not be reliably detected.',
    },
    {
        'component': 'Video Steganalysis Model',
        'limitation': (
            'The VideoStegNet model was trained on synthetically '
            'generated video steganography. Performance on real-world '
            'professionally produced video content has not been '
            'extensively validated. DCT stream results showed '
            'inflated performance on synthetic test data.'
        ),
        'implication': 'Video results require expert corroboration.',
    },
    {
        'component': 'Statistical Analysis on Small Files',
        'limitation': (
            'Chi-Square and RS Analysis statistical tests require '
            'a sufficient number of pixels to produce statistically '
            'valid results. Files with fewer than approximately '
            '10,000 pixels may produce unreliable statistical scores.'
        ),
        'implication': 'Small image files may have unreliable statistical scores.',
    },
    {
        'component': 'Adaptive Steganography Payload Extraction',
        'limitation': (
            'Without the embedding key used during steganography '
            'creation, full extraction of adaptively embedded payloads '
            'is mathematically impossible. Layer 3 can estimate payload '
            'presence and size through DCT coefficient analysis but '
            'cannot reconstruct the actual payload content.'
        ),
        'implication': 'Encrypted adaptive payloads cannot be read without the key.',
    },
    {
        'component': 'Document Neural Model',
        'limitation': (
            'The DistilBERT document model was trained on four specific '
            'steganography methods. Novel document steganography techniques '
            'not represented in training data will not be detected by '
            'the neural component. The deterministic regex component '
            'provides reliable detection for zero-width and homoglyph '
            'methods regardless of this limitation.'
        ),
        'implication': 'Novel document stego methods may not be detected.',
    },
    {
        'component': 'VirusTotal Integration',
        'limitation': (
            'VirusTotal scanning requires internet connectivity and '
            'is subject to API rate limiting at 4 requests per minute '
            'on the free tier. Unknown files require upload to a '
            'third-party service, which may not be acceptable in '
            'high-security forensic environments.'
        ),
        'implication': 'Cloud scanning may not be suitable for classified evidence.',
    },
]


# =============================================================================
# FUNCTION 1: get_confidence_band
# =============================================================================

def get_confidence_band(score: float) -> Dict:
    """Return the confidence band dict for a given score."""
    for band_name, band_data in CONFIDENCE_BANDS.items():
        if band_data['min'] <= score <= band_data['max']:
            return {
                'band_name': band_name,
                **band_data,
                'score': round(score, 4),
                'score_pct': str(round(score * 100, 1)) + '%',
            }
    # Fallback to VERY_LOW
    band_data = CONFIDENCE_BANDS['VERY_LOW']
    return {
        'band_name': 'VERY_LOW',
        **band_data,
        'score': round(score, 4),
        'score_pct': str(round(score * 100, 1)) + '%',
    }


# =============================================================================
# FUNCTION 2: detect_uncertainty_factors
# =============================================================================

def detect_uncertainty_factors(
    layer2_result: Dict,
    file_type: str = 'IMAGE'
) -> list:
    """Identify specific uncertainty factors present in this scan result."""
    factors = []

    # Check model disagreement for images
    if file_type == 'IMAGE':
        t1a = layer2_result.get('tier1a_yedroudj', {}) or {}
        t1b = layer2_result.get('tier1b_alaska2', {}) or {}
        t1a_score = t1a.get('score', 0.5) or 0.5
        t1b_score = t1b.get('score', 0.5) or 0.5

        if abs(t1a_score - t1b_score) > 0.30:
            factors.append({
                'factor': 'Inter-Model Divergence',
                'detail': (
                    f'YedroudjNetV3 returned {round(t1a_score*100,1)}% '
                    f'while the ALASKA2 adaptive model returned {round(t1b_score*100,1)}%. '
                    f'The inter-model divergence of {round(abs(t1a_score-t1b_score)*100,1)} '
                    f'percentage points reduces the forensic weight of the '
                    f'ensemble result. Independent review is required.'
                ),
                'explanation': UNCERTAINTY_FACTORS['model_disagreement'],
            })

    # Check borderline score
    score = layer2_result.get('score', 0.5)
    boundaries = [0.40, 0.65, 0.85]
    for boundary in boundaries:
        if abs(score - boundary) < 0.05:
            factors.append({
                'factor': 'Score Near Decision Threshold',
                'detail': (
                    f'The ensemble score of {round(score*100,1)}% falls '
                    f'within 5 percentage points of the '
                    f'{round(boundary*100,0):.0f}% band boundary. '
                    f'Results in this proximity to a decision threshold '
                    f'are subject to increased sensitivity and should not '
                    f'be relied upon as a standalone conclusion.'
                ),
                'explanation': UNCERTAINTY_FACTORS['borderline_score'],
            })
            break

    # Check model availability
    model_loaded = layer2_result.get('model_loaded', True)
    if not model_loaded or model_loaded is False:
        factors.append({
            'factor': 'Reduced Detection Coverage',
            'detail': 'Primary detection model was not available.',
            'explanation': UNCERTAINTY_FACTORS['model_not_loaded'],
        })

    # Check adaptive stego caveat for images
    if file_type == 'IMAGE':
        t1b = layer2_result.get('tier1b_alaska2', {}) or {}
        t1b_score = t1b.get('score', 0.5) or 0.5
        if t1b_score < 0.50:
            factors.append({
                'factor': 'Adaptive Steganography Cannot Be Excluded',
                'detail': (
                    f'The ALASKA2 adaptive model returned {round(t1b_score*100,1)}% '
                    f'(below detection threshold). Adaptive steganography '
                    f'cannot be excluded on the basis of this result alone, '
                    f'as such methods are designed to minimise statistical '
                    f'detectability. A negative adaptive model result does not '
                    f'constitute confirmation of a clean file.'
                ),
                'explanation': UNCERTAINTY_FACTORS['adaptive_stego_possible'],
            })

    # Check synthetic model for video
    if file_type == 'VIDEO':
        factors.append({
            'factor': 'Synthetic Training Data Limitation',
            'detail': (
                'Video steganalysis model was trained on synthetic '
                'data. Performance on real-world video content '
                'may vary from laboratory performance.'
            ),
            'explanation': UNCERTAINTY_FACTORS['synthetic_model'],
        })

    # Check document tokenisation caveat
    if file_type == 'DOCUMENT':
        factors.append({
            'factor': 'Neural Coverage Limitation',
            'detail': (
                'Neural document model may not detect all stego '
                'methods. Deterministic Unicode detection is '
                'highly reliable for zero-width and homoglyph methods.'
            ),
            'explanation': UNCERTAINTY_FACTORS['document_tokenisation'],
        })

    return factors


# =============================================================================
# FUNCTION 3: separate_evidence_types
# =============================================================================

def separate_evidence_types(
    layer1_result: Dict,
    layer2_result: Dict,
    layer3_result: Dict,
    lsb_result: Dict = None,
    confidence_band: Dict = None
) -> Dict:
    """
    Separate findings into four evidence categories:
    1. Confirmed Facts (directly observed, not inferred)
    2. Model Predictions (AI/statistical probability outputs)
    3. Heuristic Warnings (pattern-based, not conclusive)
    4. Expert Interpretation (synthesised conclusions)
    """
    confirmed_facts = []
    model_predictions = []
    heuristic_warnings = []
    expert_interpretation = []

    # ------------------------------------------------------------------
    # CONFIRMED FACTS — things directly measured
    # ------------------------------------------------------------------

    file_hash = layer1_result.get('stage1_hash', '')
    if file_hash and file_hash != 'UNKNOWN':
        confirmed_facts.append({
            'finding': 'File cryptographic hash verified',
            'detail': 'SHA3-512 hash confirmed file integrity '
                      'from detection to report generation.',
            'evidence_type': 'DIRECT_MEASUREMENT',
        })

    mime = layer1_result.get('stage2_mime', '')
    if mime and mime != 'UNKNOWN':
        confirmed_facts.append({
            'finding': f'File type identified as {mime}',
            'detail': 'MIME type determined from file magic bytes '
                      'and extension verification.',
            'evidence_type': 'DIRECT_MEASUREMENT',
        })

    clamav = layer1_result.get('stage3_clamav', '')
    if clamav:
        confirmed_facts.append({
            'finding': f'ClamAV scan result: {clamav}',
            'detail': 'ClamAV signature database scan. '
                      'CLEAN means no known malware signature matched.',
            'evidence_type': 'SIGNATURE_MATCH',
        })

    # Zero-width chars from layer2 document stream
    stream2b = layer2_result.get('stream2b_unicode', {}) or {}
    zw_total = stream2b.get('zero_width_total', 0) or 0
    if zw_total > 0:
        confirmed_facts.append({
            'finding': f'{zw_total} zero-width Unicode characters detected',
            'detail': (
                f'Direct character-level scan found {zw_total} invisible '
                f'Unicode characters in the document text. These are '
                f'not visible to the reader but are present in the '
                f'file encoding. This is a direct observation, not '
                f'a model prediction.'
            ),
            'evidence_type': 'DIRECT_OBSERVATION',
        })

    # Executable magic bytes from layer3
    extraction = layer3_result.get('extraction_results', {}) if layer3_result else {}
    if extraction.get('is_executable', False):
        confirmed_facts.append({
            'finding': 'Executable file signature detected in extracted payload',
            'detail': (
                'Magic byte analysis of extracted LSB data identified '
                'a Windows PE or ELF executable signature. This is a '
                'direct file format identification, not a prediction.'
            ),
            'evidence_type': 'DIRECT_OBSERVATION',
        })

    # LSB executable check result
    if lsb_result and lsb_result.get('verdict') == 'EXECUTABLE_FOUND':
        sigs = lsb_result.get('signatures_found', [])
        sig_names = [s.get('signature_type', str(s)) if isinstance(s, dict) else str(s) for s in sigs]
        pos = lsb_result.get('position', 'unknown')
        confirmed_facts.append({
            'finding': f'Executable signature in LSB data at position {pos}',
            'detail': (
                f'LSB extraction and binary header scanning found '
                f'executable signature: {", ".join(sig_names) if sig_names else "unknown"}. '
                f'This is a directly observed file signature pattern.'
            ),
            'evidence_type': 'DIRECT_OBSERVATION',
        })

    # ------------------------------------------------------------------
    # MODEL PREDICTIONS — AI and statistical outputs
    # ------------------------------------------------------------------

    score = layer2_result.get('score', 0.0)
    verdict = layer2_result.get('verdict', 'UNKNOWN')
    file_type = layer2_result.get('file_type', 'IMAGE')

    model_predictions.append({
        'finding': f'Steganalysis ensemble score: {round(score*100,1)}%',
        'detail': (
            f'The weighted fusion of all active detection models '
            f'produced a combined score of {round(score*100,1)}%. '
            f'This is a probabilistic output. It represents the '
            f'system\'s estimated probability that steganographic '
            f'content is present, not a definitive confirmation.'
        ),
        'verdict': verdict,
        'evidence_type': 'PROBABILISTIC_MODEL_OUTPUT',
    })

    # Individual tier predictions for IMAGE type
    if file_type == 'IMAGE':
        t1a = layer2_result.get('tier1a_yedroudj', {}) or {}
        t1b = layer2_result.get('tier1b_alaska2', {}) or {}
        t3  = layer2_result.get('tier3_statistical', {}) or {}

        if t1a.get('score') is not None:
            model_predictions.append({
                'finding': f'YedroudjNetV3 spatial LSB model: {round((t1a.get("score", 0))*100,1)}%',
                'detail': (
                    'Neural network trained on spatial LSB steganography. '
                    'Reliable for direct pixel-level LSB embedding. '
                    'Less reliable for transform domain methods.'
                ),
                'evidence_type': 'NEURAL_NETWORK_OUTPUT',
            })

        if t1b.get('score') is not None:
            model_predictions.append({
                'finding': f'ALASKA2 adaptive model: {round((t1b.get("score", 0))*100,1)}%',
                'detail': (
                    'Neural network trained on JMiPOD, JUNIWARD, UERD. '
                    'Targets adaptive steganography in JPEG images. '
                    'AUC 0.54 — results are indicative not conclusive.'
                ),
                'evidence_type': 'NEURAL_NETWORK_OUTPUT',
            })

        chi_score = t3.get('chi_square', {}).get('score', None) if t3 else None
        if chi_score is not None:
            model_predictions.append({
                'finding': f'Chi-Square statistical test: {round(chi_score*100,1)}%',
                'detail': (
                    'Mathematical test measuring convergence of adjacent '
                    'pixel value pair frequencies. High score indicates '
                    'LSB-level statistical anomaly consistent with embedding.'
                ),
                'evidence_type': 'STATISTICAL_TEST_OUTPUT',
            })

    # ------------------------------------------------------------------
    # HEURISTIC WARNINGS — pattern-based, not conclusive
    # ------------------------------------------------------------------

    yara_warnings  = layer1_result.get('yara_warnings', []) or []
    yara_threats   = layer1_result.get('yara_matched_rules', []) or []

    for rule in yara_threats:
        heuristic_warnings.append({
            'finding': f'YARA rule matched: {rule}',
            'detail': (
                f'The YARA pattern matching engine matched the rule '
                f'"{rule}" against the file content. YARA rules are '
                f'heuristic patterns created by security researchers. '
                f'A match indicates suspicious characteristics but '
                f'is not proof of malicious intent.'
            ),
            'severity': 'THREAT',
            'evidence_type': 'HEURISTIC_PATTERN_MATCH',
        })

    for rule in yara_warnings:
        heuristic_warnings.append({
            'finding': f'YARA warning: {rule}',
            'detail': (
                f'YARA rule "{rule}" matched. This rule is classified '
                f'as informational — it detects structural anomalies '
                f'that can also occur in legitimate files from '
                f'non-standard software.'
            ),
            'severity': 'WARNING',
            'evidence_type': 'HEURISTIC_PATTERN_MATCH',
        })

    # Entropy heuristic from layer3
    if layer3_result:
        extraction  = layer3_result.get('extraction_results', {}) or {}
        entropy     = extraction.get('payload_entropy', 0.0) or 0.0
        entropy_cls = extraction.get('payload_class', '') or ''
        if entropy > 7.2:
            heuristic_warnings.append({
                'finding': f'High payload entropy detected: {entropy:.4f} bits/byte',
                'detail': (
                    f'Shannon entropy of {entropy:.4f} bits per byte was '
                    f'measured in the extracted bit plane data. '
                    f'Values above 7.2 are consistent with encrypted '
                    f'or compressed content, suggesting deliberate '
                    f'concealment of the payload. Note: high entropy '
                    f'can also occur naturally in compressed image regions.'
                ),
                'classification': entropy_cls,
                'evidence_type': 'ENTROPY_HEURISTIC',
            })

    # ------------------------------------------------------------------
    # EXPERT INTERPRETATION — synthesised conclusion
    # ------------------------------------------------------------------

    overall_verdict  = layer2_result.get('verdict', 'UNKNOWN')
    if not confidence_band:
        score = layer2_result.get('score', 0.0)
        confidence_band = get_confidence_band(score)

    if overall_verdict == 'STEGO_DETECTED':
        interpretation = (
            f'The totality of evidence presents a {confidence_band["label"]} '
            f'case for the presence of steganographic content. '
            f'The most significant indicators are: '
            f'{", ".join([f["finding"] for f in confirmed_facts[:2]]) if confirmed_facts else "model scores"}. '
            f'A qualified digital forensic examiner should review '
            f'all findings before this result is used as evidence '
            f'in legal proceedings.'
        )
    elif overall_verdict == 'SUSPICIOUS':
        interpretation = (
            f'The evidence is borderline. Statistical and model '
            f'indicators suggest the possibility of steganographic '
            f'content but the confidence level is insufficient for '
            f'a definitive determination. Manual expert examination '
            f'is strongly recommended before any conclusions are drawn.'
        )
    else:
        interpretation = (
            f'No significant steganographic indicators were detected. '
            f'The file statistical properties are consistent with '
            f'natural unmodified content. This result supports '
            f'exclusion of steganographic content but does not '
            f'constitute absolute proof of absence, particularly '
            f'for sophisticated adaptive steganography methods.'
        )

    expert_interpretation.append({
        'finding': 'Overall forensic assessment',
        'detail': interpretation,
        'verdict': overall_verdict,
        'confidence': confidence_band['label'],
        'evidence_type': 'EXPERT_SYNTHESIS',
    })

    return {
        'confirmed_facts':      confirmed_facts,
        'model_predictions':    model_predictions,
        'heuristic_warnings':   heuristic_warnings,
        'expert_interpretation': expert_interpretation,
        'total_findings': (
            len(confirmed_facts) + len(model_predictions) +
            len(heuristic_warnings) + len(expert_interpretation)
        ),
    }


# =============================================================================
# FUNCTION 4: calibrate_result  (main entry point)
# =============================================================================

def calibrate_result(
    layer1_result: Dict,
    layer2_result: Dict,
    layer3_result: Dict = None,
    lsb_result: Dict = None,
    file_type: str = 'IMAGE'
) -> Dict:
    """
    Main entry point. Returns a complete calibrated context dict to be
    added on top of the existing forensic report. Does NOT modify scores
    or verdicts from earlier pipeline stages.
    """
    score   = layer2_result.get('score', 0.0) or 0.0
    verdict = layer2_result.get('verdict', 'UNKNOWN')

    confidence_band     = get_confidence_band(score)
    uncertainty_factors = detect_uncertainty_factors(layer2_result, file_type)
    
    if len(uncertainty_factors) > 0:
        if confidence_band['band_name'] == 'VERY_HIGH':
            confidence_band['label'] = 'Qualified High Confidence — Uncertainty Factors Present'
            confidence_band['court_weight'] = 'Corroborating Forensic Evidence'
        elif confidence_band['band_name'] == 'HIGH':
            confidence_band['label'] = 'Qualified Confidence — Uncertainty Factors Present'

    evidence_separation = separate_evidence_types(
        layer1_result,
        layer2_result,
        layer3_result or {},
        lsb_result,
        confidence_band
    )

    overall_reliability = confidence_band['reliability']
    if len(uncertainty_factors) >= 2:
        overall_reliability = 'Severely Restricted — Multiple uncertainty factors necessitate independent review'
    elif len(uncertainty_factors) == 1:
        overall_reliability = confidence_band['reliability'].title() + ' — Subject to noted limitations'

    return {
        'score':                score,
        'score_pct':            str(round(score * 100, 1)) + '%',
        'verdict':              verdict,
        'confidence_band':      confidence_band,
        'overall_reliability':  overall_reliability,
        'uncertainty_factors':  uncertainty_factors,
        'uncertainty_count':    len(uncertainty_factors),
        'evidence_separation':  evidence_separation,
        'recommended_action':   confidence_band['action'],
        'court_weight':         confidence_band['court_weight'],
        'small_file_warning':   layer2_result.get('small_file_warning', False),
        'image_size_check':     layer2_result.get('image_size_check', {}),
    }


# =============================================================================
# TEST BLOCK
# =============================================================================

if __name__ == '__main__':
    SEP = '=' * 66
    print(SEP)
    print('  SHADOW-TRACE  |  Confidence Calibration Module — Verification')
    print(SEP)
    print()

    mock_layer1 = {
        'verdict': 'CLEAN',
        'stage1_hash': 'abc123',
        'stage2_mime': 'image/jpeg',
        'stage3_clamav': 'CLEAN',
        'stage3_yara': {'verdict': 'CLEAN'},
        'yara_warnings': ['Big_Numbers1'],
        'yara_matched_rules': [],
        'informational_matches': ['Big_Numbers1'],
    }

    mock_layer2_suspicious = {
        'verdict': 'SUSPICIOUS',
        'score': 0.63,
        'file_type': 'IMAGE',
        'model_loaded': True,
        'tier1a_yedroudj': {'score': 0.91, 'verdict': 'STEGO_DETECTED'},
        'tier1b_alaska2':  {'score': 0.35, 'verdict': 'CLEAN'},
        'tier3_statistical': {
            'chi_square':  {'score': 0.95, 'verdict': 'STEGO_DETECTED'},
            'rs_analysis': {'score': 0.88, 'verdict': 'STEGO_DETECTED'},
        },
    }

    mock_layer3 = {
        'extraction_results': {
            'payload_entropy': 7.85,
            'payload_class':   'ENCRYPTED_OR_COMPRESSED',
            'is_executable':   False,
            'payload_size_bytes': 15420,
        }
    }

    result = calibrate_result(
        mock_layer1, mock_layer2_suspicious,
        mock_layer3, None, 'IMAGE'
    )

    cb = result['confidence_band']

    print('CALIBRATED RESULT SUMMARY')
    print('-' * 40)
    print('  Score (ensemble):    ' + result['score_pct'] +
          '  (calibrated; approximate — not a probability estimate)')
    print('  Verdict:             ' + result['verdict'])
    print('  Confidence Band:     ' + cb['label'])
    print()
    print('  Band Assignment Rule:')
    print(f'    Score {cb["score_pct"]} falls within the {cb["band_name"]} band '
          f'(threshold range: {cb["min"]*100:.0f}% – {cb["max"]*100:.0f}%).')
    print('    Bands are defined as: '
          'Very Low 0–20 | Low 20–40 | Medium 40–65 | High 65–85 | Very High 85–100.')
    print()
    print('  Forensic Reliability: ' + result['overall_reliability'])
    print('  Evidential Value:     ' + result['court_weight'])
    print('  Recommended Action:   ' + result['recommended_action'])
    print()

    print('UNCERTAINTY OBSERVATIONS (' + str(result['uncertainty_count']) + ' identified)')
    print('-' * 40)
    for f in result['uncertainty_factors']:
        label = f['factor']
        print('  [' + label + ']')
        print('    ' + f['detail'])
        print()

    evidence = result['evidence_separation']

    print('CONFIRMED FACTS  (directly observed; not inferred)')
    print('-' * 40)
    for f in evidence['confirmed_facts']:
        print('  [' + f['evidence_type'] + ']  ' + f['finding'])
    print()

    print('MODEL PREDICTIONS  (probabilistic outputs; not definitive)')
    print('-' * 40)
    for p in evidence['model_predictions'][:3]:
        print('  [' + p['evidence_type'] + ']  ' + p['finding'])
    print()

    print('HEURISTIC OBSERVATIONS  (pattern-based; not conclusive)')
    print('-' * 40)
    for w in evidence['heuristic_warnings']:
        print('  [' + w['evidence_type'] + ']  ' + w['finding'])
    print()

    print('FORENSIC ASSESSMENT  (expert synthesis)')
    print('-' * 40)
    for e in evidence['expert_interpretation']:
        words = e['detail'].split()
        line, lines = '', []
        for word in words:
            if len(line) + len(word) + 1 > 72:
                lines.append(line)
                line = word
            else:
                line = (line + ' ' + word).strip()
        if line:
            lines.append(line)
        for ln in lines:
            print('  ' + ln)
    print()

    print('FORMAL LIMITATION STATEMENT')
    print('-' * 40)
    print('  This result is produced by an automated steganalysis system and')
    print('  must not be relied upon as a standalone conclusion. The ensemble')
    print('  score reflects a calibrated approximation and not a mathematically')
    print('  precise probability. Inter-model divergence, score proximity to a')
    print('  decision boundary, and the inherent limitations of adaptive')
    print('  steganography detection collectively reduce the forensic weight of')
    print('  this result. Independent manual review by a qualified digital')
    print('  forensic examiner is required before this result is used in any')
    print('  investigative, disciplinary, or legal proceeding.')
    print()
    print('  Documented system limitations: ' + str(len(SYSTEM_LIMITATIONS)))
    for lim in SYSTEM_LIMITATIONS:
        print('    [' + lim['component'] + '] ' + lim['implication'])
    print()
    print(SEP)
    print('  Verification complete — module operational')
    print(SEP)
