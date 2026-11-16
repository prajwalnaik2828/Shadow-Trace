import os
import csv
import json
import hmac
import hashlib
import zipfile
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Optional
import config

HMAC_KEY = os.environ.get(
    'HMAC_SECRET_KEY',
    ''
).encode('utf-8')


def _extract_verdict_str(value: Any) -> str:
    if isinstance(value, dict):
        return value.get('verdict', str(value))
    elif isinstance(value, str):
        return value
    else:
        return str(value)


def build_evidence_bundle(
    filepath: str,
    session_id: str,
    sha3_hash: str,
    layer1_result: Dict,
    layer2_result: Dict,
    layer3_result: Dict,
    layer4_xai_result: Dict,
    calibration: Dict = None,
    technical_report_path: str = None,
    summary_report_path: str = None,
) -> Dict:
    try:
        filename = Path(filepath).name
        file_size = Path(filepath).stat().st_size if Path(filepath).exists() else 0
        verdict = layer2_result.get('verdict', 'UNKNOWN')
        score = layer2_result.get('score', 0.0) or 0.0
        file_type = layer2_result.get('file_type', 'UNKNOWN')
        generated_at = datetime.now(timezone.utc).isoformat()

        bundle = {
            'schema_version': '1.0',
            'bundle_type': 'SHADOW_TRACE_EVIDENCE_BUNDLE',
            'generated_at': generated_at,
            'shadow_trace_version': '1.0.0',
            
            'case_metadata': {
                'session_id': session_id,
                'examiner_name': os.environ.get(
                    'EXAMINER_NAME', 'Unknown'
                ),
                'examiner_id': os.environ.get(
                    'EXAMINER_ID', 'Unknown'
                ),
                'organisation': os.environ.get(
                    'EXAMINER_ORG', 'Unknown'
                ),
                'examination_date': datetime.now().strftime(
                    '%Y-%m-%d'
                ),
                'examination_time': datetime.now().strftime(
                    '%H:%M:%S'
                ),
            },
            
            'file_identity': {
                'filename': filename,
                'full_path': str(filepath),
                'file_size_bytes': file_size,
                'file_size_kb': round(file_size / 1024, 2),
                'file_type': file_type,
                'sha3_512_hash': sha3_hash,
                'mime_type': layer1_result.get(
                    'stage2_mime', 'UNKNOWN'
                ),
                'hash_verified': str(
                    layer1_result.get('stage1_hash', '')
                ) not in ['', 'UNKNOWN', 'FAILED'],
                'source_url': layer2_result.get('source_url', None),
                'url_captured': layer2_result.get('source_url') is not None,
            },
            
            'malware_screening': {
                'overall_verdict': layer1_result.get(
                    'verdict', 'UNKNOWN'
                ),
                'clamav_result': str(
                    layer1_result.get('stage3_clamav', 'UNKNOWN')
                ),
                'yara_verdict': _extract_verdict_str(
                    layer1_result.get('stage3_yara', 'UNKNOWN')
                ),
                'yara_threat_rules': layer1_result.get(
                    'yara_matched_rules', []
                ) or [],
                'yara_warning_rules': layer1_result.get(
                    'yara_warnings', []
                ) or [],
                'heuristics_result': _extract_verdict_str(
                    layer1_result.get('stage3_heuristics', 'UNKNOWN')
                ),
                'virustotal_result': _extract_verdict_str(
                    layer1_result.get('stage4_virustotal', 'UNKNOWN')
                ),
            },
            
            'lsb_check': {
                'verdict': 'UNKNOWN',
                'executable_found': False,
                'signatures_found': [],
                'position': None,
            },
            
            'steganalysis': {
                'verdict': verdict,
                'ensemble_score': round(score, 4),
                'ensemble_score_pct': str(round(score*100, 1)) + '%',
                'file_type_analysed': file_type,
                'model_results': {},
                'statistical_results': {},
                'small_file_warning': layer2_result.get('small_file_warning', False),
                'image_size_check': layer2_result.get('image_size_check', {}),
                'statistical_reliable': layer2_result.get('statistical_reliable', True),
                'fusion_notes': layer2_result.get(
                    'fusion_notes', []
                ) or [],
            },
            
            'payload_extraction': {
                'attempted': layer3_result is not None,
                'extracted': False,
                'payload_size_bytes': 0,
                'payload_type': 'Unknown',
                'payload_entropy': 0.0,
                'payload_class': 'Unknown',
                'is_executable': False,
                'is_archive': False,
                'method_used': 'None',
                'adaptive_analysis': {},
            },
            
            'confidence_calibration': {
                'available': calibration is not None,
            },
            
            'report_artifacts': {
                'technical_report': None,
                'summary_report': None,
            },
            
            'chain_of_custody': {
                'session_id': session_id,
                'note': (
                    'Full chain of custody is recorded in '
                    'the Shadow-Trace chain of custody database. '
                    'See the technical forensic report for '
                    'the complete audit trail.'
                ),
            },
        }

        lsb_data = layer2_result.get(
            'lsb_check_result',
            layer2_result.get('lsb_result', None)
        )
        if lsb_data:
            bundle['lsb_check'] = {
                'verdict': lsb_data.get('verdict', 'UNKNOWN'),
                'executable_found': (
                    lsb_data.get('verdict') == 'EXECUTABLE_FOUND'
                ),
                'signatures_found': lsb_data.get(
                    'signatures_found', []
                ) or [],
                'position': lsb_data.get('position', None),
                'auto_escalated': lsb_data.get(
                    'auto_escalate', False
                ),
            }

        if file_type == 'IMAGE':
            t1a = layer2_result.get('tier1a_yedroudj', {}) or {}
            t1b = layer2_result.get('tier1b_alaska2', {}) or {}
            t3 = layer2_result.get('tier3_statistical', {}) or {}
            
            bundle['steganalysis']['model_results'] = {
                'yedroudj_net_v3': {
                    'score': round(
                        t1a.get('score', 0.0) or 0.0, 4
                    ),
                    'verdict': t1a.get('verdict', 'UNKNOWN'),
                    'model_type': 'Neural Network',
                    'detects': 'Spatial LSB steganography',
                },
                'alaska2_efficientnet': {
                    'score': round(
                        t1b.get('score', 0.0) or 0.0, 4
                    ),
                    'verdict': t1b.get('verdict', 'UNKNOWN'),
                    'model_type': 'Neural Network',
                    'detects': 'Adaptive steganography (JMiPOD, JUNIWARD, UERD)',
                },
            }
            bundle['steganalysis']['statistical_results'] = {
                'chi_square': {
                    'score': round(
                        t3.get('chi_square', {}).get('score', 0.0) or 0.0, 4
                    ),
                    'verdict': t3.get('chi_square', {}).get(
                        'verdict', 'UNKNOWN'
                    ),
                },
                'rs_analysis': {
                    'score': round(
                        t3.get('rs_analysis', {}).get('score', 0.0) or 0.0, 4
                    ),
                    'verdict': t3.get('rs_analysis', {}).get(
                        'verdict', 'UNKNOWN'
                    ),
                },
            }

        elif file_type == 'DOCUMENT':
            bundle['steganalysis']['model_results'] = {
                'distilbert_hybrid': {
                    'neural_score': round(
                        layer2_result.get('neural_score', 0.0) or 0.0, 4
                    ),
                    'forensics_score': round(
                        layer2_result.get('forensics_score', 0.0) or 0.0, 4
                    ),
                    'fusion_method': layer2_result.get(
                        'fusion_method', 'unknown'
                    ),
                },
            }

        elif file_type == 'VIDEO':
            bundle['steganalysis']['model_results'] = {
                'video_steg_net': {
                    'score': round(score, 4),
                    'verdict': verdict,
                    'streams': 'Spatial + Temporal + DCT + Flow',
                },
            }

        if layer3_result:
            extraction = layer3_result.get(
                'extraction_results', {}
            ) or {}
            adaptive = layer3_result.get(
                'adaptive_analysis', {}
            ) or {}
            
            bundle['payload_extraction'] = {
                'attempted': True,
                'extracted': extraction.get('extracted', False),
                'payload_size_bytes': extraction.get(
                    'payload_size_bytes', 0
                ) or 0,
                'payload_type': extraction.get(
                    'payload_type', 'Unknown'
                ),
                'payload_entropy': round(
                    extraction.get('payload_entropy', 0.0) or 0.0, 4
                ),
                'payload_class': extraction.get(
                    'payload_class', 'Unknown'
                ),
                'is_executable': extraction.get(
                    'is_executable', False
                ),
                'is_archive': extraction.get(
                    'is_archive', False
                ),
                'method_used': extraction.get(
                    'method', 'multi_plane_lsb'
                ),
                'best_plane': extraction.get('best_plane', 0),
                'roi_used': extraction.get('roi_used', False),
                'adaptive_analysis': {
                    'detected': adaptive.get(
                        'adaptive_stego_detected', False
                    ),
                    'estimated_payload_kb': adaptive.get(
                        'estimated_payload_kb', 0
                    ),
                    'modification_ratio': round(
                        adaptive.get('modification_ratio', 0.0) or 0.0, 4
                    ),
                    'note': adaptive.get('note', ''),
                },
            }

        if calibration:
            bundle['confidence_calibration'] = {
                'available': True,
                'score_pct': calibration.get('score_pct', ''),
                'confidence_band': calibration.get(
                    'confidence_band', {}
                ).get('band_name', ''),
                'confidence_label': calibration.get(
                    'confidence_band', {}
                ).get('label', ''),
                'overall_reliability': calibration.get(
                    'overall_reliability', ''
                ),
                'court_weight': calibration.get(
                    'court_weight', ''
                ),
                'uncertainty_count': calibration.get(
                    'uncertainty_count', 0
                ),
                'uncertainty_factors': [
                    f.get('factor', '')
                    for f in calibration.get(
                        'uncertainty_factors', []
                    )
                ],
                'recommended_action': calibration.get(
                    'recommended_action', ''
                ),
            }

        # Ingest CAPA capability analysis if available from layer3 or layer1
        capa_src = None
        if layer3_result and isinstance(layer3_result, dict):
            capa_src = layer3_result.get('capa_analysis')
        if not capa_src and layer1_result and isinstance(layer1_result, dict):
            capa_src = layer1_result.get('capa_analysis') or layer1_result.get('all_scan_results', {}).get('capa_analysis')

        if capa_src and isinstance(capa_src, dict):
            bundle['capa_analysis'] = {
                'status': capa_src.get('status', 'UNKNOWN'),
                'capability_count': capa_src.get('capability_count', 0),
                'tactics': capa_src.get('attack_tactics', []),
                'techniques': capa_src.get('attack_techniques', []),
                'risk_indicators': capa_src.get('risk_indicators', []),
                'capa_version': capa_src.get('capa_version'),
                'rules_version': capa_src.get('rules_version'),
            }

        if technical_report_path and Path(technical_report_path).exists():
            tech_path = Path(technical_report_path)
            bundle['report_artifacts']['technical_report'] = {
                'filename': tech_path.name,
                'path': str(tech_path),
                'size_bytes': tech_path.stat().st_size,
                'seal_file': tech_path.stem + '.seal.json',
            }

        if summary_report_path and Path(summary_report_path).exists():
            sum_path = Path(summary_report_path)
            bundle['report_artifacts']['summary_report'] = {
                'filename': sum_path.name,
                'path': str(sum_path),
                'size_bytes': sum_path.stat().st_size,
                'seal_file': sum_path.stem + '.seal.json',
            }

        bundle_json = json.dumps(bundle, indent=2,
            default=str)
        bundle_hash = hashlib.sha3_512(
            bundle_json.encode('utf-8')
        ).hexdigest()
        bundle['bundle_integrity'] = {
            'sha3_512': bundle_hash,
            'computed_at': datetime.now(timezone.utc).isoformat(),
            'note': (
                'This hash covers all bundle content above. '
                'Recompute to verify bundle integrity.'
            ),
        }
        
        return bundle
    except Exception as e:
        print('[EXPORT] Error building bundle: ' + str(e))
        return {'error': str(e)}


def export_json_bundle(
    bundle: Dict,
    output_dir: Path,
    filename_stem: str,
) -> Dict:
    try:
        json_path = output_dir / (filename_stem + '_evidence.json')
        
        bundle_json = json.dumps(
            bundle, indent=2, default=str
        )
        
        with open(json_path, 'w', encoding='utf-8') as f:
            f.write(bundle_json)
            
        file_size = json_path.stat().st_size
        print('[EXPORT] JSON bundle: '
              + str(json_path.name)
              + ' (' + str(file_size) + ' bytes)')
              
        return {
            'success': True,
            'path': str(json_path),
            'size_bytes': file_size,
            'format': 'JSON',
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def export_csv_summary(
    bundle: Dict,
    output_dir: Path,
    filename_stem: str,
) -> Dict:
    try:
        csv_path = output_dir / (filename_stem + '_summary.csv')
        
        rows = []
        rows.append(['Category', 'Field', 'Value', 'Notes'])
        
        fi = bundle.get('file_identity', {})
        rows.append(['File Identity', 'Filename', fi.get('filename',''), ''])
        rows.append(['File Identity', 'File Type', fi.get('file_type',''), ''])
        rows.append(['File Identity', 'File Size (KB)', fi.get('file_size_kb',''), ''])
        rows.append(['File Identity', 'MIME Type', fi.get('mime_type',''), ''])
        rows.append(['File Identity', 'SHA3-512 Hash', str(fi.get('sha3_512_hash',''))[:32] + '...', 'Truncated for display'])
        rows.append(['File Identity', 'Hash Verified', fi.get('hash_verified',''), ''])
        
        ms = bundle.get('malware_screening', {})
        rows.append(['Malware Screening', 'Overall Verdict', ms.get('overall_verdict',''), ''])
        rows.append(['Malware Screening', 'ClamAV', ms.get('clamav_result',''), ''])
        rows.append(['Malware Screening', 'YARA', ms.get('yara_verdict',''), str(len(ms.get('yara_threat_rules',[]))) + ' threat rules matched'])
        rows.append(['Malware Screening', 'Heuristics', ms.get('heuristics_result',''), ''])
        rows.append(['Malware Screening', 'VirusTotal', ms.get('virustotal_result',''), ''])
        
        lsb = bundle.get('lsb_check', {})
        rows.append(['LSB Check', 'Verdict', lsb.get('verdict',''), ''])
        rows.append(['LSB Check', 'Executable Found', str(lsb.get('executable_found',False)), str(lsb.get('signatures_found',[]))])
        
        steg = bundle.get('steganalysis', {})
        rows.append(['Steganalysis', 'Overall Verdict', steg.get('verdict',''), ''])
        rows.append(['Steganalysis', 'Ensemble Score', steg.get('ensemble_score_pct',''), ''])
        
        for model_name, model_data in steg.get('model_results',{}).items():
            rows.append(['Steganalysis Model', model_name,
                str(model_data.get('verdict','')),
                'Score: ' + str(model_data.get('score',''))])
        
        for stat_name, stat_data in steg.get('statistical_results',{}).items():
            rows.append(['Statistical Test', stat_name,
                str(stat_data.get('verdict','')),
                'Score: ' + str(stat_data.get('score',''))])
        
        pe = bundle.get('payload_extraction', {})
        if pe.get('attempted'):
            rows.append(['Payload', 'Extracted', str(pe.get('extracted',False)), ''])
            rows.append(['Payload', 'Size (bytes)', str(pe.get('payload_size_bytes',0)), ''])
            rows.append(['Payload', 'Type', pe.get('payload_type',''), ''])
            rows.append(['Payload', 'Entropy', str(pe.get('payload_entropy',0)), pe.get('payload_class','')])
            rows.append(['Payload', 'Is Executable', str(pe.get('is_executable',False)), ''])
            
            adaptive = pe.get('adaptive_analysis', {})
            if adaptive:
                rows.append(['Adaptive Stego', 'Detected', str(adaptive.get('detected',False)), ''])
                rows.append(['Adaptive Stego', 'Estimated Size (KB)', str(adaptive.get('estimated_payload_kb',0)), ''])

        capa = bundle.get('capa_analysis', {})
        if capa:
            rows.append(['CAPA Analysis', 'Status', capa.get('status', ''), ''])
            rows.append(['CAPA Analysis', 'Capability Count', str(capa.get('capability_count', 0)), ''])
            rows.append(['CAPA Analysis', 'Tactics', ', '.join(capa.get('tactics', [])), ''])
            rows.append(['CAPA Analysis', 'Techniques', ', '.join(capa.get('techniques', [])), ''])
            risk_summary = '; '.join(f"[{r.get('severity')}] {r.get('name')}" for r in capa.get('risk_indicators', []))
            rows.append(['CAPA Analysis', 'Risk Indicators', risk_summary, ''])
            rows.append(['CAPA Analysis', 'Rules Version', str(capa.get('rules_version', '')), str(capa.get('capa_version', ''))])
        
        cal = bundle.get('confidence_calibration', {})
        if cal.get('available'):
            rows.append(['Calibration', 'Confidence Band', cal.get('confidence_label',''), ''])
            rows.append(['Calibration', 'Reliability', cal.get('overall_reliability',''), ''])
            rows.append(['Calibration', 'Court Weight', cal.get('court_weight',''), ''])
            rows.append(['Calibration', 'Uncertainty Factors', str(cal.get('uncertainty_count',0)), ', '.join(cal.get('uncertainty_factors',[]))])
            rows.append(['Calibration', 'Recommended Action', cal.get('recommended_action',''), ''])
        
        cm = bundle.get('case_metadata', {})
        rows.append(['Case', 'Session ID', str(cm.get('session_id',''))[:16] + '...', ''])
        rows.append(['Case', 'Examiner', cm.get('examiner_name',''), cm.get('examiner_id','')])
        rows.append(['Case', 'Organisation', cm.get('organisation',''), ''])
        rows.append(['Case', 'Examination Date', cm.get('examination_date',''), cm.get('examination_time','')])

        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerows(rows)
            
        file_size = csv_path.stat().st_size
        print('[EXPORT] CSV summary: '
              + str(csv_path.name)
              + ' (' + str(file_size) + ' bytes)')

        return {
            'success': True,
            'path': str(csv_path),
            'size_bytes': file_size,
            'format': 'CSV',
            'row_count': len(rows),
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def export_zip_package(
    output_dir: Path,
    filename_stem: str,
    technical_report_path: str = None,
    summary_report_path: str = None,
    json_path: str = None,
    csv_path: str = None,
    heatmap_paths: list = None,
) -> Dict:
    try:
        zip_path = output_dir / (
            filename_stem + '_evidence_package.zip'
        )
        
        manifest = {
            'package_type': 'SHADOW_TRACE_EVIDENCE_PACKAGE',
            'created_at': datetime.now(timezone.utc).isoformat(),
            'shadow_trace_version': '1.0.0',
            'examiner': os.environ.get('EXAMINER_NAME', 'Unknown'),
            'contents': [],
        }
        
        files_to_add = []
        
        if technical_report_path and Path(technical_report_path).exists():
            files_to_add.append((
                technical_report_path,
                'reports/' + Path(technical_report_path).name,
                'Technical forensic report (detailed)'
            ))
            seal_path = Path(technical_report_path).with_suffix('.seal.json')
            if seal_path.exists():
                files_to_add.append((
                    str(seal_path),
                    'reports/' + seal_path.name,
                    'Technical report cryptographic seal'
                ))
        
        if summary_report_path and Path(summary_report_path).exists():
            files_to_add.append((
                summary_report_path,
                'reports/' + Path(summary_report_path).name,
                'Plain English summary report'
            ))
            sum_seal = Path(summary_report_path).with_suffix('.seal.json')
            if sum_seal.exists():
                files_to_add.append((
                    str(sum_seal),
                    'reports/' + sum_seal.name,
                    'Summary report cryptographic seal'
                ))
        
        if json_path and Path(json_path).exists():
            files_to_add.append((
                json_path,
                'evidence/' + Path(json_path).name,
                'Machine-readable evidence bundle'
            ))
        
        if csv_path and Path(csv_path).exists():
            files_to_add.append((
                csv_path,
                'evidence/' + Path(csv_path).name,
                'CSV summary of all findings'
            ))
        
        if heatmap_paths:
            for hp in heatmap_paths:
                if hp and Path(hp).exists():
                    files_to_add.append((
                        hp,
                        'visualisations/' + Path(hp).name,
                        'Analysis visualisation'
                    ))

        for src_path, arc_name, description in files_to_add:
            p = Path(src_path)
            manifest['contents'].append({
                'filename': arc_name,
                'description': description,
                'size_bytes': p.stat().st_size,
                'sha3_512': hashlib.sha3_512(
                    p.read_bytes()
                ).hexdigest(),
            })

        with zipfile.ZipFile(
            str(zip_path), 'w',
            zipfile.ZIP_DEFLATED
        ) as zf:
            manifest_json = json.dumps(
                manifest, indent=2, default=str
            )
            zf.writestr(
                'MANIFEST.json', manifest_json
            )
            
            readme_text = (
                'SHADOW-TRACE EVIDENCE PACKAGE\n'
                '==============================\n\n'
                'This package contains digital forensic\n'
                'evidence produced by Shadow-Trace v1.0.0.\n\n'
                'Contents:\n'
                '  reports/         Forensic PDF reports\n'
                '  evidence/        Machine-readable data\n'
                '  visualisations/  Analysis heatmaps\n'
                '  MANIFEST.json    Package manifest\n\n'
                'To verify report integrity:\n'
                '  Compare .seal.json HMAC values against\n'
                '  the corresponding PDF file bytes.\n\n'
                'Generated: '
                + datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                + '\n'
                'Examiner: '
                + os.environ.get('EXAMINER_NAME', 'Unknown')
            )
            zf.writestr('README.txt', readme_text)
            
            for src_path, arc_name, _ in files_to_add:
                zf.write(src_path, arc_name)

        zip_size = zip_path.stat().st_size
        print('[EXPORT] ZIP package: '
              + str(zip_path.name)
              + ' (' + str(zip_size) + ' bytes)')

        return {
            'success': True,
            'path': str(zip_path),
            'size_bytes': zip_size,
            'file_count': len(files_to_add) + 2,
            'format': 'ZIP',
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def run_full_export(
    filepath: str,
    session_id: str,
    sha3_hash: str,
    layer1_result: Dict,
    layer2_result: Dict,
    layer3_result: Dict,
    layer4_xai_result: Dict,
    calibration: Dict = None,
    technical_report_path: str = None,
    summary_report_path: str = None,
) -> Dict:
    try:
        verdict = layer2_result.get('verdict', 'CLEAN')
        if verdict == 'STEGO_DETECTED':
            subfolder = 'stego'
        elif verdict == 'SUSPICIOUS':
            subfolder = 'suspicious'
        else:
            subfolder = 'clean'
        
        output_dir = config.BASE_DIR / 'reports' / subfolder
        output_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        stem = Path(filepath).stem
        filename_stem = timestamp_str + '_' + stem

        print('[EXPORT] Building evidence bundle...')
        bundle = build_evidence_bundle(
            filepath, session_id, sha3_hash,
            layer1_result, layer2_result, layer3_result,
            layer4_xai_result, calibration,
            technical_report_path, summary_report_path
        )

        print('[EXPORT] Exporting JSON bundle...')
        json_result = export_json_bundle(
            bundle, output_dir, filename_stem
        )

        print('[EXPORT] Exporting CSV summary...')
        csv_result = export_csv_summary(
            bundle, output_dir, filename_stem
        )

        heatmap_paths = []
        if layer4_xai_result:
            lsb_viz = layer4_xai_result.get(
                'lsb_visualization', {}
            ) or {}
            if lsb_viz.get('heatmap_path'):
                heatmap_paths.append(
                    lsb_viz['heatmap_path']
                )
            
            grad_cam = layer4_xai_result.get(
                'grad_cam', {}
            ) or {}
            if grad_cam.get('heatmap_path'):
                heatmap_paths.append(
                    grad_cam['heatmap_path']
                )
            
            token_map = layer4_xai_result.get(
                'lsb_visualization', {}
            ) or {}
            map_path = token_map.get('map_path')
            if map_path and map_path not in heatmap_paths:
                heatmap_paths.append(map_path)

        print('[EXPORT] Building ZIP package...')
        zip_result = export_zip_package(
            output_dir=output_dir,
            filename_stem=filename_stem,
            technical_report_path=technical_report_path,
            summary_report_path=summary_report_path,
            json_path=json_result.get('path') if json_result.get('success') else None,
            csv_path=csv_result.get('path') if csv_result.get('success') else None,
            heatmap_paths=heatmap_paths,
        )

        print('[EXPORT] Export complete:')
        print('[EXPORT]   JSON: ' + str(json_result.get('path','')))
        print('[EXPORT]   CSV:  ' + str(csv_result.get('path','')))
        print('[EXPORT]   ZIP:  ' + str(zip_result.get('path','')))

        return {
            'success': True,
            'output_dir': str(output_dir),
            'json_bundle': json_result,
            'csv_summary': csv_result,
            'zip_package': zip_result,
            'bundle': bundle,
            'error': None,
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

if __name__ == '__main__':
    print('=== EVIDENCE EXPORT TEST ===')
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
        'session_id': 'TEST_EXPORT_001',
        'filepath': str(Path.home() / 'Downloads' / 'test_image.jpg'),
        'sha3_hash': 'abc123def456' * 8
    }

    mock_layer2_stego = {
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
        layer2_result=mock_layer2_stego,
        layer3_result=mock_layer3,
        file_type='IMAGE',
    )

    print('Building evidence bundle...')
    bundle = build_evidence_bundle(
        filepath=str(Path.home() / 'Downloads' / 'test_image.jpg'),
        session_id='TEST_EXPORT_001',
        sha3_hash='abc123' * 20,
        layer1_result=mock_layer1,
        layer2_result=mock_layer2_stego,
        layer3_result=mock_layer3,
        layer4_xai_result={},
        calibration=calibration,
    )
    print('Bundle keys: ' + str(list(bundle.keys())))
    print()

    from pathlib import Path
    output_dir = Path(config.BASE_DIR) / 'reports' / 'stego'
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = 'test_export'

    print('Exporting JSON...')
    j = export_json_bundle(bundle, output_dir, stem)
    print('  Success: ' + str(j.get('success')))
    print('  Size: ' + str(j.get('size_bytes')) + ' bytes')

    print()
    print('Exporting CSV...')
    c = export_csv_summary(bundle, output_dir, stem)
    print('  Success: ' + str(c.get('success')))
    print('  Rows: ' + str(c.get('row_count')))
    print('  Size: ' + str(c.get('size_bytes')) + ' bytes')

    print()
    print('Exporting ZIP...')
    z = export_zip_package(
        output_dir=output_dir,
        filename_stem=stem,
        json_path=j.get('path'),
        csv_path=c.get('path'),
    )
    print('  Success: ' + str(z.get('success')))
    print('  Files in ZIP: ' + str(z.get('file_count')))
    print('  Size: ' + str(z.get('size_bytes')) + ' bytes')

    print()
    print('Running full export pipeline...')
    result = run_full_export(
        filepath=str(Path.home() / 'Downloads' / 'test_image.jpg'),
        session_id='TEST_EXPORT_001',
        sha3_hash='abc123' * 20,
        layer1_result=mock_layer1,
        layer2_result=mock_layer2_stego,
        layer3_result=mock_layer3,
        layer4_xai_result={},
        calibration=calibration,
    )
    print('Full export success: ' + str(result.get('success')))
    if result.get('success'):
        print('  JSON: ' + str(Path(result['json_bundle']['path']).name))
        print('  CSV:  ' + str(Path(result['csv_summary']['path']).name))
        print('  ZIP:  ' + str(Path(result['zip_package']['path']).name))
        print()
        print('PASS: All exports generated')
    else:
        print('FAIL: ' + str(result.get('error')))

    print()
    print('=== TEST COMPLETE ===')
