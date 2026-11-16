import os
import sys
import shutil
import hashlib
import threading
import time
import uuid
from pathlib import Path
from typing import Dict, Any

import config
import utils
import chain_of_custody as coc
import recovery_database as rdb

def scan_file_manually(filepath: str, progress_callback=None) -> Dict[str, Any]:
    filepath = Path(filepath)
    if not filepath.exists():
        return {'error': 'File not found: ' + str(filepath)}
    
    sandbox_path = None
    try:
        print('[MANUAL] Manual scan started: ' + filepath.name)
        print('[MANUAL] File size: ' + str(filepath.stat().st_size) + ' bytes')
        
        multi_hash = utils.compute_multi_hash(str(filepath))
        sha3_hash = multi_hash.get('sha3_512') if multi_hash.get('success') else utils.generate_sha3_hash(str(filepath))
        if not sha3_hash:
            return {'error': 'Failed to compute file hash'}
        print('[MANUAL] Hash: ' + sha3_hash[:16] + '...')
        
        if progress_callback:
            progress_callback('Creating sandbox copy...')
            
        sandbox_dir = config.BASE_DIR / 'sandbox'
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        timestamp = int(time.time())
        sandbox_name = f'manual_{timestamp}_{filepath.name}'
        sandbox_path = sandbox_dir / sandbox_name
        shutil.copy2(str(filepath), str(sandbox_path))
        print('[MANUAL] Sandbox copy created: ' + sandbox_name)

        session_id = coc.open_session(str(filepath), sha3_hash, 'MANUAL_SCAN')
        if not session_id:
            return {'error': 'Failed to open chain of custody session'}
        print('[MANUAL] Session: ' + session_id[:8] + '...')
        
        rdb.register_file(str(filepath), sha3_hash, 'LAYER_0_START')
        
        if progress_callback:
            progress_callback('Running malware scan...')
        print('[MANUAL] Running Layer 1 malware scan...')
        import layer1_malware
        layer1_result = layer1_malware.run_malware_screening(str(filepath), session_id, sha3_hash)
        layer1_verdict = layer1_result.get('verdict', 'CLEAN')
        print('[MANUAL] Layer 1 verdict: ' + layer1_verdict)
        
        if layer1_verdict == 'THREAT':
            print('[MANUAL] THREAT detected in Layer 1')
            quarantine_dir = config.BASE_DIR / 'quarantine'
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            ts = time.strftime('%Y%m%d_%H%M%S')
            q_path = quarantine_dir / (ts + '_' + filepath.name)
            shutil.copy2(str(filepath), str(q_path))
            if sandbox_path and sandbox_path.exists():
                sandbox_path.unlink(missing_ok=True)
            rdb.mark_complete(str(filepath))
            return {
                'verdict': 'THREAT',
                'layer1_result': layer1_result,
                'quarantined': True,
                'quarantine_path': str(q_path),
                'session_id': session_id,
            }
            
        if progress_callback:
            progress_callback('Running LSB check...')
        print('[MANUAL] Running Layer 1.5 LSB check...')
        import layer1_5_lsb_check
        lsb_result = layer1_5_lsb_check.run_lsb_executable_check(str(filepath), session_id, sha3_hash)
        lsb_verdict = lsb_result.get('verdict', 'CLEAN')
        auto_escalate = lsb_result.get('auto_escalate', False)
        print('[MANUAL] LSB verdict: ' + lsb_verdict)
        
        if progress_callback:
            progress_callback('Running steganalysis...')
        print('[MANUAL] Running Layer 2 steganalysis...')
        import layer2_steganalysis
        steg_result = layer2_steganalysis.run_steganalysis(str(filepath), session_id, sha3_hash)
        steg_verdict = steg_result.get('verdict', 'CLEAN')
        steg_score = steg_result.get('score', 0.0)
        print('[MANUAL] Layer 2 verdict: ' + steg_verdict)
        print('[MANUAL] Score: ' + str(steg_score))
        
        if progress_callback:
            progress_callback('Extracting payload...')
        print('[MANUAL] Running Layer 3 extraction...')
        try:
            import layer3_extraction
            layer3_result = layer3_extraction.run_extraction(
                filepath=str(filepath),
                session_id=session_id,
                sha3_hash=sha3_hash,
                layer2_result=steg_result
            )
            steg_result['layer3_extraction'] = layer3_result
        except Exception as e:
            print('[MANUAL] Layer 3 error: ' + str(e))
            steg_result['layer3_extraction'] = None
            
        if progress_callback:
            progress_callback('Generating report...')
        print('[MANUAL] Running Layer 4 report generation...')
        try:
            import layer4_explainability
            import layer4_report
            
            xai_result = layer4_explainability.run_explainability(
                filepath=str(filepath),
                layer2_result=steg_result,
                layer3_result=steg_result.get('layer3_extraction'),
                session_id=session_id
            )
            steg_result['layer4_xai'] = xai_result
            
            try:
                import chain_of_custody as coc_module
                coc_log = coc_module.get_session_log(session_id)
            except Exception:
                coc_log = None
                
            # Ensure file_hashes and hash_reconfirmation
            if 'multi_hash' in locals() and multi_hash and multi_hash.get('success'):
                steg_result['file_hashes'] = multi_hash

            try:
                final_hashes = utils.compute_multi_hash(str(filepath))
                init_sha3 = multi_hash.get('sha3_512') if 'multi_hash' in locals() and multi_hash else sha3_hash
                init_sha256 = multi_hash.get('sha256') if 'multi_hash' in locals() and multi_hash else None
                init_md5 = multi_hash.get('md5') if 'multi_hash' in locals() and multi_hash else None

                sha3_match = (final_hashes.get('sha3_512') == init_sha3) if init_sha3 else False
                sha256_match = (final_hashes.get('sha256') == init_sha256) if init_sha256 else True
                md5_match = (final_hashes.get('md5') == init_md5) if init_md5 else True
                all_match = sha3_match and (sha256_match if init_sha256 else True) and (md5_match if init_md5 else True)

                from datetime import datetime, timezone
                steg_result['hash_reconfirmation'] = {
                    'sha3_512_match': sha3_match,
                    'sha256_match': sha256_match,
                    'md5_match': md5_match,
                    'all_match': all_match,
                    'primary_confirmed': sha3_match,
                    'status': 'CONFIRMED' if all_match else 'FAILED',
                    'initial_sha3_512': init_sha3,
                    'initial_sha256': init_sha256,
                    'initial_md5': init_md5,
                    'final_sha3_512': final_hashes.get('sha3_512'),
                    'final_sha256': final_hashes.get('sha256'),
                    'final_md5': final_hashes.get('md5'),
                    'reconfirmed_at': datetime.now(timezone.utc).isoformat(),
                }
                coc.log_action(session_id, str(filepath), sha3_hash, 'INTEGRITY_RECONFIRMED', 'SUCCESS' if all_match else 'CRITICAL', str(steg_result['hash_reconfirmation']))
            except Exception as e:
                print('[MANUAL] Reconfirmation notice:', e)

            report_result = layer4_report.generate_forensic_report(
                filepath=str(filepath),
                session_id=session_id,
                sha3_hash=sha3_hash,
                layer1_result=layer1_result,
                layer2_result=steg_result,
                layer3_result=steg_result.get('layer3_extraction'),
                layer4_xai_result=xai_result,
                chain_of_custody_log=coc_log
            )
            steg_result['forensic_report'] = report_result
            
            if report_result.get('success'):
                print('[MANUAL] Report: ' + str(report_result.get('report_path', '')))
        except Exception as e:
            print('[MANUAL] Layer 4 error: ' + str(e))
            steg_result['forensic_report'] = {'error': str(e)}
            
        if sandbox_path and sandbox_path.exists():
            sandbox_path.unlink(missing_ok=True)
        rdb.mark_complete(str(filepath))
        
        print('[MANUAL] Scan complete: ' + steg_verdict)
        
        return {
            'verdict': steg_verdict,
            'score': steg_score,
            'session_id': session_id,
            'filepath': str(filepath),
            'filename': filepath.name,
            'layer1_result': layer1_result,
            'lsb_result': lsb_result,
            'layer2_result': steg_result,
            'layer3_result': steg_result.get('layer3_extraction'),
            'report_result': steg_result.get('forensic_report'),
            'error': None,
        }
    except Exception as e:
        print('[MANUAL] Unexpected error: ' + str(e))
        if sandbox_path and sandbox_path.exists():
            sandbox_path.unlink(missing_ok=True)
        return {'error': str(e)}

def scan_file_in_thread(filepath: str, on_complete=None, on_progress=None) -> threading.Thread:
    def run():
        result = scan_file_manually(filepath, progress_callback=on_progress)
        if on_complete:
            on_complete(result)

    thread = threading.Thread(
        target=run,
        name='ManualScan',
        daemon=True
    )
    thread.start()
    return thread

def open_file_picker():
    try:
        import tkinter as tk
        from tkinter import filedialog
        
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        
        filepath = filedialog.askopenfilename(
            title='Shadow-Trace: Select File to Scan',
            filetypes=[
                ('All Files', '*.*'),
                ('Image Files', '*.jpg *.jpeg *.png *.bmp *.gif *.webp'),
                ('Video Files', '*.mp4 *.avi *.mkv *.mov *.wmv'),
                ('Document Files', '*.pdf *.docx *.doc *.txt'),
            ],
            initialdir=str(Path.home() / 'Downloads')
        )
        root.destroy()
        return filepath if filepath else None
    except Exception as e:
        print('File picker error: ' + str(e))
        return None

if __name__ == '__main__':
    print('=== MANUAL SCAN TEST ===')
    print()
    
    filepath = open_file_picker()
    if not filepath:
        print('No file selected')
        sys.exit(0)
        
    print('Selected: ' + filepath)
    print('Starting scan...')
    print()
    
    def on_progress(message):
        print('[PROGRESS] ' + message)
        
    result = scan_file_manually(filepath, on_progress)
    
    print()
    print('=== SCAN RESULT ===')
    print('Verdict: ' + str(result.get('verdict')))
    print('Score: ' + str(result.get('score')))
    if result.get('report_result', {}).get('success'):
        print('Report: ' + str(result['report_result'].get('report_path')))
