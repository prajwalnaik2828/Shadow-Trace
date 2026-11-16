import os
import sys
from pathlib import Path
import config

def test_quarantine_report_and_hooks():
    print("=== TEST 1: Importing layer0_monitor ===")
    try:
        import layer0_monitor
        print("[PASS] layer0_monitor imported cleanly without errors.")
    except Exception as e:
        print(f"[FAIL] layer0_monitor import error: {e}")
        sys.exit(1)

    print("\n=== TEST 2: Calling generate_quarantine_report with mock data ===")
    from quarantine_report import generate_quarantine_report
    
    mock_filepath = "D:\\Shadow-trace\\scratch\\test_hook_sample.bin"
    os.makedirs(os.path.dirname(mock_filepath), exist_ok=True)
    with open(mock_filepath, "wb") as f:
        f.write(b"MOCK_MALWARE_PAYLOAD_TEST_HOOK_BYTES_12345")

    mock_layer1_result = {
        'verdict': 'THREAT',
        'detecting_stage': 'STAGE3_LOCAL',
        'detecting_engine': 'ClamAV',
        'threat_name': 'Win.Test.EICAR_Hk-55',
        'threat_family': 'TestFamily',
        'threat_type': 'Trojan',
        'threat_category': 'Ransomware',
        'severity': 'HIGH',
        'stage3_clamav': {
            'verdict': 'THREAT',
            'threat_name': 'Win.Test.EICAR_Hk-55'
        },
        'stage3_yara': {
            'verdict': 'THREAT',
            'threat_name': 'ransomware_wannacry_payload',
            'matched_rules': ['ransomware_wannacry_payload']
        },
        'stage4_virustotal': {
            'verdict': 'THREAT',
            'positives': 45,
            'total': 72,
            'most_common_threat_name': 'Trojan.TestSample'
        }
    }

    mock_multi_hash = {
        'md5': '5d41402abc4b2a76b9719d911017c592',
        'sha256': '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
        'sha3_512': 'a69f73ccd356d6e97593972f516447f8140bc1d3f0cb619e0cd5dc5d52d4e79421b33eccd32d95e03173d104ddd8a08eec91e5a95d00b717f84e345be4b56447',
        'file_size_bytes': 41,
        'algorithm_note': 'All three hashes computed simultaneously in a single streaming pass.'
    }

    res = generate_quarantine_report(
        filepath=mock_filepath,
        session_id="HOOK_TEST_SESSION_001",
        layer1_result=mock_layer1_result,
        multi_hash=mock_multi_hash,
        sha3_hash=mock_multi_hash['sha3_512'],
        quarantine_path=mock_filepath,
        quarantine_reason="ClamAV and YARA detected confirmed malware test signatures.",
        correlation_data={'correlation_risk': 'NONE', 'total_flags': 0, 'correlation_flags': []},
        hash_reconfirmation=None
    )

    print("Generation result:", res)
    assert res['success'] is True, f"Report generation failed: {res.get('error')}"
    
    pdf_path = Path(res['report_path'])
    seal_path = Path(res['seal_path'])

    assert pdf_path.exists(), f"PDF does not exist: {pdf_path}"
    assert seal_path.exists(), f"Seal JSON does not exist: {seal_path}"
    assert pdf_path.parent.name == 'quarantine', f"PDF not in quarantine dir: {pdf_path.parent}"
    assert pdf_path.stat().st_size > 0, "PDF file is empty"
    assert seal_path.stat().st_size > 0, "Seal file is empty"

    print(f"\n[PASS] Quarantine report successfully generated and verified:")
    print(f"  PDF:  {pdf_path}")
    print(f"  Seal: {seal_path}")
    print("=== ALL HOOK TESTS PASSED ===")

if __name__ == '__main__':
    test_quarantine_report_and_hooks()
