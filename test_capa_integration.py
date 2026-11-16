"""
Integration Test Suite for CAPA Capability Analysis in Shadow-Trace
Tests pipeline hooks, schema validation, quarantine report generation,
graceful unavailability fallback, and layer0_monitor module integrity.
"""

import os
import sys
import shutil
import tempfile
import unittest
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import utils
from capa_analyzer import (
    CAPA_AVAILABLE,
    analyze_with_capa,
    capa_to_classifier_hint,
    get_capa_version,
    get_rules_dir,
    get_rules_version,
)
from malware_classifier import classify_malware


class TestCapaIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp(prefix="shadow_trace_capa_test_")
        cls.notepad_orig = Path(os.environ.get("WINDIR", "C:\\Windows")) / "System32" / "notepad.exe"
        if not cls.notepad_orig.exists():
            cls.notepad_orig = Path(sys.executable)  # Fallback to python.exe if notepad not found

        cls.sample_pe = Path(cls.temp_dir) / "sample_test.exe"
        shutil.copy2(cls.notepad_orig, cls.sample_pe)

        with open(cls.sample_pe, "rb") as f:
            cls.sample_pe_bytes = f.read()

        cls.session_id = "test_session_capa_12345"
        cls.sha3_hash = "a" * 128

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.temp_dir, ignore_errors=True)

    def test_01_hook_a_layer3_payload_extraction(self):
        """Test Hook A: Executable payload extraction triggers CAPA analysis and attaches capa_analysis."""
        from layer3_extraction import run_extraction

        # Create a mock carrier file with executable payload bytes
        carrier_path = Path(self.temp_dir) / "carrier_image.png"
        carrier_path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)

        mock_layer2_result = {
            "verdict": "STEGO_DETECTED",
            "score": 0.95,
            "file_type": "IMAGE"
        }

        # Test extraction where payload contains PE bytes
        # We simulate extraction by invoking run_extraction on our carrier
        # and supplying mock PE payload in extraction results
        import layer3_extraction
        orig_extract_image = layer3_extraction.extract_image_payload

        def mock_extract_image(filepath, roi_coords=None):
            return {
                "extracted": True,
                "method": "multi_plane_lsb",
                "best_plane": 0,
                "plane_results": {},
                "payload_type": "Windows Executable",
                "payload_entropy": 7.45,
                "payload_class": "COMPRESSED",
                "is_executable": True,
                "is_archive": False,
                "payload_size_bytes": len(self.sample_pe_bytes),
                "payload_bytes": self.sample_pe_bytes,
                "text_preview": None,
                "first_32_bytes_hex": self.sample_pe_bytes[:32].hex(),
                "roi_used": False,
                "image_dimensions": (100, 100),
                "total_pixels": 10000,
                "error": None
            }

        try:
            layer3_extraction.extract_image_payload = mock_extract_image
            layer3_res = run_extraction(
                filepath=str(carrier_path),
                session_id=self.session_id,
                sha3_hash=self.sha3_hash,
                layer2_result=mock_layer2_result,
                roi_coords=None
            )

            # Assertions for Hook A
            self.assertIn("capa_analysis", layer3_res, "Hook A must attach capa_analysis to layer3_result")
            capa = layer3_res["capa_analysis"]
            self.assertIsNotNone(capa, "capa_analysis must not be None")
            self.assertEqual(capa.get("status"), "COMPLETE", f"Expected COMPLETE status, got {capa.get('status')}")
            self.assertGreater(capa.get("capability_count", 0), 0, "Expected at least 1 capability detected")
            self.__class__.cached_capa_res = capa
            print(f"[TEST 1A PASSED] Hook A executed: status={capa.get('status')}, count={capa.get('capability_count')}")

        finally:
            layer3_extraction.extract_image_payload = orig_extract_image

    def test_02_hook_b_layer1_malware_threat(self):
        """Test Hook B: Layer 1 THREAT verdict on PE/ELF executes CAPA on sandbox copy."""
        from layer1_malware import _execute_capa_hook_b

        capa_res = _execute_capa_hook_b(
            scan_target=str(self.sample_pe),
            q_path=None,
            session_id=self.session_id,
            sha3_hash=self.sha3_hash
        )

        self.assertIsNotNone(capa_res, "Hook B must return a capa_res dict for PE target")
        self.assertEqual(capa_res.get("status"), "COMPLETE")
        self.assertGreater(capa_res.get("capability_count", 0), 0)
        self.assertIn("attack_tactics", capa_res)
        self.assertIn("attack_techniques", capa_res)
        self.assertIn("risk_indicators", capa_res)
        self.__class__.cached_capa_res = capa_res
        print(f"[TEST 1B PASSED] Hook B executed: status={capa_res.get('status')}, count={capa_res.get('capability_count')}")

    def test_03_capa_schema_and_malware_classifier(self):
        """Test Schema assertions and verify classify_malware receives CAPA hints."""
        capa_res = getattr(self.__class__, 'cached_capa_res', None) or analyze_with_capa(str(self.sample_pe), timeout_seconds=120)
        self.assertEqual(capa_res.get("status"), "COMPLETE")

        required_keys = [
            "status", "file_format", "architecture", "capabilities",
            "attack_tactics", "attack_techniques", "capability_count",
            "risk_indicators", "rules_version", "capa_version",
            "plain_english", "limitations"
        ]
        for k in required_keys:
            self.assertIn(k, capa_res, f"Key '{k}' missing from capa_res")

        # Test classify_malware incorporating CAPA
        mock_l1 = {
            "verdict": "THREAT",
            "detecting_engine": "YARA",
            "threat_name": "Win.Trojan.Agent",
            "threat_category": "Trojan",
            "stage3_clamav": {"verdict": "THREAT", "threat_name": "Win.Trojan.Agent"},
            "capa_analysis": capa_res
        }
        classification = classify_malware(mock_l1, capa_result=capa_res)
        self.assertTrue(classification.get("classified"))
        self.assertEqual(classification.get("primary_category"), "trojan")

        # Confirm CAPA hints were collected
        sources = [s.get("source") for s in classification.get("sources", [])]
        self.assertIn("CAPA", sources, "CAPA must be registered as an independent classification source")
        print(f"[TEST 2 PASSED] Schema verified. Classification sources: {sources}")

    def test_04_quarantine_report_with_capa(self):
        """Test quarantine report generation including CAPA detection findings."""
        from quarantine_report import generate_quarantine_report

        capa_res = getattr(self.__class__, 'cached_capa_res', None) or analyze_with_capa(str(self.sample_pe), timeout_seconds=120)

        mock_layer1_result = {
            "verdict": "THREAT",
            "detecting_stage": "STAGE3_LOCAL",
            "detecting_engine": "ClamAV",
            "threat_name": "Win.Test.Trojan-1234",
            "threat_family": "Agent",
            "threat_type": "Trojan",
            "threat_category": "Malware",
            "severity": "CRITICAL",
            "quarantine_path": str(self.sample_pe),
            "session_id": self.session_id,
            "capa_analysis": capa_res,
            "all_scan_results": {
                "stage3_clamav": {"verdict": "THREAT", "threat_name": "Win.Test.Trojan-1234"},
                "stage3_yara": {"verdict": "CLEAN"},
                "capa_analysis": capa_res
            }
        }

        q_report = generate_quarantine_report(
            filepath=str(self.sample_pe),
            session_id=self.session_id,
            layer1_result=mock_layer1_result,
            sha3_hash=self.sha3_hash,
            quarantine_path=str(self.sample_pe),
            quarantine_reason="Test CAPA Quarantine Generation"
        )

        self.assertIsNotNone(q_report)
        pdf_path = q_report.get("report_path") or q_report.get("pdf_path")
        self.assertTrue(pdf_path and Path(pdf_path).exists(), f"PDF was not generated at {pdf_path}")
        self.assertGreater(Path(pdf_path).stat().st_size, 1000, "Quarantine report PDF must be non-empty")
        print(f"[TEST 3 PASSED] Quarantine report generated successfully at: {Path(pdf_path).name}")

    def test_05_capa_unavailable_monkeypatching(self):
        """Confirm behavior when CAPA is unavailable via monkeypatching."""
        import capa_analyzer
        orig_avail = capa_analyzer.CAPA_AVAILABLE

        try:
            capa_analyzer.CAPA_AVAILABLE = False
            fallback_res = capa_analyzer.analyze_with_capa(str(self.sample_pe))
            self.assertEqual(fallback_res.get("status"), "UNAVAILABLE")
            self.assertEqual(fallback_res.get("capability_count"), 0)
            self.assertIn("not available", fallback_res.get("plain_english", ""))

            # Test Hook B handles unavailable cleanly
            from layer1_malware import _execute_capa_hook_b
            res_b = _execute_capa_hook_b(str(self.sample_pe), None, self.session_id, self.sha3_hash)
            self.assertIsNotNone(res_b)
            self.assertEqual(res_b.get("status"), "UNAVAILABLE")

            # Verify quarantine report handles unavailable CAPA without raising
            from quarantine_report import generate_quarantine_report
            mock_l1 = {
                "verdict": "THREAT",
                "detecting_engine": "ClamAV",
                "threat_name": "TestThreat",
                "capa_analysis": fallback_res
            }
            rep = generate_quarantine_report(
                filepath=str(self.sample_pe),
                session_id=self.session_id,
                layer1_result=mock_l1,
                sha3_hash=self.sha3_hash,
                quarantine_path=str(self.sample_pe)
            )
            self.assertTrue(rep.get("success", False) or "report_path" in rep or "pdf_path" in rep)
            print("[TEST 4 PASSED] Graceful degradation confirmed when CAPA_AVAILABLE is False.")

        finally:
            capa_analyzer.CAPA_AVAILABLE = orig_avail

    def test_06_layer0_monitor_import_and_integrity(self):
        """Confirm layer0_monitor imports cleanly without side-effects or errors."""
        import layer0_monitor
        self.assertTrue(hasattr(layer0_monitor, "_dispatch_scan") or hasattr(layer0_monitor, "_process_new_file"))
        self.assertTrue(hasattr(layer0_monitor, "_scan_worker_loop"))
        self.assertTrue(hasattr(layer0_monitor, "run_extraction"))
        print("[TEST 5 PASSED] layer0_monitor imported successfully with all entry points intact.")


if __name__ == "__main__":
    suite = unittest.TestLoader().loadTestsFromTestCase(TestCapaIntegration)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
