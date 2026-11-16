# Shadow-Trace

> **Real-time digital forensic pipeline for simultaneous malware screening and multimodal steganography detection.**

[![Python 3.10](https://img.shields.io/badge/python-3.10-blue.svg)](https://www.python.org/downloads/release/python-3100/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-lightgrey.svg)]()
[![Compliance](https://img.shields.io/badge/forensic%20standard-ISO%2FIEC%2027037-brightgreen.svg)]()
[![ACPO](https://img.shields.io/badge/guideline-ACPO%20Good%20Practice-green.svg)]()
[![License](https://img.shields.io/badge/license-Pending%20Selection-orange.svg)](#16-license)

---

## 1. What It Does

**Shadow-Trace** is an automated, real-time digital forensic pipeline engineered for rapid threat triage, malware classification, and multimodal steganalysis. Built to adhere strictly to **ISO/IEC 27037** and **ACPO Good Practice Guide** digital evidence standards, Shadow-Trace monitors filesystem ingresses (such as user downloads, network shares, and external media), evaluates artifacts through a tiered six-layer inspection pipeline, cryptographically isolates malicious threats in an encrypted quarantine vault, and produces tamper-evident evidence packages complete with RFC 3161 digital timestamping and immutable chain of custody tracking.

---

## 2. Key Features

- **Six-Layer Forensic Pipeline:** Autonomous, tiered evaluation ranging from filesystem event ingress capture to explainable deep neural steganalysis and court-admissible dossier compilation.
- **Multimodal Steganalysis:** Simultaneous detection across image files (spatial domain LSB, DCT frequency domain), compressed video containers (inter-frame motion vector & DCT residue), and structured documents (PDF streams, DOCX macros, zero-width characters, homoglyphs).
- **Explainable AI (XAI) with Grad-CAM & SHAP:** Visual attribution heatmaps (Grad-CAM, SHAP token importance, and bitplane visualizers) that highlight suspect carrier regions, providing human examiners with defensible, transparent rationales.
- **Cryptographically Sealed Reports:** Automated PDF forensic dossiers sealed with **SHA3-512**, **HMAC-SHA3-512**, and **RFC 3161** trusted digital timestamping tokens (DigiCert / FreeTSA).
- **Tamper-Evident Chain of Custody (CoC):** Dedicated SQLite audit ledgers (`shadowtrace_coc.db`, `analyst_audit.db`) with HMAC chaining recording all file operations, examiner actions, and verification tokens.
- **Multi-Hash Verification & Post-Scan Reconfirmation:** Triple hashing with **SHA3-512**, **SHA-256**, and **BLAKE3** computed at initial file acquisition and re-verified post-pipeline to prove bit-level integrity was preserved throughout inspection.
- **Zone.Identifier & Ingress Provenance:** Ingress provenance extraction via NTFS Alternate Data Streams (`Zone.Identifier`), Windows DNS event logs, active TCP connection mapping, and optional Chromium browser extension URL capture.
- **Integrated Case Manager & Quarantine Vault:** Desktop analyst application built with **pywebview** and Tailwind CSS, featuring active monitoring toggles, case tagging, evidence packaging (ZIP export), and secure quarantine recovery.

---

## 3. Architecture

```
+-----------------------------------------------------------------------------------+
|                           SHADOW-TRACE PIPELINE ARCHITECTURE                     |
+-----------------------------------------------------------------------------------+

   [ INGRESS ARTIFACTS ]  (Downloads, Monitored Folders, Manual Uploads)
             |
             v
+-----------------------------------------------------------------------------------+
| LAYER 0: INGRESS CAPTURE & PROVENANCE                                             |
|  * Watchdog filesystem event monitors                                             |
|  * NTFS Alternate Data Streams (Zone.Identifier HostUrl / ReferrerUrl)            |
|  * Network event correlation (DNS logs, active TCP connections, browser ext)      |
|  * Immediate evidence hashing: SHA3-512, SHA-256, BLAKE3                         |
+-----------------------------------------------------------------------------------+
             |
             v
+-----------------------------------------------------------------------------------+
| LAYER 1: MULTI-ENGINE MALWARE SCREENING                                           |
|  * Stage 1: Exact hash lookup (VT Cache, Malicious Hash Feeds)                    |
|  * Stage 2: MIME type validation & extension anomaly audit                        |
|  * Stage 3: Local ClamAV daemon scan (127.0.0.1:3310)                             |
|  * Stage 4: YARA rule compilation (threat patterns, webshells, packers)           |
|  * Stage 5: Structural heuristics & Shannon entropy analysis                      |
|  * Stage 6: Cloud Threat Intel (VirusTotal API v3, Hybrid Analysis v2)            |
+-----------------------------------------------------------------------------------+
             |
             v
+-----------------------------------------------------------------------------------+
| LAYER 1.5: RAPID TRIAGE & LSB HEURISTIC SCREENING                                 |
|  * Fast bitplane variance & LSB flipping heuristic                                |
|  * Structural format integrity checks                                             |
|  * Early escalation decision: bypass or forward to deep neural steganalysis       |
+-----------------------------------------------------------------------------------+
             |
             v
+-----------------------------------------------------------------------------------+
| LAYER 2: DEEP MULTIMODAL STEGANALYSIS                                             |
|  * Images: Spatial domain CNN (YedroudjNetV3) & Frequency domain (ALASKA2)        |
|  * Statistical: Chi-Square Distribution Test & Sample Pair RS Analysis            |
|  * Video: VideoStegNet DCT inter-frame residue analysis                           |
|  * Documents: DistilBERT NLP classifier + Regex zero-width/homoglyph detectors    |
+-----------------------------------------------------------------------------------+
             |
             v
+-----------------------------------------------------------------------------------+
| LAYER 3: PAYLOAD EXTRACTION & ATTRIBUTION                                         |
|  * Payload presence confirmation & byte boundary estimation                       |
|  * Embedded payload entropy profiling & classification (Text, Bin, Compressed)    |
|  * Signature extraction & potential decryption routing                            |
+-----------------------------------------------------------------------------------+
             |
             v
+-----------------------------------------------------------------------------------+
| LAYER 4: EXPLAINABLE AI, REPORTING & SEALING                                      |
|  * Grad-CAM spatial activation heatmaps & SHAP token attribution                  |
|  * Forensic report generation (ReportLab PDF & structured JSON/CSV bundle)        |
|  * Post-scan hash reconfirmation (verifying file state was unmodified)            |
|  * HMAC-SHA3-512 seal & RFC 3161 timestamping token embedding                     |
|  * Quarantine Vault isolation & Chain of Custody database update                  |
+-----------------------------------------------------------------------------------+
```

---

## 4. Project Structure

The codebase is organized into modular forensic services, rulesets, and user interfaces:

```
Shadow-trace/
├── capa_rules/                 # Mandiant FLARE CAPA capability analysis rulesets
│   ├── anti-analysis/          # Anti-debugging, anti-AV, and evasion rules
│   ├── collection/             # Data harvesting and credential theft rules
│   └── ...
├── models/                     # Model architectures, tokenizers & training histories
│   ├── distilbert_tokenizer/   # DistilBERT HuggingFace tokenizer configuration
│   ├── *.json                  # Training validation curves and performance histories
│   └── .gitkeep                # Directory anchor (model weights downloaded separately)
├── ui/                         # Desktop GUI integration, tray controller & bridge
│   ├── assets/                 # System tray icons (idle, monitoring, scanning, threat)
│   ├── icons/                  # SVG graphical assets and indicators
│   ├── tray_agent.py           # Background system tray agent with pystray
│   ├── ui_api.py               # pywebview JavaScript-to-Python bridge API
│   ├── report_viewer.py        # Cryptographic seal and dossier verification viewer
│   ├── system_info.py          # Host diagnostics, telemetry & limitations exporter
│   └── *.py                    # Individual forensic window controllers
├── UIUX/                       # Webview analyst interface (HTML5, Tailwind CSS, JS)
│   ├── dashboard.html          # Real-time telemetry, active monitor & threat stream
│   ├── manual_scan.html        # On-demand multi-file & folder triage wizard
│   ├── manual_scan_stage*.html # Step-by-step triage workflow screens
│   ├── case_manager.html       # Case tagging, evidence explorer & audit trails
│   ├── qurantine_files.html    # Isolation vault, payload inspection & recovery
│   ├── settings.html           # Engine thresholds, scanning modes & API configuration
│   ├── user_profile.html       # Examiner credentials, RBAC & signature management
│   ├── lock.html               # Session locking & authentication screen
│   ├── system_info.html        # Engine status, benchmarks & formal limitations
│   ├── audit_logger.js         # Frontend forensic audit logging bridge
│   ├── dashboard_cache.js      # Client-side telemetry caching & performance helper
│   └── assets/heatmaps/        # Explanatory attribution map previews
├── yara_rules/                 # Comprehensive YARA signature rulesets
│   ├── rules-master/           # Community malware signatures, packers & webshells
│   └── signature-base-master/  # High-confidence indicators of compromise (IOCs)
├── logs/                       # Application logs & audit DBs (.gitkeep)
├── quarantine/                 # Cryptographically isolated quarantine repository (.gitkeep)
├── reports/                    # Forensic output dossiers & evidence bundles (.gitkeep)
├── sandbox/                    # Isolated staging directory for file inspection (.gitkeep)
├── tools/                      # Diagnostic and benchmarking utilities
│   ├── benchmarking.py         # Multi-threaded throughput & latency benchmark suite
│   └── html_linter.py          # UI frontend validation linter
│
├── main.py                     # Primary desktop entrypoint (CLI & GUI orchestration)
├── config.py                   # Central configuration, paths, thresholds, and environment
├── layer0_monitor.py           # Real-time filesystem observer & ADS Zone.Identifier parser
├── layer1_malware.py           # Multi-engine malware screening orchestrator
├── layer1_entropy.py           # Shannon entropy calculation & byte distribution profiler
├── layer1_heuristic.py         # Structural PE/OLE heuristics & macro anomaly detection
├── layer1_clamav.py            # Local ClamAV daemon clamd integration
├── layer1_yara.py              # Multi-threaded YARA rule compiler and scanner
├── layer1_virustotal.py        # VirusTotal API v3 integration with local SQLite cache
├── layer1_5_lsb_check.py       # Rapid LSB bitplane variance & early stego filter
├── layer2_steganalysis.py      # Deep multimodal neural steganalysis orchestrator
├── statistical_steganalysis.py # Chi-Square distribution and Sample Pair (RS) analysis
├── document_forensics.py       # PDF/DOCX structural anomaly & zero-width character scanner
├── layer3_extraction.py        # Steganographic payload presence & capacity estimator
├── layer4_explainability.py    # Explainable AI (Grad-CAM, SHAP, bitplane visualizer)
├── layer4_report.py            # Court-ready PDF dossier generator with RFC 3161 / HMAC
├── layer4_summary_report.py    # Executive summary report generator
├── quarantine_report.py        # Specialized malware isolation report generator
├── evidence_export.py          # Complete evidence package zip bundler with manifest
├── case_manager.py             # Forensic case tracking, artifact tagging & dossier manager
├── chain_of_custody.py         # Tamper-evident ISO/IEC 27037 SQLite audit ledger
├── recovery_database.py        # Quarantine registry & XOR-encrypted recovery engine
├── analyst_audit.py            # HMAC-chained analyst action logging system
├── investigation_tools.py      # Forensic investigation utilities and database queries
├── network_monitor.py          # Windows DNS event log and TCP connection correlator
├── source_correlation.py       # Ingress provenance correlation engine
├── url_server.py               # Local Flask API server for ingress URL capture (port 8765)
├── scan_tracker.py             # Real-time scan state tracker and progress notifier
├── manual_scan.py              # Standalone CLI & GUI manual triage runner
├── manual_scan_service.py      # Multi-file manual scanning pipeline service
├── confidence_calibration.py   # Multi-engine evidence calibration & limitation disclosure
├── malware_classifier.py       # Normalized threat classification and severity ranker
├── capa_analyzer.py            # Binary capability matching via Mandiant FLARE CAPA
├── model_architectures.py      # PyTorch neural network definitions (YedroudjNet, SRNet, etc.)
├── profile_manager.py          # Examiner identity, PBKDF2 authentication & OTP management
├── settings_manager.py         # Settings persistence, database backup & synchronization
├── system_health.py            # Real-time CPU, RAM, disk, and component diagnostics
├── user_prompt.py              # Interactive user prompt and alert modal bridge
├── bridge.py                   # Core system message and inter-module event bridge
├── utils.py                    # Multi-hashing (SHA3/SHA256/BLAKE3), locking, logging helpers
├── test_capa_integration.py    # Integration test suite for CAPA capability analysis
├── test_quarantine_hook.py     # Integration test suite for quarantine vault isolation
├── requirements.txt            # Python dependencies
├── .env.template               # Environment variable template
└── .gitignore                  # Production git exclusion rules
```

---

## 5. Machine Learning Models

Shadow-Trace employs specialized neural network architectures tailored for specific steganography carriers:

| Model Architecture | Carrier Domain | Target Steganography Methods | Validation Metric (AUC) |
|:---|:---|:---|:---:|
| **YedroudjNetV3** | Image (Spatial) | LSB Replacement, LSB Matching, S-UNIWARD | **0.940** |
| **ALASKA2 (EfficientNet-B0)** | Image (Frequency) | J-UNIWARD, UERD, Jsteg (JPEG DCT coefficients) | **0.540** |
| **VideoStegNet** | Video (H.264 / MP4) | Motion Vector Perturbation, Intra-Prediction Stego | **0.760** |
| **DistilBERT Hybrid** | Documents (PDF / DOCX) | Zero-Width Character Injection, Homoglyphs, Font anomalies | **0.765** |

> [!NOTE]
> **Performance Disclosure:**
> Detecting content-adaptive steganography in frequency domains (e.g., J-UNIWARD) is inherently challenging due to minimal pixel perturbation. The ALASKA2 model reflects this domain complexity; its outputs serve as indicative intelligence rather than standalone proof. Active retraining with domain-adapted real-world corpora is underway.

---

## 6. System Requirements

- **Operating System:** Windows 10 or Windows 11 (64-bit)
- **Python Version:** Python 3.10.x (x86_64)
- **GUI Engine:** Microsoft Edge WebView2 Runtime (pre-installed on Windows 10/11)
- **Optional Local Antivirus:** ClamAV Daemon running on `127.0.0.1:3310` (for high-speed local malware scanning)
- **Hardware Recommendations:**
  - CPU: 4 cores or higher (Intel Core i5/i7 or AMD Ryzen)
  - RAM: 8 GB minimum (16 GB recommended for neural network inference)
  - Storage: 2 GB free disk space (excluding model checkpoints and evidence archives)

---

## 7. Installation & Setup

### Step 1: Clone Repository
```powershell
git clone <your-repository-url>
cd Shadow-trace
```

### Step 2: Configure Virtual Environment
```powershell
python -m venv venv
.\venv\Scripts\activate
```

### Step 3: Install Dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Environment Credentials Configuration
Copy the template configuration file to `.env`:
```powershell
copy .env.template .env
```
Open `.env` in a text editor and fill in your environment parameters:
```ini
# Copy to .env and fill in; never commit .env.
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
HYBRID_ANALYSIS_KEY=your_hybrid_analysis_key_here
HMAC_SECRET_KEY=your_secure_random_hmac_key_here
VT_MODE=hash_only
OFFLINE_SCAN_MODE=false
HYBRID_ANALYSIS_MODE=hash_only
EXAMINER_NAME=Digital Forensic Examiner
EXAMINER_ID=EX-001
EXAMINER_ORG=Digital Forensics Laboratory
```

### Step 5: Download Neural Model Weights
Pre-trained model weights are excluded from Git to prevent repository bloat.

> [!IMPORTANT]
> **Model Checkpoint Downloads:**
> Download the pre-trained weights from the project release page (placeholder: `<download-link-placeholder>`) and place them in the `models/` directory:
> - `models/doc_model.pth` (~254 MB)
> - `models/srnet_model.pth` (~54 MB)
> - `models/alaska2_tier2_model.pth` (~18 MB)
> - `models/image_model.pth` (~5.65 MB)
> - `models/yedroudj_model.pth` (~5.65 MB)

### Step 6: Launch Shadow-Trace
Launch the desktop forensic interface:
```powershell
python main.py
```

---

## 8. Scanning & Operational Modes

Shadow-Trace can be configured for diverse threat environments:

### VirusTotal Modes (`VT_MODE`)
- `hash_only` *(Default)*: Computes the SHA-256 hash locally and queries VirusTotal. Zero file contents are uploaded. Recommended for data privacy.
- `full_upload` / `UPLOAD_UNKNOWN`: Automatically uploads previously unindexed artifacts to VirusTotal for complete multi-engine detonation.
- `CHECK_ONLY`: Passive hash verification against internal caches and local blacklists.

### Air-Gapped / Offline Forensic Mode (`OFFLINE_SCAN_MODE`)
- When `OFFLINE_SCAN_MODE=true` in `.env`:
  - Cloud API queries (VirusTotal, Hybrid Analysis) are bypassed.
  - Threat detection executes strictly via local engines: ClamAV daemon (`127.0.0.1:3310`), YARA rule sets, structural anomaly heuristics, and offline neural models.
  - Guarantees zero outbound data leakage for classified investigations.

### Standalone Manual Triage
In addition to the real-time background monitor, on-demand triage can be executed directly:
```powershell
# Interactive file dialog scan
python manual_scan.py

# Benchmark pipeline throughput
python tools/benchmarking.py
```

---

## 9. Ingress Provenance & URL Capture Setup

Shadow-Trace establishes forensic ingress provenance through two cooperative capture methods:

### 1. Native Windows NTFS Alternate Data Streams (Zero Configuration)
- When files are downloaded through modern web browsers (Chrome, Edge, Firefox, Brave) to an NTFS drive, Windows automatically writes a `Zone.Identifier` stream containing `HostUrl` and `ReferrerUrl`.
- Layer 0 (`layer0_monitor.py`) automatically parses the `Zone.Identifier` stream on file creation with zero external dependencies or extensions required.

### 2. Companion Browser URL Capture Server (`localhost:8765`)
- For non-NTFS targets or detailed browser telemetry, Shadow-Trace hosts a local micro-service via `url_server.py` on `http://localhost:8765`.
- Any companion Chromium extension or script transmits download events directly via HTTP POST:
  ```http
  POST http://localhost:8765/url_capture
  Content-Type: application/json

  {
    "url": "https://malicious-distribution-source.com/payload.png",
    "filename": "payload.png"
  }
  ```
- **Ingress Correlation:** `source_correlation.py` automatically correlates captured URLs with active TCP connection tables and local Windows DNS resolution events to trace the remote server IP and origin domain.

---

## 10. Evidence Packaging & Sealing

When analysis completes, Shadow-Trace generates a self-contained, tamper-evident evidence package in `reports/`:

```
reports/stego/20261107_193701_artifact_evidence_package.zip
├── 20261107_193701_artifact.png               # Unmodified original artifact
├── 20261107_193701_artifact_report.pdf         # Court-ready PDF dossier
├── 20261107_193701_artifact_report.seal.json   # Cryptographic seal & RFC 3161 token
├── 20261107_193701_artifact_evidence.json     # Comprehensive structured metadata
├── 20261107_193701_artifact_summary.csv       # Tabular metric summary
└── heatmaps/                                  # Grad-CAM, SHAP & bitplane attribution maps
```

- **HMAC Seal (`*.seal.json`):** Contains the SHA3-512 digest of the PDF report and bundle, signed with the examiner's HMAC key.
- **RFC 3161 Digital Timestamp:** Encodes a verifiable cryptographic timestamp token issued by a trusted Time Stamping Authority (DigiCert / FreeTSA).
- **Post-Scan Hash Reconfirmation:** Recomputes SHA3-512, SHA-256, and BLAKE3 hashes to confirm the analyzed file was not altered during scanning.

---

## 11. Interface Previews

| Forensic Dashboard | Triage & Steganalysis |
|:---:|:---:|
| *(Screenshots / Dashboard UI Preview Placeholder)* | *(Screenshots / Stego Analysis & Grad-CAM Heatmap Placeholder)* |

| Forensic Dossier & Sealing | Case Manager & Audit Trail |
|:---:|:---:|
| *(Screenshots / PDF Forensic Report Preview Placeholder)* | *(Screenshots / Chain of Custody Ledger Placeholder)* |

---

## 12. Documented System Limitations

In adherence to ISO/IEC 27037 disclosure requirements, the following six limitations must be considered when evaluating forensic findings:

1. **ALASKA2 Adaptive Steganography Model:** Achieves ~0.54 AUC against advanced adaptive steganography (J-UNIWARD/UERD) due to training constraints. Findings should be corroborated and not relied upon as singular proof.
2. **Video Steganalysis Validation:** VideoStegNet was evaluated predominantly on synthetic stego streams; validation on high-bitrate professional broadcast streams is limited.
3. **Statistical Tests on Small Images:** Chi-Square and RS analysis require at least 10,000 pixels for statistical validity. Image files below this dimension may produce indeterminate results.
4. **Adaptive Payload Decryption:** Without the carrier's embedding stego-key, complete reconstruction of adaptively embedded payloads is mathematically intractable; Layer 3 estimates capacity and presence only.
5. **Novel Document Steganography:** The neural document model targets trained stego patterns; unrepresented document techniques fall back to deterministic regex scanning for zero-width and homoglyphic characters.
6. **VirusTotal Cloud Rate Limits:** Free-tier VirusTotal access is limited to 4 requests/minute. Uploading unindexed artifacts sends file content to third-party cloud infrastructure, which may be prohibited for classified evidence.

---

## 13. Future Roadmap

- **CAPA Capability Engine Expansion:** Deep programmatic capability analysis and behavioral rule mapping for Windows PE and Linux ELF binaries.
- **Multi-Analyst Role-Based Access Control (RBAC):** Cryptographic user identity partitioning and FIDO2 / WebAuthn physical security key integration.
- **Continuous Domain-Adapted Retraining:** Model fine-tuning against updated, real-world social-media stego datasets (WhatsApp, Telegram compression artifacts).
- **Containerized Analysis Sandboxing:** Automated microVM detonation for dynamic behavioral telemetry during Layer 1 triage.

---

## 14. Security Notice

- **Never commit `.env`** to version control. Keep API credentials, HMAC keys, and examiner passwords private.
- Sample images, documents, and mock binaries bundled in test directories contain non-malicious synthetic data for pipeline validation and contain no classified or live malware payloads.

---

## 15. Team & Institutional Credits

- **Institution:** Anjuman Institute of Technology and Management (AITM), Bhatkal, Karnataka, India
- **Department:** Department of Computer Science & Engineering
- **Project Guide / Supervisor:** *[Project Guide / Faculty Advisor Name]*
- **Developed By:** Prajwal Naik & Project Team

---

## 16. License

License selection is currently under review by the project authors. See the project repository or release documentation for license terms before redistribution.
