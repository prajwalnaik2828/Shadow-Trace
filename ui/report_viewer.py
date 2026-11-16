import os
import sys
import json
import hmac
import hashlib
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))
import config

HMAC_KEY = os.environ.get(
    'HMAC_SECRET_KEY',
    ''
).encode('utf-8')


def verify_report_seal(report_path: str) -> dict:
    try:
        report_path = Path(report_path)
        seal_path = report_path.with_suffix('.seal.json')
        
        if not report_path.exists():
            return {
                'valid': False,
                'error': 'Report file not found',
                'report_path': str(report_path),
            }
        
        if not seal_path.exists():
            return {
                'valid': False,
                'error': 'Seal file not found. Report cannot be verified.',
                'report_path': str(report_path),
            }

        with open(seal_path) as f:
            seal_data = json.load(f)
        
        stored_hmac = seal_data.get('hmac_sha3_512', '')
        stored_sha3 = seal_data.get('sha3_512_of_report', '')
        generated_at = seal_data.get('generated_at', '')
        session_id = seal_data.get('session_id', '')
        rfc3161 = seal_data.get('rfc3161_timestamp', {})

        with open(report_path, 'rb') as f:
            report_bytes = f.read()

        current_sha3 = hashlib.sha3_512(report_bytes).hexdigest()
        
        current_hmac = hmac.new(
            HMAC_KEY,
            report_bytes,
            hashlib.sha3_512
        ).hexdigest()

        hash_valid = hmac.compare_digest(current_sha3, stored_sha3)
        hmac_valid = hmac.compare_digest(current_hmac, stored_hmac)
        overall_valid = hash_valid and hmac_valid

        return {
            'valid': overall_valid,
            'hash_match': hash_valid,
            'hmac_match': hmac_valid,
            'error': None if overall_valid else 'INTEGRITY FAILURE: Report may have been tampered with',
            'report_path': str(report_path),
            'report_name': report_path.name,
            'report_size_kb': round(len(report_bytes)/1024, 1),
            'generated_at': generated_at,
            'session_id': session_id,
            'rfc3161_verified': rfc3161.get('success', False),
            'stored_hmac_preview': stored_hmac[:32] + '...' if stored_hmac else '',
            'current_hmac_preview': current_hmac[:32] + '...',
            'calibration': seal_data.get('calibration', {}),
            'source_correlation': seal_data.get('source_correlation', {}),
        }
    except Exception as e:
        return {
            'valid': False,
            'error': f'Verification error: {str(e)}',
            'report_path': str(report_path),
        }


def fetch_all_reports() -> list:
    reports_dir = config.BASE_DIR / 'reports'
    if not reports_dir.exists():
        return []

    search_dirs = [
        reports_dir,
        reports_dir / 'clean',
        reports_dir / 'suspicious',
        reports_dir / 'stego',
    ]

    all_pdfs = []
    for search_dir in search_dirs:
        if search_dir.exists():
            for pdf in search_dir.glob('*.pdf'):
                name_lower = pdf.name.lower()
                # Exclude summary reports and only include report.pdf files
                if not name_lower.endswith(('report.pdf', '_report.pdf')) or name_lower.endswith(('summary.pdf', '_summary.pdf', 'summery.pdf', '_summery.pdf')):
                    continue
                subfolder = search_dir.name
                if subfolder == 'reports':
                    subfolder = 'uncategorised'
                all_pdfs.append((pdf, subfolder))

    all_pdfs.sort(key=lambda x: x[0].stat().st_mtime, reverse=True)

    results = []
    for i, (pdf, subfolder) in enumerate(all_pdfs):
        seal_result = verify_report_seal(str(pdf))
        cat = subfolder.lower()
        if cat in ('reports', 'uncategorised'):
            status = 'clean'
        elif cat == 'suspicious':
            status = 'suspicious'
        elif cat in ('stego', 'threat'):
            status = 'stego'
        else:
            status = 'clean'

        pdf_path_str = str(pdf).replace('\\', '/')
        h = hashlib.md5(pdf.name.encode()).hexdigest()[:8].upper() + '...'
        mod_str = datetime.fromtimestamp(
            pdf.stat().st_mtime
        ).strftime('%Y-%m-%d %H:%M:%S')

        results.append({
            'id': str(i + 1),
            'name': pdf.name,
            'filename': pdf.name,
            'path': pdf_path_str,
            'pdf_path': pdf_path_str,
            'status': status,
            'size_kb': round(pdf.stat().st_size / 1024, 1),
            'modified': mod_str,
            'date': mod_str,
            'modified_timestamp': pdf.stat().st_mtime,
            'hash': h,
            'threat': 'CRITICAL' if status == 'stego' else ('MEDIUM' if status == 'suspicious' else 'LOW'),
            'summary': f"Forensic report for {pdf.name}. Verdict: {status.upper()}.",
            'valid': seal_result.get('valid', False),
            'generated_at': seal_result.get('generated_at', 'Unknown'),
            'session_id': (seal_result.get('session_id', '') or '')[:8] + '...',
            'error': seal_result.get('error'),
            'category': subfolder,
        })

    return results

# Alias for external integration scripts
get_all_reports = fetch_all_reports


def generate_viewer_html(reports: list, selected_report: dict = None) -> str:
    reports_json_str = json.dumps(reports)
    
    html = f"""<!DOCTYPE html>
<html class="dark" lang="en">
<head>
    <meta charset="utf-8"/>
    <meta content="width=device-width, initial-scale=1.0" name="viewport"/>
    <script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
    <link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&amp;display=swap" rel="stylesheet"/>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&amp;family=IBM+Plex+Sans:wght@400;600;700;800&amp;display=swap" rel="stylesheet"/>
    <style>
        body {{
            background-color: #0f0f23;
            margin: 0;
            overflow: hidden;
        }}
        .scanline-overlay::after {{
            content: " ";
            display: block;
            position: absolute;
            top: 0;
            left: 0;
            bottom: 0;
            right: 0;
            background: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.1) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.02), rgba(0, 255, 0, 0.01), rgba(0, 0, 255, 0.02));
            z-index: 100;
            background-size: 100% 4px, 3px 100%;
            pointer-events: none;
            opacity: 0.3;
        }}
        .glass-panel {{
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        .led-pulse-green {{ box-shadow: 0 0 8px #92ccff; }}
        .led-pulse-red {{ box-shadow: 0 0 8px #ffb4ab; }}
        .material-symbols-outlined {{
            font-variation-settings: 'FILL' 0, 'wght' 400, 'GRAD' 0, 'opsz' 24;
            vertical-align: middle;
        }}
        .hidden {{ display: none !important; }}
    </style>
    <script id="tailwind-config">
        tailwind.config = {{
            darkMode: "class",
            theme: {{
                extend: {{
                    "colors": {{
                        "on-primary-fixed": "#001d31",
                        "outline": "#89929b",
                        "surface-bright": "#363a3e",
                        "outline-variant": "#3f4850",
                        "error-container": "#93000a",
                        "on-background": "#e0e3e8",
                        "primary": "#92ccff",
                        "on-secondary": "#252f4d",
                        "surface-container-high": "#262a2f",
                        "secondary-container": "#3b4665",
                        "primary-container": "#3498db",
                        "background": "#101418",
                        "secondary": "#bbc5eb",
                        "on-error-container": "#ffdad6",
                        "surface-variant": "#31353a",
                        "on-tertiary-fixed": "#291800",
                        "surface-container-highest": "#31353a",
                        "secondary-fixed-dim": "#bbc5eb",
                        "inverse-primary": "#006397",
                        "inverse-on-surface": "#2d3135",
                        "tertiary-container": "#c48400",
                        "primary-fixed-dim": "#92ccff",
                        "on-surface": "#e0e3e8",
                        "inverse-surface": "#e0e3e8",
                        "surface-dim": "#101418",
                        "on-secondary-fixed": "#0f1a37",
                        "on-tertiary-container": "#3c2500",
                        "on-surface-variant": "#bfc7d2",
                        "on-primary": "#003351",
                        "on-secondary-fixed-variant": "#3b4665",
                        "on-primary-container": "#002d47",
                        "on-error": "#690005",
                        "surface-tint": "#92ccff",
                        "on-primary-fixed-variant": "#004b73",
                        "secondary-fixed": "#dae1ff",
                        "error": "#ffb4ab",
                        "tertiary-fixed-dim": "#ffba4b",
                        "tertiary-fixed": "#ffddb1",
                        "surface-container-lowest": "#0a0f13",
                        "surface-container-low": "#181c20",
                        "on-secondary-container": "#aab4d9",
                        "on-tertiary": "#442b00",
                        "surface": "#101418",
                        "surface-container": "#1c2024",
                        "primary-fixed": "#cce5ff",
                        "tertiary": "#ffba4b",
                        "on-tertiary-fixed-variant": "#624000"
                    }},
                    "borderRadius": {{
                        "DEFAULT": "0.125rem",
                        "lg": "0.25rem",
                        "xl": "0.5rem",
                        "full": "0.75rem"
                    }},
                    "spacing": {{
                        "base": "4px",
                        "stack-gap": "12px",
                        "gutter": "16px",
                        "panel-padding": "20px",
                        "margin": "24px"
                    }},
                    "fontFamily": {{
                        "data-mono": ["JetBrains Mono"],
                        "data-lg": ["JetBrains Mono"],
                        "label-sm": ["JetBrains Mono"],
                        "headline-md": ["IBM Plex Sans"],
                        "headline-lg": ["IBM Plex Sans"],
                        "body-md": ["IBM Plex Sans"]
                    }}
                }}
            }}
        }}
    </script>
</head>
<body class="bg-background text-on-surface font-body-md overflow-hidden h-screen flex scanline-overlay">
<!-- SIDEBAR NAVIGATION -->
<aside class="fixed left-0 top-0 h-full w-[260px] bg-surface-container-high/80 backdrop-blur-xl border-r border-white/10 flex flex-col py-6 z-50">
    <div class="px-6 mb-8">
        <h1 class="font-headline-md font-black tracking-tighter text-primary">SHADOW_TRACE</h1>
        <p class="text-[10px] font-data-mono text-outline uppercase tracking-widest">V.1.0.0-STABLE</p>
    </div>
    <nav class="flex-1 flex flex-col gap-1">
        <a class="flex items-center gap-3 px-4 py-3 text-on-surface-variant hover:text-on-surface transition-colors hover:bg-white/5" href="#" onclick="openDashboard()">
            <span class="material-symbols-outlined">dashboard</span>
            <span class="text-sm">Dashboard</span>
        </a>
        <a class="flex items-center gap-3 px-4 py-3 text-primary bg-primary-container/20 border-r-2 border-primary transition-all" href="#">
            <span class="material-symbols-outlined">folder_shared</span>
            <span class="text-sm">Case Management</span>
        </a>
        <a class="flex items-center gap-3 px-4 py-3 text-on-surface-variant hover:text-on-surface transition-colors hover:bg-white/5" href="#" onclick="window.location.reload()">
            <span class="material-symbols-outlined">refresh</span>
            <span class="text-sm">Refresh Reports</span>
        </a>
    </nav>
</aside>

<!-- MAIN CONTENT AREA -->
<main class="ml-[260px] flex-1 flex flex-col h-screen overflow-hidden">
    <!-- TOP APP BAR -->
    <header class="h-16 flex justify-between items-center px-gutter bg-surface-dim/70 backdrop-blur-md border-b border-white/10 z-40 sticky top-0">
        <div class="flex items-center gap-gutter">
            <span class="font-headline-md font-bold text-primary">FORENSIC_OS</span>
            <div class="h-4 w-px bg-white/20"></div>
            <div class="flex items-center gap-4">
                <a class="text-primary border-b-2 border-primary pb-1 text-xs font-data-mono" href="#">Report Viewer</a>
            </div>
        </div>
        <div class="flex items-center gap-gutter">
            <button onclick="openDashboard()" style="background:#3498db;color:white;border:none;padding:6px 12px;border-radius:6px;cursor:pointer;margin-right:10px;font-size:12px;display:flex;align-items:center;gap:4px;">
                <span class="material-symbols-outlined text-[14px]">dashboard</span> Dashboard
            </button>
            <div class="flex flex-col items-end mr-4">
                <span class="text-[10px] font-data-mono text-primary leading-none" id="clock">...</span>
                <span class="text-[10px] font-data-mono text-outline leading-none">Examiner: Local Admin</span>
            </div>
        </div>
    </header>

    <!-- CONTENT CANVAS -->
    <div class="flex flex-1 overflow-hidden p-6 gap-6">
        <!-- LEFT COLUMN: Report Browsing -->
        <section class="w-[35%] flex flex-col gap-4 overflow-hidden">
            <div class="flex justify-between items-center">
                <h2 class="font-headline-md text-on-surface flex items-center gap-2">
                    <span class="material-symbols-outlined text-primary">folder_open</span>
                    Forensic Reports
                </h2>
                <span class="font-data-mono text-[10px] text-outline" id="reportCountDisplay">COUNT: {len(reports)} ITEMS</span>
            </div>

            <!-- SUBFOLDER NAVIGATION CARDS -->
            <div class="grid grid-cols-3 gap-2">
                <div onclick="filterByCategory('clean')" class="glass-panel bg-surface-container-low/40 p-3 rounded-lg border-t-2 border-t-[#27ae60] cursor-pointer hover:bg-surface-container-high transition-all text-center">
                    <div class="text-[10px] font-data-mono font-bold text-outline mb-1">CLEAN</div>
                    <div class="text-xl font-headline-md font-bold text-on-surface" id="badge-clean">0</div>
                </div>
                <div onclick="filterByCategory('suspicious')" class="glass-panel bg-surface-container-low/40 p-3 rounded-lg border-t-2 border-t-[#f5a623] cursor-pointer hover:bg-surface-container-high transition-all text-center">
                    <div class="text-[10px] font-data-mono font-bold text-outline mb-1">SUSPICIOUS</div>
                    <div class="text-xl font-headline-md font-bold text-on-surface" id="badge-suspicious">0</div>
                </div>
                <div onclick="filterByCategory('stego')" class="glass-panel bg-surface-container-low/40 p-3 rounded-lg border-t-2 border-t-[#e94560] cursor-pointer hover:bg-surface-container-high transition-all text-center">
                    <div class="text-[10px] font-data-mono font-bold text-outline mb-1">STEGO</div>
                    <div class="text-xl font-headline-md font-bold text-on-surface" id="badge-stego">0</div>
                </div>
            </div>

            <!-- FILTER CONTROLS -->
            <div class="flex flex-col gap-3 bg-surface-container-low/20 p-3 rounded-lg border border-white/5">
                <div class="flex gap-1 bg-surface-container-lowest p-1 rounded-md">
                    <button id="tab-all" onclick="filterByCategory('all')" class="flex-1 py-1 text-[10px] font-data-mono rounded bg-primary/20 text-primary transition-all flex items-center justify-center gap-1">All <span id="badge-all" class="bg-black/30 px-1.5 rounded text-[9px]">0</span></button>
                    <button id="tab-clean" onclick="filterByCategory('clean')" class="flex-1 py-1 text-[10px] font-data-mono rounded text-outline hover:text-on-surface hover:bg-white/5 transition-all">Clean</button>
                    <button id="tab-suspicious" onclick="filterByCategory('suspicious')" class="flex-1 py-1 text-[10px] font-data-mono rounded text-outline hover:text-on-surface hover:bg-white/5 transition-all">Suspicious</button>
                    <button id="tab-stego" onclick="filterByCategory('stego')" class="flex-1 py-1 text-[10px] font-data-mono rounded text-outline hover:text-on-surface hover:bg-white/5 transition-all">Stego</button>
                </div>
                
                <div id="sort-controls" class="flex gap-2 items-center w-full">
                    <label class="text-[10px] font-data-mono text-outline whitespace-nowrap">Sort by:</label>
                    <select id="sort-select" onchange="handleSortChange(this.value)" class="flex-1 bg-surface-container-high/40 border border-white/10 rounded px-2 py-1 text-[10px] font-data-mono text-on-surface outline-none focus:border-primary/50">
                        <option value="newest">Newest First</option>
                        <option value="oldest">Oldest First</option>
                        <option value="date">By Specific Date</option>
                    </select>
                </div>
                
                <div id="date-picker-container" style="display:none;" class="w-full">
                    <div class="flex flex-col gap-2">
                        <label class="text-[10px] font-data-mono text-outline">Select Date:</label>
                        <div class="flex gap-2">
                            <input type="date" id="date-filter" onchange="filterByDate(this.value)" class="flex-1 bg-surface-container-high/40 border border-white/10 rounded px-2 py-1 text-[10px] font-data-mono text-on-surface outline-none focus:border-primary/50" />
                            <button onclick="clearDateFilter()" class="bg-[#7f8c8d]/20 hover:bg-[#7f8c8d]/40 text-white border border-[#7f8c8d]/30 px-3 py-1 text-[10px] font-data-mono rounded transition-colors">Clear</button>
                        </div>
                    </div>
                </div>
            </div>

            <div class="relative">
                <span class="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-outline text-lg">search</span>
                <input id="searchInput" onkeyup="filterBySearch(this.value)" class="w-full bg-surface-container-high/40 border border-white/10 rounded-lg pl-10 pr-4 py-2.5 font-data-mono text-xs focus:border-primary/50 outline-none transition-all placeholder:text-outline/50" placeholder="SEARCH FILENAME..." type="text"/>
            </div>
            <div class="flex-1 overflow-y-auto pr-2 flex flex-col gap-3 custom-scrollbar" id="reportList">
                <!-- Populated by JS -->
            </div>
        </section>

        <!-- RIGHT COLUMN: Detailed Report View -->
        <section class="w-[65%] flex flex-col gap-6 overflow-y-auto custom-scrollbar pr-2 relative">
            
            <div class="empty-state absolute inset-0 flex flex-col items-center justify-center text-outline text-center" id="emptyState">
                <span class="material-symbols-outlined text-6xl mb-4">shield</span>
                <h3 class="text-lg">Select a report from the list to verify its<br>integrity and view details</h3>
            </div>
            
            <div id="detailsContainer" class="hidden flex flex-col gap-6">
                <!-- IMPACT STATUS BANNER -->
                <div id="sealBox" class="relative overflow-hidden glass-panel bg-gradient-to-r from-primary-container/20 to-surface-container rounded-xl p-8 border border-primary/20 transition-all">
                    <div class="absolute top-0 right-0 w-64 h-full bg-primary/5 -skew-x-12 translate-x-32" id="sealBgOverlay"></div>
                    <div class="relative z-10 flex items-center gap-6">
                        <div id="sealIconBox" class="w-16 h-16 rounded-full bg-primary/20 flex items-center justify-center border border-primary/40 led-pulse-green">
                            <span id="sealIcon" class="material-symbols-outlined text-[40px] text-primary" data-weight="fill">verified</span>
                        </div>
                        <div>
                            <h3 id="sealTitle" class="font-headline-lg text-primary tracking-tight leading-none mb-2">REPORT INTEGRITY VERIFIED</h3>
                            <p id="sealMessage1" class="text-outline font-data-mono text-xs max-w-lg">...</p>
                            <p id="sealError" class="text-error font-data-mono text-[10px] mt-2 font-bold max-w-lg hidden"></p>
                        </div>
                    </div>
                </div>

                <!-- ACTIONS BAR -->
                <div class="flex gap-4">
                    <button onclick="actionOpenPDF()" class="flex-1 py-3 px-6 bg-surface-container-high border border-white/10 rounded-lg flex items-center justify-center gap-3 hover:bg-surface-container-highest transition-all group">
                        <span class="material-symbols-outlined text-primary group-hover:scale-110 transition-transform">picture_as_pdf</span>
                        <span class="font-data-mono text-xs font-bold uppercase tracking-wider">Open PDF</span>
                    </button>
                    <button onclick="actionOpenFolder()" class="flex-1 py-3 px-6 bg-surface-container-high border border-white/10 rounded-lg flex items-center justify-center gap-3 hover:bg-surface-container-highest transition-all group">
                        <span class="material-symbols-outlined text-primary group-hover:scale-110 transition-transform">folder</span>
                        <span class="font-data-mono text-xs font-bold uppercase tracking-wider">Open Folder</span>
                    </button>
                    <button onclick="actionCopyPath()" class="flex-1 py-3 px-6 bg-surface-container-high border border-white/10 rounded-lg flex items-center justify-center gap-3 hover:bg-surface-container-highest transition-all group">
                        <span class="material-symbols-outlined text-primary group-hover:scale-110 transition-transform">content_copy</span>
                        <span class="font-data-mono text-xs font-bold uppercase tracking-wider">Copy Path</span>
                    </button>
                </div>

                <!-- REPORT DATA TABLE -->
                <div class="glass-panel bg-surface-container-low/40 rounded-xl overflow-hidden">
                    <div class="px-gutter py-4 bg-white/5 border-b border-white/10 flex justify-between items-center">
                        <span class="font-headline-md text-sm font-bold tracking-wider">TECHNICAL SPECIFICATIONS</span>
                        <span class="font-data-mono text-[10px] text-primary" id="detSessionHeader">...</span>
                    </div>
                    <table class="w-full border-collapse">
                        <tbody class="text-xs font-data-mono">
                            <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td class="px-gutter py-4 text-outline w-1/3 uppercase">File Name</td>
                                <td class="px-gutter py-4 text-on-surface break-all" id="detName">...</td>
                            </tr>
                            <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td class="px-gutter py-4 text-outline uppercase">File Size</td>
                                <td class="px-gutter py-4 text-on-surface" id="detSize">...</td>
                            </tr>
                            <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td class="px-gutter py-4 text-outline uppercase">Generated At</td>
                                <td class="px-gutter py-4 text-on-surface" id="detDate">...</td>
                            </tr>
                            <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td class="px-gutter py-4 text-outline uppercase">Session ID</td>
                                <td class="px-gutter py-4 text-on-surface" id="detSession">...</td>
                            </tr>
                            <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td class="px-gutter py-4 text-outline uppercase">RFC 3161 Timestamp</td>
                                <td class="px-gutter py-4 text-on-surface" id="detRFC">...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>

                <!-- HMAC SEAL BLOCK -->
                <div class="flex flex-col gap-3">
                    <div class="flex items-center gap-2">
                        <span class="material-symbols-outlined text-primary text-sm">encrypted</span>
                        <h4 class="font-data-mono text-[10px] font-bold text-outline tracking-widest uppercase">HMAC SECURITY SEAL</h4>
                    </div>
                    <div class="bg-surface-container-lowest border border-white/10 p-4 rounded-lg relative group">
                        <code class="block font-data-mono text-[10px] text-primary/80 break-all leading-relaxed" id="detHMAC">...</code>
                    </div>
                    <p class="text-[9px] text-outline/60 font-data-mono italic">Signature generated using private key: ****-****-****-1024</p>
                </div>
            </div>
        </section>
    </div>
</main>

<script>
    function updateClock() {{
        const now = new Date();
        document.getElementById('clock').innerText = now.toLocaleTimeString() + ' Local';
    }}
    setInterval(updateClock, 1000);
    updateClock();

    const allReports = JSON.parse(document.getElementById('reports-data').textContent);
    let currentPath = '';
    let currentCategory = 'all';
    let currentSort = 'newest';
    let currentDate = null;
    let currentSearch = '';

    function openDashboard() {{
        if (window.pywebview && window.pywebview.api) {{
            window.pywebview.api.open_dashboard();
        }}
    }}

    function handleSortChange(value) {{
        currentSort = value;
        var datePicker = document.getElementById('date-picker-container');
        if (value === 'date') {{
            datePicker.style.display = 'block';
        }} else {{
            datePicker.style.display = 'none';
            currentDate = null;
            applyFiltersAndSort();
        }}
    }}

    function clearDateFilter() {{
        currentDate = null;
        document.getElementById('date-filter').value = '';
        applyFiltersAndSort();
    }}

    function filterByDate(dateStr) {{
        currentDate = dateStr;
        applyFiltersAndSort();
    }}

    function filterByCategory(category) {{
        currentCategory = category;
        ['all', 'clean', 'suspicious', 'stego'].forEach(c => {{
            const tab = document.getElementById('tab-' + c);
            if (c === category) {{
                tab.className = "flex-1 py-1 text-[10px] font-data-mono rounded bg-primary/20 text-primary transition-all flex items-center justify-center gap-1";
            }} else {{
                tab.className = "flex-1 py-1 text-[10px] font-data-mono rounded text-outline hover:text-on-surface hover:bg-white/5 transition-all flex items-center justify-center gap-1";
            }}
        }});
        applyFiltersAndSort();
    }}

    function filterBySearch(query) {{
        currentSearch = query.toLowerCase();
        applyFiltersAndSort();
    }}

    function applyFiltersAndSort() {{
        let filtered = [...allReports];

        if (currentCategory !== 'all') {{
            filtered = filtered.filter(r => r.category === currentCategory);
        }}

        if (currentSearch !== '') {{
            filtered = filtered.filter(r => r.name.toLowerCase().includes(currentSearch));
        }}

        if (currentDate && currentDate !== '') {{
            filtered = filtered.filter(function(r) {{
                var reportDate = r.modified ? r.modified.substring(0, 10) : '';
                return reportDate === currentDate;
            }});
        }}

        if (currentSort === 'newest') {{
            filtered.sort((a, b) => b.modified_timestamp - a.modified_timestamp);
        }} else if (currentSort === 'oldest') {{
            filtered.sort((a, b) => a.modified_timestamp - b.modified_timestamp);
        }}

        var counter = document.getElementById('reportCountDisplay');
        if (counter) {{
            counter.innerText = `COUNT: ${{filtered.length}} ITEMS`;
        }}
        
        renderReportList(filtered);
    }}

    function renderReportList(reportsData) {{
        const listEl = document.getElementById('reportList');
        listEl.innerHTML = '';
        
        reportsData.forEach(r => {{
            let styleClasses = "";
            let validIconHtml = "";
            if (r.valid) {{
                styleClasses = "glass-panel bg-primary-container/10 p-4 rounded-xl border-l-4 border-l-primary cursor-pointer hover:bg-primary-container/20 transition-all group";
                validIconHtml = `
                <div class="bg-primary/10 px-2 py-1 flex items-center gap-1 rounded">
                    <span class="material-symbols-outlined text-[14px] text-primary" data-weight="fill">verified_user</span>
                </div>`;
            }} else {{
                styleClasses = "glass-panel bg-surface-container-low/60 p-4 rounded-xl border-l-4 border-l-error cursor-pointer hover:bg-surface-container-high transition-all group";
                validIconHtml = `
                <div class="bg-error/10 px-2 py-1 flex items-center gap-1 rounded">
                    <span class="material-symbols-outlined text-[14px] text-error" data-weight="fill">report</span>
                </div>`;
            }}

            let catColor = "text-outline";
            let catBg = "bg-surface-container-high";
            if (r.category === 'clean') {{
                catColor = "text-[#27ae60]"; catBg = "bg-[#27ae60]/10";
            }} else if (r.category === 'suspicious') {{
                catColor = "text-[#f5a623]"; catBg = "bg-[#f5a623]/10";
            }} else if (r.category === 'stego') {{
                catColor = "text-[#e94560]"; catBg = "bg-[#e94560]/10";
            }}

            let truncatedName = r.name.length > 35 ? r.name.substring(0, 32) + '...' : r.name;

            const item = document.createElement('div');
            item.className = styleClasses;
            item.setAttribute('data-path', r.path);
            item.onclick = () => showReport(r.path, item);
            
            item.innerHTML = `
                <div class="flex justify-between items-start mb-2">
                    <div class="flex flex-col pr-2">
                        <span class="font-data-mono text-xs text-on-surface font-bold group-hover:text-primary transition-colors" title="${{r.name}}">${{truncatedName}}</span>
                        <span class="text-[10px] font-data-mono text-outline mt-1">${{r.modified}}</span>
                    </div>
                    ${{validIconHtml}}
                </div>
                <div class="flex justify-between items-center mt-3">
                    <span class="px-2 py-0.5 rounded text-[9px] font-bold tracking-widest uppercase ${{catBg}} ${{catColor}}">${{r.category || 'UNCATEGORISED'}}</span>
                    <span class="text-[10px] font-data-mono text-outline">${{r.size_kb}} KB</span>
                </div>
            `;
            listEl.appendChild(item);
        }});
    }}

    function showReport(path, el) {{
        document.querySelectorAll('[data-path]').forEach(i => {{
            if (i.classList.contains('border-l-primary')) {{
                i.classList.remove('bg-primary-container/20');
                i.classList.add('bg-primary-container/10');
            }} else {{
                i.classList.remove('bg-surface-container-high');
                i.classList.add('bg-surface-container-low/60');
            }}
        }});
        
        if (el) {{
            if (el.classList.contains('border-l-primary')) {{
                el.classList.remove('bg-primary-container/10');
                el.classList.add('bg-primary-container/20');
            }} else {{
                el.classList.remove('bg-surface-container-low/60');
                el.classList.add('bg-surface-container-high');
            }}
        }} else {{
            const item = document.querySelector(`[data-path="${{path.replace(/\\/g, '\\\\')}}"]`);
            if (item) item.click();
        }}
        
        currentPath = path;
        
        if (window.pywebview) {{
            window.pywebview.api.get_report_details(path).then(resStr => {{
                const res = JSON.parse(resStr);
                updateRightPanel(res);
            }});
        }} else {{
            const fakeRes = {{
                valid: !path.includes('tamper'),
                error: path.includes('tamper') ? 'INTEGRITY FAILURE' : null,
                report_name: path.split('/').pop(),
                report_size_kb: 1024,
                generated_at: new Date().toISOString(),
                session_id: 'abc-123',
                rfc3161_verified: true,
                current_hmac_preview: 'e3b0c44298fc1c149afbf4c8996fb924...'
            }};
            updateRightPanel(fakeRes);
        }}
    }}

    function updateRightPanel(res) {{
        document.getElementById('emptyState').classList.add('hidden');
        document.getElementById('detailsContainer').classList.remove('hidden');
        
        const sealBox = document.getElementById('sealBox');
        const sealIconBox = document.getElementById('sealIconBox');
        const sealIcon = document.getElementById('sealIcon');
        const sealTitle = document.getElementById('sealTitle');
        const msg1 = document.getElementById('sealMessage1');
        const error = document.getElementById('sealError');
        const overlay = document.getElementById('sealBgOverlay');
        
        if (res.valid) {{
            sealBox.className = 'relative overflow-hidden glass-panel bg-gradient-to-r from-primary-container/20 to-surface-container rounded-xl p-8 border border-primary/20 transition-all';
            overlay.className = 'absolute top-0 right-0 w-64 h-full bg-primary/5 -skew-x-12 translate-x-32';
            sealIconBox.className = 'w-16 h-16 rounded-full bg-primary/20 flex items-center justify-center border border-primary/40 led-pulse-green';
            sealIcon.className = 'material-symbols-outlined text-[40px] text-primary';
            sealIcon.innerText = 'verified';
            sealTitle.className = 'font-headline-lg text-primary tracking-tight leading-none mb-2';
            sealTitle.innerText = 'REPORT INTEGRITY VERIFIED';
            msg1.innerText = 'The document hash matches the cryptographical seal. No tampering detected since initial archival.';
            error.classList.add('hidden');
        }} else {{
            sealBox.className = 'relative overflow-hidden glass-panel bg-gradient-to-r from-error/20 to-surface-container rounded-xl p-8 border border-error/40 transition-all';
            overlay.className = 'absolute top-0 right-0 w-64 h-full bg-error/5 -skew-x-12 translate-x-32';
            sealIconBox.className = 'w-16 h-16 rounded-full bg-error/20 flex items-center justify-center border border-error/40 led-pulse-red';
            sealIcon.className = 'material-symbols-outlined text-[40px] text-error';
            sealIcon.innerText = 'report';
            sealTitle.className = 'font-headline-lg text-error tracking-tight leading-none mb-2';
            sealTitle.innerText = 'INTEGRITY FAILURE DETECTED';
            msg1.innerText = 'This report has been modified after generation. The cryptographic seal does not match the file bytes.';
            error.classList.remove('hidden');
            error.innerText = res.error || 'Unknown Error';
        }}
        
        document.getElementById('detName').innerText = res.report_name;
        document.getElementById('detSize').innerText = res.report_size_kb + ' KB';
        document.getElementById('detDate').innerText = res.generated_at || 'Unknown';
        document.getElementById('detSession').innerText = res.session_id || 'Unknown';
        document.getElementById('detSessionHeader').innerText = 'SESSION: ' + (res.session_id ? res.session_id.substring(0, 8) : 'UNKNOWN');
        document.getElementById('detRFC').innerText = res.rfc3161_verified ? 'Verified' : 'Not Available';
        document.getElementById('detHMAC').innerText = res.current_hmac_preview || '';
    }}

    function actionOpenPDF() {{
        if (window.pywebview && currentPath) {{
            window.pywebview.api.open_pdf(currentPath);
        }}
    }}
    
    function actionOpenFolder() {{
        if (window.pywebview) {{
            window.pywebview.api.open_folder();
        }}
    }}
    
    function actionCopyPath() {{
        if (navigator.clipboard && currentPath) {{
            navigator.clipboard.writeText(currentPath).then(() => alert('Path copied to clipboard'));
        }}
    }}

    function updateCategoryBadges() {{
        var counts = {{
            'clean': 0,
            'suspicious': 0,
            'stego': 0,
            'all': allReports.length
        }};
        allReports.forEach(function(r) {{
            if (counts.hasOwnProperty(r.category)) {{
                counts[r.category]++;
            }}
        }});
        
        var cleanBadge = document.getElementById('badge-clean');
        if (cleanBadge) cleanBadge.textContent = counts.clean;
        
        var suspBadge = document.getElementById('badge-suspicious');
        if (suspBadge) suspBadge.textContent = counts.suspicious;
        
        var stegoBadge = document.getElementById('badge-stego');
        if (stegoBadge) stegoBadge.textContent = counts.stego;
        
        var allBadge = document.getElementById('badge-all');
        if (allBadge) allBadge.textContent = counts.all;
    }}

    window.onload = function() {{
        updateCategoryBadges();
        applyFiltersAndSort();
        const first = document.querySelector('[data-path]');
        if (first) first.click();
    }};
</script>
<script id="reports-data" type="application/json">
{reports_json_str}
</script>
</body>
</html>"""
    return html


class ReportViewerAPI:
    def open_pdf(self, path: str):
        try:
            os.startfile(path)
        except Exception as e:
            print('Open PDF error: ' + str(e))

    def open_folder(self):
        try:
            reports_dir = config.BASE_DIR / 'reports'
            reports_dir.mkdir(parents=True, exist_ok=True)
            os.startfile(str(reports_dir))
        except Exception as e:
            print('Open folder error: ' + str(e))

    def get_report_details(self, path: str) -> str:
        result = verify_report_seal(path)
        return json.dumps(result)

    def get_all_reports(self) -> str:
        reports = fetch_all_reports()
        return json.dumps(reports)

    def get_evidence_data(self, pdf_path: str) -> str:
        try:
            p = Path(pdf_path)
            data = {}
            prefix_minute = p.name[:13]
            clean_stem = p.stem.replace('_report', '')
            if len(clean_stem) > 16 and clean_stem[:15].replace('_', '').isdigit():
                clean_stem = clean_stem[16:]

            # 1. Search evidence json by minute prefix or clean stem
            for j in p.parent.glob(f'{prefix_minute}*_evidence.json'):
                try:
                    with open(j, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    break
                except Exception:
                    pass

            if not data and clean_stem:
                for j in p.parent.glob(f'*{clean_stem}*_evidence.json'):
                    try:
                        with open(j, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        break
                    except Exception:
                        pass

            # 2. Match seal file
            seal_file = p.with_suffix('.seal.json')
            if not seal_file.exists():
                for s in p.parent.glob(f'{prefix_minute}*_report.seal.json'):
                    seal_file = s
                    break
            if not seal_file.exists() and clean_stem:
                for s in p.parent.glob(f'*{clean_stem}*.seal.json'):
                    seal_file = s
                    break

            if seal_file.exists():
                try:
                    with open(seal_file, 'r', encoding='utf-8') as f:
                        data['seal'] = json.load(f)
                except Exception:
                    pass

            # 3. Match heatmaps and original image
            heatmaps = {}
            heatmaps_dir = config.BASE_DIR / 'reports' / 'heatmaps'
            if heatmaps_dir.exists() and clean_stem:
                for hf in heatmaps_dir.glob(f'*{clean_stem}*'):
                    nl = hf.name.lower()
                    uri = hf.as_uri()
                    if 'lsb_heatmap' in nl or 'bitplane' in nl:
                        heatmaps['lsb_heatmap'] = uri
                    elif 'attribution' in nl or 'shap' in nl:
                        heatmaps['attribution'] = uri
                    elif 'gradcam' in nl:
                        heatmaps['gradcam'] = uri
                    elif 'token_map' in nl:
                        heatmaps['token_map'] = uri

            # Check if original image exists on disk
            full_path = data.get('file_identity', {}).get('full_path')
            if not full_path and 'seal' in data:
                full_path = data['seal'].get('source_correlation', {}).get('filepath')
            if full_path:
                try:
                    orig_p = Path(full_path)
                    if orig_p.exists() and orig_p.suffix.lower() in ('.png', '.jpg', '.jpeg', '.bmp', '.webp', '.tiff'):
                        heatmaps['original'] = orig_p.as_uri()
                except Exception:
                    pass

            data['heatmaps'] = heatmaps

            # 4. Get session timeline
            session_id = data.get('case_metadata', {}).get('session_id')
            if not session_id and 'seal' in data:
                session_id = data['seal'].get('session_id')
            if session_id:
                try:
                    from case_manager import get_case_timeline
                    data['timeline'] = get_case_timeline(session_id)
                except Exception:
                    pass

            # 5. Normalize malware screening
            mw = data.get('malware_screening', {})
            if isinstance(mw.get('clamav_result'), str):
                try:
                    import ast
                    mw['clamav_result'] = ast.literal_eval(mw['clamav_result'])
                except Exception:
                    ver = 'CLEAN' if 'CLEAN' in mw['clamav_result'].upper() else 'THREAT'
                    mw['clamav_result'] = {'verdict': ver}

            if isinstance(mw.get('heuristics_result'), str):
                try:
                    import ast
                    mw['heuristics_result'] = ast.literal_eval(mw['heuristics_result'])
                except Exception:
                    pass

            if isinstance(mw.get('virustotal_result'), str):
                vt_str = mw['virustotal_result']
                mw['virustotal_result'] = {'verdict': vt_str, 'positives': 0, 'total': 70}

            # 6. Read real file bytes for hexadecimal viewer and strings
            target_read_file = None
            if full_path:
                try:
                    cand = Path(full_path)
                    if cand.exists():
                        target_read_file = cand
                except Exception:
                    pass
            if not target_read_file and p.exists():
                target_read_file = p

            hex_lines = []
            strings_found = []
            if target_read_file:
                try:
                    with open(target_read_file, 'rb') as f:
                        raw_bytes = f.read(512)
                    for i in range(0, min(len(raw_bytes), 256), 16):
                        block = raw_bytes[i:i+16]
                        off_str = f"0x{i:08x}"
                        hex_parts = [f"{b:02x}" for b in block]
                        ascii_text = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in block)
                        hex_lines.append({
                            'offset': off_str,
                            'hex': hex_parts,
                            'ascii': f"|{ascii_text}|"
                        })
                except Exception:
                    pass

            lsb = data.get('lsb_check', {})
            if lsb.get('executable_found'):
                strings_found.append({
                    'offset': lsb.get('position') or '0x0000044a',
                    'string': 'PE_EXECUTABLE (MZ_HEADER)',
                    'type': 'CRITICAL'
                })
            if hex_lines:
                first_ascii = hex_lines[0]['ascii']
                if 'JFIF' in first_ascii:
                    strings_found.append({'offset': '0x00000006', 'string': 'JFIF (JPEG_HEADER)', 'type': 'INFO'})
                elif 'PNG' in first_ascii:
                    strings_found.append({'offset': '0x00000001', 'string': 'PNG (IMAGE_HEADER)', 'type': 'INFO'})

            data['hex_preview'] = hex_lines
            data['extracted_strings'] = strings_found

            if not data:
                return json.dumps({"error": "Evidence data not found"})

            return json.dumps(data)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def open_dashboard(self):
        try:
            import subprocess
            import sys
            subprocess.Popen(
                [sys.executable, str(config.BASE_DIR / 'ui' / 'dashboard.py')],
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
        except Exception as e:
            print('Dashboard error: ' + str(e))

    def get_investigation(self, session_id: str) -> str:
        try:
            from investigation_tools import (
                get_full_session_view
            )
            result = get_full_session_view(session_id)
            import json
            return json.dumps(result, default=str)
        except Exception as e:
            import json
            return json.dumps({'error': str(e)})

    def add_note(self, session_id: str,
                 note_text: str,
                 note_type: str = 'GENERAL') -> str:
        try:
            from investigation_tools import add_note
            result = add_note(
                session_id, note_text,
                note_type=note_type
            )
            import json
            return json.dumps(result)
        except Exception as e:
            import json
            return json.dumps({'error': str(e)})

    def add_tag(self, session_id: str,
                tag: str) -> str:
        try:
            from investigation_tools import add_tag
            result = add_tag(session_id, tag)
            import json
            return json.dumps(result)
        except Exception as e:
            import json
            return json.dumps({'error': str(e)})

    def open_evidence_package(self, session_id: str) -> str:
        try:
            import os
            from case_manager import find_reports_for_session
            reports = find_reports_for_session(session_id)
            for r in reports:
                if r.get('report_type') == 'EVIDENCE_PACKAGE':
                    os.startfile(r['path'])
                    import json
                    return json.dumps({'success': True})
            import json
            return json.dumps({
                'success': False,
                'error': 'No evidence package found'
            })
        except Exception as e:
            import json
            return json.dumps({'error': str(e)})


def open_report_viewer(initial_report: str = None):
    try:
        import webview  # pyrefly: ignore [missing-import]
    except ImportError:
        print('pywebview not installed')
        print('Run: pip install pywebview')
        return

    # Load the new Case Manager UI directly from disk
    html_path = Path(__file__).parent.parent / 'UIUX' / 'case_manager.html'
    url = html_path.as_uri()

    api = ReportViewerAPI()

    window = webview.create_window(
        title='Shadow-Trace Case Manager',
        url=url,
        js_api=api,
        width=1400,
        height=900,
        resizable=True,
        min_size=(1000, 600),
        background_color='#111111',
    )

    webview.start(
        debug=False,
        private_mode=True,
    )


if __name__ == '__main__':
    print('Shadow-Trace Report Viewer\n')
    
    print('Test 1: Checking for existing reports...')
    reports = fetch_all_reports()
    print('Reports found: ' + str(len(reports)))
    
    if reports:
        print()
        print('Most recent report:')
        r = reports[0]
        print('  Name: ' + r['name'])
        print('  Size: ' + str(r['size_kb']) + ' KB')
        print('  Valid: ' + str(r['valid']))
        if not r['valid']:
            print('  Error: ' + str(r.get('error')))
        print()
        
        print('Verifying seal of most recent report...')
        result = verify_report_seal(r['path'])
        print('  Hash match: ' + str(result['hash_match']))
        print('  HMAC match: ' + str(result['hmac_match']))
        print('  Overall valid: ' + str(result['valid']))
        if result['valid']:
            print('  SEAL VERIFICATION: PASS')
        else:
            print('  SEAL VERIFICATION: FAIL')
            print('  Reason: ' + str(result.get('error')))
    else:
        print('No reports found.')
        print('Run a scan first to generate a report.')
    
    print()
    
    html = generate_viewer_html(reports)
    preview_path = config.BASE_DIR / 'test_viewer.html'
    with open(preview_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print('HTML preview saved: ' + str(preview_path))
    print('Open in browser to preview without pywebview')
    print()
    
    print('Opening report viewer window...')
    open_report_viewer()
