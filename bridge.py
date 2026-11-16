import re

def inject_loader(html_path, call_logic):
    with open(html_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    loader = f"""
        function st_bridge_init() {{
            if (window.st_bridge_started) return;
            window.st_bridge_started = true;
            {call_logic}
        }}
        window.addEventListener('pywebviewready', st_bridge_init);
        let st_attempts = 0;
        let st_poll = setInterval(() => {{
            if (window.pywebview && window.pywebview.api) {{
                clearInterval(st_poll);
                st_bridge_init();
            }}
            if (++st_attempts > 50) clearInterval(st_poll);
        }}, 200);
    """
    
    if "st_bridge_init" not in content:
        content = content.replace('</body>', f'<script>{loader}</script>\n</body>')
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
inject_loader(r'D:\Shadow-trace\UIUX\dashboard.html', 'if(typeof loadData === "function") loadData();')
inject_loader(r'D:\Shadow-trace\UIUX\case_manager.html', 'if(typeof renderReports === "function") { window.pywebview.api.get_all_reports().then(r => { reports = JSON.parse(r); renderReports(); }).catch(e => console.error(e)); }')
inject_loader(r'D:\Shadow-trace\UIUX\qurantine_files.html', '''
    window.pywebview.api.get_quarantined_files().then(rawData => {
        const files = JSON.parse(rawData);
        const tbody = document.querySelector('tbody.divide-y');
        if (tbody) {
            if (files.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="p-4 text-center text-on-surface-variant font-code-sm text-[13px]">No quarantined files found.</td></tr>';
            } else {
                tbody.innerHTML = '';
                files.forEach(f => {
                    const tr = document.createElement('tr');
                    tr.className = "hover:bg-surface-container-highest transition-colors";
                    tr.innerHTML = `
                        <td class="p-4"><input class="rounded border-outline-variant bg-surface-container-lowest text-secondary focus:ring-0" type="checkbox"></td>
                        <td class="p-4 font-code-sm text-[13px] text-primary">${f.filename}</td>
                        <td class="p-4 text-[12px] text-on-surface-variant truncate max-w-[150px]" title="${f.path}">${f.path}</td>
                        <td class="p-4 text-[12px] text-on-surface-variant">${f.date_quarantined}</td>
                        <td class="p-4"><span class="stego-badge bg-error">MALWARE</span></td>
                        <td class="p-4 text-[12px] text-on-surface-variant">Heuristic_L3</td>
                        <td class="p-4 text-[12px] text-on-surface-variant">${f.size_kb} KB</td>
                        <td class="p-4 text-right flex justify-end gap-2">
                            <button class="material-symbols-outlined text-[18px] text-on-surface-variant hover:text-primary transition-colors" title="Review">folder_managed</button>
                            <button class="material-symbols-outlined text-[18px] text-on-surface-variant hover:text-secondary transition-colors" title="Restore">undo</button>
                            <button class="material-symbols-outlined text-[18px] text-on-surface-variant hover:text-error transition-colors" title="Delete" onclick="this.closest('tr').remove()">delete</button>
                        </td>
                    `;
                    tbody.appendChild(tr);
                });
            }
        }
    }).catch(e => console.error(e));
''')
print("Injected robust pywebview bridge into all pages")
