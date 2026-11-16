import os
import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))
import manual_scan_service

class ManualScanAPI:
    def open_file_dialog(self) -> str:
        res = manual_scan_service.open_file_dialog()
        return json.dumps(res)

    def start_manual_scan(self, filepath: str, options: str = "{}") -> str:
        opt_dict = {}
        try:
            if isinstance(options, str):
                opt_dict = json.loads(options)
            elif isinstance(options, dict):
                opt_dict = options
        except Exception:
            pass
        res = manual_scan_service.get_service().start_scan(filepath, opt_dict)
        return json.dumps(res)

    def get_scan_progress(self) -> str:
        res = manual_scan_service.get_service().get_progress()
        return json.dumps(res)

    def cancel_scan(self) -> str:
        res = manual_scan_service.get_service().cancel_scan()
        return json.dumps(res)

    def reset_scan(self) -> str:
        manual_scan_service.get_service().reset()
        return json.dumps({"success": True})

    def open_pdf(self, path: str) -> str:
        res = manual_scan_service.open_pdf(path)
        return json.dumps(res)

    def open_folder(self, path: str) -> str:
        try:
            p = Path(path)
            target = p if p.is_dir() else p.parent
            if target.exists():
                os.startfile(str(target))
                return json.dumps({"success": True})
            return json.dumps({"success": False, "error": "Folder not found"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def log_ui_action(self, action_type: str, target: str = "", details: str = "", severity: str = None) -> str:
        try:
            import analyst_audit
            ok = analyst_audit.log_action(action_type, target, details, severity=severity)
            return json.dumps({"success": ok})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def get_audit_log(self, limit: int = 500) -> str:
        try:
            import analyst_audit
            return json.dumps(analyst_audit.get_audit_log(int(limit)))
        except Exception as e:
            return json.dumps({"error": str(e)})

def open_manual_scan():
    try:
        import webview  # pyrefly: ignore [missing-import]
    except ImportError:
        print('pywebview not installed')
        print('Run: pip install pywebview')
        return

    # Load the Manual Scan UI directly from disk
    html_path = Path(__file__).parent.parent / 'UIUX' / 'manual_scan.html'
    url = html_path.as_uri()

    api = ManualScanAPI()

    window = webview.create_window(
        title='Shadow-Trace Manual Scan',
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
    open_manual_scan()
