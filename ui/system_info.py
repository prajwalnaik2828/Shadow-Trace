import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
import analyst_audit

class SystemInfoAPI:
    def get_audit_log(self, limit: int = 500) -> str:
        try:
            return json.dumps(analyst_audit.get_audit_log(int(limit)))
        except Exception as e:
            return json.dumps({"error": str(e), "logs": []})

    def log_ui_action(self, action_type: str, target: str = "", details: str = "", severity: str = None) -> str:
        try:
            ok = analyst_audit.log_action(action_type, target, details, severity=severity)
            return json.dumps({"success": ok})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

    def verify_audit_integrity(self) -> str:
        try:
            return json.dumps(analyst_audit.verify_chain_integrity())
        except Exception as e:
            return json.dumps({"valid": False, "error": str(e)})

    def export_audit_csv(self, output_path: str = "") -> str:
        try:
            res = analyst_audit.export_audit_csv(output_path or None)
            return json.dumps(res)
        except Exception as e:
            return json.dumps({"error": str(e)})

    def export_limitations_report(self) -> str:
        try:
            analyst_audit.log_action('REPORT_EXPORT', 'SYSTEM_LIMITATIONS', 'Exported System Limitations documentation report', severity='normal')
            return json.dumps({"success": True})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})

def open_system_info():
    try:
        import webview
    except ImportError:
        print('pywebview not installed. Run: pip install pywebview')
        return
    html_path = Path(__file__).parent.parent / 'UIUX' / 'system_info.html'
    api = SystemInfoAPI()
    window = webview.create_window(
        title='Shadow-Trace — System Info',
        url=html_path.as_uri(),
        js_api=api,
        width=1400,
        height=900,
        resizable=True,
        min_size=(1000, 600),
        background_color='#111111',
    )
    webview.start(debug=False, private_mode=True)

if __name__ == '__main__':
    open_system_info()
