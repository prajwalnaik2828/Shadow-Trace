import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))
from ui.ui_api import CommonUIAPI

def open_user_profile():
    try:
        import webview
    except ImportError:
        print('pywebview not installed. Run: pip install pywebview')
        return
    html_path = Path(__file__).parent.parent / 'UIUX' / 'user_profile.html'
    api = CommonUIAPI()
    window = webview.create_window(
        title='Shadow-Trace — User Profile',
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
    open_user_profile()
