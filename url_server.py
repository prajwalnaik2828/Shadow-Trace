# =============================================================================
# Shadow-Trace | url_server.py
# Tiny local Flask server on localhost:8765 that captures download source
# URLs from the browser extension and serves them to Layer 0 on demand.
# =============================================================================

import json
import threading
import logging
from datetime import datetime

from flask import Flask, request, jsonify

import config
import utils

# ---------------------------------------------------------------------------
# Silence Flask / Werkzeug console noise at module level
# ---------------------------------------------------------------------------
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

# Internal flag for graceful shutdown intent logging
_server_running = False
_flask_thread   = None

# Max entries kept in the URL cache file
_MAX_CACHE_ENTRIES = 50


# =============================================================================
# FUNCTION 1: create_url_server_app
# =============================================================================

def create_url_server_app():
    """
    Build and return the Flask application with three routes:
      POST /url_capture      — store a download URL in the JSON cache
      GET  /get_url/<name>   — look up the URL for a filename
      GET  /health           — liveness probe
    """
    app = Flask(__name__)
    app.logger.setLevel(logging.ERROR)   # suppress Flask's own logger too

    # ------------------------------------------------------------------
    # Helper: load cache from disk
    # ------------------------------------------------------------------
    def _load_cache():
        try:
            if config.URL_CACHE_FILE.exists():
                with open(config.URL_CACHE_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            return []
        except Exception as e:
            utils.log_error("url_server._load_cache: failed to read cache", e)
            return []

    # Helper: persist cache to disk
    def _save_cache(entries):
        try:
            with open(config.URL_CACHE_FILE, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=2, ensure_ascii=False, default=str)
        except Exception as e:
            utils.log_error("url_server._save_cache: failed to write cache", e)

    # ------------------------------------------------------------------
    # ROUTE 1: POST /url_capture
    # ------------------------------------------------------------------
    @app.route('/url_capture', methods=['POST'])
    def url_capture():
        try:
            body = request.get_json(force=True, silent=True) or {}
            url       = body.get('url', '')
            filename  = body.get('filename', '')
            timestamp = body.get('timestamp', datetime.now().isoformat())

            if not url or not filename:
                return jsonify({'status': 'error',
                                'message': 'url and filename are required'}), 400

            entries = _load_cache()

            # Enforce max-50 rolling window
            entries.append({
                'url':       url,
                'filename':  filename,
                'timestamp': timestamp,
                'captured_at': datetime.now().isoformat(),
            })
            if len(entries) > _MAX_CACHE_ENTRIES:
                entries = entries[-_MAX_CACHE_ENTRIES:]

            _save_cache(entries)
            
            url_log_path = config.BASE_DIR / 'logs' / 'url_captures.json'
            try:
                import json
                from datetime import timezone
                url_log_path.parent.mkdir(parents=True, exist_ok=True)
                existing = []
                if url_log_path.exists():
                    with open(url_log_path) as f:
                        existing = json.load(f)
                
                existing.append({
                    'url': url,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'filename': filename,
                    'session_id': body.get('session_id', None),
                })
                
                with open(url_log_path, 'w') as f:
                    json.dump(existing[-500:], f, indent=2)
            except Exception:
                pass
            
            utils.logger.info("URL captured: %s -> %s", filename, url[:60])
            return jsonify({'status': 'ok', 'message': 'URL captured'}), 200

        except Exception as e:
            utils.log_error("url_capture route: unexpected error", e)
            return jsonify({'status': 'error', 'message': str(e)}), 500

    # ------------------------------------------------------------------
    # ROUTE 2: GET /get_url/<filename>
    # ------------------------------------------------------------------
    @app.route('/get_url/<path:filename>', methods=['GET'])
    def get_url(filename):
        try:
            entries = _load_cache()
            # Walk in reverse so most recent match wins
            for entry in reversed(entries):
                if entry.get('filename') == filename:
                    return jsonify(entry), 200
            return jsonify({'url': None, 'filename': filename,
                            'message': 'Not found in cache'}), 200
        except Exception as e:
            utils.log_error(f"get_url route: unexpected error for {filename}", e)
            return jsonify({'url': None, 'error': str(e)}), 500

    # ------------------------------------------------------------------
    # ROUTE 3: GET /health
    # ------------------------------------------------------------------
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status':  'running',
            'service': 'Shadow-Trace URL Capture Server',
            'port':    config.URL_SERVER_PORT,
        }), 200

    return app


# =============================================================================
# FUNCTION 2: get_url_for_file
# =============================================================================

def get_url_for_file(filename):
    """
    Called by layer0_monitor.py to retrieve the source download URL for a file.
    Searches the JSON cache, stripping URL encoding and Windows copy patterns.
    """
    import re
    from urllib.parse import unquote
    try:
        if not config.URL_CACHE_FILE.exists():
            return 'URL not captured'

        with open(config.URL_CACHE_FILE, 'r', encoding='utf-8') as f:
            entries = json.load(f)

        if not isinstance(entries, list):
            return 'URL not captured'
            
        # Clean the target filename (remove Windows " (1)" suffixes)
        # e.g., "Project tracking (1).pdf" -> "Project tracking.pdf"
        target_base = re.sub(r' \(\d+\)', '', filename).strip()

        for entry in reversed(entries):
            # Unquote URL-encoded spaces (e.g., %20) from the extension
            entry_filename = unquote(entry.get('filename', '')).strip()
            
            if not entry_filename:
                continue
                
            # Exact match first
            if entry_filename == filename:
                return entry.get('url', 'URL not captured')
                
            # Copy pattern match second
            entry_base = re.sub(r' \(\d+\)', '', entry_filename).strip()
            if entry_base == target_base:
                return entry.get('url', 'URL not captured')

        return 'URL not captured'
    except Exception as e:
        utils.log_error(f"get_url_for_file error looking up {filename}", e)
        return 'URL not captured'


# =============================================================================
# FUNCTION 3: start_url_server
# =============================================================================

def start_url_server():
    """
    Launch the Flask URL-capture server in a daemon background thread.

    Being a daemon thread it exits automatically when the main process ends.
    Returns the Thread object so the caller can inspect it if needed.
    """
    global _flask_thread, _server_running

    try:
        app = create_url_server_app()

        def _run():
            app.run(
                host='127.0.0.1',
                port=config.URL_SERVER_PORT,
                debug=False,
                use_reloader=False,
            )

        _flask_thread = threading.Thread(target=_run, daemon=True, name='URLCaptureServer')
        _flask_thread.start()
        _server_running = True
        print(f"URL capture server started on port {config.URL_SERVER_PORT}")
        utils.logger.info("URL capture server started on port %d", config.URL_SERVER_PORT)
        return _flask_thread
    except Exception as e:
        utils.log_error("start_url_server: failed to start server thread", e)
        return None


# =============================================================================
# FUNCTION 4: stop_url_server
# =============================================================================

def stop_url_server():
    """
    Log shutdown intent for the URL server.

    The daemon thread stops automatically when the main process exits.
    No explicit teardown is required, but this function provides a clean
    hook for logging and future graceful-shutdown integration.
    """
    global _server_running
    _server_running = False
    utils.logger.info("URL capture server shutdown requested (will stop with main process).")
    print("URL capture server shutdown requested.")


# =============================================================================
# Self-tests
# =============================================================================

if __name__ == '__main__':
    import time
    import requests as req

    PASS = '\033[92mPASS\033[0m'
    FAIL = '\033[91mFAIL\033[0m'

    print("\n" + "=" * 62)
    print("  Shadow-Trace url_server.py -- Self-Test Suite")
    print("=" * 62 + "\n")

    # ── Test 1: Start the server ─────────────────────────────────────────────
    print("TEST 1 -- Start URL capture server")
    try:
        thread = start_url_server()
        time.sleep(2)   # give Flask time to bind
        if thread and thread.is_alive():
            print("  Server thread alive: True")
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- thread not alive\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 2: POST /url_capture ────────────────────────────────────────────
    print("TEST 2 -- POST /url_capture")
    try:
        test_data = {
            'url':       'https://example.com/test_image.jpg',
            'filename':  'test_image.jpg',
            'timestamp': datetime.now().isoformat(),
        }
        resp = req.post(
            f'http://{config.URL_SERVER_HOST}:{config.URL_SERVER_PORT}/url_capture',
            json=test_data,
            timeout=5,
        )
        body = resp.json()
        print(f"  Capture response: {body}")
        if resp.status_code == 200 and body.get('status') == 'ok':
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- unexpected response\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 3: GET /get_url/<filename> ──────────────────────────────────────
    print("TEST 3 -- GET /get_url/test_image.jpg")
    try:
        resp = req.get(
            f'http://{config.URL_SERVER_HOST}:{config.URL_SERVER_PORT}/get_url/test_image.jpg',
            timeout=5,
        )
        body = resp.json()
        print(f"  Retrieved entry: {body}")
        if body.get('url') == 'https://example.com/test_image.jpg':
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- URL mismatch\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 4: get_url_for_file() utility ───────────────────────────────────
    print("TEST 4 -- get_url_for_file() utility function")
    try:
        url = get_url_for_file('test_image.jpg')
        print(f"  Utility result: {url}")
        if url == 'https://example.com/test_image.jpg':
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- got: {url}\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    # ── Test 5: GET /health ───────────────────────────────────────────────────
    print("TEST 5 -- GET /health")
    try:
        resp = req.get(
            f'http://{config.URL_SERVER_HOST}:{config.URL_SERVER_PORT}/health',
            timeout=5,
        )
        body = resp.json()
        print(f"  Health response: {body}")
        if body.get('status') == 'running':
            print(f"  Result: {PASS}\n")
        else:
            print(f"  Result: {FAIL} -- unexpected status\n")
    except Exception as exc:
        print(f"  Result: {FAIL} -- {exc}\n")

    print("=" * 62)
    print("  All tests complete.")
    print("=" * 62 + "\n")
