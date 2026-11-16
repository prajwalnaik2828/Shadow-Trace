import os
import json
import time
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional

import config

STATUS_FILE = config.BASE_DIR / 'logs' / 'scan_status.json'
_lock = threading.RLock()

_default_state: Dict[str, Any] = {
    "active": False,
    "filename": "",
    "filepath": "",
    "stage": 0,           # 1: Initialization, 2: Signature Analysis, 3: Heuristic Scanning, 4: Steganography Detection, 5: Report Generation
    "stage_name": "",     # e.g. "Initialization", "Signature Analysis", etc.
    "progress": 0,        # 0 to 100
    "queue": []           # list of dicts: [{"filename": "...", "path": "..."}]
}

_memory_state: Dict[str, Any] = dict(_default_state)
_memory_state["queue"] = []

def _write_state():
    try:
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_file = STATUS_FILE.with_suffix('.json.tmp')
        with open(tmp_file, 'w', encoding='utf-8') as f:
            json.dump(_memory_state, f, indent=2)
        os.replace(tmp_file, STATUS_FILE)
    except Exception as e:
        pass

def get_status() -> Dict[str, Any]:
    global _memory_state
    with _lock:
        if STATUS_FILE.exists():
            try:
                with open(STATUS_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        _memory_state = data
                        return dict(_memory_state)
            except Exception:
                pass
        return dict(_memory_state)

def reset():
    global _memory_state
    with _lock:
        _memory_state = {
            "active": False,
            "filename": "",
            "filepath": "",
            "stage": 0,
            "stage_name": "",
            "progress": 0,
            "queue": []
        }
        _write_state()

def enqueue(filepath: str) -> bool:
    """
    Enqueues a file.
    Returns True if this file should be started immediately as the active scan.
    Returns False if a scan is already active and this file was queued.
    """
    global _memory_state
    with _lock:
        current = get_status()
        p = Path(filepath)
        filename = p.name
        
        # Don't duplicate in queue if already active or queued
        if current.get("active") and current.get("filepath") == str(filepath):
            return False
        
        queue = current.get("queue", [])
        if any(item.get("path") == str(filepath) for item in queue):
            return False

        if not current.get("active"):
            # Start scan immediately
            _memory_state["active"] = True
            _memory_state["filename"] = filename
            _memory_state["filepath"] = str(filepath)
            _memory_state["stage"] = 1
            _memory_state["stage_name"] = "Initialization"
            _memory_state["progress"] = 15
            _memory_state["queue"] = queue
            _write_state()
            return True
        else:
            # Add to waiting queue
            queue.append({
                "filename": filename,
                "path": str(filepath)
            })
            _memory_state["queue"] = queue
            _write_state()
            return False

def update_stage(stage: int, stage_name: str = "", progress: Optional[int] = None):
    """
    Updates the stage of the currently active scan.
    Stages:
      1: Initialization (15%)
      2: Signature Analysis (35%)
      3: Heuristic Scanning (55%)
      4: Steganography Detection (75%)
      5: Report Generation (95%)
    """
    global _memory_state
    stage_defaults = {
        1: ("Initialization", 15),
        2: ("Signature Analysis", 35),
        3: ("Heuristic Scanning", 55),
        4: ("Steganography Detection", 75),
        5: ("Report Generation", 95)
    }
    
    with _lock:
        get_status()
        if not _memory_state.get("active"):
            return
            
        def_name, def_prog = stage_defaults.get(stage, ("", 0))
        _memory_state["stage"] = stage
        _memory_state["stage_name"] = stage_name or def_name
        _memory_state["progress"] = progress if progress is not None else def_prog
        _write_state()

def finish_scan(filepath: str = "") -> Optional[str]:
    """
    Marks the current scan finished.
    If items remain in queue, pops the next item and sets it as active, returning its filepath.
    If queue is empty, sets active = False and returns None.
    """
    global _memory_state
    with _lock:
        get_status()
        queue = _memory_state.get("queue", [])
        
        # Remove filepath from queue if present
        if filepath:
            queue = [q for q in queue if q.get("path") != filepath]
            
        if queue:
            next_item = queue.pop(0)
            _memory_state["active"] = True
            _memory_state["filename"] = next_item.get("filename", "")
            _memory_state["filepath"] = next_item.get("path", "")
            _memory_state["stage"] = 1
            _memory_state["stage_name"] = "Initialization"
            _memory_state["progress"] = 15
            _memory_state["queue"] = queue
            _write_state()
            return next_item.get("path")
        else:
            _memory_state["active"] = False
            _memory_state["filename"] = ""
            _memory_state["filepath"] = ""
            _memory_state["stage"] = 0
            _memory_state["stage_name"] = ""
            _memory_state["progress"] = 0
            _memory_state["queue"] = []
            _write_state()
            return None
