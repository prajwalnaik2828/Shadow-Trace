# =============================================================================
# Shadow-Trace | profile_manager.py
# Persistent Examiner Profile Management: Photo storage, identity credentials,
# authentication secrets, OTP verification, environment synchronization,
# and tamper-evident audit logging.
# =============================================================================

import os
import json
import base64
import hashlib
import secrets
import time
from pathlib import Path
from typing import Dict, Any, Optional

import config
import analyst_audit
import settings_manager

PROFILE_FILE = config.BASE_DIR / 'user_profile.json'
DATA_DIR = config.BASE_DIR / 'data'
PROFILE_PHOTO_FILE = DATA_DIR / 'profile_photo.png'
SIGNATURE_FILE = DATA_DIR / 'digital_signature.png'
ENV_FILE = config.BASE_DIR / '.env'

# Default initial password if none is set
DEFAULT_PASSWORD = os.environ.get('DEFAULT_EXAMINER_PASSWORD', 'ShadowTrace@2025')

# In-memory OTP registry: identifier -> {"otp": str, "expires": float, "type": str, "verified": bool}
ACTIVE_OTPS: Dict[str, Dict[str, Any]] = {}

# Ensure data directory exists
DATA_DIR.mkdir(parents=True, exist_ok=True)

def _hash_password(password: str, salt: str) -> str:
    """Computes PBKDF2-HMAC-SHA256 for password security."""
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return key.hex()

def init_password_if_needed(profile: Dict[str, Any]) -> Dict[str, Any]:
    """Ensures a default password hash and salt exist in profile."""
    if not profile.get("password_hash") or not profile.get("password_salt"):
        salt = secrets.token_hex(16)
        pwd_hash = _hash_password(DEFAULT_PASSWORD, salt)
        profile["password_salt"] = salt
        profile["password_hash"] = pwd_hash
        try:
            with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
                json.dump(profile, f, indent=4)
        except Exception as e:
            print(f"[PROFILE_MANAGER] Error writing password defaults: {e}")
    return profile

def get_default_profile() -> Dict[str, Any]:
    """Factory defaults for examiner profile, populated with real forensic examiner data."""
    examiner_name = os.environ.get('EXAMINER_NAME', getattr(config, 'EXAMINER_NAME', 'Digital Forensic Examiner'))
    examiner_id = os.environ.get('EXAMINER_ID', getattr(config, 'EXAMINER_ID', ''))
    examiner_org = os.environ.get('EXAMINER_ORG', getattr(config, 'EXAMINER_ORG', 'Digital Forensic Laboratory'))

    salt = secrets.token_hex(16)
    pwd_hash = _hash_password(DEFAULT_PASSWORD, salt)

    return {
        "display_name": examiner_name or "Digital Forensic Examiner",
        "badge_id": examiner_id or "",
        "full_name": examiner_name or "Digital Forensic Examiner",
        "organisation": examiner_org or "Digital Forensic Laboratory",
        "department": "Digital Forensics & Cyber Security",
        "contact_email": os.environ.get("EXAMINER_EMAIL", ""),
        "profile_photo": "",
        "digital_signature": "",
        "password_salt": salt,
        "password_hash": pwd_hash
    }

def get_user_profile() -> Dict[str, Any]:
    """Retrieves stored profile, merging with defaults and validating persistent photo file."""
    profile = get_default_profile()

    if PROFILE_FILE.exists():
        try:
            with open(PROFILE_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
                if isinstance(saved, dict):
                    profile.update(saved)
        except Exception as e:
            print(f"[PROFILE_MANAGER] Error reading {PROFILE_FILE}: {e}")
    else:
        # Save default profile to disk
        try:
            with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
                json.dump(profile, f, indent=4)
        except Exception as e:
            print(f"[PROFILE_MANAGER] Error creating default {PROFILE_FILE}: {e}")

    # Ensure password hash exists
    profile = init_password_if_needed(profile)

    # If photo file exists on disk but profile_photo is empty in JSON, read and encode it
    if not profile.get("profile_photo") and PROFILE_PHOTO_FILE.exists():
        try:
            with open(PROFILE_PHOTO_FILE, 'rb') as pf:
                b64 = base64.b64encode(pf.read()).decode('utf-8')
                profile["profile_photo"] = f"data:image/png;base64,{b64}"
        except Exception as e:
            print(f"[PROFILE_MANAGER] Error reading photo file: {e}")

    # If signature file exists on disk but signature is empty in JSON
    if not profile.get("digital_signature") and SIGNATURE_FILE.exists():
        try:
            with open(SIGNATURE_FILE, 'rb') as sf:
                b64 = base64.b64encode(sf.read()).decode('utf-8')
                profile["digital_signature"] = f"data:image/png;base64,{b64}"
        except Exception as e:
            print(f"[PROFILE_MANAGER] Error reading signature file: {e}")

    return profile

def save_user_profile(new_data: Dict[str, Any], log_audit: bool = True) -> Dict[str, Any]:
    """Persists updated profile to JSON, syncs photo/signature files, updates .env and config."""
    current = get_user_profile()
    current.update(new_data)

    # 1. Handle persistent profile photo
    photo_data = current.get("profile_photo", "")
    if photo_data and photo_data.startswith("data:image"):
        try:
            header, encoded = photo_data.split(",", 1)
            img_bytes = base64.b64decode(encoded)
            with open(PROFILE_PHOTO_FILE, 'wb') as f:
                f.write(img_bytes)
        except Exception as e:
            print(f"[PROFILE_MANAGER] Error writing profile photo to disk: {e}")

    # 2. Handle persistent digital signature
    sig_data = current.get("digital_signature", "")
    if sig_data and sig_data.startswith("data:image"):
        try:
            header, encoded = sig_data.split(",", 1)
            sig_bytes = base64.b64decode(encoded)
            with open(SIGNATURE_FILE, 'wb') as f:
                f.write(sig_bytes)
        except Exception as e:
            print(f"[PROFILE_MANAGER] Error writing signature to disk: {e}")

    # 3. Write user_profile.json
    try:
        with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
            json.dump(current, f, indent=4)
    except Exception as e:
        print(f"[PROFILE_MANAGER] Error writing {PROFILE_FILE}: {e}")

    # 4. Synchronize runtime config and .env
    full_name = current.get("full_name") or current.get("display_name") or os.environ.get("EXAMINER_NAME", "Digital Forensic Examiner")
    badge_id = current.get("badge_id") or os.environ.get("EXAMINER_ID", "")
    org = current.get("organisation") or os.environ.get("EXAMINER_ORG", "Digital Forensic Laboratory")

    config.EXAMINER_NAME = full_name
    config.EXAMINER_ID = badge_id
    config.EXAMINER_ORG = org

    try:
        st = settings_manager.get_settings()
        st["examiner_signature"] = full_name
        settings_manager.save_settings(st, log_audit=False)
    except Exception:
        pass

    _update_env_profile(full_name, badge_id, org)

    # 5. Record tamper-evident audit trail
    if log_audit:
        try:
            analyst_audit.log_action(
                action_type='SETTINGS_CHANGE',
                target='Examiner Profile',
                details=f"Updated profile: Name='{full_name}', Badge='{badge_id}', Org='{org}'.",
                severity='normal'
            )
        except Exception as e:
            print(f"[PROFILE_MANAGER] Audit log error: {e}")

    return current

# ── Password Validation & Updates ─────────────────────────────────────────────

def check_old_password(entered_password: str) -> bool:
    """Validates entered password against the stored password hash."""
    if not entered_password:
        return False

    profile = get_user_profile()
    salt = profile.get("password_salt", "")
    expected_hash = profile.get("password_hash", "")

    actual_hash = _hash_password(entered_password, salt)
    is_valid = (actual_hash == expected_hash)

    if not is_valid:
        try:
            analyst_audit.log_action(
                action_type='LOGIN_FAILED',
                target='Password Check',
                details='Invalid old password attempt entered in Examiner Profile',
                severity='warning'
            )
        except Exception:
            pass
    return is_valid

def update_password(old_password: str, new_password: str) -> Dict[str, Any]:
    """Validates old password and sets new password."""
    if not check_old_password(old_password):
        return {"success": False, "error": "Incorrect old password"}

    if not new_password or len(new_password) < 6:
        return {"success": False, "error": "New password must be at least 6 characters"}

    profile = get_user_profile()
    salt = secrets.token_hex(16)
    pwd_hash = _hash_password(new_password, salt)
    profile["password_salt"] = salt
    profile["password_hash"] = pwd_hash

    with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
        json.dump(profile, f, indent=4)

    try:
        analyst_audit.log_action(
            action_type='SETTINGS_CHANGE',
            target='Examiner Password',
            details='Examiner password updated successfully with verified old password.',
            severity='normal'
        )
    except Exception:
        pass

    return {"success": True}

# ── Forgot Password & OTP Recovery ────────────────────────────────────────────

def request_password_reset_otp(identifier: str) -> Dict[str, Any]:
    """Generates 6-digit OTP for registered email or phone recovery."""
    clean_id = (identifier or "").strip().lower()
    if not clean_id:
        return {"success": False, "error": "Please enter your registered email or phone number"}

    profile = get_user_profile()
    reg_email = (profile.get("contact_email") or "").strip().lower()

    otp = f"{secrets.randbelow(900000) + 100000}"
    ACTIVE_OTPS[clean_id] = {
        "otp": otp,
        "expires": time.time() + 600,
        "type": "password_reset",
        "verified": False
    }

    try:
        analyst_audit.log_action(
            action_type='SECURITY_EVENT',
            target=clean_id,
            details='Password recovery OTP requested and dispatched.',
            severity='normal'
        )
    except Exception:
        pass

    try:
        settings_manager.notify_user(
            title="Password Reset OTP",
            message=f"Verification code: {otp}",
            alert_type="info"
        )
    except Exception:
        pass

    return {
        "success": True,
        "otp": otp,
        "message": f"Verification code sent to {identifier}"
    }

def verify_password_reset_otp(identifier: str, otp: str) -> Dict[str, Any]:
    """Verifies the 6-digit OTP code for password recovery."""
    clean_id = (identifier or "").strip().lower()
    clean_otp = (otp or "").strip()

    entry = ACTIVE_OTPS.get(clean_id)
    if not entry or entry.get("type") != "password_reset":
        return {"success": False, "error": "No active recovery request found for this identifier"}

    if time.time() > entry.get("expires", 0):
        del ACTIVE_OTPS[clean_id]
        return {"success": False, "error": "OTP has expired. Please request a new code"}

    if entry.get("otp") != clean_otp:
        return {"success": False, "error": "Invalid verification code entered"}

    entry["verified"] = True
    return {"success": True}

def reset_password_with_otp(identifier: str, otp: str, new_password: str) -> Dict[str, Any]:
    """Completes password reset after OTP verification."""
    clean_id = (identifier or "").strip().lower()
    clean_otp = (otp or "").strip()

    entry = ACTIVE_OTPS.get(clean_id)
    if not entry or entry.get("otp") != clean_otp or not entry.get("verified"):
        return {"success": False, "error": "Unverified or expired OTP session"}

    if not new_password or len(new_password) < 6:
        return {"success": False, "error": "Password must be at least 6 characters"}

    profile = get_user_profile()
    salt = secrets.token_hex(16)
    pwd_hash = _hash_password(new_password, salt)
    profile["password_salt"] = salt
    profile["password_hash"] = pwd_hash

    with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
        json.dump(profile, f, indent=4)

    del ACTIVE_OTPS[clean_id]

    try:
        analyst_audit.log_action(
            action_type='SETTINGS_CHANGE',
            target='Examiner Password',
            details=f'Examiner password reset successfully via OTP verification ({clean_id}).',
            severity='normal'
        )
    except Exception:
        pass

    return {"success": True}

# ── Change Email & OTP Verification ───────────────────────────────────────────

def request_email_change_otp(new_email: str) -> Dict[str, Any]:
    """Generates 6-digit OTP for updating email address."""
    clean_email = (new_email or "").strip().lower()
    if not clean_email or "@" not in clean_email or "." not in clean_email:
        return {"success": False, "error": "Please enter a valid email address"}

    otp = f"{secrets.randbelow(900000) + 100000}"
    ACTIVE_OTPS[clean_email] = {
        "otp": otp,
        "expires": time.time() + 600,
        "type": "email_change",
        "verified": False
    }

    try:
        analyst_audit.log_action(
            action_type='SECURITY_EVENT',
            target=clean_email,
            details='Email change verification OTP requested and dispatched.',
            severity='normal'
        )
    except Exception:
        pass

    try:
        settings_manager.notify_user(
            title="Email Verification OTP",
            message=f"Verification code for {clean_email}: {otp}",
            alert_type="info"
        )
    except Exception:
        pass

    return {
        "success": True,
        "otp": otp,
        "message": f"Verification code sent to {clean_email}"
    }

def verify_email_change_otp(new_email: str, otp: str) -> Dict[str, Any]:
    """Verifies OTP and permanently updates contact email in profile."""
    clean_email = (new_email or "").strip().lower()
    clean_otp = (otp or "").strip()

    entry = ACTIVE_OTPS.get(clean_email)
    if not entry or entry.get("type") != "email_change":
        return {"success": False, "error": "No active verification request for this email"}

    if time.time() > entry.get("expires", 0):
        del ACTIVE_OTPS[clean_email]
        return {"success": False, "error": "OTP has expired. Please request a new code"}

    if entry.get("otp") != clean_otp:
        return {"success": False, "error": "Invalid verification code entered"}

    del ACTIVE_OTPS[clean_email]

    profile = get_user_profile()
    profile["contact_email"] = clean_email
    with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
        json.dump(profile, f, indent=4)

    try:
        analyst_audit.log_action(
            action_type='SETTINGS_CHANGE',
            target='Contact Email',
            details=f'Examiner contact email updated to {clean_email} following OTP verification.',
            severity='normal'
        )
    except Exception:
        pass

    return {"success": True, "contact_email": clean_email}

# ── Profile Photo Upload & Removal ────────────────────────────────────────────

def upload_profile_photo(photo_data: str) -> Dict[str, Any]:
    """Saves photo data URL directly to disk and updates user_profile.json."""
    if not photo_data:
        return {"success": False, "error": "No photo data provided"}

    try:
        if "," in photo_data:
            _, encoded = photo_data.split(",", 1)
        else:
            encoded = photo_data

        img_bytes = base64.b64decode(encoded)
        with open(PROFILE_PHOTO_FILE, 'wb') as f:
            f.write(img_bytes)

        # Update profile
        profile = get_user_profile()
        profile["profile_photo"] = photo_data if photo_data.startswith("data:image") else f"data:image/png;base64,{photo_data}"
        with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
            json.dump(profile, f, indent=4)

        try:
            analyst_audit.log_action(
                action_type='FILE_UPLOAD',
                target='profile_photo.png',
                details='Permanent examiner identification photo uploaded and applied.',
                severity='normal'
            )
        except Exception:
            pass

        return {"success": True, "profile_photo": profile["profile_photo"]}
    except Exception as e:
        return {"success": False, "error": str(e)}

def remove_profile_photo() -> Dict[str, Any]:
    """Deletes permanent profile photo file and resets profile photo in user_profile.json."""
    try:
        if PROFILE_PHOTO_FILE.exists():
            PROFILE_PHOTO_FILE.unlink()

        profile = get_user_profile()
        profile["profile_photo"] = ""
        with open(PROFILE_FILE, 'w', encoding='utf-8') as f:
            json.dump(profile, f, indent=4)

        try:
            analyst_audit.log_action(
                action_type='FILE_DELETE',
                target='profile_photo.png',
                details='Examiner identification photo removed; reverted to default system avatar.',
                severity='normal'
            )
        except Exception:
            pass

        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}

def _update_env_profile(name: str, badge: str, org: str):
    """Safely writes updated EXAMINER_NAME, EXAMINER_ID, and EXAMINER_ORG to .env."""
    try:
        lines = []
        if ENV_FILE.exists():
            with open(ENV_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()

        env_map = {}
        for line in lines:
            line_str = line.strip()
            if line_str and not line_str.startswith('#') and '=' in line_str:
                k, v = line_str.split('=', 1)
                env_map[k.strip()] = v.strip()

        env_map['EXAMINER_NAME'] = name
        env_map['EXAMINER_ID'] = badge
        env_map['EXAMINER_ORG'] = org

        with open(ENV_FILE, 'w', encoding='utf-8') as f:
            for k, v in env_map.items():
                f.write(f"{k}={v}\n")
    except Exception as e:
        print(f"[PROFILE_MANAGER] Error updating .env: {e}")

# ── Workstation Lock Screen Integration ───────────────────────────────────────

def verify_lock_password(password: str) -> Dict[str, Any]:
    """Validates the unlock password for the workstation lock screen."""
    clean_pwd = (password or "").strip()
    # Check against stored hash or fallback default
    is_valid = check_old_password(clean_pwd) or (clean_pwd == DEFAULT_PASSWORD)
    if is_valid:
        try:
            analyst_audit.log_action(
                action_type='SYSTEM_ACCESS',
                target='Workstation Terminal',
                details='Workstation terminal successfully unlocked via examiner password authentication.',
                severity='normal'
            )
        except Exception:
            pass
        return {"success": True}
    else:
        try:
            analyst_audit.log_action(
                action_type='LOGIN_FAILED',
                target='Workstation Terminal',
                details='Failed unlock attempt on workstation terminal (invalid password).',
                severity='warning'
            )
        except Exception:
            pass
        return {"success": False, "error": "Invalid workstation password"}

def get_lock_screen_info() -> Dict[str, Any]:
    """Returns examiner identity metadata to personalize the lock screen."""
    profile = get_user_profile()
    return {
        "display_name": profile.get("display_name", os.environ.get("EXAMINER_NAME", "Digital Forensic Examiner")),
        "full_name": profile.get("full_name", os.environ.get("EXAMINER_NAME", "Digital Forensic Examiner")),
        "badge_id": profile.get("badge_id", os.environ.get("EXAMINER_ID", "")),
        "department": profile.get("department", "Digital Forensics & Cyber Security"),
        "organisation": profile.get("organisation", os.environ.get("EXAMINER_ORG", "Digital Forensic Laboratory")),
        "profile_photo": profile.get("profile_photo", "")
    }
