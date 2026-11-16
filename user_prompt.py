import tkinter as tk
from tkinter import messagebox
from pathlib import Path
import threading

def ask_user_steg_scan(filename: str, file_type: str,
                        model_name: str) -> bool:
    """
    Show a Windows dialog asking if user wants full
    steganalysis. Returns True if yes, False if no.
    Runs in a separate thread to not block the pipeline.

    file_type: 'IMAGE', 'VIDEO', or 'DOCUMENT'
    model_name: human readable model description
    """
    result = {'choice': False}

    def show_dialog():
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        type_descriptions = {
            'IMAGE':    'YedroudjNetV3 + ALASKA2 + Chi-Square + RS Analysis',
            'VIDEO':    'VideoStegNet Four-Stream (Spatial + Temporal + DCT + Flow)',
            'DOCUMENT': 'DistilBERT Hybrid + Structural + Entropy + Unicode Scan',
        }
        model_desc = type_descriptions.get(
            file_type.upper(),
            model_name
        )

        message = (
            f"Shadow-Trace: File Scan Complete\n\n"
            f"File: {filename}\n"
            f"Type: {file_type}\n"
            f"Result: Clean (no malware, no LSB executable)\n\n"
            f"Would you like a full steganography scan?\n\n"
            f"Analysis engine: {model_desc}\n\n"
            f"Yes = Run full steganalysis (takes 5-15 seconds)\n"
            f"No  = Release file for normal use"
        )

        choice = messagebox.askyesno(
            title="Shadow-Trace: Full Scan?",
            message=message,
            icon='question'
        )
        result['choice'] = choice
        root.destroy()

    dialog_thread = threading.Thread(target=show_dialog)
    dialog_thread.start()
    dialog_thread.join(timeout=60)
    return result['choice']


def notify_steg_result(filename: str,
                        verdict: str,
                        score: float,
                        confidence_tier: str):
    """
    Show result notification after steganalysis completes.
    Non-blocking — fires and forgets.
    """
    def show():
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)

        icons = {
            'STEGO_DETECTED': 'warning',
            'SUSPICIOUS':     'warning',
            'CLEAN':          'info',
            'ERROR':          'error',
        }
        icon = icons.get(verdict, 'info')

        if verdict == 'STEGO_DETECTED':
            title = 'Shadow-Trace: STEGANOGRAPHY DETECTED'
            msg = (
                f"Hidden content detected in: {filename}\n\n"
                f"Verdict:    {verdict}\n"
                f"Confidence: {confidence_tier}\n"
                f"Score:      {score:.4f}\n\n"
                f"File remains locked pending investigation.\n"
                f"Check the forensic report for details."
            )
        elif verdict == 'SUSPICIOUS':
            title = 'Shadow-Trace: Suspicious File'
            msg = (
                f"Suspicious patterns in: {filename}\n\n"
                f"Verdict:    {verdict}\n"
                f"Confidence: {confidence_tier}\n"
                f"Score:      {score:.4f}\n\n"
                f"Recommend manual review."
            )
        else:
            title = 'Shadow-Trace: Scan Complete'
            msg = (
                f"File: {filename}\n\n"
                f"Verdict:    {verdict}\n"
                f"Score:      {score:.4f}\n\n"
                f"No steganography detected."
            )

        messagebox.showinfo(title=title, message=msg,
                           icon=icon)
        root.destroy()

    t = threading.Thread(target=show, daemon=True)
    t.start()


def format_quarantine_reason(threat_info: dict) -> str:
    """Format a human-readable explanation of why a file was quarantined."""
    if not threat_info:
        return "File flagged as malicious or anomalous during forensic screening."
    if not isinstance(threat_info, dict):
        return str(threat_info)

    engine = threat_info.get('engine', threat_info.get('detecting_engine', ''))

    # ClamAV
    if 'clamav' in str(engine).lower() or threat_info.get('detecting_stage') == 'STAGE3_CLAMAV':
        threat_name = threat_info.get('threat_name') or threat_info.get('malware_name') or 'Malware signature'
        return f"ClamAV detected known malware signature: {threat_name}"

    # YARA
    if 'yara' in str(engine).lower() or threat_info.get('detecting_stage') == 'STAGE3_YARA':
        rules = threat_info.get('matched_rules') or threat_info.get('rules') or threat_info.get('threat_name') or []
        if isinstance(rules, list):
            rules_str = ", ".join(str(r) for r in rules) if rules else "Malicious pattern"
        else:
            rules_str = str(rules)
        return f"YARA rules matched malicious pattern(s): {rules_str}"

    # VirusTotal
    if 'virustotal' in str(engine).lower() or threat_info.get('detecting_stage') == 'STAGE4_CLOUD':
        threat_name = threat_info.get('most_common_threat_name') or threat_info.get('threat_name') or 'Malicious'
        positives = threat_info.get('positives', threat_info.get('malicious_count', 'Multiple'))
        return f"VirusTotal cloud intelligence flagged threat ({positives} vendors confirmed): {threat_name}"

    # Heuristics
    if 'heuristic' in str(engine).lower() or threat_info.get('detecting_stage') == 'STAGE3_HEURISTICS':
        reason = threat_info.get('reason') or threat_info.get('threat_name') or 'High entropy / structural anomaly'
        return f"Heuristic analysis detected anomaly: {reason}"

    # Stego / Payload
    if 'steg' in str(engine).lower() or 'layer2' in str(engine).lower():
        verdict = threat_info.get('verdict', 'STEGO_DETECTED')
        score = threat_info.get('score')
        score_str = f" (Confidence Score: {score})" if score is not None else ""
        return f"Steganography detection flagged carrier as {verdict}{score_str} with hidden payload."

    # MIME / Hash / Reason field
    if threat_info.get('status') == 'MISMATCH':
        return "File integrity reconfirmation failed: hash mismatch detected during processing."
    if 'reason' in threat_info:
        return str(threat_info['reason'])
    if 'threat_name' in threat_info:
        return f"Threat identified: {threat_info['threat_name']}"

    return "Malicious or suspicious artifact flagged by security engine."


def notify_error_popup(title: str,
                       reason: str,
                       filename: str = "",
                       stage: str = ""):
    """
    Show an immediate, non-blocking pop-up error dialog to the user
    explaining exactly why a scan or pipeline error occurred.
    """
    def show():
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)

            # Play alert sound
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONHAND)
            except Exception:
                pass

            msg_lines = [
                "AN ERROR OCCURRED DURING ANALYSIS:\n"
            ]
            if filename:
                msg_lines.append(f"Target File: {filename}")
            if stage:
                msg_lines.append(f"Pipeline Stage: {stage}")
            msg_lines.append(f"\nReason / Error Details:\n{reason}")
            msg_lines.append("\nSafety Status: File lock released. Original evidence remains intact.")

            full_msg = "\n".join(msg_lines)
            dialog_title = f"Shadow-Trace: {title}"

            messagebox.showerror(title=dialog_title, message=full_msg, parent=root)
            root.destroy()
        except Exception as err:
            print(f"[POPUP-ERROR] Failed to show error dialog: {err}")

    t = threading.Thread(target=show, daemon=True)
    t.start()


def notify_quarantine_popup(filename: str,
                            reason: str,
                            threat_info: dict = None,
                            quarantine_path: str = ""):
    """
    Show an immediate, non-blocking pop-up notification dialog
    explaining why a file was quarantined and where it was moved.
    """
    def show():
        try:
            root = tk.Tk()
            root.withdraw()
            root.attributes('-topmost', True)

            # Play alert sound
            try:
                import winsound
                winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
            except Exception:
                pass

            engine = ""
            if threat_info and isinstance(threat_info, dict):
                engine = threat_info.get('engine', threat_info.get('detecting_engine', ''))

            msg_lines = [
                "SECURITY ALERT: File Quarantined to Vault\n",
                f"File: {filename}"
            ]
            if engine:
                msg_lines.append(f"Detecting Engine: {engine}")
            msg_lines.append(f"\nReason for Quarantine:\n{reason}")
            if quarantine_path:
                msg_lines.append(f"\nVault Location:\n{quarantine_path}")
            msg_lines.append("\nThe threat has been isolated in the encrypted quarantine vault.")

            full_msg = "\n".join(msg_lines)
            dialog_title = "Shadow-Trace: Threat Quarantined"

            messagebox.showwarning(title=dialog_title, message=full_msg, parent=root)
            root.destroy()
        except Exception as err:
            print(f"[POPUP-QUARANTINE] Failed to show quarantine dialog: {err}")

    t = threading.Thread(target=show, daemon=True)
    t.start()


if __name__ == '__main__':
    print('Testing user_prompt.py...')
    choice = ask_user_steg_scan(
        'test_image.jpg', 'IMAGE', 'YedroudjNetV3'
    )
    print(f'User chose: {"YES - run scan" if choice else "NO - skip scan"}')
    if choice:
        notify_steg_result(
            'test_image.jpg', 'CLEAN', 0.12, 'CLEAN'
        )
    print('Test complete')
