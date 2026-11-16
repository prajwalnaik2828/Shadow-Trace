import os
import datetime
import numpy as np
import torch
import torch.nn as nn
from pathlib import Path
from typing import Dict, Any, Optional, Tuple, List
from PIL import Image
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.cm as cm

import config
import utils

YARA_RULE_EXPLANATIONS = {
    'Big_Numbers1': (
        'The scanner found large, unusual numbers hidden inside the file. '
        'While normal files sometimes have these, hackers often use them to hide '
        'malicious computer code.'
    ),
    'Big_Numbers2': (
        'The scanner found multiple hidden large numbers in the file. '
        'This is a common trick used by attackers to hide passwords or '
        'disguise their viruses so antivirus programs cannot see them.'
    ),
    'invalid_trailer_structure': (
        'The file is not put together correctly. Its structure is broken '
        'or abnormal. This often happens when someone deliberately tampers '
        'with the file to sneak in hidden data.'
    ),
    'invalid_xref_numbers': (
        'The file\'s internal map (which tells the computer where to find things '
        'inside the file) is broken. Legitimate files almost never have this issue. '
        'This is a strong sign that the file has been modified to hide something.'
    ),
    'invalid_xref_entry': (
        'Some entries in the file\'s internal map are incorrect or corrupted. '
        'This usually means the file was messed with after it was created, '
        'often to insert hidden malicious content.'
    ),
    'suspicious_xref': (
        'The way this file is built is highly unusual and does not look like '
        'a normal file created by standard software.'
    ),
    'malformed_pdf': (
        'The structure of this PDF document is broken or incorrect. '
        'While occasionally caused by bad software, this is frequently a sign '
        'that the document was intentionally tampered with.'
    ),
    'pdf_with_embedded_exe': (
        'A hidden computer program (executable) was found inside this PDF. '
        'PDF documents should NEVER contain hidden programs. This is almost '
        'certainly a malicious attack waiting to run.'
    ),
    'pdf_javascript': (
        'JavaScript code was found hiding inside this PDF. '
        'Attackers frequently use hidden JavaScript to run viruses '
        'the moment you open the document.'
    ),
    'suspicious_lnk': (
        'The file contains patterns that look like a Windows shortcut. '
        'Hackers use shortcuts to trick your computer into running bad commands.'
    ),
    'ole_with_vba': (
        'Hidden Macro code was found in this Office document. '
        'Macros are small programs that run automatically and are one of '
        'the most common ways hackers infect computers with malware.'
    ),
    'powershell_download': (
        'The file contains instructions to secretly download things from the internet. '
        'This is a massive red flag. Malware uses this to silently download '
        'more viruses onto your computer.'
    ),
}

DEFAULT_YARA_EXPLANATION = (
    'The YARA security scanner flagged this file '
    'based on pattern matching rules. The specific '
    'pattern ({rule_name}) matched content within '
    'the file that security researchers have '
    'associated with potentially malicious activity.'
)

def explain_yara_rules(matched_rules: list,
                             warning_rules: list = None) -> list:
    explanations = []
    # Deduplicate rules while preserving order
    all_rules = []
    for r in matched_rules + (warning_rules or []):
        if r not in all_rules:
            all_rules.append(r)
            
    for rule in all_rules:
        explanation = YARA_RULE_EXPLANATIONS.get(
            rule,
            DEFAULT_YARA_EXPLANATION.format(rule_name=rule)
        )
        is_warning = rule in (warning_rules or []) and rule not in matched_rules
        explanations.append({
            'rule_name': rule,
            'explanation': explanation,
            'severity': 'WARNING' if is_warning else 'THREAT',
        })
    return explanations

def _load_model_for_gradcam():
    """
    Load the YedroudjNetV3 image model directly from disk.
    Returns (model, None) on success or (None, error_string) on failure.
    This avoids relying on the singleton from layer2_steganalysis which
    may not be initialised when Layer 4 runs.

    IMPORTANT: We must import model_architectures as a *module* (not just
    from-import specific names) so that it is registered in sys.modules.
    torch.load with weights_only=False uses pickle which looks up classes
    by their fully-qualified name (e.g. 'model_architectures.YedroudjNetV3').
    If 'model_architectures' is not in sys.modules, pickle raises
    "Can't get attribute 'YedroudjNetV3'".
    """
    import torch
    import sys
    model_path = config.MODELS_DIR / 'image_model.pth'
    if not model_path.exists():
        return None, 'image_model.pth not found at ' + str(model_path)
    try:
        # The model was saved from a Colab __main__ context, so pickle
        # stores the class path as '__main__.YedroudjNetV3'.  We must
        # inject the classes into __main__ *before* torch.load so pickle
        # can resolve the reference — this is the same approach used by
        # layer2_steganalysis._get_tier1a() which loads successfully.
        import sys
        from model_architectures import YedroudjNetV3, ConvBnRelu
        sys.modules['__main__'].YedroudjNetV3 = YedroudjNetV3
        sys.modules['__main__'].ConvBnRelu = ConvBnRelu
        model = torch.load(
            str(model_path),
            map_location=torch.device('cpu'),
            weights_only=False
        )
        model.eval()
        
        for attr in ['YedroudjNetV3', 'ConvBnRelu']:
            try:
                del sys.modules['__main__'].__dict__[attr]
            except Exception:
                pass
                
        return model, None
    except Exception as e:
        return None, str(e)


def generate_gradcam_heatmap(
    filepath: str,
    model: nn.Module = None,
    target_layer_name: str = 'group12'
) -> Dict[str, Any]:
    try:
        import torch

        # ── 0. Load model if not passed in ───────────────────────────────
        if model is None:
            model, load_error = _load_model_for_gradcam()
            if model is None:
                return {
                    'success': False,
                    'error': 'Model load failed: ' + str(load_error),
                    'heatmap_path': None
                }
        print('[GRAD-CAM] Model loaded successfully')
        print('[GRAD-CAM] Processing: ' + Path(filepath).name)

        # ── 1a. Resolve readable path (sandbox copy if original is locked) ──
        read_path = _find_readable_path(filepath)
        if read_path != filepath:
            print('[GRAD-CAM] Using sandbox copy: ' + Path(read_path).name)
        else:
            print('[GRAD-CAM] No sandbox copy found, trying original')
            print('[GRAD-CAM] WARNING: Original may be locked')

        # ── 1b. Load and pre-process image ──────────────────────────────
        img = Image.open(read_path).convert('YCbCr')
        y = img.split()[0].resize((256, 256), Image.BILINEAR)
        arr = np.array(y, dtype=np.float32)
        arr = (arr - 128.0) / 128.0
        tensor = torch.from_numpy(arr[np.newaxis, np.newaxis, :, :])
        tensor.requires_grad = True

        # ── 2. Find target layer with full fallback chain ──────────────────
        feature_maps = {}
        gradients = {}

        def forward_hook(module, input, output):
            feature_maps['target'] = output

        def backward_hook(module, grad_input, grad_output):
            gradients['target'] = grad_output[0]

        target_layer = None
        fallback_layers = ['group12', 'group11', 'group10', 'group9', 'gap', 'classifier']
        for layer_name in fallback_layers:
            for name, module in model.named_modules():
                if name == layer_name:
                    target_layer = module
                    target_layer_name = layer_name
                    break
            if target_layer is not None:
                break

        # Last resort: use the final Conv2d layer in the model
        if target_layer is None:
            for name, module in model.named_modules():
                if isinstance(module, torch.nn.Conv2d):
                    target_layer = module
                    target_layer_name = name
            if target_layer is None:
                return {
                    'success': False,
                    'error': 'No suitable target layer found in model',
                    'heatmap_path': None
                }

        print('[GRAD-CAM] Target layer: ' + target_layer_name)
        fh = target_layer.register_forward_hook(forward_hook)
        bh = target_layer.register_full_backward_hook(backward_hook)
        print('[GRAD-CAM] Hooks registered on: ' + target_layer_name)

        # ── 3. Forward + backward pass ─────────────────────────────────────
        model.eval()
        output = model(tensor)
        score = output.item()
        print('[GRAD-CAM] Forward pass complete, score: ' + str(round(score, 4)))

        model.zero_grad()
        output.backward()

        fh.remove()
        bh.remove()

        # ── 4. Compute Grad-CAM ────────────────────────────────────────────
        grads = gradients['target'].squeeze()
        fmaps = feature_maps['target'].squeeze()

        if grads.dim() == 3:
            weights = grads.mean(dim=(1, 2))
        else:
            weights = grads.mean()

        cam = torch.zeros(fmaps.shape[-2:])
        for i, w in enumerate(weights):
            if fmaps.dim() == 3:
                cam += w * fmaps[i]

        cam = torch.relu(cam)
        if cam.max() > 0:
            cam = cam / cam.max()

        cam_np = cam.detach().numpy()
        print('[GRAD-CAM] Heatmap computed, max activation: '
              + str(round(float(cam_np.max()), 4)))

        # ── 5. Resize heatmap to image size ───────────────────────────────
        from PIL import Image as PILImage
        cam_pil = PILImage.fromarray((cam_np * 255).astype(np.uint8))
        cam_resized = cam_pil.resize((256, 256), PILImage.BILINEAR)
        cam_final = np.array(cam_resized) / 255.0

        # ── 6. Overlay ────────────────────────────────────────────────────
        y_display = np.array(y, dtype=np.uint8)
        y_rgb = np.stack([y_display] * 3, axis=2)

        heatmap_colored = cm.jet(cam_final)[:, :, :3]
        heatmap_colored = (heatmap_colored * 255).astype(np.uint8)

        overlay = (
            0.6 * y_rgb.astype(float) +
            0.4 * heatmap_colored.astype(float)
        ).clip(0, 255).astype(np.uint8)

        # ── 7. ROI ────────────────────────────────────────────────────────
        threshold = 0.70
        hot_pixels = np.where(cam_final > threshold)
        if len(hot_pixels[0]) > 0:
            y1 = int(hot_pixels[0].min())
            y2 = int(hot_pixels[0].max())
            x1 = int(hot_pixels[1].min())
            x2 = int(hot_pixels[1].max())
            roi_coords = (x1, y1, x2, y2)
            roi_coverage = len(hot_pixels[0]) / (256 * 256)
        else:
            roi_coords = (0, 0, 256, 256)
            roi_coverage = 1.0

        # ── 8. Save figure ────────────────────────────────────────────────
        reports_dir = config.BASE_DIR / 'reports' / 'heatmaps'
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filepath).stem
        heatmap_path = reports_dir / (stem + '_gradcam.png')

        fig, axes = plt.subplots(1, 3, figsize=(15, 5))
        axes[0].imshow(y_rgb, cmap='gray')
        axes[0].set_title('Original Y Channel')
        axes[0].axis('off')

        im_heatmap = axes[1].imshow(cam_final, cmap='jet')
        axes[1].set_title('Grad-CAM Heatmap')
        axes[1].axis('off')
        plt.colorbar(im_heatmap, ax=axes[1])

        axes[2].imshow(overlay)
        axes[2].set_title('Overlay (Hot zones = suspicious)')
        axes[2].axis('off')

        plt.suptitle('Shadow-Trace Grad-CAM Analysis: ' + Path(filepath).name)
        plt.tight_layout()
        plt.savefig(str(heatmap_path), dpi=150, bbox_inches='tight')
        plt.close()
        print('[GRAD-CAM] Heatmap saved: ' + str(heatmap_path))

        # ── 9. Return ─────────────────────────────────────────────────────
        return {
            'success': True,
            'heatmap_path': str(heatmap_path),
            'roi_coords': roi_coords,
            'roi_coverage_pct': round(roi_coverage * 100, 2),
            'max_activation': round(float(cam_final.max()), 4),
            'mean_activation': round(float(cam_final.mean()), 4),
            'model_score': round(score, 4),
            'target_layer_used': target_layer_name,
            'error': None
        }
    except Exception as e:
        import traceback
        return {
            'success': False,
            'error': str(e) + '\n' + traceback.format_exc(),
            'heatmap_path': None
        }

def generate_video_gradcam(
    filepath: str,
    model: nn.Module
) -> Dict[str, Any]:
    try:
        import cv2

        # Resolve readable path (sandbox copy if original is locked)
        read_path = _find_readable_path(filepath)
        if read_path != filepath:
            print('[VIDEO-GRAD-CAM] Using sandbox copy: ' + Path(read_path).name)
        else:
            print('[VIDEO-GRAD-CAM] No sandbox copy found, trying original')

        cap = cv2.VideoCapture(read_path)
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        if total <= 16:
            indices = list(range(total))
        else:
            step = total // 16
            indices = [i * step for i in range(16)]
            
        spatial_encoder = model.spatial_stream
        if not hasattr(model, 'spatial_stream'):
            return {'success': False, 'error': 'Model has no spatial_stream'}
            
        frame_scores = []
        frame_arrays = []
        
        for idx in indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ret, frame = cap.read()
            if not ret: continue
            
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil = Image.fromarray(rgb).convert('YCbCr')
            y = pil.split()[0].resize((224,224), Image.BILINEAR)
            arr = np.array(y, dtype=np.float32)
            arr = (arr - 128.0) / 128.0
            tensor = torch.from_numpy(arr[np.newaxis, np.newaxis,:,:])
            
            with torch.no_grad():
                feat = spatial_encoder(tensor)
                score = float(feat.norm().item())
            frame_scores.append(score)
            frame_arrays.append(np.array(rgb))
        cap.release()
        
        if not frame_scores:
            return {'success': False, 'error': 'No frames could be read'}
            
        best_idx = int(np.argmax(frame_scores))
        best_frame = frame_arrays[best_idx]
        
        temp_path = config.BASE_DIR / 'sandbox' / 'temp_frame.png'
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        Image.fromarray(best_frame).save(str(temp_path))
        
        result = generate_gradcam_heatmap(str(temp_path), spatial_encoder, target_layer_name='group7')
        
        result['analysed_frame_index'] = best_idx
        result['total_frames_scored'] = len(frame_scores)
        result['frame_suspicion_scores'] = [round(s, 4) for s in frame_scores]
        
        if temp_path.exists():
            temp_path.unlink()
            
        return result
    except Exception as e:
        return {'success': False, 'error': str(e)}

def _find_readable_path(filepath: str) -> str:
    """Return a readable copy of filepath. Falls back to sandbox if original is locked."""
    if Path(filepath).exists():
        try:
            with open(filepath, 'rb') as f:
                f.read(1)
            return filepath  # Original is readable
        except (PermissionError, OSError):
            pass
    # Search sandbox for a copy of this file
    stem = Path(filepath).stem
    ext  = Path(filepath).suffix
    sandbox = config.SANDBOX_DIR
    if sandbox.exists():
        # scanopy_{timestamp}_{originalname}
        candidates = sorted(
            sandbox.glob(f'scanopy_*_{stem}{ext}'),
            key=lambda p: p.stat().st_mtime,
            reverse=True
        )
        for c in candidates:
            try:
                with open(str(c), 'rb') as f:
                    f.read(1)
                return str(c)
            except Exception:
                continue
        # Also try the quarantine dir
        quarantine = config.QUARANTINE_DIR
        if quarantine.exists():
            qcandidates = sorted(
                quarantine.glob(f'*_{stem}{ext}'),
                key=lambda p: p.stat().st_mtime,
                reverse=True
            )
            for c in qcandidates:
                try:
                    with open(str(c), 'rb') as f:
                        f.read(1)
                    return str(c)
                except Exception:
                    continue
    return filepath  # Return original even if locked; caller handles the exception

def generate_document_token_map(
    filepath, layer2_result=None
):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        
        stream2b = {}
        if layer2_result:
            stream2b = layer2_result.get(
                'stream2b_unicode', {}
            ) or {}
        
        zw_findings = stream2b.get(
            'zero_width_findings', {}
        ) or {}
        zw_total = stream2b.get('zero_width_total', 0) or 0
        cyrillic = stream2b.get('cyrillic_count', 0) or 0
        greek = stream2b.get('greek_count', 0) or 0
        double_sp = stream2b.get('double_spaces', 0) or 0
        
        fig, ax = plt.subplots(figsize=(14, 8))
        fig.patch.set_facecolor('#f8f9fa')
        ax.set_facecolor('#ffffff')
        
        zw_types = list(zw_findings.keys()) if zw_findings else []
        zw_counts = [zw_findings[k] for k in zw_types]
        
        if not zw_types:
            zw_types = [
                'ZERO_WIDTH_SPACE (U+200B)',
                'ZERO_WIDTH_NON_JOINER (U+200C)',
                'ZERO_WIDTH_JOINER (U+200D)',
                'LEFT_TO_RIGHT_MARK (U+200E)',
                'RIGHT_TO_LEFT_MARK (U+200F)',
                'BYTE_ORDER_MARK (U+FEFF)',
            ]
            zw_counts = [0] * len(zw_types)
        
        categories = (
            zw_types +
            [
                'Cyrillic Homoglyphs',
                'Greek Homoglyphs',
                'Double Spaces (whitespace stego)',
            ]
        )
        values = (
            zw_counts +
            [cyrillic, greek, double_sp]
        )
        
        colors = [
            '#e74c3c' if v > 0 else '#27ae60'
            for v in values
        ]
        
        bars = ax.barh(
            categories, values,
            color=colors, edgecolor='white',
            height=0.6
        )
        
        for bar, val in zip(bars, values):
            width = bar.get_width()
            ax.text(
                max(width + 0.05, 0.05),
                bar.get_y() + bar.get_height() / 2,
                str(int(val)) if val > 0 else 'None found',
                va='center', ha='left',
                fontsize=9, fontweight='bold',
                color='#2c3e50'
            )
        
        ax.set_xlabel(
            'Number of occurrences found in document',
            fontsize=10
        )
        ax.set_title(
            'Document Unicode Steganography Analysis\n'
            'Shows count of each type of hidden character '
            'found in the document\n'
            'Red bars = suspicious characters detected, '
            'Green = clean',
            fontsize=11, fontweight='bold',
            color='#2c3e50'
        )
        
        ax.set_xlim(0, max(max(values) + 2, 3))
        
        green_p = mpatches.Patch(
            color='#27ae60', label='Not detected (clean)'
        )
        red_p = mpatches.Patch(
            color='#e74c3c', label='Detected (suspicious)'
        )
        ax.legend(
            handles=[green_p, red_p],
            loc='lower right', fontsize=9
        )
        
        plt.tight_layout(pad=2.0)
        
        reports_dir = config.BASE_DIR / 'reports' / 'heatmaps'
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filepath).stem
        map_path = (
            reports_dir / (stem + '_token_map.png')
        )
        plt.savefig(
            str(map_path), dpi=150,
            bbox_inches='tight',
            facecolor=fig.get_facecolor()
        )
        plt.close('all')
        
        if map_path.exists():
            print('[TOKEN-MAP] Saved: '
                  + str(map_path.stat().st_size) + ' bytes')
        
        return {
            'success': True,
            'map_path': str(map_path),
            'zero_width_count': zw_total,
            'homoglyph_count': cyrillic + greek,
            'whitespace_count': double_sp,
            'text_length': stream2b.get('text_length', 0),
            'error': None
        }
        
    except Exception as e:
        import traceback
        utils.log_error(
            'generate_document_token_map: ' + str(e)
        )
        return {
            'success': False,
            'error': str(e) + '\n' + traceback.format_exc()
        }

def compute_feature_attribution(
    filepath: str,
    layer2_result: Dict,
    layer3_result: Dict
) -> Dict[str, Any]:
    try:
        file_type = layer2_result.get('file_type', 'IMAGE')
        
        if file_type == 'DOCUMENT':
            neural_score = layer2_result.get('neural_score') or 0.5
            stream1 = layer2_result.get('stream1_structural', {}).get('score', 0.0) or 0.0
            stream2b = layer2_result.get('stream2b_unicode', {}).get('score', 0.0) or 0.0
            stream3 = layer2_result.get('stream3_entropy', {}).get('score', 0.0) or 0.0
            stream4 = layer2_result.get('stream4_metadata', {}).get('score', 0.0) or 0.0
            
            attributions = {
                'DistilBERT Neural Model': round(neural_score * 0.45, 4),
                'PDF/DOCX Structure Audit': round(stream1 * 0.30, 4),
                'Unicode Stego Detection': round(stream2b * 0.25, 4),
                'Entropy Analysis': round(stream3 * 0.25, 4),
                'Metadata & Signature Check': round(stream4 * 0.20, 4),
            }
        elif file_type == 'VIDEO':
            video_score = layer2_result.get('score', 0.5)
            attributions = {
                'Spatial HPF Stream (LSB)': round(video_score * 0.30, 4),
                'Temporal BiLSTM Stream': round(video_score * 0.25, 4),
                'DCT Frequency Stream': round(video_score * 0.25, 4),
                'Optical Flow Stream': round(video_score * 0.20, 4),
            }
        else:
            # 1. Extract component scores
            tier1a_score = layer2_result.get('tier1a_yedroudj', {}).get('score', 0.5) or 0.5
            tier1b_score = layer2_result.get('tier1b_alaska2', {}).get('score', 0.5) or 0.5
            
            t3_stat = layer2_result.get('tier3_statistical', {})
            tier3_chi = t3_stat.get('chi_square', {}).get('score', 0.5) if isinstance(t3_stat, dict) else 0.5
            if not tier3_chi: tier3_chi = 0.5
            
            tier3_rs = t3_stat.get('rs_analysis', {}).get('score', 0.5) if isinstance(t3_stat, dict) else 0.5
            if not tier3_rs: tier3_rs = 0.5
            
            fusion_score = layer2_result.get('score', 0.5)
            
            # 2. Extract Layer 3 indicators
            extraction = layer3_result.get('extraction_results', {}) if layer3_result else {}
            payload_entropy = extraction.get('payload_entropy', 0.0) or 0.0
            is_executable = extraction.get('is_executable', False)
            
            adaptive = layer3_result.get('adaptive_analysis', {}) if layer3_result else {}
            adaptive_ratio = adaptive.get('modification_ratio', 0.0) or 0.0
            
            # 3. Build attribution scores dict
            attributions = {
                'YedroudjNetV3 (Spatial LSB)': round(tier1a_score * 0.30, 4),
                'ALASKA2 Model (Adaptive)': round(tier1b_score * 0.35, 4),
                'Chi-Square Attack': round(tier3_chi * 0.175, 4),
                'RS Analysis': round(tier3_rs * 0.175, 4),
                'Payload Entropy': round(min(1.0, payload_entropy / 8.0) * 0.15, 4),
                'DCT Adaptive Signature': round(adaptive_ratio * 0.20, 4),
                'Executable Payload Found': round(1.0 * 0.30 if is_executable else 0.0, 4),
            }
        
        # 4. Sort by contribution descending
        sorted_attributions = dict(
            sorted(attributions.items(), key=lambda x: x[1], reverse=True)
        )
        
        # 5. Generate bar chart
        reports_dir = config.BASE_DIR / 'reports' / 'heatmaps'
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filepath).stem
        chart_path = reports_dir / (stem + '_attribution.png')
        
        fig, ax = plt.subplots(figsize=(10, 6))
        names = list(sorted_attributions.keys())
        values = list(sorted_attributions.values())
        colours = ['red' if v > 0.15 else 'orange' if v > 0.08 else 'steelblue' for v in values]
        
        bars = ax.barh(names, values, color=colours)
        ax.set_xlabel('Attribution Score (contribution to verdict)')
        ax.set_title('Feature Attribution: ' + Path(filepath).name)
        ax.axvline(x=0.10, color='gray', linestyle='--', alpha=0.5, label='Decision threshold')
        ax.legend()
        plt.tight_layout()
        plt.savefig(str(chart_path), dpi=150, bbox_inches='tight')
        plt.close()
        
        # 6. Return dict
        return {
            'attributions': sorted_attributions,
            'chart_path': str(chart_path),
            'top_contributor': names[0] if names else 'Unknown',
            'top_score': values[0] if values else 0.0,
            'error': None
        }
    except Exception as e:
        return {'error': str(e), 'attributions': {}}

def generate_narrative(
    filepath: str,
    layer2_result: Dict,
    layer3_result: Dict,
    attribution_result: Dict
) -> str:
    try:
        # 1. Extract key facts
        filename = Path(filepath).name
        verdict = layer2_result.get('verdict', 'UNKNOWN')
        score = layer2_result.get('score', 0.0)
        confidence = layer2_result.get('confidence_tier', 'UNKNOWN')
        file_type = layer2_result.get('file_type', 'UNKNOWN')
        top_contributor = attribution_result.get('top_contributor', 'Unknown')
        
        extraction = layer3_result.get('extraction_results', {}) if layer3_result else {}
        payload_type = extraction.get('payload_type', 'Unknown')
        payload_entropy = extraction.get('payload_entropy', 0.0) or 0.0
        payload_size = extraction.get('payload_size_bytes', 0) or 0
        is_executable = extraction.get('is_executable', False)
        
        adaptive = layer3_result.get('adaptive_analysis', {}) if layer3_result else {}
        adaptive_detected = adaptive.get('adaptive_stego_detected', False)
        estimated_payload_kb = adaptive.get('estimated_payload_kb', 0)
        
        current_date_string = datetime.datetime.now().strftime('%Y-%m-%d')
        
        # 2. Build narrative sections
        narrative_parts = []
        
        opening = f"Shadow-Trace forensic analysis of the file {filename} was conducted on {current_date_string}. "
        
        if verdict == 'STEGO_DETECTED':
            opening += f"The analysis pipeline has determined with {confidence} confidence that this file contains hidden steganographic content. The composite threat score of {round(score*100, 1)}% exceeds the detection threshold. "
        elif verdict == 'SUSPICIOUS':
            opening += f"The analysis pipeline has flagged this file as suspicious with a composite score of {round(score*100, 1)}%. While steganography is not confirmed, anomalous statistical patterns were detected that warrant further investigation. "
        else:
            opening += "The analysis pipeline found no evidence of steganographic content in this file. "
            
        narrative_parts.append(opening)
        
        detection = f"The primary detection signal was generated by {top_contributor}. "
        narrative_parts.append(detection)
        
        # TIER DETAILS
        tier1a = layer2_result.get('tier1a_yedroudj')
        if tier1a and tier1a.get('score') is not None:
            narrative_parts.append(f"Spatial LSB analysis (YedroudjNetV3) yielded a score of {round(tier1a.get('score', 0)*100, 1)}%. ")
        
        tier1b = layer2_result.get('tier1b_alaska2')
        if tier1b and tier1b.get('score') is not None:
            narrative_parts.append(f"Adaptive steganography analysis (ALASKA2) yielded a score of {round(tier1b.get('score', 0)*100, 1)}%. ")
            
        t3_stat = layer2_result.get('tier3_statistical')
        if isinstance(t3_stat, dict):
            chi = t3_stat.get('chi_square')
            if chi and chi.get('score') is not None:
                narrative_parts.append(f"Chi-square statistical attack yielded a score of {round(chi.get('score', 0)*100, 1)}%. ")
            rs = t3_stat.get('rs_analysis')
            if rs and rs.get('score') is not None:
                narrative_parts.append(f"RS analysis yielded a score of {round(rs.get('score', 0)*100, 1)}%. ")
        
        # PAYLOAD SECTION
        if payload_size > 0:
            narrative_parts.append(f"Payload extraction recovered approximately {payload_size} bytes of embedded data. ")
        if is_executable:
            narrative_parts.append("CRITICAL: The extracted payload contains a Windows PE executable signature, indicating a potentially malicious hidden program. ")
        if payload_entropy > 7.5:
            narrative_parts.append(f"The payload entropy of {payload_entropy} bits per byte is consistent with encrypted or compressed content, suggesting deliberate concealment of the payload. ")
            
        # ADAPTIVE SECTION
        if adaptive_detected:
            narrative_parts.append(f"DCT coefficient analysis detected the statistical signature of adaptive frequency-domain steganography. An estimated payload of {estimated_payload_kb} kilobytes may be present in the DCT domain. Full extraction requires the embedding key. ")
            
        closing = "This report was generated automatically by Shadow-Trace v1.0.0. All findings are based on mathematical and machine learning analysis and should be reviewed by a qualified digital forensic examiner before being used as evidence in legal proceedings. "
        narrative_parts.append(closing)
        
        return "".join(narrative_parts)
    except Exception as e:
        return f"Error generating narrative: {str(e)}"

import math

def generate_lsb_heatmap_image(
    filepath: str,
    lsb_result: Dict = None
) -> Dict[str, Any]:
    try:
        # Resolve readable path (sandbox copy if original is locked)
        read_path = _find_readable_path(filepath)
        if read_path != filepath:
            print('[LSB-IMG] Using sandbox copy: ' + Path(read_path).name)
        else:
            print('[LSB-IMG] No sandbox copy found, trying original')

        img = Image.open(read_path).convert('RGB')
        img_resized = img.resize((256, 256), Image.BILINEAR)
        arr = np.array(img_resized, dtype=np.uint8)
        h, w = arr.shape[:2]

        lsb_plane = arr & 1
        lsb_combined = lsb_plane.mean(axis=2)
        
        window_size = 16
        rows = h // window_size
        cols = w // window_size
        entropy_map = np.zeros((rows, cols), dtype=np.float32)
        
        for i in range(rows):
            for j in range(cols):
                window = lsb_combined[
                    i*window_size:(i+1)*window_size,
                    j*window_size:(j+1)*window_size
                ].flatten()
                
                n_ones = window.sum()
                total = len(window)
                n_zeros = total - n_ones
                
                p0 = n_zeros / total if total > 0 else 0
                p1 = n_ones / total if total > 0 else 0
                
                ent = 0.0
                if p0 > 0: ent -= p0 * math.log2(p0)
                if p1 > 0: ent -= p1 * math.log2(p1)
                
                entropy_map[i, j] = ent

        suspicion_map = np.abs(entropy_map - 1.0)
        
        if lsb_result is not None:
            sigs = lsb_result.get('signatures_found', [])
            if sigs:
                position_hex = sigs[0].get('position_hex', None)
                if position_hex:
                    try:
                        byte_pos = int(position_hex, 16)
                        pixel_idx = byte_pos // 3
                        px_row = (pixel_idx // w) // window_size
                        px_col = (pixel_idx % w) // window_size
                        if 0 <= px_row < rows and 0 <= px_col < cols:
                            suspicion_map[px_row, px_col] += 1.0
                    except (ValueError, KeyError, ZeroDivisionError):
                        pass  # malformed position_hex — skip this signature marker

        from PIL import Image as PILImage
        susp_pil = PILImage.fromarray(
            (suspicion_map / max(suspicion_map.max(), 1e-9) * 255).astype(np.uint8)
        )
        susp_resized = np.array(
            susp_pil.resize((w, h), PILImage.BILINEAR)
        ) / 255.0

        fig, axes = plt.subplots(1, 3, figsize=(18, 6))
        
        axes[0].imshow(arr)
        axes[0].set_title('Original Image', fontsize=12, fontweight='bold')
        axes[0].axis('off')
        
        lsb_display = (lsb_combined * 255).astype(np.uint8)
        axes[1].imshow(lsb_display, cmap='gray')
        axes[1].set_title(
            'LSB Bit Plane\n(Shows raw LSB values - '
            'uniform regions indicate hidden data)',
            fontsize=10, fontweight='bold'
        )
        axes[1].axis('off')
        
        axes[2].imshow(arr)
        heatmap_colored = plt.cm.hot(susp_resized)[:,:,:3]
        heatmap_colored = (heatmap_colored * 255).astype(np.uint8)
        overlay = (
            0.5 * arr.astype(float) +
            0.5 * heatmap_colored.astype(float)
        ).clip(0, 255).astype(np.uint8)
        axes[2].imshow(overlay)
        axes[2].set_title(
            'LSB Suspicion Heatmap\n'
            '(Red/Yellow = suspicious LSB patterns, '
            'likely hidden data location)',
            fontsize=10, fontweight='bold'
        )
        axes[2].axis('off')
        
        n_suspicious_windows = int((suspicion_map > 0.3).sum())
        total_windows = rows * cols
        suspicious_pct = round(n_suspicious_windows/total_windows*100, 1) if total_windows > 0 else 0
        
        title = (
            f'Shadow-Trace LSB Analysis: '
            + Path(filepath).name + '\n'
            + f'Suspicious regions: {n_suspicious_windows}/'
            + f'{total_windows} windows ({suspicious_pct}%)'
        )
        
        if lsb_result:
            sigs = lsb_result.get('signatures_found', [])
            if sigs:
                title += '\nDetected: ' + ', '.join(s.get('signature_type', '') for s in sigs[:3])
        
        plt.suptitle(title, fontsize=11, fontweight='bold', color='darkred')
        plt.tight_layout()

        reports_dir = config.BASE_DIR / 'reports' / 'heatmaps'
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filepath).stem
        heatmap_path = reports_dir / (stem + '_lsb_heatmap.png')
        print('[LSB-VIZ] Saving heatmap to: ' + str(heatmap_path))
        plt.savefig(str(heatmap_path), dpi=150, bbox_inches='tight')
        plt.close(fig)
        
        if heatmap_path.exists():
            print('[LSB-VIZ] File saved successfully: '
                  + str(heatmap_path.stat().st_size) + ' bytes')
        else:
            print('[LSB-VIZ] ERROR: File was not saved')

        return {
            'success': True,
            'heatmap_path': str(heatmap_path),
            'suspicious_windows': n_suspicious_windows,
            'total_windows': total_windows,
            'suspicious_pct': suspicious_pct,
            'lsb_plane_mean': round(float(lsb_combined.mean()), 4),
            'type': 'lsb_heatmap',
            'error': None
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def generate_lsb_heatmap_video(
    filepath: str,
    lsb_result: Dict = None
) -> Dict[str, Any]:
    try:
        import cv2

        # Resolve readable path (sandbox copy if original is locked)
        read_path = _find_readable_path(filepath)
        if read_path != filepath:
            print('[LSB-VIDEO] Using sandbox copy: ' + Path(read_path).name)
        else:
            print('[LSB-VIDEO] No sandbox copy found, trying original')

        cap = cv2.VideoCapture(read_path)
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        if total <= 16:
            indices = list(range(total))
        else:
            step = total // 16
            indices = [i * step for i in range(16)]

        frame_lsb_entropies = []
        frame_arrays = []
        
        for idx in indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ret, frame = cap.read()
            if not ret: continue
            
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            resized = cv2.resize(rgb, (224, 224))
            lsb = resized & 1
            lsb_mean = lsb.mean()
            
            deviation = abs(lsb_mean - 0.5)
            frame_lsb_entropies.append(deviation)
            frame_arrays.append(resized)
        cap.release()

        if not frame_arrays:
            return {'success': False, 'error': 'No frames extracted'}
            
        best_idx = int(np.argmax(frame_lsb_entropies))
        best_frame = frame_arrays[best_idx]
        
        # Save best frame as temp image
        temp_path = config.BASE_DIR / 'reports' / 'heatmaps' / 'temp_best_frame.png'
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        Image.fromarray(best_frame).save(str(temp_path))
        
        # Call generate_lsb_heatmap_image on the best frame
        img_res = generate_lsb_heatmap_image(str(temp_path), lsb_result)
        
        fig = plt.figure(figsize=(18, 10))
        
        # Recreate the 3-panel analysis directly on best_frame array
        h, w = best_frame.shape[:2]
        lsb_plane = best_frame & 1
        lsb_combined = lsb_plane.mean(axis=2)
        
        window_size = 16
        rows = h // window_size
        cols = w // window_size
        entropy_map = np.zeros((rows, cols), dtype=np.float32)
        
        for i in range(rows):
            for j in range(cols):
                window = lsb_combined[
                    i*window_size:(i+1)*window_size,
                    j*window_size:(j+1)*window_size
                ].flatten()
                n_ones = window.sum()
                total_w = len(window)
                p0 = (total_w - n_ones) / total_w if total_w > 0 else 0
                p1 = n_ones / total_w if total_w > 0 else 0
                ent = 0.0
                if p0 > 0: ent -= p0 * math.log2(p0)
                if p1 > 0: ent -= p1 * math.log2(p1)
                entropy_map[i, j] = ent

        suspicion_map = np.abs(entropy_map - 1.0)
        from PIL import Image as PILImage
        susp_pil = PILImage.fromarray((suspicion_map / max(suspicion_map.max(), 1e-9) * 255).astype(np.uint8))
        susp_resized = np.array(susp_pil.resize((w, h), PILImage.BILINEAR)) / 255.0

        ax1 = fig.add_subplot(2, 3, 1)
        ax1.imshow(best_frame)
        ax1.set_title('Most Suspicious Frame', fontsize=12, fontweight='bold')
        ax1.axis('off')
        
        ax2 = fig.add_subplot(2, 3, 2)
        lsb_display = (lsb_combined * 255).astype(np.uint8)
        ax2.imshow(lsb_display, cmap='gray')
        ax2.set_title('LSB Bit Plane', fontsize=10, fontweight='bold')
        ax2.axis('off')
        
        ax3 = fig.add_subplot(2, 3, 3)
        ax3.imshow(best_frame)
        heatmap_colored = plt.cm.hot(susp_resized)[:,:,:3]
        heatmap_colored = (heatmap_colored * 255).astype(np.uint8)
        overlay = (0.5 * best_frame.astype(float) + 0.5 * heatmap_colored.astype(float)).clip(0, 255).astype(np.uint8)
        ax3.imshow(overlay)
        ax3.set_title('LSB Suspicion Heatmap', fontsize=10, fontweight='bold')
        ax3.axis('off')

        ax_timeline = fig.add_subplot(2, 1, 2)
        frame_numbers = list(range(len(frame_lsb_entropies)))
        ax_timeline.bar(
            frame_numbers,
            frame_lsb_entropies,
            color=['red' if e > 0.1 else 'steelblue' for e in frame_lsb_entropies]
        )
        ax_timeline.axhline(
            y=0.1, color='orange', linestyle='--',
            label='Suspicion threshold'
        )
        ax_timeline.set_xlabel('Frame Index')
        ax_timeline.set_ylabel('LSB Deviation from Natural (0=natural, higher=suspicious)')
        ax_timeline.set_title(
            'LSB Entropy Timeline Across All Sampled Frames\n'
            'Red bars indicate frames with suspicious LSB patterns'
        )
        ax_timeline.legend()

        reports_dir = config.BASE_DIR / 'reports' / 'heatmaps'
        stem = Path(filepath).stem
        heatmap_path = reports_dir / (stem + '_lsb_heatmap.png')
        plt.savefig(str(heatmap_path), dpi=150, bbox_inches='tight')
        plt.close(fig)

        return {
            'success': True,
            'heatmap_path': str(heatmap_path),
            'most_suspicious_frame': best_idx,
            'frame_suspicion_scores': [round(e,4) for e in frame_lsb_entropies],
            'total_frames_analysed': len(frame_lsb_entropies),
            'type': 'lsb_heatmap_video',
            'error': None
        }
    except Exception as e:
        return {'success': False, 'error': str(e)}

def generate_lsb_heatmap_document(
    filepath, lsb_result=None, layer2_result=None
):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        
        fig, axes = plt.subplots(1, 2, figsize=(16, 7))
        fig.patch.set_facecolor('#f8f9fa')
        
        stream2b = {}
        stream1 = {}
        stream3 = {}
        stream4 = {}
        
        if layer2_result:
            stream2b = layer2_result.get(
                'stream2b_unicode', {}
            ) or {}
            stream1 = layer2_result.get(
                'stream1_structural', {}
            ) or {}
            stream3 = layer2_result.get(
                'stream3_entropy', {}
            ) or {}
            stream4 = layer2_result.get(
                'stream4_metadata', {}
            ) or {}
        
        zw_count = stream2b.get('zero_width_total', 0) or 0
        homoglyph_count = stream2b.get(
            'cyrillic_count', 0
        ) or 0
        high_entropy = stream3.get(
            'high_entropy_stream_count', 0
        ) or 0
        struct_score = stream1.get('score', 0.0) or 0.0
        metadata_score = stream4.get('score', 0.0) or 0.0
        
        lsb_exe_found = False
        lsb_position = 'N/A'
        if lsb_result:
            lsb_exe_found = (
                lsb_result.get('verdict') == 'EXECUTABLE_FOUND'
                or lsb_result.get('auto_escalate', False)
            )
            sigs = lsb_result.get('signatures_found', [])
            if sigs:
                lsb_position = str(
                    lsb_result.get('position', 'Unknown')
                )
        
        ax1 = axes[0]
        ax1.set_facecolor('#ffffff')
        
        categories = [
            'Zero-Width\nCharacters',
            'Homoglyph\nSubstitutions',
            'High Entropy\nStreams',
            'Structure\nAnomalies',
            'Metadata\nIssues',
            'LSB Executable\nFound',
        ]
        raw_values = [
            zw_count,
            homoglyph_count,
            high_entropy,
            1 if struct_score > 0.3 else 0,
            1 if metadata_score > 0.3 else 0,
            1 if lsb_exe_found else 0,
        ]
        
        colors = []
        for v in raw_values:
            if v == 0:
                colors.append('#27ae60')
            elif v == 1 and raw_values.index(v) >= 3:
                colors.append('#e74c3c')
            else:
                colors.append('#e74c3c' if v > 5
                              else '#f39c12')
        
        bars = ax1.barh(
            categories, raw_values,
            color=colors, edgecolor='white',
            linewidth=0.5, height=0.6
        )
        
        for bar, val in zip(bars, raw_values):
            width = bar.get_width()
            label = str(int(val)) if val > 0 else 'None'
            ax1.text(
                max(width + 0.05, 0.1),
                bar.get_y() + bar.get_height() / 2,
                label,
                va='center', ha='left',
                fontsize=10, fontweight='bold',
                color='#2c3e50'
            )
        
        ax1.set_xlabel(
            'Count / Presence', fontsize=10
        )
        ax1.set_title(
            'Document Steganography Indicators\n'
            'Red = suspicious finding detected',
            fontsize=11, fontweight='bold',
            color='#2c3e50'
        )
        ax1.set_xlim(0, max(max(raw_values) + 2, 3))
        
        green_patch = mpatches.Patch(
            color='#27ae60', label='Clean / Not detected'
        )
        red_patch = mpatches.Patch(
            color='#e74c3c', label='Suspicious finding'
        )
        orange_patch = mpatches.Patch(
            color='#f39c12', label='Warning level finding'
        )
        ax1.legend(
            handles=[green_patch, red_patch, orange_patch],
            loc='lower right', fontsize=8
        )
        
        ax2 = axes[1]
        ax2.set_facecolor('#ffffff')
        ax2.set_xlim(0, 10)
        ax2.set_ylim(0, 10)
        ax2.axis('off')
        
        ax2.set_title(
            'Analysis Summary',
            fontsize=11, fontweight='bold',
            color='#2c3e50', pad=15
        )
        
        filename = Path(filepath).name
        if len(filename) > 40:
            filename = filename[:37] + '...'
        
        overall_score = (layer2_result or {}).get(
            'score', 0.0
        ) or 0.0
        verdict = (layer2_result or {}).get(
            'verdict', 'UNKNOWN'
        )
        
        verdict_color = {
            'STEGO_DETECTED': '#e74c3c',
            'SUSPICIOUS': '#f39c12',
            'CLEAN': '#27ae60',
        }.get(verdict, '#7f8c8d')
        
        summary_items = [
            ('File Analysed', filename, '#2c3e50'),
            ('Overall Verdict', verdict, verdict_color),
            ('Confidence Score',
             str(round(overall_score * 100, 1)) + '%',
             verdict_color),
            ('Zero-Width Chars Found',
             str(zw_count),
             '#e74c3c' if zw_count > 0 else '#27ae60'),
            ('Homoglyph Substitutions',
             str(homoglyph_count),
             '#e74c3c' if homoglyph_count > 0 else '#27ae60'),
            ('High Entropy Streams',
             str(high_entropy),
             '#e74c3c' if high_entropy > 0 else '#27ae60'),
            ('Structural Anomalies',
             'YES' if struct_score > 0.3 else 'NO',
             '#e74c3c' if struct_score > 0.3 else '#27ae60'),
            ('LSB Executable',
             'DETECTED at ' + lsb_position
             if lsb_exe_found else 'NOT FOUND',
             '#e74c3c' if lsb_exe_found else '#27ae60'),
        ]
        
        y_pos = 9.0
        for label, value, color in summary_items:
            ax2.text(
                0.2, y_pos, label + ':',
                fontsize=9, fontweight='bold',
                color='#555555',
                transform=ax2.transData
            )
            ax2.text(
                5.0, y_pos, value,
                fontsize=9, fontweight='bold',
                color=color,
                transform=ax2.transData
            )
            ax2.axhline(
                y=y_pos - 0.25,
                xmin=0.02, xmax=0.98,
                color='#ecf0f1', linewidth=0.5
            )
            y_pos -= 1.1
        
        fig.suptitle(
            'Shadow-Trace Document Forensic Analysis\n'
            + Path(filepath).name,
            fontsize=12, fontweight='bold',
            color='#2c3e50', y=1.02
        )
        
        plt.tight_layout(pad=2.0)
        
        reports_dir = config.BASE_DIR / 'reports' / 'heatmaps'
        reports_dir.mkdir(parents=True, exist_ok=True)
        stem = Path(filepath).stem
        heatmap_path = (
            reports_dir / (stem + '_lsb_heatmap.png')
        )
        plt.savefig(
            str(heatmap_path), dpi=150,
            bbox_inches='tight',
            facecolor=fig.get_facecolor()
        )
        plt.close('all')
        
        return {
            'success': True,
            'heatmap_path': str(heatmap_path),
            'zero_width_count': zw_count,
            'homoglyph_count': homoglyph_count,
            'high_entropy_streams': high_entropy,
            'lsb_executable_found': lsb_exe_found,
            'lsb_position': lsb_position,
            'type': 'lsb_heatmap_document',
            'error': None
        }
        
    except Exception as e:
        import traceback
        utils.log_error(
            'generate_lsb_heatmap_document: ' + str(e)
        )
        return {
            'success': False,
            'error': str(e) + '\n' + traceback.format_exc()
        }

def generate_lsb_visualization(
    filepath: str,
    file_type: str,
    lsb_result: Dict = None,
    layer2_result: Dict = None
) -> Dict[str, Any]:
    ext = Path(filepath).suffix.lower()
    image_exts = ['.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp', '.tiff']
    video_exts = ['.mp4', '.avi', '.mkv', '.mov', '.wmv']
    doc_exts = ['.pdf', '.docx', '.doc', '.txt']
    
    if file_type == 'IMAGE' or ext in image_exts:
        return generate_lsb_heatmap_image(filepath, lsb_result)
    elif file_type == 'VIDEO' or ext in video_exts:
        return generate_lsb_heatmap_video(filepath, lsb_result)
    elif file_type == 'DOCUMENT' or ext in doc_exts:
        return generate_lsb_heatmap_document(filepath, lsb_result, layer2_result)
    else:
        return generate_lsb_heatmap_image(filepath, lsb_result)

def run_explainability(
    filepath: str,
    layer2_result: Dict,
    layer3_result: Dict = None,
    session_id: str = ''
) -> Dict[str, Any]:
    try:
        print('[LAYER4-XAI] Starting explainability analysis...')
        print('[LAYER4-XAI] File: ' + Path(filepath).name)
        
        file_type = layer2_result.get('file_type', 'IMAGE')
        
        lsb_viz_result = {'success': False, 'error': 'Skipped'}
        lsb_data = layer2_result.get('lsb_check_result', None)
        if lsb_data is None:
            lsb_data = layer2_result.get('lsb_result', None)

        print('[LAYER4-XAI] Generating LSB visualization...')
        try:
            lsb_viz_result = generate_lsb_visualization(
                filepath=filepath,
                file_type=file_type,
                lsb_result=lsb_data,
                layer2_result=layer2_result
            )
            if lsb_viz_result.get('success'):
                print('[LAYER4-XAI] LSB heatmap saved: '
                      + str(lsb_viz_result.get('heatmap_path')))
            else:
                print('[LAYER4-XAI] LSB viz: '
                      + str(lsb_viz_result.get('error')))
        except Exception as e:
            print('[LAYER4-XAI] LSB viz error: ' + str(e))
            lsb_viz_result = {'success': False, 'error': str(e)}

        grad_cam_result = {'success': False, 'error': 'Skipped'}
        file_type = layer2_result.get('file_type', 'UNKNOWN')
        
        if file_type == 'IMAGE':
            try:
                print('[LAYER4-XAI] Generating Grad-CAM heatmap...')
                # Model is loaded directly inside generate_gradcam_heatmap
                # so it works even when layer2_steganalysis singleton is not initialised.
                grad_cam_result = generate_gradcam_heatmap(filepath)
                if grad_cam_result.get('success'):
                    print('[LAYER4-XAI] Heatmap saved: ' + str(grad_cam_result.get('heatmap_path')))
                    roi = grad_cam_result.get('roi_coords')
                    if roi and layer3_result is not None:
                        layer3_result['roi_coords'] = roi
                else:
                    print('[LAYER4-XAI] Grad-CAM failed: ' + str(grad_cam_result.get('error')))
            except Exception as e:
                print('[LAYER4-XAI] Grad-CAM error: ' + str(e))
                grad_cam_result = {'success': False, 'error': str(e)}
        elif file_type == 'VIDEO':
            try:
                from layer2_steganalysis import _get_video_model
                video_model = _get_video_model()
                if video_model is not None:
                    print('[LAYER4-XAI] Generating video frame Grad-CAM...')
                    grad_cam_result = generate_video_gradcam(
                        filepath, video_model
                    )
                    if grad_cam_result.get('success'):
                        best_frame = grad_cam_result.get(
                            'analysed_frame_index', 0
                        )
                        print(
                            '[LAYER4-XAI] Heatmap from frame '
                            + str(best_frame) + ' saved'
                        )
                else:
                    print('[LAYER4-XAI] Video model not loaded')
            except ImportError:
                print('[LAYER4-XAI] layer2_steganalysis not available, skipping Video Grad-CAM')
            except Exception as e:
                print('[LAYER4-XAI] Video Grad-CAM error: ' + str(e))
                grad_cam_result = {'success': False, 'error': str(e)}

        elif file_type == 'DOCUMENT':
            print('[LAYER4-XAI] Generating document token map...')
            grad_cam_result = generate_document_token_map(
                filepath, layer2_result
            )
            if grad_cam_result.get('success'):
                print(
                    '[LAYER4-XAI] Token map saved: '
                    + str(grad_cam_result.get('map_path'))
                )
        else:
            print(f'[LAYER4-XAI] Grad-CAM not supported for {file_type}, skipping')
            
        print('[LAYER4-XAI] Computing feature attribution...')
        attribution_result = compute_feature_attribution(
            filepath, layer2_result, layer3_result or {}
        )
        
        print('[LAYER4-XAI] Generating plain language narrative...')
        narrative = generate_narrative(
            filepath, layer2_result, layer3_result or {}, attribution_result
        )
        
        yara_explanations = []
        if layer2_result.get('yara_warnings'):
            yara_explanations = explain_yara_rules(
                matched_rules=[],
                warning_rules=layer2_result.get('yara_warnings', [])
            )
        elif layer2_result.get('yara_matched_rules'):
            yara_explanations = explain_yara_rules(
                matched_rules=layer2_result.get('yara_matched_rules', []),
                warning_rules=[]
            )
        
        return {
            'grad_cam': grad_cam_result,
            'lsb_visualization': lsb_viz_result,
            'attribution': attribution_result,
            'narrative': narrative,
            'yara_explanations': yara_explanations,
            'session_id': session_id,
            'filepath': filepath,
            'error': None
        }
    except Exception as e:
        return {'error': str(e), 'filepath': filepath}

if __name__ == '__main__':
    print('=== LAYER 4A EXPLAINABILITY TEST ===')
    print()
    
    print('Test 1: Narrative generation')
    
    mock_layer2 = {
        'verdict': 'STEGO_DETECTED',
        'score': 0.87,
        'confidence_tier': 'HIGH',
        'file_type': 'IMAGE',
        'tier1a_yedroudj': {'score': 0.91, 'verdict': 'STEGO_DETECTED'},
        'tier1b_alaska2': {'score': 0.72, 'verdict': 'STEGO_DETECTED'},
        'tier3_statistical': {
            'chi_square': {'score': 0.95, 'verdict': 'STEGO_DETECTED'},
            'rs_analysis': {'score': 0.88, 'verdict': 'STEGO_DETECTED'},
        },
        'fusion_notes': ['T1A: 0.91', 'T1B: 0.72', 'T3: 0.91']
    }
    
    mock_layer3 = {
        'extraction_results': {
            'payload_entropy': 7.85,
            'payload_type': 'Unknown Binary',
            'payload_size_bytes': 15420,
            'is_executable': False,
        },
        'adaptive_analysis': {
            'adaptive_stego_detected': True,
            'estimated_payload_kb': 12.3,
            'modification_ratio': 0.72,
        }
    }
    
    attribution = compute_feature_attribution(
        'test_image.jpg', mock_layer2, mock_layer3
    )
    print('Attribution computed:')
    if 'attributions' in attribution:
        for name, score in attribution['attributions'].items():
            bar = '#' * int(score * 50)
            print(f'  {name[:35]:35s} {score:.4f} {bar}')
    print()
    
    narrative = generate_narrative(
        'test_image.jpg',
        mock_layer2, mock_layer3, attribution
    )
    print('Narrative generated:')
    print('-' * 60)
    print(narrative)
    print('-' * 60)
    print()
    
    import os
    reports_dir = config.BASE_DIR / 'reports' / 'heatmaps'
    reports_dir.mkdir(parents=True, exist_ok=True)
    created = reports_dir.exists()
    print('Test 2: Reports directory: ' + ('CREATED' if created else 'FAILED'))
    print()
    
    print('=== TEST COMPLETE ===')
    print()
    print('Note: Grad-CAM test skipped in standalone mode')
    print('It runs automatically when Layer 2 model is loaded')
    print('and an image file is processed by the full pipeline')
