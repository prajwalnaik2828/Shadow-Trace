import os
import time
import threading
import numpy as np
from pathlib import Path
from typing import Dict, Any, Tuple, Optional
import torch
import torch.nn as nn
from torchvision import transforms
from PIL import Image
import cv2
import config
import utils
import chain_of_custody as coc
import recovery_database as rdb
from statistical_steganalysis import run_tier3
from document_forensics import run_document_forensics

DEVICE = torch.device('cpu')
IMAGE_SIZE = 256
FRAMES_PER_VIDEO = 16

W_TIER1A = 0.30
W_TIER1B = 0.35
W_TIER3  = 0.35

_tier1a_model = None
_tier1b_model = None
_video_model = None
_doc_model = None
_bert_tokenizer = None
_lock = threading.Lock()

def get_confidence_tier(score):
    if score >= 0.85: return ('HIGH', 'STEGO_DETECTED')
    elif score >= 0.65: return ('MEDIUM', 'STEGO_DETECTED')
    elif score >= 0.40: return ('LOW', 'SUSPICIOUS')
    else: return ('CLEAN', 'CLEAN')

def _load_tier1a():
    try:
        model_path = config.MODELS_DIR / 'image_model.pth'
        if not model_path.exists():
            print('[LAYER2-T1A] image_model.pth not found')
            return None
        from model_architectures import YedroudjNetV3, ConvBnRelu
        import sys
        sys.modules['__main__'].YedroudjNetV3 = YedroudjNetV3
        sys.modules['__main__'].ConvBnRelu = ConvBnRelu
        
        model = torch.load(str(model_path), map_location=DEVICE, weights_only=False)
        model.eval()
        
        for attr in ['YedroudjNetV3', 'ConvBnRelu']:
            try:
                del sys.modules['__main__'].__dict__[attr]
            except Exception:
                pass
        print('[LAYER2-T1A] YedroudjNetV3 loaded (AUC=0.94 spatial LSB)')
        return model
    except Exception as e:
        utils.log_error(str(e))
        print(f'[LAYER2-T1A] Error loading model: {e}')
        return None

def _get_tier1a():
    global _tier1a_model
    with _lock:
        if _tier1a_model is None:
            _tier1a_model = _load_tier1a()
        return _tier1a_model

def _preprocess_tier1a(filepath):
    img = Image.open(filepath).convert('YCbCr')
    y = img.split()[0].resize((256, 256), Image.BILINEAR)
    arr = np.array(y, dtype=np.float32)
    arr = (arr - 128.0) / 128.0
    return torch.from_numpy(arr[np.newaxis, np.newaxis, :, :])

def _run_tier1a(filepath):
    try:
        model = _get_tier1a()
        if model is None:
            return {'active': False, 'score': None, 'verdict': 'UNAVAILABLE', 'reason': 'image_model.pth not in models/'}
        tensor = _preprocess_tier1a(filepath).to(DEVICE)
        with torch.no_grad():
            score = float(model(tensor).item())
        _, verdict = get_confidence_tier(score)
        return {'active': True, 'score': round(score, 4), 'verdict': verdict, 'model': 'YedroudjNetV3', 'auc': 0.94, 'detects': 'spatial_LSB_Steghide_OpenStego'}
    except Exception as e:
        utils.log_error(str(e))
        return {'active': False, 'score': None, 'verdict': 'ERROR', 'reason': str(e)}

def _load_tier1b():
    try:
        model_path = config.MODELS_DIR / 'alaska2_tier2_model.pth'
        if not model_path.exists():
            print('[LAYER2-T1B] alaska2_tier2_model.pth not found')
            print('[LAYER2-T1B] Tier 1B inactive. Weight goes to Tier 1A.')
            print('[LAYER2-T1B] Train using the ALASKA2 Colab notebook')
            return None
        from model_architectures import ALASKA2Detector
        import sys
        sys.modules['__main__'].ALASKA2Detector = ALASKA2Detector
        model = torch.load(str(model_path), map_location=DEVICE, weights_only=False)
        model.eval()
        
        for attr in ['ALASKA2Detector']:
            try:
                del sys.modules['__main__'].__dict__[attr]
            except Exception:
                pass
        print('[LAYER2-T1B] ALASKA2 adaptive model loaded')
        print('[LAYER2-T1B] Detects: JMiPOD, JUNIWARD, UERD')
        return model
    except Exception as e:
        utils.log_error(str(e))
        print(f'[LAYER2-T1B] Error loading model: {e}')
        return None

def _get_tier1b():
    global _tier1b_model
    with _lock:
        if _tier1b_model is None:
            _tier1b_model = _load_tier1b()
        return _tier1b_model

def _preprocess_tier1b(filepath):
    img = Image.open(filepath).convert('RGB')
    img = img.resize((224, 224), Image.BILINEAR)
    arr = np.array(img, dtype=np.float32) / 255.0
    mean = np.array([0.485, 0.456, 0.406])
    std = np.array([0.229, 0.224, 0.225])
    arr = (arr - mean) / std
    t = torch.from_numpy(arr.transpose(2, 0, 1).astype(np.float32))
    return t.unsqueeze(0)

def _run_tier1b(filepath):
    try:
        model = _get_tier1b()
        if model is None:
            return {'active': False, 'score': None, 'verdict': 'UNAVAILABLE', 'reason': 'alaska2_tier2_model.pth not found'}
        tensor = _preprocess_tier1b(filepath).to(DEVICE)
        with torch.no_grad():
            score = float(model(tensor).item())
        _, verdict = get_confidence_tier(score)
        return {'active': True, 'score': round(score, 4), 'verdict': verdict, 'model': 'ALASKA2_EfficientNetB0', 'detects': 'adaptive_stego_JMiPOD_JUNIWARD_UERD'}
    except Exception as e:
        utils.log_error(str(e))
        return {'active': False, 'score': None, 'verdict': 'ERROR', 'reason': str(e)}

def _fuse(t1a, t1b, t3):
    try:
        scores = {}
        weights = {}
        notes = []

        if t1a.get('score') is not None:
            scores['t1a'] = t1a['score']
            weights['t1a'] = W_TIER1A
            notes.append(f"T1A Yedroudj: {t1a['score']:.3f} -> {t1a['verdict']}")
        else:
            notes.append("T1A unavailable: image_model.pth missing")

        if t1b.get('active') and t1b.get('score') is not None:
            scores['t1b'] = t1b['score']
            weights['t1b'] = W_TIER1B
            notes.append(f"T1B ALASKA2: {t1b['score']:.3f} -> {t1b['verdict']}")
        else:
            notes.append("T1B inactive: redistributing 0.35 weight to T1A")
            if 't1a' in weights:
                weights['t1a'] += W_TIER1B

        if t3.get('combined_score') is not None:
            scores['t3'] = t3['combined_score']
            weights['t3'] = W_TIER3
            notes.append(f"T3 Statistical: {t3['combined_score']:.3f} -> {t3['verdict']}")

        if not scores:
            return {'score': 0.0, 'verdict': 'ERROR', 'tier': 'UNKNOWN', 'notes': ['No tiers available']}

        total_w = sum(weights.values())
        norm_w = {k: v / total_w for k, v in weights.items()}
        confidence = sum(scores[k] * norm_w[k] for k in scores)
        confidence = round(float(confidence), 4)

        tier, verdict = get_confidence_tier(confidence)
        notes.append(f"Fusion score: {confidence:.3f} -> {verdict}")

        return {'score': confidence, 'verdict': verdict, 'tier': tier, 'notes': notes}
    except Exception as e:
        utils.log_error(str(e))
        return {'score': 0.0, 'verdict': 'ERROR', 'tier': 'UNKNOWN', 'notes': [f'Fusion error: {e}']}

def check_image_size(
    filepath: str,
) -> dict:
    try:
        from PIL import Image
        img = Image.open(filepath)
        width, height = img.size
        pixel_count = width * height
        
        WARNING_THRESHOLD = 10000
        
        if pixel_count < WARNING_THRESHOLD:
            warning_msg = (
                'Image has only '
                + str(pixel_count)
                + ' pixels ('
                + str(width) + 'x'
                + str(height)
                + '). Statistical analysis '
                '(Chi-Square and RS Analysis) '
                'requires a minimum of 10,000 '
                'pixels to produce statistically '
                'valid results. Results for this '
                'file may be unreliable.'
            )
            print('[LAYER2] WARNING: '
                  + warning_msg)
            return {
                'small_file': True,
                'pixel_count': pixel_count,
                'width': width,
                'height': height,
                'warning': warning_msg,
                'statistical_reliable': False,
            }
        else:
            return {
                'small_file': False,
                'pixel_count': pixel_count,
                'width': width,
                'height': height,
                'warning': None,
                'statistical_reliable': True,
            }
    
    except Exception as e:
        return {
            'small_file': False,
            'pixel_count': None,
            'warning': None,
            'statistical_reliable': True,
            'error': str(e),
        }

def analyse_image(filepath):
    try:
        size_check = check_image_size(filepath)
        if size_check.get('small_file'):
            print('[LAYER2] WARNING: ' + str(size_check.get('warning')))

        print('[LAYER2] Running Tier 1A: YedroudjNetV3...')
        t1a = _run_tier1a(filepath)
        print(f'[LAYER2-T1A] Score: {t1a.get("score")} Verdict: {t1a.get("verdict")}')

        print('[LAYER2] Running Tier 1B: ALASKA2 adaptive...')
        t1b = _run_tier1b(filepath)
        if t1b.get('active'):
            print(f'[LAYER2-T1B] Score: {t1b.get("score")} Verdict: {t1b.get("verdict")}')
        else:
            print('[LAYER2-T1B] Inactive (model not trained yet)')

        print('[LAYER2] Running Tier 3: Statistical analysis...')
        t3 = run_tier3(filepath)
        print(f'[LAYER2-T3] Chi: {t3["chi_square"]["verdict"]} RS: {t3["rs_analysis"]["verdict"]}')

        fused = _fuse(t1a, t1b, t3)
        notes = list(fused.get('notes', []))
        if size_check.get('small_file'):
            notes.append('Statistical analysis (Chi-Square and RS Analysis) results may not be reliable due to small image size (< 10,000 pixels).')
        fused['notes'] = notes
        print(f'[LAYER2] Fusion score: {fused["score"]}')
        print(f'[LAYER2] Final verdict: {fused["verdict"]}')

        result = {
            'verdict': fused['verdict'],
            'confidence_tier': fused['tier'],
            'score': fused['score'],
            'tier1a_yedroudj': t1a,
            'tier1b_alaska2': t1b,
            'tier3_statistical': t3,
            'fusion_notes': fused['notes'],
            'file_type': 'IMAGE',
            'model_loaded': (t1a.get('score') is not None or t1b.get('score') is not None),
            'image_size_check': size_check,
            'small_file_warning': size_check.get('small_file', False),
            'statistical_reliable': size_check.get('statistical_reliable', True),
        }
        return result
    except Exception as e:
        utils.log_error(str(e))
        return {
            'verdict': 'ERROR',
            'confidence_tier': 'UNKNOWN',
            'score': 0.0,
            'error': str(e),
            'file_type': 'IMAGE',
            'image_size_check': {'small_file': False, 'pixel_count': None, 'warning': None, 'statistical_reliable': True, 'error': str(e)},
            'small_file_warning': False,
            'statistical_reliable': True,
        }

IMAGE_TRANSFORM = transforms.Compose([
    transforms.Resize((IMAGE_SIZE, IMAGE_SIZE)),
    transforms.ToTensor(),
    transforms.Normalize(
        mean=[0.485, 0.456, 0.406],
        std=[0.229, 0.224, 0.225]
    )
])
BERT_MAX_LENGTH = 512

def _load_video_model():
    global _video_model
    with _lock:
        if _video_model is None:
            path = config.MODELS_DIR / 'video_model.pth'
            if not path.exists():
                print('[LAYER2] video_model.pth not found')
                return None
            try:
                import torch
                from model_architectures import (
                    VideoStegNet,
                    SpatialEncoder,
                    TemporalEncoder,
                    ConvBnRelu,
                    YedroudjNetV3,
                    LaplacianHPF,
                    DCTStream,
                    FlowStream
                )
                import sys
                import model_architectures as _ma
                
                sys.modules['__main__'].VideoStegNet = VideoStegNet
                sys.modules['__main__'].SpatialStream = SpatialEncoder
                sys.modules['__main__'].TemporalStream = TemporalEncoder
                sys.modules['__main__'].DCTStream = DCTStream
                sys.modules['__main__'].FlowStream = FlowStream
                sys.modules['__main__'].ConvBnRelu = ConvBnRelu
                sys.modules['__main__'].LaplacianHPF = LaplacianHPF
                
                _video_model = torch.load(
                    str(path),
                    map_location=DEVICE,
                    weights_only=False
                )
                _video_model.eval()
                print('[LAYER2] VideoStegNet four-stream loaded')
                
                for attr in [
                    'VideoStegNet', 'SpatialStream',
                    'TemporalStream', 'ConvBnRelu', 'LaplacianHPF',
                    'DCTStream', 'FlowStream'
                ]:
                    try:
                        del sys.modules['__main__'].__dict__[attr]
                    except Exception:
                        pass
                print('[LAYER2] Detects: LSB + DCT adaptive + Motion stego')
            except Exception as e:
                print(f'[LAYER2] Video load error: {e}')
    return _video_model

def _get_video_model():
    return _load_video_model()

def compute_dct_energy_map(y_arr):
    import cv2
    result = np.zeros_like(y_arr)
    h, w = y_arr.shape
    for i in range(0, h-7, 8):
        for j in range(0, w-7, 8):
            block = y_arr[i:i+8, j:j+8]
            dct_blk = cv2.dct(block.astype(np.float32))
            mid_energy = np.sum(np.abs(dct_blk[2:6, 2:6]))
            result[i:i+8, j:j+8] = mid_energy / 64.0
    if result.max() > 0:
        result = (result - result.mean()) / (result.std() + 1e-8)
    return result

def compute_flow(gray1, gray2):
    import cv2
    flow = cv2.calcOpticalFlowFarneback(
        gray1.astype(np.uint8),
        gray2.astype(np.uint8),
        None, 0.5, 3, 15, 3, 5, 1.2, 0
    )
    flow_norm = flow / (np.abs(flow).max() + 1e-8)
    return flow_norm.transpose(2,0,1).astype(np.float32)

def _load_doc_model():
    global _doc_model, _bert_tokenizer
    with _lock:
        if _doc_model is None:
            model_path = config.MODELS_DIR / 'doc_model.pth'
            tok_path   = config.MODELS_DIR / 'distilbert_tokenizer'
            if not model_path.exists():
                print('[LAYER2] doc_model.pth not found')
                print('[LAYER2] Run Colab document training first')
                return None, None
            try:
                from model_architectures import (
                    DistilBertSteganalyserV2,
                    extract_regex_features
                )
                import sys
                sys.modules['__main__'].DistilBertSteganalyserV2 = DistilBertSteganalyserV2
                _doc_model = torch.load(
                    str(model_path),
                    map_location=DEVICE,
                    weights_only=False
                )
                _doc_model.eval()
                
                for attr in ['DistilBertSteganalyserV2']:
                    try:
                        del sys.modules['__main__'].__dict__[attr]
                    except Exception:
                        pass
                print('[LAYER2] DistilBERT V2 hybrid model loaded')
                print('[LAYER2] Features: CLS(768) + Regex(6) = 774-dim')
                tok_path = config.MODELS_DIR / 'distilbert_tokenizer'

                # Check folder exists and has the required json file
                tok_config = tok_path / 'tokenizer_config.json'
                if tok_path.exists() and tok_config.exists():
                    try:
                        from transformers import DistilBertTokenizer  # pyrefly: ignore [missing-import]
                        _bert_tokenizer = (
                            DistilBertTokenizer.from_pretrained(
                                str(tok_path)
                            )
                        )
                        print('[LAYER2] DistilBERT tokenizer loaded')
                        print('[LAYER2] Vocab size: ' + str(_bert_tokenizer.vocab_size))
                    except Exception as e:
                        print('[LAYER2] Tokenizer load error: ' + str(e))
                        _bert_tokenizer = None
                else:
                    print('[LAYER2] Tokenizer folder not found at: ' + str(tok_path))
                    print('[LAYER2] Looked for: ' + str(tok_config))
                    _bert_tokenizer = None
            except Exception as e:
                print(f'[LAYER2] Doc model load error: {e}')
                utils.log_error(f'Doc model load error: {e}')
    return _doc_model, _bert_tokenizer

def get_doc_model():
    return _load_doc_model()

def analyse_video(filepath):
    model = _get_video_model()
    if model is None:
        return {
            'verdict': 'UNCERTAIN',
            'confidence_tier': 'UNKNOWN',
            'score': 0.0,
            'model_loaded': False,
            'file_type': 'VIDEO'
        }
    try:
        import cv2
        cap = cv2.VideoCapture(str(filepath))
        total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        
        if total <= FRAMES_PER_VIDEO:
            indices = list(range(total))
        else:
            step = total // FRAMES_PER_VIDEO
            indices = [i * step for i in range(FRAMES_PER_VIDEO)]
        
        y_frames = []
        dct_maps = []
        gray_list = []
        
        for idx in indices:
            cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
            ret, frame = cap.read()
            if ret:
                rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                pil = Image.fromarray(rgb).convert('YCbCr')
                y = np.array(
                    pil.split()[0].resize(
                        (224, 224), Image.BILINEAR
                    ), dtype=np.float32
                )
                gray_list.append(y.copy())
                y_norm = (y - 128.0) / 128.0
                y_frames.append(
                    torch.from_numpy(y_norm[np.newaxis, :, :])
                )
                dct_e = compute_dct_energy_map(y)
                dct_maps.append(
                    torch.from_numpy(dct_e[np.newaxis, :, :])
                )
        cap.release()
        
        while len(y_frames) < FRAMES_PER_VIDEO:
            y_frames.append(torch.zeros(1, 224, 224))
            dct_maps.append(torch.zeros(1, 224, 224))
            if gray_list:
                gray_list.append(gray_list[-1].copy())
        
        # Optical flow between consecutive frames
        flow_frames = []
        for i in range(min(len(gray_list)-1, FRAMES_PER_VIDEO-1)):
            flow = compute_flow(gray_list[i], gray_list[i+1])
            flow_frames.append(torch.from_numpy(flow))
        while len(flow_frames) < FRAMES_PER_VIDEO - 1:
            flow_frames.append(torch.zeros(2, 224, 224))
        
        y_tensor    = torch.stack(y_frames[:FRAMES_PER_VIDEO]).unsqueeze(0).to(DEVICE)
        dct_tensor  = torch.stack(dct_maps[:FRAMES_PER_VIDEO]).unsqueeze(0).to(DEVICE)
        flow_tensor = torch.stack(flow_frames[:FRAMES_PER_VIDEO-1]).unsqueeze(0).to(DEVICE)
        
        with torch.no_grad():
            score = float(model(y_tensor, dct_tensor, flow_tensor).item())
        
        tier, verdict = get_confidence_tier(score)
        
        return {
            'verdict': verdict,
            'confidence_tier': tier,
            'score': round(score, 4),
            'model_loaded': True,
            'model_name': 'VideoStegNet_FourStream',
            'detects': ['spatial_LSB', 'DCT_adaptive', 'motion_stego'],
            'file_type': 'VIDEO'
        }
        
    except Exception as e:
        utils.log_error(f'analyse_video error: {e}')
        return {
            'verdict': 'ERROR',
            'score': 0.0,
            'error': str(e),
            'file_type': 'VIDEO'
        }

def analyse_document(filepath: str) -> Dict[str, Any]:
    model, tokenizer = _load_doc_model()
    ext = Path(filepath).suffix.lower()

    # Step 1: Extract text from document
    # Text must be extracted WITHOUT stripping Unicode
    # Zero-width chars and homoglyphs must survive
    text = ''
    try:
        if ext == '.pdf':
            try:
                import fitz  # pyrefly: ignore [missing-import]
                doc  = fitz.open(str(filepath))
                text = ''.join(
                    page.get_text() for page in doc
                )
                doc.close()
            except ImportError:
                print('[LAYER2] PyMuPDF not installed, trying fallback')
                with open(filepath, 'rb') as f:
                    raw = f.read()
                text = raw.decode('utf-8', errors='ignore')
        elif ext in ['.docx', '.doc']:
            try:
                from docx import Document  # pyrefly: ignore [missing-import]
                d    = Document(str(filepath))
                text = ' '.join(
                    p.text for p in d.paragraphs
                )
            except ImportError:
                print('[LAYER2] python-docx not installed')
                text = ''
        else:
            with open(filepath, 'r',
                      errors='ignore') as f:
                text = f.read()
    except Exception as e:
        utils.log_error(f'Text extraction error: {e}')
        text = ''

    # Step 2: Run deterministic forensic streams
    # Always runs regardless of model availability
    try:
        forensics = run_document_forensics(
            filepath, text=text if text else None
        )
    except Exception as e:
        utils.log_error(f'Document forensics error: {e}')
        forensics = {
            'combined_score': 0.0,
            'verdict': 'ERROR',
            'stream1_structural': {'score': 0.0, 'verdict': 'ERROR'},
            'stream2b_unicode':   {'score': 0.0, 'verdict': 'ERROR'},
            'stream3_entropy':    {'score': 0.0, 'verdict': 'ERROR'},
            'stream4_metadata':   {'score': 0.0, 'verdict': 'ERROR'},
        }

    # Step 3: Run neural model if available
    neural_score = None
    if (model is not None and
            tokenizer is not None and
            text.strip()):
        try:
            from model_architectures import extract_regex_features

            encoding = tokenizer(
                text,
                max_length=256,
                padding='max_length',
                truncation=True,
                return_tensors='pt'
            )
            ids   = encoding['input_ids'].to(DEVICE)
            mask  = encoding['attention_mask'].to(DEVICE)

            # Extract regex features from RAW text
            # BEFORE tokenizer strips Unicode chars
            regex = extract_regex_features(text).unsqueeze(0).to(DEVICE)

            with torch.no_grad():
                neural_score = float(
                    model(ids, mask, regex).item()
                )

            print(
                f'[LAYER2] Neural doc score: '
                f'{neural_score:.4f}'
            )

        except Exception as e:
            utils.log_error(
                f'Neural document inference error: {e}'
            )
            neural_score = None

    # Step 4: Fuse neural score with forensics score
    # Neural: 0.45 weight (when available)
    # Forensics: 0.55 weight (always active)
    # If neural unavailable: forensics gets full weight
    if neural_score is not None:
        final_score = (
            neural_score * 0.45 +
            forensics['combined_score'] * 0.55
        )
        fusion_method = 'neural_0.45_forensics_0.55'
    else:
        final_score = forensics['combined_score']
        fusion_method = 'forensics_only_neural_unavailable'

    final_score = round(
        min(1.0, max(0.0, float(final_score))), 4
    )
    tier, verdict = get_confidence_tier(final_score)

    print(f'[LAYER2] Document final score: {final_score}')
    print(f'[LAYER2] Document verdict: {verdict}')

    return {
        'verdict':            verdict,
        'confidence_tier':    tier,
        'score':              final_score,
        'neural_score':       neural_score,
        'forensics_score':    forensics.get('combined_score', 0.0),
        'fusion_method':      fusion_method,
        'stream1_structural': forensics.get('stream1_structural', {}),
        'stream2b_unicode':   forensics.get('stream2b_unicode', {}),
        'stream3_entropy':    forensics.get('stream3_entropy', {}),
        'stream4_metadata':   forensics.get('stream4_metadata', {}),
        'model_loaded':       model is not None,
        'model_name':         'DistilBertSteganalyserV2',
        'file_type':          'DOCUMENT',
        'text_length':        len(text),
        'detects': [
            'zero_width_unicode',
            'homoglyph_substitution',
            'whitespace_steganography',
            'synonym_substitution',
            'pdf_hidden_objects',
            'docx_custom_xml',
            'high_entropy_streams',
            'magic_number_mismatch',
            'metadata_inconsistency'
        ]
    }

def run_steganalysis(filepath, session_id, sha3_hash, scan_target=None):
    try:
        read_path = scan_target or filepath
        name = Path(filepath).name
        print(f'[LAYER2] Starting steganalysis: {name}')
        print(f'[LAYER2] Session: {session_id[:8]}...')
        
        coc.log_action(session_id, filepath, sha3_hash,
             coc.STEG_TRIGGERED if hasattr(coc, 'STEG_TRIGGERED') else 'STEG_TRIGGERED', 'SUCCESS',
             f'Layer 2 requested: {name}')
        rdb.update_stage(filepath, 'LAYER2_RUNNING')
        
        mime = utils.get_mime_type(read_path)
        ext = Path(filepath).suffix.lower()
        
        IMAGE_MIMES = {'image/jpeg','image/png','image/bmp',
                       'image/webp','image/tiff','image/gif'}
        IMAGE_EXTS = {'.jpg','.jpeg','.png','.bmp',
                      '.webp','.tiff','.gif'}
        VIDEO_MIMES = {'video/mp4','video/avi','video/mkv',
                       'video/x-msvideo','video/quicktime'}
        VIDEO_EXTS = {'.mp4','.avi','.mkv','.mov','.wmv'}
        DOC_EXTS = {'.pdf','.docx','.doc','.txt'}
        
        if mime in IMAGE_MIMES or ext in IMAGE_EXTS:
            result = analyse_image(read_path)
        elif mime in VIDEO_MIMES or ext in VIDEO_EXTS:
            result = analyse_video(read_path)
        elif ext in DOC_EXTS:
            result = analyse_document(read_path)
        else:
            print(f'[LAYER2] Unknown type {ext}, trying image')
            result = analyse_image(read_path)
            
        if 'image_size_check' not in result:
            result['image_size_check'] = {'small_file': False, 'pixel_count': None, 'warning': None, 'statistical_reliable': True}
            result['small_file_warning'] = False
            result['statistical_reliable'] = True
            
        result.update({
             'session_id': session_id,
             'filepath': filepath,
             'sha3_hash': sha3_hash,
             'timestamp': utils.format_timestamp()
        })
        
        coc.log_action(session_id, filepath, sha3_hash,
             coc.STEG_COMPLETE if hasattr(coc, 'STEG_COMPLETE') else 'STEG_COMPLETE', result.get('verdict','ERROR'),
             str({'score': result.get('score'),
                  'verdict': result.get('verdict')}))
        rdb.update_stage(filepath, 'LAYER2_COMPLETE')
        
        return result
    except Exception as e:
        utils.log_error(str(e))
        return {
            'verdict': 'ERROR',
            'error': str(e),
            'session_id': session_id,
            'filepath': filepath,
            'sha3_hash': sha3_hash,
            'timestamp': utils.format_timestamp()
        }

if __name__ == '__main__':
    print('=== LAYER 2 STEGANALYSIS ENGINE TEST ===')
    print()

    print('Model files in D:\\Shadow-trace\\models\\:')
    models_to_check = [
        ('image_model.pth', 'Tier1A YedroudjNetV3'),
        ('alaska2_tier2_model.pth', 'Tier1B ALASKA2'),
        ('video_model.pth', 'Video model'),
        ('doc_model.pth', 'Document model'),
    ]
    for filename, label in models_to_check:
        path = config.MODELS_DIR / filename
        status = 'FOUND' if path.exists() else 'MISSING'
        print(f'  {label}: {status}')
    tok_path = config.MODELS_DIR / 'distilbert_tokenizer'
    tok_config = tok_path / 'tokenizer_config.json'
    tok_status = 'FOUND' if (tok_path.exists() and tok_config.exists()) else 'MISSING'
    print('  BERT tokenizer: ' + tok_status)

    print()
    print('Tier 3 statistical test:')
    from PIL import Image as PILImage
    import numpy as np
    arr = np.random.randint(50,200,(256,256,3),dtype=np.uint8)
    PILImage.fromarray(arr).save('test_l2.png')
    t3_result = run_tier3('test_l2.png')
    print(f'  Chi verdict: {t3_result["chi_square"]["verdict"]}')
    print(f'  RS verdict: {t3_result["rs_analysis"]["verdict"]}')
    print(f'  Combined: {t3_result["combined_score"]}')

    print()
    print('Full image pipeline test:')
    result = run_steganalysis(
        'test_l2.png',
        'TEST_SESSION_LAYER2_001',
        'test_hash_placeholder'
    )
    print(f'  Verdict: {result["verdict"]}')
    print(f'  Score: {result["score"]}')
    print(f'  T1A: {result["tier1a_yedroudj"].get("verdict") if "tier1a_yedroudj" in result else "ERROR"}')
    print(f'  T1B: {result["tier1b_alaska2"].get("verdict") if "tier1b_alaska2" in result else "ERROR"}')
    print(f'  T3: {result["tier3_statistical"]["verdict"] if "tier3_statistical" in result else "ERROR"}')
    print('  Fusion notes:')
    for note in result.get('fusion_notes', []):
        print(f'    {note}')

    import os
    os.remove('test_l2.png')
    print()
    print('=== TEST COMPLETE ===')
