# These architecture definitions are used for 
# reference and testing only.
# The actual trained models are saved as complete 
# model objects (not just state dicts) using 
# torch.save(model, path) in Google Colab.
# layer2_steganalysis.py loads them with 
# torch.load(path, map_location='cpu')
# This means the full class definitions must 
# be importable when loading the model.
# Therefore keep all class definitions here 
# and import them in layer2_steganalysis.py

import torch
import torch.nn as nn
from torchvision import models
# transformers is only needed for the DistilBert classes and is imported lazily
# inside those classes so that YedroudjNetV3 / ConvBnRelu can be imported even
# when the transformers package is not installed (e.g. in a minimal environment).


def extract_regex_features(text: str):
    import re, torch
    length = max(len(text), 1)
    norm   = length / 100.0

    ZW_CHARS = ['\u200b', '\u200c', '\u200d', '\u2060',
                '\u2062', '\u2063', '\u2064']
    zw_count  = sum(text.count(c) for c in ZW_CHARS)
    zw_density = min(1.0, zw_count / norm)

    thin_hair  = text.count('\u2009') + text.count('\u200a')
    th_density = min(1.0, thin_hair / norm)

    double_sp  = len(re.findall(r'  +', text))
    ds_density = min(1.0, double_sp / norm)

    cyrillic   = len(re.findall(r'[\u0400-\u04ff]', text))
    cy_density = min(1.0, cyrillic / norm)

    greek      = len(re.findall(r'[\u0370-\u03ff]', text))
    gr_density = min(1.0, greek / norm)

    DIR_MARKS  = ['\ufeff', '\u200e', '\u200f',
                  '\u202a', '\u202b', '\u202c',
                  '\u202d', '\u202e']
    dir_count  = sum(text.count(c) for c in DIR_MARKS)
    di_density = min(1.0, dir_count / norm)

    return torch.tensor(
        [zw_density, th_density, ds_density,
         cy_density, gr_density, di_density],
        dtype=torch.float32
    )


class LaplacianHPF(nn.Module):
    def __init__(self):
        super().__init__()
        self.hpf = nn.Conv2d(1, 1, kernel_size=3, padding=1, bias=False)
        lap = torch.tensor([[[[-1., -1., -1.], [-1., 8., -1.], [-1., -1., -1.]]]])
        self.hpf.weight = nn.Parameter(lap, requires_grad=False)
    def forward(self, x):
        return self.hpf(x)

class DCTStream(nn.Module):
    def forward(self, x):
        x = self.layers(x)
        x = self.gap(x)
        return x.view(x.size(0), -1)

class FlowStream(nn.Module):
    def forward(self, x):
        B, T, C, H, W = x.shape
        x_flat = x.view(B * T, C, H, W)
        feats = self.frame_encoder(x_flat)
        feats = self.gap(feats).view(B, T, -1)
        _, (h, _) = self.lstm(feats)
        return h[-1]

class ConvBnRelu(nn.Module):
    def __init__(self, in_ch, out_ch,
                 kernel=3, stride=1, padding=1):
        super().__init__()
        self.block = nn.Sequential(
            nn.Conv2d(
                in_ch, out_ch, kernel,
                stride=stride, padding=padding,
                bias=False
            ),
            nn.BatchNorm2d(out_ch),
            nn.ReLU(inplace=True)
        )
    def forward(self, x):
        return self.block(x)


class YedroudjNetV3(nn.Module):
    def __init__(self):
        super().__init__()
        self.hpf = nn.Conv2d(
            1, 1, kernel_size=3, padding=1, bias=False
        )
        laplacian = torch.tensor(
            [[[[-1., -1., -1.],
               [-1.,  8., -1.],
               [-1., -1., -1.]]]]
        )
        self.hpf.weight = nn.Parameter(
            laplacian, requires_grad=False
        )
        self.conv1   = nn.Conv2d(1, 30, 5, padding=2, bias=False)
        self.bn1     = nn.BatchNorm2d(30)
        self.group2  = ConvBnRelu(30,  30)
        self.group3  = ConvBnRelu(30,  30)
        self.group4  = ConvBnRelu(30,  30)
        self.group5  = ConvBnRelu(30,  32)
        self.group6  = ConvBnRelu(32,  32, stride=2)
        self.group7  = ConvBnRelu(32,  64)
        self.group8  = ConvBnRelu(64,  64)
        self.group9  = ConvBnRelu(64,  128, stride=2)
        self.group10 = ConvBnRelu(128, 128)
        self.group11 = ConvBnRelu(128, 256)
        self.group12 = ConvBnRelu(256, 256, stride=2)
        self.gap     = nn.AdaptiveAvgPool2d(1)
        self.classifier = nn.Sequential(
            nn.Linear(256, 1024),
            nn.ReLU(inplace=True),
            nn.Dropout(0.5),
            nn.Linear(1024, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        x = self.hpf(x)
        x = torch.abs(self.conv1(x))
        x = self.bn1(x)
        x = self.group2(x)
        x = self.group3(x)
        x = self.group4(x)
        x = self.group5(x)
        x = self.group6(x)
        x = self.group7(x)
        x = self.group8(x)
        x = self.group9(x)
        x = self.group10(x)
        x = self.group11(x)
        x = self.group12(x)
        x = self.gap(x)
        x = x.view(x.size(0), -1)
        return self.classifier(x).squeeze(1)


class HybridImageSteganalyser(nn.Module):

    def __init__(self):
        super().__init__()
        self.eff_features = 1792
        self.vit_features = 384

        # These are placeholders at init time
        # Real streams loaded from saved model

        # Fusion classifier
        self.fusion = nn.Sequential(
            nn.LayerNorm(self.eff_features + self.vit_features),
            nn.Linear(self.eff_features + self.vit_features, 512),
            nn.GELU(),
            nn.Dropout(0.4),
            nn.Linear(512, 256),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(256, 1),
            nn.Sigmoid()
        )

    def forward(self, eff_features, vit_features):
        combined = torch.cat([eff_features, vit_features], dim=1)
        return self.fusion(combined).squeeze(1)


class VideoHybridSteganalyser(nn.Module):

    def __init__(self, num_frames=16, hidden_dim=512):
        super().__init__()

        self.num_frames = num_frames
        self.feature_dim = 1792  # EfficientNet-B4 output
        self.hidden_dim = hidden_dim

        # Temporal Transformer Encoder
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=self.feature_dim,
            nhead=8,
            dim_feedforward=hidden_dim * 4,
            dropout=0.1,
            activation='gelu',
            batch_first=True
        )
        self.temporal_transformer = nn.TransformerEncoder(
            encoder_layer,
            num_layers=4
        )

        # CLS token for aggregation
        self.cls_token = nn.Parameter(
            torch.zeros(1, 1, self.feature_dim)
        )

        # Positional encoding for frames
        self.pos_embedding = nn.Parameter(
            torch.zeros(1, num_frames + 1, self.feature_dim)
        )

        # Classifier
        self.classifier = nn.Sequential(
            nn.LayerNorm(self.feature_dim),
            nn.Linear(self.feature_dim, 256),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(256, 1),
            nn.Sigmoid()
        )

    def forward(self, frame_features):
        # frame_features shape: batch, num_frames, feature_dim
        batch_size = frame_features.size(0)

        # Prepend CLS token
        cls_tokens = self.cls_token.expand(batch_size, -1, -1)
        x = torch.cat([cls_tokens, frame_features], dim=1)

        # Add positional encoding
        x = x + self.pos_embedding

        # Temporal transformer
        x = self.temporal_transformer(x)

        # Use CLS token output for classification
        cls_output = x[:, 0, :]

        return self.classifier(cls_output).squeeze(1)


class BERTSteganalyser(nn.Module):

    def __init__(self, hidden_size=768, num_classes=1):
        super().__init__()

        # BERT is loaded separately during training
        # This defines the classification head only
        # for architecture reference

        self.dropout = nn.Dropout(0.3)

        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, 256),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(256, 1),
            nn.Sigmoid()
        )

    def forward(self, pooled_output):
        x = self.dropout(pooled_output)
        return self.classifier(x).squeeze(1)


class ALASKA2Detector(nn.Module):
    def __init__(self):
        super().__init__()
        backbone = models.efficientnet_b0(
            weights=models.EfficientNet_B0_Weights.IMAGENET1K_V1
        )
        for param in backbone.parameters():
            param.requires_grad = False
        for i, block in enumerate(backbone.features):
            if i >= 6:
                for param in block.parameters():
                    param.requires_grad = True
        backbone.classifier = nn.Identity()
        self.backbone = backbone
        self.head = nn.Sequential(
            nn.Linear(1280, 512),
            nn.BatchNorm1d(512),
            nn.ReLU(inplace=True),
            nn.Dropout(0.5),
            nn.Linear(512, 128),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(128, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.head(self.backbone(x)).squeeze(1)


class DistilBertSteganalyserV2(nn.Module):
    def __init__(self):
        super().__init__()
        from transformers import DistilBertModel  # pyrefly: ignore [missing-import]
        self.distilbert = DistilBertModel.from_pretrained(
            'distilbert-base-uncased'
        )
        for param in self.distilbert.embeddings.parameters():
            param.requires_grad = False
        for i, layer in enumerate(
            self.distilbert.transformer.layer
        ):
            for param in layer.parameters():
                param.requires_grad = (i >= 4)
        self.regex_norm = nn.Sequential(
            nn.Linear(6, 32),
            nn.ReLU(inplace=True),
            nn.Linear(32, 6)
        )
        self.classifier = nn.Sequential(
            nn.Linear(774, 256),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, input_ids, attention_mask,
                regex_features):
        bert_out = self.distilbert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        cls_vec   = bert_out.last_hidden_state[:, 0, :]
        regex_vec = self.regex_norm(regex_features)
        fused     = torch.cat([cls_vec, regex_vec], dim=1)
        return self.classifier(fused).squeeze(1)


class DistilBertSteganalyser(nn.Module):
    def __init__(self):
        super().__init__()
        from transformers import DistilBertModel  # pyrefly: ignore [missing-import]
        self.distilbert = DistilBertModel.from_pretrained(
            'distilbert-base-uncased'
        )
        for param in self.distilbert.embeddings.parameters():
            param.requires_grad = False
        for i, layer in enumerate(
            self.distilbert.transformer.layer
        ):
            if i < 4:
                for param in layer.parameters():
                    param.requires_grad = False
        for i, layer in enumerate(
            self.distilbert.transformer.layer
        ):
            if i >= 4:
                for param in layer.parameters():
                    param.requires_grad = True
        self.classifier = nn.Sequential(
            nn.Linear(768, 256),
            nn.GELU(),
            nn.Dropout(0.3),
            nn.Linear(256, 64),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, input_ids, attention_mask):
        out = self.distilbert(
            input_ids=input_ids,
            attention_mask=attention_mask
        )
        cls = out.last_hidden_state[:, 0, :]
        return self.classifier(cls).squeeze(1)


# =============================================================================
# VideoStegNet — per-frame spatial encoder + bidirectional LSTM temporal encoder
# Expects input shape: (batch, num_frames, 1, H, W)  (grayscale Y-channel frames)
# =============================================================================

class SpatialEncoder(nn.Module):
    """
    Per-frame encoder that mirrors the YedroudjNetV3 HPF design but outputs a
    compact feature vector suitable for temporal aggregation.
    """
    def __init__(self, out_dim=128):
        super().__init__()
        self.hpf = nn.Conv2d(
            1, 1, kernel_size=3, padding=1, bias=False
        )
        lap = torch.tensor(
            [[[[-1., -1., -1.],
               [-1.,  8., -1.],
               [-1., -1., -1.]]]]
        )
        self.hpf.weight = nn.Parameter(
            lap, requires_grad=False
        )
        self.conv1  = nn.Conv2d(1, 30, 5, padding=2, bias=False)
        self.bn1    = nn.BatchNorm2d(30)
        self.group2 = ConvBnRelu(30,  32)
        self.group3 = ConvBnRelu(32,  32, stride=2)
        self.group4 = ConvBnRelu(32,  64)
        self.group5 = ConvBnRelu(64,  64, stride=2)
        self.group6 = ConvBnRelu(64,  128)
        self.group7 = ConvBnRelu(128, out_dim, stride=2)
        self.gap    = nn.AdaptiveAvgPool2d(1)

    def forward(self, x):
        x = self.hpf(x)
        x = torch.abs(self.conv1(x))
        x = self.bn1(x)
        x = self.group2(x)
        x = self.group3(x)
        x = self.group4(x)
        x = self.group5(x)
        x = self.group6(x)
        x = self.group7(x)
        x = self.gap(x)
        return x.view(x.size(0), -1)


class TemporalEncoder(nn.Module):
    """
    Bidirectional two-layer LSTM that aggregates per-frame feature vectors into
    a single sequence-level representation by concatenating the last hidden
    states of both directions.
    """
    def __init__(self, input_dim=128, hidden_dim=64):
        super().__init__()
        self.lstm = nn.LSTM(
            input_size=input_dim,
            hidden_size=hidden_dim,
            num_layers=2,
            batch_first=True,
            dropout=0.3,
            bidirectional=True
        )
        self.out_dim = hidden_dim * 2  # bidirectional

    def forward(self, x):
        # x: (batch, seq_len, input_dim)
        _, (h, _) = self.lstm(x)
        # h: (num_layers * 2, batch, hidden_dim)
        # take the last layer's forward and backward states
        return torch.cat([h[-2], h[-1]], dim=1)


class VideoStegNet(nn.Module):
    """
    Two-stream video steganalysis model.

    Spatial stream  — SpatialEncoder applied independently to every frame.
    Temporal stream — TemporalEncoder (biLSTM) over the sequence of frame features.

    The final verdict is produced from a classifier head that receives the
    concatenation of:
      - mean-pooled spatial features (global frame-level average)
      - temporal summary (sequence-level biLSTM output)
    """
    def __init__(self,
                 spatial_feat=128,
                 temporal_hidden=64,
                 temporal_layers=2):
        super().__init__()
        self.spatial_stream  = SpatialEncoder(spatial_feat)
        self.temporal_stream = TemporalEncoder(
            spatial_feat, temporal_hidden
        )
        combined_dim = spatial_feat + temporal_hidden * 2
        self.classifier = nn.Sequential(
            nn.Linear(combined_dim, 256),
            nn.ReLU(inplace=True),
            nn.Dropout(0.5),
            nn.Linear(256, 64),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),
            nn.Linear(64, 1),
            nn.Sigmoid()
        )

    def forward(self, x, dct=None, flow=None):
        # x: (batch, num_frames, channels, H, W)
        B, T, C, H, W = x.shape
        x_flat = x.view(B * T, C, H, W)
        spatial_feats   = self.spatial_stream(x_flat).view(B, T, -1)
        spatial_summary  = spatial_feats.mean(dim=1)
        temporal_summary = self.temporal_stream(spatial_feats)
        
        features = [spatial_summary, temporal_summary]
        
        if hasattr(self, 'dct_stream') and dct is not None:
            B_dct, T_dct, C_dct, H_dct, W_dct = dct.shape
            dct_flat = dct.view(B_dct * T_dct, C_dct, H_dct, W_dct)
            dct_feats = self.dct_stream(dct_flat).view(B_dct, T_dct, -1)
            features.append(dct_feats.mean(dim=1))
        if hasattr(self, 'flow_stream') and flow is not None:
            flow_feats = self.flow_stream(flow)
            features.append(flow_feats)
            
        combined = torch.cat(features, dim=1)
        
        if hasattr(self, 'fusion'):
            return self.fusion(combined).squeeze(1)
        else:
            return self.classifier(combined).squeeze(1)


if __name__ == "__main__":
    print("=== MODEL ARCHITECTURE VERIFICATION ===")
    print()

    print("Test 1 - Fusion classifier for image model:")
    fusion_model = nn.Sequential(
        nn.LayerNorm(1792 + 384),
        nn.Linear(1792 + 384, 512),
        nn.GELU(),
        nn.Dropout(0.4),
        nn.Linear(512, 256),
        nn.GELU(),
        nn.Dropout(0.3),
        nn.Linear(256, 1),
        nn.Sigmoid()
    )
    dummy_features = torch.zeros(2, 1792 + 384)
    out = fusion_model(dummy_features)
    print(f"Image fusion output: {out.shape}")
    total = sum(p.numel() for p in fusion_model.parameters())
    print(f"Fusion parameters: {total:,}")
    print(f"Test 1: {'PASS' if out.shape == torch.Size([2, 1]) else 'FAIL'}")
    print()

    print("Test 2 - Video temporal transformer:")
    model = VideoHybridSteganalyser(num_frames=16)
    dummy = torch.zeros(2, 16, 1792)
    out = model(dummy)
    print(f"Video model output: {out.shape}")
    params = sum(p.numel() for p in model.parameters())
    print(f"Parameters: {params:,}")
    print(f"Test 2: {'PASS' if out.shape == torch.Size([2]) else 'FAIL'}")
    print()

    print("Test 3 - BERT classifier head:")
    model = BERTSteganalyser()
    dummy = torch.zeros(2, 768)
    out = model(dummy)
    print(f"BERT head output: {out.shape}")
    params = sum(p.numel() for p in model.parameters())
    print(f"Parameters: {params:,}")
    print(f"Test 3: {'PASS' if out.shape == torch.Size([2]) else 'FAIL'}")
    print()

    model_v3 = YedroudjNetV3()
    dummy_v3 = torch.zeros(2, 1, 256, 256)
    with torch.no_grad():
        out_v3 = model_v3(dummy_v3)
    print(f'YedroudjNetV3 output: {out_v3.shape}')
    assert out_v3.shape == torch.Size([2]), \
        f'Expected [2] got {out_v3.shape}'
    print('YedroudjNetV3: PASS')
    print()

    from torchvision import models as tv_models
    detector = ALASKA2Detector()
    dummy_rgb = torch.zeros(2, 3, 224, 224)
    with torch.no_grad():
        out = detector(dummy_rgb)
    print(f'ALASKA2Detector output: {out.shape}')
    assert out.shape == torch.Size([2]), \
        f'Expected [2] got {out.shape}'
    print('ALASKA2Detector: PASS')
    print()

    print("DistilBertSteganalyser: skipping download test")
    print("(Requires network access for DistilBERT weights)")
    print()

    print("Test 4 - SpatialEncoder (per-frame feature extractor):")
    spatial_enc = SpatialEncoder(out_dim=128)
    dummy_frame = torch.zeros(4, 1, 224, 224)   # 4 grayscale frames
    with torch.no_grad():
        sp_out = spatial_enc(dummy_frame)
    print(f"SpatialEncoder output: {sp_out.shape}")
    sp_params = sum(p.numel() for p in spatial_enc.parameters())
    print(f"Parameters: {sp_params:,}")
    print(f"Test 4: {'PASS' if sp_out.shape == torch.Size([4, 128]) else 'FAIL'}")
    print()

    print("Test 5 - TemporalEncoder (biLSTM sequence aggregator):")
    temp_enc = TemporalEncoder(input_dim=128, hidden_dim=64)
    dummy_seq = torch.zeros(2, 8, 128)  # batch=2, 8 frames, feat=128
    with torch.no_grad():
        tp_out = temp_enc(dummy_seq)
    print(f"TemporalEncoder output: {tp_out.shape}")
    tp_params = sum(p.numel() for p in temp_enc.parameters())
    print(f"Parameters: {tp_params:,}")
    print(f"Test 5: {'PASS' if tp_out.shape == torch.Size([2, 128]) else 'FAIL'}")
    print()

    print("Test 6 - VideoStegNet (full two-stream model):")
    video_model = VideoStegNet(
        spatial_feat=128, temporal_hidden=64
    )
    # (batch=2, frames=8, channels=1, H=224, W=224)
    dummy_video = torch.zeros(2, 8, 1, 224, 224)
    with torch.no_grad():
        vid_out = video_model(dummy_video)
    print(f"VideoStegNet output: {vid_out.shape}")
    vid_params = sum(p.numel() for p in video_model.parameters())
    print(f"Parameters: {vid_params:,}")
    print(f"Test 6: {'PASS' if vid_out.shape == torch.Size([2]) else 'FAIL'}")
    print()

    print("=== VERIFICATION COMPLETE ===")
    print("Full models with pretrained streams are")
    print("defined in Google Colab training notebooks")
    print("and saved as complete model objects.")

