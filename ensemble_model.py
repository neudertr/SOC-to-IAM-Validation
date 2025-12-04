"""
Ensemble Dual-Encoder for CVE/CTI -> MITRE ATT&CK mapping.

This wrapper loads two RoBERTa-based dual encoders (v1 and v3) and
averages their L2-normalized embeddings. Long technique descriptions are
handled with overlapping chunking.
"""
from __future__ import annotations
import os
import json
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional

import torch
import torch.nn as nn
import torch.nn.functional as F
from transformers import AutoModel, AutoTokenizer


@dataclass
class EnsembleConfig:
    v1_subdir: str = "dual_v1"
    v3_subdir: str = "dual_v3"
    backbone: str = "roberta-base"
    max_len: int = 512
    overlap: int = 50
    proj_dim: int = 768
    batch_text: int = 32
    device: Optional[str] = None  # "cuda" / "cpu" / None autodetect

    @classmethod
    def from_json(cls, path: str) -> "EnsembleConfig":
        with open(path, "r", encoding="utf-8") as f:
            return cls(**json.load(f))

    def to_json(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.__dict__, f, indent=2)


class DualEncoderModel(nn.Module):
    def __init__(self, backbone: str = "roberta-base", proj_dim: int = 768, use_proj: bool = True):
        super().__init__()
        self.encoder = AutoModel.from_pretrained(backbone)
        hidden = self.encoder.config.hidden_size
        self.proj = nn.Linear(hidden, proj_dim) if use_proj else nn.Identity()

    @staticmethod
    def mean_pooling(last_hidden_state, attention_mask):
        m = attention_mask.unsqueeze(-1)
        s = (last_hidden_state * m).sum(dim=1)
        d = m.sum(dim=1).clamp(min=1e-6)
        return s / d

    def encode(self, input_ids, attention_mask):
        out = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        pooled = self.mean_pooling(out.last_hidden_state, attention_mask)
        proj = self.proj(pooled)
        return F.normalize(proj, p=2, dim=-1)


def _load_state_dict(path: str):
    ckpt = torch.load(path, map_location="cpu")
    if isinstance(ckpt, dict) and "model_state_dict" in ckpt:
        return ckpt["model_state_dict"]
    if isinstance(ckpt, dict):
        return ckpt
    raise ValueError(f"Unsupported checkpoint format at {path}")


def load_dual_from_dir(model_dir: str, backbone: str, proj_dim: int, device: torch.device) -> DualEncoderModel:
    candidates = ["pytorch_model.bin", "model.pt", "best.pt", "checkpoint.pt"]
    ckpt_path = None
    for c in candidates:
        p = os.path.join(model_dir, c)
        if os.path.exists(p):
            ckpt_path = p
            break
    if ckpt_path is None:
        raise FileNotFoundError(f"No checkpoint found in {model_dir}. Expected one of {candidates}.")

    state = _load_state_dict(ckpt_path)
    has_proj = any(k.startswith("proj.") for k in state.keys())

    remap_prefixes = ["projection.", "proj_head.", "projector.", "linear."]
    if not has_proj:
        for pref in remap_prefixes:
            if any(k.startswith(pref) for k in state.keys()):
                new_state = {}
                for k, v in state.items():
                    if k.startswith(pref):
                        new_state["proj."+k[len(pref):]] = v
                    else:
                        new_state[k] = v
                state = new_state
                has_proj = True
                break

    model = DualEncoderModel(backbone=backbone, proj_dim=proj_dim, use_proj=has_proj)
    model.load_state_dict(state, strict=False)
    model.to(device).eval()
    return model


class EnsembleDualEncoder(nn.Module):
    def __init__(self, config: EnsembleConfig, repo_dir: str):
        super().__init__()
        self.config = config
        self.repo_dir = repo_dir

        self.device_ = torch.device(
            config.device if config.device is not None
            else ("cuda" if torch.cuda.is_available() else "cpu")
        )
        self.tokenizer = AutoTokenizer.from_pretrained(config.backbone)

        self.m1 = load_dual_from_dir(os.path.join(repo_dir, config.v1_subdir),
                                     config.backbone, config.proj_dim, self.device_)
        self.m3 = load_dual_from_dir(os.path.join(repo_dir, config.v3_subdir),
                                     config.backbone, config.proj_dim, self.device_)

    @classmethod
    def from_pretrained(cls, repo_dir_or_hf_cache: str, config_name: str = "config.json"):
        cfg_path = os.path.join(repo_dir_or_hf_cache, config_name)
        config = EnsembleConfig.from_json(cfg_path)
        return cls(config, repo_dir_or_hf_cache)

    def chunk_long_text(self, text: str):
        tok = self.tokenizer
        max_len = self.config.max_len
        overlap = self.config.overlap

        tokens = tok(text, add_special_tokens=False)["input_ids"]
        if len(tokens) == 0:
            ids=[tok.cls_token_id, tok.sep_token_id] + [tok.pad_token_id]*(max_len-2)
            mask=[1,1]+[0]*(max_len-2)
            return [{"input_ids":torch.tensor(ids), "attention_mask":torch.tensor(mask)}]

        chunk_size=max_len-2
        stride=chunk_size-overlap
        chunks=[]
        for s in range(0, len(tokens), stride):
            sub=tokens[s:s+chunk_size]
            ids=[tok.cls_token_id]+sub+[tok.sep_token_id]
            ids=ids[:max_len]
            mask=[1]*len(ids)
            if len(ids)<max_len:
                pad=max_len-len(ids)
                ids+= [tok.pad_token_id]*pad
                mask+=[0]*pad
            chunks.append({"input_ids":torch.tensor(ids), "attention_mask":torch.tensor(mask)})
            if s+chunk_size>=len(tokens): break
        return chunks

    @torch.no_grad()
    def encode_texts(self, texts: List[str], batch_size: Optional[int]=None) -> torch.Tensor:
        bs = batch_size or self.config.batch_text
        all_embs=[]
        for i in range(0, len(texts), bs):
            b=texts[i:i+bs]
            enc=self.tokenizer(b, padding=True, truncation=True,
                               max_length=self.config.max_len, return_tensors="pt")
            enc={k:v.to(self.device_) for k,v in enc.items()}

            e1=self.m1.encode(**enc).cpu()
            e3=self.m3.encode(**enc).cpu()
            e=(e1+e3)/2.0
            all_embs.append(e)

        e=torch.cat(all_embs, dim=0)
        return F.normalize(e, p=2, dim=-1)

    @torch.no_grad()
    def encode_techniques(self, tech_list: List[Dict[str,str]]) -> Tuple[List[str], torch.Tensor]:
        ids=[]; embs=[]
        for t in tech_list:
            tid=t.get("technique_id") or t.get("id")
            txt=t.get("technique_text") or t.get("description") or ""
            chunks=self.chunk_long_text(txt)

            inp=torch.stack([c["input_ids"] for c in chunks]).to(self.device_)
            att=torch.stack([c["attention_mask"] for c in chunks]).to(self.device_)

            v1=self.m1.encode(inp, att).mean(0).cpu()
            v3=self.m3.encode(inp, att).mean(0).cpu()
            v=(v1+v3)/2.0

            ids.append(tid)
            embs.append(v)

        embs=torch.stack(embs, dim=0)
        return ids, F.normalize(embs, p=2, dim=-1)
