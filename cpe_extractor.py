# DATEINAME: cpe_extractor.py

import torch
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path
from scipy.sparse import load_npz
from sklearn.metrics.pairwise import cosine_similarity
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
from peft import PeftModel

# ==============================================================================
# CLASS: CPEMatcher (Fuzzy Matching Logic)
# ==============================================================================
class CPEMatcher:
    """Matches generated strings against the official CPE dictionary using TF-IDF."""
    
    def __init__(self, vectorizer_path: str, matrix_path: str, cpe_meta_path: str):
        print(f"[Matcher] Loading artifacts from {Path(vectorizer_path).parent}...")
        
        if not Path(vectorizer_path).exists():
            raise FileNotFoundError(f"Vectorizer not found: {vectorizer_path}")
            
        with open(vectorizer_path, "rb") as f:
            self.vectorizer = pickle.load(f)
        
        self.tfidf_matrix = load_npz(matrix_path)
        self.df = pd.read_parquet(cpe_meta_path)
        self.cpe_entries = self.df.to_dict("records")
        print(f"[Matcher] Ready with {self.tfidf_matrix.shape[0]} entries.")

    def match(self, vendor: str, product: str, threshold: float = 0.4):
        """Returns best match (vendor, product, score) or original if below threshold."""
        query = f"{vendor} {product}".strip()
        if not query:
            return vendor, product, 0.0
            
        try:
            query_vec = self.vectorizer.transform([query])
            sims = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
            best_idx = np.argmax(sims)
            score = sims[best_idx]
            
            if score < threshold:
                return vendor, product, float(score)
                
            best_match = self.cpe_entries[best_idx]
            return best_match["vendor"], best_match["product"], float(score)
        except Exception as e:
            print(f"[Matcher Warning] Error matching '{query}': {e}")
            return vendor, product, 0.0

# ==============================================================================
# CLASS: CPEExtractor (LLM Wrapper)
# ==============================================================================
class CPEExtractor:
    """Wrapper for the quantized LLM and LoRA adapter."""
    
    def __init__(self, model_id: str, adapter_path: str, matcher_paths: dict = None, max_tokens: int = 350):
        self.model_id = model_id
        self.adapter_path = adapter_path
        self.max_tokens = max_tokens
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
        self.model = None
        self.tokenizer = None
        self.matcher = None
        
        # --- EXACT SYSTEM PROMPT FROM TRAINING ---
        self.system_prompt = """You are an information extraction assistant.
Given a vulnerability description, extract all vulnerable software components.
Return a JSON object with a single field "components", which is a list of objects.
Each component object MUST have the following fields:

- part: one of "a", "o", or "h" (application, operating system, hardware).
- vendor: normalized vendor name (lowercase), as in the CPE.
- product: normalized product name (lowercase), as in the CPE.
- target_sw: normalized software target (lowercase), as in the CPE (may be empty string).
- versionStartIncluding: string (may be empty).
- versionStartExcluding: string (may be empty).
- versionEndIncluding: string (may be empty).
- versionEndExcluding: string (may be empty).

Do NOT include any other fields. Do NOT include explanations.
Return ONLY the JSON object."""

        self._load_model()
        
        if matcher_paths:
            self.matcher = CPEMatcher(
                vectorizer_path=matcher_paths["vectorizer"],
                matrix_path=matcher_paths["matrix"],
                cpe_meta_path=matcher_paths["meta"]
            )

    def _load_model(self):
        print(f"[Extractor] Loading base model {self.model_id}...")
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
        )
        
        try:
            # Optimized loading for bitsandbytes (no device_map auto conflict)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_id,
                quantization_config=bnb_config,
                torch_dtype=torch.float16,
            )
        except Exception as e:
            print(f"[Extractor Warning] Optimized load failed: {e}. Retrying with fallback...")
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_id, 
                device_map="auto", 
                torch_dtype=torch.float16
            )

        print(f"[Extractor] Loading LoRA adapter from {Path(self.adapter_path).name}...")
        self.model = PeftModel.from_pretrained(self.model, self.adapter_path)
        self.model.eval()
        
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_id)
        self.tokenizer.pad_token = self.tokenizer.eos_token
        print("[Extractor] Model ready.")

    def extract(self, description: str, use_matcher: bool = True) -> dict:
        messages = [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": description},
        ]
        prompt = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = self.tokenizer(prompt, return_tensors="pt", padding=True).to(self.device)

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs, 
                max_new_tokens=self.max_tokens, 
                do_sample=False, 
                pad_token_id=self.tokenizer.eos_token_id,
            )
        
        output_ids = outputs.sequences[:, inputs.input_ids.shape[1]:]
        output_text = self.tokenizer.decode(output_ids[0], skip_special_tokens=True)
        
        try:
            start = output_text.find("{")
            end = output_text.rfind("}") + 1
            json_str = output_text[start:end]
            data = json.loads(json_str)
        except Exception:
            return {"error": "Invalid JSON", "raw_output": output_text}

        if use_matcher and self.matcher and "components" in data:
            for comp in data["components"]:
                raw_v = comp.get("vendor", "")
                raw_p = comp.get("product", "")
                clean_v, clean_p, score = self.matcher.match(raw_v, raw_p)
                comp["vendor"] = clean_v
                comp["product"] = clean_p
                comp["_match_score"] = round(score, 3)

        return data
