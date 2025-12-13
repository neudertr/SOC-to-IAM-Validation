# text2CPE_inference.py

import json
import re
import torch
import time
from sklearn.metrics.pairwise import cosine_similarity

# --- 1. SAFETY CHECK: Get Input ---
# If the notebook defined 'input_text', we use it.
# If not (e.g. running standalone), we use a dummy default.
if 'input_text' not in globals() and 'input_text' not in locals():
    print("⚠️ No input found. Using default test case.")
    input_text = "Vulnerability in Cisco IOS XE Software allows arbitrary code execution."

# --- 2. SAFETY CHECK: Verify Models ---
required_vars = ['model_cpe', 'tokenizer_cpe', 'vectorizer', 'tfidf_matrix']
if not all(var in globals() for var in required_vars):
    print(f"❌ ERROR: Models not loaded. Please run the Setup Cell first.")
else:
    # ==========================================
    # 3. SETUP & PROMPTING
    # ==========================================
    tokenizer_cpe.padding_side = "left" 
    tokenizer_cpe.pad_token = tokenizer_cpe.eos_token

    base_instruction = """You are an information extraction assistant.
    Given a vulnerability description, extract all vulnerable software components.
    Return a JSON object with a single field "components", which is a list of objects.
    Each component object MUST have the following fields:
    - part: one of "a", "o", or "h" (application, operating system, hardware).
    - vendor: normalized vendor name (lowercase).
    - product: normalized product name (lowercase).
    - target_sw: normalized software target (lowercase).
    - versionStartIncluding: string.
    - versionStartExcluding: string.
    - versionEndIncluding: string.
    - versionEndExcluding: string.
    Do NOT include any other fields. Return ONLY the JSON object."""

    one_shot_example = """
    Description:
    A vulnerability in Apache Tomcat version 9.0.0.M1 to 9.0.0.M9 allows RCE on DSM Routers of series 100.

    {"components": [
        {
            "part": "a", "vendor": "apache", "product": "tomcat", "target_sw": "DSM100", 
            "versionStartIncluding": "9.0.0.m1", "versionStartExcluding": "", 
            "versionEndIncluding": "9.0.0.m9", "versionEndExcluding": ""
        }
    ]}
    """

    # ==========================================
    # 4. HELPERS
    # ==========================================
    def extract_json_smart(text):
        start = text.find('{"components"')
        if start == -1: start = text.find("{")
        if start == -1: return None
        stack = 0
        for i, char in enumerate(text[start:], start=start):
            if char == "{": stack += 1
            elif char == "}":
                stack -= 1
                if stack == 0: return text[start : i+1]
        return None

    def find_best_match(vendor, product, threshold=0.4):
        if not vendor or not product: return None, 0.0
        query = f"{vendor} {product}"
        query_vec = vectorizer.transform([query])
        scores = cosine_similarity(query_vec, tfidf_matrix).flatten()
        best_idx = scores.argmax()
        best_score = scores[best_idx]
        if best_score < threshold: return None, best_score
        return df_meta.iloc[best_idx], best_score

    # ==========================================
    # 5. EXECUTION
    # ==========================================
    print(f"🔹 Processing CPE Extraction...")
    
    full_prompt_content = base_instruction + "\n\n" + one_shot_example + "\n\nDescription:\n" + input_text
    msgs = [{"role": "user", "content": full_prompt_content}]
    prompt_str = tokenizer_cpe.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer_cpe(prompt_str, return_tensors="pt").to(device_cpe)

    with torch.no_grad():
        outputs = model_cpe.generate(
            **inputs, 
            max_new_tokens=512, 
            do_sample=False, 
            pad_token_id=tokenizer_cpe.eos_token_id,
            repetition_penalty=1.0,
            temperature=0.1
        )

    decoded = tokenizer_cpe.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)

    # ==========================================
    # 6. POST-PROCESSING & OUTPUT
    # ==========================================
    final_cpe_results = []
    
    json_str = extract_json_smart(decoded)
    if json_str:
        # Cleanup common JSON errors from LLMs
        json_str = re.sub(r",\s*}", "}", json_str)
        json_str = re.sub(r",\s*]", "]", json_str)
        try:
            data = json.loads(json_str)
            for comp in data.get("components", []):
                match, score = find_best_match(comp.get("vendor"), comp.get("product"))
                if match is not None:
                    comp["cpe23"] = match[cpe_col]
                    comp["match_score"] = min(float(score), 1.0)
                else:
                    comp["cpe23"] = "NOT_FOUND"
                    comp["match_score"] = 0.0
                final_cpe_results.append(comp)
        except json.JSONDecodeError:
             print("⚠️ JSON Decode Error")

    print("\n📝 CPE Extraction Results:")
    print(json.dumps(final_cpe_results, indent=2))
