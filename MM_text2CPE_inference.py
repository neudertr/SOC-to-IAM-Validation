# @title text2CPE Inference (One-Shot Fix)

import json
import re
import torch
import time
from sklearn.metrics.pairwise import cosine_similarity

# ==========================================
# 1. INPUT
# ==========================================
input_text = """
Vulnerability in Cisco IOS XE Software allows an unauthenticated, remote attacker to execute arbitrary code. 
Affected is Cisco IOS XE version 16.12.1 through 17.3.3 on ASR 1000 Series Routers.
"""

# ==========================================
# 2. SETUP
# ==========================================
tokenizer_cpe.padding_side = "left" 
tokenizer_cpe.pad_token = tokenizer_cpe.eos_token

# ==========================================
# 3. DER "MAGIC" PROMPT (One-Shot)
# ==========================================
# Wir behalten deine System-Instruktion, geben aber ein BEISPIEL (One-Shot)
# Das zeigt dem Modell: "Kopiere Versionen! Liste keine Hardware auf, die nicht da steht!"

base_instruction = """You are an information extraction assistant.
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

# DAS IST DER TRICK: Ein Beispiel vor dem echten Input
one_shot_example = """
Description:
A vulnerability in Apache Tomcat version 9.0.0.M1 to 9.0.0.M9 allows RCE on DSM Routers of series 100.

{"components": [
    {
        "part": "a", 
        "vendor": "apache", 
        "product": "tomcat", 
        "target_sw": "DSM100", 
        "versionStartIncluding": "9.0.0.m1", 
        "versionStartExcluding": "", 
        "versionEndIncluding": "9.0.0.m9", 
        "versionEndExcluding": ""
    }
]}
"""

# ==========================================
# 4. HILFSFUNKTIONEN
# ==========================================
def extract_json_smart(text):
    start = text.find('{"components"') # Wir suchen explizit den Start
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
# 5. GENERIERUNG
# ==========================================
print("🚀 Starte Extraktion (One-Shot Mode)...")
start_time = time.time()

# Wir bauen den Kontext: Instruktion -> Beispiel -> Echte Aufgabe
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
        repetition_penalty=1.0,  # WICHTIG: 1.0 erlaubt das Kopieren der Zahlen!
        temperature=0.1          # Ganz leicht erhöht, hilft manchmal bei Formatierung
    )

decoded = tokenizer_cpe.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
print(f"⏱️ Zeit: {time.time() - start_time:.2f}s")

# ==========================================
# 6. POST-PROCESSING
# ==========================================
result_cpe = []

try:
    json_str = extract_json_smart(decoded)
    if json_str:
        json_str = re.sub(r",\s*}", "}", json_str)
        json_str = re.sub(r",\s*]", "]", json_str)
        data = json.loads(json_str)
        
        for comp in data.get("components", []):
            match, score = find_best_match(comp.get("vendor"), comp.get("product"))
            
            if match is not None:
                # DB Daten
                comp["cpe23"] = match[cpe_col]
                comp["vendor"] = match["vendor"]
                comp["product"] = match["product"]
                comp["match_score"] = float(score)
            else:
                comp["cpe23"] = "NOT_FOUND"
                comp["match_score"] = 0.0
            
            result_cpe.append(comp)
    else:
        print("⚠️ Kein JSON gefunden.")
        print("Raw:", decoded)

except Exception as e:
    print(f"❌ Fehler: {e}")
    print("Raw:", decoded)

print("\n--- Ergebnis ---")
print(json.dumps(result_cpe, indent=2))
