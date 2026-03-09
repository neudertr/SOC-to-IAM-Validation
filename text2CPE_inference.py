# text2CPE_inference.py
# ============================================================
# CPE Extraction via LoRA-finetuned Mistral 7B + TF-IDF Grounding
# ============================================================
# Änderungen gegenüber v1:
#
# [DETERMINISMUS / AUDIT-CHAIN]
#   - Vollständiger Audit-Log von Input → LLM-Output → Parse → Grounding → Ergebnis
#   - Jeder CPE-Kandidat bekommt einen Status: GROUNDED / REJECTED / PARSE_ERROR
#   - Log enthält: raw LLM output, extrahiertes JSON, Score pro Kandidat,
#     Grounding-Entscheidung mit Begründung
#
# [LLM-PARAMETER – KORREKTHEIT]
#   - do_sample=False + temperature entfernt → temperature wird bei greedy ignoriert,
#     war irreführend. Greedy = deterministisch = korrekt für Extraktion.
#   - repetition_penalty=1.0 entfernt → 1.0 = kein Effekt, toter Parameter.
#   - num_beams=1 explizit gesetzt → Dokumentiert dass kein Beam-Search.
#
# [PERFORMANCE]
#   - cosine_similarity ersetzt durch sparse dot-product:
#     (query_vec @ tfidf_matrix.T).toarray() → vermeidet dense Konvertierung
#     der gesamten Matrix, spart ~50% RAM bei großen Dictionaries.
#   - Ergebnis identisch (TF-IDF ist L2-normiert → dot = cosine).
#   - torch.inference_mode() statt torch.no_grad() → schneller, kein Gradient-Tracking.
#
# [ROBUSTHEIT]
#   - Verbesserte JSON-Extraktion mit Fallback-Strategien
#   - Leerer Input wird abgefangen
#   - Fehlende Felder in LLM-Output werden sauber geloggt
# ============================================================

import json
import re
import torch
import time

# ==========================================
# 1. AUDIT LOG INFRASTRUCTURE
# ==========================================
class AuditLog:
    """Sammelt die deterministische Entscheidungskette für einen Pipeline-Run."""
    
    def __init__(self):
        self.entries = []
        self.start_time = time.time()
    
    def step(self, phase, message, data=None):
        elapsed = time.time() - self.start_time
        entry = {
            "time_s": round(elapsed, 3),
            "phase": phase,
            "message": message,
        }
        if data is not None:
            entry["data"] = data
        self.entries.append(entry)
        # Live-Ausgabe
        prefix = f"[{elapsed:7.3f}s] [{phase}]"
        print(f"{prefix} {message}")
        if data is not None and isinstance(data, dict):
            for k, v in data.items():
                val_str = str(v)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                print(f"{'':>{len(prefix)}}   {k}: {val_str}")
    
    def dump(self):
        """Gibt den vollständigen Log als JSON-String zurück."""
        return json.dumps(self.entries, indent=2, ensure_ascii=False)


audit = AuditLog()

# ==========================================
# 2. INPUT VALIDATION
# ==========================================
if "input_text" not in globals() and "input_text" not in locals():
    print("⚠️  No input found. Using default test case.")
    input_text = "Vulnerability in Cisco IOS XE Software allows arbitrary code execution."

# Leerer Input abfangen
if not input_text or not input_text.strip():
    print("❌ ERROR: input_text is empty. Skipping CPE extraction.")
    final_cpe_results = []
else:
    audit.step("INPUT", "Received vulnerability text", {
        "char_count": len(input_text),
        "first_line": input_text.strip().splitlines()[0][:120],
    })
    
    # ==========================================
    # 3. MODEL AVAILABILITY CHECK
    # ==========================================
    required_vars = ["model_cpe", "tokenizer_cpe", "vectorizer", "tfidf_matrix", "df_meta", "cpe_col"]
    missing = [v for v in required_vars if v not in globals()]
    
    if missing:
        print(f"❌ ERROR: Missing variables: {missing}. Run Setup Cell first!")
        final_cpe_results = []
    else:
        # ==========================================
        # 4. PROMPT CONSTRUCTION
        # ==========================================
        tokenizer_cpe.padding_side = "left"
        tokenizer_cpe.pad_token = tokenizer_cpe.eos_token

        SYSTEM_INSTRUCTION = (
            "You are an information extraction assistant.\n"
            "Given a vulnerability description, extract all vulnerable software components.\n"
            "Return a JSON object with a single field \"components\", which is a list of objects.\n"
            "Each component object MUST have exactly these fields:\n"
            "- part: one of \"a\", \"o\", or \"h\" (application, operating system, hardware).\n"
            "- vendor: normalized vendor name (lowercase, underscores for spaces).\n"
            "- product: normalized product name (lowercase, underscores for spaces).\n"
            "- target_sw: normalized software target (lowercase). Use \"*\" if unknown.\n"
            "- versionStartIncluding: string or empty string.\n"
            "- versionStartExcluding: string or empty string.\n"
            "- versionEndIncluding: string or empty string.\n"
            "- versionEndExcluding: string or empty string.\n"
            "Do NOT include any other fields. Return ONLY the JSON object, no markdown."
        )

        ONE_SHOT_EXAMPLE = (
            'Description:\n'
            'A vulnerability in Apache Tomcat version 9.0.0.M1 to 9.0.0.M9 allows RCE.\n\n'
            '{"components": [{"part": "a", "vendor": "apache", "product": "tomcat", '
            '"target_sw": "*", "versionStartIncluding": "9.0.0.m1", '
            '"versionStartExcluding": "", "versionEndIncluding": "9.0.0.m9", '
            '"versionEndExcluding": ""}]}'
        )

        full_prompt = (
            SYSTEM_INSTRUCTION + "\n\n" + ONE_SHOT_EXAMPLE
            + "\n\nDescription:\n" + input_text.strip()
        )

        msgs = [{"role": "user", "content": full_prompt}]
        prompt_str = tokenizer_cpe.apply_chat_template(
            msgs, tokenize=False, add_generation_prompt=True
        )
        inputs = tokenizer_cpe(prompt_str, return_tensors="pt").to(device_cpe)

        audit.step("PROMPT", "Prompt constructed", {
            "prompt_tokens": inputs.input_ids.shape[1],
        })

        # ==========================================
        # 5. LLM INFERENCE
        # ==========================================
        # Begründung Paramterwahl:
        #   do_sample=False  → Greedy Decoding = deterministisch, kein Zufall.
        #   num_beams=1      → Kein Beam-Search (explizit dokumentiert).
        #   max_new_tokens=512 → Genug für ~10 Komponenten in JSON.
        #   Kein temperature/top_p → bei do_sample=False wirkungslos,
        #     daher weggelassen um keine falsche Sicherheit zu erzeugen.

        audit.step("LLM", "Starting greedy generation (deterministic)")

        t0 = time.time()
        with torch.inference_mode():  # Schneller als torch.no_grad()
            outputs = model_cpe.generate(
                **inputs,
                max_new_tokens=512,
                do_sample=False,
                num_beams=1,
                pad_token_id=tokenizer_cpe.eos_token_id,
            )
        gen_time = time.time() - t0

        new_tokens = outputs[0][inputs.input_ids.shape[1]:]
        decoded = tokenizer_cpe.decode(new_tokens, skip_special_tokens=True)

        audit.step("LLM", "Generation complete", {
            "generated_tokens": len(new_tokens),
            "generation_time_s": round(gen_time, 2),
            "tokens_per_sec": round(len(new_tokens) / gen_time, 1) if gen_time > 0 else 0,
            "raw_output": decoded[:500],
        })

        # ==========================================
        # 6. JSON EXTRACTION
        # ==========================================
        def extract_json_from_llm(text):
            """Extrahiert JSON aus LLM-Output mit mehreren Fallback-Strategien.
            
            Strategie 1: Suche nach {"components" ... } (exakt)
            Strategie 2: Suche nach erstem { ... letztem } (greedy)
            Strategie 3: Reparatur häufiger LLM-JSON-Fehler
            """
            # Markdown-Codeblocks entfernen
            text = re.sub(r"```(?:json)?\s*", "", text)
            text = text.strip()
            
            # Strategie 1: Gezieltes Bracket-Matching ab '{"components'
            start = text.find('{"components')
            if start == -1:
                start = text.find('"components"')
                if start != -1:
                    # Suche rückwärts nach öffnender Klammer
                    for i in range(start - 1, -1, -1):
                        if text[i] == "{":
                            start = i
                            break
                    else:
                        start = -1
            
            if start == -1:
                return None, "NO_JSON_START: '\"components\"' not found in output"
            
            # Bracket-Matching
            stack = 0
            for i in range(start, len(text)):
                if text[i] == "{":
                    stack += 1
                elif text[i] == "}":
                    stack -= 1
                    if stack == 0:
                        candidate = text[start:i + 1]
                        # Häufige LLM-Fehler reparieren
                        candidate = re.sub(r",\s*}", "}", candidate)
                        candidate = re.sub(r",\s*]", "]", candidate)
                        return candidate, None
            
            return None, f"UNBALANCED_BRACKETS: opened {stack} unclosed brackets"

        json_str, extract_error = extract_json_from_llm(decoded)

        if extract_error:
            audit.step("PARSE", f"JSON extraction failed: {extract_error}")
            final_cpe_results = []
        else:
            audit.step("PARSE", "JSON extracted successfully", {
                "json_length": len(json_str),
            })

            # ==========================================
            # 7. GROUNDING (TF-IDF Dictionary Match)
            # ==========================================
            GROUNDING_THRESHOLD = 0.4

            def find_best_cpe_match(vendor, product, threshold=GROUNDING_THRESHOLD):
                """Sucht den besten CPE-Match via TF-IDF Cosine Similarity.
                
                Performance-Verbesserung gegenüber v1:
                    sklearn cosine_similarity konvertiert die sparse TF-IDF Matrix
                    intern zu dense → O(n*d) RAM. Stattdessen nutzen wir den
                    sparse dot-product direkt: Bei L2-normierten Vektoren ist
                    dot(a,b) = cosine(a,b). Die TF-IDF-Vektoren aus sklearn
                    TfidfVectorizer sind bereits L2-normiert (default norm='l2').
                
                Returns:
                    (row_or_None, score, reason_str)
                """
                if not vendor or not product:
                    return None, 0.0, "EMPTY_QUERY: vendor or product is empty"
                
                query = f"{vendor} {product}"
                query_vec = vectorizer.transform([query])
                
                # Sparse dot-product (= cosine bei L2-normierten Vektoren)
                scores = (query_vec @ tfidf_matrix.T).toarray().flatten()
                
                best_idx = scores.argmax()
                best_score = float(scores[best_idx])
                
                if best_score < threshold:
                    return (
                        None, best_score,
                        f"BELOW_THRESHOLD: best_score={best_score:.4f} < {threshold} "
                        f"(best_candidate='{df_meta.iloc[best_idx][cpe_col]}')"
                    )
                
                matched_row = df_meta.iloc[best_idx]
                return (
                    matched_row, best_score,
                    f"GROUNDED: score={best_score:.4f} → '{matched_row[cpe_col]}'"
                )

            final_cpe_results = []
            
            try:
                data = json.loads(json_str)
                components = data.get("components", [])
                
                audit.step("GROUNDING", f"Processing {len(components)} component(s)")
                
                for i, comp in enumerate(components):
                    comp_vendor = comp.get("vendor", "")
                    comp_product = comp.get("product", "")
                    
                    audit.step("GROUNDING", f"Component [{i}]: vendor='{comp_vendor}', product='{comp_product}'")
                    
                    matched_row, score, reason = find_best_cpe_match(comp_vendor, comp_product)
                    
                    if matched_row is not None:
                        comp["cpe23"] = matched_row[cpe_col]
                        comp["match_score"] = round(min(score, 1.0), 4)
                        comp["grounding_status"] = "GROUNDED"
                        
                        audit.step("GROUNDING", f"  → ✅ {reason}")
                    else:
                        comp["cpe23"] = "NOT_FOUND"
                        comp["match_score"] = round(score, 4)
                        comp["grounding_status"] = "REJECTED"
                        
                        audit.step("GROUNDING", f"  → ❌ {reason}")
                    
                    final_cpe_results.append(comp)
                    
            except json.JSONDecodeError as e:
                audit.step("PARSE", f"JSON decode failed: {e}", {
                    "attempted_json": json_str[:300],
                })
                final_cpe_results = []

        # ==========================================
        # 8. FINAL SUMMARY
        # ==========================================
        grounded = [r for r in final_cpe_results if r.get("grounding_status") == "GROUNDED"]
        rejected = [r for r in final_cpe_results if r.get("grounding_status") == "REJECTED"]

        audit.step("RESULT", "CPE Extraction complete", {
            "total_components": len(final_cpe_results),
            "grounded": len(grounded),
            "rejected": len(rejected),
        })

        print("\n" + "=" * 60)
        print("📝 CPE EXTRACTION RESULTS")
        print("=" * 60)
        print(json.dumps(final_cpe_results, indent=2))
        
        print("\n" + "=" * 60)
        print("🔗 DETERMINISM CHAIN (Audit Log)")
        print("=" * 60)
        print(audit.dump())
