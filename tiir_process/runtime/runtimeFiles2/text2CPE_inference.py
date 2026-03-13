import json
import re
import time
import torch

if "tiir_logger" not in globals():
    with open("tiir_process_log_utils.py", "r", encoding="utf-8") as _f:
        exec(_f.read(), globals())


def tiir_run_text2cpe_inference(input_text, *, verbose=False, show_audit_json=False, max_raw_output_chars=160):
    class AuditLog:
        def __init__(self, live=False):
            self.entries = []
            self.start_time = time.time()
            self.live = live

        def step(self, phase, message, data=None):
            elapsed = time.time() - self.start_time
            entry = {"time_s": round(elapsed, 3), "phase": phase, "message": message}
            if data is not None:
                entry["data"] = data
            self.entries.append(entry)
            tiir_logger.log(f"inference.{phase.lower()}", message, data or {}, status="INFO")
            if self.live:
                prefix = f"[{elapsed:7.3f}s] [{phase}]"
                print(f"{prefix} {message}")

        def dump(self):
            return json.dumps(self.entries, indent=2, ensure_ascii=False)

    final_cpe_results = []
    pipeline_summary = {}
    audit = AuditLog(live=verbose)

    if not input_text or not str(input_text).strip():
        tiir_logger.log("inference", "empty_input", {}, status="ERROR")
        return {
            "final_cpe_results": [],
            "pipeline_summary": {"components_total": 0, "grounded": 0, "rejected": 0, "generation_time_s": 0.0},
            "audit_log": audit.dump(),
        }

    required_vars = ["model_cpe", "tokenizer_cpe", "vectorizer", "tfidf_matrix", "df_meta", "cpe_col", "device_cpe"]
    missing = [v for v in required_vars if v not in globals()]
    if missing:
        raise RuntimeError(f"Missing variables: {missing}. Run setup cell first.")

    audit.step("INPUT", "Received vulnerability text", {
        "char_count": len(input_text),
        "first_line": str(input_text).strip().splitlines()[0][:120],
    })

    tokenizer_cpe.padding_side = "left"
    tokenizer_cpe.pad_token = tokenizer_cpe.eos_token

    system_instruction = (
        "You are an information extraction assistant.\n"
        "Given a vulnerability description, extract all vulnerable software components.\n"
        "Return a JSON object with a single field \"components\", which is a list of objects.\n"
        "Each component object MUST have exactly these fields: part, vendor, product, target_sw, "
        "versionStartIncluding, versionStartExcluding, versionEndIncluding, versionEndExcluding.\n"
        "Return ONLY the JSON object."
    )
    one_shot_example = (
        'Description:\n'
        'A vulnerability in Apache Tomcat version 9.0.0.M1 to 9.0.0.M9 allows RCE.\n\n'
        '{"components": [{"part": "a", "vendor": "apache", "product": "tomcat", '
        '"target_sw": "*", "versionStartIncluding": "9.0.0.m1", '
        '"versionStartExcluding": "", "versionEndIncluding": "9.0.0.m9", '
        '"versionEndExcluding": ""}]}'
    )
    full_prompt = system_instruction + "\n\n" + one_shot_example + "\n\nDescription:\n" + str(input_text).strip()
    msgs = [{"role": "user", "content": full_prompt}]
    prompt_str = tokenizer_cpe.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    inputs = tokenizer_cpe(prompt_str, return_tensors="pt").to(device_cpe)
    audit.step("PROMPT", "Prompt constructed", {"prompt_tokens": int(inputs.input_ids.shape[1])})

    audit.step("LLM", "Starting greedy generation")
    t0 = time.time()
    with torch.inference_mode():
        outputs = model_cpe.generate(
            **inputs,
            max_new_tokens=512,
            do_sample=False,
            num_beams=1,
            pad_token_id=tokenizer_cpe.eos_token_id,
        )
    gen_time = time.time() - t0
    decoded = tokenizer_cpe.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True).strip()
    audit.step("LLM", "Generation finished", {
        "generation_time_s": round(gen_time, 2),
        "raw_preview": decoded[:max_raw_output_chars],
    })

    def extract_json_from_llm(text):
        text = re.sub(r"```(?:json)?\s*", "", text).strip()
        start = text.find('{"components')
        if start == -1:
            start = text.find('"components"')
            if start != -1:
                for i in range(start - 1, -1, -1):
                    if text[i] == "{":
                        start = i
                        break
                else:
                    start = -1
        if start == -1:
            return None, "NO_JSON_START"
        stack = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                stack += 1
            elif text[i] == "}":
                stack -= 1
                if stack == 0:
                    candidate = text[start:i + 1]
                    candidate = re.sub(r",\s*}", "}", candidate)
                    candidate = re.sub(r",\s*]", "]", candidate)
                    return candidate, None
        return None, "UNBALANCED_BRACKETS"

    json_str, extract_error = extract_json_from_llm(decoded)
    if extract_error:
        audit.step("PARSE", f"JSON extraction failed: {extract_error}")
        tiir_logger.log("inference.parse", "json_extraction_failed", {
            "reason": extract_error,
            "raw_preview": decoded[:max_raw_output_chars],
        }, status="ERROR")
    else:
        audit.step("PARSE", "JSON extracted successfully", {"json_length": len(json_str)})

        def find_best_cpe_match(vendor, product, threshold=0.4):
            if not vendor or not product:
                return None, 0.0, "EMPTY_QUERY"
            query = f"{vendor} {product}"
            query_vec = vectorizer.transform([query])
            scores = (query_vec @ tfidf_matrix.T).toarray().flatten()
            best_idx = scores.argmax()
            best_score = float(scores[best_idx])
            if best_score < threshold:
                return None, best_score, f"BELOW_THRESHOLD ({best_score:.4f})"
            matched_row = df_meta.iloc[best_idx]
            return matched_row, best_score, f"GROUNDED ({best_score:.4f})"

        data = json.loads(json_str)
        components = data.get("components", [])
        audit.step("GROUNDING", f"Processing {len(components)} component(s)")

        for comp in components:
            vendor = comp.get("vendor", "")
            product = comp.get("product", "")
            matched_row, score, reason = find_best_cpe_match(vendor, product)
            if matched_row is not None:
                comp["cpe23"] = matched_row[cpe_col]
                comp["match_score"] = round(min(score, 1.0), 4)
                comp["grounding_status"] = "GROUNDED"
            else:
                comp["cpe23"] = "NOT_FOUND"
                comp["match_score"] = round(score, 4)
                comp["grounding_status"] = "REJECTED"
            comp["grounding_reason"] = reason
            final_cpe_results.append(comp)

    grounded = [r for r in final_cpe_results if r.get("grounding_status") == "GROUNDED"]
    rejected = [r for r in final_cpe_results if r.get("grounding_status") == "REJECTED"]
    pipeline_summary = {
        "components_total": len(final_cpe_results),
        "grounded": len(grounded),
        "rejected": len(rejected),
        "generation_time_s": round(gen_time, 2),
    }
    audit.step("RESULT", "CPE extraction complete", pipeline_summary)

    result = {
        "final_cpe_results": final_cpe_results,
        "pipeline_summary": pipeline_summary,
        "audit_log": audit.dump(),
    }
    tiir_logger.log("inference", "final_results", result)
    if show_audit_json:
        print(result["audit_log"])
    return result
