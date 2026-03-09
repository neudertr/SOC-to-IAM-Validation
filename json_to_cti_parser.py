# json_to_cti_parser.py
# ============================================================
# JSON Pre-Processor: Routes JSON input to Inference or Loader
# ============================================================
# Änderungen gegenüber v1:
#   - Technique-Felder aus Validierung entfernt (Pipeline ist CPE-only)
#   - STIX-Bundle Erkennung hinzugefügt: Wenn type="bundle" mit
#     vulnerability-Objekten, werden CPEs extrahiert und ein
#     Loader-kompatibles CTI Object erzeugt
#   - Klarere Fehlermeldungen
# ============================================================

import json
import os
import sys

OUTPUT_STIX_FILE = "Test_STIX.json"

# Variable aus der Notebook-Zelle erwarten
if "json_file_path" not in globals():
    if "input_text" in globals() and os.path.exists(input_text):
        json_file_path = input_text
    else:
        print("❌ JSON PARSER: No file path provided.")
        # In exec()-Kontext kein sys.exit() – bricht sonst den Kernel ab
        json_file_path = None

if json_file_path and os.path.exists(json_file_path):
    print(f"🔹 JSON PARSER: Analysing '{json_file_path}'...")

    try:
        with open(json_file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        is_ready_for_loader = False
        loader_data = None

        # --------------------------------------------------
        # CHECK A: Ist es schon ein fertiges CTI Object?
        # --------------------------------------------------
        has_cpe = "cpe" in data or "x_detected_cpes" in data
        is_cti = data.get("type") in ["CTI Object", "report"]

        if has_cpe or is_cti:
            is_ready_for_loader = True
            loader_data = data

        # --------------------------------------------------
        # CHECK B: Ist es ein STIX Bundle mit Vulnerability-Objekten?
        # --------------------------------------------------
        if not is_ready_for_loader and data.get("type") == "bundle":
            objects = data.get("objects", [])
            extracted_cpes = []
            description_parts = []

            for obj in objects:
                # CPEs aus vulnerability-Objekten extrahieren
                if obj.get("type") == "vulnerability":
                    cpe_list = obj.get("x_cpe23", [])
                    for cpe_str in cpe_list:
                        extracted_cpes.append({"cpe23": cpe_str, "grounding_status": "PREBUILT"})
                    if obj.get("description"):
                        description_parts.append(obj["description"])

                # Beschreibungen aus attack-pattern Objekten
                if obj.get("type") == "attack-pattern" and obj.get("description"):
                    description_parts.append(obj["description"])

            if extracted_cpes:
                is_ready_for_loader = True
                loader_data = {
                    "type": "CTI Object",
                    "description": " | ".join(description_parts) if description_parts else "Parsed from STIX bundle",
                    "x_detected_cpes": extracted_cpes,
                    "cpe": extracted_cpes[0]["cpe23"],
                }
                print(f"   ✅ STIX Bundle parsed: {len(extracted_cpes)} CPE(s) extracted.")

        # --------------------------------------------------
        # PFAD A: FERTIGES OBJEKT → Skip Inference
        # --------------------------------------------------
        if is_ready_for_loader and loader_data:
            print("   ✅ Valid CTI Structure detected.")
            with open(OUTPUT_STIX_FILE, "w", encoding="utf-8") as f_out:
                json.dump(loader_data, f_out, indent=2)
            print(f"   💾 Saved to {OUTPUT_STIX_FILE}.")
            print("   ⏭️  Inference step will be skipped.")

        # --------------------------------------------------
        # PFAD B: ROHDATEN → Text extrahieren für Inference
        # --------------------------------------------------
        else:
            print("   ⚠️  No CTI structure found. Looking for extractable text...")

            extracted_text = ""
            potential_fields = [
                "description", "content", "body", "summary",
                "full_text", "message", "details",
            ]

            # 1. Felder direkt im Root
            for field in potential_fields:
                val = data.get(field)
                if val and isinstance(val, str):
                    extracted_text += f"{field.upper()}: {val}\n\n"

            # 2. Nested: In 'containers.cna.descriptions' (CVE-Record Format)
            if not extracted_text:
                try:
                    descs = data["containers"]["cna"]["descriptions"]
                    for d in descs:
                        if d.get("value"):
                            extracted_text += f"DESCRIPTION: {d['value']}\n\n"
                except (KeyError, TypeError):
                    pass

            # 3. Falls Array (z.B. Alerts)
            if not extracted_text and isinstance(data, list) and len(data) > 0:
                item = data[0]
                if isinstance(item, dict):
                    for field in potential_fields:
                        val = item.get(field)
                        if val and isinstance(val, str):
                            extracted_text += f"{field.upper()}: {val}\n\n"

            if extracted_text.strip():
                print(f"   📝 Extracted {len(extracted_text)} chars of text.")
                print("   🔄 Passing text to Inference Engine...")
                input_text = extracted_text.strip()

                if os.path.exists(OUTPUT_STIX_FILE):
                    os.remove(OUTPUT_STIX_FILE)
            else:
                print("   ❌ No usable text fields found in JSON.")
                print("   → Inference will run on fallback/empty input.")

    except Exception as e:
        print(f"   ❌ Critical Error in JSON Parser: {e}")
