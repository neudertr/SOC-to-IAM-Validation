# orchestrator_stix.py
import json
import uuid
import datetime
import os

# 1. Output Dateiname
OUTPUT_STIX_FILE = "Test_STIX.json"

print("🔹 ORCHESTRATOR: Generiere CTI Object aus Inference-Daten...")

# 2. Beschreibung holen (aus dem Input der Zelle)
current_description = "Auto-generated report."
if 'input_text' in globals():
    # Wir nehmen den Text aus der Zelle und bereinigen ihn leicht
    current_description = input_text.strip()
else:
    print("   ⚠️ Variable 'input_text' nicht gefunden. Nutze Standard-Beschreibung.")

# 3. Listen aus dem Speicher holen
detected_cpes = []
detected_techniques = []

# A. CPEs
if 'final_cpe_results' in globals() and final_cpe_results:
    detected_cpes = final_cpe_results
    print(f"   ✅ {len(detected_cpes)} CPEs übernommen.")

# B. Techniques
if 'results' in globals() and results:
    # results ist [(id, name, score), ...]. Wir machen daraus Objekte.
    for item in results:
        detected_techniques.append({
            "id": item[0],
            "name": item[1],
            "score": float(item[2])
        })
    print(f"   ✅ {len(detected_techniques)} Techniken übernommen.")


# 4. Das Objekt bauen
stix_output = {
  # --- DEINE ÄNDERUNG ---
  "type": "CTI Object",                 # Typ angepasst
  "description": current_description,   # Input-Text als Beschreibung
  # ----------------------
  
  "id": str(uuid.uuid4()),
  "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
  "name": "Automated Threat Intel Report",
  
  # Die detaillierten Listen (Alle Ergebnisse)
  "x_detected_techniques": detected_techniques,
  "x_detected_cpes": detected_cpes,
  
  # Die "Gewinner" (Best Match) für Legacy-Systeme
  # Das sind einfach Kopien des jeweils ersten Eintrags der Listen oben
  "technique": detected_techniques[0]['id'] if detected_techniques else "T0000",
  "cpe": detected_cpes[0]['cpe23'] if detected_cpes else "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"
}

# 5. Speichern
try:
    with open(OUTPUT_STIX_FILE, "w", encoding="utf-8") as f:
        json.dump(stix_output, f, indent=2)
    print(f"💾 CTI Object gespeichert: {os.path.abspath(OUTPUT_STIX_FILE)}")
except Exception as e:
    print(f"❌ Fehler beim Speichern: {e}")
