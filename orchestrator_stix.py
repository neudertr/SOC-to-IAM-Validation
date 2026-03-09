# orchestrator_stix.py
# ============================================================
# CTI Object Builder (CPE-only Edition)
# ============================================================
# Änderungen gegenüber v1:
#   - text2technique Felder komplett entfernt (x_detected_techniques, technique)
#   - UUID deterministisch aus description-Hash generiert
#     → gleicher Input = gleiche ID = reproduzierbar
#   - Validierung: Leere CPE-Liste wird geloggt, nicht stillschweigend ignoriert
#   - Audit-Chain wird fortgeführt (wenn aus text2CPE_inference vorhanden)
# ============================================================

import json
import uuid
import hashlib
import datetime
import os

OUTPUT_STIX_FILE = "Test_STIX.json"

print("🔹 ORCHESTRATOR: Generating CTI Object from CPE inference data...")

# ==========================================
# 1. COLLECT INPUTS
# ==========================================

# Beschreibung aus der Notebook-Zelle
current_description = "Auto-generated report."
if "input_text" in globals() and input_text:
    current_description = input_text.strip()
else:
    print("   ⚠️  Variable 'input_text' not found – using default description.")

# CPE-Ergebnisse aus text2CPE_inference
detected_cpes = []
if "final_cpe_results" in globals() and final_cpe_results:
    detected_cpes = final_cpe_results
    print(f"   ✅ {len(detected_cpes)} CPE(s) received from inference.")
else:
    print("   ⚠️  No CPE results found (final_cpe_results empty or missing).")

# ==========================================
# 2. VALIDATION
# ==========================================
grounded_cpes = [c for c in detected_cpes if c.get("grounding_status") == "GROUNDED"]
rejected_cpes = [c for c in detected_cpes if c.get("grounding_status") == "REJECTED"]

print(f"   📊 CPE Summary: {len(grounded_cpes)} grounded, {len(rejected_cpes)} rejected")

if not grounded_cpes:
    print("   ⚠️  WARNING: No grounded CPEs! Loader will find no matches.")

# ==========================================
# 3. BUILD CTI OBJECT
# ==========================================

# Deterministischer UUID: SHA-256 über den Beschreibungstext
# → Gleicher Input erzeugt immer die gleiche Object-ID.
# Begründung: Reproduzierbarkeit in der Audit-Chain.
desc_hash = hashlib.sha256(current_description.encode("utf-8")).hexdigest()
deterministic_id = str(uuid.UUID(desc_hash[:32]))

stix_output = {
    "type": "CTI Object",
    "id": deterministic_id,
    "created": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "name": "Automated Threat Intel Report",
    "description": current_description,

    # Alle CPE-Ergebnisse (inkl. REJECTED für Nachvollziehbarkeit)
    "x_detected_cpes": detected_cpes,

    # Best-Match CPE für Legacy-/einfache Systeme
    "cpe": (
        grounded_cpes[0]["cpe23"]
        if grounded_cpes
        else "cpe:2.3:*:*:*:*:*:*:*:*:*:*:*"
    ),
}

# ==========================================
# 4. SAVE
# ==========================================
try:
    with open(OUTPUT_STIX_FILE, "w", encoding="utf-8") as f:
        json.dump(stix_output, f, indent=2, ensure_ascii=False)
    print(f"💾 CTI Object saved: {os.path.abspath(OUTPUT_STIX_FILE)}")
except Exception as e:
    print(f"❌ Error saving CTI Object: {e}")
