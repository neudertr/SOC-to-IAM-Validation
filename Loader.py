import pandas as pd
import json
import os
import glob

# ==========================================
# 1. KONFIGURATION & PFADE
# ==========================================
# In Kaggle liegen die vom Setup geladenen Files meist direkt im Working Dir.
WORKING_DIR = os.getcwd()

# Input Dateien (werden vom Setup hierher geladen)
ACCOUNTS_CSV_PATH = os.path.join(WORKING_DIR, "Accounts.CSV")
PERMISSIONS_CSV_PATH = os.path.join(WORKING_DIR, "Permissions.CSV")
STIX_PATH = os.path.join(WORKING_DIR, "Test_STIX.json")

# Output Dateien
OUTPUT_REPORT_PATH = os.path.join(WORKING_DIR, "modification_report.txt")
ACCOUNTS_MODIFIED_PATH = os.path.join(WORKING_DIR, "accounts_modified.csv")
PERMISSIONS_MODIFIED_PATH = os.path.join(WORKING_DIR, "permissions_modified.csv")

CPE_COLUMN_NAME = "Software_System"

field_names = [
    "cpe_prefix", "cpe_version", "part", "vendor", "product", "version", 
    "update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"
]

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================

def read_csv(file_path: str) -> pd.DataFrame:
    # Robustes Lesen: Versucht verschiedene Trennzeichen, falls das CSV "böse" ist
    try:
        return pd.read_csv(file_path, sep=';', engine='python') # Dein Default
    except:
        return pd.read_csv(file_path, sep=',', engine='python') # Fallback

def save_csv(df: pd.DataFrame, output_path: str):
    df.to_csv(output_path, sep=';', index=False)

def write_report(report_lines: list, output_path: str):
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.writelines(line + "\n" for line in report_lines)

def split_cpe(cpe_string: str):
    """
    Zerlegt einen CPE 2.3 String in ein Dictionary.
    Erwartet Format: cpe:2.3:part:vendor:product:version:update:edition:...
    """
    if not cpe_string.startswith("cpe:2.3"):
        return {} # Kein valider CPE 2.3
        
    parts = cpe_string.split(":")
    # Wir schneiden 'cpe' und '2.3' (die ersten 2) ab für das Mapping auf field_names
    # field_names beginnt mit 'cpe_prefix' (cpe) und 'cpe_version' (2.3)
    
    parsed = {}
    for i, name in enumerate(field_names):
        if i < len(parts):
            val = parts[i]
            # Wildcards (*) als None oder leeren String behandeln für besseren Vergleich?
            # Hier lassen wir sie als String "*", aber beim Vergleich beachten wir das.
            parsed[name] = val
        else:
            parsed[name] = "*"
            
    return parsed

def compare_cpe_parts(remote_cpe: dict, local_cpe: dict):
    """
    Vergleicht zwei CPEs feldweise.
    Matchlogik: Wenn Remote-Feld != '*' und != Local-Feld, dann KEIN Match.
    """
    matched_fields = []
    
    # Kritische Felder, die übereinstimmen MÜSSEN (wenn nicht Wildcard)
    check_fields = ["vendor", "product", "version", "update", "target_sw"]
    
    for field in check_fields:
        r_val = remote_cpe.get(field, "*")
        l_val = local_cpe.get(field, "*")
        
        # Bereinigen
        r_val = str(r_val).strip().lower()
        l_val = str(l_val).strip().lower()
        
        # Wenn Threat Intel sagt "*", passt es auf alles -> weiter
        if r_val == "*":
            continue
            
        # Wenn Asset sagt "*", ist es ungenau -> wir nehmen an es könnte passen (oder false positive prevention?)
        # Hier: Strict Match -> Wenn Asset "*" hat, aber Threat eine Version, wissen wir es nicht genau.
        # Wir gehen davon aus: Match nur bei expliziter Gleichheit.
        
        if r_val == l_val:
            matched_fields.append(field)
        else:
            # Konflikt! Z.B. Threat sagt "16.12.1", Asset sagt "17.3".
            return (False, [])

    # Wenn wir hier ankommen, gab es keine Konflikte in den spezifizierten Feldern.
    # Ein Match ist es aber nur, wenn mindestens Vendor & Product gematcht haben.
    if "vendor" in matched_fields and "product" in matched_fields:
        return (True, matched_fields)
    
    return (False, [])

def row_matches(row, value, cpe_parts_remote):
    # 1. Einfacher String Match (Fallback)
    for col in row.index:
        cell = str(row[col]).strip().lower()
        if cell == str(value).strip().lower():
            return True, ["exact_string_match"]

    # 2. Intelligenter CPE Match
    if CPE_COLUMN_NAME in row and isinstance(row[CPE_COLUMN_NAME], str):
        local_cpe_str = row[CPE_COLUMN_NAME]
        if local_cpe_str.startswith("cpe:"):
            local_cpe_dict = split_cpe(local_cpe_str)
            return compare_cpe_parts(cpe_parts_remote, local_cpe_dict)
            
    return False, []

# ==========================================
# 3. CORE LOGIC
# ==========================================

def applyRules(row, techniques, description, cpe_parts, entity_type):
    # Setup Columns
    if "Temporal_Criticality" not in row.index: row["Temporal_Criticality"] = ""
    if "Deactivated" not in row.index: row["Deactivated"] = ""

    # --- RULESET ---
    
    # RULE 1: Account Deactivation bei "Create Account" (T1136) oder Credentials Dumping (T1003)
    # Wir prüfen, ob eine der gefundenen Techniken kritisch ist
    critical_techniques = ["T1136", "T1003", "T1059"] # Create Account, Cred Dumping, Command/Scripting
    
    hit_technique = any(t['id'].startswith(ct) for t in techniques for ct in critical_techniques)
    
    if entity_type == "account":
        # Wenn eine kritische Technik erkannt wurde UND das CPE passt -> Deaktivieren
        if hit_technique:
            row["Deactivated"] = "true"
        else:
            # Fallback: Nur Warnung oder Soft-Deactivate
            row["Deactivated"] = "review_needed"

    if entity_type == "permission":
        criticality = str(row.get("Criticality", "")).upper()
        # Escalation Logic
        if criticality == "MEDIUM":
            row["Temporal_Criticality"] = "HIGH"
        elif criticality == "HIGH":
            row["Temporal_Criticality"] = "VERY_HIGH"
            
    return row

def match_stix_to_dataframe(df: pd.DataFrame, stix_data: dict, entity_type: str):
    report = []
    
    # 1. Listen laden (Neu: Support für Listen im CTI Object)
    cpe_list = stix_data.get("x_detected_cpes", [])
    technique_list = stix_data.get("x_detected_techniques", [])
    
    # Fallback für alte JSONs
    if not cpe_list and stix_data.get("cpe"):
        cpe_list = [{"cpe23": stix_data.get("cpe")}]
    
    # Description
    desc = stix_data.get("description", "")

    # Iteration über alle Zeilen der CSV
    for idx, row in df.iterrows():
        
        # Check gegen ALLE gefundenen CPEs aus dem Report
        for cpe_obj in cpe_list:
            remote_cpe_str = cpe_obj.get("cpe23", "")
            remote_cpe_parts = split_cpe(remote_cpe_str)
            
            matched, matched_fields = row_matches(row, remote_cpe_str, remote_cpe_parts)
            
            if matched:
                # Match gefunden! Regeln anwenden.
                updated_row = applyRules(row, technique_list, desc, remote_cpe_parts, entity_type)
                df.loc[idx] = updated_row
                
                # Logging
                match_info = f"Matched Fields: {matched_fields}" if matched_fields else "Exact Match"
                report.append(
                    f"[{entity_type.upper()}] HIT on ID {row.get('ID', 'N/A')}: "
                    f"Asset CPE matches Threat CPE '{remote_cpe_str}'. "
                    f"Action -> Deactivated={updated_row.get('Deactivated','')}, Crit={updated_row.get('Temporal_Criticality','')}"
                )
                # Break inner loop (ein Match reicht pro Zeile)
                break 

    return df, report

def startLoader():
    print(f"🚀 Starte Loader im Verzeichnis: {WORKING_DIR}")
    
    # Check Files
    if not os.path.exists(ACCOUNTS_CSV_PATH) or not os.path.exists(PERMISSIONS_CSV_PATH):
        print("❌ Fehler: CSV Dateien fehlen! Wurden sie vom Setup heruntergeladen?")
        return

    if not os.path.exists(STIX_PATH):
        print("❌ Fehler: Test_STIX.json fehlt! Wurde die Inference ausgeführt?")
        return

    # Load Data
    accounts_df = read_csv(ACCOUNTS_CSV_PATH)
    permissions_df = read_csv(PERMISSIONS_CSV_PATH)
    
    with open(STIX_PATH, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    print(f"📥 Verarbeite CTI Object: {stix_data.get('type', 'Unknown')} - {stix_data.get('id')}")

    # Process
    all_reports = []
    
    permissions_df, perm_report = match_stix_to_dataframe(permissions_df, stix_data, "permission")
    accounts_df, acc_report = match_stix_to_dataframe(accounts_df, stix_data, "account")
    
    all_reports.extend(perm_report)
    all_reports.extend(acc_report)

    # Save
    save_csv(accounts_df, ACCOUNTS_MODIFIED_PATH)
    save_csv(permissions_df, PERMISSIONS_MODIFIED_PATH)

    # Report
    if not all_reports:
        all_reports.append("No matches found based on current Threat Intel.")
    else:
        all_reports.insert(0, f"Modification Report for Threat: {stix_data.get('description')[:50]}...")
        
    write_report(all_reports, OUTPUT_REPORT_PATH)
    print(f"✅ Fertig. Report gespeichert unter: {OUTPUT_REPORT_PATH}")

if __name__ == "__main__":
    startLoader()
