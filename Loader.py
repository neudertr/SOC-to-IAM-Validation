import pandas as pd
import json
import os

# ==========================================
# 1. KONFIGURATION & PFADE
# ==========================================
WORKING_DIR = os.getcwd()

ACCOUNTS_CSV_PATH = os.path.join(WORKING_DIR, "Accounts.CSV")
PERMISSIONS_CSV_PATH = os.path.join(WORKING_DIR, "Permissions.CSV")
STIX_PATH = os.path.join(WORKING_DIR, "Test_STIX.json")

OUTPUT_REPORT_PATH = os.path.join(WORKING_DIR, "modification_report.txt")
ACCOUNTS_MODIFIED_PATH = os.path.join(WORKING_DIR, "accounts_modified.csv")
PERMISSIONS_MODIFIED_PATH = os.path.join(WORKING_DIR, "permissions_modified.csv")

CPE_COLUMN_NAME = "Software_System"

# Link-Spalten (Join Keys)
PERM_LINK_COL = "Sorting"
ACC_LINK_COL = "SortingAttribute"

field_names = [
    "cpe_prefix", "cpe_version", "part", "vendor", "product", "version", 
    "update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"
]

# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def read_csv(file_path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(file_path, sep=';', engine='python')
    except:
        return pd.read_csv(file_path, sep=',', engine='python')

def save_csv(df: pd.DataFrame, output_path: str):
    df.to_csv(output_path, sep=';', index=False)

def write_report(report_lines: list, output_path: str):
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.writelines(line + "\n" for line in report_lines)

def split_cpe(cpe_string: str):
    if not isinstance(cpe_string, str) or not cpe_string.startswith("cpe:2.3"):
        return {}
    parts = cpe_string.split(":")
    parsed = {}
    for i, name in enumerate(field_names):
        if i < len(parts):
            parsed[name] = parts[i]
        else:
            parsed[name] = "*"
    return parsed

def compare_cpe_parts(remote_cpe: dict, local_cpe: dict):
    matched_fields = []
    check_fields = ["vendor", "product", "version", "update", "target_sw"]
    
    for field in check_fields:
        r_val = str(remote_cpe.get(field, "*")).strip().lower()
        l_val = str(local_cpe.get(field, "*")).strip().lower()
        
        if r_val == "*" or r_val == "": continue
        
        if r_val == l_val:
            matched_fields.append(field)
        else:
            return (False, []) # Mismatch

    if "vendor" in matched_fields and "product" in matched_fields:
        return (True, matched_fields)
    return (False, [])

def row_matches_cpe(row, cpe_parts_remote):
    """ Prüft nur die CPE Spalte einer Zeile """
    if CPE_COLUMN_NAME in row and isinstance(row[CPE_COLUMN_NAME], str):
        local_cpe_str = row[CPE_COLUMN_NAME]
        if local_cpe_str.startswith("cpe:"):
            local_cpe_dict = split_cpe(local_cpe_str)
            return compare_cpe_parts(cpe_parts_remote, local_cpe_dict)
    return False, []

# ==========================================
# 3. CORE LOGIC (LINKED)
# ==========================================

def process_permissions(df: pd.DataFrame, stix_data: dict):
    """
    1. Prüft Permissions auf CPE Matches.
    2. Setzt Criticality hoch.
    3. GIBT EINE LISTE DER BETROFFENEN 'SORTING' IDs ZURÜCK!
    """
    report = []
    affected_link_ids = set() # Hier speichern wir 'A', 'B', 'C' etc.
    
    cpe_list = stix_data.get("x_detected_cpes", [])
    if not cpe_list and stix_data.get("cpe"): cpe_list = [{"cpe23": stix_data.get("cpe")}]

    if "Temporal_Criticality" not in df.columns: df["Temporal_Criticality"] = ""

    for idx, row in df.iterrows():
        for cpe_obj in cpe_list:
            remote_cpe_str = cpe_obj.get("cpe23", "")
            remote_cpe_parts = split_cpe(remote_cpe_str)
            
            matched, matched_fields = row_matches_cpe(row, remote_cpe_parts)
            
            if matched:
                # 1. Permission markieren (Eskalation)
                crit = str(row.get("Criticality", "")).upper()
                if crit == "MEDIUM": df.loc[idx, "Temporal_Criticality"] = "HIGH"
                elif crit == "HIGH": df.loc[idx, "Temporal_Criticality"] = "VERY_HIGH"
                
                # 2. Link-ID merken (für Accounts)
                link_id = row.get(PERM_LINK_COL)
                if link_id:
                    affected_link_ids.add(link_id)

                report.append(
                    f"[PERMISSION] HIT on ID {row.get('ID')} (Link: {link_id}). "
                    f"CPE Match '{remote_cpe_str}'. Crit escalated."
                )
                break 
    
    return df, report, affected_link_ids


def process_accounts(df: pd.DataFrame, stix_data: dict, affected_link_ids: set):
    """
    Prüft Accounts NICHT auf CPEs, sondern ob ihre 'SortingAttribute' ID
    in der Liste der betroffenen Permissions ist.
    """
    report = []
    technique_list = stix_data.get("x_detected_techniques", [])
    
    # Kritische Techniken, die eine Sperrung auslösen
    critical_techniques = ["T1136", "T1003", "T1059"] 
    hit_technique = any(t['id'].startswith(ct) for t in technique_list for ct in critical_techniques)
    
    if "Deactivated" not in df.columns: df["Deactivated"] = ""

    for idx, row in df.iterrows():
        # Link prüfen: Hat dieser Account eine betroffene Permission?
        acc_link_id = row.get(ACC_LINK_COL)
        
        if acc_link_id in affected_link_ids:
            # JA! Der Account nutzt die verwundbare Software (via Permission Link).
            
            if hit_technique:
                df.loc[idx, "Deactivated"] = "true"
                action = "Deactivated=true"
            else:
                df.loc[idx, "Deactivated"] = "review_needed"
                action = "Deactivated=review_needed"

            report.append(
                f"[ACCOUNT] HIT on ID {row.get('AccountID')} (Link: {acc_link_id}). "
                f"Linked Permission matches Threat CPE. Critical Technique detected? {hit_technique}. -> {action}"
            )
            
    return df, report

# ==========================================
# 4. MAIN EXECUTION
# ==========================================
def startLoader():
    print(f"🚀 Starte Linked Loader im Verzeichnis: {WORKING_DIR}")
    
    if not os.path.exists(ACCOUNTS_CSV_PATH) or not os.path.exists(PERMISSIONS_CSV_PATH) or not os.path.exists(STIX_PATH):
        print("❌ Fehler: Dateien fehlen.")
        return

    accounts_df = read_csv(ACCOUNTS_CSV_PATH)
    permissions_df = read_csv(PERMISSIONS_CSV_PATH)
    
    with open(STIX_PATH, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    print(f"📥 CTI Object geladen. Start Matching...")

    # SCHRITT 1: Permissions verarbeiten & betroffene Links sammeln
    permissions_df, perm_report, affected_links = process_permissions(permissions_df, stix_data)
    print(f"🔗 Betroffene Verknüpfungen (Sorting IDs): {affected_links}")

    # SCHRITT 2: Accounts basierend auf Links verarbeiten
    accounts_df, acc_report = process_accounts(accounts_df, stix_data, affected_links)

    # Save & Report
    save_csv(accounts_df, ACCOUNTS_MODIFIED_PATH)
    save_csv(permissions_df, PERMISSIONS_MODIFIED_PATH)

    all_reports = [f"Threat Description: {stix_data.get('description', '')[:50]}..."]
    all_reports.extend(perm_report)
    all_reports.extend(acc_report)
    
    if len(all_reports) == 1: all_reports.append("No matches found.")
        
    write_report(all_reports, OUTPUT_REPORT_PATH)
    print(f"✅ Fertig. Report gespeichert: {OUTPUT_REPORT_PATH}")

if __name__ == "__main__":
    startLoader()
