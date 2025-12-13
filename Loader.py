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

# --- WICHTIG: DIE NEUE SMART MATCHING LOGIK ---
def compare_cpe_parts(remote_cpe: dict, local_cpe: dict):
    matched_fields = []
    
    # 1. Vendor Check (Muss strikt passen, außer Wildcard)
    r_vendor = str(remote_cpe.get("vendor", "*")).strip().lower()
    l_vendor = str(local_cpe.get("vendor", "*")).strip().lower()
    
    if r_vendor != "*" and r_vendor != l_vendor:
        return (False, []) # Vendor passt nicht -> Sofort raus
    
    matched_fields.append("vendor")

    # 2. Smart Product/Version Check
    r_product = str(remote_cpe.get("product", "*")).strip().lower()
    l_product = str(local_cpe.get("product", "*")).strip().lower()
    
    r_version = str(remote_cpe.get("version", "*")).strip().lower()
    l_version = str(local_cpe.get("version", "*")).strip().lower()
    
    product_match = False

    # Szenario A: Exakter Produkt-Match
    # KI: "windows_server" == Asset: "windows_server"
    if r_product == "*" or r_product == l_product:
        product_match = True
        matched_fields.append("product_exact")
        
        # Dann prüfen wir Version strikt (sofern nicht Wildcard)
        if r_version != "*" and r_version != "-" and r_version != "":
            if r_version != l_version:
                return (False, []) # Version passt nicht
            matched_fields.append("version_exact")

    # Szenario B: "Sticky Version" (KI hat Version ins Produkt gezogen)
    # KI: "windows_server_2022" enthält Asset: "windows_server" UND Asset: "2022"
    elif l_product in r_product and l_version != "*" and l_version in r_product:
        product_match = True
        matched_fields.append("product_fuzzy_sticky")
        matched_fields.append("version_fuzzy_sticky")
        
    # Szenario C: "Overspecific Asset" (Asset hat Version im Namen, KI trennt sauber)
    # KI: "windows_server" in Asset: "windows_server_2022"
    elif r_product in l_product and r_version != "*" and r_version in l_product:
        product_match = True
        matched_fields.append("product_fuzzy_reverse")

    if not product_match:
        return (False, [])

    return (True, matched_fields)
# ---------------------------------------------

def row_matches_cpe(row, cpe_parts_remote):
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
    report = []
    affected_link_ids = set()
    
    cpe_list = stix_data.get("x_detected_cpes", [])
    # Legacy Support
    if not cpe_list and stix_data.get("cpe"): 
        cpe_list = [{"cpe23": stix_data.get("cpe")}]

    if "Temporal_Criticality" not in df.columns: df["Temporal_Criticality"] = ""

    for idx, row in df.iterrows():
        match_found = False
        for cpe_obj in cpe_list:
            remote_cpe_str = cpe_obj.get("cpe23", "")
            remote_cpe_parts = split_cpe(remote_cpe_str)
            
            matched, matched_fields = row_matches_cpe(row, remote_cpe_parts)
            
            if matched:
                match_found = True
                # Eskalation
                crit = str(row.get("Criticality", "")).upper()
                if crit == "MEDIUM": df.loc[idx, "Temporal_Criticality"] = "HIGH"
                elif crit == "HIGH": df.loc[idx, "Temporal_Criticality"] = "VERY_HIGH"
                
                # Link ID merken
                link_id = row.get(PERM_LINK_COL)
                if link_id:
                    affected_link_ids.add(link_id)

                report.append(
                    f"[PERMISSION] HIT on ID {row.get('ID')} (Link: {link_id}). "
                    f"Match Logic: {matched_fields}. Crit escalated."
                )
                break 
    
    return df, report, affected_link_ids

def process_accounts(df: pd.DataFrame, stix_data: dict, affected_link_ids: set):
    report = []
    technique_list = stix_data.get("x_detected_techniques", [])
    
    # Kritische Techniken (T1003 ist Credential Dumping)
    critical_techniques = ["T1136", "T1003", "T1059"] 
    hit_technique = any(t['id'].startswith(ct) for t in technique_list for ct in critical_techniques)
    
    if "Deactivated" not in df.columns: df["Deactivated"] = ""

    for idx, row in df.iterrows():
        acc_link_id = row.get(ACC_LINK_COL)
        
        if acc_link_id in affected_link_ids:
            # Account ist mit betroffener Permission verknüpft!
            if hit_technique:
                df.loc[idx, "Deactivated"] = "true"
                action = "Deactivated=true"
            else:
                df.loc[idx, "Deactivated"] = "review_needed"
                action = "Deactivated=review_needed"

            report.append(
                f"[ACCOUNT] HIT on ID {row.get('AccountID')} (Link: {acc_link_id}). "
                f"Inherited Vulnerability. Technique Critical? {hit_technique}. -> {action}"
            )
            
    return df, report

# ==========================================
# 4. MAIN EXECUTION
# ==========================================
def startLoader():
    print(f"🚀 Starte Linked Loader (Smart Match Edition)...")
    
    if not os.path.exists(ACCOUNTS_CSV_PATH) or not os.path.exists(PERMISSIONS_CSV_PATH) or not os.path.exists(STIX_PATH):
        print("❌ Fehler: Dateien fehlen.")
        return

    accounts_df = read_csv(ACCOUNTS_CSV_PATH)
    permissions_df = read_csv(PERMISSIONS_CSV_PATH)
    
    with open(STIX_PATH, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    print(f"📥 CTI Object geladen. Start Matching...")

    permissions_df, perm_report, affected_links = process_permissions(permissions_df, stix_data)
    print(f"🔗 Betroffene Sorting-IDs (Links): {affected_links}")

    accounts_df, acc_report = process_accounts(accounts_df, stix_data, affected_links)

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
