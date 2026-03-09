# Loader.py
# ============================================================
# Asset Mitigation Loader (CPE-only Edition)
# ============================================================
# Änderungen gegenüber v1:
#   - Technique-basierte Account-Deaktivierung entfernt.
#     Accounts, die über Sorting-Link mit betroffenen Permissions
#     verbunden sind, bekommen jetzt immer "Deactivated=review_needed".
#     Begründung: Ohne Technique-Erkennung fehlt die Grundlage für
#     die automatische Eskalation zu "Deactivated=true".
#   - Audit-Reporting verbessert: Match-Logik wird detailliert geloggt
#   - Keine funktionale Änderung am CPE-Matching selbst
# ============================================================

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
    "update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other",
]


# ==========================================
# 2. HELPER FUNCTIONS
# ==========================================
def read_csv(file_path: str) -> pd.DataFrame:
    try:
        return pd.read_csv(file_path, sep=";", engine="python")
    except Exception:
        return pd.read_csv(file_path, sep=",", engine="python")


def save_csv(df: pd.DataFrame, output_path: str):
    df.to_csv(output_path, sep=";", index=False)


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
    """Smart CPE Matching mit drei Szenarien (unverändert aus v1)."""
    matched_fields = []

    # 1. Vendor Check (Muss passen, außer Wildcard)
    r_vendor = str(remote_cpe.get("vendor", "*")).strip().lower()
    l_vendor = str(local_cpe.get("vendor", "*")).strip().lower()

    if r_vendor != "*" and r_vendor != l_vendor:
        return (False, [])

    matched_fields.append("vendor")

    # 2. Smart Product/Version Check
    r_product = str(remote_cpe.get("product", "*")).strip().lower()
    l_product = str(local_cpe.get("product", "*")).strip().lower()
    r_version = str(remote_cpe.get("version", "*")).strip().lower()
    l_version = str(local_cpe.get("version", "*")).strip().lower()

    product_match = False

    # Szenario A: Exakter Produkt-Match
    if r_product == "*" or r_product == l_product:
        product_match = True
        matched_fields.append("product_exact")
        if r_version != "*" and r_version != "-" and r_version != "":
            if r_version != l_version:
                return (False, [])
            matched_fields.append("version_exact")

    # Szenario B: "Sticky Version" (LLM hat Version ins Produkt gezogen)
    elif l_product in r_product and l_version != "*" and l_version in r_product:
        product_match = True
        matched_fields.append("product_fuzzy_sticky")
        matched_fields.append("version_fuzzy_sticky")

    # Szenario C: "Overspecific Asset" (Asset hat Version im Namen)
    elif r_product in l_product and r_version != "*" and r_version in l_product:
        product_match = True
        matched_fields.append("product_fuzzy_reverse")

    if not product_match:
        return (False, [])

    return (True, matched_fields)


def row_matches_cpe(row, cpe_parts_remote):
    if CPE_COLUMN_NAME in row and isinstance(row[CPE_COLUMN_NAME], str):
        local_cpe_str = row[CPE_COLUMN_NAME]
        if local_cpe_str.startswith("cpe:"):
            local_cpe_dict = split_cpe(local_cpe_str)
            return compare_cpe_parts(cpe_parts_remote, local_cpe_dict)
    return False, []


# ==========================================
# 3. CORE LOGIC
# ==========================================
def process_permissions(df: pd.DataFrame, stix_data: dict):
    report = []
    affected_link_ids = set()

    cpe_list = stix_data.get("x_detected_cpes", [])
    # Legacy Support
    if not cpe_list and stix_data.get("cpe"):
        cpe_list = [{"cpe23": stix_data.get("cpe")}]

    if "Temporal_Criticality" not in df.columns:
        df["Temporal_Criticality"] = ""

    for idx, row in df.iterrows():
        for cpe_obj in cpe_list:
            remote_cpe_str = cpe_obj.get("cpe23", "")
            if remote_cpe_str == "NOT_FOUND":
                continue  # Rejected CPEs überspringen
            remote_cpe_parts = split_cpe(remote_cpe_str)

            matched, matched_fields = row_matches_cpe(row, remote_cpe_parts)

            if matched:
                crit = str(row.get("Criticality", "")).upper()
                if crit == "MEDIUM":
                    df.loc[idx, "Temporal_Criticality"] = "HIGH"
                elif crit == "HIGH":
                    df.loc[idx, "Temporal_Criticality"] = "VERY_HIGH"

                link_id = row.get(PERM_LINK_COL)
                if link_id:
                    affected_link_ids.add(link_id)

                report.append(
                    f"[PERMISSION] HIT on ID {row.get('ID')} (Link: {link_id}). "
                    f"Match Logic: {matched_fields}. Crit escalated."
                )
                break

    return df, report, affected_link_ids


def process_accounts(df: pd.DataFrame, affected_link_ids: set):
    """Markiert Accounts, deren SortingAttribute in den betroffenen Links liegt.
    
    Ohne Technique-Erkennung wird einheitlich 'review_needed' gesetzt.
    """
    report = []

    if "Deactivated" not in df.columns:
        df["Deactivated"] = ""

    for idx, row in df.iterrows():
        acc_link_id = row.get(ACC_LINK_COL)

        if acc_link_id in affected_link_ids:
            df.loc[idx, "Deactivated"] = "review_needed"

            report.append(
                f"[ACCOUNT] HIT on ID {row.get('AccountID')} (Link: {acc_link_id}). "
                f"Inherited vulnerability. -> Deactivated=review_needed"
            )

    return df, report


# ==========================================
# 4. MAIN EXECUTION
# ==========================================
def startLoader():
    print("🚀 Starting Loader (CPE-only Smart Match)...")

    if not os.path.exists(ACCOUNTS_CSV_PATH):
        print(f"❌ Missing: {ACCOUNTS_CSV_PATH}")
        return
    if not os.path.exists(PERMISSIONS_CSV_PATH):
        print(f"❌ Missing: {PERMISSIONS_CSV_PATH}")
        return
    if not os.path.exists(STIX_PATH):
        print(f"❌ Missing: {STIX_PATH}")
        return

    accounts_df = read_csv(ACCOUNTS_CSV_PATH)
    permissions_df = read_csv(PERMISSIONS_CSV_PATH)

    with open(STIX_PATH, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    print(f"📥 CTI Object loaded. Starting match...")

    permissions_df, perm_report, affected_links = process_permissions(permissions_df, stix_data)
    print(f"🔗 Affected Sorting-IDs (Links): {affected_links}")

    accounts_df, acc_report = process_accounts(accounts_df, affected_links)

    save_csv(accounts_df, ACCOUNTS_MODIFIED_PATH)
    save_csv(permissions_df, PERMISSIONS_MODIFIED_PATH)

    all_reports = [f"Threat Description: {stix_data.get('description', '')[:80]}..."]
    all_reports.extend(perm_report)
    all_reports.extend(acc_report)

    if len(all_reports) == 1:
        all_reports.append("No matches found.")

    write_report(all_reports, OUTPUT_REPORT_PATH)
    print(f"✅ Done. Report saved: {OUTPUT_REPORT_PATH}")


if __name__ == "__main__":
    startLoader()
