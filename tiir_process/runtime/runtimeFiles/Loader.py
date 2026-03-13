import json
import os
import pandas as pd

if "tiir_logger" not in globals():
    with open("tiir_process_log_utils.py", "r", encoding="utf-8") as _f:
        exec(_f.read(), globals())

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
        parsed[name] = parts[i] if i < len(parts) else "*"
    return parsed


def compare_cpe_parts(remote_cpe: dict, local_cpe: dict):
    matched_fields = []

    r_vendor = str(remote_cpe.get("vendor", "*")).strip().lower()
    l_vendor = str(local_cpe.get("vendor", "*")).strip().lower()
    if r_vendor != "*" and r_vendor != l_vendor:
        return False, []
    matched_fields.append("vendor")

    r_product = str(remote_cpe.get("product", "*")).strip().lower()
    l_product = str(local_cpe.get("product", "*")).strip().lower()
    r_version = str(remote_cpe.get("version", "*")).strip().lower()
    l_version = str(local_cpe.get("version", "*")).strip().lower()

    product_match = False
    if r_product == "*" or r_product == l_product:
        product_match = True
        matched_fields.append("product_exact")
        if r_version not in ["*", "-", ""]:
            if r_version != l_version:
                return False, []
            matched_fields.append("version_exact")
    elif l_product in r_product and l_version != "*" and l_version in r_product:
        product_match = True
        matched_fields.extend(["product_fuzzy_sticky", "version_fuzzy_sticky"])
    elif r_product in l_product and r_version != "*" and r_version in l_product:
        product_match = True
        matched_fields.append("product_fuzzy_reverse")

    return (product_match, matched_fields) if product_match else (False, [])


def row_matches_cpe(row, cpe_parts_remote):
    if CPE_COLUMN_NAME in row and isinstance(row[CPE_COLUMN_NAME], str):
        local_cpe_str = row[CPE_COLUMN_NAME]
        if local_cpe_str.startswith("cpe:"):
            local_cpe_dict = split_cpe(local_cpe_str)
            return compare_cpe_parts(cpe_parts_remote, local_cpe_dict)
    return False, []


def process_permissions(df: pd.DataFrame, stix_data: dict):
    report = []
    affected_link_ids = set()
    permission_hits = []

    cpe_list = stix_data.get("x_detected_cpes", [])
    if not cpe_list and stix_data.get("cpe"):
        cpe_list = [{"cpe23": stix_data.get("cpe")}]

    if "Temporal_Criticality" not in df.columns:
        df["Temporal_Criticality"] = ""

    for idx, row in df.iterrows():
        for cpe_obj in cpe_list:
            remote_cpe_str = cpe_obj.get("cpe23", "")
            if remote_cpe_str == "NOT_FOUND":
                continue
            remote_cpe_parts = split_cpe(remote_cpe_str)
            matched, matched_fields = row_matches_cpe(row, remote_cpe_parts)
            if matched:
                old_crit = str(row.get("Criticality", "")).upper()
                new_crit = ""
                if old_crit == "MEDIUM":
                    df.loc[idx, "Temporal_Criticality"] = "HIGH"
                    new_crit = "HIGH"
                elif old_crit == "HIGH":
                    df.loc[idx, "Temporal_Criticality"] = "VERY_HIGH"
                    new_crit = "VERY_HIGH"
                else:
                    new_crit = str(df.loc[idx, "Temporal_Criticality"])

                link_id = row.get(PERM_LINK_COL)
                if link_id:
                    affected_link_ids.add(link_id)

                hit = {
                    "PermissionID": row.get("ID"),
                    "LinkID": link_id,
                    "Entitlement": row.get("Entitlement"),
                    "Matched_CPE": row.get(CPE_COLUMN_NAME),
                    "Criticality_before": old_crit,
                    "Criticality_after": new_crit,
                    "MatchLogic": ", ".join(matched_fields),
                }
                permission_hits.append(hit)
                report.append(
                    f"[PERMISSION] HIT on ID {row.get('ID')} (Link: {link_id}). Match Logic: {matched_fields}. Crit escalated."
                )
                break

    permission_hits = sorted(permission_hits, key=lambda x: (str(x["LinkID"]), int(x["PermissionID"])))
    return df, report, sorted(affected_link_ids), permission_hits


def process_accounts(df: pd.DataFrame, affected_link_ids: list):
    report = []
    account_hits = []
    if "Deactivated" not in df.columns:
        df["Deactivated"] = ""

    for idx, row in df.iterrows():
        acc_link_id = row.get(ACC_LINK_COL)
        if acc_link_id in affected_link_ids:
            df.loc[idx, "Deactivated"] = "review_needed"
            hit = {
                "AccountID": row.get("AccountID"),
                "LinkID": acc_link_id,
                "givenName": row.get("givenName"),
                "lastName": row.get("lastName"),
                "Team": row.get("Team"),
                "Function": row.get("Function"),
                "Action": "review_needed",
            }
            account_hits.append(hit)
            report.append(
                f"[ACCOUNT] HIT on ID {row.get('AccountID')} (Link: {acc_link_id}). Inherited vulnerability. -> Deactivated=review_needed"
            )

    account_hits = sorted(account_hits, key=lambda x: (str(x["LinkID"]), int(x["AccountID"])))
    return df, report, account_hits


def startLoader(return_results=True, quiet=False):
    if not quiet:
        print("Starting Loader (CPE-only Smart Match)...")

    for path in [ACCOUNTS_CSV_PATH, PERMISSIONS_CSV_PATH, STIX_PATH]:
        if not os.path.exists(path):
            tiir_logger.log("loader", "missing_input", {"path": path}, status="ERROR")
            raise FileNotFoundError(path)

    accounts_df = read_csv(ACCOUNTS_CSV_PATH)
    permissions_df = read_csv(PERMISSIONS_CSV_PATH)
    with open(STIX_PATH, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    permissions_df, perm_report, affected_links, permission_hits = process_permissions(permissions_df, stix_data)
    accounts_df, acc_report, account_hits = process_accounts(accounts_df, affected_links)

    save_csv(accounts_df, ACCOUNTS_MODIFIED_PATH)
    save_csv(permissions_df, PERMISSIONS_MODIFIED_PATH)

    all_reports = [f"Threat Description: {stix_data.get('description', '')[:80]}..."]
    all_reports.extend(perm_report)
    all_reports.extend(acc_report)
    if len(all_reports) == 1:
        all_reports.append("No matches found.")
    write_report(all_reports, OUTPUT_REPORT_PATH)

    result = {
        "affected_links": affected_links,
        "permission_hits": permission_hits,
        "account_hits": account_hits,
        "counts": {
            "permission_hits": len(permission_hits),
            "account_hits": len(account_hits),
        },
        "files": {
            "report": OUTPUT_REPORT_PATH,
            "accounts_modified": ACCOUNTS_MODIFIED_PATH,
            "permissions_modified": PERMISSIONS_MODIFIED_PATH,
            "tiir_process_log": TIIR_PROCESS_LOG_PATH,
            "stix_object": STIX_PATH,
        },
    }
    tiir_logger.log("loader", "mapping_completed", result)

    if not quiet:
        print(f"Permission hits: {result['counts']['permission_hits']}")
        print(f"Linked identities: {result['counts']['account_hits']}")

    return result if return_results else None
