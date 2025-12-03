import pandas as pd
import json
import os

#Define input and output file paths
ACCOUNTS_CSV_PATH = "C:/Users/rNeudert/CTI_Implement/Git/Accounts.CSV"
PERMISSIONS_CSV_PATH = "C:/Users/rNeudert/CTI_Implement/Git/Permissions.csv"
STIX_PATH = "C:/Users/rNeudert/CTI_Implement/Git/Test_STIX.json"
OUTPUT_REPORT_PATH = "C:/Users/rNeudert/CTI_Implement/Git/modification_report.txt"

ACCOUNTS_MODIFIED_PATH = "C:/Users/rNeudert/CTI_Implement/Git/accounts_modified.csv"
PERMISSIONS_MODIFIED_PATH = "C:/Users/rNeudert/CTI_Implement/Git/permissions_modified.csv"

CPE_COLUMN_NAME = "Software_System"

field_names = [
    "cpe_prefix",
    "cpe_version",
    "part",
    "vendor",
    "product",
    "version",
    "update",
    "edition",
    "language",
    "sw_edition",
    "target_sw",
    "target_hw",
    "other",
]




def read_csv(file_path: str) -> pd.DataFrame:
    df = pd.read_csv(file_path, sep=None, engine='python')
    return df


def save_csv(df: pd.DataFrame, output_path: str):
    df.to_csv(output_path, sep=';', index=False)



#Write text report
def write_report(report_lines: list, output_path: str):
    #Write all lines into a text file
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.writelines(line + "\n" for line in report_lines)

def split_cpe(cpe_string: str):
    """
    cpe:<cpe_version>:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
    """
    parts = cpe_string.split(":")

    parsed = {}
    for i, name in enumerate(field_names):
        parsed[name] = parts[i] if i < len(parts) else None

    for name in field_names:
        print(f"  {name}: {parsed.get(name)}")

    return parsed

# Compare two parsed CPE dictionaries field-by-field (explicit checks, no loop).
# Returns a tuple: (bool_match_found, list_of_matched_field_names)
def compare_cpe_parts(remote_cpe: dict, local_cpe: dict):
    matched_fields = []

    # Compare vendor fields
    # If both sides have a vendor and they match (case-insensitive), record match
    if remote_cpe.get("vendor") and local_cpe.get("vendor"):
        if str(remote_cpe.get("vendor")).strip().lower() == str(local_cpe.get("vendor")).strip().lower():
            matched_fields.append("vendor")

    # Compare product fields
    # If both sides have a product and they match (case-insensitive), record match
    if remote_cpe.get("product") and local_cpe.get("product"):
        if str(remote_cpe.get("product")).strip().lower() == str(local_cpe.get("product")).strip().lower():
            matched_fields.append("product")

    # Compare version fields
    if remote_cpe.get("version") and local_cpe.get("version"):
        if str(remote_cpe.get("version")).strip().lower() == str(local_cpe.get("version")).strip().lower():
            matched_fields.append("version")

    # Compare update fields
    if remote_cpe.get("update") and local_cpe.get("update"):
        if str(remote_cpe.get("update")).strip().lower() == str(local_cpe.get("update")).strip().lower():
            matched_fields.append("update")

    # Compare edition fields
    if remote_cpe.get("edition") and local_cpe.get("edition"):
        if str(remote_cpe.get("edition")).strip().lower() == str(local_cpe.get("edition")).strip().lower():
            matched_fields.append("edition")

    # Compare language fields
    if remote_cpe.get("language") and local_cpe.get("language"):
        if str(remote_cpe.get("language")).strip().lower() == str(local_cpe.get("language")).strip().lower():
            matched_fields.append("language")

    # Compare sw_edition fields
    if remote_cpe.get("sw_edition") and local_cpe.get("sw_edition"):
        if str(remote_cpe.get("sw_edition")).strip().lower() == str(local_cpe.get("sw_edition")).strip().lower():
            matched_fields.append("sw_edition")

    # Compare target_sw fields
    if remote_cpe.get("target_sw") and local_cpe.get("target_sw"):
        if str(remote_cpe.get("target_sw")).strip().lower() == str(local_cpe.get("target_sw")).strip().lower():
            matched_fields.append("target_sw")

    # Compare target_hw fields
    if remote_cpe.get("target_hw") and local_cpe.get("target_hw"):
        if str(remote_cpe.get("target_hw")).strip().lower() == str(local_cpe.get("target_hw")).strip().lower():
            matched_fields.append("target_hw")

    # Compare other fields
    if remote_cpe.get("other") and local_cpe.get("other"):
        if str(remote_cpe.get("other")).strip().lower() == str(local_cpe.get("other")).strip().lower():
            matched_fields.append("other")

    # Return boolean (any match) and the list of matched field names
    return (len(matched_fields) > 0, matched_fields)



# Check whether a DataFrame row matches the provided value or CPE components.
# Uses explicit field-by-field CPE comparison via compare_cpe_parts().
def row_matches(row, value, cpe_parts):
    # 1) Basic column-by-column equality checks (unchanged)
    for col in row.index:
        cell = row[col]
        if cell == value:
            return True, []  # match found, no CPE fields to report
        if isinstance(cell, (str, int, float)) and str(cell).strip().lower() == str(value).strip().lower():
            return True, []

    # 2) If remote CPE dict provided and row has CPE_original, parse and compare field-by-field
    if CPE_COLUMN_NAME in row and isinstance(row[CPE_COLUMN_NAME], str):
        # Parse the row-level CPE into a dict using the provided split_cpe function
        local_cpe_dict = split_cpe(row[CPE_COLUMN_NAME])

        # Perform explicit field-by-field comparisons (vendor vs vendor, product vs product, ...)
        matched, matched_fields = compare_cpe_parts(cpe_parts, local_cpe_dict)

        # If any field matched, return True and the matched fields
        if matched:
            return True, matched_fields

    # No match found
    return False, []



#Check if a STIX object references any attribute values in the dataframe
def match_stix_to_dataframe(df: pd.DataFrame, stix_data: dict, entity_type: str):
    report = []

    id = stix_data.get("id", "")
    technique = stix_data.get("technique", "")
    description = stix_data.get("description", "")
    cpe_value = stix_data.get("cpe", "")


    #This is a map accessed by get(field_name)
    cpe_parts = split_cpe(cpe_value)

    #Add Temporal_Criticality column if missing
    if "Temporal_Criticality" not in df.columns:
        df["Temporal_Criticality"] = ""
    if "Deactivated" not in df.columns:
        df["Deactivated"] = ""


    # Iterate through each row
    for idx, row in df.iterrows():
        matched, matched_fields = row_matches(row, cpe_value, cpe_parts)
        if matched:
            # Apply per-row rules
            updated_row = applyRules(row, technique, description, cpe_parts, entity_type)

            # Write modifications back to DataFrame
            df.loc[idx] = updated_row

            # Add to report and include which CPE fields matched (if any)
            if matched_fields:
                report.append(
                    f"[{entity_type.upper()}] CPE field match for '{cpe_value}' -> ID {updated_row.get('ID', 'N/A')}, "
                    f"matched_fields={matched_fields}, Temporal_Criticality={updated_row.get('Temporal_Criticality','')}, "
                    f"Deactivated={updated_row.get('Deactivated','')}"
                )
            else:
                report.append(
                    f"[{entity_type.upper()}] Value match for '{cpe_value}' -> ID {updated_row.get('ID', 'N/A')}, "
                    f"Temporal_Criticality={updated_row.get('Temporal_Criticality','')}, Deactivated={updated_row.get('Deactivated','')}"
                )

    return df, report


# Apply rules to a single DataFrame row (pandas.Series) and return the modified row.
def applyRules(row, technique, description, cpe_parts, entity_type):
    # Ensure columns exist on the row object (these will be added to the DataFrame when assigned back).
    if "Temporal_Criticality" not in row.index:
        # Add Temporal_Criticality placeholder
        row["Temporal_Criticality"] = ""
    if "Deactivated" not in row.index:
        # Add Deactivated placeholder
        row["Deactivated"] = ""

    # Permission rules: use Criticality column value to decide new Temporal_Criticality
    if entity_type == "permission":
        # Read existing criticality value (empty string if missing)
        criticality = row.get("Criticality", "")

        # If criticality is MEDIUM, escalate to HIGH
        if isinstance(criticality, str) and criticality.upper() == "MEDIUM":
            row["Temporal_Criticality"] = "HIGH"

        # If criticality is HIGH, escalate to VERY_HIGH
        elif isinstance(criticality, str) and criticality.upper() == "HIGH":
            row["Temporal_Criticality"] = "VERY_HIGH"

        # TODO: add more fine-grained permission rules (e.g., consider technique/description/cpe_parts)

    # Account rules: mark account as deactivated
    if entity_type == "account":
        # Mark the account as deactivated
        row["Deactivated"] = "true"

        # TODO: use technique/description/cpe_parts to refine decision (e.g., only deactivate if cpe matches)

    # Optionally store triggering context for auditing (uncomment if desired)
    # row["Triggered_Technique"] = technique
    # row["Triggered_Description"] = description
    # row["Triggered_CPE"] = ",".join(cpe_parts) if cpe_parts else ""

    # Return the modified row so caller can write it back into the DataFrame
    return row



def startLoader():
    #Step 1: Read CSV files  
    accounts_df = read_csv(ACCOUNTS_CSV_PATH)
    permissions_df = read_csv(PERMISSIONS_CSV_PATH)

    #Step 2: Determine attributes and Print columns for debugging
    print("Accounts attributes:", list(accounts_df.columns))
    print("Permissions attributes:", list(permissions_df.columns))

    #Step 3: Load STIX JSON file  
    with open( STIX_PATH, "r", encoding="utf-8") as f:
        stix_data = json.load(f)

    #Step 4: Extract relevant data from transformed STIX object


    #TODO Expand logic 
    all_reports = []
    #Try to match object attributes against both CSVs
    permissions_df, perm_report = match_stix_to_dataframe(permissions_df, stix_data, "permission")
    accounts_df, acc_report = match_stix_to_dataframe(accounts_df, stix_data, "account")
    
    #Collect reports
    all_reports.extend(perm_report)
    all_reports.extend(acc_report)
        


    #Step 5: Save CSV files  
    #save_csv(accounts_df, "accounts.csv")
    #save_csv(permissions_df, "permissions.csv")
    #Aktuell Test mit modifizierten files
    save_csv(accounts_df, ACCOUNTS_MODIFIED_PATH)
    save_csv(permissions_df, PERMISSIONS_MODIFIED_PATH)



    #Step 6: Write final report  
    if not all_reports:
        all_reports.append("No rules were activated.")
    else:
        all_reports.insert(0, "STIX-based CSV modification report")
        #all_reports.insert(1, "=" * 60)
    write_report(all_reports, OUTPUT_REPORT_PATH)

    print("Processing complete. Modified files and generated report.")


startLoader()
