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



#Write text report TODO enhance with more info
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

    print("Parsed fields of CPE:")
    for name in field_names:
        print(f"  {name}: {parsed.get(name)}")

    return parsed



#Check if a STIX object references any attribute values in the dataframe
def match_stix_to_dataframe(df: pd.DataFrame, stix_data: dict, entity_type: str):
    report = []

    id = stix_data.get("id", "")
    technique = stix_data.get("technique", "")
    description = stix_data.get("description", "")
    cpe_value = stix_data.get("cpe", "")


    cpe_parts = split_cpe(cpe_value)


    stix_values = []
    if technique:
        stix_values.append(technique)

    if description:
        stix_values.append(description)

    if cpe_parts:
        stix_values.extend(cpe_parts)

    if cpe_value:
        stix_values.extend(cpe_value)

    #Add Temporal_Criticality column if missing
    if "Temporal_Criticality" not in df.columns:
        df["Temporal_Criticality"] = ""
    if "Deactivated" not in df.columns:
        df["Deactivated"] = ""


    print("Ready to match")
    # Iterate over extracted STIX values
    #TODO Expand matching logic
    matches = df.isin([cpe_value]).any(axis=1)
    if matches.any():

        # Get indices of matched rows
        matched_indices = df.index[matches]

        # For each matched row, call applyRules on the single-row Series and write it back
        for idx in matched_indices:
            # Get a copy of the row to avoid chained-assignment issues
            row = df.loc[idx].copy()

            # Call per-row rule engine; applyRules returns the modified row
            updated_row = applyRules(row, technique, description, cpe_parts, entity_type)

            # Write the updated row back into the DataFrame at the original index
            df.loc[idx] = updated_row

            # Add information to report using the updated DataFrame values
            report.append(
                f"[{entity_type.upper()}] Match found for '{cpe_value}' -> ID {df.loc[idx].get('ID', 'N/A')}, "
                f"Temporal_Criticality={df.loc[idx].get('Temporal_Criticality', '')}, "
                f"Deactivated={df.loc[idx].get('Deactivated', '')}"
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
