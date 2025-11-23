import pandas as pd
import json
import os

#Define input and output file paths
ACCOUNTS_CSV_PATH = "Accounts.csv"
PERMISSIONS_CSV_PATH = "Permissions.csv"
STIX_PATH = "stix_data.json"
OUTPUT_REPORT_PATH = "modification_report.txt"

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

    #Add Temporal_Criticality column if missing
    if "Temporal_Criticality" not in df.columns:
        df["Temporal_Criticality"] = ""
    if "Deactivated" not in df.columns:
        df["Deactivated"] = ""


    # Iterate over extracted STIX values
    for val in stix_values:
        #TODO Expand matching logic
        matches = df.isin([val]).any(axis=1)

        if matches.any():

            applyRules(df, matches, technique, description, cpe_parts)

            affected_rows = df.loc[matches]
            for _, row in affected_rows.iterrows():
                report.append(
                    f"[{entity_type.upper()}] Match found for '{val}' "
                    f"-> ID {row.get('ID', 'N/A')}, marked as HIGH."
                )

    return df, report

def applyRules(df, matches, technique, description, cpe_parts):

    # Permission rules
    if entity_type == "permission":
        # Mark matched rows with HIGH
        df.loc[matches, "Temporal_Criticality"] = "HIGH"

    # Account rules
    if entity_type == "account":
        # Mark account as deactivated
        df.loc[matches, "Deactivated"] = "true"

    # TODO: add more rule logic here



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
    for obj in stix_data.get("objects", []):
        obj_type = obj.get("type", "unknown")
        print(f"Processing STIX object of type: {obj_type}")
        
        #Try to match object attributes against both CSVs
        permissions_df, perm_report = match_stix_to_dataframe(permissions_df, obj, "permission")
        accounts_df, acc_report = match_stix_to_dataframe(accounts_df, obj, "account")
        
        #Collect reports
        all_reports.extend(perm_report)
        all_reports.extend(acc_report)

    #Step 5: Save CSV files  
    #save_csv(accounts_df, "accounts.csv")
    #save_csv(permissions_df, "permissions.csv")
    #Aktuell Test mit modifizierten files
    save_csv(accounts_df, "accounts_modified.csv")
    save_csv(permissions_df, "permissions_modified.csv")



    #Step 6: Write final report  
    if not all_reports:
        all_reports.append("No rules were activated.")
    else:
        all_reports.insert(0, "STIX-based CSV modification report")
        #all_reports.insert(1, "=" * 60)
    write_report(all_reports, OUTPUT_REPORT_PATH)

    print("Processing complete. Modified files and generated report.")


startLoader()
