import pandas as pd
import json
import os

#Define input and output file paths
ACCOUNTS_CSV_PATH = "Accounts.csv"
PERMISSIONS_CSV_PATH = "Permissions.csv"
STIX_PATH = "stix_data.json"
OUTPUT_REPORT_PATH = "modification_report.txt"



#Read CSV and detect available columns dynamically
def read_csv(file_path: str) -> pd.DataFrame:
    df = pd.read_csv(file_path, sep=None, engine='python')
    return df

#Save modified IAM data to CSV
def save_csv(df: pd.DataFrame, output_path: str):
    df.to_csv(output_path, sep=';', index=False)



#Write text report TODO enhance with more info
def write_report(report_lines: list, output_path: str):
    #Write all lines into a text file
    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.writelines(line + "\n" for line in report_lines)




#Check if a STIX object references any attribute values in the dataframe
def match_stix_to_dataframe(df: pd.DataFrame, stix_data: dict, entity_type: str):
    #list to store lines for report
    report = []
    
    #Iterate over all STIX attributes
    for key, value in stix_data.items():

        #TODO Expand matching logic,
        
        #Check if the value exists in any of the iam data columns
        matches = df.isin([value]).any(axis=1)
        if matches.any():
            #Add Temporal_Criticality column if missing
            if "Temporal_Criticality" not in df.columns:
                df["Temporal_Criticality"] = ""
            

            #TODO write more evaluation, Mark matched rows with HIGH
            df.loc[matches, "Temporal_Criticality"] = "HIGH"
            


            #Add information to report
            affected_rows = df.loc[matches]
            for _, row in affected_rows.iterrows():
                report.append(
                    f"[{entity_type.upper()}] Match found for STIX attribute '{key}' = '{value}' "
                    f"-> ID {row.get('ID', 'N/A')}, marked as HIGH."
                )


    return df, report

def applyRules():

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
