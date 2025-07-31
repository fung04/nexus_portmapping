import pandas as pd
import os

def process_and_merge_data(
    switch_data_excel='combined_port_mappings.xlsx',
    server_ip_csv='server_ip_app.csv',
    output_excel='combined_port_mappings_with_serverip.xlsx'):
    """
    Reads switch port data from an Excel file (with multiple sheets),
    merges it with server IP data from a CSV, and saves the result
    to a new Excel file.
    """
    # --- 1. Read and Prepare Server IP Data ---
    try:
        server_ip_map_df = pd.read_csv(server_ip_csv)
    except FileNotFoundError:
        print(f"Error: The server IP file '{server_ip_csv}' was not found.")
        return

    # Clean the server data: drop rows with no IP, split multi-IPs, and clean whitespace
    server_ip_map_df = server_ip_map_df.dropna(subset=['Clean IP address'])
    server_ip_map_df['Clean IP address'] = server_ip_map_df['Clean IP address'].str.split(',')
    server_ip_map_df = server_ip_map_df.explode('Clean IP address')
    server_ip_map_df['Clean IP address'] = server_ip_map_df['Clean IP address'].str.strip()
    print("Successfully processed server IP data.")

    # --- 2. Read Switch Data from all sheets of the Excel file ---
    try:
        # sheet_name=None reads all sheets into a dictionary of DataFrames
        all_sheets_df = pd.read_excel(switch_data_excel, sheet_name=None, keep_default_na=False)
        print(f"Found {len(all_sheets_df)} sheets in '{switch_data_excel}'.")
    except FileNotFoundError:
        print(f"Error: The switch data file '{switch_data_excel}' was not found.")
        return

    # --- 3. Process each sheet and save to a new Excel file ---
    with pd.ExcelWriter(output_excel, engine='openpyxl') as writer:
        print(f"\nProcessing each sheet and writing to '{output_excel}'...")
        for sheet_name, switch_port_map_df in all_sheets_df.items():
            print(f"  - Merging data for sheet: '{sheet_name}'")
            
            # Ensure the key column exists and clean it
            if 'IP Address on Existing Switch Port' not in switch_port_map_df.columns:
                print(f"    - SKIPPING: Column 'IP Address on Existing Switch Port' not found in sheet '{sheet_name}'.")
                continue
            
            switch_port_map_df['IP Address on Existing Switch Port'] = switch_port_map_df['IP Address on Existing Switch Port'].astype(str).str.strip()

            # Perform the left merge
            merged_df = pd.merge(
                switch_port_map_df,
                server_ip_map_df,
                left_on='IP Address on Existing Switch Port',
                right_on='Clean IP address',
                how='left'
            )
            merged_df = merged_df.drop(columns=['Clean IP address'])

            # Reorder columns to place merged data next to the IP
            new_cols = [col for col in server_ip_map_df.columns if col != 'Clean IP address']
            original_cols = [col for col in merged_df.columns if col not in new_cols]
            
            try:
                insert_pos = original_cols.index('IP Address on Existing Switch Port') + 1
                final_column_order = original_cols[:insert_pos] + new_cols + original_cols[insert_pos:]
                merged_df = merged_df[final_column_order]
            except ValueError:
                # If the key column isn't found after merge (unlikely), just use the default order
                pass

            # Write the final DataFrame to the new Excel file
            merged_df.to_excel(writer, sheet_name=sheet_name, index=False)
        
    print("\nAll done! The final merged Excel file has been saved.")


def combine_csv_to_excel(output_filename='combined_port_mappings.xlsx'):
    """
    Reads all CSV files in the current directory ending with '_port_mapping.csv',
    and combines them into a single Excel file with multiple sheets.
    """
    current_directory = os.getcwd()
    csv_files = [f for f in os.listdir(current_directory) if f.endswith('_port_mapping.csv')]
        
    if not csv_files:
        print("No '*_port_mapping.csv' files found in the current directory.")
        return False

    print(f"Found {len(csv_files)} CSV files to combine.")

    with pd.ExcelWriter(output_filename, engine='openpyxl') as writer:
        for csv_file in csv_files:
            try:
                file_path = os.path.join(current_directory, csv_file)
                sheet_name = csv_file.replace('_port_mapping.csv', '')
                df = pd.read_csv(file_path, keep_default_na=False)
                df.to_excel(writer, sheet_name=sheet_name, index=False)
                print(f"  - Added '{csv_file}' to sheet '{sheet_name}'.")
            except Exception as e:
                print(f"Could not process file {csv_file}. Error: {e}")
    
    print(f"\nCombination complete. File saved as '{output_filename}'.\n")
    return True

if __name__ == '__main__':
    # Step 1: Combine all relevant CSVs into one Excel file.
    if combine_csv_to_excel():
        # Step 2: If combination was successful, proceed with merging.
        process_and_merge_data()
