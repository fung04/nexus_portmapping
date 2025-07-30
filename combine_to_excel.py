import pandas as pd
import os

def combine_csv_to_excel(output_filename='combined_port_mappings.xlsx'):
    """
    Reads all CSV files in the current directory ending with '_port_mapping.csv',
    and combines them into a single Excel file with multiple sheets.

    Each sheet is named after the CSV file, with the '_port_mapping' suffix removed.
    """
    # Get the current working directory
    current_directory = os.getcwd()
    
    # Find all files in the directory that end with '_port_mapping.csv'
    csv_files = [f for f in os.listdir(current_directory) if f.endswith('_port_mapping.csv')]
    
    if not csv_files:
        print("No '*_port_mapping.csv' files found in the current directory.")
        return

    print(f"Found {len(csv_files)} CSV files to process.")

    # Create a Pandas Excel writer using openpyxl as the engine
    with pd.ExcelWriter(output_filename, engine='openpyxl') as writer:
        for csv_file in csv_files:
            try:
                # Construct the full file path
                file_path = os.path.join(current_directory, csv_file)
                
                # Create a clean sheet name by removing the suffix
                # This handles both '_port_mapping.csv' and '.csv'
                sheet_name = csv_file.replace('_port_mapping.csv', '')
                
                # Read the CSV file into a pandas DataFrame
                # keep_default_na=False prevents pandas from interpreting 'N/A' as a null value
                df = pd.read_csv(file_path, keep_default_na=False)
                
                # Write the DataFrame to a specific sheet in the Excel file
                # index=False prevents pandas from writing the DataFrame index as a column
                df.to_excel(writer, sheet_name=sheet_name, index=False)
                
                print(f"Successfully added '{csv_file}' to sheet '{sheet_name}'.")
            
            except Exception as e:
                print(f"Could not process file {csv_file}. Error: {e}")

    print(f"\nAll done! The combined Excel file has been saved as '{output_filename}'.")

if __name__ == '__main__':
    # To run the script, place it in the same directory as your CSV files
    # and execute it from your terminal using: python your_script_name.py
    combine_csv_to_excel()