# Loading SecVulEval Dataset
import os
import pandas as pd


file_path = 'D:\GP\Dataset\SecVulEval\secVulEval.parquet'

try:
    secVulEval_df = pd.read_parquet(file_path)
    print("Parquet file read successfully!")
    print(secVulEval_df.head())
except FileNotFoundError:
    print(f"Error: File not found at {file_path}")
except Exception as e:
    print(f"An error occurred: {e}")


columns_to_drop = ['idx', 'filepath', 'commit_id', 'hash','func_name','project','fixed_func_idx','changed_lines','changed_statements']
secVulEval = secVulEval_df.drop(columns=columns_to_drop)
print(secVulEval.info())

output_file_path = 'Dataset/SecVulEval/secVulEval_cleaned.parquet'
# Save Cleaned Dataset
# Ensure output directory exists
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

secVulEval.to_parquet(output_file_path, index=False)
print(f"\nCleaned dataset saved to: {output_file_path}")
