# Loading SecVulEval Dataset
import os
import pandas as pd
from pathlib import Path
rel_path = Path(__file__).parent / '../datasets/SecVulEval/secVulEval.parquet'

try:
    secVulEval_df = pd.read_parquet(rel_path)
    print("Parquet file read successfully!")
    print(secVulEval_df.head())
except FileNotFoundError:
    print(f"Error: File not found at {rel_path}")
except Exception as e:
    print(f"An error occurred: {e}")


columns_to_drop = ['idx', 'filepath', 'commit_id', 'hash','func_name','project','fixed_func_idx','changed_lines','changed_statements']
secVulEval = secVulEval_df.drop(columns=columns_to_drop)
print(secVulEval.info())

output_file_path = Path(__file__).parent / '../datasets/SecVulEval/secVulEval_cleaned.parquet'
# Save Cleaned Dataset
# Ensure output directory exists
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)

secVulEval.to_parquet(output_file_path, index=False)
print(f"\nCleaned dataset saved to: {output_file_path}")
