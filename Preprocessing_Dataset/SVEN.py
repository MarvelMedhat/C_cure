import os
import pandas as pd
from pathlib import Path


secVulEval = Path(__file__).parent / '../datasets/SecVulEval/secVulEval_cleaned.parquet'
secVulEval = pd.read_parquet(secVulEval, engine='pyarrow')


# Loading SVEN Dataset
file_path = Path(__file__).parent / '../datasets/SVEN/train.parquet'

try:
    SVEN_df = pd.read_parquet(file_path)
    print("Parquet file read successfully!")
    print(SVEN_df.head(10))
except FileNotFoundError:
    print(f"Error: File not found at {file_path}")
except Exception as e:
    print(f"An error occurred: {e}")

SVEN_df.info()

# Removes Python files
SVEN_df=SVEN_df[~SVEN_df['file_name'].str.endswith('.py', na=False)]

SVEN_df.info()

columns_to_drop = ['file_name', 'commit_link','func_name','func_src_after']
Cleaned_SVEN = SVEN_df.drop(columns=columns_to_drop)
print(Cleaned_SVEN.head())


# To rename multiple columns:
Cleaned_SVEN = Cleaned_SVEN.rename(columns={'func_src_before': 'func_body', 'vul_type': 'cwe_list', 'line_changes':'changed_lines', 'char_changes':'changed_statements'})


#Cleaned_SVEN['is_vulnerable'] = True
print(Cleaned_SVEN.info())

def align_columns(df_source, df_target):

    # Drop columns not in df_source, and make a real copy to avoid warnings
    df_target = df_target[[col for col in df_target.columns if col in df_source.columns]].copy()

    # Add missing columns
    for col in df_source.columns:
        if col not in df_target.columns:
            df_target[col] = pd.NA

    # Reorder columns
    df_target = df_target[df_source.columns]

    return df_target


SVEN = align_columns(secVulEval,Cleaned_SVEN)

# converts to uppercase strings and wraps each value in square brackets.
SVEN["cwe_list"] = SVEN["cwe_list"].astype(str).str.upper().apply(lambda x: f"[{x}]")

SVEN["is_vulnerable"]=1

SVEN.info()

output_file_path = Path(__file__).parent / '../datasets/SVEN/SVEN_cleaned.parquet'
# Save cleaned dataset
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
SVEN.to_parquet(output_file_path, index=False, engine='pyarrow')

print(f"\nCleaned SVEN dataset saved to: {os.path.abspath(output_file_path)}")
