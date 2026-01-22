import json
import os
import pandas as pd
from pathlib import Path

secVulEval = Path(__file__).parent / '../datasets/SecVulEval/secVulEval_cleaned.parquet'
secVulEval = pd.read_parquet(secVulEval, engine='pyarrow')


# Loading PrimeVul Dataset

file_paths = [
    Path(__file__).parent / '../datasets/PrimeVul/primevul_train.jsonl',
    Path(__file__).parent / '../datasets/PrimeVul/primevul_test.jsonl',
    Path(__file__).parent / '../datasets/PrimeVul/primevul_valid.jsonl'
]


def read_jsonl_safely(path):

    try:
        df = pd.read_json(path, lines=True)
        print(f"Successfully read: {path}")
        return df
    except ValueError as e:
        print(f"pandas.read_json failed for {path}: {e}")
        print("   Trying manual JSONL parsing...")

        data = []
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.strip():
                        data.append(json.loads(line))
            df = pd.DataFrame(data)
            print(f"Successfully read (manual parse): {path}")
            return df
        except Exception as e2:
            print(f"Failed to read {path}: {e2}")
            return pd.DataFrame()

# Read all files and combine into one DataFrame
all_dfs = [read_jsonl_safely(p) for p in file_paths]
Primevul_df = pd.concat(all_dfs, ignore_index=True)

print("\n All files loaded and combined!")
print(f"Total records: {len(Primevul_df)}")


Primevul_df.head()


Primevul_df.info()

columns_to_drop = ["idx", "project", "commit_id","project_url","commit_url","func_hash","file_name","file_hash","cve_desc","nvd_url"]
Primevul_cleaned = Primevul_df.drop(columns=columns_to_drop)

# Rename columns
Primevul_cleaned = Primevul_cleaned.rename(columns={"func": "func_body", "target": "is_vulnerable", "cwe": "cwe_list","cve":"cve_list"})

# binary label normalization
Primevul_cleaned["is_vulnerable"] = Primevul_cleaned["is_vulnerable"].astype(int)

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

Primevul = align_columns(secVulEval,Primevul_cleaned)

Primevul.info()

print(Primevul["cwe_list"].value_counts())


Primevul['cwe_list'] = Primevul_cleaned['cwe_list'].astype(str)

print("Have Dupliacted ??")
print(Primevul.duplicated().any())

print(Primevul["is_vulnerable"].value_counts())
Primevul.loc[Primevul['is_vulnerable'] == False, 'cwe_list'] = Primevul.loc[Primevul['is_vulnerable'] == False, 'cwe_list'].apply(lambda _: [])


output_file_path = Path(__file__).parent / '../datasets/PrimeVul/PrimeVul_cleaned.parquet'

# Save cleaned dataset
os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
Primevul.to_parquet(output_file_path, index=False, engine='pyarrow')

print(f"\nCleaned PrimeVul dataset saved to: {os.path.abspath(output_file_path)}")
