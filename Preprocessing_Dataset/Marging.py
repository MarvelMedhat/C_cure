import numpy as np
import pandas as pd
import json
import re
from sklearn.utils import resample
import os



secVulEval = 'D:\GP\Dataset\SecVulEval\secVulEval_cleaned.parquet'
secVulEval = pd.read_parquet(secVulEval, engine='pyarrow')
SVEN = 'D:\GP\Dataset\SVEN\SVEN_cleaned.parquet'
SVEN = pd.read_parquet(SVEN, engine='pyarrow')
Primevul = 'D:\GP\Dataset\PrimeVul\PrimeVul_cleaned.parquet'
Primevul = pd.read_parquet(Primevul, engine='pyarrow')


secVulEval = secVulEval.drop_duplicates(subset=["func_body"])
SVEN = SVEN.drop_duplicates(subset=["func_body"])
Primevul = Primevul.drop_duplicates(subset=["func_body"])

dataset = pd.concat([Primevul, SVEN, secVulEval], ignore_index=True)
print(dataset.head())

dataset.info()

dataset = dataset.dropna(subset=["commit_message","is_vulnerable","func_body","cve_list", "cwe_list",])

dataset.info()

print(dataset["is_vulnerable"].value_counts())
dataset.drop_duplicates(subset=['func_body'], inplace=True)
print(dataset["is_vulnerable"].value_counts())

def clean_code(code):
    if not isinstance(code, str):
        return ""
    code = re.sub(r'//.*?$|/\*.*?\*/', '', code, flags=re.S)
    code = re.sub(r'\s+', ' ', code)
    return code.strip()

dataset["func_body"] = dataset["func_body"].apply(clean_code)
dataset = dataset[dataset["func_body"].str.len() < 4000]

dataset.loc[dataset['is_vulnerable'] == 0, 'cwe_list'] = dataset.loc[dataset['is_vulnerable'] == False, 'cwe_list'].apply(lambda _: [])

dataset["is_vulnerable"] = dataset["is_vulnerable"].astype(int)

def ensure_list(x):
    if isinstance(x, list):
        return x
    if isinstance(x, np.ndarray):
        return x.tolist()  # convert ndarray to list
    if pd.isna(x):
        return []
    return [x]  # fallback: wrap single values in a list

dataset["cwe_list"] = dataset["cwe_list"].apply(ensure_list).apply(json.dumps)
dataset["cve_list"] = dataset["cve_list"].apply(ensure_list).apply(json.dumps)


# Save merged dataset
output_path = "D:\GP\Dataset\Merged\merged_dataset.parquet"
os.makedirs(os.path.dirname(output_path), exist_ok=True)

dataset.to_parquet(output_path, index=False, engine="pyarrow")

print(f"\n Merged dataset saved to:\n{output_path}")




