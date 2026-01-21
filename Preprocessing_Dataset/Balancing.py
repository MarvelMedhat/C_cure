import pandas as pd
import os
from sklearn.utils import resample
from pathlib import Path


dataset = Path(__file__).parent / '../datasets/Merged/merged_dataset.parquet'
dataset = pd.read_parquet(dataset, engine='pyarrow')

#columns_drop = ['commit_message', 'cve_list', 'cwe_list','context']
#dataset = dataset.drop(columns=columns_drop)

df_majority = dataset[dataset.is_vulnerable==0]
df_minority = dataset[dataset.is_vulnerable==1]

# Sample 20000 rows from the majority class
df_majority_sampled = resample(df_majority,
                                    replace=False,
                                    n_samples=20000,
                                    random_state=42)

# Combine minority class with the sampled majority class
dataset_balanced = pd.concat([df_minority, df_majority_sampled])

print("Class counts after sampling:")
print(dataset_balanced.is_vulnerable.value_counts())
df=dataset_balanced.copy()
df.info()
df_majority = dataset[dataset.is_vulnerable==0]
df_minority = dataset[dataset.is_vulnerable==1]

# Sample 20000 rows from the majority class
df_majority_sampled = resample(df_majority,
                                    replace=False,
                                    n_samples=20000,
                                    random_state=42)

# Combine minority class with the sampled majority class
dataset_balanced = pd.concat([df_minority, df_majority_sampled])

print("Class counts after sampling:")
print(dataset_balanced.is_vulnerable.value_counts())
df=dataset_balanced.copy()
df.info()

output_path = Path(__file__).parent / '../datasets/Balanced/balanced_dataset.parquet'
os.makedirs(os.path.dirname(output_path), exist_ok=True)

df.to_parquet(output_path, index=False, engine="pyarrow")