import os
import pandas as pd
from pathlib import Path


dataset = Path(__file__).parent / '../datasets/Merged/merged_dataset.parquet'
dataset = pd.read_parquet(dataset, engine='pyarrow')



print(dataset['vulnerability_category'].value_counts())


category_counts = dataset['vulnerability_category'].value_counts()

# Filter only the categories that appear at least 350 times
valid_categories = category_counts[category_counts >= 1500].index

# Keep only those rows in the dataset
dataset = dataset[dataset['vulnerability_category'].isin(valid_categories)]

# Optional: verify the result
print(dataset['vulnerability_category'].value_counts())

print(dataset['is_vulnerable'].value_counts())


output_path = Path(__file__).parent / '../datasets/Merged/merged_dataset.parquet'
os.makedirs(os.path.dirname(output_path), exist_ok=True)

dataset.to_parquet(output_path, index=False, engine="pyarrow")

print(f"\n Merged dataset saved to:\n{output_path}")