import pandas as pd
from pathlib import Path

'''
Split the dataset into 3 subsets:
- Memory Corruption
- Memory Lifecycle Issues
- Input Validation
'''

dataset = Path(__file__).parent / '../datasets/Balanced/balanced_dataset.parquet'
dataset = pd.read_parquet(dataset, engine='pyarrow')
dataset.info()

columns_drop = ['commit_message', 'cve_list', 'vulnerability_category','context']
memory_corruption = dataset[(dataset['vulnerability_category'] == "['Memory Corruption']") | (dataset['vulnerability_category'] == "[]")]
memory_corruption = memory_corruption.drop(columns=columns_drop)
memory_corruption.info()

memory_lifecycle = dataset[(dataset['vulnerability_category'] == "['Memory Lifecycle Issues']") | (dataset['vulnerability_category'] == "[]")]
memory_lifecycle = memory_lifecycle.drop(columns=columns_drop)
memory_lifecycle.info()

input_validation = dataset[(dataset['vulnerability_category'] == "['Input Validation']") | (dataset['vulnerability_category'] == "[]")]
input_validation = input_validation.drop(columns=columns_drop)
input_validation.info()

memory_corruption.to_parquet(Path(__file__).parent / '../datasets/Datasets_of_Families/Memory_Corruption.parquet', engine='pyarrow')
memory_lifecycle.to_parquet(Path(__file__).parent / '../datasets/Datasets_of_Families/Memory_Lifecycle.parquet', engine='pyarrow')
input_validation.to_parquet(Path(__file__).parent / '../datasets/Datasets_of_Families/Input_Validation.parquet', engine='pyarrow')


