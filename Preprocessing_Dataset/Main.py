import subprocess
import sys

# List your files in the exact order you want them to run
scripts_to_run = [
   "Preprocessing_Dataset/SecVulEval.py",
   "Preprocessing_Dataset/SVEN.py",
   "Preprocessing_Dataset/PrimeVul.py",
   "Preprocessing_Dataset/Merging.py",
   "Preprocessing_Dataset/Mapping_CWE.py",
   "Preprocessing_Dataset/CWE_Category.py",
   "Preprocessing_Dataset/Families.py",
   "Preprocessing_Dataset/Balancing.py",
   "Preprocessing_Dataset/Split_Dataset.py"
]

for script in scripts_to_run:
    print(f"--- Running {script} ---")
    try:
        # check=True stops the sequence if a script fails (returns an error)
        subprocess.run([sys.executable, script], check=True)
        print(f"--- Finished {script} ---\n")
    except subprocess.CalledProcessError:
        print(f"Error occurred in {script}. Stopping pipeline.")
        break