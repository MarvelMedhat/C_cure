# Fine-tuning DeepSeek-Coder-V2-Lite-Base (16B) on Kaggle GPU (32GB)
# Using QLoRA for memory efficiency

# %% [code]
# Install required packages
import subprocess
import sys

print("Installing required packages...")
subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", "-U", 
                      "transformers", "datasets", "peft", "bitsandbytes", 
                      "accelerate", "trl"])
print("Packages installed successfully!\n")

# %% [code]
import os
import torch
from datasets import load_dataset
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,
    BitsAndBytesConfig,
    TrainingArguments,
    pipeline
)
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from trl import SFTTrainer

# %% [code]
# Configuration for 32GB GPU (Optimized for Kaggle)
MODEL_NAME = "deepseek-ai/DeepSeek-Coder-V2-Lite-Base"
OUTPUT_DIR = "./deepseek-finetuned-memory-corruption"
DATASET_PATH = "/kaggle/input/memory-corruptuion/Memory_Corruption.parquet"

# QLoRA Configuration - Optimized for 16B model on 32GB GPU
QLORA_CONFIG = {
    # LoRA parameters
    "lora_r": 16,              # LoRA rank (16-32 recommended)
    "lora_alpha": 32,          # LoRA alpha (usually 2 × rank)
    "lora_dropout": 0.05,      # Dropout for regularization
    "target_modules": [        # Which layers to apply LoRA to
        "q_proj",
        "k_proj", 
        "v_proj",
        "o_proj",
        "gate_proj",
        "up_proj",
        "down_proj"
    ],
}

# Training hyperparameters for 32GB GPU
TRAINING_CONFIG = {
    "num_train_epochs": 3,
    "per_device_train_batch_size": 1,      # Start with 1, can try 2
    "gradient_accumulation_steps": 8,      # Effective batch size = 1 × 8 = 8
    "learning_rate": 2e-4,
    "max_grad_norm": 0.3,
    "warmup_ratio": 0.03,
    "lr_scheduler_type": "cosine",
    "weight_decay": 0.001,
    "optim": "paged_adamw_8bit",          # Memory-efficient optimizer
    "logging_steps": 10,
    "save_strategy": "steps",
    "save_steps": 100,
    "max_seq_length": 2048,               # Max sequence length
}

# %% [code]
# 4-bit quantization configuration
bnb_config = BitsAndBytesConfig(
    load_in_4bit=True,
    bnb_4bit_quant_type="nf4",           # Normal Float 4-bit
    bnb_4bit_compute_dtype=torch.bfloat16,
    bnb_4bit_use_double_quant=True,      # Nested quantization for extra savings
)

# %% [code]
# Load tokenizer
print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(
    MODEL_NAME,
    trust_remote_code=True,
    padding_side="right"  # Important for training
)

# Add pad token if it doesn't exist
if tokenizer.pad_token is None:
    tokenizer.pad_token = tokenizer.eos_token

# %% [code]
# Load model with 4-bit quantization
print("Loading model with 4-bit quantization...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",                    # Automatically distribute across GPUs
    trust_remote_code=True,
    torch_dtype=torch.bfloat16,
)

# Prepare model for k-bit training
model = prepare_model_for_kbit_training(model)

# %% [code]
# Configure LoRA
print("Configuring LoRA...")
peft_config = LoraConfig(
    r=QLORA_CONFIG["lora_r"],
    lora_alpha=QLORA_CONFIG["lora_alpha"],
    lora_dropout=QLORA_CONFIG["lora_dropout"],
    target_modules=QLORA_CONFIG["target_modules"],
    bias="none",
    task_type="CAUSAL_LM"
)

# model = get_peft_model(model, peft_config)
# model.print_trainable_parameters()

# %% [code]
# Load and prepare dataset
print("Loading dataset...")
dataset = load_dataset("parquet", data_files=DATASET_PATH, split="train")

# Inspect the dataset
print(f"\nDataset info:")
print(f"Total samples: {len(dataset)}")
print(f"Columns: {dataset.column_names}")
print(f"\nFirst example:")
print(dataset[0])

# %% [code]
# Format the dataset for training
def format_prompt(example):
    """
    Format the Memory Corruption dataset into a prompt-response structure.
    
    Dataset columns:
    - is_vulnerable: Binary label (0=safe, 1=vulnerable)
    - func_body: The source code
    - cwe_list: List of CWE IDs (e.g., ['CWE-119'])
    """
    func_body = example["func_body"]
    is_vulnerable = example["is_vulnerable"]
    cwe_list = example.get("cwe_list", [])
    
    # Create a clear, instructive prompt
    if is_vulnerable == 1:
        # Vulnerable code
        if cwe_list and len(cwe_list) > 0:
            cwe_str = ", ".join(cwe_list)
            analysis = f"This code is VULNERABLE to memory corruption. CWE(s): {cwe_str}"
        else:
            analysis = "This code is VULNERABLE to memory corruption."
    else:
        # Safe code
        analysis = "This code is SAFE. No memory corruption vulnerabilities detected."
    
    prompt = f"""### Task: Analyze the following C/C++ code for memory corruption vulnerabilities.

### Code:
{func_body}

### Analysis:
{analysis}"""
    
    return {"text": prompt}

# Apply formatting
print("\nFormatting dataset...")
formatted_dataset = dataset.map(format_prompt, remove_columns=dataset.column_names)

# IMPORTANT: Shuffle the dataset before splitting
print("Shuffling dataset...")
formatted_dataset = formatted_dataset.shuffle(seed=42)

# Split into train/validation (90/10 split)
train_val_split = formatted_dataset.train_test_split(test_size=0.1, seed=42)
train_dataset = train_val_split["train"]
eval_dataset = train_val_split["test"]

print(f"Training samples: {len(train_dataset)}")
print(f"Validation samples: {len(eval_dataset)}")

# %% [code]
# Training arguments
training_args = TrainingArguments(
    output_dir=OUTPUT_DIR,
    num_train_epochs=TRAINING_CONFIG["num_train_epochs"],
    per_device_train_batch_size=TRAINING_CONFIG["per_device_train_batch_size"],
    gradient_accumulation_steps=TRAINING_CONFIG["gradient_accumulation_steps"],
    gradient_checkpointing=True,          # Save memory at cost of speed
    learning_rate=TRAINING_CONFIG["learning_rate"],
    max_grad_norm=TRAINING_CONFIG["max_grad_norm"],
    warmup_ratio=TRAINING_CONFIG["warmup_ratio"],
    lr_scheduler_type=TRAINING_CONFIG["lr_scheduler_type"],
    weight_decay=TRAINING_CONFIG["weight_decay"],
    optim=TRAINING_CONFIG["optim"],
    logging_steps=TRAINING_CONFIG["logging_steps"],
    save_strategy=TRAINING_CONFIG["save_strategy"],
    save_steps=TRAINING_CONFIG["save_steps"],
    eval_strategy="steps",
    eval_steps=100,
    bf16=True,                            # Use bfloat16 for training
    logging_dir=f"{OUTPUT_DIR}/logs",
    report_to="none",                     # Change to "tensorboard" if you want logging
    save_total_limit=3,                   # Keep only last 3 checkpoints
    load_best_model_at_end=True,
    group_by_length=True,                 # Group similar lengths for efficiency
)

# %% [code]
# Set max sequence length in tokenizer (fallback for SFTTrainer)
tokenizer.model_max_length = TRAINING_CONFIG["max_seq_length"]

# Initialize trainer
trainer = SFTTrainer(
    model=model,
    train_dataset=train_dataset,
    eval_dataset=eval_dataset,
    peft_config=peft_config,
    processing_class=tokenizer,
    args=training_args,
)

# %% [code]
# Start training
print("\n" + "="*50)
print("Starting training...")
print("="*50 + "\n")

trainer.train()

# %% [code]
# Save the final model
print("\nSaving final model...")
trainer.save_model(OUTPUT_DIR)
tokenizer.save_pretrained(OUTPUT_DIR)

# %% [code]
# Comprehensive Model Evaluation with Metrics
print("\n" + "="*50)
print("EVALUATING MODEL PERFORMANCE")
print("="*50 + "\n")

# Load the fine-tuned model for inference
from peft import PeftModel
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, classification_report, confusion_matrix
from tqdm import tqdm
import re

base_model = AutoModelForCausalLM.from_pretrained(
    MODEL_NAME,
    quantization_config=bnb_config,
    device_map="auto",
    trust_remote_code=True,
)

finetuned_model = PeftModel.from_pretrained(base_model, OUTPUT_DIR)
finetuned_model.eval()

print("Model loaded successfully!\n")

# %% [code]
# Helper function to parse model output and extract prediction
def parse_prediction(output_text):
    """
    Parse the model's text output to determine if it predicted VULNERABLE or SAFE.
    Returns: 1 for vulnerable, 0 for safe, -1 for uncertain
    """
    # Extract only the analysis part (after "### Analysis:")
    if "### Analysis:" in output_text:
        analysis = output_text.split("### Analysis:")[-1].strip().lower()
    else:
        analysis = output_text.lower()
    
    # Check for vulnerability indicators
    vulnerable_keywords = ["vulnerable", "vulnerability", "cwe-", "buffer overflow", "use-after-free", "memory leak"]
    safe_keywords = ["safe", "no vulnerabilities", "no memory corruption"]
    
    # Count keyword matches
    vulnerable_score = sum(1 for keyword in vulnerable_keywords if keyword in analysis)
    safe_score = sum(1 for keyword in safe_keywords if keyword in analysis)
    
    if vulnerable_score > safe_score:
        return 1  # Vulnerable
    elif safe_score > vulnerable_score:
        return 0  # Safe
    else:
        return -1  # Uncertain

# %% [code]
# Run evaluation on validation set
print(f"Running evaluation on {len(eval_dataset)} validation samples...\n")

true_labels = []
predicted_labels = []
uncertain_count = 0

# Use a smaller subset if dataset is very large (for faster evaluation)
eval_size = min(len(eval_dataset), 500)  # Evaluate on max 500 samples
print(f"Evaluating on {eval_size} samples (adjust eval_size if needed)\n")

for i in tqdm(range(eval_size), desc="Evaluating"):
    sample = eval_dataset[i]
    
    # Get ground truth from original dataset
    original_sample = dataset[dataset.shuffle(seed=42).select(range(len(dataset)))['__index_level_0__'][i]]
    true_label = original_sample['is_vulnerable']
    
    # Create input prompt (without the answer)
    func_body = original_sample['func_body']
    input_prompt = f"""### Task: Analyze the following C/C++ code for memory corruption vulnerabilities.

### Code:
{func_body}

### Analysis:"""
    
    # Generate prediction
    inputs = tokenizer(input_prompt, return_tensors="pt", truncation=True, max_length=2048).to("cuda")
    with torch.no_grad():
        outputs = finetuned_model.generate(
            **inputs,
            max_new_tokens=150,
            temperature=0.3,  # Lower temperature for more deterministic outputs
            top_p=0.9,
            do_sample=True,
            pad_token_id=tokenizer.eos_token_id
        )
    
    output_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
    predicted_label = parse_prediction(output_text)
    
    # Handle uncertain predictions (default to safe to be conservative)
    if predicted_label == -1:
        uncertain_count += 1
        predicted_label = 0  # Default to safe
    
    true_labels.append(true_label)
    predicted_labels.append(predicted_label)

# %% [code]
# Calculate metrics
print("\n" + "="*50)
print("EVALUATION RESULTS")
print("="*50 + "\n")

# Overall metrics
accuracy = accuracy_score(true_labels, predicted_labels)
precision, recall, f1, support = precision_recall_fscore_support(
    true_labels, predicted_labels, average='binary', zero_division=0
)

print(f"📊 OVERALL METRICS:")
print(f"  Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
print(f"  Precision: {precision:.4f} ({precision*100:.2f}%)")
print(f"  Recall:    {recall:.4f} ({recall*100:.2f}%)")
print(f"  F1 Score:  {f1:.4f} ({f1*100:.2f}%)")
print(f"  Uncertain predictions: {uncertain_count}/{eval_size} ({uncertain_count/eval_size*100:.2f}%)")

# Detailed classification report
print(f"\n📋 DETAILED CLASSIFICATION REPORT:")
print(classification_report(
    true_labels, 
    predicted_labels, 
    target_names=['Safe', 'Vulnerable'],
    digits=4,
    zero_division=0
))

# Confusion matrix
print(f"🔢 CONFUSION MATRIX:")
cm = confusion_matrix(true_labels, predicted_labels)
print(f"                Predicted")
print(f"              Safe  Vulnerable")
print(f"Actual Safe     {cm[0][0]:4d}  {cm[0][1]:4d}")
print(f"     Vulnerable {cm[1][0]:4d}  {cm[1][1]:4d}")

# Additional insights
tn, fp, fn, tp = cm.ravel()
print(f"\n📈 ADDITIONAL METRICS:")
print(f"  True Positives:  {tp} (Correctly identified vulnerabilities)")
print(f"  True Negatives:  {tn} (Correctly identified safe code)")
print(f"  False Positives: {fp} (Safe code marked as vulnerable)")
print(f"  False Negatives: {fn} (Missed vulnerabilities - CRITICAL!)")
if tp + fn > 0:
    print(f"  Vulnerability Detection Rate: {tp/(tp+fn)*100:.2f}%")

# %% [code]
# Show example predictions
print("\n" + "="*50)
print("SAMPLE PREDICTIONS (First 3 examples)")
print("="*50 + "\n")

for i in range(min(3, eval_size)):
    original_sample = dataset[i]
    func_body = original_sample['func_body'][:200] + "..." if len(original_sample['func_body']) > 200 else original_sample['func_body']
    
    print(f"Example {i+1}:")
    print(f"Code snippet: {func_body}")
    print(f"True label: {'VULNERABLE' if true_labels[i] == 1 else 'SAFE'}")
    print(f"Predicted:  {'VULNERABLE' if predicted_labels[i] == 1 else 'SAFE'}")
    print(f"Correct: {'✅' if true_labels[i] == predicted_labels[i] else '❌'}")
    print("-" * 50 + "\n")

# %% [markdown]
# ## Memory Usage Tips for Kaggle 32GB GPU
# 
# If you run into OOM (Out of Memory) errors, try these adjustments:
# 
# 1. **Reduce batch size**: Set `per_device_train_batch_size=1`
# 2. **Increase gradient accumulation**: Set `gradient_accumulation_steps=16`
# 3. **Reduce sequence length**: Set `max_seq_length=1024` or `512`
# 4. **Reduce LoRA rank**: Set `lora_r=8` instead of 16
# 5. **Use fewer target modules**: Only apply LoRA to `["q_proj", "v_proj"]`
# 6. **Enable packing**: Set `packing=True` in SFTTrainer (if your data allows)
# 
# ## Expected Training Time on Kaggle
# 
# - With these settings, expect ~2-4 hours for 3 epochs (depending on dataset size)
# - Monitor GPU usage with: `!nvidia-smi` in a separate cell
# 
# ## Saving Your Model
# 
# The model will be saved to `./deepseek-finetuned-memory-corruption/`
# You can download it from Kaggle or push it to HuggingFace Hub.
# 
# To push to HuggingFace Hub:
# ```python
# from huggingface_hub import login
# login()  # Enter your token
# model.push_to_hub("your-username/deepseek-memory-corruption")
# tokenizer.push_to_hub("your-username/deepseek-memory-corruption")
# ```
