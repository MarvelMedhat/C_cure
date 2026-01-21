import os
import re
import pandas as pd
from pathlib import Path

dataset = Path(__file__).parent / '../datasets/Merged/merged_dataset.parquet'
dataset = pd.read_parquet(dataset, engine='pyarrow')


# Define the 10-family CWE to vulnerability category mapping
cwe_to_category = {
    # Family 1: Memory Corruption
    'CWE-119': 'Memory Corruption',  # Improper Restriction of Operations within Memory Buffer
    'CWE-125': 'Memory Corruption',  # Out-of-bounds Read
    'CWE-787': 'Memory Corruption',  # Out-of-bounds Write
    'CWE-120': 'Memory Corruption',  # Buffer Copy without Checking Size of Input
    'CWE-122': 'Memory Corruption',  # Heap-based Buffer Overflow
    'CWE-121': 'Memory Corruption',  # Stack-based Buffer Overflow
    'CWE-131': 'Memory Corruption',  # Incorrect Calculation of Buffer Size
    'CWE-193': 'Memory Corruption',  # Off-by-one Error
    'CWE-824': 'Memory Corruption',  # Access of Uninitialized Pointer
    'CWE-823': 'Memory Corruption',  # Use of Out-of-range Pointer Offset

    # Family 2: Input Validation
    'CWE-20': 'Input Validation',   # Improper Input Validation
    'CWE-190': 'Input Validation',  # Integer Overflow or Wraparound
    'CWE-191': 'Input Validation',  # Integer Underflow
    'CWE-189': 'Input Validation',  # Numeric Errors
    'CWE-369': 'Input Validation',  # Divide By Zero
    'CWE-681': 'Input Validation',  # Incorrect Conversion between Numeric Types
    'CWE-682': 'Input Validation',  # Incorrect Calculation
    'CWE-129': 'Input Validation',  # Improper Validation of Array Index
    'CWE-1077': 'Input Validation', # Floating Point Comparison with Incorrect Operator

    # Family 3: Memory Lifecycle Issues
    'CWE-416': 'Memory Lifecycle Issues',  # Use After Free
    'CWE-415': 'Memory Lifecycle Issues',  # Double Free
    'CWE-417': 'Memory Lifecycle Issues',  # Channel and Path Errors
    'CWE-476': 'Memory Lifecycle Issues',  # NULL Pointer Dereference
    'CWE-672': 'Memory Lifecycle Issues',  # Operation on a Resource after Expiration
    'CWE-908': 'Memory Lifecycle Issues',  # Use of Uninitialized Resource
    'CWE-825': 'Memory Lifecycle Issues',  # Expired Pointer Dereference

    # Family 4: Access Control & Authentication
    'CWE-264': 'Access Control & Authentication',  # Permissions, Privileges, and Access Controls
    'CWE-269': 'Access Control & Authentication',  # Improper Privilege Management
    'CWE-276': 'Access Control & Authentication',  # Incorrect Default Permissions
    'CWE-284': 'Access Control & Authentication',  # Improper Access Control
    'CWE-285': 'Access Control & Authentication',  # Improper Authorization
    'CWE-287': 'Access Control & Authentication',  # Improper Authentication
    'CWE-288': 'Access Control & Authentication',  # Authentication Bypass Using Alternate Path
    'CWE-290': 'Access Control & Authentication',  # Authentication Bypass by Spoofing
    'CWE-306': 'Access Control & Authentication',  # Missing Authentication for Critical Function
    'CWE-307': 'Access Control & Authentication',  # Improper Restriction of Excessive Authentication Attempts
    'CWE-732': 'Access Control & Authentication',  # Incorrect Permission Assignment for Critical Resource
    'CWE-862': 'Access Control & Authentication',  # Missing Authorization
    'CWE-863': 'Access Control & Authentication',  # Incorrect Authorization
    'CWE-273': 'Access Control & Authentication',  # Improper Check for Dropped Privileges
    'CWE-275': 'Access Control & Authentication',  # Permission Issues
    'CWE-281': 'Access Control & Authentication',  # Improper Preservation of Permissions
    'CWE-1284': 'Access Control & Authentication', # Improper Validation of Specified Quantity in Input

    # Family 5: Resource Management
    'CWE-400': 'Resource Management',  # Uncontrolled Resource Consumption
    'CWE-401': 'Resource Management',  # Missing Release of Memory after Effective Lifetime
    'CWE-404': 'Resource Management',  # Improper Resource Shutdown or Release
    'CWE-770': 'Resource Management',  # Allocation of Resources Without Limits
    'CWE-772': 'Resource Management',  # Missing Release of Resource after Effective Lifetime
    'CWE-617': 'Resource Management',  # Reachable Assertion
    'CWE-771': 'Resource Management',  # Missing Reference to Active Allocated Resource
    'CWE-399': 'Resource Management',  # Resource Management Errors
    'CWE-407': 'Resource Management',  # Inefficient Algorithmic Complexity
    'CWE-835': 'Resource Management',  # Loop with Unreachable Exit Condition
    'CWE-834': 'Resource Management',  # Excessive Iteration
    'CWE-674': 'Resource Management',  # Uncontrolled Recursion
    'CWE-776': 'Resource Management',  # Improper Restriction of Recursive Entity References in DTDs
    'CWE-664': 'Resource Management',  # Improper Control of a Resource
    'CWE-1187': 'Resource Management', # DEPRECATED: Use of Uninitialized Resource

    # Family 6: Information Disclosure
    'CWE-200': 'Information Disclosure',  # Exposure of Sensitive Information
    'CWE-203': 'Information Disclosure',  # Observable Discrepancy
    'CWE-208': 'Information Disclosure',  # Observable Timing Discrepancy
    'CWE-209': 'Information Disclosure',  # Generation of Error Message with Sensitive Information
    'CWE-212': 'Information Disclosure',  # Improper Removal of Sensitive Information
    'CWE-522': 'Information Disclosure',  # Insufficiently Protected Credentials
    'CWE-532': 'Information Disclosure',  # Insertion of Sensitive Information into Log File
    'CWE-565': 'Information Disclosure',  # Reliance on Cookies without Validation

    # Family 7: Injection Attacks
    'CWE-74': 'Injection Attacks',   # Improper Neutralization of Special Elements in Output
    'CWE-77': 'Injection Attacks',   # Command Injection
    'CWE-78': 'Injection Attacks',   # OS Command Injection
    'CWE-79': 'Injection Attacks',   # Cross-site Scripting (XSS)
    'CWE-88': 'Injection Attacks',   # Argument Injection
    'CWE-89': 'Injection Attacks',   # SQL Injection
    'CWE-90': 'Injection Attacks',   # LDAP Injection
    'CWE-91': 'Injection Attacks',   # XML Injection
    'CWE-93': 'Injection Attacks',   # Improper Neutralization of CRLF Sequences
    'CWE-94': 'Injection Attacks',   # Improper Control of Generation of Code
    'CWE-113': 'Injection Attacks',  # HTTP Response Splitting
    'CWE-116': 'Injection Attacks',  # Improper Encoding or Escaping of Output
    'CWE-134': 'Injection Attacks',  # Use of Externally-Controlled Format String
    'CWE-611': 'Injection Attacks',  # Improper Restriction of XML External Entity Reference
    'CWE-918': 'Injection Attacks',  # Server-Side Request Forgery (SSRF)
    'CWE-943': 'Injection Attacks',  # Improper Neutralization of Special Elements in Data Query Logic

    # Family 8: Race Conditions & Concurrency
    'CWE-362': 'Race Conditions & Concurrency',  # Concurrent Execution using Shared Resource
    'CWE-366': 'Race Conditions & Concurrency',  # Race Condition within a Thread
    'CWE-367': 'Race Conditions & Concurrency',  # Time-of-check Time-of-use (TOCTOU)
    'CWE-361': 'Race Conditions & Concurrency',  # 7PK - Time and State
    'CWE-662': 'Race Conditions & Concurrency',  # Improper Synchronization
    'CWE-663': 'Race Conditions & Concurrency',  # Use of a Non-reentrant Function
    'CWE-667': 'Race Conditions & Concurrency',  # Improper Locking

    # Family 9: Error Handling & Exception Management
    'CWE-241': 'Error Handling & Exception Management',  # Improper Handling of Unexpected Data Type
    'CWE-252': 'Error Handling & Exception Management',  # Unchecked Return Value
    'CWE-388': 'Error Handling & Exception Management',  # 7PK - Errors
    'CWE-391': 'Error Handling & Exception Management',  # Unchecked Error Condition
    'CWE-459': 'Error Handling & Exception Management',  # Incomplete Cleanup
    'CWE-460': 'Error Handling & Exception Management',  # Improper Cleanup on Thrown Exception
    'CWE-703': 'Error Handling & Exception Management',  # Improper Check or Handling of Exceptional Conditions
    'CWE-754': 'Error Handling & Exception Management',  # Improper Check for Unusual Conditions
    'CWE-755': 'Error Handling & Exception Management',  # Improper Handling of Exceptional Conditions

    # Family 10: Path & File Operations
    'CWE-22': 'Path & File Operations',   # Path Traversal
    'CWE-59': 'Path & File Operations',   # Improper Link Resolution Before File Access
    'CWE-61': 'Path & File Operations',   # UNIX Symbolic Link Following
    'CWE-426': 'Path & File Operations',  # Untrusted Search Path
    'CWE-427': 'Path & File Operations',  # Uncontrolled Search Path Element
    'CWE-428': 'Path & File Operations',  # Unquoted Search Path or Element
    'CWE-434': 'Path & File Operations',  # Unrestricted Upload of Dangerous File Type
    'CWE-552': 'Path & File Operations',  # Files or Directories Accessible to External Parties

    # Additional Important CWEs - Categorized into Existing Families

    # Cryptographic Issues (subcategory of Access Control & Authentication or separate handling)
    'CWE-295': 'Cryptographic Issues',  # Improper Certificate Validation
    'CWE-294': 'Cryptographic Issues',  # Authentication Bypass by Capture-replay
    'CWE-310': 'Cryptographic Issues',  # Cryptographic Issues
    'CWE-311': 'Cryptographic Issues',  # Missing Encryption of Sensitive Data
    'CWE-312': 'Cryptographic Issues',  # Cleartext Storage of Sensitive Information
    'CWE-319': 'Cryptographic Issues',  # Cleartext Transmission of Sensitive Information
    'CWE-320': 'Cryptographic Issues',  # Key Management Errors
    'CWE-323': 'Cryptographic Issues',  # Reusing a Nonce, Key Pair in Encryption
    'CWE-326': 'Cryptographic Issues',  # Inadequate Encryption Strength
    'CWE-327': 'Cryptographic Issues',  # Use of a Broken or Risky Cryptographic Algorithm
    'CWE-330': 'Cryptographic Issues',  # Use of Insufficiently Random Values
    'CWE-331': 'Cryptographic Issues',  # Insufficient Entropy
    'CWE-337': 'Cryptographic Issues',  # Predictable Seed in PRNG
    'CWE-345': 'Cryptographic Issues',  # Insufficient Verification of Data Authenticity
    'CWE-346': 'Cryptographic Issues',  # Origin Validation Error
    'CWE-347': 'Cryptographic Issues',  # Improper Verification of Cryptographic Signature
    'CWE-349': 'Cryptographic Issues',  # Acceptance of Extraneous Untrusted Data
    'CWE-354': 'Cryptographic Issues',  # Improper Validation of Integrity Check Value
    'CWE-798': 'Cryptographic Issues',  # Use of Hard-coded Credentials

    # Web-Specific Security Issues
    'CWE-352': 'Web Security',  # Cross-Site Request Forgery (CSRF)
    'CWE-384': 'Web Security',  # Session Fixation
    'CWE-436': 'Web Security',  # Interpretation Conflict
    'CWE-444': 'Web Security',  # HTTP Request Smuggling
    'CWE-494': 'Web Security',  # Download of Code Without Integrity Check
    'CWE-502': 'Web Security',  # Deserialization of Untrusted Data
    'CWE-601': 'Web Security',  # URL Redirection to Untrusted Site
    'CWE-613': 'Web Security',  # Insufficient Session Expiration
    'CWE-913': 'Web Security',  # Improper Control of Dynamically-Managed Code Resources
    'CWE-924': 'Web Security',  # Improper Enforcement of Message Integrity
    'CWE-1021': 'Web Security', # Improper Restriction of Rendered UI Layers

    # Code Quality & Design Issues
    'CWE-172': 'Code Quality',  # Encoding Error
    'CWE-457': 'Code Quality',  # Use of Uninitialized Variable
    'CWE-639': 'Code Quality',  # Authorization Bypass Through User-Controlled Key
    'CWE-665': 'Code Quality',  # Improper Initialization
    'CWE-668': 'Code Quality',  # Exposure of Resource to Wrong Sphere
    'CWE-670': 'Code Quality',  # Always-Incorrect Control Flow Implementation
    'CWE-697': 'Code Quality',  # Incorrect Comparison
    'CWE-704': 'Code Quality',  # Incorrect Type Conversion or Cast
    'CWE-706': 'Code Quality',  # Use of Incorrectly-Resolved Name or Reference
    'CWE-763': 'Code Quality',  # Release of Invalid Pointer or Reference
    'CWE-843': 'Code Quality',  # Access of Resource Using Incompatible Type
    'CWE-909': 'Code Quality',  # Missing Initialization of Resource

    # Configuration & Deployment Issues
    'CWE-16': 'Configuration',   # Configuration
    'CWE-17': 'Configuration',   # DEPRECATED: Code
    'CWE-18': 'Configuration',   # Source Code
    'CWE-19': 'Configuration',   # Data Processing Errors
    'CWE-254': 'Configuration',  # Security Features
    'CWE-255': 'Configuration',  # Credentials Management
    'CWE-358': 'Configuration',  # Improperly Implemented Security Check for Standard
    'CWE-693': 'Configuration',  # Protection Mechanism Failure
    'CWE-707': 'Configuration',  # Improper Neutralization

    # Special/Meta Categories
    'NVD-CWE-noinfo': 'Insufficient Information',
    'NVD-CWE-Other': 'Other'
}


def map_cwe_to_category(cwe_string):

    if not isinstance(cwe_string, str):
        return str(cwe_string)

    cwe_pattern = r'(?:CWE-\d+|NVD-CWE-[a-zA-Z]+)'
    cwes = re.findall(cwe_pattern, cwe_string)

    if not cwes:
        return cwe_string

    # Map each CWE to its category
    categories = []
    for cwe in cwes:
        category = cwe_to_category.get(cwe, 'Uncategorized')
        if category not in categories:  # Avoid duplicates
            categories.append(category)

    if cwe_string.strip().startswith('['):
        if len(categories) == 1:
            return f"['{categories[0]}']"
        else:
            quoted_cats = [f"'{cat}'" for cat in categories]
            return f"[{' '.join(quoted_cats)}]"
    else:
        return ', '.join(categories)

print("\n" + "="*80)
print(f"Total CWEs mapped: {len([k for k in cwe_to_category.keys() if k.startswith('CWE-')])}")

# Count by family
family_counts = {}
for cwe, family in cwe_to_category.items():
    if cwe.startswith('CWE-'):
        family_counts[family] = family_counts.get(family, 0) + 1

print("\nCWEs per Family:")
for family in sorted(family_counts.keys()):
    print(f"  {family}: {family_counts[family]} CWEs")
dataset['vulnerability_category'] = dataset['cwe_list'].apply(map_cwe_to_category)

print(dataset["is_vulnerable"].value_counts())

def correct_category(dataset): 
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "Command Injection" with "OS Command Injection"
        .str.replace(r'(?<!OS\s)\bCommand Injection\b', 'OS Command Injection',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "authorization" with "Improper Access Control"
        .str.replace(r'\b(Improper Authorization|Incorrect Authorization|Missing Authorization)\b',
                    'Improper Access Control',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "Stack/Heap" with "Buffer Overflow"
        .str.replace(r'\b(Stack|Heap)\s+Buffer Overflow\b', 'Buffer Overflow',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "race condition variants" with "Race Condition"
        .str.replace(r'\b(Time-of-check Time-of-use|Improper Locking|Improper Synchronization)\b',
                    'Race Condition',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "information exposure variants" with "Information Exposure"
        .str.replace(r'\b(Exposure of Sensitive Information|Insufficiently Protected Credentials|Cleartext Transmission|Cleartext Storage of Sensitive Information|Information Exposure Through Error Message)\b',
                    'Information Exposure',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "Out-of-bounds Read/Write" with "Out-of-bounds Access"
        .str.replace(r'\b(Out-of-bounds Read|Out-of-bounds Write)\b',
                    'Out-of-bounds Access',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "OAuthentication Bypass variants" with "Improper Authentication"
        .str.replace(r'\b(Authentication Bypass by Spoofing|Authentication Bypass by Capture-replay|Improper Authentication Restriction)\b',
                    'Improper Authentication',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "Pointer problems" with "Pointer Issue"
        .str.replace(r'\b(NULL Pointer Dereference|Uninitialized Pointer|Release of Invalid Pointer|Use of Out-of-range Pointer)\b',
                    'Pointer Issue',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    dataset["vulnerability_category"] = (
        dataset["vulnerability_category"]
        # Replaces "Memory lifecycle bugs" with "Memory Management Issue"
        .str.replace(r'\b(Use After Free|Double Free|Memory Leak)\b',
                    'Memory Management Issue',
                    regex=True, case=False)
        .str.replace(r'\s{2,}', ' ', regex=True)
        .str.strip()
    )
    
correct_category(dataset)
vc2 = dataset["vulnerability_category"].value_counts(dropna=False)

with pd.option_context("display.max_rows", None, "display.max_colwidth", None):
    print(vc2)

cwe_counts = dataset['cwe_list'].value_counts()
pd.set_option('display.max_rows', None)
print(cwe_counts)

output_path = Path(__file__).parent / '../datasets/Merged/merged_dataset.parquet'
os.makedirs(os.path.dirname(output_path), exist_ok=True)

dataset.to_parquet(output_path, index=False, engine="pyarrow")

print(f"\n Merged dataset saved to:\n{output_path}")