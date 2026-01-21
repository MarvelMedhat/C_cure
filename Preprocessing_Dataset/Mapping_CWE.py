import ast
import os
import re
import pandas as pd
from pathlib import Path


dataset = Path(__file__).parent / '../datasets/Merged/merged_dataset.parquet'
dataset = pd.read_parquet(dataset, engine='pyarrow')


cve_to_cwe = {
    'CVE-2010-2060': 'N/A', 'CVE-2010-4648': 'CWE-264', 'CVE-2011-1023': 'N/A',
    'CVE-2011-1767': 'NVD-CWE-Other', 'CVE-2011-1927': 'NVD-CWE-Other', 'CVE-2011-2699': 'NVD-CWE-Other',
    'CVE-2011-2905': 'CWE-426', 'CVE-2011-4324': 'CWE-119', 'CVE-2012-1013': 'N/A',
    'CVE-2012-2744': 'CWE-476', 'CVE-2012-3375': 'NVD-CWE-Other', 'CVE-2012-4444': 'CWE-20',
    'CVE-2012-5517': 'N/A', 'CVE-2013-0250': 'CWE-665', 'CVE-2013-0311': 'NVD-CWE-Other',
    'CVE-2013-1826': 'CWE-476', 'CVE-2013-2206': 'CWE-476', 'CVE-2013-3301': 'CWE-476',
    'CVE-2013-4160': 'CWE-476', 'CVE-2013-4265': 'CWE-476', 'CVE-2013-7017': 'CWE-476',
    'CVE-2013-7446': 'CWE-416', 'CVE-2014-1439': 'CWE-611', 'CVE-2014-1832': 'N/A',
    'CVE-2014-2527': 'NVD-CWE-Other', 'CVE-2014-2528': 'NVD-CWE-Other', 'CVE-2014-3571': 'CWE-476',
    'CVE-2014-3631': 'CWE-476', 'CVE-2014-5352': 'CWE-416', 'CVE-2014-5354': 'CWE-476',
    'CVE-2014-5355': 'CWE-476', 'CVE-2014-9421': 'CWE-416', 'CVE-2014-9491': 'CWE-476',
    'CVE-2014-9904': 'CWE-190', 'CVE-2015-0253': 'CWE-476', 'CVE-2015-1790': 'CWE-476',
    'CVE-2015-2925': 'NVD-CWE-Other', 'CVE-2015-4177': 'CWE-476', 'CVE-2015-7566': 'CWE-476',
    'CVE-2015-8324': 'CWE-476', 'CVE-2015-8630': 'CWE-476', 'CVE-2015-8812': 'CWE-416',
    'CVE-2015-8816': 'CWE-476', 'CVE-2015-8830': 'NVD-CWE-Other', 'CVE-2016-0758': 'CWE-190',
    'CVE-2016-2185': 'CWE-476', 'CVE-2016-2187': 'CWE-476', 'CVE-2016-2384': 'CWE-415',
    'CVE-2016-2543': 'CWE-476', 'CVE-2016-3136': 'CWE-476', 'CVE-2016-3137': 'CWE-476',
    'CVE-2016-3951': 'CWE-415', 'CVE-2016-4470': 'CWE-416', 'CVE-2016-4557': 'CWE-416',
    'CVE-2016-4558': 'CWE-416', 'CVE-2016-4581': 'CWE-476', 'CVE-2016-6873': 'CWE-674',
    'CVE-2016-6874': 'CWE-674', 'CVE-2016-6875': 'CWE-674', 'CVE-2016-9388': 'CWE-617',
    'CVE-2016-9391': 'CWE-617', 'CVE-2019-19959': 'N/A', 'CVE-2020-14399': 'NVD-CWE-Other',
    'CVE-2020-14400': 'N/A', 'CVE-2020-15202': 'CWE-197, CWE-754', 'CVE-2020-15224': 'CWE-552',
    'CVE-2020-15945': 'N/A', 'CVE-2021-3331': 'N/A', 'CVE-2021-37491': 'CWE-79',
    'CVE-2021-37492': 'CWE-20', 'CVE-2021-42341': 'N/A', 'CVE-2021-43114': 'N/A',
    'CVE-2022-29201': 'CWE-20, CWE-476', 'CVE-2022-3910': 'CWE-416', 'CVE-2022-41898': 'CWE-20',
    'CVE-2022-46663': 'N/A', 'CVE-2023-1390': 'CWE-1050', 'CVE-2023-34188': 'CWE-1284',
    'CVE-2024-0607': 'CWE-229', 'CVE-2011-1019': 'CWE-119', 'CVE-2011-1182': 'CWE-20',
    'CVE-2011-3638': 'CWE-119', 'CVE-2011-4112': 'CWE-399', 'CVE-2012-5532': 'CWE-200',
    'CVE-2013-0313': 'CWE-119', 'CVE-2013-4220': 'CWE-264', 'CVE-2014-4667': 'CWE-264',
    'CVE-2014-3610': 'CWE-119', 'CVE-2014-3647': 'CWE-284', 'CVE-2014-3646': 'CWE-284',
    'CVE-2016-2383': 'CWE-20', 'CVE-2016-20022': 'N/A', 'CVE-2017-5551': 'CWE-119',
    'CVE-2017-5546': 'CWE-119', 'CVE-2017-2583': 'CWE-416', 'CVE-2017-6348': 'CWE-125',
    'CVE-2017-5669': 'CWE-20', 'CVE-2017-18270': 'CWE-125', 'CVE-2017-18204': 'CWE-119',
    'CVE-2017-18232': 'CWE-476', 'CVE-2018-10021': 'CWE-89', 'CVE-2018-1000204': 'CWE-79',
    'CVE-2018-15572': 'CWE-200', 'CVE-2020-36766': 'CWE-79', 'CVE-2020-27673': 'CWE-295',
    'CVE-2021-38199': 'CWE-787', 'CVE-2021-3732': 'CWE-415', 'CVE-2023-22995': 'CWE-787',
    'CVE-2022-1353': 'CWE-787', 'CVE-2022-1975': 'CWE-416', 'CVE-2022-36123': 'CWE-787',
    'CVE-2023-30456': 'CWE-77', 'CVE-2023-51779': 'CWE-89', 'CVE-2024-25742': 'CWE-787',
    'CVE-2024-31585': 'CWE-89', 'CVE-2023-50007': 'CWE-79', 'CVE-2012-1107': 'CWE-264',
    'CVE-2024-26256': 'CWE-79', 'CVE-2024-24474': 'CWE-79', 'CVE-2023-28095': 'CWE-79',
    'CVE-2023-27601': 'CWE-79', 'CVE-2024-32658': 'CWE-79', 'CVE-2024-32660': 'CWE-79',
    'CVE-2024-32662': 'CWE-79', 'CVE-2014-3480': 'CWE-399', 'CVE-2014-3479': 'CWE-399',
    'CVE-2019-11936': 'CWE-416', 'CVE-2022-36937': 'CWE-787', 'CVE-2014-3985': 'CWE-89',
    'CVE-2015-5224': 'CWE-89', 'CVE-2024-2397': 'CWE-22', 'CVE-2014-9496': 'CWE-284',
    'CVE-2016-8677': 'CWE-284', 'CVE-2016-0546': 'N/A', 'CVE-2023-51384': 'CWE-203',
    'CVE-2023-27567': 'CWE-79', 'CVE-2023-29323': 'CWE-79', 'CVE-2023-52557': 'CWE-79',
    'CVE-2023-52558': 'CWE-79', 'CVE-2023-52556': 'CWE-79', 'CVE-2024-24479': 'CWE-79',
    'CVE-2024-24476': 'CWE-79', 'CVE-2024-24478': 'CWE-79', 'CVE-2016-9842': 'CWE-125',
    'CVE-2016-9841': 'CWE-125', 'CVE-2016-9840': 'CWE-125', 'CVE-2016-9843': 'CWE-125',
    'CVE-2017-1000083': 'CWE-79', 'CVE-2017-6903': 'CWE-89', 'CVE-2017-15377': 'CWE-89',
    'CVE-2021-45098': 'CWE-79', 'CVE-2019-7663': 'CWE-22', 'CVE-2018-1000041': 'CWE-89',
    'CVE-2018-12713': 'CWE-89', 'CVE-2023-5595': 'CWE-89', 'CVE-2019-18604': 'CWE-77',
    'CVE-2018-25103': 'N/A', 'CVE-2023-6507': 'CWE-89', 'CVE-2024-0397': 'CWE-89',
    'CVE-2024-4030': 'CWE-89', 'CVE-2022-35967': 'CWE-617', 'CVE-2022-35979': 'CWE-476',
    'CVE-2022-35974': 'CWE-476', 'CVE-2022-35966': 'CWE-617', 'CVE-2022-36027': 'CWE-617',
    'CVE-2022-35973': 'CWE-476', 'CVE-2024-32462': 'CWE-400', 'CVE-2021-27138': 'CWE-787',
    'CVE-2020-19498': 'CWE-787', 'CVE-2019-12210': 'CWE-787', 'CVE-2024-23324': 'CWE-22',
    'CVE-2024-32475': 'CWE-22', 'CVE-2019-19603': 'CWE-787', 'CVE-2022-24807': 'CWE-22',
    'CVE-2022-24805': 'CWE-22', 'CVE-2022-24808': 'CWE-22', 'CVE-2022-39269': 'CWE-22',
    'CVE-2023-50229': 'CWE-787', 'CVE-2023-50230': 'CWE-787', 'CVE-2024-4323': 'CWE-787',
    'CVE-2022-29859': 'CWE-89', 'CVE-2024-31744': 'CWE-89', 'CVE-2021-28117': 'CWE-89',
    'CVE-2023-32762': 'CWE-22', 'CVE-2021-4076': 'CWE-787', 'CVE-2024-27628': 'CWE-79',
    'CVE-2024-34509': 'CWE-89', 'CVE-2024-34508': 'CWE-89', 'CVE-2024-40130': 'CWE-79',
    'CVE-2024-40129': 'CWE-79', 'CVE-2021-46462': 'CWE-787', 'CVE-2022-21227': 'CWE-125',
    'CVE-2022-35978': 'CWE-476', 'CVE-2024-27319': 'CWE-918', 'CVE-2024-27318': 'CWE-918',
    'CVE-2022-25885': 'CWE-1333', 'CVE-2022-26530': 'CWE-89', 'CVE-2022-29264': 'CWE-22',
    'CVE-2024-25714': 'CWE-22', 'CVE-2023-42465': 'CWE-787', 'CVE-2022-47515': 'CWE-89',
    'CVE-2024-31583': 'CWE-787', 'CVE-2024-31584': 'CWE-787', 'CVE-2022-48624': 'CWE-787',
    'CVE-2024-32487': 'CWE-787', 'CVE-2022-48682': 'CWE-787', 'CVE-2022-4967': 'CWE-787',
    'CVE-2022-4968': 'CWE-787', 'CVE-2022-4969': 'CWE-787', 'CVE-2024-24814': 'CWE-79',
    'CVE-2024-29882': 'CWE-89', 'CVE-2023-35846': 'CWE-79', 'CVE-2023-37378': 'CWE-79',
    'CVE-2024-35190': 'CWE-22', 'CVE-2023-39150': 'CWE-79', 'CVE-2024-28231': 'CWE-89',
    'CVE-2023-44451': 'CWE-79', 'CVE-2023-44452': 'CWE-79', 'CVE-2023-45132': 'CWE-1333',
    'CVE-2023-46046': 'CWE-79', 'CVE-2023-48183': 'CWE-89', 'CVE-2024-25110': 'CWE-89',
    'CVE-2024-27099': 'CWE-89', 'CVE-2024-2313': 'CWE-416', 'CVE-2024-2314': 'CWE-416',
    'CVE-2024-23770': 'CWE-89', 'CVE-2024-28871': 'CWE-89', 'CVE-2024-23837': 'CWE-89',
    'CVE-2024-27454': 'CWE-89', 'CVE-2024-28183': 'CWE-1321', 'CVE-2024-29188': 'CWE-89',
    'CVE-2024-29187': 'CWE-89', 'CVE-2024-29195': 'CWE-89', 'CVE-2024-31221': 'CWE-79',
    'CVE-2024-31226': 'CWE-79', 'CVE-2024-31581': 'CWE-89', 'CVE-2024-31582': 'CWE-89',
    'CVE-2024-31578': 'CWE-89', 'CVE-2024-31852': 'CWE-22', 'CVE-2024-33655': 'CWE-22',
    'CVE-2024-33904': 'CWE-79', 'CVE-2024-36405': 'CWE-79', 'CVE-2024-37310': 'CWE-89',
    'CVE-2024-38375': 'CWE-79', 'CVE-2024-40630': 'CWE-79', 'CVE-2024-41130': 'CWE-89'
}

def parse_cve_list(value):

    if value is None :
        return []

    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        raw = str(value).strip()
        try:
            parsed = ast.literal_eval(raw)
            # if parsed is a single string convert to list
            if isinstance(parsed, str):
                items = [parsed]
            elif isinstance(parsed, (list, tuple, set)):
                items = list(parsed)
            else:
                # unexpected type fallback to regex
                items = None
        except Exception:
            items = None

        if items is None:

            cleaned = raw.replace('\n', ',').replace(';', ',')
            items = re.findall(r'CVE-\d{2,4}-\d{1,7}', cleaned, flags=re.IGNORECASE)

    normalized = []
    for it in items:
        s = str(it).strip().upper().replace('–', '-')
        if re.match(r'^CVE-\d{2,4}-\d{1,7}$', s):
            normalized.append(s)
        else:
            normalized.append(s)
    return normalized

def map_cve_to_cwe_corrected(dataset, cve_to_cwe_map, debug=False):
    unmapped_rows = []

    def get_cwe_for_row(row):
        if 'NVD-CWE-noinfo' not in str(row.get('cwe_list', '')):
            return row['cwe_list']

        parsed_cves = parse_cve_list(row.get('cve_list'))
        found_cwes = set()
        missing_cves = []

        for cve in parsed_cves:
            if cve in cve_to_cwe_map:
                found_cwes.add(cve_to_cwe_map[cve])
            else:
                missing_cves.append(cve)

        if found_cwes:
            return list(found_cwes)

        if debug:
            unmapped_rows.append({
                'index': row.name,
                'original_cve_list': row.get('cve_list'),
                'parsed_cves': parsed_cves,
                'missing_cves': missing_cves,
                'original_cwe_list': row.get('cwe_list'),
            })
        return row['cwe_list']

    dataset['cwe_list'] = dataset.apply(get_cwe_for_row, axis=1)

    if debug:
        diag = pd.DataFrame(unmapped_rows)
        if not diag.empty:
            diag = diag.set_index('index')
        else:
            diag = pd.DataFrame(columns=['index','original_cve_list','parsed_cves','missing_cves','original_cwe_list']).set_index('index')
        return dataset, diag

    return dataset

dataset = map_cve_to_cwe_corrected(dataset, cve_to_cwe)

dataset["cwe_list"] = dataset["cwe_list"].apply(
    lambda x: ", ".join(x) if isinstance(x, list) else str(x)
)

def normalize_cwe_ids(cwe_string):

    if not isinstance(cwe_string, str):
        return str(cwe_string)

    def replace_cwe(match):
        prefix = match.group(1)  # 'CWE-'
        number = match.group(2)  # the digits
        normalized_num = str(int(number))
        return f"{prefix}{normalized_num}"

    normalized = re.sub(r'(CWE-)(\d+)', replace_cwe, cwe_string)
    return normalized

dataset['cwe_list'] = dataset['cwe_list'].apply(normalize_cwe_ids)

print(dataset['cwe_list'].value_counts().head(20))


def quote_cwe_only(cwe_string):

    if not isinstance(cwe_string, str):
        return str(cwe_string)

    pattern = r"(?<!['\"])(\b(?:CWE|NVD-CWE)-[a-zA-Z0-9]+\b)(?!['\"])"

    result = re.sub(pattern, r"'\1'", cwe_string)

    return result

dataset['cwe_list'] = dataset['cwe_list'].apply(quote_cwe_only)


vc = dataset["cwe_list"].value_counts(dropna=False)

with pd.option_context("display.max_rows", None, "display.max_colwidth", None):
    print(vc)

output_path = Path(__file__).parent / '../datasets/Merged/merged_dataset.parquet'
os.makedirs(os.path.dirname(output_path), exist_ok=True)

dataset.to_parquet(output_path, index=False, engine="pyarrow")

print(f"\n Merged dataset saved to:\n{output_path}")

