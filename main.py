import os
import re
import json
import time
import html
import requests
from collections import defaultdict
from dotenv import load_dotenv
from datetime import datetime

# Load env
load_dotenv()

# Configuration (can be overridden by environment variables)
GITHUB_PAT = os.getenv("GITHUB_PAT")
GITHUB_API_BASE = "https://api.github.com/repos/DefiLlama/DefiLlama-Adapters/contents/"
# Discovery keywords (user-optimized)
DISCOVERY_KEYWORDS = [
    "withdraw","reward","treasury","incentive","fee","claim","unstake","owner","admin","governance","vault",
    "payment","distribute","allocation","release","transfer","send","disburse","expenditure",
    "fund","finance","financial","treasury","balance","asset","token","coin","crypto",
    "wallet","account","escrow","custody","deposit","withdrawal","claimable","claiming",
    "rewards","earnings","profit","distribution","dividend","interest","yield"
]

# Additional address categories
EXTRA_CATEGORIES = [
    "payment_addresses",
    "escrow_addresses",
    "custody_addresses",
    "distribution_addresses",
    "allocation_addresses",
    "transfer_addresses",
]

# Defaults (can be overridden via env)
LIMIT = int(os.getenv("LIMIT", "500"))
FULL_SCAN = os.getenv("FULL_SCAN", "true").lower() in ("1","true","yes")
REQUEST_DELAY = float(os.getenv("REQUEST_DELAY", "0.12"))
PRIORITY_CATEGORIES = os.getenv("PRIORITY_CATEGORIES", "payment,withdrawal,treasury,reward,escrow,custody,governance").split(',')

# Scanning helpers
ADDRESS_REGEX = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
KEYWORD_TO_CATEGORY = {
    'stake': 'stake_contracts', 'staking': 'stake_contracts', 'staked': 'stake_contracts',
    'reward': 'reward_contracts', 'rewards': 'reward_contracts',
    'withdraw': 'withdrawal_contracts', 'withdrawal': 'withdrawal_contracts',
    'vault': 'vault_contracts', 'chef': 'chef_contracts',
    'owner': 'owner_addresses', 'admin': 'admin_addresses',
    'governor': 'governance_addresses', 'liquid': 'liquid_contracts',
    'pool2': 'pool2_contracts', 'fee': 'fee_related', 'payment': 'payment_addresses',
    'escrow': 'escrow_addresses', 'custody': 'custody_addresses'
}
SECURITY_KEYWORDS = [
    'onlyOwner','transferOwnership','setFee','pause','unpause','renounceOwnership',
    'multisig','require(msg.sender == owner)','initialize(','proxy','upgrade','setAdmin'
]

HEADERS = { 'Accept': 'application/vnd.github.v3.raw' }
if GITHUB_PAT:
    HEADERS['Authorization'] = f'token {GITHUB_PAT}'


def extract_addresses_from_text(text: str):
    text = html.unescape(text or '')
    return ADDRESS_REGEX.findall(text)


def classify_address_by_context(text: str, addr_index: int, address: str):
    N = 200
    start = max(0, addr_index - N)
    end = min(len(text), addr_index + len(address) + N)
    ctx = text[start:end].lower()
    cats = set()
    for kw, cat in KEYWORD_TO_CATEGORY.items():
        if kw in ctx:
            cats.add(cat)
    return cats


def scan_adapter_folder(adapter_path: str, max_files=100):
    """List files under adapter_path and scan relevant file types for addresses and security keywords."""
    url = GITHUB_API_BASE + adapter_path
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
    except Exception as e:
        return {'error': str(e)}

    try:
        items = r.json()
    except Exception as e:
        return {'error': 'bad-json-listing'}

    results = defaultdict(list)
    files = 0
    if isinstance(items, dict) and items.get('type') == 'file':
        items = [items]

    for it in items:
        if files >= max_files:
            break
        if it.get('type') != 'file':
            continue
        name = it.get('name','')
        if not name.lower().endswith(('.js','.ts','.mjs','.cjs','.json','.sol')):
            continue
        files += 1
        raw = it.get('download_url')
        if not raw:
            continue
        try:
            rf = requests.get(raw, headers=HEADERS, timeout=30)
            rf.raise_for_status()
            text = rf.text
        except Exception:
            continue
        # find addresses
        for m in ADDRESS_REGEX.finditer(text):
            addr = m.group(0)
            cats = classify_address_by_context(text, m.start(), addr)
            if not cats:
                results['candidates'].append((addr, name, 'regex'))
            else:
                for c in cats:
                    results[c].append((addr, name, 'regex_context'))
        # security patterns
        lowered = text.lower()
        for sk in SECURITY_KEYWORDS:
            if sk.lower() in lowered:
                results['security_flags'].append((sk, name))
        time.sleep(REQUEST_DELAY)
    return results


class BroadScanner:
    def __init__(self):
        self.protocols = []

    def get_projects_listing(self):
        url = GITHUB_API_BASE + 'projects'
        try:
            r = requests.get(url, headers=HEADERS, timeout=30)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            print(f"Error fetching projects listing: {e}")
            return []

    def is_interesting(self, item):
        # file or dir
        try:
            if item.get('type') == 'file':
                txt = requests.get(item.get('download_url'), headers=HEADERS, timeout=30).text
                if ADDRESS_REGEX.search(txt) or any(k in txt.lower() for k in DISCOVERY_KEYWORDS):
                    return True
                return False
            # dir: list files and inspect top-level .js/.ts
            listing_url = GITHUB_API_BASE + item.get('path')
            r = requests.get(listing_url, headers=HEADERS, timeout=30)
            r.raise_for_status()
            files = r.json()
            for f in files:
                if f.get('type') == 'file' and f.get('name','').lower().endswith(('.js','.ts')):
                    txt = requests.get(f.get('download_url'), headers=HEADERS, timeout=30).text
                    if ADDRESS_REGEX.search(txt) or any(k in txt.lower() for k in DISCOVERY_KEYWORDS):
                        return True
            return False
        except Exception:
            return False

    def extract_from_item(self, item):
        # try to read index.js first, otherwise scan folder
        try:
            if item.get('type') == 'file':
                name = item.get('name','').rsplit('.',1)[0]
                content = requests.get(item.get('download_url'), headers=HEADERS, timeout=30).text
                addrs = extract_addresses_from_text(content)
                categorized = self.categorize_by_context(content, addrs)
                return {'protocol': name, 'adapter_url': item.get('html_url'), **categorized}
            # dir
            proto = item.get('name')
            index_url = GITHUB_API_BASE + f"projects/{proto}/index.js"
            r = requests.get(index_url, headers=HEADERS, timeout=30)
            if r.status_code == 200:
                data = r.json()
                raw = requests.get(data.get('download_url'), headers=HEADERS, timeout=30).text
                addrs = extract_addresses_from_text(raw)
                categorized = self.categorize_by_context(raw, addrs)
                return {'protocol': proto, 'adapter_url': data.get('html_url'), 'index_file_url': data.get('html_url'), **categorized}
            # fallback to folder scan
            scan = scan_adapter_folder(f"projects/{proto}")
            # merge scan results into categorized structure
            contracts = defaultdict(list)
            for k, items in scan.items():
                if k == 'security_flags' or k == 'error':
                    continue
                for addr, fname, method in items:
                    entry = f"{addr} ({fname}|{method})"
                    contracts[k].append(entry)
            # ensure keys
            out = {
                'protocol': proto,
                'adapter_url': f"https://github.com/DefiLlama/DefiLlama-Adapters/tree/main/projects/{proto}",
                'stake_contracts': contracts.get('stake_contracts', []),
                'reward_contracts': contracts.get('reward_contracts', []),
                'withdrawal_contracts': contracts.get('withdrawal_contracts', []),
                'candidates': contracts.get('candidates', []),
            }
            return out
        except Exception as e:
            return None

    def categorize_by_context(self, text, addresses):
        categorized = { 'stake_contracts': [], 'reward_contracts': [], 'withdrawal_contracts': [], 'other_contracts': [] }
        lines = (text or '').split('\n')
        for addr in set(addresses):
            for i, line in enumerate(lines):
                if addr in line:
                    ctx = ' '.join(lines[max(0,i-2):min(len(lines),i+3)]).lower()
                    if any(k in ctx for k in ['stake','staking','deposit','lsp']):
                        categorized['stake_contracts'].append(addr)
                    elif any(k in ctx for k in ['reward','incentive','fee','rewards']):
                        categorized['reward_contracts'].append(addr)
                    elif any(k in ctx for k in ['withdraw','unstake','claim','withdrawal']):
                        categorized['withdrawal_contracts'].append(addr)
                    else:
                        categorized['other_contracts'].append(addr)
        return {k: list(dict.fromkeys(v)) for k,v in categorized.items()}

    def run(self):
        print('\n' + '='*80)
        print('🚀 BROAD SCANNER - Discovery & Extraction')
        print('='*80)
        items = self.get_projects_listing()
        if not items:
            print('No projects found or failed to fetch listing')
            return
        print(f"Found {len(items)} project entries; scanning up to {LIMIT} entries (FULL_SCAN={FULL_SCAN})")
        to_scan = items[:LIMIT]
        for i, item in enumerate(to_scan, 1):
            name = item.get('name')
            print(f"[{i}/{len(to_scan)}] Checking {name}...", end=' ', flush=True)
            try:
                if self.is_interesting(item):
                    res = self.extract_from_item(item)
                    if res:
                        self.protocols.append(res)
                        print('✓')
                    else:
                        print('✗')
                else:
                    print('✗')
            except Exception as e:
                print(f'err')
            time.sleep(REQUEST_DELAY)
        # save
        out = { 'metadata': { 'extracted_at': datetime.now().isoformat(), 'limit': LIMIT, 'full_scan': FULL_SCAN }, 'protocols': self.protocols }
        with open('liquid_staking_analysis.json','w') as f:
            json.dump(out, f, indent=2)
        print('\nSaved results to liquid_staking_analysis.json')


if __name__ == '__main__':
    scanner = BroadScanner()
    scanner.run()
