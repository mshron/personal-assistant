"""Find past transactions with similar descriptions in an hledger journal.

Usage:
    python find_similar.py "WHOLEFDS MKT 10432" /workspace/main.journal --top 5

Returns JSON array of matching transactions with their assigned accounts.
"""

import argparse
import json
import re
import subprocess
import sys
from difflib import SequenceMatcher


def normalize(s: str) -> str:
    """Normalize a transaction description for comparison."""
    s = s.lower()
    # Strip trailing store/location numbers (e.g. "WHOLEFDS MKT 10432" -> "wholefds mkt")
    s = re.sub(r'\s*#?\d{3,}$', '', s)
    # Strip common prefixes
    s = re.sub(r'^(sq \*|tst \*|sp \*|pp \*)', '', s)
    # Collapse whitespace
    s = re.sub(r'\s+', ' ', s).strip()
    return s


def get_transactions(journal_path: str) -> list[dict]:
    """Get all transactions from the journal using hledger."""
    result = subprocess.run(
        ['hledger', 'print', '-f', journal_path, '-O', 'json'],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"hledger error: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def extract_info(txn: dict) -> dict | None:
    """Extract date, description, amount, and account from an hledger JSON transaction."""
    desc = txn.get('tdescription', '')
    date = txn.get('tdate', '')
    postings = txn.get('tpostings', [])

    # Find the non-source posting (the expense/income account, not assets/liabilities)
    for p in postings:
        account = p.get('paccount', '')
        if account.startswith(('expenses:', 'income:')):
            # Skip uncategorized
            if account in ('expenses:unknown', 'income:unknown'):
                continue
            amounts = p.get('pamount', [])
            amount_str = ''
            if amounts:
                qty = amounts[0].get('aquantity', {}).get('decimalMantissa', 0)
                places = amounts[0].get('aquantity', {}).get('decimalPlaces', 0)
                commodity = amounts[0].get('acommodity', '$')
                amount_val = qty / (10 ** places) if places else qty
                amount_str = f"{commodity}{amount_val:.2f}"
            return {
                'date': date,
                'description': desc,
                'amount': amount_str,
                'account': account,
            }
    return None


def find_similar(query: str, journal_path: str, top_n: int = 5) -> list[dict]:
    """Find transactions with descriptions similar to the query."""
    txns = get_transactions(journal_path)
    query_norm = normalize(query)

    scored = []
    for txn in txns:
        info = extract_info(txn)
        if not info:
            continue
        desc_norm = normalize(info['description'])
        score = SequenceMatcher(None, query_norm, desc_norm).ratio()
        if score > 0.4:
            scored.append((score, info))

    scored.sort(key=lambda x: x[0], reverse=True)

    # Deduplicate by account+description, keeping highest score
    seen = set()
    results = []
    for score, info in scored:
        key = (info['account'], normalize(info['description']))
        if key not in seen:
            seen.add(key)
            results.append(info)
        if len(results) >= top_n:
            break

    return results


def main():
    parser = argparse.ArgumentParser(description='Find similar past transactions')
    parser.add_argument('query', help='Transaction description to search for')
    parser.add_argument('journal', help='Path to hledger journal file')
    parser.add_argument('--top', type=int, default=5, help='Number of results (default: 5)')
    args = parser.parse_args()

    results = find_similar(args.query, args.journal, args.top)
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
