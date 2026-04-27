"""Convert Amazon order CSV (from browser extension) to hledger journal entries.

Groups rows by order_id into multi-posting transactions with pro-rated tax/shipping.

Usage:
    python amazon_import.py amazon-orders.csv -o 2026/2026-04.journal
    python amazon_import.py amazon-orders.csv --tax-handling separate
    python amazon_import.py amazon-orders.csv --dry-run
"""

import argparse
import csv
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path


@dataclass
class Item:
    name: str
    seller: str
    price: Decimal


@dataclass
class Order:
    order_id: str
    date: str
    subtotal: Decimal
    shipping: Decimal
    shipping_discount: Decimal
    tax: Decimal
    grand_total: Decimal
    payment_method: str
    items: list[Item] = field(default_factory=list)


def parse_payment_method(raw: str) -> str:
    """Convert 'Visa ****5071' to 'liabilities:credit-card:visa-5071'."""
    raw = raw.strip()
    match = re.search(r'(\w+)\s*\*{3,4}(\d{4})', raw)
    if match:
        card_type = match.group(1).lower()
        last4 = match.group(2)
        return f"liabilities:credit-card:{card_type}-{last4}"
    # Fallback for other formats like "Amazon Visa ending in 5071"
    match = re.search(r'(\w+)\s+ending in\s+(\d{4})', raw)
    if match:
        card_type = match.group(1).lower()
        last4 = match.group(2)
        return f"liabilities:credit-card:{card_type}-{last4}"
    return "liabilities:credit-card:unknown"


def parse_csv(path: str) -> dict[str, Order]:
    """Parse the Amazon orders CSV into Order objects grouped by order_id."""
    orders: dict[str, Order] = {}
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            oid = row['order_id']
            if oid not in orders:
                orders[oid] = Order(
                    order_id=oid,
                    date=row['date'],
                    subtotal=Decimal(row['subtotal']),
                    shipping=Decimal(row['shipping']),
                    shipping_discount=Decimal(row['shipping_discount']),
                    tax=Decimal(row['tax']),
                    grand_total=Decimal(row['grand_total']),
                    payment_method=row['payment_method'],
                )
            orders[oid].items.append(Item(
                name=row['item'],
                seller=row.get('seller', ''),
                price=Decimal(row['item_price']),
            ))
    return orders


def prorate(total: Decimal, items: list[Item], subtotal: Decimal) -> list[Decimal]:
    """Pro-rate a total across items proportional to price. Residual goes to last item."""
    if subtotal == 0 or total == 0:
        return [Decimal('0.00')] * len(items)
    penny = Decimal('0.01')
    shares = []
    allocated = Decimal('0.00')
    for i, item in enumerate(items):
        if i == len(items) - 1:
            # Last item absorbs rounding residual
            shares.append(total - allocated)
        else:
            share = (item.price / subtotal * total).quantize(penny, rounding=ROUND_HALF_UP)
            shares.append(share)
            allocated += share
    return shares


def truncate_item_name(name: str, max_len: int = 50) -> str:
    """Truncate item name for comment, keeping it readable."""
    if len(name) <= max_len:
        return name
    return name[:max_len - 3] + '...'


def format_order(order: Order, tax_handling: str, existing_ids: set[str]) -> str | None:
    """Format an order as an hledger transaction. Returns None if already imported."""
    if order.order_id in existing_ids:
        return None

    lines = [f"{order.date} Amazon.com | Order {order.order_id}"]
    credit_account = parse_payment_method(order.payment_method)

    # Calculate net shipping (shipping + discount)
    net_shipping = order.shipping + order.shipping_discount

    # Pro-rate tax and shipping across items
    tax_shares = prorate(order.tax, order.items, order.subtotal)
    ship_shares = prorate(net_shipping, order.items, order.subtotal)

    if tax_handling == 'separate':
        # Items at face value, tax as separate posting
        for item in order.items:
            name = truncate_item_name(item.name)
            lines.append(f"    expenses:unknown{' ' * max(1, 36 - len('expenses:unknown'))}${item.price:.2f}  ; {name}")
        if order.tax > 0:
            lines.append(f"    expenses:tax{' ' * max(1, 36 - len('expenses:tax'))}${order.tax:.2f}")
        if net_shipping > 0:
            lines.append(f"    expenses:shipping{' ' * max(1, 36 - len('expenses:shipping'))}${net_shipping:.2f}")
    else:
        # inclusive or both: fold tax+shipping into each item
        for i, item in enumerate(order.items):
            all_in = item.price + tax_shares[i] + ship_shares[i]
            name = truncate_item_name(item.name)
            comment_parts = [f"${item.price:.2f}"]
            if tax_shares[i] > 0:
                comment_parts.append(f"${tax_shares[i]:.2f} tax")
            if ship_shares[i] > 0:
                comment_parts.append(f"${ship_shares[i]:.2f} ship")
            comment = f"{name} ({' + '.join(comment_parts)})"
            lines.append(f"    expenses:unknown{' ' * max(1, 36 - len('expenses:unknown'))}${all_in:.2f}  ; {comment}")

        if tax_handling == 'both' and order.tax > 0:
            lines.append(f"    (expenses:tax){' ' * max(1, 36 - len('(expenses:tax)'))}${order.tax:.2f}  ; virtual posting for tax tracking")

    lines.append(f"    {credit_account}{' ' * max(1, 36 - len(credit_account))}$-{order.grand_total:.2f}")
    return '\n'.join(lines)


def find_existing_order_ids(journal_path: str) -> set[str]:
    """Scan a journal file for already-imported Amazon order IDs."""
    ids = set()
    if not Path(journal_path).exists():
        return ids
    pattern = re.compile(r'Order (\d{3}-\d{7}-\d{7})')
    with open(journal_path, encoding='utf-8') as f:
        for line in f:
            m = pattern.search(line)
            if m:
                ids.add(m.group(1))
    return ids


def main():
    parser = argparse.ArgumentParser(description='Convert Amazon CSV to hledger journal')
    parser.add_argument('csv_file', help='Path to amazon-orders.csv')
    parser.add_argument('-o', '--output', help='Output journal file (appends). Omit for stdout.')
    parser.add_argument('--tax-handling', choices=['inclusive', 'separate', 'both'],
                        default='inclusive', help='How to handle tax (default: inclusive)')
    parser.add_argument('--dry-run', action='store_true', help='Print to stdout even if -o is set')
    args = parser.parse_args()

    orders = parse_csv(args.csv_file)

    # Check for existing order IDs to avoid duplicates
    existing_ids: set[str] = set()
    if args.output and not args.dry_run:
        existing_ids = find_existing_order_ids(args.output)

    # Sort by date
    sorted_orders = sorted(orders.values(), key=lambda o: o.date)

    entries = []
    for order in sorted_orders:
        entry = format_order(order, args.tax_handling, existing_ids)
        if entry:
            entries.append(entry)

    if not entries:
        print("No new orders to import.", file=sys.stderr)
        return

    output_text = '\n\n'.join(entries) + '\n'

    if args.dry_run or not args.output:
        print(output_text)
    else:
        with open(args.output, 'a', encoding='utf-8') as f:
            f.write('\n' + output_text)
        print(f"Imported {len(entries)} orders to {args.output}", file=sys.stderr)


if __name__ == '__main__':
    main()
