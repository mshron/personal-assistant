---
name: hledger
description: "Use this skill for anything related to personal finance, accounting, bookkeeping, or transaction management. This includes: processing new bank transactions, categorizing expenses or income, querying balances and reports, importing CSV or PDF statements, adding manual transactions (e.g. cash spending reported via Zulip), reviewing uncategorized transactions, generating financial summaries, and working with hledger journal files. Trigger whenever the user mentions money, spending, accounts, budgets, transactions, or references files in /workspace."
metadata: {"nanobot": {"requires": {"bins": ["hledger"]}}}
---

# hledger Personal Finance Skill

Manage personal finances using hledger plain-text accounting. You have full read-write access to the journal files in `/workspace`.

## Journal format quick reference

```journal
; A transaction (two or more postings that balance to zero)
2026-04-12 Whole Foods Market
    expenses:groceries          $52.30
    assets:checking

; Income
2026-04-12 Employer Inc | March salary
    assets:checking           $5000.00
    income:salary

; Use ! for pending (uncleared) transactions
2026-04-12 ! Amazon
    expenses:unknown           $29.99
    assets:checking
```

Key rules:
- First line: date, optional status (`*` cleared, `!` pending), payee, optional `|` and note
- Indented postings below, at least 2 spaces indent
- At least two postings per transaction; one amount can be omitted (auto-balanced)
- Account names are colon-separated hierarchies: `expenses:groceries`, `assets:checking`
- Amounts use `$` prefix for USD: `$52.30`, `-$52.30`

## Account structure notes

Most accounts are straightforward (`assets:checking`, `liabilities:credit-card:visa-5071`), but some need special handling:

**Brokerage account (used as checking):** One brokerage account appears in SimpleFin with both cash and holdings. Split it:
```
assets:brokerage:cash          ; cash sweep — daily transactions land here
assets:brokerage:etf:VTI       ; holdings by ticker (updated from statements)
assets:brokerage:etf:BND
```

Daily SimpleFin transactions include both cash activity AND investment transactions (buys, sells, dividends). When the brokerage auto-sells ETFs to cover spending, categorize as an internal transfer, NOT income:
```journal
2026-04-14 Auto-sell VTI
    assets:brokerage:cash           $500.00
    assets:brokerage:etf:VTI       $-500.00

2026-04-14 Buy VTI
    assets:brokerage:etf:VTI        $1000.00
    assets:brokerage:cash           $-1000.00

2026-04-14 Dividend | VTI
    assets:brokerage:cash             $12.50
    income:dividends:VTI
```

Some brokerage accounts are NOT covered by SimpleFin -- those will be imported separately via other connectors or PDF statements (for historical data). The same account structure applies regardless of the source.

## Directory structure

```
/workspace/
  main.journal              # Top-level file with include directives
  accounts.journal          # Chart of accounts (account directives)
  YYYY/
    YYYY-MM.journal         # Monthly transaction journals
  import/
    simplefin/
      incoming/             # New CSVs from launchd job (unprocessed)
      csv/                  # Archived CSVs (already imported)
      rules/                # hledger CSV rules files (one per account)
```

If this structure doesn't exist yet, create it. The `main.journal` should include the other files:

```journal
; main.journal
include accounts.journal
include 2026/*.journal
```

## Workflow 1: Process new SimpleFin imports

New CSV files land in `/workspace/import/simplefin/incoming/` from a launchd job on the host. Check for them on startup or when asked.

```bash
# List unprocessed files
ls /workspace/import/simplefin/incoming/

# Import a CSV (deduplicates automatically)
hledger import /workspace/import/simplefin/incoming/2026-04-12.csv --rules-file /workspace/import/simplefin/rules/checking.rules

# Archive after successful import
mv /workspace/import/simplefin/incoming/2026-04-12.csv /workspace/import/simplefin/csv/
```

After import, proceed to categorization (Workflow 6).

## Workflow 2: Import from PDF statements

Use your pdf skill to extract transaction data from PDF statements, then write journal entries directly.

1. Read the PDF and extract: dates, descriptions/payees, amounts
2. Determine which account the statement belongs to (e.g. `assets:checking`, `liabilities:credit-card`)
3. Write transactions in journal format to the appropriate monthly file
4. Proceed to categorization (Workflow 6)

## Workflow 3: Manual transaction entry from Zulip

When the user reports a cash transaction or other manual entry via Zulip:

1. Parse the message for: amount, payee/description, date (default: today)
2. Determine the source account (usually `assets:cash` for cash transactions)
3. Look up similar past transactions for categorization (see Workflow 6)
4. Write the transaction to the current month's journal file
5. Post confirmation to Zulip with the categorized entry

Examples of user messages and how to parse them:
- "Spent $15 at the farmer's market" -> $15, farmer's market, today, assets:cash
- "Paid the dog walker $40 cash" -> $40, dog walker, today, assets:cash
- "Got $20 back from Jake for dinner" -> -$20 (income/reimbursement), Jake, today, assets:cash

## Workflow 4: Amazon order import

A browser extension scrapes Amazon order history daily and exports `amazon-orders.csv` to a known location. The CSV is denormalized — one row per item, with order-level fields (date, order ID, shipping, tax, grand total, payment method) repeated on every row.

**CSV format:**
```csv
date,order_id,item,seller,item_price,subtotal,shipping,shipping_discount,tax,grand_total,payment_method
2026-04-11,114-4009184-6792248,"Olive Oil, 2L",California Olive Ranch,54.99,100.96,2.99,-2.99,3.21,104.17,Visa ****5071
```

**Import workflow:**

1. Check for new/updated `amazon-orders.csv` in `/workspace/import/amazon/incoming/`
2. Run the conversion script to produce multi-posting hledger transactions grouped by order:
   ```bash
   python /workspace/skills/hledger/scripts/amazon_import.py \
     /workspace/import/amazon/incoming/amazon-orders.csv \
     -o /workspace/2026/2026-04.journal \
     --tax-handling inclusive
   ```
3. The script groups rows by `order_id` and produces one transaction per order:
   ```journal
   2026-04-11 Amazon.com | Order 114-4009184-6792248
       expenses:unknown                     $56.74  ; CA Olive Ranch Olive Oil ($54.99 + $1.75 tax)
       expenses:unknown                     $20.63  ; Mixed Chicks Conditioner ($19.99 + $0.64 tax)
       expenses:unknown                     $16.50  ; BeeGreen Kids Apron ($15.99 + $0.51 tax)
       expenses:unknown                     $10.30  ; S Hooks 12 Pack ($9.99 + $0.31 tax)
       liabilities:credit-card:visa-5071  $-104.17
   ```
4. Tax and shipping are pro-rated across items proportional to price (comments preserve the breakdown)
5. The `payment_method` field maps to a liability account automatically (e.g. `Visa ****5071` -> `liabilities:credit-card:visa-5071`)
6. The script deduplicates by order ID — re-running on an updated CSV won't create duplicate transactions
7. Archive the CSV: `mv /workspace/import/amazon/incoming/amazon-orders.csv /workspace/import/amazon/csv/`
8. Proceed to categorization (Workflow 6) — Amazon items arrive as `expenses:unknown` and need per-item categorization

**Tax handling modes** (set via `--tax-handling`):
- `inclusive` (default): tax pro-rated into each item posting — shows true all-in cost per category
- `separate`: tax kept as its own `expenses:tax` posting
- `both`: pro-rated into items AND a virtual `(expenses:tax)` posting for querying total tax

**Categorizing Amazon items:**

Amazon items are categorized the same way as any other transaction (Workflow 6), but the item descriptions from invoices are usually clear product names (not cryptic bank codes), so precedent matching and your own judgment should handle most of them well. When categorizing, consider the item name in the comment, not just the payee ("Amazon.com").

## Workflow 5: Other recurring imports

For monthly data from investment accounts or other sources (CSV, JSON, PDF):

1. Parse the data into transactions (dates, amounts, descriptions)
2. Write journal entries to the appropriate monthly file
3. Proceed to categorization (Workflow 6)

## Workflow 6: Categorize transactions

This is your core task. You categorize transactions using your judgment, not mechanical rules.

### Step 1: Find uncategorized transactions

```bash
hledger register expenses:unknown income:unknown -f /workspace/main.journal
```

### Step 2: Look up precedent for each transaction

```bash
python /workspace/skills/hledger/scripts/find_similar.py "WHOLEFDS MKT 10432" /workspace/main.journal --top 5
```

This returns past transactions with similar descriptions and their assigned accounts. Use this as your primary signal.

### Step 2b: Decode cryptic transaction descriptions

Bank transaction descriptions are often abbreviated or prefixed by payment processors. Before categorizing, decode the description:

**Common payment processor prefixes** (strip these to get the merchant name):

| Prefix | Processor |
|--------|-----------|
| `SQ *` | Square |
| `TST*` | Toast POS |
| `SP *` | Shopify |
| `PAYPAL *` | PayPal |
| `PP*` | PayPal / ProPay |
| `VENMO *` | Venmo |
| `AMZN MKTP US` | Amazon Marketplace |
| `AMZ*` | Amazon |
| `APPLE.COM/BILL` | Apple subscriptions |
| `APL*APPLE` | Apple |
| `GOOGLE *` | Google services |
| `MSFT *` | Microsoft |
| `CKO*` | Checkout.com |
| `STRIPE*` | Stripe |
| `CASH APP*` | Cash App |
| `DD *` | DoorDash |
| `KLARNA*` | Klarna (BNPL) |
| `AFTERPAY` | Afterpay (BNPL) |
| `SQSP*` | Squarespace |

If the description is still unclear after stripping prefixes, use **Brave web search** to look up the merchant:

```
Search: "what is [DESCRIPTOR] bank statement charge"
```

For example: `what is "CKO* ACME" bank statement charge`. This usually surfaces community sites that decode cryptic bank descriptors. Use this when the payee name is opaque and neither the prefix table nor find_similar.py clarifies it.

### Step 3: Decide on a category

Use these sources of information, in order of priority:
1. **Precedent**: How were similar transactions categorized before? If 5 past "WHOLEFDS MKT" transactions are all `expenses:groceries`, this one probably is too.
2. **Your memory**: Do you know anything about the user's context that's relevant? New subscriptions mentioned, lifestyle changes, etc.
3. **Merchant lookup**: What did the prefix table or a web search reveal about the merchant?
4. **Reasoning**: What does the payee name suggest? What's a reasonable category?

### Step 4: Edit the journal

Replace `expenses:unknown` with the chosen account in the journal file. Change `!` (pending) to `*` (cleared) if you're confident.

### Step 5: Handle uncertainty

If you're not confident about a categorization:
- Keep the transaction as `expenses:unknown` with `!` status
- Add it to the daily digest for user review (see Workflow 7)
- Include your best guesses so the user can pick quickly

Reasons to be uncertain:
- New payee never seen before with an ambiguous name
- Transaction could plausibly be multiple categories (e.g. a store that sells both groceries and household items)
- Unusual amount for a known payee

## Workflow 7: Zulip communication

### Post every transaction (passive feed)

After importing and categorizing, post all transactions to Zulip. One line per transaction, concise format:

```
Apr 12: Whole Foods Market — $52.30 -> expenses:groceries
Apr 12: Netflix — $15.49 -> expenses:subscriptions:netflix
Apr 12: Unknown Store — $29.99 -> expenses:unknown (uncertain)
```

This gives the user passive visibility into spending and helps catch forgotten subscriptions or miscategorizations.

### Daily digest of uncertain items

Batch all uncertain transactions into a single message:

```
I categorized 12 transactions today. 3 need your input:

1. Apr 12: AMZN MKTP US — $29.99 (could be expenses:shopping or expenses:household)
2. Apr 11: SQ *COFFEE — $8.50 (new payee, guessing expenses:food:coffee?)
3. Apr 11: VENMO — $150.00 (transfer? expense? need context)

Reply with corrections like "1: shopping, 2: yes, 3: transfer to Jake for rent"
```

Process the user's reply and update the journal accordingly.

## Common hledger commands

```bash
# Reports
hledger balancesheet -f /workspace/main.journal          # Assets and liabilities
hledger incomestatement -f /workspace/main.journal       # Income and expenses
hledger balance expenses --tree -M -f /workspace/main.journal  # Monthly expense breakdown

# Transaction queries
hledger register ACCOUNT -f /workspace/main.journal      # History for one account
hledger register desc:amazon -f /workspace/main.journal  # Search by description
hledger register date:2026-04 -f /workspace/main.journal # Filter by date

# Account management
hledger accounts -f /workspace/main.journal              # List all accounts
hledger accounts expenses -f /workspace/main.journal     # List expense accounts

# Checking for problems
hledger check -f /workspace/main.journal                 # Validate journal
hledger register expenses:unknown -f /workspace/main.journal  # Find uncategorized
```

## CSV rules files

For SimpleFin CSV imports, each bank account needs a `.rules` file in `/workspace/import/simplefin/rules/`. Example:

```rules
# checking.rules
skip 1
fields date, amount, payee, description, memo, id

account1 assets:checking
account2 expenses:unknown

# Date format from simplefincsv
date-format %Y-%m-%d

# Dedup by SimpleFin transaction ID
if %id
 comment  simplefin-id:%id
```

## Version control

The `/workspace` directory is a git repository. Commit after every batch of changes.

### After importing and categorizing

```bash
cd /workspace
git add -A
git commit -m "Import and categorize transactions for YYYY-MM-DD"
```

### After processing user corrections from Zulip

```bash
cd /workspace
git add -A
git commit -m "Apply user corrections for YYYY-MM-DD"
```

### Before making bulk changes (account renames, restructuring)

```bash
cd /workspace
git status  # Make sure working tree is clean first
```

### If something goes wrong

```bash
# See what changed
git log --oneline -10
git diff HEAD~1

# Undo the last commit (keeps changes as uncommitted)
git reset HEAD~1
```

### Coordination with other agents

If another agent (e.g. pi) also writes to `/workspace`, use a lockfile to avoid conflicts:

```bash
# Before writing
if [ -f /workspace/.lock ]; then echo "LOCKED"; exit 1; fi
touch /workspace/.lock

# After committing
rm /workspace/.lock
```

Wait and retry if the lockfile exists. Do not force past it.

## Important rules

- ALWAYS use `hledger check` after editing journal files to validate them
- ALWAYS commit after a batch of changes — never leave uncommitted edits
- NEVER delete transactions — if something is wrong, add a correcting entry
- Use `!` for pending/uncertain and `*` for cleared/confident
- When in doubt about a category, leave as `expenses:unknown` and ask the user
- Post ALL transactions to Zulip, not just uncertain ones
