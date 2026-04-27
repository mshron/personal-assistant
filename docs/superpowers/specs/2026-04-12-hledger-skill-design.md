# hledger Skill Design

## Purpose

A nanobot skill that teaches the agent how to manage personal finances using hledger. The skill is shared between nanobot and pi (both running Gemma 4 locally). The agent handles the full lifecycle: importing bank data from SimpleFin Bridge, categorizing transactions using LLM judgment informed by precedent and memory, querying reports, and communicating with the user via Zulip.

## Architecture

### Skill files

```
workspace/skills/hledger/
  SKILL.md                  # Skill definition: hledger CLI reference, journal format,
                            #   workflows, categorization guidance
  scripts/
    find_similar.py         # Lookup tool: find past transactions with similar
                            #   descriptions, return matches with their accounts
```

### External dependencies (already added to Dockerfiles)

- `hledger` binary (v1.42, standalone install in agent container)

### Host-side dependencies (user's machine, not in container)

- hledger's SimpleFin scripts: `simplefinjson` (Bash), `simplefincsv` (Python 3) -- fetched from the hledger repo
- `launchd` plist for daily scheduling (macOS native)

### Data location

All journal data lives in `/workspace` (mounted from `~/finance` on the host). The skill documents a recommended directory structure but does not enforce it -- the user or pi may set up the structure independently.

Recommended layout:
```
/workspace/
  main.journal              # Top-level file with include directives
  accounts.journal          # Chart of accounts
  YYYY/
    YYYY-MM.journal         # Monthly transaction journals
  import/
    simplefin/
      rules/                # hledger CSV rules files (one per account)
      csv/                  # Raw CSV from simplefincsv (archived)
```

## Workflows

### 1. Daily import (SimpleFin Bridge)

The SimpleFin pull runs outside the agent as a macOS `launchd` job on the user's machine. This keeps the deterministic fetch separate from the LLM-driven categorization work.

**launchd job** (lives in `~/finance/`, written to `/tmp` for the user to install):
- Runs daily via launchd (fires on wake if the machine was asleep at scheduled time)
- Executes `simplefinjson | simplefincsv` and writes output to `~/finance/import/simplefin/incoming/YYYY-MM-DD.csv`
- The SimpleFin access URL is read from an env var or file in `~/finance/` (never touches the agent container)
- hledger's `simplefinjson` fetches a 30-day rolling window; dedup at import time makes overlap harmless

**Agent reacts to new files:**
- On startup or daily run, the agent checks `/workspace/import/simplefin/incoming/` for unprocessed CSV files
- Runs `hledger import` with `.rules` files to ingest new transactions, deduplicating against existing journal
- Moves processed files to `/workspace/import/simplefin/csv/` for archival
- New transactions land with `expenses:unknown` or `income:unknown` as the unclassified account (configurable in rules files)

This approach keeps SimpleFin credentials entirely off the agent container -- no credential proxy route needed.

### 2. PDF statement import

For statements and invoices arriving as PDFs:

1. Agent uses its pdf skill to extract transaction data (dates, amounts, descriptions)
2. Agent writes journal entries directly in hledger format
3. No custom script needed -- the agent knows journal format from the skill

### 3. Manual transaction entry via Zulip

The user sends cash transactions (and other items not captured by SimpleFin) to Zulip. The agent parses the message, creates a journal entry, and categorizes it using the same LLM-driven process as imported transactions. Examples of user messages:

- "Spent $15 cash at the farmer's market"
- "Paid the dog walker $40 cash"
- "Got $20 back from Jake for dinner"

The agent extracts date (defaults to today), amount, payee/description, and uses its judgment + precedent to assign an account. If unclear, it asks in-thread.

### 4. Other recurring imports

Beyond SimpleFin, the user will have monthly transaction data arriving from other sources (investment accounts, etc.). The skill teaches the agent how to handle arbitrary structured data (CSV, JSON, PDF statements) and convert it to journal entries. The import workflow is the same: parse the data, write journal entries, categorize, post to Zulip. Specific connectors are outside skill scope -- the skill covers the hledger side of ingestion.

### 5. LLM-driven categorization (applies to all sources)

This is the core value of the skill. The agent categorizes transactions using judgment, not rules:

1. **Find uncategorized**: `hledger register expenses:unknown income:unknown` to list transactions needing attention
2. **Look up precedent**: For each transaction, call `find_similar.py` with the payee/description. The script searches the journal for transactions with similar descriptions and returns the top matches with their assigned accounts.
3. **Agent decides**: Using precedent from the similarity script, its nanobot memory (which accumulates context about the user's life, habits, subscriptions), and its own reasoning, the agent assigns an account category.
4. **Agent edits the journal**: Replaces `expenses:unknown` with the chosen account in the journal file.
5. **Flag uncertainty**: If the agent isn't confident, it holds the transaction for the daily digest (see Zulip behavior below).

The skill instructs the agent to reason about categorization rather than just pattern-match. Examples of judgment calls:
- "This $12.99 charge to 'NFLX' matches 5 past transactions all categorized as `expenses:subscriptions:netflix`" -- high confidence, categorize directly
- "This $47.00 charge to 'WHOLEFDS MKT' could be groceries or it could be a gift card purchase" -- check memory for context, or flag if unclear
- "This is a new payee I've never seen" -- flag for user input, learn from the response

### 6. Zulip communication

Two posting patterns:

**Every transaction** (passive visibility): After import and categorization, the agent posts each transaction to Zulip. This gives the user a passive feed to notice unexpected charges, forgotten subscriptions, or miscategorizations. Format should be concise -- one line per transaction with date, payee, amount, and assigned category.

**Daily digest of uncertain items**: Transactions the agent couldn't confidently categorize get batched into a single Zulip message at the end of the daily run. The digest presents each uncertain transaction with the agent's best guesses and asks the user to confirm or correct. The user can reply (e.g. via Wispr voice) and the agent processes the response.

### 7. Query and reporting

The skill teaches standard hledger CLI usage for ad-hoc queries:

- `hledger balancesheet` -- assets and liabilities
- `hledger incomestatement` -- income and expenses for a period
- `hledger register ACCOUNT` -- transaction history for an account
- `hledger balance expenses --tree -M` -- monthly expense breakdown
- `hledger accounts` -- list all accounts in the chart

## find_similar.py script

**Input**: A description/payee string and path to the journal file (or directory)
**Output**: JSON array of the top N most similar past transactions, each with: date, description, amount, account assigned

Matching approach: normalized string similarity (lowercase, strip common suffixes like store numbers, fuzzy match). This is a lookup tool -- it returns candidates, it does not make categorization decisions.

```
python scripts/find_similar.py "WHOLEFDS MKT 10432" /workspace/main.journal --top 5
```

Returns:
```json
[
  {"date": "2026-03-15", "description": "WHOLEFDS MKT 10432", "amount": "-52.30", "account": "expenses:groceries"},
  {"date": "2026-02-28", "description": "WHOLE FOODS MARKET", "amount": "-31.17", "account": "expenses:groceries"}
]
```

## What the skill does NOT cover

- **SimpleFin fetching**: Handled by a launchd job on the host machine, not by the agent. The skill teaches the agent to react to new files, not to pull data.
- **SimpleFin setup**: The access URL is already configured on the host. The agent never sees it.
- **Chart of accounts design**: The skill documents hledger's account hierarchy conventions but doesn't prescribe a specific chart. The user or pi will set this up.
- **Investment tracking**: Future work. The user mentioned investment connectors that don't work well with SimpleFin -- these will be separate integrations.

## Testing plan

1. Verify `hledger` binary works in container: `hledger --version`
2. Create a sample journal with known transactions, run `find_similar.py` against it, verify matches
3. End-to-end: create a small journal, drop a CSV in `incoming/`, run the import + categorization workflow manually, verify the journal is updated correctly
4. Verify hledger CLI queries work against the sample journal
5. Verify launchd plist loads and fires correctly on the host (user tests after moving from `/tmp`)
