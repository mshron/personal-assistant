---
name: agent-browser
description: Browser automation CLI for AI agents. Use when you need to interact with websites, fill forms, click buttons, or verify page content.
metadata: {"nanobot": {"requires": {"bins": ["agent-browser"]}}}
---

# Browser Automation with agent-browser

CLI tool for headless browser automation via Chrome/Chromium CDP. Use `exec` to run commands.

## Core Workflow

1. **Navigate**: `agent-browser open <url>`
2. **Snapshot**: `agent-browser snapshot -i` (get element refs like `@e1`, `@e2`)
3. **Interact**: Use refs to click, fill, select
4. **Re-snapshot**: After navigation or DOM changes, get fresh refs

```bash
agent-browser open https://example.com/form
agent-browser snapshot -i
# Output: @e1 [input type="email"], @e2 [button] "Submit"

agent-browser fill @e1 "user@example.com"
agent-browser click @e2
agent-browser wait --load networkidle
agent-browser snapshot -i  # Check result
```

## Command Chaining

Chain commands with `&&` when you don't need intermediate output:

```bash
agent-browser open https://example.com && agent-browser wait --load networkidle && agent-browser snapshot -i
```

Run separately when you need to read output first (e.g., snapshot to discover refs).

## Essential Commands

```bash
# Navigation
agent-browser open <url>              # Navigate to URL
agent-browser close                   # Close browser

# Snapshot (ALWAYS use -i for interactive elements)
agent-browser snapshot -i             # Interactive elements with refs
agent-browser snapshot -s "#selector" # Scope to CSS selector

# Interaction (use @refs from snapshot)
agent-browser click @e1               # Click element
agent-browser fill @e2 "text"         # Clear and type text
agent-browser select @e1 "option"     # Select dropdown option
agent-browser check @e1               # Check checkbox
agent-browser press Enter             # Press key
agent-browser scroll down 500         # Scroll page

# Get information
agent-browser get text @e1            # Get element text
agent-browser get url                 # Get current URL
agent-browser get title               # Get page title

# Wait
agent-browser wait @e1                # Wait for element
agent-browser wait --load networkidle # Wait for network idle
agent-browser wait --url "**/page"    # Wait for URL pattern
agent-browser wait --text "Welcome"   # Wait for text to appear
agent-browser wait 2000               # Wait milliseconds

# Capture
agent-browser screenshot              # Screenshot to temp dir
agent-browser screenshot --full       # Full page screenshot
```

## Ref Lifecycle

Refs (`@e1`, `@e2`) are invalidated when the page changes. ALWAYS re-snapshot after:
- Clicking links or buttons that navigate
- Form submissions
- Dynamic content loading (dropdowns, modals)

## Form Submission Pattern

```bash
agent-browser open https://example.com/form
agent-browser snapshot -i
agent-browser fill @e1 "Jane Doe"
agent-browser fill @e2 "jane@example.com"
agent-browser select @e3 "California"
agent-browser click @e5
agent-browser wait --load networkidle
agent-browser snapshot -i  # Verify result
```

## Timeouts

Default timeout is 25 seconds. For slow pages, use explicit waits:

```bash
agent-browser wait --load networkidle  # Wait for network to settle
agent-browser wait "#content"          # Wait for specific element
agent-browser wait --fn "document.readyState === 'complete'"
```

## Security

Use `--content-boundaries` to wrap page output with markers that distinguish tool output from untrusted page content:

```bash
AGENT_BROWSER_CONTENT_BOUNDARIES=1 agent-browser snapshot -i
```
