# Personal Agent Backlog

Ideas and improvements discussed during development, not yet implemented.

---

## Cost optimization

### Route memory consolidation to Haiku
Nanobot's memory consolidation fires ~2 LLM calls per user exchange, using the main Sonnet model. These calls are identifiable in our `InstrumentedProvider` wrapper (system message contains "memory consolidation agent", no tools passed). Rerouting them to Haiku ($0.80/$4 per M tokens vs $3/$15) would cut API costs by ~$300/month at 500 messages/day.

**Approach:** Add model override in `InstrumentedProvider.chat()` — detect consolidation calls by system prompt content, swap `model` kwarg to `anthropic/claude-haiku-4-5-20241022`. No nanobot changes needed.

### Prompt caching
Anthropic supports caching repeated message prefixes at 90% discount ($0.30/M vs $3/M input). The system prompt + tool definitions (~2K tokens) are sent on every call. At high volume this adds up. Requires adding `cache_control` headers — would need to patch how LiteLLM constructs requests, possibly via our provider wrapper.

### Disable memory consolidation entirely
Nuclear option. Drops from ~3 LLM calls per exchange to 1, cutting API cost by ~60%. Conversation history stays in JSONL sessions. Loses auto-summarization into MEMORY.md/HISTORY.md. Configurable via Nanobot's `memory_window` setting (set very high to effectively disable).

---

### Tokenizer for Mac deployment
When deploying the agent on a Mac (not Fly.io), set up Fly's [Tokenizer](https://github.com/superfly/tokenizer) or equivalent to keep the Anthropic API key out of plaintext environment variables. The Fly deployment currently uses `ANTHROPIC_API_KEY` directly as a secret; the tokenizer sealed-secret path (`TOKENIZED_ANTHROPIC`) is still supported in `main.py` but the tokenizer binary was removed from the Docker build.

---

## Security hardening

### Egress restriction
Lock down outbound network from the Fly machine. Currently the agent can make arbitrary HTTP requests. Restrict to known hosts (api.anthropic.com, api.groq.com, etc.) via Fly firewall rules or iptables in the container. Noted in Gemini review as future hardening.

### Image-based prompt injection
PromptGuard only scans text. Prompt injections embedded in images (text overlaid on photos) bypass it entirely. Options: OCR images and scan extracted text, or rely on Claude's built-in resistance. Low priority unless the agent starts processing image-heavy content.

### User intent tracking for multi-turn conversations
Action Review needs the user's original intent. Currently `GuardedToolRegistry.user_intent` is set once at construction. For multi-turn conversations, it should update with each new user message. Requires hooking into message processing to capture the latest user message and pass it to the wrapper.

---

## Features

### ~~Zulip channel integration~~ (DONE)
Implemented and deployed. `ZulipChannel(BaseChannel)` supports both DMs and stream messages.

### Brave Search API key
Nanobot's `web_search` tool uses the Brave Search API. Without a key, the agent can fetch specific URLs but cannot do open-ended web searches. Add `BRAVE_API_KEY` to the environment.

### CI/CD pipeline
Set up GitHub Actions (or similar) to run tests and deploy to Fly.io on push to main. Discussed early in planning but deferred.

---

## Reliability

### Litestream replication
If conversation history becomes critical, add Litestream-to-R2 (or S3) replication for the JSONL session files. Currently relying on Fly's daily volume snapshots (5-day retention). Low priority for a personal agent on a 2-3 month Fly stint.

### PromptGuard model stability
Groq's `meta-llama/llama-prompt-guard-2-86m` is labeled "Preview" — could be discontinued. Have a fallback plan: local inference, alternative hosted model, or skip Layer 1 and rely on Action Review as the sole guardrail.

### Groq rate limits
Free tier is 30 RPM. Sufficient for personal use but could be hit with heavy email volumes or rapid tool use. Monitor and upgrade to paid tier if needed.

---

## Observability

### Log analysis tooling
The append-only JSONL log captures everything now, but there's no tooling to query it. Consider a simple CLI script or web UI to filter/search logs by event type, time range, tool name, etc.

### Alerting on blocked actions
When PromptGuard or Action Review blocks something, it's logged but nobody is notified. Add a webhook or Zulip notification for blocked events so the user knows when the guardrails fire.
