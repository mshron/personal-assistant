#!/bin/bash
set -euo pipefail

# Starts llama-server with the local Qwen3.6-35B-A3B model.
# API key is read from .env to avoid hardcoding secrets.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="$SCRIPT_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: $ENV_FILE not found." >&2
    exit 1
fi

API_KEY=$(grep -E '^LOCAL_LLM_API_KEY=' "$ENV_FILE" | cut -d= -f2- | tr -d '"'"'" || true)
if [ -z "$API_KEY" ]; then
    echo "Error: LOCAL_LLM_API_KEY not found in $ENV_FILE" >&2
    exit 1
fi

# Resolve the GGUF inside the HuggingFace snapshot dir (single snapshot per download).
MODEL=$(ls "$HOME/.cache/huggingface/hub/models--unsloth--Qwen3.6-35B-A3B-GGUF/snapshots/"*/Qwen3.6-35B-A3B-UD-IQ4_XS.gguf 2>/dev/null | head -1 || true)
if [ -z "$MODEL" ]; then
    echo "Error: Qwen3.6 GGUF not found under HF cache. Download with:" >&2
    echo "  uvx --from 'huggingface_hub[cli]' hf download unsloth/Qwen3.6-35B-A3B-GGUF Qwen3.6-35B-A3B-UD-IQ4_XS.gguf" >&2
    exit 1
fi

# --alias accepts comma-separated names; keeping the legacy gemma name allows
# clients with LOCAL_LLM_MODEL=gemma-4-26b-a4b-it to keep working through the
# transition.
exec "$HOME/code/llama.cpp/build/bin/llama-server" \
    --model "$MODEL" \
    --alias "qwen3.6-35b-a3b-thinking,gemma-4-26b-a4b-it" \
    --jinja \
    --reasoning-format deepseek \
    --host 0.0.0.0 \
    --ctx-size 65536 \
    --cache-type-k q8_0 \
    --cache-type-v q8_0 \
    --temp 0.7 \
    --top-p 0.95 \
    --top-k 20 \
    --min-p 0.0 \
    --presence-penalty 1.5 \
    --api-key "$API_KEY"
