"""Encrypt secrets for use with Fly Tokenizer.

Usage:
    python -m tokenizer.encrypt_secret --seal-key <hex> --token <api-key> --host <host> [--dst <header>]

Examples:
    # Anthropic (uses x-api-key header):
    python -m tokenizer.encrypt_secret \\
        --seal-key a29dcbaa... \\
        --token sk-ant-api03-... \\
        --host api.anthropic.com \\
        --dst x-api-key --fmt '%s'

    # Groq (uses Authorization: Bearer):
    python -m tokenizer.encrypt_secret \\
        --seal-key a29dcbaa... \\
        --token gsk_... \\
        --host api.groq.com

    # Generate a new keypair:
    python -m tokenizer.encrypt_secret --generate-keypair
"""

import argparse
import base64
import json

from nacl.public import PrivateKey, PublicKey, SealedBox


def generate_keypair() -> tuple[str, str]:
    """Generate a Curve25519 keypair. Returns (open_key_hex, seal_key_hex)."""
    priv = PrivateKey.generate()
    open_key_hex = priv.encode().hex()
    seal_key_hex = priv.public_key.encode().hex()
    return open_key_hex, seal_key_hex


def encrypt_secret(
    seal_key_hex: str,
    token: str,
    allowed_hosts: list[str],
    dst: str = "Authorization",
    fmt: str = "Bearer %s",
) -> str:
    """Encrypt a secret for Tokenizer. Returns base64-encoded sealed secret."""
    pub = PublicKey(bytes.fromhex(seal_key_hex))
    secret = {
        "inject_processor": {"token": token, "dst": dst, "fmt": fmt},
        "no_auth": True,
        "allowed_hosts": allowed_hosts,
    }
    box = SealedBox(pub)
    sealed = box.encrypt(json.dumps(secret).encode())
    return base64.b64encode(sealed).decode()


def main():
    parser = argparse.ArgumentParser(description="Encrypt a secret for Fly Tokenizer")
    parser.add_argument("--seal-key", help="Hex-encoded Tokenizer public key")
    parser.add_argument("--token", help="The API key/token to encrypt")
    parser.add_argument("--host", action="append", help="Allowed destination host(s)")
    parser.add_argument("--dst", default="Authorization", help="Destination header (default: Authorization)")
    parser.add_argument("--fmt", default="Bearer %s", help="Header format string (default: 'Bearer %%s')")
    parser.add_argument("--generate-keypair", action="store_true", help="Generate a new keypair and exit")
    args = parser.parse_args()

    if args.generate_keypair:
        open_key, seal_key = generate_keypair()
        print(f"OPEN_KEY={open_key}")
        print(f"SEAL_KEY={seal_key}")
        return

    if not args.seal_key or not args.token or not args.host:
        parser.error("--seal-key, --token, and --host are required (unless --generate-keypair)")

    sealed = encrypt_secret(args.seal_key, args.token, args.host, args.dst, args.fmt)
    print(sealed)


if __name__ == "__main__":
    main()
