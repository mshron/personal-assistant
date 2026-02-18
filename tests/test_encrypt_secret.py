import base64
import json

from nacl.public import PrivateKey, SealedBox


def test_seal_and_unseal_secret():
    """Verify we can encrypt a secret and decrypt it (simulating Tokenizer)."""
    priv = PrivateKey.generate()
    pub = priv.public_key

    secret = {
        "inject_processor": {"token": "sk-test-key", "dst": "x-api-key", "fmt": "%s"},
        "no_auth": True,
        "allowed_hosts": ["api.anthropic.com"],
    }

    # Encrypt (what our script does)
    box = SealedBox(pub)
    sealed = box.encrypt(json.dumps(secret).encode())
    sealed_b64 = base64.b64encode(sealed).decode()

    # Decrypt (what Tokenizer does)
    open_box = SealedBox(priv)
    plaintext = open_box.decrypt(base64.b64decode(sealed_b64))
    recovered = json.loads(plaintext)

    assert recovered["inject_processor"]["token"] == "sk-test-key"
    assert recovered["allowed_hosts"] == ["api.anthropic.com"]


def test_sealed_secret_is_different_each_time():
    """Sealed boxes use ephemeral keys, so same plaintext gives different ciphertext."""
    priv = PrivateKey.generate()
    pub = priv.public_key
    box = SealedBox(pub)
    plaintext = b'{"token": "test"}'
    sealed1 = base64.b64encode(box.encrypt(plaintext)).decode()
    sealed2 = base64.b64encode(box.encrypt(plaintext)).decode()
    assert sealed1 != sealed2


def test_encrypt_secret_script():
    """Test the encrypt_secret function from our script."""
    from tokenizer.encrypt_secret import encrypt_secret

    priv = PrivateKey.generate()
    seal_key_hex = priv.public_key.encode().hex()

    sealed_b64 = encrypt_secret(
        seal_key_hex=seal_key_hex,
        token="sk-ant-test",
        allowed_hosts=["api.anthropic.com"],
        dst="x-api-key",
        fmt="%s",
    )

    # Decrypt and verify
    open_box = SealedBox(priv)
    plaintext = open_box.decrypt(base64.b64decode(sealed_b64))
    recovered = json.loads(plaintext)
    assert recovered["inject_processor"]["token"] == "sk-ant-test"
    assert recovered["inject_processor"]["dst"] == "x-api-key"
    assert recovered["no_auth"] is True


def test_generate_keypair():
    """Test keypair generation helper."""
    from tokenizer.encrypt_secret import generate_keypair

    open_key_hex, seal_key_hex = generate_keypair()
    assert len(open_key_hex) == 64  # 32 bytes hex-encoded
    assert len(seal_key_hex) == 64

    # Verify they're a valid pair: encrypt with seal, decrypt with open
    from nacl.public import PublicKey
    pub = PublicKey(bytes.fromhex(seal_key_hex))
    priv = PrivateKey(bytes.fromhex(open_key_hex))
    box = SealedBox(pub)
    sealed = box.encrypt(b"test")
    assert SealedBox(priv).decrypt(sealed) == b"test"
