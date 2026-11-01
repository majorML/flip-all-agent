#!/usr/bin/env python3
"""Generate a standalone Ed25519 keypair and DID for Flip all."""
import os
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key_path = Path(__file__).parent / "identity.pem"

if not key_path.exists():
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    print(f"Generated fresh standalone key at {key_path}")
else:
    pem = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(pem, password=None)
    print(f"Loaded existing key from {key_path}")

# Derive raw public bytes and multicodec did:key
pub_bytes = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)
# Ed25519 multicodec prefix: 0xed01
import base58
did = "did:key:z" + base58.b58encode(b"\xed\x01" + pub_bytes).decode("ascii")
print(f"DID: {did}")

(Path(__file__).parent / "did.txt").write_text(did)
