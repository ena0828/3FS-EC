#!/usr/bin/env python3
"""Verify the pinned libfuse archive and its upstream signify signature."""
import argparse
import base64
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
args = parser.parse_args()
root = args.directory
payload = (root / "fuse-3.16.2.tar.gz").read_bytes()
expected = "f797055d9296b275e981f5f62d4e32e089614fc253d1ef2985851025b8a0ce87"
if hashlib.sha256(payload).hexdigest() != expected:
    raise SystemExit("release archive SHA-256 mismatch")
public = (root / "fuse-3.16.pub").read_bytes()
if hashlib.sha256(public).hexdigest() != "c650ae9728ef491c21cbab70cde169fb91221fcc0a8e1e39e3db19df2179c22c":
    raise SystemExit("pinned public key SHA-256 mismatch")
key = base64.b64decode(public.splitlines()[1], validate=True)
signature = base64.b64decode((root / "fuse-3.16.2.tar.gz.sig").read_bytes().splitlines()[1], validate=True)
if len(key) != 42 or len(signature) != 74 or key[:2] != b"Ed" or signature[:2] != b"Ed":
    raise SystemExit("unexpected signify record format")
if key[2:10] != signature[2:10]:
    raise SystemExit("signify key identifier mismatch")
Ed25519PublicKey.from_public_bytes(key[10:]).verify(signature[10:], payload)
print("PASS: pinned archive, public key and upstream Ed25519 signature")
