#!/usr/bin/env python3
"""Tiny smoke test: generate a local RSA key, encrypt, and decrypt."""
import base64, tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import subprocess, sys

with tempfile.TemporaryDirectory() as td:
    d = Path(td)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (d/"key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    pt = b"bcsctf{local_smoke_test}"
    ct = key.public_key().encrypt(pt, padding.PKCS1v15())
    (d/"ct.txt").write_text(base64.b64encode(ct).decode())
    res = subprocess.run([sys.executable, "pemctf.py", "analyze", str(d/"key.pem"),
                          "-c", str(d/"ct.txt"), "-o", str(d/"out.bin")],
                         capture_output=True, text=True)
    print(res.stdout)
    if res.returncode or (d/"out.bin").read_bytes() != pt:
        print(res.stderr)
        raise SystemExit("SMOKE TEST FAILED")
    print("SMOKE TEST PASSED")
