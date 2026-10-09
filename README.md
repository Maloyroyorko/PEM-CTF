## Interactive menu

Run `python3 pemctf.py` with no arguments to choose:
1. Normal PEM inspection/decryption.
2. Recover one unknown `?` Base64 character and try each parseable candidate against the ciphertext.

Recovery mode does not assume a flag prefix. It reports every successful decryption in both hex and UTF-8 (when valid), and saves candidate keys/plaintexts. A parseable key alone is not proof that it is the original key.

# PEM-CTF

A Python helper for authorized cryptography CTF challenges involving PEM keys and ciphertext.

## Install (Kali Linux)

```bash
sudo apt update
sudo apt install -y python3-cryptography openssl
# Or use a virtual environment if pip reports an externally-managed-environment error:
python3 -m venv .venv
source .venv/bin/activate
python -m pip install cryptography
```

## Usage

Inspect a PEM:
```bash
python3 pemctf.py analyze key.pem
```

Try RSA decryption (automatically detects Base64, hex, or raw ciphertext):
```bash
python3 pemctf.py analyze private.pem -c ciphertext.txt -o plaintext.bin -r writeup.md
```

Force ciphertext encoding:
```bash
python3 pemctf.py analyze private.pem -c ciphertext.txt --format base64
python3 pemctf.py analyze private.pem -c ciphertext.hex --format hex
```

Recover one marked Base64 character and test candidates against ciphertext:
```bash
python3 pemctf.py recover damaged.pem -c ciphertext.txt --format base64 \
  --output-dir candidates -r recovery-writeup.md
```

Use `?` to mark the unknown Base64 character. The tool substitutes each Base64 alphabet character, parses candidate keys, then tries RSA PKCS#1 v1.5 and OAEP-SHA1/SHA256 decryption when `-c` is supplied. Successful plaintext and recovered keys are saved in the output directory. Without `-c`, it only checks whether candidates parse as keys. This does not recover a missing RSA integer or a whole missing word.

## Notes

- RSA decryption needs a valid RSA **private** key. A public PEM cannot decrypt ciphertext.
- The tool tests PKCS#1 v1.5 and OAEP with SHA-1/SHA-256 defaults. CTFs may use other OAEP parameters, hybrid encryption, or non-RSA schemes.
- A PEM that parses is not necessarily the correct recovered key. Validate candidates against the challenge's public key, ciphertext, signature, or known plaintext.
- A missing numeric RSA component such as `p`, `q`, or `d` is a different problem from a damaged Base64 character and is not brute-forced by this script.
- Use only on challenge files and systems you are authorized to test.
