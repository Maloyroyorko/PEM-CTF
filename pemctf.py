#!/usr/bin/env python3
"""
PEM-CTF: helper toolkit for authorized cryptography CTF challenges.
Features:
- Inspect PEM keys and certificates.
- Decode ciphertext represented as Base64 or hex.
- Try RSA PKCS#1 v1.5 and OAEP decryption when a valid private key is supplied.
- Inspect RSA parameters and report common weak-key clues.
- Attempt bounded recovery of a single missing Base64 character marked with '?' or 'x'
  in a PEM body, validating candidates with the cryptography parser.
- Generate a Markdown writeup report.
"""
from __future__ import annotations
import argparse, base64, binascii, datetime, json, re, sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec, ed25519, ed448, dsa
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("Missing dependency. Install with: python3 -m pip install cryptography", file=sys.stderr)
    sys.exit(2)

REPORT = []

def log(s=""):
    print(s)
    REPORT.append(str(s))

def read_bytes(path):
    return Path(path).read_bytes()

def load_pem(data, password=None):
    pw = password.encode() if password else None
    errors = []
    try:
        return serialization.load_pem_private_key(data, password=pw)
    except Exception as e:
        errors.append(str(e))
    try:
        return serialization.load_pem_public_key(data)
    except Exception as e:
        errors.append(str(e))
    try:
        cert = x509.load_pem_x509_certificate(data)
        return cert.public_key()
    except Exception as e:
        errors.append(str(e))
    raise ValueError("Could not parse PEM/key/certificate. " + " | ".join(errors[-2:]))

def key_kind(key):
    if isinstance(key, rsa.RSAPrivateKey): return "RSA private key"
    if isinstance(key, rsa.RSAPublicKey): return "RSA public key"
    if isinstance(key, ec.EllipticCurvePrivateKey): return f"EC private key ({key.curve.name})"
    if isinstance(key, ec.EllipticCurvePublicKey): return f"EC public key ({key.curve.name})"
    if isinstance(key, ed25519.Ed25519PrivateKey): return "Ed25519 private key"
    if isinstance(key, ed25519.Ed25519PublicKey): return "Ed25519 public key"
    if isinstance(key, ed448.Ed448PrivateKey): return "Ed448 private key"
    if isinstance(key, ed448.Ed448PublicKey): return "Ed448 public key"
    if isinstance(key, dsa.DSAPrivateKey): return "DSA private key"
    if isinstance(key, dsa.DSAPublicKey): return "DSA public key"
    return type(key).__name__

def inspect_key(key):
    log(f"Key type: {key_kind(key)}")
    if isinstance(key, (rsa.RSAPrivateKey, rsa.RSAPublicKey)):
        nums = key.private_numbers() if isinstance(key, rsa.RSAPrivateKey) else key.public_numbers()
        pub = nums.public_numbers if isinstance(key, rsa.RSAPrivateKey) else nums
        log(f"RSA modulus bits: {pub.n.bit_length()}")
        log(f"Public exponent e: {pub.e}")
        log(f"Modulus n (hex): {pub.n:x}")
        if isinstance(key, rsa.RSAPrivateKey):
            log("Private components present: p, q, d, dmp1, dmq1, iqmp")
        if pub.n.bit_length() < 2048:
            log("Warning: RSA modulus is below 2048 bits; investigate whether the CTF intentionally uses a weak key.")
        if pub.e < 65537:
            log("Note: unusually small public exponent; this alone does not prove a vulnerability.")
    else:
        log("No RSA-specific parameters available.")

def decode_ciphertext(path, fmt="auto"):
    raw = Path(path).read_bytes().strip()
    if fmt in ("auto", "base64"):
        try:
            compact = re.sub(rb"\s+", b"", raw)
            out = base64.b64decode(compact, validate=True)
            if out: return out, "base64"
        except (binascii.Error, ValueError):
            if fmt == "base64": raise ValueError("Input is not valid Base64")
    if fmt in ("auto", "hex"):
        try:
            compact = re.sub(rb"\s+", b"", raw)
            out = bytes.fromhex(compact.decode("ascii"))
            if out: return out, "hex"
        except (ValueError, UnicodeDecodeError):
            if fmt == "hex": raise ValueError("Input is not valid hex")
    if fmt == "raw":
        return raw, "raw"
    if fmt != "auto":
        raise ValueError(f"Unsupported ciphertext format: {fmt}")
    return raw, "raw"

def try_decrypt(key, ct):
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("Decryption requires an RSA private key, not a public key/certificate.")
    results = []
    schemes = [
        ("RSA PKCS#1 v1.5", padding.PKCS1v15()),
        ("RSA-OAEP-SHA1", padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA1(), label=None)),
        ("RSA-OAEP-SHA256", padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)),
    ]
    for name, pad in schemes:
        try:
            pt = key.decrypt(ct, pad)
            results.append((name, pt))
        except Exception:
            pass
    return results

def analyze(args):
    data = read_bytes(args.pem)
    key = load_pem(data, args.password)
    log("# PEM-CTF analysis")
    log(f"Input: {args.pem}")
    inspect_key(key)
    if args.ciphertext:
        ct, fmt = decode_ciphertext(args.ciphertext, args.format)
        log(f"Ciphertext: {args.ciphertext}")
        log(f"Detected encoding: {fmt}")
        log(f"Ciphertext bytes: {len(ct)}")
        results = try_decrypt(key, ct)
        if results:
            for name, pt in results:
                log(f"\nDecryption succeeded using {name}")
                try: log("Plaintext UTF-8: " + pt.decode("utf-8"))
                except UnicodeDecodeError: log("Plaintext hex: " + pt.hex())
                if args.output:
                    Path(args.output).write_bytes(pt)
                    log(f"Plaintext saved to: {args.output}")
        else:
            log("No supported RSA padding method decrypted this ciphertext.")
            log("Check key/ciphertext pairing, ciphertext encoding, OAEP hash/MGF settings, and whether this is actually RSA ciphertext.")
    if args.report:
        write_report(args.report)

def normalize_markers(data):
    # In recovery mode, x or ? is treated as one unknown Base64 alphabet character
    # only within the PEM body. Header/footer and line breaks are preserved.
    lines = data.decode("ascii", errors="strict").splitlines()
    body_idx = [i for i, line in enumerate(lines)
                if line and not line.startswith("-----")]
    question_markers = []
    x_markers = []
    for i in body_idx:
        for j, ch in enumerate(lines[i]):
            if ch == "?":
                question_markers.append((i, j, ch))
            elif ch == "x":
                x_markers.append((i, j, ch))
    # '?' is unambiguous. Only accept 'x' as a marker when exactly one x exists,
    # because x is a valid character in ordinary Base64 data.
    if question_markers:
        return lines, question_markers
    return lines, x_markers if len(x_markers) == 1 else x_markers

def recover(args):
    raw = read_bytes(args.pem)
    lines, markers = normalize_markers(raw)
    log("# PEM-CTF bounded PEM recovery")
    log(f"Input: {args.pem}")
    if args.ciphertext:
        ct, fmt = decode_ciphertext(args.ciphertext, args.format)
        log(f"Ciphertext: {args.ciphertext}")
        log(f"Detected encoding: {fmt}")
        log(f"Ciphertext bytes: {len(ct)}")
    else:
        ct = None

    if len(markers) != 1:
        log(f"Found {len(markers)} marker characters ('x' or '?') in PEM body.")
        log("This mode supports exactly one unknown character. Use '?' to mark it; 'x' is ambiguous because x is valid Base64.")
        if args.report:
            write_report(args.report)
        return

    i, j, original = markers[0]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    candidates_to_try = alphabet[:max(0, min(args.max_candidates, len(alphabet)))]
    parseable = 0
    decrypt_successes = 0
    attempted = 0
    outdir = Path(args.output_dir) if args.output_dir else None
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    log(f"Unknown character marker at line {i+1}, column {j+1}")
    log(f"Candidate substitutions to test: {len(candidates_to_try)}")
    log("Flag-prefix filtering: disabled (all plaintexts are reported).")

    for ch in candidates_to_try:
        attempted += 1
        trial_lines = list(lines)
        trial_lines[i] = trial_lines[i][:j] + ch + trial_lines[i][j+1:]
        candidate = ("\n".join(trial_lines) + "\n").encode()
        try:
            key = load_pem(candidate, args.password)
        except Exception:
            continue

        parseable += 1
        log(f"\n[PARSEABLE] Replacement {ch!r}: {key_kind(key)}")
        decrypt_results = try_decrypt(key, ct) if ct is not None else []
        if decrypt_results:
            for idx, (method, plaintext) in enumerate(decrypt_results, 1):
                decrypt_successes += 1
                log(f"[DECRYPTION SUCCESS] Replacement {ch!r}; method: {method}")
                log(f"  Plaintext length: {len(plaintext)} bytes")
                log(f"  Plaintext hex: {plaintext.hex()}")
                try:
                    decoded = plaintext.decode("utf-8")
                    log(f"  Plaintext UTF-8: {decoded!r}")
                except UnicodeDecodeError:
                    log("  Plaintext UTF-8: <not valid UTF-8; inspect hex/binary output>")
                if outdir:
                    key_path = outdir / f"recovered_{ord(ch):02x}.pem"
                    key_path.write_bytes(candidate)
                    plain_path = outdir / f"plaintext_{ord(ch):02x}_{idx}.bin"
                    plain_path.write_bytes(plaintext)
                    log(f"  Recovered key saved: {key_path}")
                    log(f"  Plaintext saved: {plain_path}")
        elif outdir:
            key_path = outdir / f"parseable_{ord(ch):02x}.pem"
            key_path.write_bytes(candidate)

    log(f"\nCandidate substitutions attempted: {attempted}")
    log(f"Parseable key candidates: {parseable}")
    if ct is not None:
        log(f"Successful decryptions (method/result pairs): {decrypt_successes}")
        if decrypt_successes == 0:
            log("No candidate decrypted the supplied ciphertext with supported RSA padding schemes.")
            log("Check the key/ciphertext pairing, ciphertext encoding, and RSA padding/hash settings.")
    else:
        log("No ciphertext supplied; candidates were checked only for key parseability.")
        log("Supply -c/--ciphertext to test candidates by decryption.")
    if args.report:
        write_report(args.report)

def write_report(path):
    p = Path(path)
    p.write_text("\n".join(REPORT) + "\n", encoding="utf-8")
    print(f"\nWriteup saved to: {p}")

def interactive_menu():
    print("\n=== PEM-CTF ===")
    print("1) Normal decrypt / inspect a PEM key")
    print("2) Recover unknown '?' character and try decrypting with every candidate")
    choice = input("Choose mode [1/2]: ").strip()
    if choice == "1":
        pem = input("PEM private-key file [private.pem]: ").strip() or "private.pem"
        ct = input("Ciphertext file (blank to inspect key only): ").strip()
        fmt = input("Ciphertext format [auto/base64/hex/raw] (auto): ").strip() or "auto"
        out = input("Plaintext output file (plaintext.bin): ").strip() or "plaintext.bin"
        report = input("Report file (writeup.md): ").strip() or "writeup.md"
        argv = ["analyze", pem]
        if ct: argv += ["-c", ct, "--format", fmt, "-o", out]
        if report: argv += ["-r", report]
    elif choice == "2":
        pem = input("Damaged PEM file containing one '?' [damaged.pem]: ").strip() or "damaged.pem"
        ct = input("Ciphertext file to test (required for decrypt attempts): ").strip()
        fmt = input("Ciphertext format [auto/base64/hex/raw] (auto): ").strip() or "auto"
        outdir = input("Output directory (recovered): ").strip() or "recovered"
        report = input("Report file (recovery_writeup.md): ").strip() or "recovery_writeup.md"
        argv = ["recover", pem, "--output-dir", outdir, "--format", fmt]
        if ct: argv += ["-c", ct]
        if report: argv += ["-r", report]
    else:
        print("Invalid choice. Run again and choose 1 or 2.")
        return 2
    return main(argv)

def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        return interactive_menu()
    parser = argparse.ArgumentParser(description="PEM-CTF: PEM inspection, RSA decryption and bounded recovery")
    sub = parser.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="inspect a PEM and optionally decrypt ciphertext")
    a.add_argument("pem")
    a.add_argument("--ciphertext", "-c")
    a.add_argument("--format", choices=["auto", "base64", "hex", "raw"], default="auto")
    a.add_argument("--password", help="PEM private-key password (avoid on shared systems)")
    a.add_argument("--output", "-o", help="write decrypted plaintext bytes here")
    a.add_argument("--report", "-r", help="save Markdown/text report")
    a.set_defaults(func=analyze)
    r = sub.add_parser("recover", help="try one marked Base64 character in a PEM body")
    r.add_argument("pem")
    r.add_argument("--password")
    r.add_argument("--ciphertext", "-c", help="ciphertext to test each candidate against")
    r.add_argument("--format", choices=["auto", "base64", "hex", "raw"], default="auto")
    r.add_argument("--output-dir", default="pemctf_candidates")
    r.add_argument("--max-candidates", type=int, default=64)
    r.add_argument("--report", "-r")
    r.set_defaults(func=recover)
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except (OSError, ValueError, TypeError) as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
