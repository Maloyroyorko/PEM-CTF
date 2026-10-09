# 🔐 PEM-CTF

### A Python Toolkit for PEM Key Analysis, RSA Decryption & CTF Recovery Experiments

**PEM-CTF** is a Python-based command-line tool designed to help Capture The Flag (CTF) players inspect PEM-encoded cryptographic keys, decrypt RSA ciphertexts, and experiment with recovering a damaged PEM key containing one unknown Base64 character.

Built with Python and the `cryptography` library, PEM-CTF provides an interactive menu for normal key inspection and decryption, along with candidate-based recovery experiments.

> **Author:** Maloy Roy Orko
> **Development assistance:** AI-assisted coding and documentation
> **Cryptographic test tooling:** OpenSSL
> **Platform:** Kali Linux and other compatible systems
> **Language:** Python 3
> **Status:** Experimental

---

## 📌 Table of Contents

* [Overview](#-overview)
* [Features](#-features)
* [How It Works](#-how-it-works)
* [Requirements](#-requirements)
* [Installation](#-installation)
* [Usage](#-usage)
* [Recovery Mode](#-recovery-mode)
* [Reproducible OpenSSL Test](#-reproducible-openssl-test)
* [Example Output](#-example-output)
* [Project Structure](#-project-structure)
* [Limitations](#-limitations)
* [Troubleshooting](#-troubleshooting)
* [Security Considerations](#-security-considerations)
* [Roadmap](#-roadmap)
* [Contributing](#-contributing)
* [Author & Acknowledgments](#-author--acknowledgments)
* [License](#-license)

---

## 🎯 Overview

Cryptography challenges often involve private keys, public keys, certificates, encoded ciphertexts, and malformed cryptographic files. Manually inspecting these artifacts can be time-consuming, especially when a challenge introduces a damaged key or requires testing different decryption methods.

PEM-CTF brings several of these tasks into one interactive tool.

With PEM-CTF, you can:

* Inspect supported PEM-encoded cryptographic keys.
* Identify RSA private-key parameters and modulus size.
* Load ciphertext from a file.
* Attempt RSA decryption using supported padding schemes.
* Experiment with replacing one unknown Base64 character in a damaged PEM key.
* Examine successful plaintext results without assuming a particular CTF flag format.
* Save decrypted output and generate a Markdown analysis report.

PEM-CTF is an educational utility, not a universal cryptographic solver. Its success depends on the input format, available key material, ciphertext, encryption scheme, and challenge constraints.

---

## ✨ Features

### 🔍 1. PEM Key Inspection

Analyze supported PEM files and display useful key information, including:

* Detected key type.
* RSA modulus size.
* Public exponent.
* RSA modulus in hexadecimal.
* Availability of private-key components.

The tool attempts to load supported private keys, public keys, and X.509 certificates.

### 🔓 2. RSA Ciphertext Decryption

Load ciphertext from a file and attempt decryption with a compatible RSA private key.

Supported ciphertext input formats:

| Format   | Description                               |
| -------- | ----------------------------------------- |
| `auto`   | Automatically detect a supported encoding |
| `base64` | Decode Base64-encoded ciphertext          |
| `hex`    | Decode hexadecimal ciphertext             |
| `raw`    | Use file contents as raw ciphertext bytes |

The tool supports attempts using:

* RSA PKCS#1 v1.5 encryption padding.
* RSA-OAEP with SHA-1.
* RSA-OAEP with SHA-256.

**Important:** The padding mode and OAEP parameters must match those used during encryption. A failed attempt does not necessarily mean the private key is incorrect.

### 🧩 3. Single-Character PEM Recovery

PEM-CTF includes an experimental recovery mode for a PEM key whose Base64-encoded body contains one explicitly marked unknown character.

For example:

```text
MIIB...Ab?D...AQAB
```

The tool tests candidate Base64 characters at the marked position, attempts to parse candidate keys, and—when ciphertext is supplied—tries supported decryption methods.

This is useful for learning about PEM formatting, Base64 encoding, RSA key validation, and ciphertext verification in controlled CTF scenarios.

### 📄 4. Plaintext Output

When decryption succeeds, PEM-CTF reports the recovered plaintext. Depending on its contents, the plaintext may be displayed as UTF-8 text or hexadecimal data.

The tool does **not** require plaintext to match a predefined flag prefix. This allows it to display arbitrary recovered messages, including flags with unfamiliar formats.

### 📝 5. Markdown Report Generation

PEM-CTF can generate a Markdown report containing relevant analysis results, such as:

* Input file information.
* Detected key type and RSA parameters.
* Ciphertext encoding and byte length.
* Successful decryption method, when applicable.
* Output file locations.

Review reports before sharing them publicly because cryptographic metadata or plaintext may be sensitive.

---

## ⚙️ How It Works

### Normal Mode

1. Load the specified PEM file.
2. Parse the supported cryptographic object.
3. Display key information.
4. Optionally load and decode a ciphertext file.
5. Attempt supported RSA decryption methods.
6. Display successful plaintext.
7. Save output and an analysis report.

### Recovery Mode

1. Read a PEM file containing one supported unknown-character marker.
2. Generate candidate substitutions from the Base64 alphabet.
3. Attempt to parse each candidate as a cryptographic key.
4. If ciphertext is provided and a usable private key is recovered, attempt supported decryption methods.
5. Display successful results without assuming a flag prefix.
6. Save relevant recovery artifacts and a report.

A candidate that parses successfully is not automatically proof that the original key has been recovered. Successful decryption and independent validation of the expected challenge result provide additional evidence.

---

## 📦 Requirements

* Python 3.10 or newer recommended.
* `pip` for installing Python dependencies.
* The Python `cryptography` package.
* A compatible PEM key and, for decryption, matching ciphertext.
* OpenSSL for reproducing the optional test workflow.

PEM-CTF is designed to run on Kali Linux but can also run on other systems that support its Python dependencies.

---

## 🚀 Installation

### 1. Clone the repository

Replace `YOUR_USERNAME` with the GitHub username hosting this repository.

```bash
git clone https://github.com/YOUR_USERNAME/pem-ctf.git
cd pem-ctf
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

If virtual environments are unavailable on Kali Linux:

```bash
sudo apt update
sudo apt install -y python3-venv
```

### 3. Install dependencies

If the repository contains `requirements.txt`:

```bash
python3 -m pip install -r requirements.txt
```

Otherwise, install the required dependency directly:

```bash
python3 -m pip install cryptography
```

### 4. Launch PEM-CTF

```bash
python3 pemctf.py
```

---

## 🖥️ Usage

Start the tool:

```bash
python3 pemctf.py
```

The interactive menu provides two main modes:

```text
=== PEM-CTF ===
1) Normal decrypt / inspect a PEM key
2) Recover unknown '?' character and try decrypting with every candidate

Choose mode [1/2]:
```

### Option 1 — Normal Decryption / Inspection

Choose `1` to inspect a PEM key and optionally decrypt a ciphertext file.

The tool prompts for:

* PEM private-key file.
* Optional ciphertext file.
* Ciphertext encoding.
* Plaintext output path.
* Markdown report path.

Example inputs:

```text
PEM private-key file [private.pem]: private.pem
Ciphertext file (blank to inspect key only): encrypted.txt
Ciphertext format [auto/base64/hex/raw] (auto): auto
Plaintext output file (plaintext.bin): plaintext.bin
Report file (writeup.md): writeup.md
```

Use a PEM private key you are authorized to analyze and ciphertext intended for that key.

### Option 2 — Recovery Mode

Choose `2` to test candidate substitutions for one unknown Base64 character in a damaged PEM key.

Provide the damaged PEM file, corresponding ciphertext file, ciphertext format, and output directory when prompted.

The tool will report candidate-testing results, including how many candidate keys were parseable and whether any supported decryption attempts succeeded.

---

## 🧪 Reproducible OpenSSL Test

This section demonstrates how to generate a temporary RSA key pair, encrypt a test message with OpenSSL, and verify PEM-CTF's normal decryption mode.

**Use synthetic test data only.** The example flag below is a test string, not a real CTF flag.

### Step 1: Generate a 2048-bit RSA private key

```bash
openssl genpkey -algorithm RSA \
  -pkeyopt rsa_keygen_bits:2048 \
  -out private.pem
```

OpenSSL will print key-generation progress in the terminal. That output is normal.

### Step 2: Export the public key

```bash
openssl pkey -in private.pem -pubout -out public.pem
```

### Step 3: Create a test plaintext

```bash
printf 'bcsctf{manual_pem_test}' > plaintext.txt
```

### Step 4: Encrypt the plaintext with RSA

```bash
openssl pkeyutl -encrypt \
  -pubin -inkey public.pem \
  -in plaintext.txt \
  -out encrypted.bin \
  -pkeyopt rsa_padding_mode:pkcs1
```

This uses RSA PKCS#1 v1.5 encryption padding, which matches the successful decryption method in the example test.

### Step 5: Encode the ciphertext as Base64

```bash
base64 -w 0 encrypted.bin > encrypted.txt
echo
```

### Step 6: Run PEM-CTF

```bash
python3 pemctf.py
```

Select **Option 1 — Normal decrypt / inspect a PEM key**, then enter:

```text
PEM private-key file: private.pem
Ciphertext file: encrypted.txt
Ciphertext format: auto
Plaintext output file: plaintext.bin
Report file: writeup.md
```

Press Enter to accept the displayed defaults where appropriate.

### Expected Result

The tool should identify the RSA private key, detect the Base64-encoded ciphertext, and attempt RSA PKCS#1 v1.5 decryption.

For this example, the expected plaintext is:

```text
bcsctf{manual_pem_test}
```

Verify the recovered file:

```bash
cat plaintext.bin
```

Inspect the generated report:

```bash
cat writeup.md
```

### What This Test Demonstrates

* RSA private-key generation with OpenSSL.
* Public-key extraction from a private key.
* RSA PKCS#1 v1.5 encryption.
* Base64 encoding of ciphertext.
* PEM-CTF's key inspection and normal decryption workflow.
* Generation of a Markdown analysis report.

**Test status:** The author reported a successful run using this workflow, including recovery of the expected test plaintext and generation of `writeup.md`.

This demonstrates a basic known-plaintext workflow. It does not establish that every recovery scenario or ciphertext format is supported.

### Cleanup

The generated private key and plaintext are test artifacts. Do not upload them to a public repository.

After testing, remove the local artifacts if they are no longer needed:

```bash
rm -f private.pem public.pem plaintext.txt \
  encrypted.bin encrypted.txt plaintext.bin
```

Run this command only in your dedicated test directory, after confirming that you do not need the files.

---

## 🧾 Example Output

The following is an illustrative example based on the author's reported test. The modulus value and other key details will vary when a new RSA key is generated.

```text
# PEM-CTF analysis
Input: private.pem
Key type: RSA private key
RSA modulus bits: 2048
Public exponent e: 65537

Ciphertext: encrypted.txt
Detected encoding: base64
Ciphertext bytes: 256

Decryption succeeded using RSA PKCS#1 v1.5
Plaintext UTF-8: bcsctf{manual_pem_test}

Plaintext saved to: plaintext.bin
Writeup saved to: writeup.md
```

The example plaintext is illustrative only. PEM-CTF does not assume that every challenge uses a `bcsctf{...}` flag format.

### Run the included smoke test

If `smoke_test.py` is present in the repository root:

```bash
python3 smoke_test.py
```

If it is stored in the `tests/` directory instead:

```bash
python3 tests/smoke_test.py
```

The smoke test is intended to verify a basic cryptographic workflow using test data. Passing it does not guarantee compatibility with every PEM format or CTF challenge.

---

## 📁 Project Structure

A typical repository layout is:

```text
pem-ctf/
├── pemctf.py
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── smoke_test.py
└── examples/
    └── README.md
```

The exact layout may vary depending on which optional files are included in the repository.

| File               | Purpose                                                 |
| ------------------ | ------------------------------------------------------- |
| `pemctf.py`        | Main command-line application                           |
| `README.md`        | Documentation and usage instructions                    |
| `requirements.txt` | Python dependencies                                     |
| `LICENSE`          | Project license                                         |
| `.gitignore`       | Excludes selected local and sensitive files             |
| `smoke_test.py`    | Basic functionality test, if included                   |
| `examples/`        | Safe examples and supporting documentation, if included |

---

## ⚠️ Limitations

PEM-CTF is an experimental tool with a deliberately limited recovery scope.

* Recovery mode is designed for one unknown Base64 character, not an arbitrary missing word or an unknown-length section of a PEM file.
* It does not automatically recover forgotten private-key passphrases.
* It cannot generally reconstruct a private key when required cryptographic information is missing.
* It does not guarantee recovery of every malformed or truncated PEM file.
* Decryption attempts are limited to the supported RSA padding configurations.
* A valid PEM structure does not guarantee that a key matches the ciphertext.
* Encrypted PEM files, alternative key formats, and unusual ciphertext encodings may require additional handling.
* A successful key parse or decryption does not independently prove that a result is the intended challenge flag.

Treat recovery results as candidates that require verification, not as guaranteed solutions.

---

## 🛠️ Troubleshooting

### `ModuleNotFoundError: No module named 'cryptography'`

Install the dependency in your active Python environment:

```bash
python3 -m pip install cryptography
```

If you are using a virtual environment, activate it before installing packages.

### The PEM file cannot be loaded

Check that:

* The file is complete and has the expected PEM header and footer.
* The file contains a supported key or certificate type.
* The Base64 body has not been accidentally altered.
* The file is not encrypted using an unsupported or unhandled format.

### Decryption fails

Verify that:

* The ciphertext corresponds to the private key.
* The ciphertext was decoded using the correct input format.
* The encryption padding and OAEP parameters match.
* The ciphertext has not been truncated or corrupted.

### Recovery finds no successful decryption

A failed recovery does not prove that no valid key exists. The damaged marker may be in an unsupported position, the input may contain additional corruption, the ciphertext may not match the key, or the challenge may use an unsupported encryption scheme.

---

## 🔒 Security Considerations

PEM-CTF is intended for authorized security research, educational cryptography experiments, and CTF competitions.

* Use only keys and ciphertexts you own or are authorized to analyze.
* Never commit production private keys, passwords, API tokens, or confidential ciphertexts to a public repository.
* Do not publish recovered secrets or challenge flags without permission.
* Keep generated plaintext files and analysis reports out of public commits when they contain sensitive data.
* Remember that `.gitignore` does not automatically remove files that Git is already tracking.
* Use synthetic test keys and plaintexts when demonstrating the project publicly.

### Recommended `.gitignore`

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/

# Private keys and certificates
*.pem
*.key
*.p12
*.pfx

# Test ciphertexts and plaintexts
encrypted.bin
encrypted.txt
plaintext.txt
plaintext.bin

# Generated reports
writeup.md
```

**Important:** This `.gitignore` is a precaution, not a guarantee. Check the files already staged or tracked by Git before publishing the repository.

**Responsible use:** This project is provided for learning and authorized testing. Users are responsible for complying with applicable laws, competition rules, and data-handling requirements.

---

## 🗺️ Roadmap

Potential future improvements include:

* [ ] Automated tests for additional RSA key and ciphertext formats.
* [ ] More robust PEM validation and error messages.
* [ ] Clearer distinction between key parsing, decryption, and recovery failures.
* [ ] Support for additional explicitly documented recovery scenarios.
* [ ] Improved report formatting and reproducible test cases.
* [ ] Safer handling and cleanup of generated plaintext files.
* [ ] Continuous integration tests on supported Python versions.
* [ ] Versioned releases with documented changes.

Roadmap items are proposed improvements, not features currently guaranteed to be implemented.

---

## 🤝 Contributing

Contributions, bug reports, and feature suggestions are welcome.

To propose a change:

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Add or update tests where appropriate.
5. Verify that the existing smoke test still passes.
6. Open a pull request describing the change and its test results.

Please avoid submitting real private keys, sensitive challenge artifacts, or undisclosed flags in issues and pull requests.

---

## 👨‍💻 Author & Acknowledgments

**Author:** Maloy Roy Orko

**Project:** PEM-CTF

**Focus areas:** Python · Cryptography · RSA · CTF tooling · Cybersecurity

### Development Assistance

* **AI assistance:** Used during development for coding support, debugging, documentation, and test-workflow preparation.
* **OpenSSL:** Used to generate RSA test keys, derive the public key, and encrypt sample plaintext for functional testing.
* **Python `cryptography` library:** Used by the application for cryptographic key handling and supported RSA decryption operations.

The author reported testing the normal decryption workflow with a locally generated RSA-2048 key pair and synthetic plaintext. The test recovered the expected message and generated a Markdown analysis report.

If you find PEM-CTF useful, consider starring the repository ⭐, reporting bugs, or contributing improvements.

---

## 📄 License

This project is distributed under the license included in the repository. If the repository uses the MIT License, see [`LICENSE`](LICENSE) for the full terms.

---

*PEM-CTF — Learn the structure. Test the candidates. Verify the plaintext.*
