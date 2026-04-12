# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Open source Python implementation of Synology NAS Cloud Sync encryption/decryption algorithm. Decrypts files encrypted by Synology Cloud Sync using either a password or a private key.

## Commands

```bash
# Install dependencies
uv pip install -r requirements.txt

# Run all tests (requires `lz4` binary on PATH)
uv run pytest

# Run a single test
uv run pytest tests/test_decrypt.py::test_decrypt_single_line_stream_with_password_v1

# Run with coverage
uv run coverage run -m pytest

# Run the CLI tool
uv run python -m syndecrypt (-p <password-file> | -k <private.pem>) -O <output-dir> <encrypted-file>...
```

## Runtime Dependency

The `lz4` command-line binary must be on `PATH` (Ubuntu: `apt install liblz4-tool`, macOS: `brew install lz4`). It is invoked as a subprocess for LZ4 decompression.

## Architecture

The package is `syndecrypt/` with three modules:

- **`core.py`** — The decryption algorithm. Parses the `.csenc` binary format (`__CLOUDSYNC_ENC__` magic + custom TLV objects), derives AES-256-CBC keys via an OpenSSL-compatible KDF (`_openssl_kdf`), decrypts session keys with password (AES) or private key (RSA-OAEP), then decrypts data chunks with PKCS7 padding removal. Supports format versions 1.0, 3.0, and 3.1. Version 3+ uses a salt (1000 hash iterations) while v1 uses no salt (1 iteration).
- **`files.py`** — File-level wrapper: reads encrypted file, writes decrypted output, handles directory creation and cleanup on failure.
- **`util.py`** — `switch` pattern-matching helper, `FilterSubprocess` for piping data through external commands, and `Lz4Decompressor` which wraps the `lz4 -d` CLI.

## Key Design Details

- The `.csenc` format uses a custom binary TLV encoding (type bytes: `0x42`=dict, `0x10`=string, `0x11`=bytes, `0x01`=int, `0x40`=end). `decode_csenc_stream` yields `(key, value)` pairs: metadata fields first, then `(None, data)` for encrypted data chunks.
- PKCS7 padding is only stripped on the **last** chunk of multi-chunk files.
- Crypto library is `pycryptodomex` (imported as `Cryptodome`).
- CLI argument parsing uses `docopt`.
- Tests use `assertpy` alongside plain `assert`.
