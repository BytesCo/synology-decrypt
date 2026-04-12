# Synology Cloud Sync Encryption Algorithm

This document describes the encryption algorithm used by Synology NAS Cloud Sync,
reverse-engineered from the decryption implementation in `syndecrypt/core.py` and
verified against actual encrypted files.

## Overview

Synology Cloud Sync encrypts files individually. Each encrypted file (`.csenc`)
is self-contained: it carries all the metadata needed to decrypt it, given
either the original password or the RSA private key.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    .csenc File Structure                            │
├─────────────────────────────────────────────────────────────────────┤
│  Magic Header    │  b'__CLOUDSYNC_ENC__'              (17 bytes)   │
│  Magic Hash      │  MD5(magic).hexdigest()            (32 bytes)   │
│  Metadata Dict   │  TLV-encoded OrderedDict           (variable)   │
│  Data Chunk 1    │  TLV-encoded encrypted block       (≤ 8192 B)   │
│  Data Chunk 2    │  TLV-encoded encrypted block       (≤ 8192 B)   │
│  ...             │                                                  │
│  Data Chunk N    │  TLV-encoded encrypted block (PKCS7-padded)     │
│  File MD5 Dict   │  TLV-encoded OrderedDict           (variable)   │
└─────────────────────────────────────────────────────────────────────┘
```

## Decryption Pipeline

```
.csenc file
    │
    ▼
┌──────────────────┐
│  Parse Header    │  Verify magic + MD5 hash
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Parse Metadata  │  Extract: salt, version, enc_key1/enc_key2,
│  (TLV objects)   │  key1_hash, session_key_hash, file_md5, etc.
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Recover Session Key                                  │
│                                                       │
│  Password path:                                       │
│    (key, iv) = KDF(password, salt)                    │
│    session_key = AES-256-CBC-decrypt(enc_key1)        │
│    strip PKCS7 padding                                │
│                                                       │
│  Private key path:                                    │
│    session_key = RSA-OAEP-decrypt(enc_key2)           │
└────────┬─────────────────────────────────────────────┘
         │
         │  Verify session_key_hash
         ▼
┌──────────────────────────────────────────────────────┐
│  Derive Data Decryption Key                           │
│                                                       │
│  v1: data_key_material = session_key (raw bytes)      │
│  v3: data_key_material = unhexlify(session_key)       │
│                                                       │
│  (key, iv) = KDF(data_key_material, salt=b'')         │
│  Create AES-256-CBC decryptor (stateful)              │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Decrypt Data Chunks (sequential, CBC state carries)  │
│                                                       │
│  For each chunk except last:                          │
│    plaintext_chunk = AES-CBC-decrypt(chunk)            │
│    feed to LZ4 decompressor                           │
│                                                       │
│  For last chunk:                                      │
│    plaintext_chunk = AES-CBC-decrypt(chunk)            │
│    plaintext_chunk = strip_PKCS7(plaintext_chunk)      │
│    feed to LZ4 decompressor                           │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────┐
│ LZ4 Decompress   │  lz4 -d (frame format)
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Verify MD5      │  Compare computed MD5 with file_md5
└────────┬─────────┘
         │
         ▼
    Original file


```

## Encryption Pipeline (Reverse)

```
Original file
    │
    ▼
┌──────────────────┐
│  Compute MD5     │  file_md5 = MD5(plaintext).hexdigest()
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  LZ4 Compress    │  lz4 (frame format)
└────────┬─────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Generate Session Key                                 │
│                                                       │
│  v1: session_key = random 32 ASCII bytes              │
│  v3: session_key = random 32 bytes, hex-encoded       │
│      (64-char hex string, stored as bytes)            │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Encrypt Session Key                                  │
│                                                       │
│  v1: salt = b''                                       │
│  v3: salt = random 8 ASCII chars                      │
│                                                       │
│  Password path (enc_key1):                            │
│    (key, iv) = KDF(password, salt)                    │
│    enc_key1 = AES-256-CBC-encrypt(session_key)        │
│    add PKCS7 padding before encryption                │
│    base64-encode result                               │
│                                                       │
│  RSA path (enc_key2):                                 │
│    enc_key2 = RSA-OAEP-encrypt(session_key, pub_key)  │
│    base64-encode result                               │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Derive Data Encryption Key                           │
│                                                       │
│  v1: data_key_material = session_key                  │
│  v3: data_key_material = unhexlify(session_key)       │
│                                                       │
│  (key, iv) = KDF(data_key_material, salt=b'')         │
│  Create AES-256-CBC encryptor (stateful)              │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Encrypt Compressed Data (chunked)                    │
│                                                       │
│  Split compressed data into blocks of up to 8192 B    │
│  (each block must be a multiple of 16 = AES block)    │
│                                                       │
│  For each chunk except last:                          │
│    ciphertext = AES-CBC-encrypt(chunk)                 │
│                                                       │
│  For last chunk:                                      │
│    add PKCS7 padding to multiple of 16                │
│    ciphertext = AES-CBC-encrypt(padded_chunk)          │
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Generate Verification Hashes                         │
│                                                       │
│  key1_hash       = salted_hash(random_salt, password) │
│  key2_hash       = salted_hash(random_salt, pub_key)  │
│  session_key_hash = salted_hash(random_salt, sess_key)│
└────────┬─────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────┐
│  Build .csenc File                                    │
│                                                       │
│  1. Write magic header + MD5(magic)                   │
│  2. Write metadata TLV dict                           │
│  3. Write data chunk TLV dicts                        │
│  4. Write file_md5 TLV dict                           │
└──────────────────────────────────────────────────────┘
```

## Detailed Component Specifications

### 1. Binary TLV Encoding

The `.csenc` format uses a custom Type-Length-Value encoding with these type bytes:

| Byte   | Type          | Length Encoding              | Payload                     |
|--------|---------------|-----------------------------|-----------------------------|
| `0x42` | OrderedDict   | none (delimited by `0x40`)  | Key-value pairs, then `0x40`|
| `0x10` | String (UTF-8)| 2 bytes, big-endian uint16  | UTF-8 bytes                 |
| `0x11` | Bytes (raw)   | 2 bytes, big-endian uint16  | Raw binary data             |
| `0x01` | Integer       | 1 byte, uint8               | Big-endian integer          |
| `0x40` | End marker    | none                        | none (terminates a dict)    |

#### Encoding Examples

**Integer 1:**
```
01 01 01
│  │  └─ value: 1
│  └──── length: 1 byte
└─────── type: integer
```

**String "md5":**
```
10 00 03 6d 64 35
│  └──┬─┘ └──┬──┘
│     │      └─ UTF-8 bytes: "md5"
│     └──────── length: 3 (big-endian)
└────────────── type: string
```

**Bytes (80 bytes of encrypted data):**
```
11 00 50 [80 bytes of data]
│  └──┬─┘
│     └── length: 0x0050 = 80 (big-endian)
└──────── type: bytes
```

**Dict with key-value pairs:**
```
42                          ← dict start
  10 00 04 74 79 70 65      ← key: string "type"
  10 00 08 6d 65 74 ...     ← value: string "metadata"
  10 00 08 63 6f 6d ...     ← key: string "compress"
  01 01 01                  ← value: integer 1
  ...                       ← more key-value pairs
40                          ← dict end
```

#### Top-Level File Structure (TLV Objects)

A `.csenc` file contains exactly 3+ top-level dict objects:

1. **Metadata dict** (`type` = `"metadata"`): all encryption parameters
2. **Data dicts** (`type` = `"data"`): one per encrypted chunk, each contains a `data` field (bytes)
3. **File MD5 dict** (`type` = `"metadata"`): contains `file_md5` field

### 2. Metadata Fields

The metadata dict contains these key-value pairs (in order):

| Field              | TLV Type | Description                                              |
|--------------------|----------|----------------------------------------------------------|
| `compress`         | int      | Compression flag, always `1`                             |
| `digest`           | string   | Hash algorithm, always `"md5"`                           |
| `enc_key1`         | string   | Base64-encoded session key, encrypted with password      |
| `enc_key2`         | string   | Base64-encoded session key, encrypted with RSA-OAEP      |
| `encrypt`          | int      | Encryption flag, always `1`                              |
| `file_name`        | string   | Original filename                                        |
| `key1_hash`        | string   | Salted MD5 hash of the password (42 chars)               |
| `key2_hash`        | string   | Salted MD5 hash of the public key material (42 chars)    |
| `salt`             | string   | KDF salt: 8 ASCII chars (v3+) or absent (v1)             |
| `session_key_hash` | string   | Salted MD5 hash of the session key (42 chars)            |
| `type`             | string   | Always `"metadata"`                                      |
| `version`          | dict     | `{"major": int, "minor": int}`                           |

Data chunk dicts contain:

| Field  | TLV Type | Description                                  |
|--------|----------|----------------------------------------------|
| `data` | bytes    | Encrypted compressed data (up to 8192 bytes) |
| `type` | string   | Always `"data"`                              |

The trailing dict contains:

| Field      | TLV Type | Description                                |
|------------|----------|--------------------------------------------|
| `file_md5` | string   | MD5 hex digest of the original plaintext   |
| `type`     | string   | Always `"metadata"`                        |

### 3. Key Derivation Function (KDF)

The KDF is compatible with OpenSSL's `EVP_BytesToKey` using MD5:

```
function KDF(password, salt) → (key, iv):
    iterations = 1 if salt is empty, else 1000
    key_size   = 32 bytes (AES-256)
    iv_size    = 16 bytes (AES block size)

    derived = b''
    prev_hash = b''
    while len(derived) < key_size + iv_size:
        input = prev_hash + password + salt
        for i in 1..iterations:
            input = MD5(input)
        prev_hash = input
        derived += prev_hash

    key = derived[0:32]
    iv  = derived[32:48]
    return (key, iv)
```

#### KDF Test Vectors

**v1 (no salt, 1 iteration):**
```
password = b'buJx9/y9fV'
salt     = b''

key = 4F3E66EF6D006CFF64B332226E8F109DA8D0441F966FBA2948F55934F92AACB8
iv  = 3ADCF6A17E01689567E1C6C6856112B1
```

**v3 (8-byte salt, 1000 iterations):**
```
password = b'buJx9/y9fV'
salt     = b'DXzp4VKu'

key = 74DCF4660DA7FDE6B18B88E48D72D7E6E9EC48D13995D420FE3CE7DF71E62B04
iv  = 95487A753CD99A7D8E8B19280455E151
```

### 4. Session Key

The session key is a random value used to encrypt/decrypt the actual file data.
It is stored in the `.csenc` metadata twice — once encrypted with the password
(AES-256-CBC), once with the public key (RSA-OAEP) — so either credential can
recover it.

#### Format Differences by Version

| Version | Session Key Format                        | Example                                      |
|---------|-------------------------------------------|----------------------------------------------|
| 1.0     | 32 random printable ASCII bytes           | `BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6`          |
| 3.0+    | 32 random bytes, hex-encoded (64 chars)   | `EA23EB5F36B9008A...09CBC215`                |

**Critical:** When deriving the data encryption key, v3+ session keys must be
decoded from hex first:

```
v1:  data_key_material = session_key                    (32 bytes)
v3+: data_key_material = bytes.fromhex(session_key)     (32 bytes)
```

In both cases, the data encryption key is derived with:
```
(data_key, data_iv) = KDF(data_key_material, salt=b'')     ← always empty salt, 1 iteration
```

### 5. Session Key Encryption

#### Password Path (enc_key1)

```
Encrypt:
  (key, iv) = KDF(password, salt)           ← salt from metadata (empty for v1)
  padded    = PKCS7_pad(session_key)         ← pad to 16-byte boundary
  enc_key1  = AES-256-CBC-encrypt(padded, key, iv)
  store as: base64(enc_key1)

Decrypt:
  (key, iv)    = KDF(password, salt)
  padded       = AES-256-CBC-decrypt(base64_decode(enc_key1), key, iv)
  session_key  = PKCS7_strip(padded)
```

#### Private Key Path (enc_key2)

```
Encrypt:
  enc_key2 = RSA-OAEP-encrypt(session_key, public_key)
  store as: base64(enc_key2)

Decrypt:
  session_key = RSA-OAEP-decrypt(base64_decode(enc_key2), private_key)
```

RSA key size is typically 2048-bit (256 bytes). The RSA-OAEP scheme uses
SHA-1 as the hash function (pycryptodomex default).

### 6. Salted Hash Format

All verification hashes use a custom salted format:

```
salted_hash = salt_prefix + MD5(salt_prefix + data).hexdigest()
              ╰──10 chars─╯  ╰──────────32 chars──────────────╯
              ╰────────────── 42 chars total ─────────────────╯
```

Where `salt_prefix` is 10 random ASCII characters.

#### Verification

```
function verify(stored_hash, data) → bool:
    salt    = stored_hash[0:10]
    expected = salt + MD5(salt.encode('ascii') + data).hexdigest()
    return stored_hash == expected
```

#### Test Vectors

```
password = b'buJx9/y9fV'
salt     = '4ZF3pd4Y17'
hash     = '4ZF3pd4Y17' + MD5(b'4ZF3pd4Y17' + b'buJx9/y9fV').hexdigest()
         = '4ZF3pd4Y17c7cf0f016aada3f8398d22c8708d8649'

session_key = b'BxY2A-ouRpI8YRvmiWii5KkCF3LVN1O6'
salt        = 'jM41by6vAd'
hash        = 'jM41by6vAd' + MD5(b'jM41by6vAd' + session_key).hexdigest()
            = 'jM41by6vAd517830d42bfb52eae9b58cd41eac95b0'
```

### 7. PKCS7 Padding

Standard PKCS7 padding to AES block size (16 bytes):

```
If data length mod 16 == 0: add 16 bytes of value 0x10
If data length mod 16 == N: add (16-N) bytes of value (16-N)
```

**Critical:** In multi-chunk files, PKCS7 padding is applied **only to the
last chunk**. Intermediate chunks must be exactly a multiple of 16 bytes.

### 8. Data Chunk Layout

Encrypted data is split into chunks stored as separate TLV dict objects:

```
Intermediate chunks:  exactly 8192 bytes of ciphertext (512 AES blocks)
Last chunk:           ≤ 8192 bytes of ciphertext (includes PKCS7 padding)
```

The AES-256-CBC cipher is **stateful** — the IV carries over across chunks.
A single cipher object processes all chunks sequentially.

### 9. Version Differences

| Feature               | v1.0            | v3.0             | v3.1             |
|-----------------------|-----------------|------------------|------------------|
| `version`             | `{1, 0}`        | `{3, 0}`         | `{3, 1}`         |
| `salt` field          | absent          | 8 ASCII chars    | 8 ASCII chars    |
| KDF iterations        | 1               | 1000             | 1000             |
| Session key format    | ASCII bytes     | hex string       | hex string       |
| Data key salt         | `b''`           | `b''`            | `b''`            |

The `salt` field only affects the password-to-key derivation for `enc_key1`.
The data encryption key is **always** derived with an empty salt (1 iteration).

### 10. LZ4 Compression

The plaintext is compressed using LZ4 **frame format** (the format produced by
the `lz4` CLI tool). This is the format with the magic number `0x04224D18` at
the start.

```
Compress:   lz4 < plaintext > compressed
Decompress: lz4 -d < compressed > plaintext
```

## Encryption Algorithm (Step by Step)

To produce a `.csenc` file compatible with the decryption algorithm:

### Step 1: Prepare Inputs

```
plaintext       ← original file bytes
password        ← user password (bytes)
public_key      ← RSA public key PEM (optional, for enc_key2)
version         ← target version (recommended: 3.1)
file_name       ← original filename
```

### Step 2: Compress and Hash

```
file_md5         = MD5(plaintext).hexdigest()
compressed_data  = LZ4_compress(plaintext)             # lz4 frame format
```

### Step 3: Generate Random Values

```
if version >= 3:
    salt         = random_ascii(8)                     # e.g., 'DXzp4VKu'
    session_key  = random_bytes(32).hex().upper()      # 64-char hex string, as bytes
else:
    salt         = b''
    session_key  = random_printable_ascii(32)           # 32 ASCII bytes
```

### Step 4: Encrypt Session Key

```
# Password path
(key, iv) = KDF(password, salt)
enc_key1_raw  = AES-256-CBC-encrypt(PKCS7_pad(session_key), key, iv)
enc_key1      = base64_encode(enc_key1_raw)

# RSA path (if public key available)
enc_key2_raw  = RSA-OAEP-encrypt(session_key, public_key)
enc_key2      = base64_encode(enc_key2_raw)
```

### Step 5: Generate Verification Hashes

```
key1_hash        = random_salt(10) + MD5(salt_bytes + password).hexdigest()
key2_hash        = random_salt(10) + MD5(salt_bytes + public_key_data).hexdigest()
session_key_hash = random_salt(10) + MD5(salt_bytes + session_key).hexdigest()
```

### Step 6: Encrypt Data

```
if version >= 3:
    data_key_material = bytes.fromhex(session_key)
else:
    data_key_material = session_key

(data_key, data_iv) = KDF(data_key_material, salt=b'')     # always empty salt
encryptor = AES-256-CBC(data_key, data_iv)                   # stateful cipher

chunks = split compressed_data into 8192-byte blocks
encrypted_chunks = []

for each chunk except last:
    assert len(chunk) % 16 == 0                              # must be block-aligned
    encrypted_chunks.append(encryptor.encrypt(chunk))

last_chunk_padded = PKCS7_pad(last_chunk)
encrypted_chunks.append(encryptor.encrypt(last_chunk_padded))
```

### Step 7: Build .csenc File

```
Write: b'__CLOUDSYNC_ENC__'                                  # 17-byte magic
Write: MD5(b'__CLOUDSYNC_ENC__').hexdigest().encode('ascii')  # 32-byte hash

Write TLV dict (type='metadata'):
    compress         = 1
    digest           = 'md5'
    enc_key1         = <base64 string>
    enc_key2         = <base64 string>
    encrypt          = 1
    file_name        = <filename>
    key1_hash        = <42-char salted hash>
    key2_hash        = <42-char salted hash>
    salt             = <8-char salt string>        # omit for v1
    session_key_hash = <42-char salted hash>
    type             = 'metadata'
    version          = {major: 3, minor: 1}

For each encrypted_chunk:
    Write TLV dict (type='data'):
        data = <encrypted bytes>
        type = 'data'

Write TLV dict (type='metadata'):
    file_md5 = <32-char MD5 hex>
    type     = 'metadata'
```

### Step 8: TLV Serialization

To serialize a value to TLV bytes:

```
function serialize_string(s):
    encoded = s.encode('utf-8')
    return b'\x10' + len(encoded).to_bytes(2, 'big') + encoded

function serialize_bytes(b):
    return b'\x11' + len(b).to_bytes(2, 'big') + b

function serialize_int(n):
    if n == 0:
        return b'\x01\x00'
    byte_len = (n.bit_length() + 7) // 8
    return b'\x01' + byte_len.to_bytes(1, 'big') + n.to_bytes(byte_len, 'big')

function serialize_dict(d):
    result = b'\x42'
    for key, value in d.items():
        result += serialize(key)
        result += serialize(value)
    result += b'\x40'
    return result
```

## Security Notes

- **v1 uses only 1 KDF iteration** — vulnerable to brute-force. Prefer v3+.
- **MD5 is used throughout** — for KDF, file integrity, and password hashing.
  Not ideal by modern standards, but sufficient for the file format.
- **The data encryption key always uses empty salt** (1 iteration), regardless
  of version. Only the session key encryption benefits from v3's 1000 iterations.
- **RSA-OAEP** provides the strongest recovery path if the private key is kept
  secure and separate from the encrypted files.
