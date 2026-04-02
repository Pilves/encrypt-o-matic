# Encrypt-o-Matic

CLI tool that encrypts Windows .exe files so they can't be opened until you decrypt them. Supports three algorithms (AES, ChaCha20, Twofish), a timer that locks the file for a set duration, and password-based decryption.

## Setup

Needs Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
```

For running tests:

```bash
uv sync --extra dev
```

To build a Windows .exe with PyInstaller:

```bash
uv run pyinstaller --onefile --name encrypt-o-matic src/encrypt_o_matic/main.py
```

## Usage

### Encrypting

```bash
uv run encrypt-o-matic encrypt <target_app> <algorithm> <size_mb> <custom_var> <duration_min>
```

- `target_app` — path to the .exe you want to encrypt
- `algorithm` — `AES`, `ChaCha20`, or `Twofish`
- `size_mb` — how many MB of random data to add to the file
- `custom_var` — range for the custom operation, like `0-100000`
- `duration_min` — how long to keep it locked (in minutes, 0 = no timer)

Example:

```bash
uv run encrypt-o-matic encrypt app.exe AES 10 0-100000 60
```

This encrypts `app.exe` with AES, adds 10MB of padding, does the custom operation from 0 to 100000, and locks it for 60 minutes. You'll be asked to set a master password.

The original file is kept, and the encrypted version is saved as `app.exe.encrypted`.

### Decrypting

```bash
# decrypt right away with password
uv run encrypt-o-matic decrypt app.exe.encrypted --password

# wait for timer to expire first
uv run encrypt-o-matic decrypt app.exe.encrypted
```

Without `--password` it checks if the timer is up. If not, it tells you how long is left. With `--password` you can decrypt immediately regardless of the timer.

The decrypted file is identical to the original — verified by comparing sizes.

### Directory mode (extra feature)

Encrypt all .exe files in a folder recursively:

```bash
uv run encrypt-o-matic encrypt --dir ./some_folder AES 5 0-10000 30
```

This creates a `manifest.json` inside the folder that tracks what was encrypted. To decrypt everything:

```bash
uv run encrypt-o-matic decrypt --dir ./some_folder --password
```

## How it works

### Encryption

1. Read the file and compress it with zlib
2. Add random padding bytes to inflate the file size
3. Run the custom time-consuming operation (iterates through the range and prints progress)
4. Encrypt the whole thing with the chosen algorithm
5. Build a binary header with all the metadata (filename, sizes, timer, etc.)
6. HMAC the header so nobody can hex-edit the timer or other fields
7. Write header + encrypted data to `.encrypted` file

### Decryption

1. Read the header and check the magic bytes
2. If there's a timer and it hasn't expired, block (unless `--password` is used)
3. Ask for password, check HMAC integrity, verify password against stored hash
4. Decrypt, strip padding, decompress
5. Check the size matches the original, write the file back

### Algorithms

- **AES-256-CBC** — standard block cipher, PKCS7 padding, uses pycryptodome
- **ChaCha20-Poly1305** — stream cipher with built-in authentication (the poly1305 tag), also pycryptodome
- **Twofish-256-CBC** — pure Python implementation since the twofish pip package is broken on Python 3.12+. The library only does single-block ECB so CBC mode is done manually (XOR with previous ciphertext block before encrypting each block)

### Password and key derivation

- Password is hashed with **Argon2id** (memory-hard, resists GPU attacks) and stored in the header
- The actual encryption key comes from **PBKDF2-HMAC-SHA256** with 600,000 iterations and a random 32-byte salt
- A separate HMAC key is derived from the same password but with a different salt prefix (`b"hmac" + salt`) so the two keys are independent
- Password input uses `getpass` so it's not visible on screen

### File format

Custom binary format — header followed by encrypted payload:

```
MAGIC (b"ENCO") | VERSION | ALGORITHM | FILENAME_LEN | FILENAME
ORIGINAL_SIZE | ARGON2_HASH (128 bytes) | SALT (32 bytes) | IV/NONCE
EXPIRY_TIMESTAMP | HMAC-SHA256 (32 bytes) | COMPRESSED_FLAG | PADDING_SIZE
ENCRYPTED_PAYLOAD
```

The HMAC covers everything above it in the header. This means if someone tries to change the expiry timestamp with a hex editor, the HMAC check fails and decryption is refused.

### Custom operation

The custom variable is a range like `0-100000`. The program just iterates from start to end and prints progress every 10%. It's a simple time-consuming step — makes the encryption process take longer, which is part of the assignment requirements.

## Extra features

- **Directory encryption** — recursively encrypts all .exe files, saves a manifest for batch decryption
- **Compression** — zlib compression before encryption reduces the actual data size

