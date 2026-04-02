import argparse
import getpass
import hashlib
import hmac as hmac_mod
import json
import os
import struct
import sys
import time
import zlib

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from Crypto.Cipher import AES, ChaCha20_Poly1305
from Crypto.Util.Padding import pad, unpad

from .twofish import TwofishECB, pkcs7_pad, pkcs7_unpad


MAGIC = b"ENCO"
VERSION = 1

# argon2id for password hashing - memory-hard so gpu brute force is expensive
_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


# ---- password stuff ----

def prompt_password(confirm=False):
    pw = getpass.getpass("Enter master password: ")
    if not pw:
        print("Password cannot be empty.", file=sys.stderr)
        sys.exit(1)
    if confirm:
        pw2 = getpass.getpass("Confirm master password: ")
        if pw != pw2:
            print("Passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return pw


def derive_key(password, salt):
    # pbkdf2 with 600k iterations for the actual encryption key
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600000, dklen=32)


def derive_hmac_key(password, salt):
    # separate key for hmac so compromising one doesnt compromise the other
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"hmac" + salt, 600000, dklen=32)


# ---- encryption/decryption for each algorithm ----

def aes_encrypt(key, data):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv, cipher.encrypt(pad(data, AES.block_size))


def aes_decrypt(key, iv, ct):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)


def chacha_encrypt(key, data):
    nonce = os.urandom(12)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(data)
    # tag goes at the end of ciphertext, we split it off during decrypt
    return nonce, ct + tag


def chacha_decrypt(key, nonce, ct):
    data, tag = ct[:-16], ct[-16:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(data, tag)


def twofish_encrypt(key, data):
    # twofish lib only does ECB so we do CBC manually
    iv = os.urandom(16)
    tf = TwofishECB(key)
    padded = pkcs7_pad(data)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        block = padded[i:i + 16]
        xored = bytes(a ^ b for a, b in zip(block, prev))
        enc = tf.encrypt_block(xored)
        out.extend(enc)
        prev = enc
    return iv, bytes(out)


def twofish_decrypt(key, iv, ct):
    tf = TwofishECB(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ct), 16):
        block = ct[i:i + 16]
        dec = tf.decrypt_block(block)
        xored = bytes(a ^ b for a, b in zip(dec, prev))
        out.extend(xored)
        prev = block
    return pkcs7_unpad(bytes(out))


def do_encrypt(algorithm, key, data):
    if algorithm == "AES":
        return aes_encrypt(key, data)
    elif algorithm == "ChaCha20":
        return chacha_encrypt(key, data)
    elif algorithm == "Twofish":
        return twofish_encrypt(key, data)


def do_decrypt(algorithm, key, iv, ct):
    if algorithm == "AES":
        return aes_decrypt(key, iv, ct)
    elif algorithm == "ChaCha20":
        return chacha_decrypt(key, iv, ct)
    elif algorithm == "Twofish":
        return twofish_decrypt(key, iv, ct)


# ---- file format ----
# custom binary format: header with metadata + hmac + encrypted payload
# hmac covers the header so you cant hex edit the timer or algorithm

ALGO_IDS = {"AES": 0, "ChaCha20": 1, "Twofish": 2}
ALGO_NAMES = {0: "AES", 1: "ChaCha20", 2: "Twofish"}


def build_header(algo_id, filename, original_size, argon2_hash,
                 salt, iv_nonce, expiry, hmac_key, padding_size):
    fname = filename.encode("utf-8")
    # argon2 hash string gets padded to exactly 128 bytes
    ahash = argon2_hash.encode("utf-8").ljust(128, b"\x00")[:128]

    hdr = bytearray()
    hdr.extend(MAGIC)                              # 4 bytes
    hdr.append(VERSION)                             # 1 byte
    hdr.append(algo_id)                             # 1 byte
    hdr.extend(struct.pack("<H", len(fname)))       # 2 bytes
    hdr.extend(fname)                               # variable
    hdr.extend(struct.pack("<Q", original_size))    # 8 bytes
    hdr.extend(ahash)                               # 128 bytes
    hdr.extend(salt)                                # 32 bytes
    hdr.extend(iv_nonce)                            # 12 or 16 bytes
    hdr.extend(struct.pack("<q", expiry))           # 8 bytes

    # hmac everything above
    h = hmac_mod.new(hmac_key, bytes(hdr), hashlib.sha256).digest()
    hdr.extend(h)                                   # 32 bytes

    hdr.append(1)                                   # compressed flag (always on)
    hdr.extend(struct.pack("<Q", padding_size))     # 8 bytes

    return bytes(hdr)


def parse_header(data):
    pos = 0

    if data[pos:pos + 4] != MAGIC:
        raise ValueError("File corrupted or tampered with")
    pos += 4

    if data[pos] != VERSION:
        raise ValueError("File corrupted or tampered with")
    pos += 1

    algo_id = data[pos]; pos += 1

    fname_len = struct.unpack_from("<H", data, pos)[0]; pos += 2
    filename = data[pos:pos + fname_len].decode("utf-8"); pos += fname_len

    original_size = struct.unpack_from("<Q", data, pos)[0]; pos += 8

    argon2_hash = data[pos:pos + 128].rstrip(b"\x00").decode("utf-8"); pos += 128

    salt = data[pos:pos + 32]; pos += 32

    # chacha uses 12 byte nonce, aes and twofish use 16 byte iv
    nonce_len = 12 if algo_id == 1 else 16
    iv_nonce = data[pos:pos + nonce_len]; pos += nonce_len

    expiry = struct.unpack_from("<q", data, pos)[0]; pos += 8

    # everything up to here is what the hmac covers
    hmac_data = data[:pos]
    stored_hmac = data[pos:pos + 32]; pos += 32

    compressed = data[pos]; pos += 1
    padding_size = struct.unpack_from("<Q", data, pos)[0]; pos += 8

    return {
        "algo_id": algo_id,
        "filename": filename,
        "original_size": original_size,
        "argon2_hash": argon2_hash,
        "salt": salt,
        "iv_nonce": iv_nonce,
        "expiry": expiry,
        "hmac_data": hmac_data,
        "stored_hmac": stored_hmac,
        "padding_size": padding_size,
        "payload": data[pos:],
    }


def check_hmac(hmac_key, hmac_data, stored_hmac):
    computed = hmac_mod.new(hmac_key, hmac_data, hashlib.sha256).digest()
    return hmac_mod.compare_digest(computed, stored_hmac)


# ---- main encrypt/decrypt logic ----

def encrypt_file(target_path, algorithm, size_mb, custom_var, duration_min, password=None):
    if not os.path.isfile(target_path):
        print(f"File not found: {target_path}", file=sys.stderr)
        sys.exit(1)

    # parse the custom var (format: "start-end")
    parts = custom_var.split("-")
    if len(parts) != 2:
        print('Expected format: start-end (e.g., "0-100000")', file=sys.stderr)
        sys.exit(1)
    try:
        start, end = int(parts[0]), int(parts[1])
    except ValueError:
        print('Expected format: start-end (e.g., "0-100000")', file=sys.stderr)
        sys.exit(1)

    if password is None:
        password = prompt_password(confirm=True)

    # key setup
    salt = os.urandom(32)
    argon2_hash = _hasher.hash(password)
    enc_key = derive_key(password, salt)
    hmac_key = derive_hmac_key(password, salt)

    with open(target_path, "rb") as f:
        original_data = f.read()
    original_size = len(original_data)
    filename = os.path.basename(target_path)

    # compress to save space, then add random padding to inflate size
    compressed = zlib.compress(original_data, level=9)
    padding = os.urandom(size_mb * 1024 * 1024)
    payload = compressed + padding

    # custom operation - just counts up and prints progress
    total = end - start
    if total > 0:
        step = max(1, total // 10)
        for i in range(total + 1):
            if i % step == 0:
                print(f"Custom operation progress: {(i * 100) // total}%", flush=True)

    iv_nonce, ciphertext = do_encrypt(algorithm, enc_key, payload)

    expiry = int(time.time()) + (duration_min * 60) if duration_min > 0 else 0

    header = build_header(
        ALGO_IDS[algorithm], filename, original_size, argon2_hash,
        salt, iv_nonce, expiry, hmac_key, len(padding),
    )

    output_path = target_path + ".encrypted"
    with open(output_path, "wb") as f:
        f.write(header + ciphertext)

    print(f"Original size:  {original_size} bytes")
    print(f"Encrypted size: {len(header) + len(ciphertext)} bytes")
    print(f"Algorithm:      {algorithm}")
    if expiry > 0:
        print(f"Expires at:     {expiry} (unix timestamp)")
    else:
        print("Timer:          disabled (password-only)")
    print(f"Output:         {output_path}")

    return output_path


def decrypt_file(encrypted_path, use_password=False, password=None, output_dir=None):
    if not os.path.isfile(encrypted_path):
        print(f"File not found: {encrypted_path}", file=sys.stderr)
        sys.exit(1)

    with open(encrypted_path, "rb") as f:
        data = f.read()

    try:
        hdr = parse_header(data)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)

    # if theres a timer and it hasnt expired yet, block unless --password
    if not use_password and hdr["expiry"] > 0 and time.time() < hdr["expiry"]:
        left = max(0, int(hdr["expiry"] - time.time()))
        print(f"File encrypted for {left // 60}m {left % 60}s more. Use --password to decrypt early.")
        sys.exit(0)

    if password is None:
        password = prompt_password(confirm=False)

    # check hmac first - catches tampering before we even try decryption
    hmac_key = derive_hmac_key(password, hdr["salt"])
    if not check_hmac(hmac_key, hdr["hmac_data"], hdr["stored_hmac"]):
        print("File corrupted or tampered with", file=sys.stderr)
        sys.exit(1)

    # verify the password against the stored argon2 hash
    try:
        _hasher.verify(hdr["argon2_hash"], password)
    except VerifyMismatchError:
        print("Invalid password", file=sys.stderr)
        sys.exit(1)

    algo_name = ALGO_NAMES.get(hdr["algo_id"])
    if not algo_name:
        print("Unknown algorithm", file=sys.stderr)
        sys.exit(1)

    enc_key = derive_key(password, hdr["salt"])
    try:
        decrypted = do_decrypt(algo_name, enc_key, hdr["iv_nonce"], hdr["payload"])
    except Exception:
        print("Decryption failed", file=sys.stderr)
        sys.exit(1)

    # undo the padding and compression
    if hdr["padding_size"] > 0:
        decrypted = decrypted[:-hdr["padding_size"]]
    decompressed = zlib.decompress(decrypted)

    if len(decompressed) != hdr["original_size"]:
        print("Size mismatch - file may be corrupted", file=sys.stderr)
        sys.exit(1)

    if output_dir:
        out = os.path.join(output_dir, hdr["filename"])
    else:
        out = os.path.join(os.path.dirname(encrypted_path), hdr["filename"])

    with open(out, "wb") as f:
        f.write(decompressed)
    print(f"Decrypted: {out}")
    return out


# ---- directory mode (extra requirement) ----

def encrypt_directory(directory, algorithm, size_mb, custom_var, duration_min, password=None):
    if password is None:
        password = prompt_password(confirm=True)

    manifest = {"files": []}
    for root, _, files in os.walk(directory):
        for fname in files:
            if fname.lower().endswith(".exe"):
                fpath = os.path.join(root, fname)
                print(f"\nEncrypting: {fpath}")
                out = encrypt_file(fpath, algorithm, size_mb, custom_var, duration_min, password=password)
                manifest["files"].append({"original": fpath, "encrypted": out})

    manifest_path = os.path.join(directory, "manifest.json")
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"\nManifest: {manifest_path}")
    print(f"Encrypted {len(manifest['files'])} files")


def decrypt_directory(directory, use_password):
    manifest_path = os.path.join(directory, "manifest.json")
    if not os.path.isfile(manifest_path):
        print(f"Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path) as f:
        manifest = json.load(f)

    password = prompt_password(confirm=False)
    for entry in manifest["files"]:
        if os.path.isfile(entry["encrypted"]):
            print(f"\nDecrypting: {entry['encrypted']}")
            decrypt_file(entry["encrypted"], use_password=use_password, password=password)
        else:
            print(f"Skipping (not found): {entry['encrypted']}")


# ---- cli ----

def main():
    parser = argparse.ArgumentParser(
        prog="encrypt-o-matic",
        description="Encrypt and decrypt Windows executables",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a target application")
    enc.add_argument("target_app", nargs="?", help="Path to the target .exe file")
    enc.add_argument("algorithm", help="Encryption algorithm: AES | ChaCha20 | Twofish")
    enc.add_argument("size_mb", type=int, help="File size inflation in MB")
    enc.add_argument("custom_var", help='Custom variable as "start-end"')
    enc.add_argument("duration_min", type=int, help="Encryption duration in minutes (0 = no timer)")
    enc.add_argument("--dir", help="Encrypt all .exe files in directory recursively")

    dec = sub.add_parser("decrypt", help="Decrypt an encrypted application")
    dec.add_argument("encrypted_file", nargs="?", help="Path to the .encrypted file")
    dec.add_argument("--password", action="store_true", help="Decrypt immediately with password")
    dec.add_argument("--dir", help="Decrypt all files from directory manifest")

    args = parser.parse_args()

    if args.command == "encrypt":
        if args.algorithm not in ALGO_IDS:
            print("Valid options: AES, ChaCha20, Twofish", file=sys.stderr)
            sys.exit(1)
        if args.dir:
            encrypt_directory(args.dir, args.algorithm, args.size_mb, args.custom_var, args.duration_min)
        elif not args.target_app:
            print("target_app is required unless --dir is used", file=sys.stderr)
            sys.exit(1)
        else:
            encrypt_file(args.target_app, args.algorithm, args.size_mb, args.custom_var, args.duration_min)

    elif args.command == "decrypt":
        if args.dir:
            decrypt_directory(args.dir, args.password)
        elif not args.encrypted_file:
            print("encrypted_file is required unless --dir is used", file=sys.stderr)
            sys.exit(1)
        else:
            decrypt_file(args.encrypted_file, use_password=args.password)


if __name__ == "__main__":
    main()
