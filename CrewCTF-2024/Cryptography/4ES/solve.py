from hashlib import sha256
from random import choices
import itertools
import json
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

start_time = time.time()

def decrypt_aes_ecb(key: bytes, ciphertext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext

pt = "4145535f4145535f4145535f41455321"
ct = "edb43249be0d7a4620b9b876315eb430"

pt_bytes = bytes.fromhex(pt)
ct_bytes = bytes.fromhex(ct)

# generate keys SHA256 table
print("[!] Generate hash key table...")
chars = b'crew_AES*4=$!?'
L = 3

combinations = list(itertools.product(chars, repeat=L))
combinations_bytes = [bytes(combo) for combo in combinations]

keys_sha256_table = {}  # length 2744
for c in combinations_bytes:
    keys_sha256_table[c] = sha256(c).digest()

# encryption double
print("[!] Generate encryption table...")
encryption_table = {}
for k1, v1 in keys_sha256_table.items():
    pt1 = encrypt_aes_ecb(key=v1, plaintext=pt_bytes)
    for k2, v2 in keys_sha256_table.items():
        pt2 = encrypt_aes_ecb(key=v2, plaintext=pt1)
        encryption_table[pt2] = [k1, k2]

# decryption double
print("[!] Generate decryption table...")
decryption_table = {}
for k4, v4 in keys_sha256_table.items():
    pt3 = decrypt_aes_ecb(key=v4, ciphertext=ct_bytes)
    for k3, v3 in keys_sha256_table.items():
        pt2 = decrypt_aes_ecb(key=v3, ciphertext=pt3)
        decryption_table[pt2] = [k4, k3]  # Corrected here

print("[!] Wait for intersections")
encryption_table_set = set(encryption_table.keys())
decryption_table_set = set(decryption_table.keys())
intersection = encryption_table_set.intersection(decryption_table_set)

if not intersection:
    print("[!] No intersection found.")
else:
    meet = next(iter(intersection))
    encryption_key = encryption_table[meet]
    decryption_key = decryption_table[meet]
    print(f"[*] Encryption key: {encryption_key}")
    print(f"[*] Decryption key: {decryption_key}")

    # Example encrypted flag (replace with actual value)
    enc_flag = "e5218894e05e14eb7cc27dc2aeed10245bfa4426489125a55e82a3d81a15d18afd152d6c51a7024f05e15e1527afa84b"
    enc_flag_bytes = bytes.fromhex(enc_flag)

    # Generate key for AES decryption
    key_flag = sha256(encryption_key[0] + encryption_key[1] + decryption_key[1] + decryption_key[0]).digest()
    print(f"[*] Got key for flag: {key_flag.hex()}")

    # Decrypt the flag
    cipher = AES.new(key_flag, AES.MODE_ECB)
    ciphertext = enc_flag_bytes  # Use enc_flag_bytes as ciphertext
    try:
        padded_plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(padded_plaintext, AES.block_size)
        print(f"Flag: {plaintext.decode()}")
    except (ValueError, KeyError) as e:
        print(f"Decryption error: {e}")

# Duration
end_time = time.time()
duration_seconds = end_time - start_time
duration_minutes = duration_seconds / 60
print(f"Duration: {duration_minutes:.2f} minutes")
