import argparse

parser = argparse.ArgumentParser(description="XOR file crypter")
parser.add_argument("binaryfile", help="Binary file")
parser.add_argument("outfile", help="Out file")
parser.add_argument("key", help="Key file")

args = parser.parse_args()

# XOR encryption key
key_hex = ""

with open(args.key, "r") as f:
  key_hex = f.read()

# convert the key to bytes
key = bytes.fromhex(key_hex)

# XOR encryption
def xor(data, key):
    encrypted_data = bytearray(len(data))
    for i in range(len(data)):
        encrypted_data[i] = data[i] ^ key[i % len(key)]

    return bytes(encrypted_data)

# read binary payload from file
with open(args.binaryfile, "rb") as f:
    payload = f.read()
    print()

    # Encrypt the payload
    encrypted_payload = xor(payload, key)

# save to binary file, make a confusing name
with open(args.outfile, "wb") as f2:
    f2.write(encrypted_payload)

print(f"Key is: {key_hex[:512]}")
print(f"[ENCRYPTED_FROM]\r\n{payload[:512]}")
print(f"[ENCRYPTED TO]\r\n{encrypted_payload[:512]}")