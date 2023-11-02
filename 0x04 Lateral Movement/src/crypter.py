# XOR encryption key (replace with your own)
key_hex = "4f130123a70d83b551efed9191e71a30ef5ed5dc660c5cbe8fc468547de2425c62345e470706d3566d046a467b71000160d119efe51a63286d04de4d5cad3159"

# convert the key to bytes
key = bytes.fromhex(key_hex)

# XOR encryption
def xor(data, key):
    encrypted_data = bytearray(len(data))
    for i in range(len(data)):
        encrypted_data[i] = data[i] ^ key[i % len(key)]
        
    return bytes(encrypted_data)

# read binary payload from file
with open("loader.bin", "rb") as f:
    payload = f.read()
    print()

    # Encrypt the payload
    encrypted_payload = xor(payload, key)
    
# save to binary file, make a confusing name
with open("datastore.bin", "wb") as f2:
    f2.write(encrypted_payload)
    
print(f"Key is: {key_hex}")
print(f"[ENCRYPTED_FROM]\r\n{payload[:512]}")
print(f"[ENCRYPTED TO]\r\n{encrypted_payload[:512]}")