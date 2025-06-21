def xor_decrypt(data, key):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

cipher = "LDDLap^Y^p"
key = "kR[j"

result = xor_decrypt(cipher, key)
print("[+] Decrypted:", result)
