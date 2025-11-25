from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# 1. User A generates RSA keys
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save keys
with open("public_key.pem", "wb") as f:
    f.write(public_key)

with open("private_key.pem", "wb") as f:
    f.write(private_key)

# 2. User B writes a message
with open("message.txt", "r") as f:
    message = f.read().encode()

# Generate AES key
aes_key = get_random_bytes(32)  # AES-256
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

# Save encrypted message
with open("encrypted_message.bin", "wb") as f:
    f.write(cipher_aes.nonce + tag + ciphertext)

# Encrypt AES key using RSA
rsa_public = RSA.import_key(open("public_key.pem").read())
cipher_rsa = PKCS1_OAEP.new(rsa_public)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# 3. User A decrypts AES key
rsa_private = RSA.import_key(open("private_key.pem").read())
cipher_rsa_dec = PKCS1_OAEP.new(rsa_private)

with open("aes_key_encrypted.bin", "rb") as f:
    encrypted_aes_key = f.read()

decrypted_aes_key = cipher_rsa_dec.decrypt(encrypted_aes_key)

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# 1. User A generates RSA keys
key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Save keys
with open("public_key.pem", "wb") as f:
    f.write(public_key)

with open("private_key.pem", "wb") as f:
    f.write(private_key)

# 2. User B writes a message
with open("message.txt", "r") as f:
    message = f.read().encode()

# Generate AES key
aes_key = get_random_bytes(32)  # AES-256
cipher_aes = AES.new(aes_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

# Save encrypted message
with open("encrypted_message.bin", "wb") as f:
    f.write(cipher_aes.nonce + tag + ciphertext)

# Encrypt AES key using RSA
rsa_public = RSA.import_key(open("public_key.pem").read())
cipher_rsa = PKCS1_OAEP.new(rsa_public)
encrypted_aes_key = cipher_rsa.encrypt(aes_key)

with open("aes_key_encrypted.bin", "wb") as f:
    f.write(encrypted_aes_key)

# 3. User A decrypts AES key
rsa_private = RSA.import_key(open("private_key.pem").read())
cipher_rsa_dec = PKCS1_OAEP.new(rsa_private)

with open("aes_key_encrypted.bin", "rb") as f:
    encrypted_aes_key = f.read()

decrypted_aes_key = cipher_rsa_dec.decrypt(encrypted_aes_key)

# Decrypt AES message
with open("encrypted_message.bin", "rb") as f:
    data = f.read()

nonce = data[:16]
tag = data[16:32]
ciphertext = data[32:]

cipher_dec = AES.new(decrypted_aes_key, AES.MODE_EAX, nonce)
plaintext = cipher_dec.decrypt_and_verify(ciphertext, tag)

with open("decrypted_message.txt", "w") as f:
    f.write(plaintext.decode())

print("Encryption + Decryption Successful!")
