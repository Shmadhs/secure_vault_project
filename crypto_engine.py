import os
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key_super_secure(master_password: str, salt: bytes = None):
    if salt is None:
        salt = os.urandom(32) 
    
    pepper = b"MySecretPepper_NeverStoreThisInTheDatabase!" 
    password_bytes = master_password.encode('utf-8') + pepper
    
    kdf = Argon2id(
        salt=salt,
        length=32,
        iterations=3,
        lanes=4,
        memory_cost=65536,
    )
    
    key = kdf.derive(password_bytes)
    del password_bytes 
    
    return key, salt

def encrypt_password(key: bytes, plaintext_password: str) -> bytes:
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    data_to_encrypt = plaintext_password.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data_to_encrypt, associated_data=None)
    
    return nonce + ciphertext

def decrypt_password(key: bytes, encrypted_bundle: bytes) -> str:
    nonce = encrypted_bundle[:12]
    ciphertext = encrypted_bundle[12:]
    aesgcm = AESGCM(key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    
    return plaintext_bytes.decode('utf-8')

if __name__ == "__main__":
    master_password = "NothingHereLOSER"
    my_key, my_salt = derive_key_super_secure(master_password)
    
    my_bank_password = "WhatAreYouLoookingFor?Boy"
    encrypted_data = encrypt_password(my_key, my_bank_password)
    decrypted_password = decrypt_password(my_key, encrypted_data)
    
    print(f"Master Password: {master_password}")
    print(f"Decrypted Password: {decrypted_password}")
    
    if my_bank_password == decrypted_password:
        print("SUCCESS")