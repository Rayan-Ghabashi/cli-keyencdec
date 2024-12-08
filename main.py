from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import argparse
import sys
import hashlib
import ast
def aes_encrypt(text, key):
    # Convert the key to 16, 24, or 32 bytes (for AES-128, AES-192, AES-256)
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    # Create Cipher and Encryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()

    # Pad the text to a multiple of 16 bytes (block size)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    # Encrypt the data
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    return encrypted

def aes_decrypt(ciphertext, key):
    # Convert the key to 16, 24, or 32 bytes (for AES-128, AES-192, AES-256)
    if len(key) not in [16, 24, 32]:
        raise ValueError("Key must be 16, 24, or 32 bytes long")

    # Create Cipher and Decryptor
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted.decode()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Encryption/Decryption Tool")
    parser.add_argument("--mode", type=str, required=True, help="(e)ncode or (d)ecode")
    parser.add_argument("--key", type=str, required=True, help="Encryption/Decryption key")
    parser.add_argument("--text", type=str, required=True, help="Input text to encrypt/decrypt(it must be wrapped in double quotes)")
    args = parser.parse_args()

    mode = args.mode
    key = args.key
    text = args.text

    if mode.lower() == "e":
        encrypted_message = aes_encrypt(text, key)
        print(encrypted_message)  # Output as bytes
    elif mode.lower() == "d":
        # Convert input string back to bytes
        if text.startswith("b'") or text.startswith('b"'):
            text = ast.literal_eval(text)  # Safely convert to bytes
        else:
            raise ValueError("Ciphertext must be in bytes format (e.g., b'...')")
        
        decrypted_message = aes_decrypt(text, key)
        print(decrypted_message)
    else:
        print("Invalid mode. Use 'e' for encryption or 'd' for decryption.")

