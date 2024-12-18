# generate_aes_key.py
from Crypto.Random import get_random_bytes
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AES_KEY_PATH = os.path.join(BASE_DIR, 'aes_key.bin')

def generate_aes_key():
    try:
        aes_key = get_random_bytes(16)
        with open(AES_KEY_PATH, 'wb') as key_file:
            key_file.write(aes_key)
        print("AES key generated successfully")
    except Exception as e:
        print(f"Error generating AES key: {str(e)}")

if __name__ == "__main__":
    generate_aes_key()
