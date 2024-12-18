from Crypto.PublicKey import DSA
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_KEY_PATH = os.path.join(BASE_DIR, 'dsa_private_key.pem')
PUBLIC_KEY_PATH = os.path.join(BASE_DIR, 'dsa_public_key.pem')

def generate_dsa_keys():
    try:
        key = DSA.generate(2048)
        
        with open(PRIVATE_KEY_PATH, 'wb') as private_file:
            private_file.write(key.export_key(format='PEM'))
            print("Private key generated successfully")

        with open(PUBLIC_KEY_PATH, 'wb') as public_file:
            public_file.write(key.publickey().export_key(format='PEM'))
            print("Public key generated successfully")
            
    except Exception as e:
        print(f"Error generating keys: {str(e)}")

if __name__ == "__main__":
    generate_dsa_keys()
