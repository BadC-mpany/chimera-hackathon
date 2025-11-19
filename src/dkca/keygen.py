import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = "keys"
KEY_SIZE = 4096

def generate_key_pair(name: str):
    """Generates an RSA key pair and saves to disk."""
    print(f"Generating {name} key pair ({KEY_SIZE}-bit RSA)...")
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=KEY_SIZE,
    )

    # Serialize Private Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize Public Key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Save files
    with open(os.path.join(KEY_DIR, f"private_{name}.pem"), "wb") as f:
        f.write(private_pem)
    
    with open(os.path.join(KEY_DIR, f"public_{name}.pem"), "wb") as f:
        f.write(public_pem)

    print(f"Saved keys for {name}.")

def main():
    if not os.path.exists(KEY_DIR):
        os.makedirs(KEY_DIR)
        print(f"Created directory: {KEY_DIR}")

    if os.path.exists(os.path.join(KEY_DIR, "private_prime.pem")):
        print("Keys already exist. Skipping generation to prevent overwrite.")
        return

    generate_key_pair("prime")
    generate_key_pair("shadow")
    print("Key generation complete.")

if __name__ == "__main__":
    main()

