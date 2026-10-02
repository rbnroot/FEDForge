import os
import json
import base64
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class KeyManager:
    
    def __init__(self, key_dir="./keys"):
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(exist_ok=True)
        self.private_key_path = self.key_dir / "private.pem"
        self.public_key_path = self.key_dir / "public.pem"
        self.kid = "key-1"  # Key ID for JWKS. Can be modified on key rotation
        
    def generate_keys(self):
        print("[+] Generating RSA key pair...")
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        self.private_key_path.write_bytes(pem_private)
        
        public_key = private_key.public_key()
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.public_key_path.write_bytes(pem_public)
        
        print(f"[+] Private key saved to {self.private_key_path}")
        print(f"[+] Public key saved to {self.public_key_path}")
        
        return private_key, public_key
    
    def load_keys(self):
        """Load existing RSA key pair"""
        if not self.private_key_path.exists():
            return self.generate_keys()
        
        print("[+] Loading existing RSA key pair...")
        
        pem_private = self.private_key_path.read_bytes()
        private_key = serialization.load_pem_private_key(
            pem_private,
            password=None,
            backend=default_backend()
        )
        
        pem_public = self.public_key_path.read_bytes()
        public_key = serialization.load_pem_public_key(
            pem_public,
            backend=default_backend()
        )
        
        return private_key, public_key
    
    def get_jwks(self, public_key):
        public_numbers = public_key.public_numbers()
        
        def int_to_base64url(num):
            num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
            return base64.urlsafe_b64encode(num_bytes).decode('utf-8').rstrip('=')
        
        n = int_to_base64url(public_numbers.n)  
        e = int_to_base64url(public_numbers.e)  
        
        jwks = {
            "keys": [
                {
                    "kty": "RSA",
                    "use": "sig",
                    "kid": self.kid,
                    "alg": "RS256",
                    "n": n,
                    "e": e
                }
            ]
        }
        
        return jwks
    
    def get_private_key(self):
        private_key, _ = self.load_keys()
        return private_key
    
    def get_public_key(self):
        _, public_key = self.load_keys()
        return public_key