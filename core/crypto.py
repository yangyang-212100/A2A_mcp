"""
Cryptographic utilities for signature generation and verification.
Simulates SM2/ECC signature using cryptography library.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.backends import default_backend
import base64
import json


class KeyPair:
    """Key pair generation and management for Agent signing."""
    
    def __init__(self):
        """Generate a new ECC key pair (simulating SM2)."""
        self._private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self._public_key = self._private_key.public_key()
    
    @property
    def private_key(self) -> EllipticCurvePrivateKey:
        """Get the private key."""
        return self._private_key
    
    @property
    def public_key(self) -> EllipticCurvePublicKey:
        """Get the public key."""
        return self._public_key
    
    def private_key_bytes(self) -> bytes:
        """Serialize private key to PEM format."""
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def public_key_bytes(self) -> bytes:
        """Serialize public key to PEM format."""
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def public_key_pem(self) -> str:
        """Get public key as PEM string."""
        return self.public_key_bytes().decode('utf-8')
    
    @staticmethod
    def from_private_key_bytes(private_key_pem: bytes) -> 'KeyPair':
        """Create KeyPair from serialized private key."""
        key_pair = KeyPair.__new__(KeyPair)
        key_pair._private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=default_backend()
        )
        key_pair._public_key = key_pair._private_key.public_key()
        return key_pair


def sign(data: str, private_key: EllipticCurvePrivateKey) -> str:
    """
    Sign data using ECC private key (simulating SM2).
    
    Args:
        data: The data string to sign
        private_key: The private key for signing
        
    Returns:
        Base64-encoded signature string
    """
    # Convert string to bytes
    data_bytes = data.encode('utf-8')
    
    # Sign using ECDSA with SHA256
    signature = private_key.sign(
        data_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    
    # Return base64-encoded signature
    return base64.b64encode(signature).decode('utf-8')


def verify(data: str, signature: str, public_key: EllipticCurvePublicKey) -> bool:
    """
    Verify signature using ECC public key (simulating SM2).
    
    Args:
        data: The original data string
        signature: Base64-encoded signature string
        public_key: The public key for verification
        
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Decode signature from base64
        signature_bytes = base64.b64decode(signature.encode('utf-8'))
        
        # Convert data string to bytes
        data_bytes = data.encode('utf-8')
        
        # Verify signature
        public_key.verify(
            signature_bytes,
            data_bytes,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False

