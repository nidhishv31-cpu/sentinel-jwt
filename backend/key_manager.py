import uuid
import json
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
import base64

from backend.database import get_connection

def generate_rsa_keypair(key_size=2048) -> tuple[str, str, str]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    kid = str(uuid.uuid4())
    return (kid, private_pem, public_pem)

def store_key(kid, private_pem, public_pem, db_path):
    conn = get_connection(db_path)
    cursor = conn.cursor()
    
    # Retire existing active keys
    cursor.execute("UPDATE signing_keys SET status = 'retired' WHERE status = 'active'")
    
    created_at = datetime.utcnow().isoformat()
    cursor.execute(
        "INSERT INTO signing_keys (kid, algorithm, private_key, public_key, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (kid, "RS256", private_pem, public_pem, "active", created_at)
    )
    conn.commit()
    conn.close()

def get_active_key(db_path) -> dict:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, public_key, private_key, algorithm FROM signing_keys WHERE status = 'active' LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return dict(row)
    return {}

def _base64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def _int_to_base64url(val: int) -> str:
    val_bytes = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return _base64url_encode(val_bytes)

def get_jwks(db_path) -> dict:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, public_key, algorithm FROM signing_keys WHERE status IN ('active', 'retired')")
    rows = cursor.fetchall()
    conn.close()
    
    keys = []
    for row in rows:
        public_pem = row["public_key"].encode('utf-8')
        public_key = serialization.load_pem_public_key(public_pem)
        
        if isinstance(public_key, RSAPublicKey):
            numbers = public_key.public_numbers()
            keys.append({
                "kty": "RSA",
                "kid": row["kid"],
                "use": "sig",
                "alg": row["algorithm"],
                "n": _int_to_base64url(numbers.n),
                "e": _int_to_base64url(numbers.e)
            })
            
    return {"keys": keys}

def rotate_keys(db_path) -> dict:
    kid, private_pem, public_pem = generate_rsa_keypair()
    store_key(kid, private_pem, public_pem, db_path)
    return {"new_kid": kid}

def list_keys(db_path) -> list:
    conn = get_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, algorithm, status, created_at FROM signing_keys ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]
