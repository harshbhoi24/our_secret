import hashlib
import hmac
import os
from config import Config

def get_server_hmac_key() -> bytes:
    """Retrieve the server-side HMAC master key."""
    key = os.environ.get('OUR_SECRET_HMAC_KEY', Config.HMAC_SECRET_KEY)
    return key.encode('utf-8')

def calculate_sha256(data: bytes) -> str:
    """Calculate SHA-256 hex digest for given bytes."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

def calculate_file_sha256(filepath: str) -> str:
    """Calculate SHA-256 hex digest for a file on disk."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()

def calculate_hmac_sha256(data: bytes, key: bytes = None) -> str:
    """Calculate HMAC-SHA256 hex digest using the server secret key."""
    if key is None:
        key = get_server_hmac_key()
    elif isinstance(key, str):
        key = key.encode('utf-8')
    h = hmac.new(key, data, hashlib.sha256)
    return h.hexdigest()

def calculate_file_hmac(filepath: str, key: bytes = None) -> str:
    """Calculate HMAC-SHA256 hex digest for a file on disk."""
    if key is None:
        key = get_server_hmac_key()
    elif isinstance(key, str):
        key = key.encode('utf-8')
    h = hmac.new(key, digestmod=hashlib.sha256)
    with open(filepath, 'rb') as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()

def verify_hmac_sha256(data: bytes, expected_hmac: str, key: bytes = None) -> bool:
    """
    Verify HMAC-SHA256 signature using constant-time comparison.
    Prevents timing attack vulnerabilities.
    """
    calculated = calculate_hmac_sha256(data, key)
    return hmac.compare_digest(calculated.lower(), expected_hmac.lower())

def verify_file_hmac(filepath: str, expected_hmac: str, key: bytes = None) -> bool:
    """Verify file HMAC-SHA256 against expected signature."""
    calculated = calculate_file_hmac(filepath, key)
    return hmac.compare_digest(calculated.lower(), expected_hmac.lower())

