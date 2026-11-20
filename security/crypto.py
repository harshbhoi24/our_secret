import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

class DecryptionError(Exception):
    """Raised when decryption fails due to invalid password or tampered ciphertext."""
    pass

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERATIONS = 100_000
KEY_LENGTH = 32  # AES-256

# Payload Type Flags for Structured Multi-Format Steganography
PAYLOAD_TYPE_TEXT = 0x01
PAYLOAD_TYPE_FILE = 0x02
PAYLOAD_TYPE_DENIABLE = 0x03

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_bytes(data: bytes, password: str) -> bytes:
    """
    Encrypt arbitrary bytes using authenticated AES-256-GCM.
    Returns: salt (16 bytes) + nonce (12 bytes) + ciphertext_and_tag.
    """
    if not data:
        raise ValueError("Payload data to encrypt cannot be empty.")
    if not password:
        raise ValueError("Encryption password cannot be empty.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext_and_tag = aesgcm.encrypt(nonce, data, associated_data=None)
    return salt + nonce + ciphertext_and_tag

def decrypt_bytes(payload: bytes, password: str) -> bytes:
    """
    Decrypt AES-256-GCM payload and verify authentication tag.
    Returns decrypted raw bytes.
    Raises DecryptionError if authentication tag fails or password is incorrect.
    """
    min_required_len = SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(payload) < min_required_len:
        raise DecryptionError("Corrupted or incomplete ciphertext payload.")

    salt = payload[:SALT_SIZE]
    nonce = payload[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
    ciphertext_and_tag = payload[SALT_SIZE + NONCE_SIZE:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        return aesgcm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
    except InvalidTag:
        raise DecryptionError("Authentication failed: Incorrect password or tampered data.")

def pack_payload(payload_type: str, content: bytes, filename: str = "") -> bytes:
    """
    Pack confidential content into a structured binary envelope:
    - Text: b'\\x01' + utf8_bytes
    - File: b'\\x02' + uint16(filename_len) + utf8(filename) + file_bytes
    """
    if payload_type == 'FILE':
        safe_fn = (filename or "cloaked_secret.bin").encode('utf-8')[:255]
        return bytes([PAYLOAD_TYPE_FILE]) + struct.pack('>H', len(safe_fn)) + safe_fn + content
    else:
        return bytes([PAYLOAD_TYPE_TEXT]) + content

def unpack_payload(decrypted_bytes: bytes) -> dict:
    """
    Unpack decrypted binary envelope.
    Returns dict:
      {'type': 'TEXT'|'FILE', 'text': str, 'filename': str, 'file_bytes': bytes, 'size': int}
    Gracefully falls back to legacy raw text if header flag is not present.
    """
    if len(decrypted_bytes) >= 1:
        flag = decrypted_bytes[0]
        if flag == PAYLOAD_TYPE_TEXT:
            try:
                return {
                    'type': 'TEXT',
                    'text': decrypted_bytes[1:].decode('utf-8'),
                    'filename': None,
                    'file_bytes': None,
                    'size': len(decrypted_bytes) - 1
                }
            except UnicodeDecodeError:
                pass
        elif flag == PAYLOAD_TYPE_FILE and len(decrypted_bytes) >= 3:
            fn_len = struct.unpack('>H', decrypted_bytes[1:3])[0]
            if len(decrypted_bytes) >= 3 + fn_len:
                filename = decrypted_bytes[3:3 + fn_len].decode('utf-8', errors='ignore')
                file_bytes = decrypted_bytes[3 + fn_len:]
                return {
                    'type': 'FILE',
                    'text': None,
                    'filename': filename,
                    'file_bytes': file_bytes,
                    'size': len(file_bytes)
                }

    # Backward compatibility: legacy UTF-8 text fallback
    try:
        return {
            'type': 'TEXT',
            'text': decrypted_bytes.decode('utf-8'),
            'filename': None,
            'file_bytes': None,
            'size': len(decrypted_bytes)
        }
    except UnicodeDecodeError:
        return {
            'type': 'FILE',
            'text': None,
            'filename': 'extracted_file.bin',
            'file_bytes': decrypted_bytes,
            'size': len(decrypted_bytes)
        }

def encrypt_message(plaintext: str, password: str) -> bytes:
    """Convenience wrapper for text strings using the structured envelope."""
    if not plaintext:
        raise ValueError("Plaintext secret message cannot be empty.")
    packed = pack_payload('TEXT', plaintext.encode('utf-8'))
    return encrypt_bytes(packed, password)

def decrypt_message(payload: bytes, password: str) -> str:
    """Convenience wrapper for text strings."""
    raw = decrypt_bytes(payload, password)
    info = unpack_payload(raw)
    if info['type'] == 'TEXT' and info['text'] is not None:
        return info['text']
    elif info['file_bytes'] is not None:
        # Return filename info if it was a file
        return f"[CLOAKED FILE: {info['filename']} ({info['size']} bytes)]"
    raise DecryptionError("Decrypted data is not valid text.")

def encrypt_deniable(real_packed_bytes: bytes, real_password: str, decoy_text: str, decoy_password: str) -> bytes:
    """
    Encrypt two distinct payloads under two different keys for Plausible Deniability:
    - Slot 1: Real payload (text or file envelope) encrypted with real_password
    - Slot 2: Decoy message (text envelope) encrypted with decoy_password (Duress Passcode)
    
    Wire Format:
      b'\x03' + struct.pack('>I', len(ct_real)) + ct_real + struct.pack('>I', len(ct_decoy)) + ct_decoy
    """
    if not real_password or len(real_password) < 6:
        raise ValueError("Real encryption password must be at least 6 characters.")
    if not decoy_password or len(decoy_password) < 6:
        raise ValueError("Decoy (Duress) passcode must be at least 6 characters.")
    if real_password == decoy_password:
        raise ValueError("Decoy passcode cannot be identical to the real password.")
    if not decoy_text or not decoy_text.strip():
        raise ValueError("Decoy secret message cannot be empty.")

    ct_real = encrypt_bytes(real_packed_bytes, real_password)
    decoy_packed = pack_payload('TEXT', decoy_text.strip().encode('utf-8'))
    ct_decoy = encrypt_bytes(decoy_packed, decoy_password)

    envelope = (
        bytes([PAYLOAD_TYPE_DENIABLE]) +
        struct.pack('>I', len(ct_real)) +
        ct_real +
        struct.pack('>I', len(ct_decoy)) +
        ct_decoy
    )
    return envelope

def decrypt_carrier_payload(payload_bytes: bytes, password: str) -> dict:
    """
    Decrypts carrier payload, supporting:
    1. Plausible Deniability Dual-Envelope (PAYLOAD_TYPE_DENIABLE = 0x03)
       - Attempts decryption on Real Slot first. If tag matches -> is_decoy=False.
       - If Real Slot fails, attempts decryption on Decoy Slot. If tag matches -> is_decoy=True.
       - If both fail -> raises DecryptionError.
    2. Single Envelope (PAYLOAD_TYPE_TEXT / FILE or legacy) -> is_decoy=False.
    """
    if len(payload_bytes) >= 9 and payload_bytes[0] == PAYLOAD_TYPE_DENIABLE:
        len1 = struct.unpack('>I', payload_bytes[1:5])[0]
        slot1_end = 5 + len1
        if len(payload_bytes) >= slot1_end + 4:
            slot1 = payload_bytes[5:slot1_end]
            len2 = struct.unpack('>I', payload_bytes[slot1_end:slot1_end + 4])[0]
            slot2 = payload_bytes[slot1_end + 4:slot1_end + 4 + len2]

            # 1. Try Real Slot
            try:
                decrypted = decrypt_bytes(slot1, password)
                unpacked = unpack_payload(decrypted)
                unpacked['is_decoy'] = False
                unpacked['is_deniable'] = True
                return unpacked
            except DecryptionError:
                pass

            # 2. Try Decoy Slot
            try:
                decrypted = decrypt_bytes(slot2, password)
                unpacked = unpack_payload(decrypted)
                unpacked['is_decoy'] = True
                unpacked['is_deniable'] = True
                return unpacked
            except DecryptionError:
                pass

            # Both slots failed authentication tag check
            raise DecryptionError("Authentication failed: Incorrect password or tampered data.")

    # Standard single envelope
    decrypted = decrypt_bytes(payload_bytes, password)
    unpacked = unpack_payload(decrypted)
    unpacked['is_decoy'] = False
    unpacked['is_deniable'] = False
    return unpacked
