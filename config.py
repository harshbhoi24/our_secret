import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Core Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', 'our-secret-super-secure-key-2026-cyber-vault')
    
    # Server-Side HMAC Secret Key (Never exposed to client)
    HMAC_SECRET_KEY = os.environ.get(
        'OUR_SECRET_HMAC_KEY', 
        'our-secret-server-hmac-sha256-cryptographic-master-key-secure-vault-99'
    )
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL', 
        f"sqlite:///{os.path.join(BASE_DIR, 'our_secret.db')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Upload Configurations
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ORIGINALS_FOLDER = os.path.join(UPLOAD_FOLDER, 'originals')
    STEGO_FOLDER = os.path.join(UPLOAD_FOLDER, 'stego')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB max upload
    ALLOWED_EXTENSIONS = {'png', 'bmp'}
    
    # Security & Session Settings
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Steganography Engine Settings
    MAGIC_HEADER = b'OS01'
    HEADER_SIZE_BYTES = 8
    LEGACY_MAGIC_HEADER = b'OSEC'
    PROTOCOL_VERSION = 1

