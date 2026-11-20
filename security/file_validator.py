"""
security/file_validator.py
Enterprise Multi-Layered Suspicious File Detection and Image Verification Module.

Enforces deep defensive inspection for all user-supplied uploads:
1. Suspicious filename detection:
   - Null bytes (\x00).
   - Path traversal attempts (.. , / , \\).
   - Dangerous double or disguised extensions (e.g., .php.png, .png.exe, .sh.bmp).
   - Hidden dot files (.htaccess, .env).
2. File extension & MIME enforcement (.png, .bmp, .jpg, .jpeg).
3. File size constraints (non-zero and <= 16MB).
4. Magic byte signature verification against declared extension and detection of prohibited binaries/scripts.
5. Pillow structural and header integrity verification (identifies corrupted files and invalid stream headers).
6. Decompression bomb (pixel flood) defense: enforces maximum dimension (4096x4096) and maximum pixel threshold (16,000,000 px).
7. Optional ClamAV antivirus integration (checks pyclamd if active).
8. Formal Antivirus Disclaimer: Explicitly clarifies that heuristic file validation does not replace a comprehensive antimalware suite.
"""

import os
import re
from PIL import Image

class FileValidationError(Exception):
    """Raised when an uploaded file fails security validation checks."""
    pass

# Security Limits
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16 Megabytes
MAX_WIDTH = 4096                   # 4096 px
MAX_HEIGHT = 4096                  # 4096 px
MAX_PIXELS = 16_000_000            # 16 Megapixels

# Permitted Extensions
STEGO_ALLOWED_EXTENSIONS = {'.png', '.bmp'}
QR_ALLOWED_EXTENSIONS = {'.png', '.bmp', '.jpg', '.jpeg'}

# Magic byte signatures for authorized image formats
MAGIC_SIGNATURES = {
    '.png': b'\x89PNG\r\n\x1a\n',
    '.bmp': b'BM',
    '.jpg': b'\xff\xd8\xff',
    '.jpeg': b'\xff\xd8\xff',
}

# Signatures of prohibited/dangerous payloads disguised as images
DANGEROUS_MAGIC_SIGNATURES = [
    (b'MZ', 'Windows Executable / DLL (PE binary)'),
    (b'\x7fELF', 'Linux ELF Executable'),
    (b'%PDF', 'PDF Document'),
    (b'PK\x03\x04', 'ZIP / Java Archive / Office Document'),
    (b'PK\x05\x06', 'Empty ZIP Archive'),
    (b'PK\x07\x08', 'Spanned ZIP Archive'),
    (b'Rar!\x1a\x07', 'RAR Archive'),
    (b'7z\xbc\xaf\x27\x1c', '7-Zip Archive'),
    (b'\x1f\x8b', 'GZIP Compressed Data'),
    (b'<!DOCTYPE', 'HTML / Script payload'),
    (b'<html', 'HTML / Script payload'),
    (b'<?php', 'PHP Script payload'),
    (b'#!', 'UNIX Shell Script'),
]

# Patterns for dangerous extensions in double-extension attacks
SUSPICIOUS_EXTENSION_PATTERNS = [
    r'\.(exe|dll|bat|cmd|sh|ps1|vbs|js|php|phtml|py|rb|pl|jar|scr|msi|vbe|wsf|hta)$',
    r'\.(exe|dll|bat|cmd|sh|ps1|vbs|js|php|phtml|py|rb|pl|jar|scr|msi|vbe|wsf|hta)\.',
]

ANTIVIRUS_DISCLAIMER = (
    "SECURITY NOTICE: Our Secret multi-layer file validation strictly enforces format signatures, "
    "MIME constraints, Pillow structural integrity, and decompression bomb defenses. "
    "While this mitigates malicious script embedding, renamed binaries, and malformed image overflows, "
    "it does not constitute an enterprise-grade antimalware or cloud sandbox engine."
)

def check_clamav_status():
    """
    Checks whether a ClamAV daemon is reachable locally or across the network.
    Returns:
        tuple (is_available: bool, status_message: str)
    """
    try:
        import pyclamd
        cd = pyclamd.ClamdAgnostic()
        if cd.ping():
            version = cd.version()
            return True, f"ClamAV Daemon Active ({version})"
    except Exception:
        pass
    return False, "ClamAV daemon not detected; native heuristic inspection active"

def scan_with_clamav_if_available(file_stream):
    """
    Scans the provided file stream using ClamAV if pyclamd is installed and the daemon is online.
    Safely preserves file stream position.
    """
    try:
        import pyclamd
        cd = pyclamd.ClamdAgnostic()
        if cd.ping():
            file_stream.seek(0)
            data = file_stream.read()
            file_stream.seek(0)
            result = cd.scan_stream(data)
            if result:
                virus_name = list(result.values())[0][1]
                raise FileValidationError(f"Malware signature detected by ClamAV: {virus_name}")
    except FileValidationError:
        raise
    except Exception:
        # ClamAV unavailable or network timeout; fallback safely to native heuristic validation
        pass

def validate_uploaded_image(file_storage, allowed_extensions=None, max_size=MAX_FILE_SIZE, allow_corrupt=False):
    """
    Performs comprehensive security inspection on an uploaded file stream.
    
    Args:
        file_storage: Werkzeug FileStorage or file-like object with .filename, .seek, .read, .tell
        allowed_extensions: Set of permitted extensions, e.g. {'.png', '.bmp'}
        max_size: Maximum allowed file size in bytes (default 16MB)
        allow_corrupt: If True (e.g. for integrity verification), permits structurally altered 
                       or tampered image streams while still enforcing filename safety, 
                       size limits, prohibited executable signatures, and magic headers.
        
    Returns:
        dict: Verified metadata {sanitized_filename, original_filename, format, width, height, size_bytes, pixel_count, is_corrupted}
        
    Raises:
        FileValidationError: When any security violation, corrupt structure, or anomaly is detected.
    """
    if file_storage is None:
        raise FileValidationError("No file object was provided for validation.")

    filename = getattr(file_storage, 'filename', '') or ''
    filename = filename.strip()
    if not filename:
        raise FileValidationError("Uploaded file has an empty or missing filename.")

    # 1. Filename security checks
    if '\x00' in filename:
        raise FileValidationError("Suspicious filename rejected: contains forbidden null bytes.")

    if '..' in filename or '/' in filename or '\\' in filename:
        raise FileValidationError("Path traversal sequence rejected in filename.")

    if filename.startswith('.'):
        raise FileValidationError("Hidden dot files are strictly prohibited.")

    lower_name = filename.lower()
    for pattern in SUSPICIOUS_EXTENSION_PATTERNS:
        if re.search(pattern, lower_name):
            raise FileValidationError(
                f"Suspicious filename rejected: dangerous executable or script pattern identified in '{filename}'."
            )

    # Extension validation
    _, ext = os.path.splitext(lower_name)
    if not ext:
        raise FileValidationError(f"File '{filename}' rejected: missing file extension.")

    if allowed_extensions is None:
        allowed_extensions = STEGO_ALLOWED_EXTENSIONS
    allowed_set = {e.lower() for e in allowed_extensions}

    if ext not in allowed_set:
        allowed_list_str = ', '.join(sorted(list(allowed_set)))
        raise FileValidationError(
            f"Unsupported file format '{ext}'. Authorized formats are: {allowed_list_str}."
        )

    # 2. File size constraints
    try:
        file_storage.seek(0, os.SEEK_END)
        file_size = file_storage.tell()
        file_storage.seek(0)
    except Exception as e:
        raise FileValidationError(f"Failed to inspect file stream: {str(e)}")

    if file_size == 0:
        raise FileValidationError("Uploaded file is completely empty (0 bytes).")

    if file_size > max_size:
        max_mb = max_size / (1024 * 1024)
        actual_mb = file_size / (1024 * 1024)
        raise FileValidationError(
            f"File size ({actual_mb:.2f} MB) exceeds maximum allowed limit of {max_mb:.0f} MB."
        )

    # 3. Magic byte signature verification
    header_bytes = file_storage.read(32)
    file_storage.seek(0)

    # Check for prohibited signatures (e.g., EXE, ELF, PDF, ZIP, script disguised as image)
    for bad_sig, desc in DANGEROUS_MAGIC_SIGNATURES:
        if header_bytes.startswith(bad_sig):
            raise FileValidationError(
                f"Prohibited file signature detected ({desc}). File appears to be disguised as an image."
            )

    # Validate signature against declared extension
    expected_sig = MAGIC_SIGNATURES.get(ext)
    if expected_sig and not header_bytes.startswith(expected_sig):
        raise FileValidationError(
            f"Invalid image signature: Declared extension is '{ext}' but internal magic bytes do not match standard {ext.upper()[1:]} format."
        )

    # 4. Pillow structural and header integrity verification
    is_corrupted = False
    try:
        img = Image.open(file_storage)
        declared_format = img.format
        if not declared_format:
            raise FileValidationError("Corrupted image structure: Pillow could not identify valid image format.")
        img.verify()
    except FileValidationError:
        file_storage.seek(0)
        raise
    except Exception as e:
        file_storage.seek(0)
        if allow_corrupt:
            is_corrupted = True
        else:
            raise FileValidationError(f"Corrupted or invalid image structure: {str(e)}")

    # 5. Dimension & Decompression Bomb (Pixel Flood) Check
    width = 0
    height = 0
    pixel_count = 0
    img_format = ext.upper()[1:]

    if not is_corrupted:
        file_storage.seek(0)
        try:
            img = Image.open(file_storage)
            width, height = img.size
            pixel_count = width * height
            img_format = img.format

            if width <= 0 or height <= 0:
                raise FileValidationError(f"Invalid image dimensions: {width}x{height}.")

            if width > MAX_WIDTH or height > MAX_HEIGHT:
                raise FileValidationError(
                    f"Image dimensions ({width}x{height}) exceed maximum allowed limit of {MAX_WIDTH}x{MAX_HEIGHT} pixels."
                )

            if pixel_count > MAX_PIXELS:
                raise FileValidationError(
                    f"Decompression bomb risk: Pixel count ({pixel_count:,} px) exceeds maximum safe limit of {MAX_PIXELS:,} pixels."
                )

            # Check format consistency with extension
            expected_format = 'PNG' if ext == '.png' else ('BMP' if ext == '.bmp' else 'JPEG')
            if img.format != expected_format:
                raise FileValidationError(
                    f"MIME/Format mismatch: Declared extension is '{ext}' but internal image format is '{img.format}'."
                )

        except FileValidationError:
            file_storage.seek(0)
            raise
        except Exception as e:
            file_storage.seek(0)
            if allow_corrupt:
                is_corrupted = True
            else:
                raise FileValidationError(f"Failed to inspect image dimensions: {str(e)}")

    # 6. Optional ClamAV Antivirus inspection
    file_storage.seek(0)
    scan_with_clamav_if_available(file_storage)

    # Reset stream pointer
    file_storage.seek(0)

    from werkzeug.utils import secure_filename
    clean_name = secure_filename(filename)

    return {
        'sanitized_filename': clean_name,
        'original_filename': filename,
        'format': img_format,
        'width': width,
        'height': height,
        'size_bytes': file_size,
        'pixel_count': pixel_count,
        'is_corrupted': is_corrupted,
        'disclaimer': ANTIVIRUS_DISCLAIMER
    }
