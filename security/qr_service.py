import io
import base64
import re
from PIL import Image
import numpy as np
import qrcode
import cv2

class QRScanError(Exception):
    """Raised when QR code scanning fails or no QR is detected in image."""
    pass

class QRValidationError(Exception):
    """Raised when QR content exceeds capacity or violates safety rules."""
    pass

MAX_QR_CONTENT_LENGTH = 2048  # Maximum safe characters for reliable QR density

def validate_qr_content(content: str) -> dict:
    """
    Validate and classify QR code content.
    Prevents excessively dense QR codes and categorizes payload type.
    """
    if not content or not content.strip():
        raise QRValidationError("QR code content cannot be empty.")
    
    content = content.strip()
    if len(content.encode('utf-8')) > MAX_QR_CONTENT_LENGTH:
        raise QRValidationError(
            f"Content length ({len(content)} characters) exceeds maximum reliable QR density ({MAX_QR_CONTENT_LENGTH} chars)."
        )

    # Classify content type
    if re.match(r'^https?://[^\s/$.?#].[^\s]*$', content, re.IGNORECASE):
        content_type = 'SECURE_LINK'
    elif re.match(r'^[0-9a-fA-F]{64}$', content):  # SHA-256 hash or token
        content_type = 'INTEGRITY_TOKEN'
    elif re.match(r'^[A-Za-z0-9+/=]{40,}$', content):  # Base64 encrypted payload
        content_type = 'ENCRYPTED_PAYLOAD'
    else:
        content_type = 'TEXT_PAYLOAD'

    return {
        'valid': True,
        'type': content_type,
        'char_length': len(content),
        'byte_length': len(content.encode('utf-8'))
    }

def generate_qr_code(content: str, error_correction: str = 'M') -> (bytes, str):
    """
    Generate QR code image bytes and base64 data URI.
    Uses standard QR density with customizable error correction (L, M, Q, H).
    Returns: (png_bytes, base64_data_uri)
    """
    validation = validate_qr_content(content)
    
    ec_levels = {
        'L': qrcode.constants.ERROR_CORRECT_L,
        'M': qrcode.constants.ERROR_CORRECT_M,
        'Q': qrcode.constants.ERROR_CORRECT_Q,
        'H': qrcode.constants.ERROR_CORRECT_H,
    }
    ec_level = ec_levels.get(error_correction.upper(), qrcode.constants.ERROR_CORRECT_M)

    qr = qrcode.QRCode(
        version=None,  # Automatically determine version
        error_correction=ec_level,
        box_size=10,
        border=4,
    )
    qr.add_data(content)
    qr.make(fit=True)

    img = qr.make_image(fill_color="#070b14", back_color="#ffffff")
    
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    png_bytes = buf.getvalue()
    b64_str = base64.b64encode(png_bytes).decode('utf-8')
    data_uri = f"data:image/png;base64,{b64_str}"

    return png_bytes, data_uri

def scan_qr_code(image_bytes: bytes) -> dict:
    """
    Decode and read QR code from image bytes using OpenCV QRCodeDetector.
    Includes adaptive preprocessing for challenging contrast/lighting.
    Returns: {'content': str, 'type': str, 'char_length': int}
    """
    if not image_bytes:
        raise QRScanError("Empty image provided for QR scanning.")

    np_arr = np.frombuffer(image_bytes, np.uint8)
    cv_img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    if cv_img is None:
        raise QRScanError("Failed to decode uploaded image data.")

    detector = cv2.QRCodeDetector()
    decoded_text, bbox, _ = detector.detectAndDecode(cv_img)

    # If initial pass fails, try adaptive contrast enhancement
    if not decoded_text:
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        # Try Otsu thresholding
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        decoded_text, bbox, _ = detector.detectAndDecode(thresh)

    if not decoded_text:
        # Try adaptive thresholding
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        adaptive = cv2.adaptiveThreshold(
            gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 51, 0
        )
        decoded_text, bbox, _ = detector.detectAndDecode(adaptive)

    if not decoded_text:
        raise QRScanError(
            "No readable QR code found in the image. Please ensure the QR code is clear, well-lit, and not corrupted."
        )

    meta = validate_qr_content(decoded_text)
    return {
        'content': decoded_text,
        'type': meta['type'],
        'char_length': meta['char_length'],
        'byte_length': meta['byte_length']
    }

