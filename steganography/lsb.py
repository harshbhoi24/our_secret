import struct
from io import BytesIO
from PIL import Image
import numpy as np

class StegoCapacityError(Exception):
    """Raised when data to hide exceeds image LSB storage capacity."""
    pass

class InvalidStegoImageError(Exception):
    """Raised when image does not contain valid stego header or is corrupted."""
    pass

MAGIC_HEADER_OS01 = b'OS01'  # Standard 8-byte header: 4-byte magic + 4-byte uint32 length
LEGACY_MAGIC_HEADER = b'OSEC'  # Backward compatibility
HEADER_SIZE_BYTES = 8  # 4 (magic OS01) + 4 (payload length)
HEADER_SIZE_BITS = HEADER_SIZE_BYTES * 8
CRYPTO_OVERHEAD_BYTES = 44  # AES-256-GCM: 16 (salt) + 12 (nonce) + 16 (auth tag)

def load_rgb_image(image_input) -> Image.Image:
    """
    Load an image from filepath, bytes, or BytesIO, and convert to RGB mode.
    Ensures safe handling of palette, RGBA, and grayscale images.
    """
    if isinstance(image_input, (str, bytes, bytearray, BytesIO)):
        if isinstance(image_input, (bytes, bytearray)):
            image_input = BytesIO(image_input)
        img = Image.open(image_input)
    elif isinstance(image_input, Image.Image):
        img = image_input
    else:
        raise ValueError("Unsupported image input type.")

    if img.mode != 'RGB':
        img = img.convert('RGB')
    return img

def calculate_capacity(image_input, message_size_bytes: int = 0) -> dict:
    """
    Calculate the storage capacity of an image for RGB LSB embedding.
    Includes the 8-byte OS01 header overhead and 44-byte AES-GCM crypto overhead.
    Returns comprehensive metrics for real-time UI capacity feedback.
    """
    img = load_rgb_image(image_input)
    width, height = img.size
    total_channels = width * height * 3
    max_total_bytes = total_channels // 8
    max_payload_bytes = max(0, max_total_bytes - HEADER_SIZE_BYTES)
    max_message_chars = max(0, max_payload_bytes - CRYPTO_OVERHEAD_BYTES)
    
    current_size = max(0, int(message_size_bytes))
    remaining_bytes = max_message_chars - current_size
    percentage_used = 0.0
    if max_message_chars > 0:
        percentage_used = round(min(100.0, (current_size / max_message_chars) * 100), 2)
    is_oversized = current_size > max_message_chars

    return {
        'width': width,
        'height': height,
        'dimensions': f"{width}x{height}",
        'total_pixels': width * height,
        'total_channels': total_channels,
        'header_overhead_bytes': HEADER_SIZE_BYTES,
        'header_protocol': 'OS01 (8 bytes)',
        'crypto_overhead_bytes': CRYPTO_OVERHEAD_BYTES,
        'max_total_bytes': max_total_bytes,
        'max_payload_bytes': max_payload_bytes,
        'max_message_chars': max_message_chars,
        'current_message_bytes': current_size,
        'remaining_capacity_bytes': remaining_bytes,
        'percentage_used': percentage_used,
        'is_oversized': is_oversized
    }

def embed_payload(image_input, payload_bytes: bytes, output_path: str = None) -> (Image.Image, dict):
    """
    Embed arbitrary payload bytes into the LSB of image RGB channels using the 8-byte OS01 header.
    Header format: b'OS01' (4 bytes) + uint32 payload_length (4 bytes, big-endian) = 8 bytes.
    Saves lossless PNG image if output_path is provided.
    Returns: (output_PIL_Image, capacity_metadata)
    """
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise TypeError("payload_bytes must be bytes or bytearray.")

    img = load_rgb_image(image_input)
    width, height = img.size
    total_channels = width * height * 3
    max_payload_bytes = (total_channels // 8) - HEADER_SIZE_BYTES

    if len(payload_bytes) > max_payload_bytes:
        raise StegoCapacityError(
            f"Secret data ({len(payload_bytes)} bytes) exceeds image capacity "
            f"({max_payload_bytes} bytes). Use a larger image or shorten the message."
        )

    # 8-byte OS01 header: b'OS01' + 4-byte payload length
    header = MAGIC_HEADER_OS01 + struct.pack('>I', len(payload_bytes))
    full_data = header + payload_bytes

    # Convert full data stream into 1-bit array (MSB to LSB)
    raw_bytes = np.frombuffer(full_data, dtype=np.uint8)
    bits = np.unpackbits(raw_bytes)

    # Flatten image pixels array
    pixels = np.array(img, dtype=np.uint8)
    original_shape = pixels.shape
    flat_pixels = pixels.flatten()

    # Embed bits into least significant bit
    flat_pixels[:len(bits)] = (flat_pixels[:len(bits)] & 0xFE) | bits

    # Reshape back to (H, W, 3)
    stego_pixels = flat_pixels.reshape(original_shape)
    stego_image = Image.fromarray(stego_pixels)

    if output_path:
        stego_image.save(output_path, format='PNG', optimize=False)

    metadata = {
        'width': width,
        'height': height,
        'dimensions': f"{width}x{height}",
        'payload_size_bytes': len(payload_bytes),
        'header_size_bytes': HEADER_SIZE_BYTES,
        'total_embedded_bytes': len(full_data),
        'bits_used': len(bits),
        'total_bits_available': total_channels,
        'utilization_percent': round((len(bits) / total_channels) * 100, 2)
    }

    return stego_image, metadata

def extract_payload(image_input) -> bytes:
    """
    Extract embedded payload bytes from LSB of an image.
    Supports both 8-byte OS01 header and legacy 10-byte OSEC header for backward compatibility.
    Validates magic header and bounds.
    Returns the embedded payload bytes.
    """
    img = load_rgb_image(image_input)
    pixels = np.array(img, dtype=np.uint8).flatten()

    if len(pixels) < HEADER_SIZE_BITS:
        raise InvalidStegoImageError("Image is too small to contain Our Secret data.")

    # First check 8-byte OS01 header (64 bits)
    header_bits_8 = pixels[:HEADER_SIZE_BITS] & 1
    header_bytes_8 = np.packbits(header_bits_8).tobytes()

    magic = header_bytes_8[:4]
    
    if magic == MAGIC_HEADER_OS01:
        # 8-byte OS01 format: b'OS01' + 4-byte length
        payload_length = struct.unpack('>I', header_bytes_8[4:8])[0]
        header_offset_bits = HEADER_SIZE_BITS
    elif magic == LEGACY_MAGIC_HEADER:
        # Legacy 10-byte OSEC format: b'OSEC' + ver(1) + flags(1) + len(4) = 80 bits
        if len(pixels) < 80:
            raise InvalidStegoImageError("Image is too small for legacy Our Secret header.")
        header_bits_10 = pixels[:80] & 1
        header_bytes_10 = np.packbits(header_bits_10).tobytes()
        payload_length = struct.unpack('>I', header_bytes_10[6:10])[0]
        header_offset_bits = 80
    else:
        raise InvalidStegoImageError(
            "No valid 'Our Secret' steganographic watermark found in this image."
        )

    total_data_bits = payload_length * 8
    required_total_bits = header_offset_bits + total_data_bits

    if required_total_bits > len(pixels):
        raise InvalidStegoImageError(
            "Header specifies a payload larger than available image data. The file may be truncated or corrupted."
        )

    # Extract payload bits
    payload_bits = pixels[header_offset_bits:required_total_bits] & 1
    payload_bytes = np.packbits(payload_bits).tobytes()

    return payload_bytes
