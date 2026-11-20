"""
steganography/steganalysis.py
-----------------------------
Defense-Grade Visual Steganalysis & Difference Heatmap Inspector.
Calculates Peak Signal-to-Noise Ratio (PSNR), Mean Squared Error (MSE), 
Bit Error Rate (BER), and generates amplified visual pixel delta heatmaps.
"""

import io
import base64
import numpy as np
from PIL import Image

def analyze_steganography(original_img_or_bytes, stego_img_or_bytes) -> dict:
    """
    Perform forensic steganalysis comparing an original cover image to its stego carrier.
    
    Returns:
        dict: Forensic metrics (MSE, PSNR, Changed Pixels, Flipped Bits) and
              base64-encoded Data URIs for Cover, Stego, and Amplified Heatmap.
    """
    # 1. Load PIL RGB images
    if isinstance(original_img_or_bytes, (bytes, bytearray)):
        orig_pil = Image.open(io.BytesIO(original_img_or_bytes)).convert('RGB')
    else:
        orig_pil = original_img_or_bytes.convert('RGB')

    if isinstance(stego_img_or_bytes, (bytes, bytearray)):
        stego_pil = Image.open(io.BytesIO(stego_img_or_bytes)).convert('RGB')
    else:
        stego_pil = stego_img_or_bytes.convert('RGB')

    if orig_pil.size != stego_pil.size:
        raise ValueError(
            f"Image dimension mismatch: Cover is {orig_pil.size[0]}x{orig_pil.size[1]} px, "
            f"Stego is {stego_pil.size[0]}x{stego_pil.size[1]} px. Both images must have identical dimensions."
        )

    width, height = orig_pil.size
    total_pixels = width * height
    total_channel_values = total_pixels * 3
    total_bits = total_channel_values * 8

    # 2. Convert to numpy arrays for high-performance vectorized operations
    arr_orig = np.array(orig_pil, dtype=np.int16)
    arr_stego = np.array(stego_pil, dtype=np.int16)

    # 3. Calculate difference matrix
    diff = arr_orig - arr_stego
    abs_diff = np.abs(diff)

    # 4. Mean Squared Error (MSE)
    mse = float(np.mean(diff ** 2))

    # 5. Peak Signal-to-Noise Ratio (PSNR in dB)
    if mse == 0.0:
        psnr = 99.99
        psnr_str = "∞ (Identical / Zero Distortion)"
        psnr_eval = "Perfect Covert Match (No Modification)"
    else:
        psnr = float(10.0 * np.log10((255.0 ** 2) / mse))
        psnr_str = f"{psnr:.2f} dB"
        if psnr >= 65.0:
            psnr_eval = "Defense-Grade Imperceptible (>65 dB)"
        elif psnr >= 45.0:
            psnr_eval = "Standard Undetectable to Human Eye (>45 dB)"
        elif psnr >= 30.0:
            psnr_eval = "Acceptable Covert Quality (30-45 dB)"
        else:
            psnr_eval = "High Forensic Distortion (<30 dB)"

    # 6. Altered pixels (pixels where at least one channel changed)
    pixel_changed_mask = np.any(abs_diff > 0, axis=2)
    changed_pixels = int(np.sum(pixel_changed_mask))
    changed_pixel_pct = (changed_pixels / total_pixels) * 100.0 if total_pixels > 0 else 0.0

    # 7. Bit-level differences (XOR bit count)
    xor_diff = np.bitwise_xor(np.array(orig_pil, dtype=np.uint8), np.array(stego_pil, dtype=np.uint8))
    changed_bits = int(np.sum(np.unpackbits(xor_diff)))
    changed_bit_pct = (changed_bits / total_bits) * 100.0 if total_bits > 0 else 0.0

    # 8. Generate Amplified Visual Difference Heatmap
    # Base: Cyber Midnight Slate [10, 15, 26]
    # Altered LSBs: Fluorescent Electric Cyan [0, 240, 255] with red intensity for higher deltas
    heatmap_arr = np.full((height, width, 3), [10, 15, 26], dtype=np.uint8)
    
    # Highlight altered pixels with high visibility
    max_channel_delta = np.max(abs_diff, axis=2)
    # Standard 1-bit LSB flip has delta == 1 -> highlight in bright cyan
    # Higher deltas highlight in bright amber/red
    cyan_mask = pixel_changed_mask & (max_channel_delta <= 1)
    high_mask = pixel_changed_mask & (max_channel_delta > 1)
    
    heatmap_arr[cyan_mask] = [0, 240, 255]      # Fluorescent Electric Cyan
    heatmap_arr[high_mask] = [255, 75, 75]      # Warning Coral/Red for multi-bit flips

    heatmap_pil = Image.fromarray(heatmap_arr)

    # 9. Helper to convert PIL to Base64 PNG data-URI
    def to_base64_png(pil_img, max_dim=900):
        preview = pil_img.copy()
        if preview.width > max_dim or preview.height > max_dim:
            preview.thumbnail((max_dim, max_dim), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        preview.save(buf, format='PNG', optimize=True)
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode('ascii')

    return {
        'width': width,
        'height': height,
        'dimensions': f"{width} × {height} px",
        'total_pixels': total_pixels,
        'changed_pixels': changed_pixels,
        'changed_pixel_pct': round(changed_pixel_pct, 4),
        'total_bits': total_bits,
        'changed_bits': changed_bits,
        'changed_bit_pct': round(changed_bit_pct, 4),
        'mse': round(mse, 6),
        'psnr': round(psnr, 2) if isinstance(psnr, float) else psnr,
        'psnr_str': psnr_str,
        'psnr_eval': psnr_eval,
        'heatmap_b64': to_base64_png(heatmap_pil),
        'cover_b64': to_base64_png(orig_pil),
        'stego_b64': to_base64_png(stego_pil)
    }
