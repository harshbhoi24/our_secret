import io
import os
import sys
from PIL import Image
from werkzeug.datastructures import FileStorage

# Ensure project root is in sys.path
sys.path.insert(0, r"C:\Users\Harsh's Laptop\.gemini\antigravity\scratch\our_secret")

from app import create_app
from database import db
from database.models import User, ActivityLog
from security.file_validator import (
    validate_uploaded_image, FileValidationError,
    ANTIVIRUS_DISCLAIMER, check_clamav_status,
    MAX_FILE_SIZE, MAX_WIDTH, MAX_HEIGHT, MAX_PIXELS
)

def create_dummy_png(width=50, height=50, color='red'):
    img = Image.new('RGB', (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)
    return buf

def create_dummy_bmp(width=50, height=50, color='blue'):
    img = Image.new('RGB', (width, height), color=color)
    buf = io.BytesIO()
    img.save(buf, format='BMP')
    buf.seek(0)
    return buf

def create_dummy_jpeg(width=50, height=50):
    img = Image.new('RGB', (width, height), color='green')
    buf = io.BytesIO()
    img.save(buf, format='JPEG')
    buf.seek(0)
    return buf

def test_suspicious_file_detection():
    print("[*] Starting Feature 6: Suspicious File Detection Verification...")

    # -------------------------------------------------------------
    # 1. Valid Files
    # -------------------------------------------------------------
    png_buf = create_dummy_png(100, 100)
    fs_png = FileStorage(stream=png_buf, filename="valid_cover.png", content_type="image/png")
    meta_png = validate_uploaded_image(fs_png)
    assert meta_png['format'] == 'PNG'
    assert meta_png['width'] == 100
    assert meta_png['height'] == 100
    assert meta_png['size_bytes'] > 0
    print("  [+] Valid PNG file passed inspection: PASSED")

    bmp_buf = create_dummy_bmp(80, 60)
    fs_bmp = FileStorage(stream=bmp_buf, filename="valid_carrier.bmp", content_type="image/bmp")
    meta_bmp = validate_uploaded_image(fs_bmp)
    assert meta_bmp['format'] == 'BMP'
    assert meta_bmp['width'] == 80
    assert meta_bmp['height'] == 60
    print("  [+] Valid BMP file passed inspection: PASSED")

    # -------------------------------------------------------------
    # 2. Incorrect / Unsupported Extension
    # -------------------------------------------------------------
    txt_buf = io.BytesIO(b"Just plain text")
    fs_txt = FileStorage(stream=txt_buf, filename="document.txt", content_type="text/plain")
    try:
        validate_uploaded_image(fs_txt)
        assert False, "document.txt should have been rejected"
    except FileValidationError as e:
        assert "Unsupported file format" in str(e)
        print("  [+] Unsupported extension (.txt) rejected: PASSED")

    # -------------------------------------------------------------
    # 3. Suspicious Filenames (Path Traversal, Null Bytes, Double Extensions)
    # -------------------------------------------------------------
    # Path traversal
    png_buf.seek(0)
    fs_trav = FileStorage(stream=png_buf, filename="../../etc/passwd.png")
    try:
        validate_uploaded_image(fs_trav)
        assert False, "Path traversal should have been rejected"
    except FileValidationError as e:
        assert "Path traversal" in str(e)
        print("  [+] Path traversal filename rejected: PASSED")

    # Null byte
    png_buf.seek(0)
    fs_null = FileStorage(stream=png_buf, filename="innocent\x00.png")
    try:
        validate_uploaded_image(fs_null)
        assert False, "Null byte should have been rejected"
    except FileValidationError as e:
        assert "null bytes" in str(e)
        print("  [+] Null byte in filename rejected: PASSED")

    # Dangerous double extension (executable disguise)
    png_buf.seek(0)
    fs_double_exe = FileStorage(stream=png_buf, filename="invoice.exe.png")
    try:
        validate_uploaded_image(fs_double_exe)
        assert False, "Dangerous double extension should have been rejected"
    except FileValidationError as e:
        assert "executable or script" in str(e)
        print("  [+] Dangerous double extension (.exe.png) rejected: PASSED")

    # Script disguise (.php.png)
    png_buf.seek(0)
    fs_double_php = FileStorage(stream=png_buf, filename="shell.php.png")
    try:
        validate_uploaded_image(fs_double_php)
        assert False, "Shell.php.png should have been rejected"
    except FileValidationError as e:
        assert "executable or script" in str(e)
        print("  [+] Dangerous script extension (.php.png) rejected: PASSED")

    # Hidden dot file
    png_buf.seek(0)
    fs_hidden = FileStorage(stream=png_buf, filename=".hidden_image.png")
    try:
        validate_uploaded_image(fs_hidden)
        assert False, "Hidden file should have been rejected"
    except FileValidationError as e:
        assert "Hidden dot files" in str(e)
        print("  [+] Hidden dot file rejected: PASSED")

    # -------------------------------------------------------------
    # 4. Prohibited Magic Signatures Disguised as Images
    # -------------------------------------------------------------
    # Renamed Windows Executable (.exe disguised as .png)
    fake_exe = io.BytesIO(b'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00')
    fs_fake_exe = FileStorage(stream=fake_exe, filename="malware.png")
    try:
        validate_uploaded_image(fs_fake_exe)
        assert False, "Renamed PE executable should have been rejected"
    except FileValidationError as e:
        assert "Prohibited file signature" in str(e) or "PE binary" in str(e)
        print("  [+] Disguised Windows Executable (MZ) rejected: PASSED")

    # Renamed Linux ELF (.elf disguised as .png)
    fake_elf = io.BytesIO(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00')
    fs_fake_elf = FileStorage(stream=fake_elf, filename="payload.png")
    try:
        validate_uploaded_image(fs_fake_elf)
        assert False, "Renamed ELF should have been rejected"
    except FileValidationError as e:
        assert "Prohibited file signature" in str(e) or "ELF" in str(e)
        print("  [+] Disguised Linux ELF Executable rejected: PASSED")

    # Renamed ZIP/Archive (.zip disguised as .png)
    fake_zip = io.BytesIO(b'PK\x03\x04\x14\x00\x00\x00\x08\x00' + b'A' * 20)
    fs_fake_zip = FileStorage(stream=fake_zip, filename="secret.png")
    try:
        validate_uploaded_image(fs_fake_zip)
        assert False, "Renamed ZIP archive should have been rejected"
    except FileValidationError as e:
        assert "Prohibited file signature" in str(e) or "ZIP" in str(e)
        print("  [+] Disguised ZIP/Archive (PK) rejected: PASSED")

    # PHP script disguised as BMP
    fake_php = io.BytesIO(b'<?php echo system($_GET["cmd"]); ?>')
    fs_fake_php = FileStorage(stream=fake_php, filename="backdoor.bmp")
    try:
        validate_uploaded_image(fs_fake_php)
        assert False, "PHP script disguised as BMP should have been rejected"
    except FileValidationError as e:
        assert "Prohibited file signature" in str(e) or "PHP" in str(e)
        print("  [+] Disguised PHP script (<?php) rejected: PASSED")

    # -------------------------------------------------------------
    # 5. MIME / Format Mismatch
    # -------------------------------------------------------------
    # Real JPEG renamed to .png
    jpeg_buf = create_dummy_jpeg(64, 64)
    fs_jpeg_as_png = FileStorage(stream=jpeg_buf, filename="fake_extension.png")
    try:
        validate_uploaded_image(fs_jpeg_as_png)
        assert False, "JPEG disguised as PNG should have been rejected"
    except FileValidationError as e:
        assert "Invalid image signature" in str(e)
        print("  [+] Extension / Magic bytes format mismatch caught: PASSED")

    # -------------------------------------------------------------
    # 6. Corrupted Image Structure
    # -------------------------------------------------------------
    corrupt_png = io.BytesIO(b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR' + b'CORRUPTED_TRUNCATED_CHUNKS')
    fs_corrupt = FileStorage(stream=corrupt_png, filename="broken.png")
    try:
        validate_uploaded_image(fs_corrupt)
        assert False, "Corrupted PNG should have been rejected"
    except FileValidationError as e:
        assert "Corrupted or invalid" in str(e)
        print("  [+] Corrupted/truncated image structure rejected: PASSED")

    # -------------------------------------------------------------
    # 7. Empty (0-byte) File
    # -------------------------------------------------------------
    empty_buf = io.BytesIO(b'')
    fs_empty = FileStorage(stream=empty_buf, filename="zero_byte.png")
    try:
        validate_uploaded_image(fs_empty)
        assert False, "Empty file should have been rejected"
    except FileValidationError as e:
        assert "empty (0 bytes)" in str(e)
        print("  [+] Empty 0-byte file rejected: PASSED")

    # -------------------------------------------------------------
    # 8. Excessive Dimensions & Decompression Bomb (Pixel Flood)
    # -------------------------------------------------------------
    # Test dimension boundaries
    huge_img = Image.new('RGB', (4097, 100), color='white')
    huge_buf = io.BytesIO()
    huge_img.save(huge_buf, format='PNG')
    huge_buf.seek(0)
    fs_huge = FileStorage(stream=huge_buf, filename="oversized_dimension.png")
    try:
        validate_uploaded_image(fs_huge)
        assert False, "Dimensions exceeding 4096px should have been rejected"
    except FileValidationError as e:
        assert "exceed maximum allowed limit of 4096x4096" in str(e)
        print("  [+] Excessive dimension (> 4096px) rejected: PASSED")

    # -------------------------------------------------------------
    # 9. Antivirus Disclaimer Check
    # -------------------------------------------------------------
    assert "not constitute an enterprise-grade antimalware" in ANTIVIRUS_DISCLAIMER
    clam_avail, clam_status = check_clamav_status()
    print(f"  [+] ClamAV check completed (Status: {clam_status}): PASSED")
    print("  [+] Antivirus disclaimer properly documented: PASSED")

    # -------------------------------------------------------------
    # 10. End-to-End Route Integration & Activity Log Blocking Test
    # -------------------------------------------------------------
    print("[*] Testing Flask Route Integration & REJECTED_UPLOAD Activity Logging...")
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.app_context():
        user = User.query.filter_by(username='testuser').first()
        client = app.test_client()

        with client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

        initial_blocked_count = ActivityLog.query.filter_by(operation='REJECTED_UPLOAD').count()

        # Route 1: Post malicious file to /steganography/hide
        evil_file = io.BytesIO(b'MZ' + b'\x00' * 50)
        resp_hide = client.post('/steganography/hide', data={
            'image': (evil_file, 'backdoor.exe.png'),
            'secret_message': 'Classified Secret Text',
            'password': 'SecurePassword123'
        }, follow_redirects=True)

        assert resp_hide.status_code == 200
        html_hide = resp_hide.data.decode('utf-8')
        assert 'Security Alert: Upload Rejected' in html_hide
        print("  [+] /steganography/hide blocked malicious upload with alert: PASSED")

        # Route 2: Post corrupt file to /steganography/extract
        corrupt_png.seek(0)
        resp_extract = client.post('/steganography/extract', data={
            'image': (corrupt_png, 'corrupted_test.png'),
            'password': 'SomePassword'
        }, follow_redirects=True)

        assert resp_extract.status_code == 200
        html_extract = resp_extract.data.decode('utf-8')
        assert 'Security Alert: Upload Rejected' in html_extract
        print("  [+] /steganography/extract blocked corrupt file with alert: PASSED")

        # Route 3: Post renamed file to /steganography/compare
        fake_zip.seek(0)
        valid_png_buf = create_dummy_png(50, 50)
        resp_verify = client.post('/steganography/compare', data={
            'cover_image': (valid_png_buf, 'clean_cover.png'),
            'stego_image': (fake_zip, 'trojan.zip.png')
        }, follow_redirects=True)

        assert resp_verify.status_code == 200
        html_verify = resp_verify.data.decode('utf-8')
        assert 'Security Alert: Upload Rejected' in html_verify
        print("  [+] /steganography/compare blocked prohibited signature with alert: PASSED")

        # Verify that ActivityLog recorded the blocked operations
        new_blocked_count = ActivityLog.query.filter_by(operation='REJECTED_UPLOAD').count()
        assert new_blocked_count >= initial_blocked_count + 3, f"Expected at least 3 new blocked logs, got {new_blocked_count - initial_blocked_count}"
        
        # Verify the details of the latest blocked log
        latest_blocked = ActivityLog.query.filter_by(operation='REJECTED_UPLOAD').order_by(ActivityLog.created_at.desc()).first()
        assert latest_blocked.status == 'BLOCKED'
        assert latest_blocked.user_id == user.id
        print("  [+] ActivityLog recorded REJECTED_UPLOAD events with status BLOCKED: PASSED")

    print("\n[***] ALL FEATURE 6 (SUSPICIOUS FILE DETECTION) TESTS PASSED! [***]\n")

if __name__ == '__main__':
    test_suspicious_file_detection()
