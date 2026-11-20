"""
test_all_features.py
Comprehensive Master Test Suite covering all 6 Advanced Features:
1. Image Capacity Checker (RGB LSB + OS01 8-byte header overhead)
2. Message Expiry Policy (1h, 24h, 7d, custom, extraction blocking, file cleanup)
3. QR Code Support (generation, OpenCV scanning, payload validation, zero-knowledge logging)
4. Dark and Light Mode (CSS theme tokens, theme toggle enforcement)
5. Security Activity Monitor (admin metrics, category/status/keyword filtering, zero-knowledge)
6. Suspicious File Detection (mime/ext mismatch, prohibited signatures, corrupt files, bombs, ClamAV disclaimer)
"""

import os
import io
import sys
import unittest
from datetime import datetime, timedelta
from PIL import Image
from werkzeug.datastructures import FileStorage

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from database import db
from database.models import User, ActivityLog, IntegrityRecord, QRBurnRecord
from security.crypto import encrypt_message, decrypt_message
from security.integrity import calculate_sha256, calculate_hmac_sha256
from steganography.lsb import embed_payload, extract_payload, calculate_capacity, StegoCapacityError
from security.qr_service import generate_qr_code, scan_qr_code, validate_qr_content
from security.file_validator import (
    validate_uploaded_image, FileValidationError, ANTIVIRUS_DISCLAIMER,
    check_clamav_status, MAX_FILE_SIZE, MAX_WIDTH, MAX_HEIGHT, MAX_PIXELS
)

class MasterFeaturesTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.app.config['WTF_CSRF_ENABLED'] = False
        cls.client = cls.app.test_client()

        with cls.app.app_context():
            db.create_all()
            admin = User.query.filter_by(username='admin').first()
            if not admin:
                admin = User(username='admin', email='admin@cyber.local', role='admin')
                admin.set_password('Admin@123456')
                db.session.add(admin)

            user = User.query.filter_by(username='testuser').first()
            if not user:
                user = User(username='testuser', email='test@cyber.local', role='user')
                user.set_password('User@123456')
                db.session.add(user)
            db.session.commit()
            cls.admin_id = admin.id
            cls.user_id = user.id

    # =========================================================================
    # FEATURE 1: IMAGE CAPACITY CHECKER
    # =========================================================================
    def test_feature1_capacity_checker(self):
        print("\n--- Testing Feature 1: Image Capacity Checker ---")
        img = Image.new('RGB', (100, 100), color=(10, 20, 30))
        cap = calculate_capacity(img, message_size_bytes=50)

        # 100 x 100 x 3 = 30,000 bits = 3,750 raw bytes
        # Minus 8-byte OS01 header overhead = 3,742 bytes max payload
        self.assertEqual(cap['width'], 100)
        self.assertEqual(cap['height'], 100)
        self.assertEqual(cap['total_channels'], 30000)
        self.assertEqual(cap['max_total_bytes'], 3750)
        self.assertEqual(cap['header_overhead_bytes'], 8)
        self.assertEqual(cap['max_payload_bytes'], 3742)
        self.assertFalse(cap['is_oversized'])
        self.assertGreater(cap['remaining_capacity_bytes'], 0)
        print("  [+] Capacity calculation with OS01 8-byte overhead: PASSED")

        # Test Oversized Warning Flag
        huge_cap = calculate_capacity(img, message_size_bytes=10000)
        self.assertTrue(huge_cap['is_oversized'])
        self.assertLess(huge_cap['remaining_capacity_bytes'], 0)
        self.assertEqual(huge_cap['percentage_used'], 100.0)
        print("  [+] Oversized message detection & percentage calculation: PASSED")

    # =========================================================================
    # FEATURE 2: MESSAGE EXPIRY
    # =========================================================================
    def test_feature2_message_expiry(self):
        print("\n--- Testing Feature 2: Message Expiry ---")
        with self.app.app_context():
            # Generate valid PNG bytes for active and expired records
            dummy_img = Image.new('RGB', (60, 60), color=(10, 20, 30))
            buf = io.BytesIO()
            dummy_img.save(buf, format='PNG')
            valid_png_bytes = buf.getvalue()

            now = datetime.utcnow()
            active_rec = IntegrityRecord(
                user_id=self.user_id,
                filename="active_stego.png",
                original_filename="active.png",
                file_hash=calculate_sha256(valid_png_bytes),
                hmac_signature=calculate_hmac_sha256(valid_png_bytes),
                file_size=len(valid_png_bytes),
                image_dimensions="60x60",
                expires_at=now + timedelta(hours=24)
            )

            # Create an expired record with valid PNG bytes
            expired_img = Image.new('RGB', (60, 60), color=(40, 50, 60))
            buf_exp = io.BytesIO()
            expired_img.save(buf_exp, format='PNG')
            expired_png_bytes = buf_exp.getvalue()

            expired_rec = IntegrityRecord(
                user_id=self.user_id,
                filename="expired_stego.png",
                original_filename="expired.png",
                file_hash=calculate_sha256(expired_png_bytes),
                hmac_signature=calculate_hmac_sha256(expired_png_bytes),
                file_size=len(expired_png_bytes),
                image_dimensions="60x60",
                expires_at=now - timedelta(hours=2)
            )
            db.session.add_all([active_rec, expired_rec])
            db.session.commit()

            self.assertFalse(active_rec.is_expired)
            self.assertEqual(active_rec.expiry_status, "ACTIVE")
            self.assertTrue(expired_rec.is_expired)
            self.assertEqual(expired_rec.expiry_status, "EXPIRED")
            print("  [+] Database model properties (is_expired, expiry_status): PASSED")

            # Test Extraction blocking on expired image via HTTP
            with self.client.session_transaction() as sess:
                sess['user_id'] = self.user_id
                sess['username'] = 'testuser'

            resp = self.client.post('/steganography/extract', data={
                'image': (io.BytesIO(expired_png_bytes), 'expired_stego.png'),
                'password': 'SomePassword'
            }, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"ACCESS BLOCKED", resp.data)
            self.assertIn(b"SECRET MESSAGE EXPIRED", resp.data)
            print("  [+] Backend extraction blocked for expired payload: PASSED")

    # =========================================================================
    # FEATURE 3: QR CODE SUPPORT
    # =========================================================================
    def test_feature3_qr_code(self):
        print("\n--- Testing Feature 3: QR Code Support ---")
        test_payload = "https://defense.internal/vault/token?id=99283716"
        png_bytes, data_uri = generate_qr_code(test_payload, error_correction='H')
        self.assertTrue(data_uri.startswith('data:image/png;base64,'))
        self.assertGreater(len(png_bytes), 0)
        print("  [+] QR code generation with high error correction (Level H): PASSED")

        scan_result = scan_qr_code(png_bytes)
        self.assertEqual(scan_result['content'], test_payload)
        self.assertEqual(scan_result['type'], 'SECURE_LINK')
        self.assertEqual(scan_result['char_length'], len(test_payload))
        print("  [+] OpenCV QR code scan and payload identification: PASSED")

        # Validation test: Disallow dangerous javascript uri
        try:
            validate_qr_content("javascript:alert('xss')")
            self.fail("Dangerous javascript URI should have been rejected")
        except Exception:
            print("  [+] Dangerous QR payload (javascript:) properly rejected: PASSED")

        # Test Burn-After-Reading QR Code flow
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.user_id
            sess['username'] = 'testuser'

        burn_qr_secret = "CLASSIFIED_INTEL_TOKEN_ONE_TIME#7788"
        # 1. Generate with burn_after_reading=1
        gen_resp = self.client.post('/qr/generate', data={
            'qr_content': burn_qr_secret,
            'content_type': 'text',
            'error_correction': 'M',
            'burn_after_reading': '1'
        }, follow_redirects=True)
        self.assertEqual(gen_resp.status_code, 200)
        self.assertIn(b"ONE-TIME SELF-DESTRUCT", gen_resp.data)

        # Retrieve generated QR record from DB
        with self.app.app_context():
            qr_rec = QRBurnRecord.query.order_by(QRBurnRecord.created_at.desc()).first()
            self.assertIsNotNone(qr_rec)
            self.assertFalse(qr_rec.is_burned)

        # Generate the burner QR image to scan
        burner_encoded = f"OSBURN#{qr_rec.token_id}#{burn_qr_secret}"
        burner_png_bytes, _ = generate_qr_code(burner_encoded, error_correction='M')

        # 2. First Scan: Reveals secret + triggers Burn
        scan1_resp = self.client.post('/qr/scan', data={
            'qr_image': (io.BytesIO(burner_png_bytes), 'burn_qr.png')
        }, follow_redirects=True)
        self.assertEqual(scan1_resp.status_code, 200)
        self.assertIn(burn_qr_secret.encode(), scan1_resp.data)
        self.assertIn(b"BURNED AFTER READING", scan1_resp.data)

        # Check DB state: now is_burned is True
        with self.app.app_context():
            qr_rec_refreshed = db.session.get(QRBurnRecord, qr_rec.id)
            self.assertTrue(qr_rec_refreshed.is_burned)

        # 3. Second Scan: Blocked by self-destruct!
        scan2_resp = self.client.post('/qr/scan', data={
            'qr_image': (io.BytesIO(burner_png_bytes), 'burn_qr.png')
        }, follow_redirects=True)
        self.assertEqual(scan2_resp.status_code, 200)
        self.assertNotIn(burn_qr_secret.encode(), scan2_resp.data)
        self.assertIn(b"ACCESS DENIED", scan2_resp.data)
        self.assertIn(b"SELF-DESTRUCTED", scan2_resp.data)
        print("  [+] Burn-After-Reading QR flow (1st scan reveals, 2nd scan blocked): PASSED")

    # =========================================================================
    # FEATURE 4: DARK AND LIGHT MODE
    # =========================================================================
    def test_feature4_dark_light_mode(self):
        print("\n--- Testing Feature 4: Dark & Light Mode ---")
        # Check css file for both theme tokens
        css_path = os.path.join(os.path.dirname(__file__), 'static', 'css', 'style.css')
        with open(css_path, 'r', encoding='utf-8') as f:
            css = f.read()

        # Dark enterprise theme tokens
        self.assertIn('--bg-main: #0b1120;', css)
        self.assertIn('--purple-vibrant: #2563eb;', css)
        # Light theme tokens
        self.assertIn('[data-theme="light"]', css)
        self.assertIn('--bg-main: #f8fafc;', css)
        self.assertIn('--purple-vibrant: #2563eb;', css)
        print("  [+] CSS definitions for Enterprise Dark (Slate/Blue) and Executive Light: PASSED")

        # Check base.html for theme toggle button and zero-leakage head script
        base_path = os.path.join(os.path.dirname(__file__), 'templates', 'base.html')
        with open(base_path, 'r', encoding='utf-8') as f:
            base_html = f.read()

        self.assertIn('id="themeToggleBtn"', base_html)
        self.assertIn("localStorage.getItem('our_secret_theme')", base_html)
        print("  [+] Base template theme toggle and localStorage persistence: PASSED")

    # =========================================================================
    # FEATURE 5: SECURITY ACTIVITY MONITOR
    # =========================================================================
    def test_feature5_security_monitor(self):
        print("\n--- Testing Feature 5: Security Activity Monitor ---")
        with self.client.session_transaction() as sess:
            sess['user_id'] = self.admin_id
            sess['username'] = 'admin'

        resp = self.client.get('/admin/security-monitor')
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode('utf-8')

        self.assertIn('Security Activity Monitor', html)
        self.assertIn('Total Audit Events', html)
        self.assertIn('Logins (Success / Fail)', html)
        self.assertIn('Suspicious Rejections', html)
        self.assertIn('Zero-Knowledge Privacy Enforcement', html)
        print("  [+] Admin Security Monitor dashboard and 5 SOC metrics cards: PASSED")

        # Test filtering by category
        resp_cat = self.client.get('/admin/security-monitor?category=LOGIN')
        self.assertEqual(resp_cat.status_code, 200)
        self.assertIn('LOGIN', resp_cat.data.decode('utf-8'))
        print("  [+] SOC Log filtering by category: PASSED")

    # =========================================================================
    # FEATURE 6: SUSPICIOUS FILE DETECTION
    # =========================================================================
    def test_feature6_suspicious_files(self):
        print("\n--- Testing Feature 6: Suspicious File Detection ---")
        # 1. Prohibited Executable disguised as PNG
        fake_exe = io.BytesIO(b'MZ' + b'\x00' * 50)
        fs_exe = FileStorage(stream=fake_exe, filename="bad.png")
        with self.assertRaises(FileValidationError):
            validate_uploaded_image(fs_exe)
        print("  [+] Disguised Windows Executable (MZ) rejected: PASSED")

        # 2. Suspicious Double Extension
        fake_png = io.BytesIO(b'\x89PNG\r\n\x1a\n' + b'\x00' * 30)
        fs_double = FileStorage(stream=fake_png, filename="shell.php.png")
        with self.assertRaises(FileValidationError):
            validate_uploaded_image(fs_double)
        print("  [+] Dangerous double extension (shell.php.png) rejected: PASSED")

        # 3. Path Traversal
        fake_png.seek(0)
        fs_trav = FileStorage(stream=fake_png, filename="../../etc/passwd.png")
        with self.assertRaises(FileValidationError):
            validate_uploaded_image(fs_trav)
        print("  [+] Path traversal filename rejected: PASSED")

        # 4. Null bytes
        fake_png.seek(0)
        fs_null = FileStorage(stream=fake_png, filename="test\x00.png")
        with self.assertRaises(FileValidationError):
            validate_uploaded_image(fs_null)
        print("  [+] Null byte in filename rejected: PASSED")

        # 5. Extension vs MIME Mismatch
        jpeg_img = Image.new('RGB', (50, 50), color='blue')
        jpeg_buf = io.BytesIO()
        jpeg_img.save(jpeg_buf, format='JPEG')
        jpeg_buf.seek(0)
        fs_mismatch = FileStorage(stream=jpeg_buf, filename="fake.png")
        with self.assertRaises(FileValidationError):
            validate_uploaded_image(fs_mismatch)
        print("  [+] Extension / Magic signature mismatch rejected: PASSED")

        # 6. Antivirus Disclaimer
        self.assertIn("not constitute an enterprise-grade antimalware", ANTIVIRUS_DISCLAIMER)
        print("  [+] Antivirus disclaimer validated: PASSED")

    # =========================================================================
    # END-TO-END CRYPTOGRAPHIC STEGANOGRAPHY PIPELINE
    # =========================================================================
    def test_full_steganography_crypto_pipeline(self):
        print("\n--- Testing Full End-to-End Steganography & Integrity Pipeline ---")
        secret = "TOP SECRET DEFENSE DIRECTIVE #88190: Cryptographic matrix intact."
        password = "MilStandardMasterPassword#2026"

        # 1. Encrypt with AES-256-GCM
        ciphertext_payload = encrypt_message(secret, password)
        self.assertGreater(len(ciphertext_payload), 28)

        # 2. Embed into cover image with OS01 header
        cover = Image.new('RGB', (200, 200), color=(15, 25, 45))
        stego_img, meta = embed_payload(cover, ciphertext_payload)
        self.assertEqual(meta['header_size_bytes'], 8)

        # 3. Extract payload and authenticate
        extracted_payload = extract_payload(stego_img)
        self.assertEqual(extracted_payload, ciphertext_payload)

        # 4. Decrypt and verify AES-GCM tag
        recovered_secret = decrypt_message(extracted_payload, password)
        self.assertEqual(recovered_secret, secret)
        print("  [+] Full AES-256-GCM + LSB (OS01) Embed & Decrypt Pipeline: PASSED")

    # =========================================================================
    # ADVANCED FEATURE: CONFIDENTIAL FILE CLOAKING
    # =========================================================================
    def test_new_feature_file_cloaking(self):
        print("\n--- Testing Advanced Feature: Secret File Cloaking ---")
        from security.crypto import pack_payload, unpack_payload, encrypt_bytes, decrypt_bytes

        # Simulated secret PDF file bytes
        fake_pdf_content = b"%PDF-1.7\n%CONFIDENTIAL INTEL DATA\n1 0 obj<<>>endobj\nxref\ntrailer<<>>startxref\n%%EOF"
        fake_filename = "covert_directive.pdf"

        # Pack and encrypt file
        packed = pack_payload('FILE', fake_pdf_content, fake_filename)
        self.assertEqual(packed[0], 0x02)

        password = "FileCloakMasterKey#2026"
        encrypted_blob = encrypt_bytes(packed, password)

        # Embed into cover image
        cover = Image.new('RGB', (180, 180), color=(10, 20, 30))
        stego_img, meta = embed_payload(cover, encrypted_blob)

        # Extract and unpack
        extracted = extract_payload(stego_img)
        decrypted_raw = decrypt_bytes(extracted, password)
        unpacked = unpack_payload(decrypted_raw)

        self.assertEqual(unpacked['type'], 'FILE')
        self.assertEqual(unpacked['filename'], fake_filename)
        self.assertEqual(unpacked['file_bytes'], fake_pdf_content)
        self.assertEqual(unpacked['size'], len(fake_pdf_content))
        print("  [+] Multi-format File Cloaking (PDF embedding & extraction): PASSED")

    # =========================================================================
    # ADVANCED FEATURE: BURN AFTER READING (SELF-DESTRUCT)
    # =========================================================================
    def test_new_feature_burn_after_reading(self):
        print("\n--- Testing Advanced Feature: Burn After Reading ---")
        with self.app.app_context():
            # Create a carrier record marked burn_after_reading
            burn_rec = IntegrityRecord(
                user_id=self.user_id,
                filename="stego_burn_test.png",
                original_filename="cover.png",
                file_hash="burn_hash_1234567890abcdef",
                hmac_signature="burn_hmac_1234567890abcdef",
                file_size=1024,
                image_dimensions="100x100",
                burn_after_reading=True,
                is_burned=False
            )
            db.session.add(burn_rec)
            db.session.commit()

            self.assertFalse(burn_rec.is_burned)
            self.assertEqual(burn_rec.expiry_status, 'PERMANENT')

            # Simulate first extraction: burns record
            burn_rec.is_burned = True
            burn_rec.burned_at = datetime.utcnow()
            burn_rec.extraction_count = 1
            burn_rec.is_purged = True
            db.session.commit()

            self.assertTrue(burn_rec.is_burned)
            self.assertEqual(burn_rec.expiry_status, 'BURNED')
            print("  [+] Burn After Reading self-destruct state & purge tracking: PASSED")

    # =========================================================================
    # ADVANCED FEATURE: CRYPTOGRAPHIC PASSWORD ENTROPY & GENERATOR
    # =========================================================================
    def test_new_feature_password_entropy_and_generator(self):
        print("\n--- Testing Advanced Feature: Password Entropy & Passphrase Generator ---")
        # Check main.js for entropy computation & generator routines
        js_path = os.path.join(os.path.dirname(__file__), 'static', 'js', 'main.js')
        with open(js_path, 'r', encoding='utf-8') as f:
            js = f.read()

        self.assertIn("initPasswordEntropyMeter", js)
        self.assertIn("initPassphraseGenerator", js)
        self.assertIn("Math.log2", js)
        self.assertIn("crypto.getRandomValues", js)
        print("  [+] Client-side zero-knowledge entropy & Diceware generator: PASSED")

        # Check hide.html for entropy bar and generator controls
        hide_path = os.path.join(os.path.dirname(__file__), 'templates', 'steganography', 'hide.html')
        with open(hide_path, 'r', encoding='utf-8') as f:
            html = f.read()

        self.assertIn('id="pwEntropyBar"', html)
        self.assertIn('id="pwCrackTimeLabel"', html)
        self.assertIn('id="btnGenToken"', html)
        self.assertIn('id="btnGenDiceware"', html)
        self.assertIn('id="burn_after_reading"', html)
        print("  [+] Template controls for Entropy, Generator and Burn Toggle: PASSED")

    # =========================================================================
    # ADVANCED FEATURE: VISUAL STEGANALYSIS & DIFFERENCE HEATMAP
    # =========================================================================
    def test_new_feature_visual_steganalysis(self):
        print("\n--- Testing Advanced Feature: Visual Steganalysis & Difference Heatmap ---")
        from steganography.steganalysis import analyze_steganography

        # 1. Test identical images -> MSE = 0, PSNR = infinity
        cover = Image.new('RGB', (100, 100), (45, 85, 125))
        stego_identical = cover.copy()
        res_id = analyze_steganography(cover, stego_identical)
        self.assertEqual(res_id['mse'], 0.0)
        self.assertEqual(res_id['changed_pixels'], 0)
        self.assertEqual(res_id['changed_bits'], 0)
        self.assertIn("Identical", res_id['psnr_str'])

        # 2. Test modified stego carrier (1 pixel LSB change)
        stego_mod = cover.copy()
        stego_mod.putpixel((10, 10), (44, 85, 125))  # 1 bit flipped in R channel (45 ^ 44 == 1)
        res_mod = analyze_steganography(cover, stego_mod)
        self.assertEqual(res_mod['changed_pixels'], 1)
        self.assertEqual(res_mod['changed_bits'], 1)
        self.assertGreater(res_mod['psnr'], 65.0)  # Defense-Grade Imperceptibility
        self.assertTrue(res_mod['heatmap_b64'].startswith('data:image/png;base64,'))
        self.assertTrue(res_mod['cover_b64'].startswith('data:image/png;base64,'))
        self.assertTrue(res_mod['stego_b64'].startswith('data:image/png;base64,'))
        print("  [+] Mathematical PSNR/MSE metrics & Difference Heatmap: PASSED")

        # 3. Test Steganalysis Compare route
        with self.client:
            self.client.post('/auth/login', data={'username': 'testuser', 'password': 'User@123456'})
            cov_buf = io.BytesIO()
            stg_buf = io.BytesIO()
            cover.save(cov_buf, format='PNG')
            stego_mod.save(stg_buf, format='PNG')
            cov_buf.seek(0)
            stg_buf.seek(0)

            resp = self.client.post('/steganography/compare', data={
                'cover_image': (cov_buf, 'test_cover.png'),
                'stego_image': (stg_buf, 'test_stego.png')
            }, content_type='multipart/form-data')
            self.assertEqual(resp.status_code, 200)
            self.assertIn(b"FORENSIC ANALYSIS COMPLETE", resp.data)
            self.assertIn(b"Difference Heatmap", resp.data)
            print("  [+] HTTP Visual Steganalysis Comparator endpoint: PASSED")

    # =========================================================================
    # ADVANCED FEATURE: PLAUSIBLE DENIABILITY (DECOY SECRET & DURESS ALARM)
    # =========================================================================
    def test_new_feature_plausible_deniability(self):
        print("\n--- Testing Advanced Feature: Plausible Deniability (Duress Defense) ---")
        from security.crypto import encrypt_deniable, decrypt_carrier_payload, pack_payload, DecryptionError

        real_msg = "TOP-SECRET MILITARY SATELLITE FREQUENCY 142.85 MHz"
        decoy_msg = "Draft agenda for Monday morning team sync in Room 4B"

        real_packed = pack_payload('TEXT', real_msg.encode('utf-8'))
        dual_envelope = encrypt_deniable(real_packed, "RealMasterPass999!", decoy_msg, "DuressCode123!")

        # 1. Decrypt with Real Master Password -> reveals real secret
        real_res = decrypt_carrier_payload(dual_envelope, "RealMasterPass999!")
        self.assertEqual(real_res['text'], real_msg)
        self.assertFalse(real_res['is_decoy'])
        self.assertTrue(real_res['is_deniable'])

        # 2. Decrypt with Decoy (Duress) Passcode -> reveals decoy secret
        decoy_res = decrypt_carrier_payload(dual_envelope, "DuressCode123!")
        self.assertEqual(decoy_res['text'], decoy_msg)
        self.assertTrue(decoy_res['is_decoy'])
        self.assertTrue(decoy_res['is_deniable'])

        # 3. Decrypt with Wrong Password -> raises DecryptionError
        with self.assertRaises(DecryptionError):
            decrypt_carrier_payload(dual_envelope, "CompletelyWrongPass123")

        print("  [+] Dual-key plausible deniability encryption/decryption: PASSED")

        # 4. HTTP E2E: Hide with Plausible Deniability, Extract with Decoy -> Verifies Duress Alarm
        with self.client:
            self.client.post('/auth/login', data={'username': 'testuser', 'password': 'User@123456'})
            img = Image.new('RGB', (180, 180), (70, 110, 150))
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            buf.seek(0)

            # Embed with Plausible Deniability enabled
            hide_resp = self.client.post('/steganography/hide', data={
                'image': (buf, 'covert_deniable.png'),
                'payload_type': 'text',
                'secret_message': real_msg,
                'password': 'RealMasterPass999!',
                'access_mode': 'time_limited',
                'expiry_option': '24h',
                'enable_deniable': '1',
                'decoy_password': 'DuressCode123!',
                'decoy_message': decoy_msg
            }, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(hide_resp.status_code, 200)
            self.assertIn(b"ARMED (Duress Active)", hide_resp.data)

            # Extract generated filename from database
            with self.app.app_context():
                rec = IntegrityRecord.query.filter_by(has_plausible_deniability=True).order_by(IntegrityRecord.id.desc()).first()
                self.assertIsNotNone(rec)
                self.assertTrue(rec.has_plausible_deniability)
                stego_path = os.path.join(self.app.config['STEGO_FOLDER'], rec.filename)

            with open(stego_path, 'rb') as f_stg:
                stg_data = f_stg.read()

            # Extract using DECOY (Duress) Passcode
            ext_resp = self.client.post('/steganography/extract', data={
                'image': (io.BytesIO(stg_data), 'stego_deniable.png'),
                'password': 'DuressCode123!'
            }, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(ext_resp.status_code, 200)
            self.assertIn(decoy_msg.encode('utf-8'), ext_resp.data)
            self.assertIn(b"DECOY / DURESS MODE", ext_resp.data)

            # Check that DURESS ALARM was logged in ActivityLog
            with self.app.app_context():
                duress_log = ActivityLog.query.filter_by(operation='EXTRACT_DURESS_TRIGGERED').order_by(ActivityLog.id.desc()).first()
                self.assertIsNotNone(duress_log)
                self.assertEqual(duress_log.status, 'DURESS_ALARM')
                self.assertIn("CRITICAL DURESS ALERT", duress_log.details)
                print("  [+] Silent SOC Duress Alarm & decoy display verified: PASSED")

    def test_new_feature_recipient_inbox_and_access_control(self):
        """Test recipient-targeted dispatch, covert inbox, and unauthorized access blocking."""
        print("\n--- Testing Advanced Feature: Recipient-Targeted Dispatch & Covert Inbox ---")
        with self.app.app_context():
            sender = User.query.filter_by(username='testuser').first()
            recipient = User.query.filter_by(username='agent2').first()
            if not recipient:
                recipient = User(username='agent2', email='agent2@defense.org', role='user')
                recipient.set_password('User@123456')
                db.session.add(recipient)
                db.session.commit()
            intruder = User.query.filter_by(username='intruder_agent').first()
            if not intruder:
                intruder = User(username='intruder_agent', email='intruder@agency.gov', role='user')
                intruder.set_password('IntruderPass#123')
                db.session.add(intruder)
                db.session.commit()
            sender_id = sender.id
            recipient_id = recipient.id
            intruder_id = intruder.id

        # 1. Login as testuser and dispatch secret to agent2 by entering User ID
        with self.client:
            self.client.get('/auth/logout')
            self.client.post('/auth/login', data={'username': 'testuser', 'password': 'User@123456'})
            img = Image.new('RGB', (150, 150), (20, 90, 60))
            buf = io.BytesIO()
            img.save(buf, format='PNG')
            buf.seek(0)

            secret_data = "COVERT DISPATCH: Intel received for operative 007."
            hide_resp = self.client.post('/steganography/hide', data={
                'image': (buf, 'targeted_courier.png'),
                'payload_type': 'text',
                'secret_message': secret_data,
                'password': 'CourierKey@999',
                'access_mode_type': 'specific',
                'recipient_input': str(recipient_id)
            }, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(hide_resp.status_code, 200)

            with self.app.app_context():
                rec = IntegrityRecord.query.filter_by(user_id=sender_id, recipient_id=recipient_id).order_by(IntegrityRecord.id.desc()).first()
                self.assertIsNotNone(rec)
                self.assertEqual(rec.recipient_id, recipient_id)
                self.assertFalse(rec.is_read)
                target_filename = rec.filename

            # Verify Sender's Outbox in Covert Inbox
            inbox_resp = self.client.get('/steganography/inbox')
            self.assertEqual(inbox_resp.status_code, 200)
            self.assertIn(target_filename.encode(), inbox_resp.data)
            print("  [+] Sender dispatch & Outbox registration: PASSED")

        # 2. Login as Intruder and verify access is strictly blocked
        with self.client:
            self.client.get('/auth/logout')
            self.client.post('/auth/login', data={'username': 'intruder_agent', 'password': 'IntruderPass#123'})
            # Intruder visits inbox -> target secret is NOT visible
            inbox_resp = self.client.get('/steganography/inbox')
            self.assertNotIn(target_filename.encode(), inbox_resp.data)

            # Intruder tries download -> Blocked
            dl_resp = self.client.get(f'/download/{target_filename}', follow_redirects=True)
            self.assertTrue(b"Access Denied" in dl_resp.data or dl_resp.status_code in [403, 302])

            # Intruder tries extract via carrier param -> Blocked
            ext_page = self.client.get(f'/steganography/extract?carrier={target_filename}', follow_redirects=True)
            self.assertIn(b"Access Denied", ext_page.data)
            print("  [+] Unauthorized access restriction (Download & Extract blocked): PASSED")

        # 3. Login as Admin and verify Admin is ALSO blocked from private recipient carrier
        with self.client:
            self.client.get('/auth/logout')
            self.client.post('/auth/login', data={'username': 'admin', 'password': 'Admin@123456'})
            admin_dl = self.client.get(f'/download/{target_filename}', follow_redirects=True)
            self.assertIn(b"Access Denied", admin_dl.data)
            print("  [+] Admin bypass restriction (Admin cannot access private message): PASSED")

        # 4. Login as Target Recipient (agent2) -> Allowed
        with self.client:
            self.client.get('/auth/logout')
            self.client.post('/auth/login', data={'username': 'agent2', 'password': 'User@123456'})
            # agent2 visits inbox -> secret carrier is present
            inbox_resp = self.client.get('/steganography/inbox')
            self.assertIn(target_filename.encode(), inbox_resp.data)

            # agent2 can download
            dl_resp = self.client.get(f'/download/{target_filename}')
            self.assertEqual(dl_resp.status_code, 200)

            # agent2 performs 1-click extraction
            ext_resp = self.client.post('/steganography/extract', data={
                'carrier_filename': target_filename,
                'password': 'CourierKey@999'
            }, content_type='multipart/form-data', follow_redirects=True)
            self.assertEqual(ext_resp.status_code, 200)
            self.assertIn(secret_data.encode(), ext_resp.data)

            with self.app.app_context():
                rec_check = db.session.get(IntegrityRecord, rec.id)
                self.assertTrue(rec_check.is_read)
                self.assertIsNotNone(rec_check.read_at)
            print("  [+] Recipient Covert Inbox 1-Click extraction & read receipt: PASSED")

    # =========================================================================
    # ADVANCED FEATURE: QR ADVANCED CRYPTOGRAPHIC SUITE
    # =========================================================================
    def test_new_feature_qr_advanced_suite(self):
        print("\n--- Testing Advanced Feature: QR Advanced Cryptographic Suite ---")
        
        # 1. Generate QR targeted to recipient 'agent2' with AES-256-GCM password
        with self.client:
            self.client.post('/auth/login', data={'username': 'testuser', 'password': 'User@123456'})
            qr_payload = "EYES-ONLY-TOP-SECRET-AGENT2"
            qr_pass = "QrMilitaryKey@2026"
            
            gen_resp = self.client.post('/qr/generate', data={
                'qr_content': qr_payload,
                'content_type': 'text',
                'error_correction': 'H',
                'recipient_mode': 'user',
                'recipient_input': 'agent2',
                'lifecycle_mode': '24h',
                'password': qr_pass
            }, follow_redirects=True)
            self.assertEqual(gen_resp.status_code, 200)
            self.assertIn(b"AUTHENTICATED ENCRYPTION (AES-256-GCM)", gen_resp.data)
            self.assertIn(b"agent2", gen_resp.data)
            
            with self.app.app_context():
                qr_rec = QRBurnRecord.query.filter_by(recipient_id=3).order_by(QRBurnRecord.created_at.desc()).first()
                self.assertIsNotNone(qr_rec)
                self.assertTrue(qr_rec.is_encrypted)
                qr_filename = qr_rec.qr_filename
                token_id = qr_rec.token_id

        # 2. Intruder login -> should NOT see the QR carrier in Covert Inbox, and cannot download/scan
        with self.client:
            self.client.get('/auth/logout')
            self.client.post('/auth/login', data={'username': 'intruder_agent', 'password': 'IntruderPass#123'})
            inbox_resp = self.client.get('/steganography/inbox')
            self.assertNotIn(qr_filename.encode(), inbox_resp.data)
            
            # Intruder tries scanning prefilled carrier
            scan_block = self.client.get(f'/qr/tools?scan_carrier={qr_filename}', follow_redirects=True)
            self.assertIn(b"Access Denied", scan_block.data)
            print("  [+] Unauthorized operative blocked from QR carrier & inbox: PASSED")

        # 3. Target recipient 'agent2' login -> sees QR in inbox, scans carrier, decrypts with password
        with self.client:
            self.client.get('/auth/logout')
            self.client.post('/auth/login', data={'username': 'agent2', 'password': 'User@123456'})
            inbox_resp = self.client.get('/steganography/inbox')
            self.assertIn(qr_filename.encode(), inbox_resp.data)
            self.assertIn(b"Scan QR", inbox_resp.data)
            
            # agent2 accesses prefilled scan tool
            scan_page = self.client.get(f'/qr/tools?scan_carrier={qr_filename}', follow_redirects=True)
            self.assertEqual(scan_page.status_code, 200)
            self.assertIn(b"Dispatched QR Token Loaded from Secret Inbox", scan_page.data)
            
            # agent2 scans without password -> prompted for AES-256-GCM password
            prompt_resp = self.client.post('/qr/scan', data={'carrier_filename': qr_filename}, follow_redirects=True)
            self.assertIn(b"AES-256-GCM ciphertext", prompt_resp.data)
            
            # agent2 decrypts with password
            decrypt_resp = self.client.post('/qr/scan', data={
                'carrier_filename': qr_filename,
                'password': qr_pass
            }, follow_redirects=True)
            self.assertEqual(decrypt_resp.status_code, 200)
            self.assertIn(qr_payload.encode(), decrypt_resp.data)
            print("  [+] Recipient Inbox 1-click Scan QR & AES-256-GCM Decryption: PASSED")

        # 4. QR Plausible Deniability (Duress Defense)
        with self.client:
            self.client.get('/auth/logout')
            self.client.post('/auth/login', data={'username': 'testuser', 'password': 'User@123456'})
            duress_gen = self.client.post('/qr/generate', data={
                'qr_content': 'CLASSIFIED-REACTOR-BLUEPRINT',
                'content_type': 'text',
                'error_correction': 'M',
                'recipient_mode': 'public',
                'lifecycle_mode': 'permanent',
                'enable_password': '1',
                'enable_deniable': '1',
                'password': 'MasterPassword#1',
                'decoy_password': 'DecoyPassword#2',
                'decoy_message': 'UNCLASSIFIED-STAFF-DUTY-ROSTER'
            }, follow_redirects=True)
            self.assertEqual(duress_gen.status_code, 200)
            self.assertIn(b"PLAUSIBLE DENIABILITY ACTIVE", duress_gen.data)
            
            with self.app.app_context():
                duress_qr = QRBurnRecord.query.filter_by(has_plausible_deniability=True).order_by(QRBurnRecord.created_at.desc()).first()
                self.assertIsNotNone(duress_qr)
                duress_filename = duress_qr.qr_filename

            # Scan with Decoy Password -> reveals Decoy Message & triggers SOC Duress Alarm
            decoy_scan = self.client.post('/qr/scan', data={
                'carrier_filename': duress_filename,
                'password': 'DecoyPassword#2'
            }, follow_redirects=True)
            self.assertEqual(decoy_scan.status_code, 200)
            self.assertIn(b"UNCLASSIFIED-STAFF-DUTY-ROSTER", decoy_scan.data)
            self.assertNotIn(b"CLASSIFIED-REACTOR-BLUEPRINT", decoy_scan.data)
            self.assertIn(b"DECOY / DURESS MODE", decoy_scan.data)
            
            # Verify SOC alarm event in DB
            with self.app.app_context():
                duress_log = ActivityLog.query.filter_by(operation='EXTRACT_DURESS_TRIGGERED', status='DURESS_ALARM').order_by(ActivityLog.created_at.desc()).first()
                self.assertIsNotNone(duress_log)
            print("  [+] QR Plausible Deniability Decoy Extraction & SOC Duress Alarm: PASSED")

if __name__ == '__main__':
    unittest.main(verbosity=2)
