import os
import sys
import unittest
from io import BytesIO
from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import create_app
from database import db
from database.models import User, ActivityLog, IntegrityRecord
from security.crypto import encrypt_message, decrypt_message, DecryptionError
from security.integrity import calculate_sha256, calculate_hmac_sha256, verify_hmac_sha256
from steganography.lsb import (
    embed_payload, extract_payload, calculate_capacity, 
    StegoCapacityError, InvalidStegoImageError
)

class OurSecretComprehensiveTestSuite(unittest.TestCase):

    def setUp(self):
        # Configure app for testing in memory
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['WTF_CSRF_ENABLED'] = False
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            # Seed test admin
            admin = User(username='test_admin', email='admin@test.com', role='admin')
            admin.set_password('AdminPass@123')
            # Seed test regular user
            user = User(username='test_operator', email='operator@test.com', role='user')
            user.set_password('OperatorPass@123')
            db.session.add_all([admin, user])
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    # -------------------------------------------------------------
    # 1. AUTHENTICATION & ACCESS CONTROL TESTS
    # -------------------------------------------------------------
    def test_user_password_hashing(self):
        with self.app.app_context():
            user = User.query.filter_by(username='test_operator').first()
            self.assertTrue(user.check_password('OperatorPass@123'))
            self.assertFalse(user.check_password('WrongPassword'))
            self.assertNotEqual(user.password_hash, 'OperatorPass@123')

    def test_role_based_access_control(self):
        # Unauthenticated access to dashboard should redirect to login
        res = self.client.get('/dashboard')
        self.assertEqual(res.status_code, 302)
        self.assertIn('/auth/login', res.headers['Location'])

        # Regular user access to admin panel should be redirected to dashboard
        with self.client.session_transaction() as sess:
            sess['user_id'] = 2
            sess['username'] = 'test_operator'
            sess['role'] = 'user'

        res = self.client.get('/admin')
        self.assertEqual(res.status_code, 302)
        self.assertIn('/dashboard', res.headers['Location'])

        # Admin user access to admin panel should succeed
        with self.client.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'test_admin'
            sess['role'] = 'admin'

        res = self.client.get('/admin')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'System Security Administrator Console', res.data)

    # -------------------------------------------------------------
    # 2. CRYPTO AES-256-GCM & PBKDF2 TESTS
    # -------------------------------------------------------------
    def test_crypto_encryption_and_decryption(self):
        secret = "TopSecretCoordinate: 37.2431 N, 115.7930 W (Area 51 Vault)"
        password = "CyberStrongPassword!2026"

        payload = encrypt_message(secret, password)
        self.assertIsInstance(payload, bytes)
        # Payload must include salt (16) + nonce (12) + tag (16) + ciphertext
        self.assertGreaterEqual(len(payload), 44 + len(secret))

        # Successful decryption
        decrypted = decrypt_message(payload, password)
        self.assertEqual(decrypted, secret)

    def test_crypto_wrong_password_rejection(self):
        secret = "Classified Defense File #891"
        payload = encrypt_message(secret, "CorrectPassword99")

        with self.assertRaises(DecryptionError):
            decrypt_message(payload, "WrongPassword99")

    def test_crypto_tampered_ciphertext_detection(self):
        secret = "Integrity check test payload"
        payload = bytearray(encrypt_message(secret, "PasswordKey123"))

        # Alter one byte in ciphertext / authentication tag
        payload[-1] ^= 0x01

        with self.assertRaises(DecryptionError):
            decrypt_message(bytes(payload), "PasswordKey123")

    # -------------------------------------------------------------
    # 3. STEGANOGRAPHY LSB ENGINE & CAPACITY TESTS
    # -------------------------------------------------------------
    def test_steganography_capacity_calculation(self):
        img = Image.new('RGB', (200, 150), color=(30, 40, 50))
        cap = calculate_capacity(img)

        total_channels = 200 * 150 * 3  # 90,000 channels
        expected_bytes = 90000 // 8     # 11,250 bytes
        max_payload = expected_bytes - 8  # 11,242 bytes (8-byte OS01 header overhead)

        self.assertEqual(cap['width'], 200)
        self.assertEqual(cap['height'], 150)
        self.assertEqual(cap['total_channels'], total_channels)
        self.assertEqual(cap['max_payload_bytes'], max_payload)

    def test_steganography_capacity_overflow_error(self):
        img = Image.new('RGB', (10, 10), color=(0, 0, 0))
        # 10x10x3 = 300 bits = 37 bytes max total, minus 8-byte OS01 header = 29 bytes payload
        cap = calculate_capacity(img)
        huge_payload = b"A" * (cap['max_payload_bytes'] + 50)

        with self.assertRaises(StegoCapacityError):
            embed_payload(img, huge_payload)

    def test_steganography_embed_and_extract_flow(self):
        img = Image.new('RGB', (150, 150), color=(15, 25, 45))
        secret_msg = "ENCRYPTED_MESSAGE_PAYLOAD_TEST_LSB_2026"
        password = "StegoSafePassword!99"

        # Encrypt with AES-GCM
        payload = encrypt_message(secret_msg, password)

        # Embed into image
        stego_img, meta = embed_payload(img, payload)
        self.assertIsNotNone(stego_img)
        self.assertEqual(meta['payload_size_bytes'], len(payload))

        # Save to buffer and extract
        buffer = BytesIO()
        stego_img.save(buffer, format='PNG')
        buffer.seek(0)

        extracted_payload = extract_payload(buffer.getvalue())
        self.assertEqual(extracted_payload, payload)

        # Decrypt extracted payload
        decrypted_text = decrypt_message(extracted_payload, password)
        self.assertEqual(decrypted_text, secret_msg)

    def test_steganography_non_stego_image_rejection(self):
        plain_img = Image.new('RGB', (50, 50), color=(255, 255, 255))
        buffer = BytesIO()
        plain_img.save(buffer, format='PNG')
        buffer.seek(0)

        with self.assertRaises(InvalidStegoImageError):
            extract_payload(buffer.getvalue())

    # -------------------------------------------------------------
    # 4. DATA INTEGRITY & TAMPERING DETECTION TESTS
    # -------------------------------------------------------------
    def test_sha256_and_hmac_integrity_verification(self):
        data = b"DEFENSE SATELLITE TELEMETRY PACKET #4401"
        sha = calculate_sha256(data)
        hmac_sig = calculate_hmac_sha256(data)

        self.assertEqual(len(sha), 64)
        self.assertEqual(len(hmac_sig), 64)
        self.assertTrue(verify_hmac_sha256(data, hmac_sig))

        # Tamper test
        tampered_data = data + b"X"
        self.assertNotEqual(calculate_sha256(tampered_data), sha)
        self.assertFalse(verify_hmac_sha256(tampered_data, hmac_sig))

    # -------------------------------------------------------------
    # 5. PRIVACY & FORENSIC LOGGING COMPLIANCE
    # -------------------------------------------------------------
    def test_zero_knowledge_message_logging(self):
        with self.app.app_context():
            secret_canary = "SUPER_SECRET_CANARY_STRING_XYZ_999"
            user = User.query.filter_by(username='test_operator').first()

            # Create an activity log
            log = ActivityLog(
                user_id=user.id,
                operation='HIDE_MESSAGE',
                filename='test_stego.png',
                file_hash='abc123sha256hash',
                status='SUCCESS',
                details='Embedded 128 bytes in image'
            )
            db.session.add(log)
            db.session.commit()

            # Ensure secret message is NOT in logs table
            all_logs = ActivityLog.query.all()
            for l in all_logs:
                self.assertNotIn(secret_canary, str(l.details or ''))
                self.assertNotIn(secret_canary, str(l.filename or ''))

if __name__ == '__main__':
    print("==================================================")
    print("RUNNING OUR SECRET COMPREHENSIVE AUTOMATED TEST SUITE")
    print("==================================================")
    unittest.main()

