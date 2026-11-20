import os
import sys
from io import BytesIO
from PIL import Image

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import create_app
from database import db
from database.models import User, ActivityLog, IntegrityRecord
from seed_data import seed_database

def run_integration_tests():
    print("--------------------------------------------------")
    print("STARTING OUR SECRET END-TO-END HTTP INTEGRATION TEST")
    print("--------------------------------------------------")

    app = create_app()
    app.config['TESTING'] = True
    client = app.test_client()

    with app.app_context():
        # Ensure database is clean and seeded
        db.create_all()
        seed_database()

    # Step 1: Probe Landing Page
    res = client.get('/')
    assert res.status_code == 200, f"Landing page failed with {res.status_code}"
    assert b"Our Secret" in res.data
    print("[+] 1. Public Landing Page probe: 200 OK")

    # Step 2: Login as Admin
    # First get csrf_token from session
    with client:
        res = client.get('/auth/login')
        csrf_token = client.session_transaction().__enter__()['csrf_token']

        login_res = client.post('/auth/login', data={
            'csrf_token': csrf_token,
            'username': 'admin',
            'password': 'Admin@123456'
        }, follow_redirects=True)
        assert login_res.status_code == 200
        assert b"Welcome back, admin" in login_res.data
        print("[+] 2. Operator Authentication (Admin login): 200 OK")

        # Step 3: Check Dashboard
        dash_res = client.get('/dashboard')
        assert dash_res.status_code == 200
        assert b"Operational Dashboard" in dash_res.data
        assert b"Images Processed" in dash_res.data
        print("[+] 3. Dashboard Real-time Statistics: 200 OK")

        # Step 4: Hide Message via HTTP POST
        # Generate cover image in memory
        cover_img = Image.new('RGB', (250, 200), color=(20, 30, 50))
        cover_buf = BytesIO()
        cover_img.save(cover_buf, format='PNG')
        cover_buf.seek(0)

        secret_text = "CONFIDENTIAL INTEL: Target coordinates 19.0760 N, 72.8777 E. Operation Falcon."
        secret_password = "FalconMasterKey#2026"

        csrf_token = client.session_transaction().__enter__()['csrf_token']
        hide_res = client.post('/steganography/hide', data={
            'csrf_token': csrf_token,
            'image': (cover_buf, 'cover_test.png'),
            'secret_message': secret_text,
            'password': secret_password
        }, content_type='multipart/form-data', follow_redirects=True)

        assert hide_res.status_code == 200
        assert b"Steganographic Concealment Complete!" in hide_res.data
        print("[+] 4. LSB Embedding & AES-256-GCM Encryption: 200 OK")

        # Retrieve the generated stego filename from DB
        with app.app_context():
            latest_record = IntegrityRecord.query.order_by(IntegrityRecord.created_at.desc()).first()
            assert latest_record is not None
            stego_filename = latest_record.filename
            file_hash = latest_record.file_hash
            print(f"    Generated stego file: {stego_filename}")
            print(f"    SHA-256 Fingerprint: {file_hash[:16]}...")

        # Step 5: Download the generated stego file
        download_res = client.get(f'/download/{stego_filename}')
        assert download_res.status_code == 200
        stego_bytes = download_res.data
        assert len(stego_bytes) > 0
        print("[+] 5. Lossless Stego PNG Download: 200 OK")

        # Step 6: Extract Secret Message with Correct Password
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        extract_buf = BytesIO(stego_bytes)
        extract_res = client.post('/steganography/extract', data={
            'csrf_token': csrf_token,
            'image': (extract_buf, stego_filename),
            'password': secret_password
        }, content_type='multipart/form-data', follow_redirects=True)

        assert extract_res.status_code == 200
        assert secret_text.encode() in extract_res.data
        assert b"AUTHENTICATED" in extract_res.data
        print("[+] 6. Extract & Authenticate Secret Message: 200 OK")

        # Step 7: Attempt Extract with Wrong Password
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        wrong_pw_buf = BytesIO(stego_bytes)
        wrong_pw_res = client.post('/steganography/extract', data={
            'csrf_token': csrf_token,
            'image': (wrong_pw_buf, stego_filename),
            'password': 'IncorrectPassword999'
        }, content_type='multipart/form-data', follow_redirects=True)

        assert wrong_pw_res.status_code == 200
        assert b"Decryption Failed" in wrong_pw_res.data or b"Authentication failed" in wrong_pw_res.data
        print("[+] 7. Reject Incorrect Password via AES-GCM Tag: 200 OK")

        # Step 8: Optical QR Tools (Generate and Validate Token)
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        qr_gen_res = client.post('/qr/generate', data={
            'csrf_token': csrf_token,
            'content_type': 'encrypted',
            'error_correction': 'H',
            'qr_content': 'CIPHERTEXT_SAMPLE_TOKEN_TEST#123'
        }, follow_redirects=True)

        assert qr_gen_res.status_code == 200
        assert b"Generated Optical QR Code" in qr_gen_res.data
        print("[+] 8. Optical QR Code Generation (Level H): 200 OK")

        # Step 9: Message Expiry Server Cleanup
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        cleanup_res = client.post('/steganography/cleanup-expired', data={
            'csrf_token': csrf_token
        }, follow_redirects=True)

        assert cleanup_res.status_code == 200
        assert b"Server-Side Cleanup:" in cleanup_res.data
        print("[+] 9. Expired Server Files Cleanup Process: 200 OK")

        # Step 10: History Module
        hist_res = client.get('/history')
        assert hist_res.status_code == 200
        assert b"Audit Logs & Forensic Activity" in hist_res.data
        # Ensure secret message is NOT in history HTML
        assert secret_text.encode() not in hist_res.data
        print("[+] 10. Audit Log History & Zero Plaintext Leakage: 200 OK")

        # Step 11: Admin Management Console
        admin_res = client.get('/admin')
        assert admin_res.status_code == 200
        assert b"Operator & User Management" in admin_res.data
        assert b"Tamper Anomalies" in admin_res.data
        print("[+] 11. Admin Management & Audit Feed: 200 OK")

        # Step 12: Profile Management
        profile_res = client.get('/profile')
        assert profile_res.status_code == 200
        assert b"Security Profile" in profile_res.data
        print("[+] 12. Security Profile: 200 OK")

        # Step 13: Secret File Cloaking (Hide PDF / Document file via HTTP)
        file_cover = Image.new('RGB', (220, 220), color=(10, 20, 40))
        file_cover_buf = BytesIO()
        file_cover.save(file_cover_buf, format='PNG')
        file_cover_buf.seek(0)

        secret_file_bytes = b"%PDF-1.4\n1 0 obj<</Type/Catalog>>endobj\n%%EOF"
        secret_file_buf = BytesIO(secret_file_bytes)

        csrf_token = client.session_transaction().__enter__()['csrf_token']
        hide_file_res = client.post('/steganography/hide', data={
            'csrf_token': csrf_token,
            'image': (file_cover_buf, 'carrier_for_file.png'),
            'payload_type': 'file',
            'secret_file': (secret_file_buf, 'directive_falcon.pdf'),
            'password': 'FileCloakPassword#2026'
        }, content_type='multipart/form-data', follow_redirects=True)

        assert hide_file_res.status_code == 200
        assert b"Steganographic Concealment Complete!" in hide_file_res.data
        print("[+] 13. HTTP Secret File Cloaking (PDF Concealment): 200 OK")

        # Extract Cloaked File
        with app.app_context():
            latest_file_rec = IntegrityRecord.query.order_by(IntegrityRecord.created_at.desc()).first()
            file_stego_fn = latest_file_rec.filename

        download_file_res = client.get(f'/download/{file_stego_fn}')
        file_stego_bytes = download_file_res.data

        csrf_token = client.session_transaction().__enter__()['csrf_token']
        extract_file_res = client.post('/steganography/extract', data={
            'csrf_token': csrf_token,
            'image': (BytesIO(file_stego_bytes), file_stego_fn),
            'password': 'FileCloakPassword#2026'
        }, content_type='multipart/form-data', follow_redirects=True)

        assert extract_file_res.status_code == 200
        assert b"directive_falcon.pdf" in extract_file_res.data
        assert b"Download Cloaked File" in extract_file_res.data
        print("[+] 14. HTTP Cloaked File Extraction & Reconstruction: 200 OK")

        # Step 15: Burn After Reading (One-Time Self-Destruct)
        burn_cover = Image.new('RGB', (200, 200), color=(30, 10, 10))
        burn_cover_buf = BytesIO()
        burn_cover.save(burn_cover_buf, format='PNG')
        burn_cover_buf.seek(0)

        csrf_token = client.session_transaction().__enter__()['csrf_token']
        hide_burn_res = client.post('/steganography/hide', data={
            'csrf_token': csrf_token,
            'image': (burn_cover_buf, 'burn_carrier.png'),
            'payload_type': 'text',
            'secret_message': 'SELF DESTRUCT INTEL 007',
            'password': 'BurnPassword#2026',
            'burn_after_reading': '1'
        }, content_type='multipart/form-data', follow_redirects=True)

        assert hide_burn_res.status_code == 200
        with app.app_context():
            burn_rec = IntegrityRecord.query.order_by(IntegrityRecord.created_at.desc()).first()
            burn_fn = burn_rec.filename
            self_destruct_hash = burn_rec.file_hash

        download_burn_res = client.get(f'/download/{burn_fn}')
        burn_bytes = download_burn_res.data
        download_burn_res.close()

        # 1st Extraction: Success + triggers Burn
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        first_extract = client.post('/steganography/extract', data={
            'csrf_token': csrf_token,
            'image': (BytesIO(burn_bytes), burn_fn),
            'password': 'BurnPassword#2026'
        }, content_type='multipart/form-data', follow_redirects=True)

        assert first_extract.status_code == 200
        assert b"SELF DESTRUCT INTEL 007" in first_extract.data
        assert b"Burn-After-Reading" in first_extract.data
        print("[+] 15. Burn-After-Reading Initial Extraction & Self-Destruct Trigger: 200 OK")

        # 2nd Extraction: Blocked because it's burned!
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        second_extract = client.post('/steganography/extract', data={
            'csrf_token': csrf_token,
            'image': (BytesIO(burn_bytes), burn_fn),
            'password': 'BurnPassword#2026'
        }, content_type='multipart/form-data', follow_redirects=True)

        assert second_extract.status_code == 200
        assert b"SELF DESTRUCT INTEL 007" not in second_extract.data
        assert b"already self-destructed" in second_extract.data
        print("[+] 16. Burn-After-Reading Second Extraction Blocked: 200 OK")

        # Step 17: Visual Steganalysis & Difference Heatmap Comparator
        cov_img = Image.new('RGB', (150, 150), color=(60, 90, 120))
        stg_img = cov_img.copy()
        stg_img.putpixel((20, 20), (61, 90, 120))

        cov_b = BytesIO()
        stg_b = BytesIO()
        cov_img.save(cov_b, format='PNG')
        stg_img.save(stg_b, format='PNG')
        cov_b.seek(0)
        stg_b.seek(0)

        csrf_token = client.session_transaction().__enter__()['csrf_token']
        steg_compare_res = client.post('/steganography/compare', data={
            'csrf_token': csrf_token,
            'cover_image': (cov_b, 'e2e_cover.png'),
            'stego_image': (stg_b, 'e2e_stego.png')
        }, content_type='multipart/form-data', follow_redirects=True)

        assert steg_compare_res.status_code == 200
        assert b"FORENSIC ANALYSIS COMPLETE" in steg_compare_res.data
        assert b"Difference Heatmap" in steg_compare_res.data
        print("[+] 17. HTTP Visual Steganalysis & Difference Heatmap: 200 OK")

        # Step 18: Plausible Deniability (Duress Passcode & Silent Alarm Trigger)
        deniable_cov = Image.new('RGB', (220, 220), color=(40, 60, 80))
        deniable_cov_buf = BytesIO()
        deniable_cov.save(deniable_cov_buf, format='PNG')
        deniable_cov_buf.seek(0)

        real_classified = "REAL CLASSIFIED ASSET LOCATION: SECTOR 7"
        decoy_innocent = "MEETING CANCELLED: ENJOY YOUR WEEKEND"

        csrf_token = client.session_transaction().__enter__()['csrf_token']
        hide_deniable_res = client.post('/steganography/hide', data={
            'csrf_token': csrf_token,
            'image': (deniable_cov_buf, 'deniable_carrier.png'),
            'payload_type': 'text',
            'secret_message': real_classified,
            'password': 'TrueMasterPassword#999',
            'enable_deniable': '1',
            'decoy_password': 'DuressEmergencyCode#111',
            'decoy_message': decoy_innocent
        }, content_type='multipart/form-data', follow_redirects=True)

        assert hide_deniable_res.status_code == 200
        assert b"ARMED (Duress Active)" in hide_deniable_res.data

        with app.app_context():
            deniable_rec = IntegrityRecord.query.filter_by(has_plausible_deniability=True).order_by(IntegrityRecord.created_at.desc()).first()
            deniable_fn = deniable_rec.filename

        download_deniable = client.get(f'/download/{deniable_fn}')
        deniable_bytes = download_deniable.data
        download_deniable.close()

        # Extract with DECOY passcode -> Displays decoy and triggers silent alarm
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        extract_decoy_res = client.post('/steganography/extract', data={
            'csrf_token': csrf_token,
            'image': (BytesIO(deniable_bytes), deniable_fn),
            'password': 'DuressEmergencyCode#111'
        }, content_type='multipart/form-data', follow_redirects=True)

        assert extract_decoy_res.status_code == 200
        assert decoy_innocent.encode('utf-8') in extract_decoy_res.data
        assert real_classified.encode('utf-8') not in extract_decoy_res.data
        assert b"DECOY / DURESS MODE" in extract_decoy_res.data

        # Verify Silent Alarm in Admin SOC ActivityLog
        with app.app_context():
            alarm_event = ActivityLog.query.filter_by(operation='EXTRACT_DURESS_TRIGGERED').first()
            assert alarm_event is not None
            assert alarm_event.status == 'DURESS_ALARM'
        print("[+] 18. Plausible Deniability Decoy Extraction & SOC Duress Alarm: 200 OK")

        # Step 19: Covert Inbox & Recipient-Targeted Dispatch Access Control
        # Ensure agent2 exists
        with app.app_context():
            agent2_user = User.query.filter_by(username='agent2').first()
            if not agent2_user:
                agent2_user = User(username='agent2', email='agent2@defense.org', role='user')
                agent2_user.set_password('User@123456')
                db.session.add(agent2_user)
                db.session.commit()
            agent2_id = agent2_user.id

            intruder = User.query.filter_by(username='intruder').first()
            if not intruder:
                intruder = User(username='intruder', email='intruder@cybersec.corp', role='user')
                intruder.set_password('Intruder@123456')
                db.session.add(intruder)
                db.session.commit()
            intruder_id = intruder.id

            admin_user = User.query.filter_by(username='admin').first()
            admin_id = admin_user.id
            test_user = User.query.filter_by(username='testuser').first()
            test_user_id = test_user.id

        # 1. Login as testuser (Sender) and hide a secret targeted specifically to agent2 by User ID
        client.get('/auth/logout')
        client.get('/auth/login')
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        client.post('/auth/login', data={'csrf_token': csrf_token, 'username': 'testuser', 'password': 'User@123456'}, follow_redirects=True)

        target_img = Image.new('RGB', (160, 160), color=(40, 80, 120))
        target_buf = BytesIO()
        target_img.save(target_buf, format='PNG')
        target_buf.seek(0)

        targeted_secret = "TARGETED EYES ONLY: Operative Alpha meeting at sector 7."
        targeted_pass = "TargetPasscode#99"

        csrf_token = client.session_transaction().__enter__()['csrf_token']
        hide_target_res = client.post('/steganography/hide', data={
            'csrf_token': csrf_token,
            'image': (target_buf, 'targeted_cover.png'),
            'secret_message': targeted_secret,
            'password': targeted_pass,
            'access_mode_type': 'specific',
            'recipient_input': str(agent2_id)
        }, content_type='multipart/form-data', follow_redirects=True)
        assert hide_target_res.status_code == 200

        with app.app_context():
            target_record = IntegrityRecord.query.filter_by(recipient_id=agent2_id, user_id=test_user_id).order_by(IntegrityRecord.id.desc()).first()
            assert target_record is not None
            assert target_record.is_read is False
            target_fn = target_record.filename

        # Verify Sender's Outbox shows this dispatch
        inbox_sender = client.get('/steganography/inbox')
        assert inbox_sender.status_code == 200
        assert target_fn.encode() in inbox_sender.data

        # 2. Login as intruder (3rd party unauthorized user) -> BLOCKED
        client.get('/auth/logout')
        client.get('/auth/login')
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        client.post('/auth/login', data={'csrf_token': csrf_token, 'username': 'intruder', 'password': 'Intruder@123456'}, follow_redirects=True)

        intruder_inbox = client.get('/steganography/inbox')
        assert intruder_inbox.status_code == 200
        assert b"No Secret Transmissions Received Yet" in intruder_inbox.data
        assert target_fn.encode() not in intruder_inbox.data

        intruder_download = client.get(f'/download/{target_fn}', follow_redirects=True)
        assert b"Access Denied" in intruder_download.data or intruder_download.status_code in [403, 302]

        intruder_extract = client.get(f'/steganography/extract?carrier={target_fn}', follow_redirects=True)
        assert b"Access Denied" in intruder_extract.data

        # 3. Login as Admin -> ALSO BLOCKED from downloading/extracting private user transmission
        client.get('/auth/logout')
        client.get('/auth/login')
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        client.post('/auth/login', data={'csrf_token': csrf_token, 'username': 'admin', 'password': 'Admin@123456'}, follow_redirects=True)

        admin_download = client.get(f'/download/{target_fn}', follow_redirects=True)
        assert b"Access Denied" in admin_download.data

        # 4. Login as target recipient (agent2) -> SUCCESS
        client.get('/auth/logout')
        client.get('/auth/login')
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        client.post('/auth/login', data={'csrf_token': csrf_token, 'username': 'agent2', 'password': 'User@123456'}, follow_redirects=True)

        # Recipient's inbox must show the incoming transmission
        recip_inbox = client.get('/steganography/inbox')
        assert recip_inbox.status_code == 200
        assert target_fn.encode() in recip_inbox.data

        # Recipient can download the carrier
        recip_download = client.get(f'/download/{target_fn}')
        assert recip_download.status_code == 200
        assert len(recip_download.data) > 0

        # Recipient 1-Click extraction from inbox
        recip_extract_page = client.get(f'/steganography/extract?carrier={target_fn}')
        assert recip_extract_page.status_code == 200
        assert b"Dispatched Carrier Loaded from Secret Inbox" in recip_extract_page.data

        # Submit extraction with password
        csrf_token = client.session_transaction().__enter__()['csrf_token']
        recip_extract_res = client.post('/steganography/extract', data={
            'csrf_token': csrf_token,
            'carrier_filename': target_fn,
            'password': targeted_pass
        }, content_type='multipart/form-data', follow_redirects=True)
        assert recip_extract_res.status_code == 200
        assert targeted_secret.encode() in recip_extract_res.data

        # Verify is_read is marked True in database
        with app.app_context():
            rec_updated = db.session.get(IntegrityRecord, target_record.id)
            assert rec_updated.is_read is True
            assert rec_updated.read_at is not None

        print("[+] 19. Covert Inbox & Recipient-Targeted Dispatch Access Control: 200 OK")

    print("--------------------------------------------------")
    print("ALL 19 END-TO-END HTTP INTEGRATION TESTS PASSED 100%!")
    print("--------------------------------------------------")

if __name__ == '__main__':
    run_integration_tests()
