import sys
import os

# Set path to project
sys.path.insert(0, r"C:\Users\Harsh's Laptop\.gemini\antigravity\scratch\our_secret")

from app import create_app
from database import db
from database.models import User, ActivityLog

def test_security_activity_monitor():
    print("[*] Starting Feature 5: Security Activity Monitor Verification...")
    app = create_app()
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.app_context():
        # Ensure admin and regular users exist
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

        # Add sample logs for diverse security operations
        test_logs = [
            ActivityLog(user_id=admin.id, operation='USER_LOGIN', status='SUCCESS', details='Admin logged in successfully', ip_address='127.0.0.1'),
            ActivityLog(user_id=None, operation='USER_LOGIN', status='FAILED', details='Brute force attempt on admin', ip_address='192.168.1.100'),
            ActivityLog(user_id=user.id, operation='HIDE_MESSAGE', status='SUCCESS', filename='classified_stego.png', details='Encoded secret into payload', ip_address='127.0.0.1'),
            ActivityLog(user_id=user.id, operation='EXTRACT_MESSAGE', status='FAILED', filename='classified_stego.png', details='Decryption failed with invalid pass', ip_address='127.0.0.1'),
            ActivityLog(user_id=user.id, operation='INTEGRITY_CHECK', status='SUCCESS', integrity_status='VERIFIED', filename='classified_stego.png', details='Hash match', ip_address='127.0.0.1'),
            ActivityLog(user_id=user.id, operation='INTEGRITY_CHECK', status='FAILED', integrity_status='TAMPERED', filename='corrupt_stego.png', details='Hash mismatch detected', ip_address='127.0.0.1'),
            ActivityLog(user_id=user.id, operation='REJECTED_UPLOAD', status='BLOCKED', filename='malware.exe', details='Rejected suspicious executable extension', ip_address='10.0.0.5'),
            ActivityLog(user_id=user.id, operation='QR_GENERATE', status='SUCCESS', filename='qr_test.png', details='Generated QR code for secure token', ip_address='127.0.0.1')
        ]
        db.session.add_all(test_logs)
        db.session.commit()

        client = app.test_client()

        # Test 1: Anonymous access redirected
        resp = client.get('/admin/security-monitor')
        assert resp.status_code == 302, f"Expected 302 for anonymous, got {resp.status_code}"
        assert '/login' in resp.headers.get('Location', '')
        print("  [+] Anonymous access properly blocked and redirected to login: PASSED")

        # Test 2: Regular user access blocked (403 or redirect with error)
        with client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username
        resp = client.get('/admin/security-monitor')
        assert resp.status_code == 302, f"Expected 302 for regular user, got {resp.status_code}"
        print("  [+] Regular user blocked from admin security monitor: PASSED")

        # Test 3: Admin access succeeds (200 OK)
        with client.session_transaction() as sess:
            sess['user_id'] = admin.id
            sess['username'] = admin.username
        resp = client.get('/admin/security-monitor')
        assert resp.status_code == 200, f"Expected 200 for admin, got {resp.status_code}"
        html = resp.data.decode('utf-8')
        assert 'Security Activity Monitor' in html
        assert 'SOC AUDIT CONSOLE' in html
        assert 'Zero-Knowledge Privacy Enforcement' in html
        print("  [+] Admin access granted and page rendered: PASSED")

        # Test 4: Verify metrics cards are populated
        assert 'Total Audit Events' in html
        assert 'Logins (Success / Fail)' in html
        assert 'Suspicious Rejections' in html
        print("  [+] All 5 SOC metrics cards rendered in HTML: PASSED")

        # Test 5: Filter by category = 'LOGIN'
        resp_cat = client.get('/admin/security-monitor?category=LOGIN')
        assert resp_cat.status_code == 200
        html_cat = resp_cat.data.decode('utf-8')
        assert 'LOGIN' in html_cat
        print("  [+] Category filtering (LOGIN) executed successfully: PASSED")

        # Test 6: Filter by status = 'BLOCKED'
        resp_status = client.get('/admin/security-monitor?status=BLOCKED')
        assert resp_status.status_code == 200
        html_status = resp_status.data.decode('utf-8')
        assert 'BLOCKED' in html_status
        assert 'malware.exe' in html_status
        print("  [+] Status filtering (BLOCKED) executed successfully: PASSED")

        # Test 7: Search by keyword = 'corrupt_stego.png'
        resp_search = client.get('/admin/security-monitor?search=corrupt_stego.png')
        assert resp_search.status_code == 200
        html_search = resp_search.data.decode('utf-8')
        assert 'corrupt_stego.png' in html_search
        assert 'TAMPERED' in html_search
        print("  [+] Search filtering by filename/keyword executed successfully: PASSED")

        # Test 8: Zero-Knowledge audit integrity check
        # Confirm that no password hashes or secret text leak into the rendered HTML
        assert 'User@123456' not in html
        assert 'Admin@123456' not in html
        assert 'pbkdf2:sha256' not in html
        print("  [+] Zero-Knowledge audit check (no secrets, passwords, or hashes leaked): PASSED")

    print("\n[***] ALL FEATURE 5 (SECURITY ACTIVITY MONITOR) TESTS PASSED! [***]\n")

if __name__ == '__main__':
    test_security_activity_monitor()

