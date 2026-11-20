import os
import sys
from PIL import Image, ImageDraw

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import create_app
from database import db
from database.models import User, ActivityLog, IntegrityRecord
from security.crypto import encrypt_message
from security.integrity import calculate_sha256, calculate_hmac_sha256
from steganography.lsb import embed_payload

def generate_sample_image(filepath, width=400, height=300):
    """Generate a clean cyber-pattern image to serve as a demo cover."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    img = Image.new('RGB', (width, height), color=(14, 21, 37))
    draw = ImageDraw.Draw(img)
    
    # Draw dark purple/blue cyber grid lines
    for x in range(0, width, 40):
        draw.line([(x, 0), (x, height)], fill=(28, 41, 74), width=1)
    for y in range(0, height, 40):
        draw.line([(0, y), (width, y)], fill=(28, 41, 74), width=1)
        
    # Draw cybersecurity emblem shape
    cx, cy = width // 2, height // 2
    draw.rectangle([cx - 60, cy - 60, cx + 60, cy + 60], outline=(121, 40, 202), width=3)
    draw.line([(cx - 40, cy), (cx + 40, cy)], fill=(168, 85, 247), width=2)
    draw.line([(cx, cy - 40), (cx, cy + 40)], fill=(168, 85, 247), width=2)
    
    img.save(filepath, format='PNG')
    return img

def seed_database():
    app = create_app()
    with app.app_context():
        db.create_all()

        # 1. Create Admin Account
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@oursecret.sec', role='admin')
            admin.set_password('Admin@123456')
            db.session.add(admin)
            print("Created default admin: admin / Admin@123456")

        # 2. Create Demo User Account 1 (Operator)
        demo_user = User.query.filter_by(username='testuser').first()
        if not demo_user:
            demo_user = User(username='testuser', email='testuser@defense.org', role='user')
            demo_user.set_password('User@123456')
            db.session.add(demo_user)
            print("Created default user: testuser / User@123456")

        # 3. Create Demo User Account 2 (Target Operative)
        demo_user2 = User.query.filter_by(username='agent2').first()
        if not demo_user2:
            demo_user2 = User(username='agent2', email='agent2@defense.org', role='user')
            demo_user2.set_password('User@123456')
            db.session.add(demo_user2)
            print("Created default user 2: agent2 / User@123456")

        db.session.commit()

        # 4. Create Sample Cover Image in static/images
        sample_cover_path = os.path.join(app.config['UPLOAD_FOLDER'], 'originals', 'sample_cover.png')
        generate_sample_image(sample_cover_path, 500, 400)
        
        static_sample_path = os.path.join(BASE_DIR, 'static', 'images', 'sample_cover.png')
        generate_sample_image(static_sample_path, 500, 400)

        # 4. Generate initial Stego image and Integrity Record if not present
        if IntegrityRecord.query.count() == 0:
            secret = "MISSION ALPHA: The rendezvous point is 45.4215 N, 75.6972 W. Code name: NIGHTFALL."
            demo_password = "CyberSecretPassword#99"
            encrypted_payload = encrypt_message(secret, demo_password)

            stego_filename = "stego_demo_cyber_vault.png"
            stego_filepath = os.path.join(app.config['STEGO_FOLDER'], stego_filename)

            with open(sample_cover_path, 'rb') as f:
                img_bytes = f.read()

            stego_img, meta = embed_payload(img_bytes, encrypted_payload, stego_filepath)

            with open(stego_filepath, 'rb') as f:
                stego_bytes = f.read()

            file_hash = calculate_sha256(stego_bytes)
            hmac_sig = calculate_hmac_sha256(stego_bytes)

            record = IntegrityRecord(
                user_id=demo_user.id,
                filename=stego_filename,
                original_filename="sample_cover.png",
                file_hash=file_hash,
                hmac_signature=hmac_sig,
                file_size=len(stego_bytes),
                image_dimensions=meta['dimensions']
            )
            db.session.add(record)

            # Activity logs
            log1 = ActivityLog(
                user_id=demo_user.id,
                operation='HIDE_MESSAGE',
                filename=stego_filename,
                file_hash=file_hash,
                status='SUCCESS',
                integrity_status='VERIFIED',
                details=f"Demo steganography embedding ({meta['dimensions']})"
            )
            log2 = ActivityLog(
                user_id=demo_user.id,
                operation='INTEGRITY_CHECK',
                filename=stego_filename,
                file_hash=file_hash,
                status='SUCCESS',
                integrity_status='VERIFIED',
                details="Initial SHA-256 and HMAC-SHA256 baseline verification"
            )
            db.session.add_all([log1, log2])
            db.session.commit()
            print("Created sample stego image and integrity record.")

        print("Database initialized and seeded successfully.")

if __name__ == '__main__':
    seed_database()

