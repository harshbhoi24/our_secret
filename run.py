import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import create_app
from database import db
from seed_data import seed_database

app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Seed initial admin and demo user if database is empty
        from database.models import User
        if User.query.count() == 0:
            seed_database()

    port = int(os.environ.get('PORT', 5000))
    print(f"[*] Starting 'Our Secret' Cybersecurity Platform at http://127.0.0.1:{port}")
    print("[*] Pre-configured accounts:")
    print("    - Admin:     admin    / Admin@123456")
    print("    - Operator:  testuser / User@123456 (User ID: 2)")
    print("    - Operative: agent2   / User@123456 (User ID: 3)")
    app.run(host='127.0.0.1', port=port, debug=False)

