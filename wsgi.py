import os
import sys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from app import create_app
from database import db
from seed_data import seed_database
from database.models import User

app = create_app()

with app.app_context():
    db.create_all()
    # Seed default operational credentials if empty
    if User.query.count() == 0:
        seed_database()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
