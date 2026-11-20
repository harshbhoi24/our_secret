from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

db = SQLAlchemy()

def run_db_migrations(app):
    """Safely update existing SQLite tables with new columns if not already present."""
    with app.app_context():
        try:
            db.create_all()
            with db.engine.connect() as conn:
                result = conn.execute(text("PRAGMA table_info(integrity_records)")).fetchall()
                cols = [row[1] for row in result]
                if cols:
                    if 'expires_at' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN expires_at DATETIME"))
                    if 'is_purged' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN is_purged BOOLEAN DEFAULT 0"))
                    if 'burn_after_reading' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN burn_after_reading BOOLEAN DEFAULT 0"))
                    if 'is_burned' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN is_burned BOOLEAN DEFAULT 0"))
                    if 'burned_at' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN burned_at DATETIME"))
                    if 'extraction_count' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN extraction_count INTEGER DEFAULT 0"))
                    if 'payload_type' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN payload_type VARCHAR(20) DEFAULT 'TEXT'"))
                    if 'cloaked_filename' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN cloaked_filename VARCHAR(255)"))
                    if 'cloaked_file_size' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN cloaked_file_size INTEGER"))
                    if 'has_plausible_deniability' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN has_plausible_deniability BOOLEAN DEFAULT 0"))
                    if 'cover_filename' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN cover_filename VARCHAR(255)"))
                    if 'recipient_id' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN recipient_id INTEGER"))
                    if 'is_read' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN is_read BOOLEAN DEFAULT 0"))
                    if 'read_at' not in cols:
                        conn.execute(text("ALTER TABLE integrity_records ADD COLUMN read_at DATETIME"))

                result_qr = conn.execute(text("PRAGMA table_info(qr_burn_records)")).fetchall()
                cols_qr = [row[1] for row in result_qr]
                if cols_qr:
                    if 'expires_at' not in cols_qr:
                        conn.execute(text("ALTER TABLE qr_burn_records ADD COLUMN expires_at DATETIME"))
                    if 'is_encrypted' not in cols_qr:
                        conn.execute(text("ALTER TABLE qr_burn_records ADD COLUMN is_encrypted BOOLEAN DEFAULT 0"))
                    if 'has_plausible_deniability' not in cols_qr:
                        conn.execute(text("ALTER TABLE qr_burn_records ADD COLUMN has_plausible_deniability BOOLEAN DEFAULT 0"))
                    if 'qr_filename' not in cols_qr:
                        conn.execute(text("ALTER TABLE qr_burn_records ADD COLUMN qr_filename VARCHAR(255)"))
                    if 'recipient_id' not in cols_qr:
                        conn.execute(text("ALTER TABLE qr_burn_records ADD COLUMN recipient_id INTEGER"))
                    if 'is_read' not in cols_qr:
                        conn.execute(text("ALTER TABLE qr_burn_records ADD COLUMN is_read BOOLEAN DEFAULT 0"))
                    if 'read_at' not in cols_qr:
                        conn.execute(text("ALTER TABLE qr_burn_records ADD COLUMN read_at DATETIME"))

                conn.commit()
        except Exception as e:
            app.logger.warning(f"Database migration notice: {e}")

