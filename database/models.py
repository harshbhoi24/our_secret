from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from database import db

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)  # 'user' or 'admin'
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    # Relationships
    activities = db.relationship('ActivityLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    integrity_records = db.relationship('IntegrityRecord', foreign_keys='IntegrityRecord.user_id', backref='sender', lazy='dynamic', cascade='all, delete-orphan')
    received_records = db.relationship('IntegrityRecord', foreign_keys='IntegrityRecord.recipient_id', backref='recipient', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role == 'admin'

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'


class ActivityLog(db.Model):
    __tablename__ = 'activity_logs'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=True)
    operation = db.Column(db.String(50), nullable=False)  # 'HIDE_MESSAGE', 'EXTRACT_MESSAGE', 'INTEGRITY_CHECK', 'LOGIN', etc.
    filename = db.Column(db.String(255), nullable=True)
    file_hash = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(20), nullable=False)  # 'SUCCESS', 'FAILED'
    integrity_status = db.Column(db.String(20), default='N/A', nullable=False)  # 'VERIFIED', 'TAMPERED', 'N/A'
    details = db.Column(db.String(500), nullable=True)  # NOTE: Strictly metadata/logs. NEVER stores secret message text!
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    def __repr__(self):
        return f'<ActivityLog {self.operation} - {self.status} by User {self.user_id}>'


class IntegrityRecord(db.Model):
    __tablename__ = 'integrity_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    file_hash = db.Column(db.String(64), nullable=False, index=True)  # SHA-256
    hmac_signature = db.Column(db.String(64), nullable=False)  # HMAC-SHA256
    file_size = db.Column(db.Integer, nullable=False)
    image_dimensions = db.Column(db.String(50), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)  # Feature 2: Message Expiry (None = permanent)
    is_purged = db.Column(db.Boolean, default=False, nullable=False)  # True when server file is cleaned up
    burn_after_reading = db.Column(db.Boolean, default=False, nullable=False)  # Feature 3: Self-destruct after 1 read
    is_burned = db.Column(db.Boolean, default=False, nullable=False)
    burned_at = db.Column(db.DateTime, nullable=True)
    extraction_count = db.Column(db.Integer, default=0, nullable=False)
    payload_type = db.Column(db.String(20), default='TEXT', nullable=False)  # 'TEXT' or 'FILE'
    cloaked_filename = db.Column(db.String(255), nullable=True)
    cloaked_file_size = db.Column(db.Integer, nullable=True)
    has_plausible_deniability = db.Column(db.Boolean, default=False, nullable=False)  # Duress / Decoy Secret
    cover_filename = db.Column(db.String(255), nullable=True)  # Saved cover image filename for steganalysis
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)  # Target Operative
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    @property
    def formatted_created_at(self):
        """Format real creation time in human-friendly military/local format."""
        if self.created_at:
            return self.created_at.strftime('%d %b %Y, %I:%M:%S %p')
        return 'N/A'

    @property
    def user(self):
        """Backward compatibility for record.user."""
        return self.sender

    @property
    def is_expired(self):
        """Check if secret message has passed its expiry threshold."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def expiry_status(self):
        """Human-readable status for UI dashboards."""
        if self.is_burned:
            return 'BURNED'
        if self.is_purged:
            return 'PURGED'
        if self.is_expired:
            return 'EXPIRED'
        if self.expires_at is None:
            return 'PERMANENT'
        return 'ACTIVE'

    def __repr__(self):
        return f'<IntegrityRecord {self.filename} - Expired: {self.is_expired}>'


class QRBurnRecord(db.Model):
    __tablename__ = 'qr_burn_records'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    token_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    content_hash = db.Column(db.String(64), nullable=False, index=True)
    burn_after_reading = db.Column(db.Boolean, default=True, nullable=False)
    is_burned = db.Column(db.Boolean, default=False, nullable=False)
    burned_at = db.Column(db.DateTime, nullable=True)
    scan_count = db.Column(db.Integer, default=0, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    is_encrypted = db.Column(db.Boolean, default=False, nullable=False)
    has_plausible_deniability = db.Column(db.Boolean, default=False, nullable=False)
    qr_filename = db.Column(db.String(255), nullable=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    read_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now, nullable=False)

    @property
    def formatted_created_at(self):
        """Format real creation time in human-friendly military/local format."""
        if self.created_at:
            return self.created_at.strftime('%d %b %Y, %I:%M:%S %p')
        return 'N/A'

    # Relationships
    sender = db.relationship('User', foreign_keys=[user_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

    @property
    def is_expired(self):
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    @property
    def expiry_status(self):
        if self.is_burned:
            return 'BURNED'
        if self.is_expired:
            return 'EXPIRED'
        if self.expires_at is None:
            return 'PERMANENT'
        return 'ACTIVE'

    def __repr__(self):
        return f'<QRBurnRecord {self.token_id} - Burned: {self.is_burned} - Expired: {self.is_expired}>'

