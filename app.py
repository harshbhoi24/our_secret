import os
import base64
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for, flash, 
    session, send_from_directory, jsonify, abort
)
from werkzeug.utils import secure_filename
from sqlalchemy import or_
from PIL import Image

from config import Config
from database import db, run_db_migrations
from database.models import User, ActivityLog, IntegrityRecord, QRBurnRecord
from security.crypto import (
    encrypt_message, decrypt_message, encrypt_bytes, decrypt_bytes, 
    pack_payload, unpack_payload, encrypt_deniable, decrypt_carrier_payload, DecryptionError
)
from security.integrity import (
    calculate_sha256, calculate_file_sha256, calculate_hmac_sha256, 
    verify_hmac_sha256
)
from steganography.lsb import (
    embed_payload, extract_payload, calculate_capacity, 
    StegoCapacityError, InvalidStegoImageError
)
from steganography.steganalysis import analyze_steganography
from security.qr_service import (
    generate_qr_code, scan_qr_code, QRScanError, QRValidationError
)
from security.file_validator import (
    validate_uploaded_image, FileValidationError, ANTIVIRUS_DISCLAIMER,
    check_clamav_status
)

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure upload directories exist
    os.makedirs(app.config['ORIGINALS_FOLDER'], exist_ok=True)
    os.makedirs(app.config['STEGO_FOLDER'], exist_ok=True)

    # Initialize extensions and schema migrations
    db.init_app(app)
    run_db_migrations(app)

    # Helper: CSRF Generation and Validation
    @app.before_request
    def csrf_protect():
        if app.config.get('TESTING') and not app.config.get('WTF_CSRF_ENABLED', True):
            return

        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(32)
        
        # Only validate state-changing POST requests
        if request.method == 'POST':
            # Check form data, json, or headers
            token = (
                request.form.get('csrf_token') or 
                request.headers.get('X-CSRF-Token')
            )
            if not token or token != session.get('csrf_token'):
                # Return JSON error if API request, else 400
                if request.is_json or request.path.startswith('/api/'):
                    return jsonify({'error': 'CSRF token verification failed.'}), 400
                flash('Security validation error (CSRF token mismatch). Please try again.', 'danger')
                return redirect(request.referrer or url_for('index'))

    # Context processor: make current_user, csrf_token, and unread inbox count accessible in all templates
    @app.context_processor
    def inject_globals():
        current_user = None
        unread_inbox_count = 0
        user_id = session.get('user_id')
        if user_id:
            current_user = db.session.get(User, user_id)
            if current_user:
                unread_inbox_count = IntegrityRecord.query.filter_by(
                    recipient_id=user_id,
                    is_read=False,
                    is_purged=False
                ).count()
        return {
            'current_user': current_user,
            'csrf_token': session.get('csrf_token'),
            'now': datetime.utcnow(),
            'unread_inbox_count': unread_inbox_count
        }

    @app.route('/favicon.ico')
    def favicon():
        return '', 204

    # Auth Decorators
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login', next=request.url))
            user = db.session.get(User, session['user_id'])
            if not user or not user.is_active:
                session.clear()
                flash('Your session has expired or your account has been deactivated.', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access the administrator panel.', 'warning')
                return redirect(url_for('login'))
            user = db.session.get(User, session['user_id'])
            if not user or not user.is_admin:
                flash('Access denied. Administrator privileges required.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function

    def log_activity(operation, status, filename=None, file_hash=None, integrity_status='N/A', details=None):
        """Helper to create standardized audit activity logs. Strictly never stores secret messages."""
        user_id = session.get('user_id')
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        activity = ActivityLog(
            user_id=user_id,
            operation=operation,
            filename=filename,
            file_hash=file_hash,
            status=status,
            integrity_status=integrity_status,
            details=details,
            ip_address=client_ip
        )
        db.session.add(activity)
        db.session.commit()

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

    # -------------------------------------------------------------
    # PUBLIC & AUTH ROUTES
    # -------------------------------------------------------------
    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return render_template('index.html')

    @app.route('/auth/register', methods=['GET', 'POST'])
    def register():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Validation
            if not username or len(username) < 3 or not username.isalnum():
                flash('Username must be alphanumeric and at least 3 characters long.', 'danger')
                return render_template('auth/register.html')
            
            if not email or '@' not in email or '.' not in email:
                flash('Please provide a valid email address.', 'danger')
                return render_template('auth/register.html')

            if not password or len(password) < 8:
                flash('Password must be at least 8 characters long.', 'danger')
                return render_template('auth/register.html')

            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('auth/register.html')

            # Check existing username or email
            if User.query.filter_by(username=username).first():
                flash('Username is already taken.', 'danger')
                return render_template('auth/register.html')

            if User.query.filter_by(email=email).first():
                flash('Email is already registered.', 'danger')
                return render_template('auth/register.html')

            # Make first user admin, subsequent users regular
            user_count = User.query.count()
            role = 'admin' if user_count == 0 else 'user'

            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()

            # Automatically log in new user
            session.permanent = True
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['role'] = new_user.role

            log_activity('USER_REGISTER', 'SUCCESS', details=f"New user registered: {username} (Role: {role})")
            flash(f'Account created successfully! Welcome to Our Secret, {username}.', 'success')
            return redirect(url_for('dashboard'))

        return render_template('auth/register.html')

    @app.route('/auth/login', methods=['GET', 'POST'])
    def login():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            user = User.query.filter((User.username == username) | (User.email == username.lower())).first()

            if user and user.check_password(password):
                if not user.is_active:
                    flash('This account has been deactivated by an administrator.', 'danger')
                    log_activity('USER_LOGIN', 'FAILED', details=f"Deactivated login attempt: {username}")
                    return render_template('auth/login.html')

                session.permanent = True
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role

                log_activity('USER_LOGIN', 'SUCCESS', details=f"User {user.username} authenticated successfully.")
                flash(f'Welcome back, {user.username}!', 'success')

                next_page = request.args.get('next')
                if next_page and next_page.startswith('/'):
                    return redirect(next_page)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username/email or password.', 'danger')
                log_activity('USER_LOGIN', 'FAILED', details=f"Failed login attempt for identifier: {username}")

        return render_template('auth/login.html')

    @app.route('/auth/logout')
    def logout():
        username = session.get('username', 'Unknown')
        if 'user_id' in session:
            log_activity('USER_LOGOUT', 'SUCCESS', details=f"User {username} logged out.")
        session.clear()
        flash('You have been logged out securely.', 'info')
        return redirect(url_for('login'))

    # -------------------------------------------------------------
    # USER DASHBOARD
    # -------------------------------------------------------------
    @app.route('/dashboard')
    @login_required
    def dashboard():
        user_id = session['user_id']
        current_user = db.session.get(User, user_id)

        # Database-driven metrics
        now_utc = datetime.utcnow()
        total_images_processed = ActivityLog.query.filter(
            ActivityLog.user_id == user_id,
            ActivityLog.operation.in_(['HIDE_MESSAGE', 'EXTRACT_MESSAGE'])
        ).count()

        successful_hides = ActivityLog.query.filter_by(
            user_id=user_id,
            operation='HIDE_MESSAGE',
            status='SUCCESS'
        ).count()

        successful_extracts = ActivityLog.query.filter_by(
            user_id=user_id,
            operation='EXTRACT_MESSAGE',
            status='SUCCESS'
        ).count()

        # Integrity verification metrics
        total_verifications = ActivityLog.query.filter_by(
            user_id=user_id,
            operation='INTEGRITY_CHECK'
        ).count()

        verified_count = ActivityLog.query.filter_by(
            user_id=user_id,
            operation='INTEGRITY_CHECK',
            integrity_status='VERIFIED'
        ).count()

        tampered_count = ActivityLog.query.filter_by(
            user_id=user_id,
            operation='INTEGRITY_CHECK',
            integrity_status='TAMPERED'
        ).count()

        # Feature 2: Expired carrier count
        expired_count = IntegrityRecord.query.filter(
            IntegrityRecord.user_id == user_id,
            IntegrityRecord.expires_at.isnot(None),
            IntegrityRecord.expires_at < now_utc
        ).count()

        # Received covert carriers addressed to current user
        received_inbox = IntegrityRecord.query.filter_by(
            recipient_id=user_id,
            is_purged=False
        ).order_by(IntegrityRecord.created_at.desc()).limit(10).all()

        # Sent covert carriers dispatched by current user
        sent_dispatches = IntegrityRecord.query.filter(
            IntegrityRecord.user_id == user_id,
            IntegrityRecord.recipient_id.isnot(None),
            IntegrityRecord.is_purged == False
        ).order_by(IntegrityRecord.created_at.desc()).limit(10).all()

        # Recent activities (last 10)
        recent_activities = ActivityLog.query.filter_by(user_id=user_id)\
            .order_by(ActivityLog.created_at.desc())\
            .limit(10).all()

        # Active stego carriers
        active_carriers = IntegrityRecord.query.filter_by(
            user_id=user_id,
            is_purged=False
        ).count()

        stats = {
            'total_images_processed': total_images_processed,
            'successful_hides': successful_hides,
            'successful_extracts': successful_extracts,
            'total_verifications': total_verifications,
            'verified_count': verified_count,
            'tampered_count': tampered_count,
            'active_carriers': active_carriers,
            'expired_count': expired_count,
            'inbox_count': len(received_inbox),
            'outbox_count': len(sent_dispatches)
        }

        return render_template(
            'dashboard.html', 
            stats=stats, 
            recent_activities=recent_activities, 
            received_inbox=received_inbox,
            sent_dispatches=sent_dispatches,
            user=current_user
        )

    # -------------------------------------------------------------
    # CAPACITY API (Interactive frontend feedback)
    # -------------------------------------------------------------
    @app.route('/api/steganography/capacity', methods=['POST'])
    @login_required
    def check_capacity():
        if 'image' not in request.files:
            return jsonify({'error': 'No image file uploaded'}), 400

        file = request.files['image']
        if not file or file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400

        try:
            validate_uploaded_image(file, allowed_extensions={'.png', '.bmp'})
        except FileValidationError as fve:
            log_activity(
                operation='REJECTED_UPLOAD',
                status='BLOCKED',
                filename=file.filename,
                details=f"Capacity API blocked: {str(fve)}"
            )
            return jsonify({'error': str(fve)}), 400

        try:
            image_bytes = file.read()
            msg_len = request.form.get('message_length', 0, type=int)
            capacity_info = calculate_capacity(image_bytes, message_size_bytes=msg_len)
            return jsonify({
                'success': True,
                'capacity': capacity_info
            })
        except Exception as e:
            return jsonify({'error': f'Failed to process image: {str(e)}'}), 400

    # -------------------------------------------------------------
    # HIDE MESSAGE MODULE
    # -------------------------------------------------------------
    @app.route('/steganography/hide', methods=['GET', 'POST'])
    @login_required
    def hide_message():
        if request.method == 'POST':
            if 'image' not in request.files:
                flash('Please select an image file to upload.', 'danger')
                return redirect(request.url)

            file = request.files['image']
            secret_message = request.form.get('secret_message', '').strip()
            password = request.form.get('password', '')

            if not file or file.filename == '':
                flash('Please select a valid image file.', 'danger')
                return redirect(request.url)

            try:
                meta = validate_uploaded_image(file, allowed_extensions={'.png', '.bmp'})
            except FileValidationError as fve:
                log_activity(
                    operation='REJECTED_UPLOAD',
                    status='BLOCKED',
                    filename=file.filename,
                    details=f"Stego Hide blocked: {str(fve)}"
                )
                flash(f"Security Alert: Upload Rejected – {str(fve)}", 'danger')
                return redirect(request.url)

            if not password or len(password) < 6:
                flash('Encryption password must be at least 6 characters long.', 'danger')
                return redirect(request.url)

            # Feature 2: Payload Mode (Text Message vs Cloaked Confidential File)
            payload_type = request.form.get('payload_type', 'text').lower()
            if payload_type == 'file':
                secret_file = request.files.get('secret_file')
                if not secret_file or secret_file.filename == '':
                    flash('Please select a confidential file to cloak.', 'danger')
                    return redirect(request.url)
                raw_payload_bytes = secret_file.read()
                if len(raw_payload_bytes) == 0:
                    flash('The selected confidential file is empty.', 'danger')
                    return redirect(request.url)
                cloaked_fn = secure_filename(secret_file.filename) or "cloaked_secret.bin"
                payload_to_pack = pack_payload('FILE', raw_payload_bytes, cloaked_fn)
                raw_size = len(raw_payload_bytes)
                display_type = f"FILE ({cloaked_fn})"
            else:
                secret_message = request.form.get('secret_message', '').strip()
                if not secret_message:
                    flash('Secret message cannot be empty.', 'danger')
                    return redirect(request.url)
                raw_payload_bytes = secret_message.encode('utf-8')
                cloaked_fn = None
                payload_to_pack = pack_payload('TEXT', raw_payload_bytes)
                raw_size = len(raw_payload_bytes)
                display_type = "TEXT"

            try:
                # Read original image bytes
                orig_filename = secure_filename(file.filename)
                image_bytes = file.read()

                # Save original cover image for forensic steganalysis
                cover_filename = f"cover_{secrets.token_hex(8)}.png"
                cover_filepath = os.path.join(app.config['ORIGINALS_FOLDER'], cover_filename)
                with open(cover_filepath, 'wb') as f_cov:
                    f_cov.write(image_bytes)
                
                # Check capacity before encrypting (Feature 1: RGB LSB + OS01 overhead enforcement)
                capacity = calculate_capacity(image_bytes, message_size_bytes=raw_size)

                if capacity['is_oversized']:
                    flash(
                        f"⚠️ Oversized Payload: Secret data size ({raw_size} bytes) exceeds "
                        f"maximum carrier capacity ({capacity['max_message_chars']} bytes payload / {capacity['max_payload_bytes']} bytes raw). "
                        f"Please shorten your data or use a higher resolution cover image.", 
                        'danger'
                    )
                    log_activity('HIDE_MESSAGE', 'FAILED', filename=orig_filename, 
                                 details=f"Oversized payload rejected: {raw_size}B > max {capacity['max_message_chars']}B")
                    return redirect(request.url)

                # Plausible Deniability (Duress / Decoy Secret)
                enable_deniable = bool(request.form.get('enable_deniable'))
                if enable_deniable:
                    decoy_password = request.form.get('decoy_password', '').strip()
                    decoy_message = request.form.get('decoy_message', '').strip()

                    if not decoy_password or len(decoy_password) < 6:
                        flash('Decoy (Duress) passcode must be at least 6 characters long.', 'danger')
                        return redirect(request.url)
                    if decoy_password == password:
                        flash('Decoy passcode cannot be identical to the master encryption password.', 'danger')
                        return redirect(request.url)
                    if not decoy_message:
                        flash('Decoy secret message cannot be empty when Plausible Deniability is enabled.', 'danger')
                        return redirect(request.url)

                    encrypted_payload = encrypt_deniable(payload_to_pack, password, decoy_message, decoy_password)
                    has_plausible_deniability = True
                    deniable_log_str = "Deniable: ARMED"
                else:
                    encrypted_payload = encrypt_bytes(payload_to_pack, password)
                    has_plausible_deniability = False
                    deniable_log_str = "Deniable: Disabled"

                # Check if encrypted payload fits
                if len(encrypted_payload) > capacity['max_payload_bytes']:
                    flash(
                        f"⚠️ Payload Overflow: Encrypted payload ({len(encrypted_payload)} bytes) exceeds cover image capacity "
                        f"({capacity['max_payload_bytes']} bytes). Please use a larger image or smaller payload.", 
                        'danger'
                    )
                    log_activity('HIDE_MESSAGE', 'FAILED', filename=orig_filename, 
                                 details=f"Capacity overflow: payload {len(encrypted_payload)}B > cap {capacity['max_payload_bytes']}B")
                    return redirect(request.url)

                # Embed payload using LSB
                stego_filename = f"stego_{secrets.token_hex(8)}.png"
                stego_filepath = os.path.join(app.config['STEGO_FOLDER'], stego_filename)

                stego_image, meta = embed_payload(image_bytes, encrypted_payload, stego_filepath)

                # Calculate SHA-256 and HMAC-SHA256 for integrity record
                with open(stego_filepath, 'rb') as f:
                    stego_bytes = f.read()
                
                file_hash = calculate_sha256(stego_bytes)
                hmac_sig = calculate_hmac_sha256(stego_bytes)
                file_size = len(stego_bytes)

                # Forensic Steganalysis calculation (PSNR, MSE, altered bits, difference heatmap)
                steg_analysis = analyze_steganography(image_bytes, stego_bytes)

                # Feature 2: Message Expiry calculation (1h, 24h, 7d, custom, none)
                expiry_choice = request.form.get('expiry_option', '24h')
                now_utc = datetime.utcnow()
                expires_at = None

                if expiry_choice == '1h':
                    expires_at = now_utc + timedelta(hours=1)
                elif expiry_choice == '24h':
                    expires_at = now_utc + timedelta(hours=24)
                elif expiry_choice == '7d':
                    expires_at = now_utc + timedelta(days=7)
                elif expiry_choice == 'custom':
                    try:
                        custom_hours = max(1, int(request.form.get('custom_expiry_hours', 24)))
                    except (ValueError, TypeError):
                        custom_hours = 24
                    expires_at = now_utc + timedelta(hours=custom_hours)

                # Feature 3: Burn After Reading
                burn_after_reading = bool(request.form.get('burn_after_reading'))

                # Target Recipient / Operative Access Control
                access_mode_type = request.form.get('access_mode_type', '').strip()
                recip_raw = request.form.get('recipient_input', '').strip() or request.form.get('recipient_id', '').strip()
                recipient_id = None
                recip_user = None

                # If not public and recipient specified, resolve recipient
                if access_mode_type != 'public' and recip_raw:
                    # Allow searching by numeric User ID or by Username
                    if recip_raw.isdigit():
                        recip_user = db.session.get(User, int(recip_raw))
                    else:
                        clean_name = recip_raw.lstrip('@').strip()
                        recip_user = User.query.filter(User.username.ilike(clean_name)).first()

                    if not recip_user:
                        flash(f"Recipient user '{recip_raw}' not found. Please enter a valid User ID or Username.", "danger")
                        return redirect(request.url)

                    if recip_user.role == 'admin':
                        flash("Administrator cannot be selected as a covert recipient. Please enter an operative User ID or Username.", "danger")
                        return redirect(request.url)

                    if recip_user.id == session['user_id']:
                        flash("You cannot dispatch a covert secret to yourself. Please enter another operative's User ID or Username.", "danger")
                        return redirect(request.url)

                    recipient_id = recip_user.id

                recip_username = recip_user.username if recip_user else 'Public (Anyone with Password)'

                # Save Integrity Record in Database with Expiry, Burn Option, Plausible Deniability & Recipient
                integrity_rec = IntegrityRecord(
                    user_id=session['user_id'],
                    recipient_id=recipient_id,
                    filename=stego_filename,
                    original_filename=orig_filename,
                    cover_filename=cover_filename,
                    file_hash=file_hash,
                    hmac_signature=hmac_sig,
                    file_size=file_size,
                    image_dimensions=meta['dimensions'],
                    expires_at=expires_at,
                    burn_after_reading=burn_after_reading,
                    has_plausible_deniability=has_plausible_deniability,
                    payload_type='FILE' if payload_type == 'file' else 'TEXT',
                    cloaked_filename=cloaked_fn,
                    cloaked_file_size=raw_size if payload_type == 'file' else None
                )
                db.session.add(integrity_rec)

                # Log activity (Strictly NO message content)
                expiry_log_str = expires_at.strftime('%Y-%m-%d %H:%M UTC') if expires_at else 'Permanent'
                log_activity(
                    operation='HIDE_MESSAGE',
                    status='SUCCESS',
                    filename=stego_filename,
                    file_hash=file_hash,
                    integrity_status='VERIFIED',
                    details=f"Embedded {len(encrypted_payload)} encrypted bytes ({display_type}) in {meta['dimensions']} image. (Dispatched to: @{recip_username}, Expires: {expiry_log_str}, Burn: {burn_after_reading}, {deniable_log_str})"
                )

                db.session.commit()

                # Render success view with steganalysis
                result = {
                    'filename': stego_filename,
                    'original_filename': orig_filename,
                    'cover_filename': cover_filename,
                    'dimensions': meta['dimensions'],
                    'file_size': f"{file_size / 1024:.2f} KB",
                    'file_hash': file_hash,
                    'hmac_signature': hmac_sig,
                    'created_at': datetime.now().strftime('%d %b %Y, %I:%M:%S %p'),
                    'expires_at': expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if expires_at else 'Permanent (No Expiry)',
                    'is_expired': False,
                    'burn_after_reading': burn_after_reading,
                    'has_plausible_deniability': has_plausible_deniability,
                    'recipient_id': recipient_id,
                    'recipient_username': recip_username,
                    'payload_type': 'FILE' if payload_type == 'file' else 'TEXT',
                    'cloaked_filename': cloaked_fn,
                    'utilization': meta['utilization_percent'],
                    'download_url': url_for('download_file', filename=stego_filename),
                    'steg_analysis': steg_analysis
                }
                flash(f'Secret message successfully encrypted and hidden inside image! (Target: {recip_username})', 'success')
                return render_template('steganography/hide_success.html', result=result)

            except StegoCapacityError as sce:
                flash(str(sce), 'danger')
                log_activity('HIDE_MESSAGE', 'FAILED', filename=file.filename, details=str(sce))
            except Exception as e:
                flash(f'An unexpected error occurred during steganography embedding: {str(e)}', 'danger')
                log_activity('HIDE_MESSAGE', 'FAILED', filename=file.filename, details=str(e))

            return redirect(request.url)

        active_users = User.query.filter(User.id != session['user_id'], User.role != 'admin', User.is_active == True).order_by(User.username).all()
        return render_template('steganography/hide.html', users=active_users)

    # -------------------------------------------------------------
    # EXTRACT MESSAGE MODULE
    # -------------------------------------------------------------
    @app.route('/steganography/extract', methods=['GET', 'POST'])
    @login_required
    def extract_message():
        extracted_message = None
        cloaked_file = None
        extract_meta = None

        # Check for 1-click extraction parameter from Covert Inbox
        prefill_carrier = None
        carrier_param = request.args.get('carrier', '').strip()
        if carrier_param:
            safe_carrier = secure_filename(carrier_param)
            prefill_carrier = IntegrityRecord.query.filter_by(filename=safe_carrier, is_purged=False).first()
            if prefill_carrier and prefill_carrier.recipient_id:
                user_id = session.get('user_id')
                if user_id not in [prefill_carrier.recipient_id, prefill_carrier.user_id]:
                    recip_name = prefill_carrier.recipient.username if prefill_carrier.recipient else 'another operative'
                    flash(f"⛔ Access Denied: This covert carrier was specifically dispatched to user '{recip_name}'. You are not authorized to view or extract this secret.", 'danger')
                    return redirect(url_for('dashboard'))

        if request.method == 'POST':
            carrier_filename = request.form.get('carrier_filename', '').strip()
            file = request.files.get('image')
            password = request.form.get('password', '')

            if (not file or file.filename == '') and not carrier_filename:
                flash('Please select or upload an image file to extract from.', 'danger')
                return redirect(request.url)

            if not password:
                flash('Decryption password is required.', 'danger')
                return redirect(request.url)

            try:
                # Load image bytes from either uploaded file or server carrier
                if file and file.filename != '':
                    meta = validate_uploaded_image(file, allowed_extensions={'.png', '.bmp'})
                    image_bytes = file.read()
                    filename = secure_filename(file.filename)
                else:
                    filename = secure_filename(carrier_filename)
                    stego_path = os.path.join(app.config['STEGO_FOLDER'], filename)
                    if not os.path.exists(stego_path):
                        flash('The selected carrier file is no longer available on the server.', 'danger')
                        return redirect(request.url)
                    with open(stego_path, 'rb') as f_car:
                        image_bytes = f_car.read()

                file_hash = calculate_sha256(image_bytes)

                # Check if image has a registered integrity record
                record = IntegrityRecord.query.filter_by(file_hash=file_hash).first()
                if not record and carrier_filename:
                    record = IntegrityRecord.query.filter_by(filename=filename).first()
                integrity_status = 'VERIFIED' if record else 'N/A'

                # Targeted Recipient Access Control Enforcement
                user_id = session.get('user_id')
                current_op = db.session.get(User, user_id)

                if record and record.recipient_id:
                    if user_id not in [record.recipient_id, record.user_id]:
                        recip_name = record.recipient.username if record.recipient else 'another operative'
                        flash(f"⛔ Access Denied: This covert carrier was specifically dispatched to user '{recip_name}'. You are not authorized to extract this secret.", 'danger')
                        log_activity(
                            operation='EXTRACT_MESSAGE',
                            status='BLOCKED',
                            filename=filename,
                            file_hash=file_hash,
                            details=f"Unauthorized extraction attempt by user '{current_op.username if current_op else user_id}' on carrier addressed to @{recip_name}."
                        )
                        return redirect(url_for('dashboard'))

                # Feature 3: Burn-After-Reading check (Block if already burned)
                if record and record.is_burned:
                    burned_str = record.burned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if record.burned_at else 'Prior Session'
                    flash(
                        f"🔥 Access Denied: This secret was configured with 'Burn-After-Reading' and has already self-destructed upon its initial extraction ({burned_str}).", 
                        'danger'
                    )
                    log_activity(
                        operation='EXTRACT_MESSAGE',
                        status='FAILED',
                        filename=filename,
                        file_hash=file_hash,
                        integrity_status=integrity_status,
                        details=f"Extraction blocked: Secret burned and self-destructed on {burned_str}."
                    )
                    extract_meta = {
                        'filename': filename,
                        'file_hash': file_hash,
                        'is_burned_blocked': True,
                        'burned_at': burned_str,
                        'is_verified': True,
                        'record': record
                    }
                    return render_template(
                        'steganography/extract.html',
                        extracted_message=None,
                        cloaked_file=None,
                        extract_meta=extract_meta,
                        prefill_carrier=prefill_carrier
                    )

                # Feature 2: Message Expiry backend enforcement
                if record and record.is_expired:
                    expiry_time_str = record.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC')
                    flash(
                        f"⛔ Access Denied: This confidential message expired on {expiry_time_str} and can no longer be decrypted.", 
                        'danger'
                    )
                    log_activity(
                        operation='EXTRACT_MESSAGE',
                        status='FAILED',
                        filename=filename,
                        file_hash=file_hash,
                        integrity_status=integrity_status,
                        details=f"Extraction blocked: Secret message expired on {expiry_time_str}."
                    )
                    extract_meta = {
                        'filename': filename,
                        'file_hash': file_hash,
                        'is_expired': True,
                        'expires_at': expiry_time_str,
                        'is_verified': True,
                        'record': record
                    }
                    return render_template(
                        'steganography/extract.html',
                        extracted_message=None,
                        cloaked_file=None,
                        extract_meta=extract_meta,
                        prefill_carrier=prefill_carrier
                    )

                # 1. Extract LSB payload
                extracted_payload = extract_payload(image_bytes)

                # 2. Decrypt with AES-GCM and verify authentication tag (supports Single & Plausible Deniability Dual-Envelope)
                payload_info = decrypt_carrier_payload(extracted_payload, password)
                is_duress = payload_info.get('is_decoy', False)

                # 3. Handle Burn-After-Reading self-destruct trigger
                burned_triggered = False
                if record and record.burn_after_reading:
                    record.is_burned = True
                    record.burned_at = datetime.utcnow()
                    record.extraction_count = (record.extraction_count or 0) + 1
                    # Purge server carrier file
                    import gc
                    gc.collect()
                    stego_path = os.path.join(app.config['STEGO_FOLDER'], record.filename)
                    if os.path.exists(stego_path):
                        try:
                            os.remove(stego_path)
                        except Exception as e:
                            app.logger.warning(f"Error purging burned file {stego_path}: {e}")
                    record.is_purged = True
                    db.session.commit()
                    burned_triggered = True

                # Mark as read for target recipient
                if record and user_id == record.recipient_id and not record.is_read:
                    record.is_read = True
                    record.read_at = datetime.utcnow()
                    db.session.commit()

                # Activity Logging: Check if Duress/Decoy Code was used
                if is_duress:
                    log_activity(
                        operation='EXTRACT_DURESS_TRIGGERED',
                        status='DURESS_ALARM',
                        filename=filename,
                        file_hash=file_hash,
                        integrity_status=integrity_status,
                        details=f"CRITICAL DURESS ALERT: Decoy/Duress passcode was used on carrier '{filename}'! Possible operator coercion or compromised device."
                    )
                else:
                    log_activity(
                        operation='EXTRACT_MESSAGE',
                        status='SUCCESS',
                        filename=filename,
                        file_hash=file_hash,
                        integrity_status=integrity_status,
                        details=f"Successfully extracted payload ({payload_info['type']}, {len(extracted_payload)} bytes). Burned: {burned_triggered}"
                    )

                if payload_info['type'] == 'FILE':
                    file_bytes = payload_info['file_bytes'] or b''
                    b64_data = base64.b64encode(file_bytes).decode('ascii')
                    cloaked_file = {
                        'filename': payload_info['filename'] or 'cloaked_secret.bin',
                        'size': len(file_bytes),
                        'formatted_size': f"{len(file_bytes) / 1024:.2f} KB" if len(file_bytes) >= 1024 else f"{len(file_bytes)} bytes",
                        'data_uri': f"data:application/octet-stream;base64,{b64_data}"
                    }
                    extracted_message = None
                else:
                    cloaked_file = None
                    extracted_message = payload_info['text']

                extract_meta = {
                    'filename': filename,
                    'file_hash': file_hash,
                    'payload_size': f"{len(extracted_payload)} bytes",
                    'is_verified': record is not None,
                    'is_burned': burned_triggered,
                    'is_duress': is_duress,
                    'record': record,
                    'extracted_at': datetime.now().strftime('%d %b %Y, %I:%M:%S %p')
                }

                if burned_triggered:
                    flash('🔥 Burn-After-Reading Triggered: Secret successfully authenticated and decrypted! Carrier file has self-destructed and been wiped from the server.', 'warning')
                else:
                    flash('Secret payload successfully extracted and verified!', 'success')

            except FileValidationError as fve:
                log_activity(
                    operation='REJECTED_UPLOAD',
                    status='BLOCKED',
                    filename=file.filename if file else 'N/A',
                    details=f"Stego Extract blocked: {str(fve)}"
                )
                flash(f"Security Alert: Upload Rejected – {str(fve)}", 'danger')
            except InvalidStegoImageError as isie:
                flash(f'Steganography Error: {str(isie)}', 'danger')
                log_activity('EXTRACT_MESSAGE', 'FAILED', filename=filename if 'filename' in locals() else 'unknown', details=str(isie))
            except DecryptionError as de:
                flash(f'Decryption Failed: {str(de)}', 'danger')
                log_activity('EXTRACT_MESSAGE', 'FAILED', filename=filename if 'filename' in locals() else 'unknown', 
                             details="Decryption error: incorrect password or corrupted ciphertext.")
            except Exception as e:
                flash(f'Failed to extract message: {str(e)}', 'danger')
                log_activity('EXTRACT_MESSAGE', 'FAILED', filename=filename if 'filename' in locals() else 'unknown', details=str(e))

        return render_template(
            'steganography/extract.html', 
            extracted_message=extracted_message,
            cloaked_file=cloaked_file,
            extract_meta=extract_meta,
            prefill_carrier=prefill_carrier
        )

    # -------------------------------------------------------------
    # FEATURE 2: EXPIRED FILE SERVER CLEANUP
    # -------------------------------------------------------------
    @app.route('/steganography/cleanup-expired', methods=['POST'])
    @login_required
    def cleanup_expired_files():
        user_id = session['user_id']
        current_user = db.session.get(User, user_id)
        now_utc = datetime.utcnow()

        # Admin cleans all expired files; regular users clean their own
        if current_user.is_admin:
            expired_records = IntegrityRecord.query.filter(
                IntegrityRecord.expires_at.isnot(None),
                IntegrityRecord.expires_at < now_utc,
                IntegrityRecord.is_purged == False
            ).all()
        else:
            expired_records = IntegrityRecord.query.filter(
                IntegrityRecord.user_id == user_id,
                IntegrityRecord.expires_at.isnot(None),
                IntegrityRecord.expires_at < now_utc,
                IntegrityRecord.is_purged == False
            ).all()

        purged_count = 0
        for rec in expired_records:
            stego_path = os.path.join(app.config['STEGO_FOLDER'], rec.filename)
            if os.path.exists(stego_path):
                try:
                    os.remove(stego_path)
                except Exception as e:
                    app.logger.warning(f"Error removing {stego_path}: {e}")
            rec.is_purged = True
            purged_count += 1

        db.session.commit()
        log_activity(
            operation='FILE_CLEANUP',
            status='SUCCESS',
            details=f"Server cleanup: Purged {purged_count} expired stego carrier file(s)."
        )
        flash(f"Server-Side Cleanup: {purged_count} expired carrier file(s) have been deleted from server storage. (Note: Offline downloaded copies cannot be remotely deleted).", 'info')
        return redirect(request.referrer or url_for('dashboard'))

    # -------------------------------------------------------------
    # VISUAL STEGANALYSIS & DIFFERENCE COMPARATOR
    # -------------------------------------------------------------
    @app.route('/steganography/compare', methods=['GET', 'POST'])
    @login_required
    def compare_images():
        analysis_result = None
        if request.method == 'POST':
            if 'cover_image' not in request.files or 'stego_image' not in request.files:
                flash('Please select both the Cover Image and the Stego Image to compare.', 'danger')
                return redirect(request.url)

            cover_file = request.files['cover_image']
            stego_file = request.files['stego_image']

            if not cover_file or cover_file.filename == '' or not stego_file or stego_file.filename == '':
                flash('Both image files are required for comparison.', 'danger')
                return redirect(request.url)

            try:
                validate_uploaded_image(cover_file, allowed_extensions={'.png', '.bmp'})
                validate_uploaded_image(stego_file, allowed_extensions={'.png', '.bmp'})

                cover_bytes = cover_file.read()
                stego_bytes = stego_file.read()

                analysis_result = analyze_steganography(cover_bytes, stego_bytes)
                analysis_result['cover_filename'] = secure_filename(cover_file.filename)
                analysis_result['stego_filename'] = secure_filename(stego_file.filename)

                log_activity(
                    operation='STEGANALYSIS_COMPARE',
                    status='SUCCESS',
                    filename=analysis_result['stego_filename'],
                    details=f"Forensic steganalysis complete: PSNR {analysis_result['psnr_str']}, MSE {analysis_result['mse']}, Altered bits {analysis_result['changed_bits']}"
                )
                flash('Forensic Steganalysis and Pixel Heatmap generated successfully!', 'success')
            except FileValidationError as fve:
                log_activity(
                    operation='REJECTED_UPLOAD',
                    status='BLOCKED',
                    filename=secure_filename(stego_file.filename or cover_file.filename),
                    details=f"Steganalysis upload blocked: {str(fve)}"
                )
                flash(f"Security Alert: Upload Rejected – {str(fve)}", 'danger')
            except ValueError as ve:
                flash(f"Forensic Comparison Error: {str(ve)}", 'danger')
            except Exception as e:
                flash(f"Unexpected error during steganalysis: {str(e)}", 'danger')

        return render_template('steganography/compare.html', analysis=analysis_result)

    # -------------------------------------------------------------
    # COVERT INBOX & OPERATIVE DISPATCH CENTER
    # -------------------------------------------------------------
    @app.route('/steganography/inbox')
    @login_required
    def covert_inbox():
        user_id = session['user_id']
        current_user = db.session.get(User, user_id)

        # Received covert carriers addressed to current user
        received_records = IntegrityRecord.query.filter_by(
            recipient_id=user_id,
            is_purged=False
        ).order_by(IntegrityRecord.created_at.desc()).all()

        # Sent covert carriers dispatched by current user
        sent_records = IntegrityRecord.query.filter(
            IntegrityRecord.user_id == user_id,
            IntegrityRecord.recipient_id.isnot(None),
            IntegrityRecord.is_purged == False
        ).order_by(IntegrityRecord.created_at.desc()).all()

        return render_template(
            'steganography/inbox.html',
            received_records=received_records,
            sent_records=sent_records,
            user=current_user
        )

    # -------------------------------------------------------------
    # DATA INTEGRITY SUITE (REDIRECTED TO DASHBOARD)
    # -------------------------------------------------------------
    @app.route('/integrity/verify', methods=['GET', 'POST'])
    @login_required
    def verify_integrity():
        return redirect(url_for('dashboard'))

    # -------------------------------------------------------------
    # FEATURE 3: QR CODE GENERATOR & SCANNER MODULE (EXPANDED SUITE)
    # -------------------------------------------------------------
    @app.route('/qr/tools')
    @login_required
    def qr_tools():
        scan_carrier = request.args.get('scan_carrier', '').strip()
        prefill_qr = None
        if scan_carrier:
            safe_name = secure_filename(scan_carrier)
            prefill_qr = IntegrityRecord.query.filter_by(filename=safe_name, is_purged=False).first()
            if prefill_qr and prefill_qr.recipient_id:
                user_id = session.get('user_id')
                if user_id not in [prefill_qr.recipient_id, prefill_qr.user_id]:
                    recip_name = prefill_qr.recipient.username if prefill_qr.recipient else 'another operative'
                    flash(f"⛔ Access Denied: This QR transmission was specifically dispatched to user '{recip_name}'. You are not authorized to view or scan it.", 'danger')
                    return redirect(url_for('dashboard'))

        active_users = User.query.filter(User.id != session['user_id'], User.role != 'admin', User.is_active == True).order_by(User.username).all()
        active_tab = 'scan' if scan_carrier else request.args.get('active_tab', 'generate')
        return render_template('qr/tools.html', active_tab=active_tab, users=active_users, prefill_qr=prefill_qr)

    @app.route('/qr/generate', methods=['POST'])
    @login_required
    def qr_generate():
        qr_content = request.form.get('qr_content', '').strip()
        content_type = request.form.get('content_type', 'link')
        error_correction = request.form.get('error_correction', 'M')

        if not qr_content:
            flash('Please enter content to generate a QR code.', 'danger')
            return redirect(url_for('qr_tools'))

        # 1. Target Recipient / Operative Access Control ("admin nahi rakhna")
        access_mode_type = request.form.get('access_mode_type', '').strip()
        recip_raw = request.form.get('recipient_input', '').strip() or request.form.get('recipient_id', '').strip()
        recipient_id = None
        recip_user = None

        if access_mode_type != 'public' and recip_raw:
            if recip_raw.isdigit():
                recip_user = db.session.get(User, int(recip_raw))
            else:
                clean_name = recip_raw.lstrip('@').strip()
                recip_user = User.query.filter(User.username.ilike(clean_name)).first()

            if not recip_user:
                flash(f"Recipient user '{recip_raw}' not found. Please enter a valid User ID or Username.", "danger")
                return redirect(url_for('qr_tools'))

            if recip_user.role == 'admin':
                flash("Administrator cannot be selected as a covert recipient. Please enter an operative User ID or Username.", "danger")
                return redirect(url_for('qr_tools'))

            if recip_user.id == session['user_id']:
                flash("You cannot dispatch a covert QR token to yourself. Please enter another operative's User ID or Username.", "danger")
                return redirect(url_for('qr_tools'))

            recipient_id = recip_user.id

        recip_username = recip_user.username if recip_user else 'Public (Anyone with Scanner)'

        # 2. Lifecycle & Expiry Policy (Burn-After-Reading vs Multi-View Window vs Permanent)
        burn_checkbox = bool(request.form.get('burn_after_reading'))
        lifecycle_mode = request.form.get('lifecycle_mode', 'burn' if burn_checkbox else 'permanent').strip()
        burn_after_reading = (lifecycle_mode == 'burn') or burn_checkbox
        expires_at = None

        if lifecycle_mode == 'time_limited':
            burn_after_reading = False
            expiry_choice = request.form.get('expiry_option', '24h')
            now_utc = datetime.utcnow()
            if expiry_choice == '1h':
                expires_at = now_utc + timedelta(hours=1)
            elif expiry_choice == '24h':
                expires_at = now_utc + timedelta(hours=24)
            elif expiry_choice == '7d':
                expires_at = now_utc + timedelta(days=7)
            elif expiry_choice == 'custom':
                try:
                    custom_hours = max(1, int(request.form.get('custom_expiry_hours', 24)))
                except (ValueError, TypeError):
                    custom_hours = 24
                expires_at = now_utc + timedelta(hours=custom_hours)

        # 3. Password Protection & Encryption (AES-256-GCM)
        password = request.form.get('password', '').strip()
        enable_password = bool(request.form.get('enable_password')) or bool(password)
        enable_deniable = bool(request.form.get('enable_deniable')) and enable_password
        decoy_password = request.form.get('decoy_password', '').strip()
        decoy_message = request.form.get('decoy_message', '').strip()

        if enable_password and not password:
            flash('Encryption password is required when password protection is enabled.', 'danger')
            return redirect(url_for('qr_tools'))

        if enable_deniable:
            if not decoy_password or len(decoy_password) < 6:
                flash('Decoy (Duress) passcode must be at least 6 characters.', 'danger')
                return redirect(url_for('qr_tools'))
            if password == decoy_password:
                flash('Decoy passcode cannot be identical to the master encryption password.', 'danger')
                return redirect(url_for('qr_tools'))
            if not decoy_message:
                flash('Innocent decoy message cannot be empty when Duress Defense is active.', 'danger')
                return redirect(url_for('qr_tools'))

        try:
            token_id = secrets.token_hex(16)
            is_encrypted = False
            has_plausible_deniability = False

            # Wire protocol construction:
            if enable_deniable:
                packed_real = pack_payload('TEXT', qr_content.encode('utf-8'))
                envelope = encrypt_deniable(packed_real, password, decoy_message, decoy_password)
                b64_env = base64.b64encode(envelope).decode('utf-8')
                encoded_qr_str = f"OSDEN#{token_id}#{b64_env}"
                is_encrypted = True
                has_plausible_deniability = True
            elif enable_password:
                packed_real = pack_payload('TEXT', qr_content.encode('utf-8'))
                ct = encrypt_bytes(packed_real, password)
                b64_ct = base64.b64encode(ct).decode('utf-8')
                encoded_qr_str = f"OSENC#{token_id}#{b64_ct}"
                is_encrypted = True
            elif burn_after_reading:
                encoded_qr_str = f"OSBURN#{token_id}#{qr_content}"
            elif recipient_id or expires_at:
                encoded_qr_str = f"OSTOK#{token_id}#{qr_content}"
            else:
                encoded_qr_str = qr_content

            png_bytes, data_uri = generate_qr_code(encoded_qr_str, error_correction=error_correction)
            qr_filename = f"qr_{token_id}.png"
            qr_filepath = os.path.join(app.config['STEGO_FOLDER'], qr_filename)
            with open(qr_filepath, 'wb') as f_qr:
                f_qr.write(png_bytes)

            file_hash = calculate_sha256(png_bytes)
            hmac_sig = calculate_hmac_sha256(png_bytes, app.config['SECRET_KEY'])

            # Save QRBurnRecord
            burn_rec = QRBurnRecord(
                user_id=session['user_id'],
                token_id=token_id,
                content_hash=file_hash,
                burn_after_reading=burn_after_reading,
                is_burned=False,
                expires_at=expires_at,
                is_encrypted=is_encrypted,
                has_plausible_deniability=has_plausible_deniability,
                qr_filename=qr_filename,
                recipient_id=recipient_id
            )
            db.session.add(burn_rec)

            # Save IntegrityRecord (registered in Secret Inbox & Dashboard)
            integrity_rec = IntegrityRecord(
                user_id=session['user_id'],
                recipient_id=recipient_id,
                filename=qr_filename,
                original_filename=f"QR_Token_{token_id[:8]}.png",
                file_hash=file_hash,
                hmac_signature=hmac_sig,
                file_size=len(png_bytes),
                image_dimensions='300x300 (QR)',
                expires_at=expires_at,
                burn_after_reading=burn_after_reading,
                has_plausible_deniability=has_plausible_deniability,
                payload_type='QR'
            )
            db.session.add(integrity_rec)
            db.session.commit()

            # Logging & Flash
            status_desc = []
            if recipient_id: status_desc.append(f"To: @{recip_username}")
            if burn_after_reading: status_desc.append("Burn-After-Reading")
            if expires_at: status_desc.append(f"Exp: {expires_at.strftime('%Y-%m-%d %H:%M')}")
            if is_encrypted: status_desc.append("AES-GCM Encrypted")
            if has_plausible_deniability: status_desc.append("Duress Armed")

            log_activity(
                operation='QR_GENERATE',
                status='SUCCESS',
                filename=qr_filename,
                file_hash=file_hash,
                details=f"Generated QR optical token (Type: {content_type.upper()}, Length: {len(qr_content)} chars, {', '.join(status_desc) or 'Standard Public'})"
            )

            flash_msg = 'QR code successfully generated'
            if recipient_id:
                flash_msg += f" and dispatched to operative @{recip_username}'s Secret Inbox!"
            elif burn_after_reading:
                flash_msg += ' with Burn-After-Reading protection!'
            elif is_encrypted:
                flash_msg += ' with AES-256-GCM encryption!'
            else:
                flash_msg += '!'
            flash(flash_msg, 'success')

            active_users = User.query.filter(User.id != session['user_id'], User.role != 'admin', User.is_active == True).order_by(User.username).all()
            return render_template(
                'qr/tools.html',
                active_tab='generate',
                qr_data_uri=data_uri,
                qr_filename=qr_filename,
                qr_token_id=token_id,
                qr_input_content=qr_content,
                qr_content_type=content_type,
                qr_burn_after_reading=burn_after_reading,
                qr_recipient_username=recip_username if recipient_id else None,
                qr_expires_at=expires_at,
                qr_is_encrypted=is_encrypted,
                qr_is_deniable=has_plausible_deniability,
                qr_created_at=datetime.now().strftime('%d %b %Y, %I:%M:%S %p'),
                users=active_users
            )
        except QRValidationError as qve:
            flash(f"QR Validation Error: {str(qve)}", 'danger')
        except Exception as e:
            flash(f"Failed to generate QR code: {str(e)}", 'danger')

        return redirect(url_for('qr_tools'))

    @app.route('/qr/scan', methods=['POST'])
    @login_required
    def qr_scan():
        carrier_filename = request.form.get('carrier_filename', '').strip()
        file = request.files.get('qr_image')
        password = request.form.get('password', '').strip()
        scanned_token_cache = request.form.get('scanned_token_cache', '').strip()

        if (not file or file.filename == '') and not carrier_filename and not scanned_token_cache:
            flash('Please select or upload a QR code image to scan.', 'danger')
            return redirect(url_for('qr_tools', active_tab='scan'))

        filename = 'scanned_qr_token.png'
        try:
            if scanned_token_cache:
                raw_content = scanned_token_cache
            else:
                if file and file.filename != '':
                    meta = validate_uploaded_image(file, allowed_extensions={'.png', '.bmp', '.jpg', '.jpeg'})
                    filename = secure_filename(file.filename)
                    img_bytes = file.read()
                else:
                    filename = secure_filename(carrier_filename)
                    stego_path = os.path.join(app.config['STEGO_FOLDER'], filename)
                    if not os.path.exists(stego_path):
                        flash('The selected QR carrier file is no longer available on the server.', 'danger')
                        return redirect(url_for('qr_tools', active_tab='scan'))
                    with open(stego_path, 'rb') as f_car:
                        img_bytes = f_car.read()

                scan_res = scan_qr_code(img_bytes)
                raw_content = scan_res['content']

        except FileValidationError as fve:
            log_activity(
                operation='REJECTED_UPLOAD',
                status='BLOCKED',
                filename=file.filename if file else carrier_filename,
                details=f"QR Scanner blocked: {str(fve)}"
            )
            flash(f"Security Alert: QR Upload Rejected – {str(fve)}", 'danger')
            return redirect(url_for('qr_tools', active_tab='scan'))
        except QRScanError as qse:
            flash(str(qse), 'danger')
            log_activity('QR_SCAN', 'FAILED', filename=file.filename if file else carrier_filename, details=str(qse))
            return redirect(url_for('qr_tools', active_tab='scan'))
        except Exception as e:
            flash(f"Scanning failed: {str(e)}", 'danger')
            log_activity('QR_SCAN', 'FAILED', filename=file.filename if file else carrier_filename, details=str(e))
            return redirect(url_for('qr_tools', active_tab='scan'))

        try:
            is_burned_triggered = False
            is_decoy_triggered = False
            user_id = session.get('user_id')

            # Check if this is a managed token (OSDEN#, OSENC#, OSBURN#, OSTOK#)
            matched_prefix = None
            for pfx in ['OSDEN#', 'OSENC#', 'OSBURN#', 'OSTOK#']:
                if raw_content.startswith(pfx):
                    matched_prefix = pfx
                    break

            scan_res = {
                'content': raw_content,
                'type': 'TEXT_PAYLOAD',
                'char_length': len(raw_content),
                'byte_length': len(raw_content.encode('utf-8'))
            }

            if matched_prefix:
                parts = raw_content.split('#', 2)
                if len(parts) >= 3:
                    token_id = parts[1]
                    payload_part = parts[2]
                    burn_record = QRBurnRecord.query.filter_by(token_id=token_id).first()
                    integ_record = IntegrityRecord.query.filter_by(filename=f"qr_{token_id}.png").first()

                    # 1. Target Recipient Authorization Enforcement
                    if burn_record and burn_record.recipient_id:
                        if user_id not in [burn_record.recipient_id, burn_record.user_id]:
                            recip_name = burn_record.recipient.username if burn_record.recipient else 'another operative'
                            flash(f"⛔ Access Denied: This QR token was specifically dispatched to user '{recip_name}'. You are not authorized to scan or view this secret.", 'danger')
                            log_activity(
                                operation='QR_SCAN',
                                status='BLOCKED',
                                filename=filename,
                                details=f"Unauthorized QR scan attempt on token addressed to @{recip_name}."
                            )
                            return redirect(url_for('dashboard'))

                    # 2. Expiry Policy Enforcement
                    if burn_record and burn_record.is_expired:
                        exp_str = burn_record.expires_at.strftime('%Y-%m-%d %H:%M:%S UTC') if burn_record.expires_at else 'Prior Threshold'
                        flash(f"⏳ Access Denied: This QR token has expired ({exp_str}) and cannot be decoded.", 'danger')
                        log_activity(
                            operation='QR_SCAN',
                            status='BLOCKED',
                            filename=filename,
                            details=f"QR Scan blocked: Token {token_id[:8]}... expired on {exp_str}."
                        )
                        return render_template(
                            'qr/tools.html',
                            active_tab='scan',
                            scan_result={'is_expired_blocked': True, 'expires_at': exp_str}
                        )

                    # 3. Burn-After-Reading Enforcement
                    if burn_record and burn_record.is_burned:
                        burned_at_str = burn_record.burned_at.strftime('%Y-%m-%d %H:%M:%S UTC') if burn_record.burned_at else 'Previous Session'
                        log_activity(
                            operation='QR_SCAN',
                            status='BLOCKED',
                            filename=filename,
                            details=f"QR Scan blocked: Burn-After-Reading token {token_id[:8]}... already self-destructed on {burned_at_str}."
                        )
                        flash('🔥 Access Denied: This QR token has already self-destructed and cannot be read again.', 'danger')
                        return render_template(
                            'qr/tools.html',
                            active_tab='scan',
                            scan_result={'is_burned_blocked': True, 'burned_at': burned_at_str}
                        )

                    # 4. Decryption Handling (AES-256-GCM / Plausible Deniability)
                    actual_secret = payload_part
                    if matched_prefix in ['OSENC#', 'OSDEN#']:
                        if not password:
                            flash('🔒 This QR payload is encrypted with AES-256-GCM. Please enter the decryption password below.', 'warning')
                            return render_template(
                                'qr/tools.html',
                                active_tab='scan',
                                scan_requires_password=True,
                                pending_carrier_filename=carrier_filename or filename,
                                pending_token=raw_content
                            )
                        try:
                            envelope_bytes = base64.b64decode(payload_part)
                            unpacked = decrypt_carrier_payload(envelope_bytes, password)
                            actual_secret = unpacked.get('text') or ''
                            if unpacked.get('is_decoy'):
                                is_decoy_triggered = True
                                log_activity(
                                    operation='EXTRACT_DURESS_TRIGGERED',
                                    status='DURESS_ALARM',
                                    filename=filename,
                                    details=f"CRITICAL DURESS ALERT: Operative coerced into scanning QR decoy. Token {token_id[:8]}."
                                )
                        except DecryptionError:
                            flash('Authentication Failed: Incorrect decryption password or tampered QR payload.', 'danger')
                            log_activity(
                                operation='QR_SCAN',
                                status='FAILED',
                                filename=filename,
                                details=f"Decryption authentication tag failed for QR token {token_id[:8]}."
                            )
                            return render_template(
                                'qr/tools.html',
                                active_tab='scan',
                                scan_requires_password=True,
                                pending_carrier_filename=carrier_filename or filename,
                                pending_token=raw_content
                            )

                    # 5. Burn-After-Reading Execution & Read Receipts
                    if burn_record:
                        if burn_record.burn_after_reading:
                            burn_record.is_burned = True
                            burn_record.burned_at = datetime.utcnow()
                            is_burned_triggered = True
                            flash('🔥 Burn-After-Reading Triggered: QR payload revealed! This token has now self-destructed.', 'warning')
                        burn_record.scan_count += 1
                        burn_record.is_read = True
                        burn_record.read_at = datetime.utcnow()

                    if integ_record:
                        integ_record.is_read = True
                        integ_record.read_at = datetime.utcnow()
                        if burn_record and burn_record.burn_after_reading:
                            integ_record.is_burned = True
                            integ_record.burned_at = datetime.utcnow()

                    db.session.commit()

                    scan_res['content'] = actual_secret
                    scan_res['char_length'] = len(actual_secret)
                    scan_res['byte_length'] = len(actual_secret.encode('utf-8'))
                    scan_res['is_burned'] = is_burned_triggered
                    scan_res['is_decoy'] = is_decoy_triggered
                    scan_res['scanned_at'] = datetime.now().strftime('%d %b %Y, %I:%M:%S %p')
                    if burn_record and burn_record.created_at:
                        scan_res['created_at'] = burn_record.created_at.strftime('%d %b %Y, %I:%M:%S %p')
                    elif integ_record and integ_record.created_at:
                        scan_res['created_at'] = integ_record.created_at.strftime('%d %b %Y, %I:%M:%S %p')
                    else:
                        scan_res['created_at'] = datetime.now().strftime('%d %b %Y, %I:%M:%S %p')

                    if burn_record and burn_record.sender:
                        scan_res['sender_username'] = burn_record.sender.username
                    elif integ_record and integ_record.sender:
                        scan_res['sender_username'] = integ_record.sender.username
                    else:
                        scan_res['sender_username'] = 'Operator'

            # Final Logging & Render
            log_activity(
                operation='QR_SCAN',
                status='SUCCESS',
                filename=filename,
                details=f"Decoded QR token (Type: {scan_res.get('type')}, Size: {scan_res.get('char_length')} chars, Burned: {is_burned_triggered}, Decoy: {is_decoy_triggered})"
            )
            if not is_burned_triggered and not is_decoy_triggered:
                flash('QR code successfully scanned and decoded!', 'success')

            active_users = User.query.filter(User.id != session['user_id'], User.role != 'admin', User.is_active == True).order_by(User.username).all()
            return render_template(
                'qr/tools.html',
                active_tab='scan',
                scan_result=scan_res,
                users=active_users
            )

        except Exception as e:
            flash(f"Scanning failed: {str(e)}", 'danger')
            log_activity('QR_SCAN', 'FAILED', filename=filename, details=str(e))

        return redirect(url_for('qr_tools', active_tab='scan'))

    # -------------------------------------------------------------
    # HISTORY MODULE
    # -------------------------------------------------------------
    @app.route('/history')
    @login_required
    def history():
        user_id = session['user_id']
        page = request.args.get('page', 1, type=int)
        filter_op = request.args.get('operation', '')
        filter_status = request.args.get('status', '')

        query = ActivityLog.query.filter_by(user_id=user_id)

        if filter_op:
            query = query.filter_by(operation=filter_op)
        if filter_status:
            query = query.filter_by(status=filter_status)

        activities = query.order_by(ActivityLog.created_at.desc()).paginate(
            page=page, per_page=15, error_out=False
        )

        return render_template(
            'history.html', 
            activities=activities, 
            filter_op=filter_op, 
            filter_status=filter_status
        )

    # -------------------------------------------------------------
    # PROFILE MODULE
    # -------------------------------------------------------------
    @app.route('/profile', methods=['GET', 'POST'])
    @login_required
    def profile():
        user_id = session['user_id']
        current_user = db.session.get(User, user_id)

        if request.method == 'POST':
            action = request.form.get('action')

            if action == 'update_details':
                new_email = request.form.get('email', '').strip().lower()
                if not new_email or '@' not in new_email:
                    flash('Please enter a valid email address.', 'danger')
                else:
                    existing = User.query.filter(User.email == new_email, User.id != user_id).first()
                    if existing:
                        flash('Email address is already in use by another account.', 'danger')
                    else:
                        current_user.email = new_email
                        db.session.commit()
                        log_activity('PROFILE_UPDATE', 'SUCCESS', details="Updated email address.")
                        flash('Profile details updated successfully.', 'success')

            elif action == 'change_password':
                current_password = request.form.get('current_password', '')
                new_password = request.form.get('new_password', '')
                confirm_password = request.form.get('confirm_password', '')

                if not current_user.check_password(current_password):
                    flash('Current password is incorrect.', 'danger')
                elif len(new_password) < 8:
                    flash('New password must be at least 8 characters long.', 'danger')
                elif new_password != confirm_password:
                    flash('New passwords do not match.', 'danger')
                else:
                    current_user.set_password(new_password)
                    db.session.commit()
                    log_activity('PROFILE_UPDATE', 'SUCCESS', details="Password changed successfully.")
                    flash('Password changed successfully! Please log in again if required.', 'success')

            return redirect(url_for('profile'))

        # Metrics for profile
        activity_count = ActivityLog.query.filter_by(user_id=user_id).count()
        return render_template('profile.html', user=current_user, activity_count=activity_count)

    # -------------------------------------------------------------
    # ADMIN PANEL
    # -------------------------------------------------------------
    @app.route('/admin')
    @admin_required
    def admin_dashboard():
        total_users = User.query.count()
        total_operations = ActivityLog.query.count()
        failed_integrity_checks = ActivityLog.query.filter_by(
            operation='INTEGRITY_CHECK',
            integrity_status='TAMPERED'
        ).count()
        total_stego_records = IntegrityRecord.query.count()

        # Users table
        users = User.query.order_by(User.created_at.desc()).all()

        # System security activity logs (latest 20)
        logs = ActivityLog.query.order_by(ActivityLog.created_at.desc()).limit(20).all()

        admin_stats = {
            'total_users': total_users,
            'total_operations': total_operations,
            'failed_integrity_checks': failed_integrity_checks,
            'total_stego_records': total_stego_records
        }

        return render_template(
            'admin/dashboard.html', 
            stats=admin_stats, 
            users=users, 
            logs=logs
        )

    @app.route('/admin/users/<int:target_user_id>/toggle-role', methods=['POST'])
    @admin_required
    def admin_toggle_role(target_user_id):
        if target_user_id == session['user_id']:
            flash('You cannot alter your own administrative role.', 'danger')
            return redirect(url_for('admin_dashboard'))

        target_user = db.session.get(User, target_user_id)
        if not target_user:
            flash('Target user not found.', 'danger')
            return redirect(url_for('admin_dashboard'))

        target_user.role = 'user' if target_user.role == 'admin' else 'admin'
        db.session.commit()
        
        log_activity(
            operation='ADMIN_ROLE_CHANGE',
            status='SUCCESS',
            details=f"Admin {session['username']} changed role of {target_user.username} to {target_user.role}."
        )
        flash(f"User '{target_user.username}' role updated to {target_user.role}.", 'success')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/users/<int:target_user_id>/toggle-status', methods=['POST'])
    @admin_required
    def admin_toggle_status(target_user_id):
        if target_user_id == session['user_id']:
            flash('You cannot deactivate your own account.', 'danger')
            return redirect(url_for('admin_dashboard'))

        target_user = db.session.get(User, target_user_id)
        if not target_user:
            flash('Target user not found.', 'danger')
            return redirect(url_for('admin_dashboard'))

        target_user.is_active = not target_user.is_active
        db.session.commit()

        status_str = "activated" if target_user.is_active else "deactivated"
        log_activity(
            operation='ADMIN_USER_STATUS',
            status='SUCCESS',
            details=f"Admin {session['username']} {status_str} user {target_user.username}."
        )
        flash(f"User '{target_user.username}' has been {status_str}.", 'info')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/users/<int:target_user_id>/delete', methods=['POST'])
    @admin_required
    def admin_delete_user(target_user_id):
        if target_user_id == session['user_id']:
            flash('You cannot delete your own account.', 'danger')
            return redirect(url_for('admin_dashboard'))

        target_user = db.session.get(User, target_user_id)
        if not target_user:
            flash('User not found.', 'danger')
            return redirect(url_for('admin_dashboard'))

        username = target_user.username
        db.session.delete(target_user)
        db.session.commit()

        log_activity(
            operation='ADMIN_USER_DELETE',
            status='SUCCESS',
            details=f"Admin {session['username']} permanently deleted user {username}."
        )
        flash(f"User '{username}' was permanently deleted.", 'warning')
        return redirect(url_for('admin_dashboard'))

    @app.route('/admin/security-monitor')
    @admin_required
    def admin_security_monitor():
        # Compute monitor stats across all activity logs
        total_events = ActivityLog.query.count()
        login_success = ActivityLog.query.filter(
            ActivityLog.operation.like('%LOGIN%'), 
            ActivityLog.status == 'SUCCESS'
        ).count()
        login_failed = ActivityLog.query.filter(
            ActivityLog.operation.like('%LOGIN%'), 
            ActivityLog.status == 'FAILED'
        ).count()
        hide_events = ActivityLog.query.filter_by(operation='HIDE_MESSAGE').count()
        extract_events = ActivityLog.query.filter_by(operation='EXTRACT_MESSAGE').count()
        integrity_verified = ActivityLog.query.filter_by(integrity_status='VERIFIED').count()
        integrity_tampered = ActivityLog.query.filter_by(integrity_status='TAMPERED').count()
        suspicious_rejections = ActivityLog.query.filter(
            or_(
                ActivityLog.operation.like('%REJECT%'),
                ActivityLog.operation.like('%SUSPICIOUS%'),
                ActivityLog.status == 'BLOCKED'
            )
        ).count()
        duress_alarms = ActivityLog.query.filter(
            or_(
                ActivityLog.operation.like('%DURESS%'),
                ActivityLog.status == 'DURESS_ALARM'
            )
        ).count()

        monitor_stats = {
            'total_events': total_events,
            'login_success': login_success,
            'login_failed': login_failed,
            'hide_events': hide_events,
            'extract_events': extract_events,
            'integrity_verified': integrity_verified,
            'integrity_tampered': integrity_tampered,
            'suspicious_rejections': suspicious_rejections,
            'duress_alarms': duress_alarms
        }

        # Query and filtering parameters
        filter_category = request.args.get('category', '').strip()
        filter_status = request.args.get('status', '').strip()
        search_query = request.args.get('search', '').strip()
        page = request.args.get('page', 1, type=int)

        query = ActivityLog.query

        if filter_category == 'LOGIN':
            query = query.filter(ActivityLog.operation.like('%LOGIN%'))
        elif filter_category == 'HIDE':
            query = query.filter(ActivityLog.operation == 'HIDE_MESSAGE')
        elif filter_category == 'EXTRACT':
            query = query.filter(ActivityLog.operation == 'EXTRACT_MESSAGE')
        elif filter_category == 'INTEGRITY':
            query = query.filter(ActivityLog.operation == 'INTEGRITY_CHECK')
        elif filter_category == 'REJECTION':
            query = query.filter(
                or_(
                    ActivityLog.operation.like('%REJECT%'),
                    ActivityLog.operation.like('%SUSPICIOUS%'),
                    ActivityLog.status == 'BLOCKED'
                )
            )
        elif filter_category == 'QR':
            query = query.filter(ActivityLog.operation.like('%QR%'))
        elif filter_category == 'DURESS':
            query = query.filter(
                or_(
                    ActivityLog.operation.like('%DURESS%'),
                    ActivityLog.status == 'DURESS_ALARM'
                )
            )

        if filter_status:
            query = query.filter(ActivityLog.status == filter_status)

        if search_query:
            search_pat = f"%{search_query}%"
            query = query.outerjoin(User).filter(
                or_(
                    ActivityLog.filename.ilike(search_pat),
                    ActivityLog.details.ilike(search_pat),
                    ActivityLog.ip_address.ilike(search_pat),
                    User.username.ilike(search_pat)
                )
            )

        logs = query.order_by(ActivityLog.created_at.desc()).paginate(
            page=page, per_page=20, error_out=False
        )

        clamav_available, clamav_status = check_clamav_status()

        return render_template(
            'admin/security_monitor.html',
            monitor_stats=monitor_stats,
            logs=logs,
            filter_category=filter_category,
            filter_status=filter_status,
            search_query=search_query,
            clamav_available=clamav_available,
            clamav_status=clamav_status,
            antivirus_disclaimer=ANTIVIRUS_DISCLAIMER
        )

    # -------------------------------------------------------------
    # SECURE FILE DOWNLOAD
    # -------------------------------------------------------------
    @app.route('/download/<path:filename>')
    @login_required
    def download_file(filename):
        safe_name = secure_filename(filename)
        # Ensure file exists in stego directory
        filepath = os.path.join(app.config['STEGO_FOLDER'], safe_name)
        if not os.path.exists(filepath):
            abort(404)

        # Recipient Authorization Enforcement
        record = IntegrityRecord.query.filter_by(filename=safe_name).first()
        if record and record.recipient_id:
            user_id = session.get('user_id')
            user = db.session.get(User, user_id)
            if user_id not in [record.recipient_id, record.user_id]:
                flash("⛔ Access Denied: This covert carrier was specifically dispatched to another operative. You are not authorized to download it.", "danger")
                log_activity(
                    operation='FILE_DOWNLOAD_BLOCKED',
                    status='BLOCKED',
                    filename=safe_name,
                    details=f"Unauthorized download attempt by user {user.username if user else user_id}"
                )
                return redirect(url_for('dashboard'))

        return send_from_directory(
            app.config['STEGO_FOLDER'], 
            safe_name, 
            as_attachment=True,
            mimetype='image/png'
        )

    # -------------------------------------------------------------
    # ERROR HANDLERS
    # -------------------------------------------------------------
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('errors/404.html'), 404

    @app.errorhandler(403)
    def forbidden_error(error):
        return render_template('errors/403.html'), 403

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('errors/500.html'), 500

    @app.errorhandler(413)
    def request_entity_too_large(error):
        flash('Uploaded file is too large. Maximum supported file size is 16MB.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

    return app

if __name__ == '__main__':
    application = create_app()
    with application.app_context():
        db.create_all()
    application.run(host='127.0.0.1', port=5000, debug=True)

