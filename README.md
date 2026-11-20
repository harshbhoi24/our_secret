# Our Secret – Image Steganography and Data Integrity Tool 🛡️

A professional, defense-grade cybersecurity web application built for **BCA Cybersecurity Projects**. It combines **Least Significant Bit (LSB) Steganography**, authenticated **AES-256-GCM Encryption**, cryptographic **SHA-256 / HMAC-SHA256 Data Integrity Verification**, and six enterprise security modules with role-based access control.

---

## 🚀 Key Security Architecture & Advanced Features

### 1. Image Capacity Checker (Feature 1)
- **RGB LSB Formula**: Embedding into red, green, and blue 8-bit channels (`width * height * 3 // 8` raw bytes).
- **8-Byte Header Protocol (`OS01`)**: Header overhead includes 4-byte magic signature `b'OS01'` and 4-byte big-endian uint32 payload length. Backward-compatible with legacy `b'OSEC'` images.
- **Crypto Overhead Accounting**: Includes 44-byte AES-GCM envelope (16-byte PBKDF2 salt + 12-byte IV + 16-byte authentication tag).
- **Live Dynamic Capacity Meter**: Real-time frontend calculation showing max message capacity, current message size, remaining capacity, and percentage used with animated progress bar and oversized warnings.
- **Strict Backend Enforcement**: Blocks uploads exceeding capacity before encryption to prevent overflow and carrier truncation.

### 2. Message Expiry Policy (Feature 2)
- **Flexible Expiration Tiers**: Supports **1 Hour**, **24 Hours**, **7 Days**, and **Custom Expiry Date/Time**.
- **Database Vault Storage**: Stored as UTC timestamp (`expires_at`) in `IntegrityRecord`.
- **Backend Extraction Blocking**: Any extraction request for an expired stego image is immediately blocked with an explicit security alert and revoked status.
- **Server-Side File Cleanup Process**: Provides `/steganography/cleanup-expired` allowing operators to purge expired carriers from disk.
- **Offline Copy Disclaimer**: Explicitly notifies operators that downloaded offline copies cannot be remotely deleted from recipient devices.

### 3. QR Code Cryptographic & Security Suite (Feature 3)
- **High-Res Optical Generation & Reed-Solomon Correction**: Generates high-density optical QR tokens using `qrcode` with configurable Level H (30%) or Level M error correction for scratch/distortion recovery.
- **Robust Multi-Pass Computer Vision Scanner**: Uses OpenCV (`cv2.QRCodeDetector`) with fallback adaptive Otsu grayscale thresholding for low-contrast, rotated, or distorted photographs.
- **Operative Access Control & Recipient Dispatch**:
  - Send QR tokens directly to a specific operative by entering their **User ID** or **Username** (with quick-select pills).
  - Admin accounts are strictly excluded from covert recipient selection ("admin nahi rakhna").
  - Dispatched QR codes automatically register in the recipient's **Covert Inbox** (`/steganography/inbox`) with 1-click **Scan QR** redirection (`/qr/tools?scan_carrier=...`).
  - Unauthorized operators and intruders are strictly blocked with 403 access control.
- **Lifecycle & Expiry Enforcement**:
  - 🔥 **Burn-After-Reading**: Single-use token that self-destructs upon initial scan; all subsequent scans are permanently denied.
  - ⏳ **Multi-View Expiry Window**: 1 Hour, 24 Hours, 7 Days, or custom hour window. Scanning is automatically revoked past the threshold.
  - ♾️ **Permanent**: Unrestricted optical verification.
- **Authenticated AES-256-GCM Password Encryption**:
  - Securely encrypts raw QR payloads with PBKDF2 (100,000 iterations) and AES-256-GCM.
  - Scanner prompts for the decryption password upon detecting encrypted ciphertext tokens (`OSENC#`).
  - Integrated **Shannon Password Entropy Meter** and 1-click zero-knowledge **Military Token / Diceware Generator**.
- **Plausible Deniability & Decoy Duress Defense**:
  - Dual-key optical envelope (`OSDEN#`).
  - Entering the **Master Password** unlocks authentic intelligence.
  - Entering the **Decoy Passcode** renders an innocent decoy message while silently firing a high-priority SOC Duress Alarm (`EXTRACT_DURESS_TRIGGERED`) to the Admin Security Monitor.
- **Payload Sanitization & Zero-Knowledge Logging**: Blocks dangerous URI schemes (`javascript:`, `data:text/html`). Plaintext secrets are strictly excluded from all audit trails.
- **LSB Carrier Warning**: Explicitly alerts operators that QR codes make poor LSB steganography carriers due to high-contrast binary patterns.

### 4. 4-Theme Professional Cyber Switcher (Feature 4)
- **Enterprise Blue (Cyber Sentinel - Default)**: Sleek cybersecurity operations center styling (`#0a1128`, `#0077b6`, `#00b4d8`, `#90e0ef`).
- **Tactical Emerald (Defense Grid)**: Military matrix theme (`#061a12`, `#005b41`, `#008170`, `#232d3f`).
- **Navy Purple (Dark Synthwave)**: High-contrast Electric Purple & Deep Slate (`#070b14`, `#0d1527`, `#9d4edd`).
- **Executive Light (Crisp Clean)**: Daylight presentation mode (`#ffffff`, `#f8f7ff`, `#7c3aed`).
- **Zero-Flicker & Instant 1-Click Switch**: Navbar theme dropdown with instant CSS variable updates and `localStorage` persistence.

### 5. Security Activity Monitor (Feature 5)
- **Admin SOC Console (`/admin/security-monitor`)**: Dedicated real-time monitoring console for security administrators.
- **5 Security Metric Cards**:
  1. Total Audit Events
  2. Logins (Successful vs. Failed)
  3. Stego Operations (Encoding vs. Extraction)
  4. Cryptographic Integrity (Verified vs. Tampered)
  5. Suspicious Upload Rejections
- **Forensic Filtering Matrix**: Filter logs dynamically by event category, event status (`SUCCESS`, `FAILED`, `BLOCKED`), and keyword/filename search.
- **Zero-Knowledge Privacy Enforcement**: Plaintext secrets, passwords, and encryption keys are strictly excluded from all audit records.

### 6. Suspicious File Detection & Hardening (Feature 6)
- **Multi-Layer Defensive Inspection (`security/file_validator.py`)**:
  - **Filename Safety**: Blocks path traversal (`..`, `/`, `\`), null bytes (`\x00`), disguised double extensions (`.exe.png`, `.php.bmp`), and hidden files.
  - **MIME & Magic Byte Verification**: Validates magic signatures (`\x89PNG\r\n\x1a\n` for PNG, `BM` for BMP). Detects and rejects renamed Windows PE binaries (`MZ`), ELF executables, ZIP/Office archives, and scripts.
  - **Structural Image Verification**: Uses Pillow (`img.verify()`) to catch corrupted streams, broken chunks, and invalid headers.
  - **Decompression Bomb / Pixel Flood Defense**: Enforces maximum image dimensions (4096&times;4096 px) and total pixel threshold (&le; 16 Megapixels).
  - **File Size Constraints**: Rejects 0-byte files and caps upload sizes at 16MB.
  - **ClamAV Integration Hook**: Detects if ClamAV daemon is reachable via `pyclamd`.
  - **Formal Antivirus Disclaimer**: Explicitly informs operators that heuristic file validation prevents injection and malformed overflows but does not replace an enterprise antimalware engine.

### 7. Secret File Cloaking (Advanced Feature)
- **Arbitrary File Embedding**: Hide entire confidential files (PDF, DOCX, TXT, ZIP, etc.) inside cover images instead of only plain text.
- **Envelope Packing Protocol**:
  - `0x01`: Text envelope (`\x01` + UTF-8 string).
  - `0x02`: File envelope (`\x02` + 2-byte filename length + filename + raw file bytes).
- **AES-256-GCM Binary Encryption**: Encrypts raw binary stream directly before embedding into LSB channels.
- **1-Click File Reconstruction & Download**: During extraction, cloaked files are reconstructed with their original filenames and delivered via safe Base64 Data-URI cards.

### 8. "Burn After Reading" & Dual-Lifecycle Expiry Policy (Advanced Feature)
- **Sender Policy Selection**: The sender chooses between two operational modes:
  1. 🕒 **Multi-View Expiry Window**: Secret can be viewed/extracted multiple times until the expiration deadline (1h, 24h, 7d, custom) passes.
  2. 🔥 **Burn After Reading (Single-Use)**: Ultra-sensitive secrets self-destruct immediately after the first successful extraction. The server carrier file is securely unlinked/deleted from disk and marked `is_burned = True`. All subsequent extraction attempts are permanently blocked.
- **Cross-Module Implementation**:
  - **Steganography Module**: Self-destructs the embedded payload and server carrier file upon first read.
  - **QR Code Security Suite**: Burn-After-Reading QR codes self-destruct upon the first scan; second scan shows revoked alert.

### 9. Cryptographic Password Entropy & Passphrase Generator (Advanced Feature)
- **Real-Time Entropy Meter**: Calculates Shannon password entropy in bits \(E = L \times \log_2(R)\) as the user types.
- **GPU Brute-Force Time Estimation**: Real-time crack resistance calculation based on a modern RTX 4090 cluster (\(10^{11}\) guesses/sec).
- **1-Click Zero-Knowledge Generator**:
  - **Military Token**: 20-character high-entropy alphanumeric/symbolic key (130+ bits).
  - **Diceware Passphrase**: 5 random security words joined with hyphens (e.g., `cipher-sentinel-vault-vector-matrix`).
  - Completely client-side in browser memory (`crypto.getRandomValues`); never sent across the network.

### 10. Visual Steganalysis & Difference Heatmap Inspector (Feature 10)
- **Vectorized Forensic Pixel Subtraction**: Computes exact pixel-by-pixel deltas between reference cover and stego carrier: \(\Delta = |I_{\text{cover}} - I_{\text{stego}}|\).
- **Peak Signal-to-Noise Ratio (PSNR)**: Mathematical logarithmic assessment in decibels (\(10 \cdot \log_{10}(255^2 / \text{MSE})\)). Achieves **&gt; 65 dB PSNR** (Defense-Grade Imperceptibility).
- **Mean Squared Error (MSE)** & **Bit Error Rate (BER)**: Accurately counts altered RGB bits and modified pixels down to a single bit.
- **Amplified Difference Heatmap**: Visualizes invisible 1-bit LSB alterations by amplifying deltas by 255x into fluorescent cyan highlights on a dark slate background.
- **Dedicated Forensic Comparator Route (`/steganography/compare`)**: Allows operators and examiners to upload any cover/stego image pair to inspect and prove covert imperceptibility live.

### 11. Plausible Deniability & Decoy Duress Defense (Feature 11)
- **Anti-Coercion Protection**: Enables sender to set two distinct passwords:
  - **Master Password**: Unlocks the authentic classified intelligence or cloaked file.
  - **Decoy (Duress) Passcode**: Unlocks an innocent decoy message (e.g., meeting schedule).
- **Dual-Slot Ciphertext Packing (`0x03`)**: Authenticated AES-256-GCM encrypted slots for both real and decoy payloads.
- **Silent SOC Duress Alarm**: When an operator extracts with the decoy passcode, the decoy message is displayed cleanly without alerting the coercer, while a critical silent alert (`EXTRACT_DURESS_TRIGGERED`, status `DURESS_ALARM`) is transmitted to the Admin SOC Security Monitor.
- **SOC Alert Dashboard**: Highlights coercion incidents with pulsating red banners and dedicated SOC metric cards.

### 12. Covert Inbox & Recipient-Targeted Dispatch (Feature 12)
- **End-to-End Targeted Dispatch**: When concealing a secret, the sender chooses the specific intended recipient (e.g. `@testuser` or `@admin`) via the **Send Secret To (Target Recipient)** selector.
- **Dedicated Covert Inbox (`/steganography/inbox`)**:
  - **Incoming Secrets (Inbox)**: Displays carriers addressed directly to the logged-in operative, tagged with an unread badge (`NEW / UNREAD`) and unread counter in the top navigation bar.
  - **Dispatched Outbox (Sent)**: Tracks all covert transmissions sent by the operative, displaying the recipient, time, and whether the recipient has extracted/read it yet.
- **1-Click Decrypt & Extract**: Recipients can click **Extract** directly from their inbox without manually re-uploading carrier image files. The carrier is automatically preloaded securely into the extraction vault.
- **Strict Role-Based Access Control**:
  - Non-recipients (unauthorized 3rd-party users) are strictly blocked from downloading the stego carrier file (`/download/<filename>`).
  - Unauthorized users attempting to extract the carrier are immediately rejected with an explicit `⛔ Access Denied` alert, and a security audit event is logged.
  - Only the targeted recipient, the sender, and security administrators have authorization.
- **Streamlined Operator Navigation**:
  - Technical audit logs are removed from regular user navigation and dashboards so regular operators are not overwhelmed by forensic system logs.
  - Regular users get a clean, mission-focused interface centered on **Secret Operations** and their **Covert Inbox**.
  - Detailed audit logs and the Security Monitor console remain strictly protected and accessible only to Administrators.

---

## 📂 Project Architecture

```
our_secret/
│
├── config.py                 # Application configuration (Secrets, DB URI, Limits, HMAC key)
├── app.py                    # Flask application factory, routes, CSRF middleware, security handlers
├── run.py                    # Server launcher
├── seed_data.py              # Database seeding script (Admin, test operator, demo files)
├── start.bat                 # 1-Click launcher for Windows
├── requirements.txt          # Complete pinned dependencies
│
├── test_all_features.py      # Master Test Suite covering all 6 Advanced Features
├── test_feature5_monitor.py  # Unit & security tests for Security Activity Monitor
├── test_feature6_suspicious_files.py # Unit tests for file inspection & rejected upload logging
├── test_suite.py             # 11-point unit test suite
├── e2e_integration_test.py   # Full 12-step end-to-end HTTP integration test
│
├── database/
│   ├── __init__.py           # SQLAlchemy setup & automatic safe SQLite schema migrations
│   └── models.py             # User, ActivityLog, IntegrityRecord models
│
├── security/
│   ├── __init__.py
│   ├── crypto.py             # AES-256-GCM encryption, decryption, PBKDF2-HMAC-SHA256 key derivation
│   ├── integrity.py          # SHA-256 and HMAC-SHA256 hashing & constant-time verification
│   ├── qr_service.py         # QR code generation, OpenCV scanning & payload categorization
│   └── file_validator.py     # Suspicious file detection, magic bytes, decompression bomb defense
│
├── steganography/
│   ├── __init__.py
│   └── lsb.py                # LSB embedding, extraction, OS01 8-byte protocol, capacity calculation
│
├── templates/
│   ├── base.html             # Main layout with theme toggle, navigation & CSRF token
│   ├── index.html            # Public overview with security matrix
│   ├── dashboard.html        # Dynamic operator dashboard with live DB statistics
│   ├── history.html          # Forensic audit log table with zero plaintext leakage
│   ├── profile.html          # Security profile management
│   ├── auth/
│   │   ├── login.html        # Authentication portal with quick demo credential buttons
│   │   └── register.html     # Secure registration
│   ├── steganography/
│   │   ├── hide.html         # Image upload, real-time capacity meter, expiry selector
│   │   ├── hide_success.html # Output summary, SHA-256 fingerprint, download link
│   │   └── extract.html      # Stego image upload, expiry validation, AES-GCM tag check
│   ├── integrity/
│   │   └── verify.html       # File tamper detection and arbitrary text hashing
│   ├── qr/
│   │   └── tools.html        # Optical QR generator and scanner with security advisory
│   ├── admin/
│   │   ├── dashboard.html    # Operator management, tamper alert metrics, audit feed
│   │   └── security_monitor.html # Real-time SOC forensic activity monitor
│   └── errors/
│       ├── 403.html          # Forbidden error
│       ├── 404.html          # Not found error
│       └── 500.html          # Internal error
│
├── static/
│   ├── css/
│   │   └── style.css         # Dark (navy/purple) and Light (white/lavender) design systems
│   └── js/
│       └── main.js           # Theme toggle, live capacity calculations, preview, copy tools
│
└── uploads/
    ├── originals/            # Storage for original cover images
    └── stego/                # Storage for generated lossless steganographic PNG images
```

---

## 🗄️ Database Schema & Safe Migrations

The database (`our_secret.db`) is managed via SQLAlchemy. Safe automatic schema migration is executed during application startup in `database/__init__.py`:

### Models:
1. **`User`**:
   - `id`, `username`, `email`, `password_hash`, `role` (`'admin'` or `'user'`), `is_active`, `created_at`.
2. **`ActivityLog`**:
   - `id`, `user_id`, `operation`, `filename`, `file_hash`, `status`, `integrity_status`, `details`, `ip_address`, `created_at`.
   - **Zero Plaintext Rule**: Never stores secret message text, passwords, or encryption keys.
3. **`IntegrityRecord`**:
   - `id`, `user_id`, `filename`, `original_filename`, `file_hash` (SHA-256), `hmac_signature` (HMAC-SHA256), `file_size`, `image_dimensions`, `expires_at` (DateTime), `is_purged` (Boolean), `created_at`.
   - Properties: `.is_expired` (boolean) and `.expiry_status` (`'ACTIVE'` vs. `'EXPIRED'`).

---

## 🌐 Complete Flask Route Catalog

| Endpoint | HTTP Method | Access Level | Description |
|---|---|---|---|
| `/` | GET | Public | Public landing page & cryptographic matrix overview |
| `/auth/login` | GET, POST | Public | Operator authentication & session establishment |
| `/auth/register` | GET, POST | Public | New operator enrollment |
| `/auth/logout` | GET | Authenticated | Secure session termination & audit logging |
| `/dashboard` | GET | Authenticated | Operational dashboard with live DB statistics |
| `/steganography/hide` | GET, POST | Authenticated | LSB embedding with capacity & expiry policies |
| `/steganography/extract` | GET, POST | Authenticated | LSB extraction with AES-GCM tag & expiry checks |
| `/steganography/compare` | GET, POST | Authenticated | Forensic visual steganalysis & amplified difference heatmap |
| `/steganography/cleanup-expired` | POST | Authenticated | Purges expired stego carrier files from server disk |
| `/api/steganography/capacity` | POST | Authenticated | Real-time capacity JSON API with file validation |
| `/integrity/verify` | GET, POST | Authenticated | SHA-256 & HMAC-SHA256 file and text tamper checks |
| `/qr/tools` | GET | Authenticated | Optical QR generator and scanner console |
| `/qr/generate` | POST | Authenticated | Generates high-res QR code with Level H correction |
| `/qr/scan` | POST | Authenticated | Decodes uploaded QR code with OpenCV |
| `/history` | GET | Authenticated | Forensic activity log history |
| `/profile` | GET, POST | Authenticated | Security profile and credential updates |
| `/admin` | GET | Admin Only | User administration, roles, and status controls |
| `/admin/security-monitor` | GET | Admin Only | Real-time SOC audit monitor with category/status filters |
| `/admin/users/<id>/toggle-role` | POST | Admin Only | Changes user role between admin and user |
| `/admin/users/<id>/toggle-status` | POST | Admin Only | Activates or deactivates an operator account |
| `/admin/users/<id>/delete` | POST | Admin Only | Permanently deletes a user account |
| `/download/<filename>` | GET | Authenticated | Secure lossless download of generated stego PNGs |

---

## 🧪 Comprehensive Test Execution & Results

Every feature was systematically verified and tested:

```bash
# 1. Master Features Test Suite (All Features + Steganalysis + Plausible Deniability)
python test_all_features.py
# Result: 12/12 Tests Passed (100% OK in 1.51s)

# 2. Security Activity Monitor Unit & Access Control Tests
python test_feature5_monitor.py
# Result: 8/8 Tests Passed (OK)

# 3. Suspicious File Detection & Hardening Tests
python test_feature6_suspicious_files.py
# Result: 10/10 Tests Passed (OK)

# 4. Comprehensive Steganography Unit Tests
python test_suite.py
# Result: 11/11 Tests Passed (OK)

# 5. Full End-to-End HTTP Integration Test (18 Real HTTP Scenarios)
python e2e_integration_test.py
# Result: 18/18 End-to-End Steps Passed (100% OK)
```

---

## ⚡ How to Start & Run the Application

### Option 1: One-Click Windows Launcher (Recommended)
Double-click **`start.bat`** in the project directory. It will:
1. Initialize the SQLite database and seed demo accounts.
2. Launch the Flask server at `http://127.0.0.1:5000`.
3. Automatically open your default web browser to the application.

### Option 2: Command Line
```bash
# Navigate to the project directory
cd "C:\Users\Harsh's Laptop\.gemini\antigravity\scratch\our_secret"

# Run the Flask application
python run.py
```

Open your browser and navigate to:
👉 **`http://127.0.0.1:5000`**

### Pre-Configured Demo Accounts:
| Role | Username | Password |
|---|---|---|
| **System Administrator** | `admin` | `Admin@123456` |
| **Security Operator** | `testuser` | `User@123456` |
