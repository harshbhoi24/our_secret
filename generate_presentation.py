"""
generate_presentation.py
Generates a defense-grade 16:9 PowerPoint Presentation (.pptx)
for "Our Secret – Defense-Grade Image Steganography and Cryptographic Suite"
BCA Final Year Cybersecurity Project.
"""

import os
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

def create_deck():
    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank_layout = prs.slide_layouts[6]

    # Color Palette (Enterprise Cyber Dark Theme)
    BG_DARK = RGBColor(10, 17, 40)        # #0A1128
    BG_CARD = RGBColor(15, 23, 42)        # #0F172A
    CARD_BORDER = RGBColor(30, 41, 59)    # #1E293B
    CYAN = RGBColor(0, 180, 216)          # #00B4D8
    LIGHT_CYAN = RGBColor(144, 224, 239)  # #90E0EF
    PURPLE = RGBColor(157, 78, 221)       # #9D4EDD
    GREEN = RGBColor(16, 185, 129)        # #10B981
    YELLOW = RGBColor(245, 158, 11)       # #F59E0B
    WHITE = RGBColor(255, 255, 255)       # #FFFFFF
    TEXT_MUTED = RGBColor(148, 163, 184)  # #94A3B8

    def add_bg(slide):
        bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0), Inches(0), Inches(13.333), Inches(7.5))
        bg.fill.solid()
        bg.fill.fore_color.rgb = BG_DARK
        bg.line.color.rgb = BG_DARK
        return bg

    def add_header(slide, title_text, category="CYBERSECURITY PLATFORM"):
        # Header Badge
        badge = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.5), Inches(3.2), Inches(0.35))
        badge.fill.solid()
        badge.fill.fore_color.rgb = RGBColor(14, 165, 233)
        badge.line.color.rgb = CYAN
        tf = badge.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = f"🛡️ {category.upper()}"
        p.font.size = Pt(11)
        p.font.bold = True
        p.font.color.rgb = WHITE
        p.alignment = PP_ALIGN.CENTER

        # Main Title
        tx_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.85), Inches(11.7), Inches(0.8))
        tf = tx_box.text_frame
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.text = title_text
        p.font.size = Pt(26)
        p.font.bold = True
        p.font.color.rgb = WHITE

    def add_card(slide, left, top, width, height, title, items, border_color=CYAN, accent_title=False):
        card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
        card.fill.solid()
        card.fill.fore_color.rgb = BG_CARD
        card.line.color.rgb = border_color
        card.line.width = Pt(1.5)

        tf = card.text_frame
        tf.word_wrap = True
        tf.vertical_anchor = MSO_ANCHOR.TOP
        tf.margin_left = Inches(0.25)
        tf.margin_right = Inches(0.25)
        tf.margin_top = Inches(0.25)
        tf.margin_bottom = Inches(0.25)

        p0 = tf.paragraphs[0]
        p0.text = title
        p0.font.size = Pt(15)
        p0.font.bold = True
        p0.font.color.rgb = CYAN if accent_title else WHITE
        p0.space_after = Pt(10)

        for item in items:
            p = tf.add_paragraph()
            p.text = f"•  {item}"
            p.font.size = Pt(11.5)
            p.font.color.rgb = TEXT_MUTED
            p.space_after = Pt(6)

        return card

    # =========================================================================
    # SLIDE 1: TITLE SLIDE
    # =========================================================================
    s1 = prs.slides.add_slide(blank_layout)
    add_bg(s1)

    # Big decorative box
    title_box = s1.shapes.add_textbox(Inches(1.2), Inches(1.5), Inches(11), Inches(4.5))
    tf1 = title_box.text_frame
    tf1.word_wrap = True

    p = tf1.paragraphs[0]
    p.text = "OUR SECRET"
    p.font.size = Pt(48)
    p.font.bold = True
    p.font.color.rgb = CYAN

    p = tf1.add_paragraph()
    p.text = "Defense-Grade Image Steganography & Data Integrity Platform"
    p.font.size = Pt(24)
    p.font.bold = True
    p.font.color.rgb = WHITE
    p.space_after = Pt(20)

    p = tf1.add_paragraph()
    p.text = "A Multi-Layered Cryptographic Covert Communication System combining LSB Steganography, Authenticated AES-256-GCM Encryption, SHA-256 Integrity, Plausible Deniability, and Optical QR Security."
    p.font.size = Pt(13)
    p.font.color.rgb = TEXT_MUTED
    p.space_after = Pt(30)

    # Footer pills
    p = tf1.add_paragraph()
    p.text = "🎓 BCA Final Year Cybersecurity Project   |   Author: Harsh Bhoi   |   Python 3.9 & Flask Web Suite"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = LIGHT_CYAN

    # =========================================================================
    # SLIDE 2: INTRODUCTION & DOMAIN CONTEXT
    # =========================================================================
    s2 = prs.slides.add_slide(blank_layout)
    add_bg(s2)
    add_header(s2, "Introduction & Domain Context: What is Steganography?")

    add_card(s2, 0.8, 1.8, 3.7, 5.0, "1. The Concept of Steganography", [
        "Origin: Greek 'steganos' (covered/hidden) + 'graphein' (writing).",
        "Goal: Conceal the very existence of confidential communication within an ordinary digital cover file.",
        "Unlike encryption, which makes data unreadable, steganography makes data invisible to passive observers.",
        "Widely applied in secure intelligence transmission, digital watermarking, and copyright protection."
    ], CYAN)

    add_card(s2, 4.8, 1.8, 3.7, 5.0, "2. Steganography vs Cryptography", [
        "Cryptography scrambles plaintext into ciphertext: an eavesdropper knows a secret exists, making it an interception target.",
        "Steganography hides the ciphertext inside innocuous media: eavesdroppers cannot suspect any payload exists.",
        "Syllabus Mandate: 'Steganography hides the existence; sensitive messages must be encrypted before being hidden.'",
        "Our Secret unifies both paradigms into a cohesive defense-grade pipeline."
    ], PURPLE)

    add_card(s2, 8.8, 1.8, 3.7, 5.0, "3. Core Project Mission", [
        "Develop a production-ready, browser-accessible cyber operations suite.",
        "Provide zero-knowledge authenticated encryption (AES-256-GCM).",
        "Preserve visual imperceptibility of cover images (>65 dB PSNR).",
        "Enforce strict operative access control with zero admin backdoors.",
        "Equip operators with duress defense and self-destruct lifecycles."
    ], GREEN)

    # =========================================================================
    # SLIDE 3: PROBLEM STATEMENT & MOTIVATION
    # =========================================================================
    s3 = prs.slides.add_slide(blank_layout)
    add_bg(s3)
    add_header(s3, "Problem Statement: The Vulnerabilities in Standard Steganography")

    add_card(s3, 0.8, 1.8, 5.6, 5.0, "⚠️ Limitations of Traditional Tools", [
        "Unencrypted Plaintext Payloads: Most basic tools embed raw strings. Any automated LSB extraction tool immediately reveals the message.",
        "Zero Integrity Verification: No mechanism exists to verify whether pixel data was altered, compressed, or tampered in transit.",
        "Lack of Expiry & Self-Destruct: Secret carriers persist indefinitely on servers and devices, increasing exposure to post-transmission forensic recovery.",
        "Lack of Access Control: Anyone in possession of the carrier image can extract the secret without recipient authentication.",
        "Coercion & Duress Vulnerability: Operators captured or forced to decrypt have no defensive mechanism to protect ultra-classified data."
    ], RGBColor(239, 68, 68))

    add_card(s3, 6.8, 1.8, 5.7, 5.0, "🛡️ How 'Our Secret' Solves These Problems", [
        "Dual-Layer Architecture: Pre-encryption with 256-bit AES-GCM before LSB embedding ensures mathematical secrecy even if extracted.",
        "Cryptographic Integrity: SHA-256 fingerprinting and server HMAC-SHA256 signatures detect single-bit carrier tampering.",
        "Burn-After-Reading & Timed Expiry: Self-destructs the carrier upon first read or revokes access after an operational time window (1h, 24h, 7d).",
        "Operative Access Control: Dispatches to specific User IDs; unauthorized users and administrators are strictly locked out.",
        "Plausible Deniability: Dual-key duress defense reveals authentic decoys while silently alerting the Security Operations Center (SOC)."
    ], GREEN)

    # =========================================================================
    # SLIDE 4: PROJECT OBJECTIVES & SCOPE
    # =========================================================================
    s4 = prs.slides.add_slide(blank_layout)
    add_bg(s4)
    add_header(s4, "Project Objectives & Technical Scope")

    add_card(s4, 0.8, 1.8, 5.6, 2.4, "🎯 Primary Objectives", [
        "Implement lossless RGB Least Significant Bit (LSB) embedding and extraction for PNG/BMP images.",
        "Integrate PBKDF2 (100,000 iterations) + authenticated AES-256-GCM cipher pipeline.",
        "Engineer real-time dynamic capacity checker with byte-level overhead accounting."
    ], CYAN)

    add_card(s4, 6.8, 1.8, 5.7, 2.4, "🎯 Defense & Lifecycle Objectives", [
        "Implement Burn-After-Reading (single-use self-destruct) and multi-view expiry policies.",
        "Construct Covert Inbox with recipient-targeted dispatch and read receipts.",
        "Implement Plausible Deniability (decoy duress passcode + silent SOC alarm)."
    ], PURPLE)

    add_card(s4, 0.8, 4.4, 5.6, 2.4, "🎯 Optical & Verification Scope", [
        "Deliver Optical QR Code Security Suite with Reed-Solomon Level H correction and OpenCV scanner.",
        "Develop Visual Steganalysis comparator proving >65 dB PSNR imperceptibility with amplified difference heatmaps."
    ], GREEN)

    add_card(s4, 6.8, 4.4, 5.7, 2.4, "🎯 Platform Hardening Scope", [
        "Multi-layer defensive inspection rejecting disguised PE executables, double extensions, and decompression bombs.",
        "Admin SOC Security Activity Monitor with 5 real-time metrics cards and zero-knowledge audit logging."
    ], YELLOW)

    # =========================================================================
    # SLIDE 5: SYSTEM ARCHITECTURE & DUAL-LAYER PIPELINE
    # =========================================================================
    s5 = prs.slides.add_slide(blank_layout)
    add_bg(s5)
    add_header(s5, "High-Level Architecture: The Dual-Layer Defense Pipeline")

    add_card(s5, 0.8, 1.8, 3.7, 5.0, "Phase 1: Cryptographic Envelope", [
        "Input: Confidential plaintext or cloaked file binary (PDF, ZIP, DOCX).",
        "Key Derivation: PBKDF2-HMAC-SHA256 with 100,000 iterations & 16-byte random salt.",
        "Cipher: AES-256 in Galois/Counter Mode (GCM) using 12-byte cryptographically random IV.",
        "Authentication Tag: 16-byte MAC tag verifying both confidentiality and integrity.",
        "Result: 44-byte overhead authenticated binary ciphertext envelope."
    ], CYAN)

    add_card(s5, 4.8, 1.8, 3.7, 5.0, "Phase 2: Steganographic LSB Embed", [
        "Cover Image Check: Validated for PNG/BMP format, magic bytes, dimensions, and pixel safety.",
        "Capacity Validation: Dynamic frontend meter checks that payload fits within 3 LSB bits per pixel.",
        "Header Assembly: 4-byte magic signature 'OS01' + 4-byte big-endian payload length.",
        "Bit Manipulation: Payload bitstream sequentially replaces the Least Significant Bit of R, G, B channels.",
        "Carrier Output: Lossless carrier with unchanged visual appearance."
    ], PURPLE)

    add_card(s5, 8.8, 1.8, 3.7, 5.0, "Phase 3: Extraction & Verification", [
        "Recipient Authentication: Validates operative User ID against access control policy.",
        "Lifecycle Evaluation: Verifies active operational status; blocks expired or burned tokens.",
        "LSB Stream Extraction: Reads 'OS01' header and reconstructs exact ciphertext bytes.",
        "AES-GCM Decryption: Validates 16-byte MAC tag. If password wrong or pixels modified -> instant rejection.",
        "Post-Extraction Action: Triggers burn purge (if single-use) and logs zero-knowledge audit record."
    ], GREEN)

    # =========================================================================
    # SLIDE 6: LEAST SIGNIFICANT BIT (LSB) STEGANOGRAPHY
    # =========================================================================
    s6 = prs.slides.add_slide(blank_layout)
    add_bg(s6)
    add_header(s6, "Core Steganography: RGB LSB Embedding & The OS01 Protocol")

    add_card(s6, 0.8, 1.8, 5.6, 5.0, "🔬 The Mathematics of LSB Embedding", [
        "In 24-bit TrueColor images, each pixel consists of 3 channels: Red (8 bits), Green (8 bits), Blue (8 bits).",
        "Color values range from 0 to 255. Modifying the Least Significant Bit (bit 0) alters the color intensity by at most ±1/255 (0.39%).",
        "Human Visual System (HVS) cannot distinguish this minute luminance shift under normal viewing conditions.",
        "Capacity Formula: Total embeddable raw bytes = (Width × Height × 3) // 8.",
        "Example (800×600 px image): 1,440,000 bits = 180,000 bytes (~175.7 KB capacity)."
    ], CYAN)

    add_card(s6, 6.8, 1.8, 5.7, 5.0, "📦 The OS01 Wire Header Protocol", [
        "Standard LSB tools use zero-terminators or fixed size blocks, causing silent overflows or truncation.",
        "Our Secret implements the structured 8-byte 'OS01' header protocol:",
        "  • Bytes 0-3: Magic Signature b'OS01' (identifies valid carrier).",
        "  • Bytes 4-7: 32-bit big-endian unsigned integer (exact payload length in bytes).",
        "  • Bytes 8+: Encrypted payload envelope (AES-GCM ciphertext).",
        "Backward Compatibility: Automatically recognizes legacy 'OSEC' headers.",
        "Header Corruption Check: If 'OS01' magic is absent, extraction immediately rejects without reading further."
    ], PURPLE)

    # =========================================================================
    # SLIDE 7: CRYPTOGRAPHIC INTEGRITY & PROTOCOL
    # =========================================================================
    s7 = prs.slides.add_slide(blank_layout)
    add_bg(s7)
    add_header(s7, "Cryptographic Architecture: Authenticated Encryption & Integrity")

    add_card(s7, 0.8, 1.8, 3.7, 5.0, "1. Key Derivation (PBKDF2)", [
        "Standard: PBKDF2 with HMAC-SHA256.",
        "Iteration Count: 100,000 rounds.",
        "Salt: 16-byte cryptographically secure random bytes (os.urandom).",
        "Protects against pre-computed rainbow tables and dictionary attacks.",
        "Generates a 256-bit symmetric encryption key directly in memory."
    ], CYAN)

    add_card(s7, 4.8, 1.8, 3.7, 5.0, "2. Authenticated Cipher (AES-256-GCM)", [
        "Cipher: Advanced Encryption Standard in Galois/Counter Mode (GCM).",
        "Initialization Vector: 12-byte cryptographically random IV per operation.",
        "Authentication Tag: 16-byte MAC tag verifying payload authenticity.",
        "Benefit: Provides AEAD (Authenticated Encryption with Associated Data).",
        "Any bit flip in stego pixels causes MAC tag mismatch and instant rejection."
    ], GREEN)

    add_card(s7, 8.8, 1.8, 3.7, 5.0, "3. Dual Hashing & HMAC Integrity", [
        "SHA-256 Fingerprint: Cryptographic hash calculated across raw PNG/BMP carrier bytes.",
        "HMAC-SHA256 Signature: Server-side cryptographic signature using server master secret key.",
        "Tamper Detection: Comparing stored hash with current image immediately detects unauthorized modifications.",
        "Registered automatically in Database Vault on upload."
    ], PURPLE)

    # =========================================================================
    # SLIDE 8: FEATURES 1 & 2: CAPACITY & LIFECYCLE EXPIRY
    # =========================================================================
    s8 = prs.slides.add_slide(blank_layout)
    add_bg(s8)
    add_header(s8, "Features 1 & 2: Live Capacity Meter & Dual Lifecycle Policy")

    add_card(s8, 0.8, 1.8, 5.6, 5.0, "📊 Feature 1: Real-Time Capacity Checker", [
        "Live Client-Side Capacity Meter: As the operator selects an image, the system calculates exact pixel capacity in real time.",
        "Accounting for Overheads: Deducts 8-byte OS01 header + 44-byte AES-GCM envelope + payload packaging flag.",
        "Dynamic Progress Bar: Color-coded utilization gauge (Green < 60%, Yellow 60-85%, Red > 85%).",
        "Oversized Message Prevention: Blocks payload submission if content exceeds image capacity, preventing carrier truncation.",
        "Supports dynamic recalculation across text input and secret file cloaking."
    ], CYAN)

    add_card(s8, 6.8, 1.8, 5.7, 5.0, "⏳ Feature 2: Dual Lifecycle Expiry Policy", [
        "1. 🕒 Multi-View Expiry Window:",
        "   • Operational windows: 1 Hour, 24 Hours, 7 Days, or Custom Hours.",
        "   • Allows legitimate multi-view relay until deadline expires.",
        "   • Extraction post-deadline is strictly blocked by database vault.",
        "2. 🔥 Burn-After-Reading (Single-Use Self-Destruct):",
        "   • Ultra-sensitive intelligence self-destructs upon first extraction.",
        "   • Server carrier file is securely unlinked/deleted from disk.",
        "   • Record marked is_burned = True; all future reads permanently denied.",
        "3. Server Cleanup Process: Purges expired carrier files from storage."
    ], YELLOW)

    # =========================================================================
    # SLIDE 9: FEATURE 3: OPTICAL QR CODE SECURITY SUITE
    # =========================================================================
    s9 = prs.slides.add_slide(blank_layout)
    add_bg(s9)
    add_header(s9, "Feature 3: Optical QR Code Cryptographic & Security Suite")

    add_card(s9, 0.8, 1.8, 3.7, 5.0, "1. High-Density Optical QR", [
        "Generator: Python qrcode with configurable error correction.",
        "Reed-Solomon Level H: 30% data recovery capability for damaged, printed, or scratched tokens.",
        "Wire Protocols:",
        "  • OSDEN#: Plausible deniability envelope.",
        "  • OSENC#: AES-256-GCM encrypted payload.",
        "  • OSBURN#: Single-use self-destruct.",
        "  • OSTOK#: Expiry / recipient tracked token."
    ], CYAN)

    add_card(s9, 4.8, 1.8, 3.7, 5.0, "2. Multi-Pass Vision Scanner", [
        "Engine: OpenCV cv2.QRCodeDetector.",
        "Fallback Adaptive Thresholding: Applies Otsu binarization for low-contrast, rotated, or distorted photos.",
        "Sanitization: Rejects dangerous URI schemes (javascript:, data:text/html) to prevent XSS injection.",
        "Smart Password Prompt: Prompts for AES-GCM password upon detecting encrypted ciphertext tokens."
    ], PURPLE)

    add_card(s9, 8.8, 1.8, 3.7, 5.0, "3. Operative Access & Lifecycles", [
        "Direct Dispatch: Send QR tokens to specific User ID / Username with quick-select pills.",
        "Admin Excluded: Zero administrative backdoor ('admin nahi rakhna').",
        "Inbox Integration: Dispatched QR registered in Covert Inbox with 1-Click 'Scan QR'.",
        "Burn-After-Reading: QR token permanently self-destructs after first optical decode."
    ], GREEN)

    # =========================================================================
    # SLIDE 10: FEATURES 5 & 6: SECURITY MONITOR & FILE HARDENING
    # =========================================================================
    s10 = prs.slides.add_slide(blank_layout)
    add_bg(s10)
    add_header(s10, "Features 5 & 6: Security Activity Monitor & Defensive Hardening")

    add_card(s10, 0.8, 1.8, 5.6, 5.0, "🛡️ Feature 5: Admin SOC Security Monitor", [
        "Real-Time SOC Console (/admin/security-monitor): Dedicated dashboard for system administrators.",
        "5 Security Metric Cards:",
        "  1. Total Audit Events logged.",
        "  2. Authentication Activity (Successful vs. Failed Logins).",
        "  3. Steganography Operations (Embedding vs. Extraction).",
        "  4. Cryptographic Integrity (Verified vs. Tampered).",
        "  5. Suspicious Upload Rejections.",
        "Forensic Filtering: Dynamic filtering by event category, status (SUCCESS, FAILED, BLOCKED, DURESS_ALARM), and keyword search.",
        "Zero-Knowledge Privacy: Plaintext secrets, passwords, and hashes are strictly excluded from all audit records."
    ], CYAN)

    add_card(s10, 6.8, 1.8, 5.7, 5.0, "🚫 Feature 6: Suspicious File Detection", [
        "Multi-Layer Inspection (security/file_validator.py):",
        "  • Filename Safety: Blocks path traversal (../), null bytes (\\x00), and dangerous double extensions (.exe.png, .php.bmp).",
        "  • MIME & Magic Bytes: Enforces raw magic signatures (\\x89PNG for PNG, BM for BMP). Detects and rejects renamed Windows PE (MZ), ELF binaries, ZIP archives, and scripts.",
        "  • Structural Verification: Uses Pillow img.verify() to catch corrupted streams, broken chunks, and invalid image headers.",
        "  • Decompression Bomb Defense: Restricts image dimensions to ≤ 4096×4096 px and total pixels ≤ 16 Megapixels.",
        "  • Upload Constraints: Rejects 0-byte empty files and caps size at 16MB.",
        "  • Antivirus Disclaimer: Explicitly documents scope of heuristic file inspection."
    ], RGBColor(239, 68, 68))

    # =========================================================================
    # SLIDE 11: ADVANCED INNOVATIONS: FILE CLOAKING & DURESS DEFENSE
    # =========================================================================
    s11 = prs.slides.add_slide(blank_layout)
    add_bg(s11)
    add_header(s11, "Advanced Innovations: Secret File Cloaking & Plausible Deniability")

    add_card(s11, 0.8, 1.8, 5.6, 5.0, "📁 Secret File Cloaking (Arbitrary Media)", [
        "Concept: Beyond plain text, operators can hide entire confidential binary files (PDF reports, ZIP archives, DOCX, TXT) inside cover images.",
        "Binary Envelope Protocol:",
        "  • Flag 0x01: Text envelope (\\x01 + UTF-8 payload).",
        "  • Flag 0x02: File envelope (\\x02 + 2-byte filename length + filename string + raw file bytes).",
        "AES-256-GCM Binary Encryption: Encrypts the raw binary byte stream before LSB embedding.",
        "1-Click Lossless Reconstruction: Upon extraction, the file is reconstructed with its original filename and presented via secure Data-URI download."
    ], CYAN)

    add_card(s11, 6.8, 1.8, 5.7, 5.0, "🎭 Plausible Deniability (Duress Defense)", [
        "Anti-Coercion Threat Model: If an operator is captured and physically forced to decrypt the stego image, they must not reveal the classified secret.",
        "Dual-Slot Ciphertext Packing (Flag 0x03):",
        "  • Slot 1: Classified Secret encrypted with Master Password.",
        "  • Slot 2: Innocent Decoy Message encrypted with Decoy (Duress) Passcode.",
        "Coercion Defense: Entering the Decoy Passcode displays the innocent decoy message cleanly to the coercer.",
        "Silent SOC Panic Alarm: Simultaneously transmits a high-priority silent alert (EXTRACT_DURESS_TRIGGERED, status DURESS_ALARM) to the Admin Monitor."
    ], RGBColor(245, 158, 11))

    # =========================================================================
    # SLIDE 12: COVERT INBOX & REAL-TIME TIMESTAMPS
    # =========================================================================
    s12 = prs.slides.add_slide(blank_layout)
    add_bg(s12)
    add_header(s12, "Advanced Innovations: Covert Inbox & Real Current Timestamps")

    add_card(s12, 0.8, 1.8, 5.6, 5.0, "📬 Covert Inbox & Recipient Access Control", [
        "Targeted Dispatch: Sender designates intended operative by User ID or Username (e.g., @agent2, User ID: 3).",
        "Strict Access Boundary: Download endpoint (/download/<filename>) and Extractor verify recipient identity. Unauthorized operators get 403 Access Denied.",
        "Admin Backdoor Prohibition: Administrators cannot intercept or decrypt private transmissions ('admin nahi rakhna').",
        "Dedicated Covert Inbox (/steganography/inbox):",
        "  • Received Tab (Inbox): Shows incoming secrets tagged with NEW / UNREAD badge and 1-Click Extract button.",
        "  • Sent Tab (Outbox): Tracks dispatch history, read receipts, and burn statuses.",
        "  • Dynamic Unread Counter: Displays unread count in navbar badge."
    ], CYAN)

    add_card(s12, 6.8, 1.8, 5.7, 5.0, "🕒 Real Current Local Timestamps", [
        "Local System Time Alignment: Replaced generic UTC with real local system time (datetime.now()) matching operator's actual clock.",
        "Concealed / Dispatched At: Records exact date, hour, minute, and second when secret was encrypted and embedded.",
        "Forensic Provenance Card on Extraction:",
        "  • Displays Dispatched At timestamp (e.g. 20 Nov 2026, 01:35 PM).",
        "  • Displays Dispatched By (@sender username).",
        "  • Displays Target Carrier and Decrypted At timestamp.",
        "QR Code Provenance: Optical QR scanner displays original generated timestamp and decoding timestamp."
    ], GREEN)

    # =========================================================================
    # SLIDE 13: MATHEMATICAL STEGANALYSIS & HEATMAP
    # =========================================================================
    s13 = prs.slides.add_slide(blank_layout)
    add_bg(s13)
    add_header(s13, "Forensic Proof: Mathematical Steganalysis & Difference Heatmap")

    add_card(s13, 0.8, 1.8, 5.6, 5.0, "📐 Mathematical Metrics & PSNR Assessment", [
        "To scientifically prove that the cover image is visually undamaged, the platform computes forensic pixel deltas:",
        "1. Mean Squared Error (MSE):",
        "   MSE = (1 / 3MN) Σ [I_cover(x,y,c) - I_stego(x,y,c)]²",
        "2. Peak Signal-to-Noise Ratio (PSNR):",
        "   PSNR = 10 · log10(255² / MSE)  [in decibels, dB]",
        "Defense-Grade Benchmark (>65 dB):",
        "  • Industry standard for imperceptible steganography is > 40 dB.",
        "  • Our Secret consistently achieves > 65 to 80 dB PSNR, demonstrating military-grade imperceptibility.",
        "3. Bit Error Rate (BER): Exact count of modified LSB bits."
    ], CYAN)

    add_card(s13, 6.8, 1.8, 5.7, 5.0, "🔥 Amplified Difference Heatmap Inspector", [
        "Visual Comparator Route (/steganography/compare): Allows examiners to upload Cover Image vs. Stego Image side-by-side.",
        "Vectorized Pixel Subtraction: Computes Δ = |I_cover - I_stego| across NumPy RGB arrays.",
        "255× Amplification: Because 1-bit LSB changes (0.39%) are invisible to human eyes, the delta is multiplied by 255×.",
        "Color Palette: Renders unaltered pixels as deep black/slate, and modified secret payload pixels as fluorescent cyan highlights.",
        "Examiner Utility: Visually demonstrates where bits were embedded while proving the actual stego image remains visually indistinguishable."
    ], PURPLE)

    # =========================================================================
    # SLIDE 14: TECH STACK & DATABASE ARCHITECTURE
    # =========================================================================
    s14 = prs.slides.add_slide(blank_layout)
    add_bg(s14)
    add_header(s14, "Technology Stack & Database Vault Architecture")

    add_card(s14, 0.8, 1.8, 5.6, 5.0, "💻 Technology Stack", [
        "Backend Framework: Python 3.9 & Flask 3.0 (lightweight, modular WSGI architecture).",
        "ORM & Storage: Flask-SQLAlchemy 3.1 with SQLite database (zero-configuration standalone vault).",
        "Computer Vision: OpenCV (cv2.QRCodeDetector) & Pillow (PIL) for lossless pixel manipulation.",
        "Cryptography Engine: cryptography library (hazmat primitives for AES-256-GCM and PBKDF2).",
        "Frontend Architecture: Bootstrap 5.3, Bootstrap Icons 1.11, JetBrains Mono & Plus Jakarta Sans typography.",
        "Client-Side Zero-Knowledge: Web Crypto API (window.crypto.getRandomValues) for client-side password entropy & Diceware."
    ], CYAN)

    add_card(s14, 6.8, 1.8, 5.7, 5.0, "🗄️ Database Vault Schema (SQLite)", [
        "1. users: id, username, email, password_hash (pbkdf2:sha256), role (admin/user), is_active, created_at.",
        "2. integrity_records: id, user_id (sender), recipient_id, filename, original_filename, file_hash (SHA-256), hmac_signature, file_size, dimensions, expires_at, is_burned, is_purged, payload_type (TEXT/FILE/QR), cloaked_filename, has_plausible_deniability, is_read, read_at, created_at.",
        "3. qr_burn_records: id, user_id, recipient_id, token_id, content_hash, burn_after_reading, is_burned, burned_at, scan_count, expires_at, is_encrypted, has_plausible_deniability, qr_filename, is_read, created_at.",
        "4. activity_logs: id, user_id, operation, filename, file_hash, status, integrity_status, details, ip_address, created_at."
    ], GREEN)

    # =========================================================================
    # SLIDE 15: RIGOROUS TESTING & VERIFICATION
    # =========================================================================
    s15 = prs.slides.add_slide(blank_layout)
    add_bg(s15)
    add_header(s15, "Testing & Quality Assurance: 100% Automated Test Coverage")

    add_card(s15, 0.8, 1.8, 5.6, 5.0, "🧪 Master Unit Test Suite (test_all_features.py)", [
        "14 Comprehensive Test Suites — 100% Passed (13.39s):",
        "  [+] Feature 1: Capacity calculation with OS01 8-byte overhead.",
        "  [+] Feature 2: Message expiry models & backend extraction blocking.",
        "  [+] Feature 3: QR code generation (Level H) & OpenCV scan.",
        "  [+] Feature 4: CSS theme tokens & theme toggle persistence.",
        "  [+] Feature 5: Security Activity Monitor metrics & category filters.",
        "  [+] Feature 6: Suspicious file inspection (PE, bombs, extensions).",
        "  [+] Crypto Pipeline: Full AES-256-GCM + LSB embed/decrypt.",
        "  [+] Advanced BAR: Burn-After-Reading self-destruct state.",
        "  [+] Advanced Cloaking: Secret PDF embedding & reconstruction.",
        "  [+] Advanced Entropy: Shannon entropy & Diceware generator.",
        "  [+] Advanced Duress: Dual-key decoy extraction & silent SOC alarm.",
        "  [+] Advanced QR Suite: Encrypted QR, duress QR & recipient block.",
        "  [+] Advanced Inbox: Recipient dispatch & outbox read receipts.",
        "  [+] Advanced Steganalysis: Mathematical PSNR/MSE metrics."
    ], GREEN)

    add_card(s15, 6.8, 1.8, 5.7, 5.0, "🌐 End-to-End HTTP Integration (e2e_integration_test.py)", [
        "19 Full-Stack HTTP Route Tests — 100% Passed:",
        "  [+] 1. Public Landing Page probe (200 OK)",
        "  [+] 2. Operator Authentication & Admin login (200 OK)",
        "  [+] 3. Dashboard Real-time Statistics (200 OK)",
        "  [+] 4. LSB Embedding & AES-256-GCM Encryption (200 OK)",
        "  [+] 5. Lossless Stego PNG Download (200 OK)",
        "  [+] 6. Extract & Authenticate Secret Message (200 OK)",
        "  [+] 7. Reject Incorrect Password via AES-GCM Tag (200 OK)",
        "  [+] 8. Optical QR Code Generation (200 OK)",
        "  [+] 9. Expired Server Files Cleanup (200 OK)",
        "  [+] 10. Audit Log History & Zero Plaintext Leakage (200 OK)",
        "  [+] 11. Admin Management & Audit Feed (200 OK)",
        "  [+] 12. Security Profile (200 OK)",
        "  [+] 13. HTTP Secret File Cloaking (PDF Concealment) (200 OK)",
        "  [+] 14. HTTP Cloaked File Extraction (200 OK)",
        "  [+] 15. Burn-After-Reading Initial Extraction & Self-Destruct (200 OK)",
        "  [+] 16. Burn-After-Reading Second Extraction Blocked (200 OK)",
        "  [+] 17. HTTP Visual Steganalysis & Difference Heatmap (200 OK)",
        "  [+] 18. Plausible Deniability Decoy Extraction & SOC Duress (200 OK)",
        "  [+] 19. Covert Inbox & Recipient Dispatch Access Control (200 OK)"
    ], CYAN)

    # =========================================================================
    # SLIDE 16: CONCLUSION & FUTURE ENHANCEMENTS
    # =========================================================================
    s16 = prs.slides.add_slide(blank_layout)
    add_bg(s16)
    add_header(s16, "Conclusion & Future Research Directions")

    add_card(s16, 0.8, 1.8, 5.6, 5.0, "🏁 Project Summary & Achievements", [
        "Exceeded Syllabus Mandate: Satisfied all university requirements while elevating the application to defense-grade cybersecurity standards.",
        "Dual-Layer Innovation: Unifies AES-256-GCM cryptographic confidentiality with RGB LSB steganographic imperceptibility (>65 dB PSNR).",
        "Novel Anti-Coercion Defense: Plausible Deniability allows operators under duress to unlock decoy data while silently alerting security monitors.",
        "Zero-Knowledge Architecture: Plaintext secrets and passwords never touch logs or databases.",
        "Cross-Platform Deployment: Production-ready for local workstations, mobile browser access, and 24/7 cloud hosting on Render.com."
    ], GREEN)

    add_card(s16, 6.8, 1.8, 5.7, 5.0, "🔮 Future Enhancements", [
        "1. Transform Domain Steganography: Implement Discrete Cosine Transform (DCT) and Discrete Wavelet Transform (DWT) for JPEG resilience.",
        "2. Audio & Video Steganography: Expand covert channels into MP3 audio frames and MP4 video H.264 macroblocks.",
        "3. Hardware Security Key (FIDO2 / YubiKey): Hardware-backed authentication for master stego key storage.",
        "4. Mobile Native App (Flutter/React Native): Native camera integration with instant offline optical stego decoding.",
        "5. Automated Steganalysis AI: Machine Learning CNN models (e.g. XuNet, SRNet) to detect third-party steganography carriers."
    ], PURPLE)

    # =========================================================================
    # SLIDE 17: QUESTIONS & ANSWERS / VIVA DEFENSE
    # =========================================================================
    s17 = prs.slides.add_slide(blank_layout)
    add_bg(s17)

    box = s17.shapes.add_textbox(Inches(1.5), Inches(1.8), Inches(10.3), Inches(4.5))
    tf17 = box.text_frame
    tf17.word_wrap = True

    p = tf17.paragraphs[0]
    p.text = "THANK YOU!"
    p.font.size = Pt(44)
    p.font.bold = True
    p.font.color.rgb = CYAN
    p.alignment = PP_ALIGN.CENTER

    p = tf17.add_paragraph()
    p.text = "QUESTIONS & VIVA DISCUSSION"
    p.font.size = Pt(22)
    p.font.bold = True
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.CENTER
    p.space_after = Pt(25)

    p = tf17.add_paragraph()
    p.text = "Key Topics Ready for Viva Demonstration:\n" \
             "• Mathematical Proof of Imperceptibility (PSNR > 65 dB & Difference Heatmap)\n" \
             "• AES-256-GCM AEAD Tag Authentication & Bit Flip Rejection\n" \
             "• Plausible Deniability & Silent SOC Duress Alarm Transmission\n" \
             "• One-Time Burn-After-Reading Self-Destruct Lifecycle\n" \
             "• Covert Inbox Operative Access Control (User ID vs Public Mode)\n" \
             "• Optical QR Code Level H Error Correction & OpenCV Multi-Pass Decoding"
    p.font.size = Pt(13)
    p.font.color.rgb = LIGHT_CYAN
    p.alignment = PP_ALIGN.CENTER
    p.space_after = Pt(30)

    p = tf17.add_paragraph()
    p.text = "GitHub: https://github.com/harshbhoi24/our_secret   |   Project: Our Secret v2.0"
    p.font.size = Pt(12)
    p.font.bold = True
    p.font.color.rgb = TEXT_MUTED
    p.alignment = PP_ALIGN.CENTER

    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "Our_Secret_Steganography_Project_Presentation.pptx")
    prs.save(output_path)
    print(f"[*] Presentation successfully generated at: {output_path}")

if __name__ == '__main__':
    create_deck()
