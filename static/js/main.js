/**
 * Our Secret - Cyber Steganography & Integrity UI Utilities
 */

document.addEventListener('DOMContentLoaded', () => {
    initThemeToggle();
    initPasswordToggles();
    initCopyButtons();
    initImageUploadPreview();
    initCapacityCounter();
    initExpiryPolicyToggle();
    initPayloadTypeToggle();
    initDeniableToggle();
    initPasswordEntropyMeter();
    initPassphraseGenerator();
});

// Feature 4: Multi-Theme Switcher (Enterprise Blue, Tactical Emerald, Navy Purple, Executive Light)
function initThemeToggle() {
    const toggleIcon = document.getElementById('themeToggleIcon');
    const toggleLabel = document.getElementById('themeToggleLabel');

    function applyTheme(theme) {
        // Map legacy 'dark' to 'enterprise-blue'
        if (theme === 'dark') theme = 'enterprise-blue';

        document.documentElement.setAttribute('data-theme', theme);
        document.body.setAttribute('data-theme', theme);
        
        // Security rule: Only store theme identifier in localStorage (never secret payloads)
        localStorage.setItem('our_secret_theme', theme);

        if (toggleIcon && toggleLabel) {
            if (theme === 'light') {
                toggleIcon.className = 'bi bi-sun-fill text-warning';
                toggleLabel.textContent = 'Light';
            } else if (theme === 'tactical-emerald') {
                toggleIcon.className = 'bi bi-terminal-fill text-success';
                toggleLabel.textContent = 'Emerald';
            } else if (theme === 'navy-purple') {
                toggleIcon.className = 'bi bi-moon-stars-fill text-purple';
                toggleLabel.textContent = 'Purple';
            } else {
                toggleIcon.className = 'bi bi-shield-shaded text-info';
                toggleLabel.textContent = 'Enterprise';
            }
        }

        // Update active checkmark in theme dropdown
        document.querySelectorAll('[data-theme-check]').forEach(icon => {
            if (icon.getAttribute('data-theme-check') === theme) {
                icon.classList.remove('d-none');
            } else {
                icon.classList.add('d-none');
            }
        });
    }

    let currentTheme = localStorage.getItem('our_secret_theme') || 'enterprise-blue';
    if (currentTheme === 'dark') currentTheme = 'enterprise-blue';
    applyTheme(currentTheme);

    // Attach click listeners to all theme options in dropdown
    document.querySelectorAll('.theme-select-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            const chosenTheme = btn.getAttribute('data-theme-val');
            if (chosenTheme) {
                applyTheme(chosenTheme);
            }
        });
    });
}

// Expiry & Retention Policy Selector (Multi-View Expiry vs One-Time Burn After Reading)
function initExpiryPolicyToggle() {
    const radioTimeLimited = document.getElementById('mode_time_limited');
    const radioBurn = document.getElementById('mode_burn_after_reading');
    const burnCheckbox = document.getElementById('burn_after_reading');
    const expiryContainer = document.getElementById('expiryOptionsContainer');
    const expirySelect = document.getElementById('expiry_option');
    const customContainer = document.getElementById('customExpiryContainer');
    const customInput = document.getElementById('custom_expiry_hours');
    const explanationText = document.getElementById('policyExplanationText');

    function updatePolicyUI() {
        if (!explanationText) return;

        if (radioBurn && radioBurn.checked) {
            if (burnCheckbox) burnCheckbox.checked = true;
            if (expiryContainer) expiryContainer.classList.add('d-none');
            explanationText.innerHTML = '<span class="text-danger fw-bold"><i class="bi bi-fire me-1"></i>One-Time Burn After Reading:</span> Recipient can extract this secret <strong>only ONCE</strong>. Upon initial decryption, it immediately self-destructs and the server carrier file is wiped.';
        } else {
            if (burnCheckbox) burnCheckbox.checked = false;
            if (expiryContainer) expiryContainer.classList.remove('d-none');

            const val = expirySelect ? expirySelect.value : '24h';
            if (val === 'custom') {
                if (customContainer) customContainer.classList.remove('d-none');
                const hrs = (customInput && customInput.value) ? customInput.value : 'X';
                explanationText.innerHTML = `<strong>Multi-View Window:</strong> Recipient can extract and read this payload multiple times until the <strong>${hrs} Hours</strong> custom deadline expires.`;
            } else if (val === 'none') {
                if (customContainer) customContainer.classList.add('d-none');
                explanationText.innerHTML = '<strong>Permanent Retention:</strong> Secret has no expiry deadline and can be accessed repeatedly unless manually purged.';
            } else {
                if (customContainer) customContainer.classList.add('d-none');
                const label = val === '1h' ? '1 Hour' : (val === '7d' ? '7 Days' : '24 Hours');
                explanationText.innerHTML = `<strong>Multi-View Window:</strong> Recipient can extract and read this payload multiple times until the <strong>${label}</strong> deadline passes. Ideal when the recipient needs time to access the carrier.`;
            }
        }
    }

    if (radioTimeLimited) radioTimeLimited.addEventListener('change', updatePolicyUI);
    if (radioBurn) radioBurn.addEventListener('change', updatePolicyUI);
    if (expirySelect) expirySelect.addEventListener('change', updatePolicyUI);
    if (customInput) customInput.addEventListener('input', updatePolicyUI);

    updatePolicyUI();
}

// Plausible Deniability / Duress Secret Toggle
function initDeniableToggle() {
    const deniableSwitch = document.getElementById('enable_deniable');
    const deniableContainer = document.getElementById('deniableFieldsContainer');
    const decoyPw = document.getElementById('decoy_password');
    const decoyMsg = document.getElementById('decoy_message');

    if (!deniableSwitch || !deniableContainer) return;

    function updateDeniableUI() {
        if (deniableSwitch.checked) {
            deniableContainer.classList.remove('d-none');
            if (decoyPw) decoyPw.setAttribute('required', 'required');
            if (decoyMsg) decoyMsg.setAttribute('required', 'required');
        } else {
            deniableContainer.classList.add('d-none');
            if (decoyPw) {
                decoyPw.removeAttribute('required');
                decoyPw.value = '';
            }
            if (decoyMsg) {
                decoyMsg.removeAttribute('required');
                decoyMsg.value = '';
            }
        }
    }

    deniableSwitch.addEventListener('change', updateDeniableUI);
    updateDeniableUI();
}

// 1. Password Visibility Toggle
function initPasswordToggles() {
    document.querySelectorAll('.btn-toggle-password').forEach(button => {
        button.addEventListener('click', () => {
            const targetId = button.getAttribute('data-target');
            const input = document.getElementById(targetId);
            if (!input) return;

            const icon = button.querySelector('i');
            if (input.type === 'password') {
                input.type = 'text';
                if (icon) {
                    icon.classList.remove('bi-eye');
                    icon.classList.add('bi-eye-slash');
                }
            } else {
                input.type = 'password';
                if (icon) {
                    icon.classList.remove('bi-eye-slash');
                    icon.classList.add('bi-eye');
                }
            }
        });
    });
}

// 2. One-click Copy to Clipboard with Tooltip/Notification
function initCopyButtons() {
    document.querySelectorAll('.btn-copy-clipboard').forEach(button => {
        button.addEventListener('click', () => {
            const textToCopy = button.getAttribute('data-copy');
            if (!textToCopy) return;

            navigator.clipboard.writeText(textToCopy).then(() => {
                const originalHtml = button.innerHTML;
                button.innerHTML = '<i class="bi bi-check2"></i> Copied!';
                button.classList.add('btn-success');
                setTimeout(() => {
                    button.innerHTML = originalHtml;
                    button.classList.remove('btn-success');
                }, 2000);
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        });
    });
}

// 3. Image Upload Dropzone & Live Preview
function initImageUploadPreview() {
    const dropzone = document.getElementById('uploadDropzone');
    const fileInput = document.getElementById('imageFileInput');
    const previewContainer = document.getElementById('imagePreviewContainer');
    const previewImage = document.getElementById('imagePreview');
    const imageInfo = document.getElementById('imageInfo');

    if (!fileInput || !dropzone) return;

    // Trigger file dialog on dropzone click
    dropzone.addEventListener('click', () => fileInput.click());

    // Drag & drop visual feedback
    ['dragenter', 'dragover'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropzone.classList.remove('dragover');
        });
    });

    // Handle dropped files
    dropzone.addEventListener('drop', (e) => {
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            handleFileSelect(fileInput.files[0]);
        }
    });

    // Handle standard input change
    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });

    function handleFileSelect(file) {
        if (!file) return;

        // Preview local image
        const reader = new FileReader();
        reader.onload = (e) => {
            if (previewImage) {
                previewImage.src = e.target.result;
            }
            if (previewContainer) {
                previewContainer.classList.remove('d-none');
            }
            if (imageInfo) {
                imageInfo.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            }
        };
        reader.readAsDataURL(file);

        // Fetch dynamic capacity from server API if on Hide page
        const capacityCard = document.getElementById('capacityInfoCard');
        if (capacityCard) {
            fetchImageCapacity(file);
        }
    }
}

// 4. Live Server-Side Capacity Check and Message Capacity Counter (Feature 1: OS01 Header)
let currentMaxPayload = 0;
let currentMaxMessageChars = 0;

function fetchImageCapacity(file) {
    const formData = new FormData();
    formData.append('image', file);

    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');

    fetch('/api/steganography/capacity', {
        method: 'POST',
        headers: {
            'X-CSRF-Token': csrfToken || ''
        },
        body: formData
    })
    .then(res => res.json())
    .then(data => {
        if (data.success && data.capacity) {
            const cap = data.capacity;
            currentMaxPayload = cap.max_payload_bytes;
            currentMaxMessageChars = cap.max_message_chars;

            const capacityCard = document.getElementById('capacityInfoCard');
            if (capacityCard) capacityCard.classList.remove('d-none');

            const dimElem = document.getElementById('capDimensions');
            if (dimElem) dimElem.textContent = `${cap.dimensions} (${cap.total_pixels.toLocaleString()} px)`;

            const maxCapElem = document.getElementById('capMaxCapacity');
            if (maxCapElem) maxCapElem.textContent = `${cap.max_message_chars.toLocaleString()} bytes`;

            updateCapacityProgress();
        }
    })
    .catch(err => {
        console.warn('Capacity lookup notice:', err);
    });
}

function initCapacityCounter() {
    const secretText = document.getElementById('secret_message');
    if (!secretText) return;

    secretText.addEventListener('input', () => {
        updateCapacityProgress();
    });
}

function updateCapacityProgress() {
    const secretText = document.getElementById('secret_message');
    const counterBadge = document.getElementById('msgCharCounter');
    const progressBar = document.getElementById('capacityProgressBar');
    const currentSizeElem = document.getElementById('capCurrentSize');
    const remainingElem = document.getElementById('capRemaining');
    const percentageElem = document.getElementById('capPercentage');
    const warningAlert = document.getElementById('oversizedWarningAlert');
    const oversizedCount = document.getElementById('oversizedByteCount');
    const submitBtn = document.getElementById('btnHideSubmit');

    let currentLen = 0;
    const radioFile = document.getElementById('payload_type_file');
    const secretFileInput = document.getElementById('secret_file_input');

    if (radioFile && radioFile.checked && secretFileInput && secretFileInput.files.length > 0) {
        currentLen = secretFileInput.files[0].size;
    } else if (secretText) {
        currentLen = new TextEncoder().encode(secretText.value).length;
    }

    if (counterBadge) {
        counterBadge.textContent = `${currentLen.toLocaleString()} bytes`;
    }

    if (currentSizeElem) {
        currentSizeElem.textContent = `${currentLen.toLocaleString()} bytes`;
    }

    if (currentMaxMessageChars > 0) {
        const remaining = currentMaxMessageChars - currentLen;
        const isOversized = remaining < 0;
        const percent = Math.min(100, Math.max(0, (currentLen / currentMaxMessageChars) * 100)).toFixed(1);

        if (remainingElem) {
            remainingElem.textContent = `${remaining.toLocaleString()} bytes`;
            remainingElem.className = isOversized ? 'text-danger fw-bold' : 'text-success fw-bold';
        }

        if (percentageElem) {
            percentageElem.textContent = `${((currentLen / currentMaxMessageChars) * 100).toFixed(1)}%`;
            percentageElem.className = isOversized ? 'text-danger fw-bold' : 'text-light';
        }

        if (progressBar) {
            progressBar.style.width = `${Math.min(100, percent)}%`;
            progressBar.textContent = `${((currentLen / currentMaxMessageChars) * 100).toFixed(1)}%`;

            if (isOversized) {
                progressBar.className = 'progress-bar bg-danger progress-bar-striped progress-bar-animated';
            } else if (percent > 85) {
                progressBar.className = 'progress-bar bg-danger';
            } else if (percent > 65) {
                progressBar.className = 'progress-bar bg-warning text-dark';
            } else {
                progressBar.className = 'progress-bar bg-primary';
            }
        }

        // Show/hide oversized alert warning
        if (warningAlert && oversizedCount) {
            if (isOversized) {
                warningAlert.classList.remove('d-none');
                oversizedCount.textContent = Math.abs(remaining).toLocaleString();
                if (submitBtn) {
                    submitBtn.classList.remove('btn-cyber-primary');
                    submitBtn.classList.add('btn-danger');
                    submitBtn.disabled = true;
                    submitBtn.innerHTML = '<i class="bi bi-exclamation-octagon-fill"></i> Oversized Message — Cannot Embed';
                }
            } else {
                warningAlert.classList.add('d-none');
                if (submitBtn) {
                    submitBtn.classList.remove('btn-danger');
                    submitBtn.classList.add('btn-cyber-primary');
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = '<i class="bi bi-lock-fill"></i> Encrypt & Embed into Image';
                }
            }
        }
    }
}

// Feature 2: Secret File Cloaking vs Text Payload Toggle
function initPayloadTypeToggle() {
    const radioText = document.getElementById('payload_type_text');
    const radioFile = document.getElementById('payload_type_file');
    const textContainer = document.getElementById('textPayloadContainer');
    const fileContainer = document.getElementById('filePayloadContainer');
    const secretFileInput = document.getElementById('secret_file_input');
    const secretFileLabel = document.getElementById('secretFileNameDisplay');
    const secretMessageTextarea = document.getElementById('secret_message');

    if (!radioText || !radioFile) return;

    function handleToggle() {
        if (radioFile.checked) {
            if (textContainer) textContainer.classList.add('d-none');
            if (fileContainer) fileContainer.classList.remove('d-none');
            if (secretMessageTextarea) secretMessageTextarea.required = false;
            if (secretFileInput) secretFileInput.required = true;
        } else {
            if (textContainer) textContainer.classList.remove('d-none');
            if (fileContainer) fileContainer.classList.add('d-none');
            if (secretMessageTextarea) secretMessageTextarea.required = true;
            if (secretFileInput) secretFileInput.required = false;
        }
        updateCapacityProgress();
    }

    radioText.addEventListener('change', handleToggle);
    radioFile.addEventListener('change', handleToggle);

    if (secretFileInput) {
        secretFileInput.addEventListener('change', () => {
            if (secretFileInput.files && secretFileInput.files.length > 0) {
                const f = secretFileInput.files[0];
                if (secretFileLabel) {
                    secretFileLabel.textContent = `${f.name} (${(f.size / 1024).toFixed(1)} KB)`;
                }
            }
            updateCapacityProgress();
        });
    }
}

// Feature 5: Cryptographic Password Entropy & Passphrase Generator
function initPasswordEntropyMeter() {
    const pwInput = document.getElementById('hide_password');
    const bar = document.getElementById('pwEntropyBar');
    const label = document.getElementById('pwEntropyLabel');
    const crackTime = document.getElementById('pwCrackTimeLabel');
    if (!pwInput) return;

    pwInput.addEventListener('input', () => {
        calculateEntropy(pwInput.value);
    });

    function calculateEntropy(pass) {
        if (!bar || !label) return;
        const len = pass.length;
        if (len === 0) {
            bar.style.width = '0%';
            bar.style.backgroundColor = '#64748b';
            label.textContent = '0 bits (Empty)';
            label.className = 'badge badge-cyber na';
            if (crackTime) crackTime.textContent = 'Enter password to estimate';
            return;
        }

        let pool = 0;
        if (/[a-z]/.test(pass)) pool += 26;
        if (/[A-Z]/.test(pass)) pool += 26;
        if (/[0-9]/.test(pass)) pool += 10;
        if (/[^a-zA-Z0-9]/.test(pass)) pool += 32;

        const entropy = pool > 0 ? Math.round(len * Math.log2(pool)) : 0;
        const percent = Math.min(100, Math.round((entropy / 80) * 100));
        bar.style.width = `${percent}%`;

        if (entropy < 30) {
            bar.style.backgroundColor = '#ef4444';
            label.textContent = `${entropy} bits (Very Weak)`;
            label.className = 'badge badge-cyber failed';
            if (crackTime) crackTime.innerHTML = '<span class="text-danger">&lt; 1 Second</span> (GPU Cluster Brute-force)';
        } else if (entropy < 50) {
            bar.style.backgroundColor = '#f59e0b';
            label.textContent = `${entropy} bits (Moderate)`;
            label.className = 'badge badge-cyber na text-warning';
            if (crackTime) crackTime.innerHTML = '<span class="text-warning">~Few Hours / Days</span> (Dictionary attack vulnerable)';
        } else if (entropy < 70) {
            bar.style.backgroundColor = '#06b6d4';
            label.textContent = `${entropy} bits (Strong)`;
            label.className = 'badge badge-cyber success';
            if (crackTime) crackTime.innerHTML = '<span class="text-info">~Decades to Centuries</span> (AES-256 Resistant)';
        } else {
            bar.style.backgroundColor = '#10b981';
            label.textContent = `${entropy} bits (Military Grade)`;
            label.className = 'badge badge-cyber success';
            if (crackTime) crackTime.innerHTML = '<span class="text-success">&gt; 100 Million Years</span> (NIST Compliant)';
        }
    }

    window.updatePasswordEntropy = calculateEntropy;
}

function initPassphraseGenerator() {
    const btnToken = document.getElementById('btnGenToken');
    const btnDiceware = document.getElementById('btnGenDiceware');
    const pwInput = document.getElementById('hide_password');
    if (!pwInput) return;

    if (btnToken) {
        btnToken.addEventListener('click', (e) => {
            e.preventDefault();
            const charset = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+";
            const array = new Uint32Array(20);
            window.crypto.getRandomValues(array);
            let token = "";
            for (let i = 0; i < 20; i++) {
                token += charset[array[i] % charset.length];
            }
            pwInput.value = token;
            pwInput.type = 'text';
            if (window.updatePasswordEntropy) window.updatePasswordEntropy(token);
        });
    }

    if (btnDiceware) {
        btnDiceware.addEventListener('click', (e) => {
            e.preventDefault();
            const words = [
                'falcon', 'quantum', 'orbital', 'cipher', 'zenith', 'sentinel',
                'matrix', 'cobalt', 'stealth', 'phantom', 'vector', 'vertex',
                'apex', 'nexus', 'vanguard', 'titan', 'beacon', 'protocol',
                'enigma', 'aurora', 'pulsar', 'shadow', 'cortex', 'shield'
            ];
            const array = new Uint32Array(5);
            window.crypto.getRandomValues(array);
            const w1 = words[array[0] % words.length];
            const w2 = words[array[1] % words.length];
            const w3 = words[array[2] % words.length];
            const w4 = words[array[3] % words.length];
            const num = (array[4] % 90) + 10;
            const phrase = `${w1}-${w2}-${w3}-${w4}-${num}`;
            pwInput.value = phrase;
            pwInput.type = 'text';
            if (window.updatePasswordEntropy) window.updatePasswordEntropy(phrase);
        });
    }
}


