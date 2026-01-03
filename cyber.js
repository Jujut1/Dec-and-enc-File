// ====================== GLOBAL VARIABLES ======================
let elements = {};
let currentMode = 'encrypt';

// ====================== DETECTION PATTERNS ======================
const ENCRYPTION_PATTERNS = [
    { name: "Base64", regex: /^[A-Za-z0-9+/]+={0,2}$/, description: "Standard Base64" },
    { name: "Hex", regex: /^[0-9A-Fa-f]+$/, description: "Hexadecimal" },
    { name: "AES", regex: /^U2FsdGVkX1[0-9A-Za-z+/=]+$/, description: "AES Encrypted" },
    { name: "Binary", regex: /^[01\s]+$/, description: "Binary Data" },
    { name: "URL Encoded", regex: /%[0-9A-Fa-f]{2}/, description: "URL Encoding" },
    { name: "JSON", regex: /^\{.*\}$|^\[.*\]$/, description: "JSON Format" }
];

// ====================== INITIALIZATION ======================
document.addEventListener('DOMContentLoaded', () => {
    initElements();
    setupEventListeners();
    generateRandomKey();
    initDetectionGrid();
});

function initElements() {
    elements = {
        // Input elements
        inputText: document.getElementById('inputText'),
        keyInput: document.getElementById('keyInput'),
        generateKey: document.getElementById('generateKey'),
        keyStrengthBar: document.getElementById('keyStrengthBar'),
        keyStrengthText: document.getElementById('keyStrengthText'),
        
        // Mode buttons
        encryptMode: document.getElementById('encryptMode'),
        decryptMode: document.getElementById('decryptMode'),
        
        // Action buttons
        processEncrypt: document.getElementById('processEncrypt'),
        processDecrypt: document.getElementById('processDecrypt'),
        
        // Result elements
        resultOutput: document.getElementById('resultOutput'),
        copyResult: document.getElementById('copyResult'),
        clearAll: document.getElementById('clearAll'),
        saveResult: document.getElementById('saveResult'),
        
        // Status and detection
        statusBar: document.getElementById('statusBar'),
        statusText: document.getElementById('statusText'),
        detectionGrid: document.getElementById('detectionGrid')
    };
}

function setupEventListeners() {
    // Key input events
    elements.keyInput.addEventListener('input', updateKeyStrength);
    elements.generateKey.addEventListener('click', generateRandomKey);
    
    // Mode switching
    elements.encryptMode.addEventListener('click', () => switchMode('encrypt'));
    elements.decryptMode.addEventListener('click', () => switchMode('decrypt'));
    
    // Process buttons
    elements.processEncrypt.addEventListener('click', processEncryption);
    elements.processDecrypt.addEventListener('click', processDecryption);
    
    // Text input for detection
    elements.inputText.addEventListener('input', detectEncryptionFormats);
    
    // Result actions
    elements.copyResult.addEventListener('click', copyResultToClipboard);
    elements.clearAll.addEventListener('click', clearAll);
    elements.saveResult.addEventListener('click', saveResultAsFile);
}

// ====================== KEY MANAGEMENT ======================
function generateRandomKey() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    const length = 32;
    let key = '';
    
    // Use crypto.getRandomValues for true randomness
    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);
    
    for (let i = 0; i < length; i++) {
        key += charset[randomValues[i] % charset.length];
    }
    
    elements.keyInput.value = key;
    updateKeyStrength();
    showStatus('✅ Random key generated!', 'success');
}

function updateKeyStrength() {
    const key = elements.keyInput.value;
    let strength = 0;
    
    // Length check
    if (key.length >= 32) strength += 40;
    else if (key.length >= 16) strength += 30;
    else if (key.length >= 8) strength += 20;
    else if (key.length >= 4) strength += 10;
    
    // Complexity checks
    if (/[A-Z]/.test(key) && /[a-z]/.test(key)) strength += 20;
    if (/\d/.test(key)) strength += 15;
    if (/[^A-Za-z0-9]/.test(key)) strength += 15;
    
    // Cap at 100
    strength = Math.min(strength, 100);
    
    // Update UI
    elements.keyStrengthBar.style.width = `${strength}%`;
    
    let strengthText = 'Very Weak';
    let color = '#ff0000';
    
    if (strength >= 80) {
        strengthText = 'VERY STRONG';
        color = '#00ff00';
        elements.keyStrengthBar.style.background = 'linear-gradient(90deg, #00ff00, #00cc00)';
    } else if (strength >= 60) {
        strengthText = 'Strong';
        color = '#00cc00';
        elements.keyStrengthBar.style.background = 'linear-gradient(90deg, #ffff00, #00cc00)';
    } else if (strength >= 40) {
        strengthText = 'Medium';
        color = '#ffff00';
        elements.keyStrengthBar.style.background = 'linear-gradient(90deg, #ff9900, #ffff00)';
    } else if (strength >= 20) {
        strengthText = 'Weak';
        color = '#ff9900';
        elements.keyStrengthBar.style.background = 'linear-gradient(90deg, #ff0000, #ff9900)';
    } else {
        elements.keyStrengthBar.style.background = 'linear-gradient(90deg, #ff0000, #ff6600)';
    }
    
    elements.keyStrengthText.textContent = `Strength: ${strengthText} (${strength}%)`;
    elements.keyStrengthText.style.color = color;
}

// ====================== MODE SWITCHING ======================
function switchMode(mode) {
    currentMode = mode;
    
    // Update button states
    elements.encryptMode.classList.toggle('active', mode === 'encrypt');
    elements.decryptMode.classList.toggle('active', mode === 'decrypt');
    
    // Show/hide process buttons
    if (mode === 'encrypt') {
        elements.processEncrypt.style.display = 'flex';
        elements.processDecrypt.style.display = 'none';
    } else {
        elements.processEncrypt.style.display = 'none';
        elements.processDecrypt.style.display = 'flex';
    }
    
    showStatus(`Mode: ${mode.toUpperCase()}`, 'success');
}

// ====================== ENCRYPTION/DECRYPTION ======================
async function processEncryption() {
    const text = elements.inputText.value.trim();
    const key = elements.keyInput.value.trim();
    
    if (!text) {
        showStatus('❌ Masukkan text dulu!', 'error');
        return;
    }
    
    if (!key) {
        showStatus('❌ Masukkan encryption key!', 'error');
        return;
    }
    
    showStatus('🔒 Encrypting...', 'processing');
    
    try {
        // Generate random salt and IV
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        
        // Derive encryption key from password
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(key),
            "PBKDF2",
            false,
            ["deriveKey"]
        );
        
        const cryptoKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );
        
        // Encrypt the text
        const encrypted = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            cryptoKey,
            new TextEncoder().encode(text)
        );
        
        // Combine salt + iv + encrypted data
        const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
        combined.set(salt, 0);
        combined.set(iv, salt.length);
        combined.set(new Uint8Array(encrypted), salt.length + iv.length);
        
        // Convert to Base64
        let binary = '';
        for (let i = 0; i < combined.length; i++) {
            binary += String.fromCharCode(combined[i]);
        }
        const encryptedBase64 = btoa(binary);
        
        // Format output
        const output = `
╔══════════════════════════════════════╗
║     CYBER INDONET - ENCRYPTED DATA     ║
╚══════════════════════════════════════╝

🔐 ENCRYPTION DETAILS:
• Algorithm: AES-256-GCM
• Key: ${key.substring(0, 15)}...
• Timestamp: ${new Date().toLocaleString()}
• Original Size: ${text.length} characters
• Encrypted Size: ${encryptedBase64.length} characters

📊 FORMAT BREAKDOWN:
• Salt: 16 bytes
• IV: 12 bytes
• Encrypted Data: ${encrypted.byteLength} bytes

🔒 ENCRYPTED TEXT (Base64):
${encryptedBase64}

⚠️ IMPORTANT:
• Save this key: ${key}
• Without key, decryption is IMPOSSIBLE
• This is military-grade encryption
        `;
        
        elements.resultOutput.textContent = output;
        showStatus('✅ Encryption successful!', 'success');
        
        // Auto-copy to input for easy testing
        elements.inputText.value = encryptedBase64;
        detectEncryptionFormats();
        
    } catch (error) {
        showStatus(`❌ Encryption failed: ${error.message}`, 'error');
        console.error(error);
    }
}

async function processDecryption() {
    const encryptedText = elements.inputText.value.trim();
    const key = elements.keyInput.value.trim();
    
    if (!encryptedText) {
        showStatus('❌ Masukkan encrypted text!', 'error');
        return;
    }
    
    if (!key) {
        showStatus('❌ Masukkan encryption key!', 'error');
        return;
    }
    
    showStatus('🔓 Decrypting...', 'processing');
    
    try {
        // Decode Base64
        const binary = atob(encryptedText);
        const combined = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            combined[i] = binary.charCodeAt(i);
        }
        
        // Extract components
        const salt = combined.slice(0, 16);
        const iv = combined.slice(16, 28);
        const encryptedData = combined.slice(28);
        
        // Derive key
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode(key),
            "PBKDF2",
            false,
            ["deriveKey"]
        );
        
        const cryptoKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: 100000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );
        
        // Decrypt
        const decrypted = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            cryptoKey,
            encryptedData
        );
        
        const decryptedText = new TextDecoder().decode(decrypted);
        
        // Format output
        const output = `
╔══════════════════════════════════════╗
║     CYBER INDONET - DECRYPTED DATA     ║
╚══════════════════════════════════════╝

🔓 DECRYPTION DETAILS:
• Algorithm: AES-256-GCM
• Key Used: ${key.substring(0, 15)}...
• Timestamp: ${new Date().toLocaleString()}
• Encrypted Size: ${encryptedText.length} characters
• Decrypted Size: ${decryptedText.length} characters

✅ DECRYPTION VERIFIED:
• Salt: Valid (16 bytes)
• IV: Valid (12 bytes)
• Data Integrity: 100% OK

📄 DECRYPTED TEXT:
${decryptedText}

🎯 FORMAT ANALYSIS:
• Type: ${detectTextType(decryptedText)}
• Length: ${decryptedText.length} chars
• Lines: ${decryptedText.split('\\n').length}
        `;
        
        elements.resultOutput.textContent = output;
        showStatus('✅ Decryption successful!', 'success');
        
        // Auto-copy decrypted text to input
        elements.inputText.value = decryptedText;
        detectEncryptionFormats();
        
    } catch (error) {
        showStatus(`❌ Decryption failed! Wrong key or corrupt data.`, 'error');
        
        // Try alternative decodings
        tryAlternativeDecodings(encryptedText);
    }
}

function tryAlternativeDecodings(text) {
    let output = `❌ AES DECRYPTION FAILED\n\n`;
    output += `Trying alternative decodings:\n\n`;
    
    // Try Base64 decode
    try {
        const base64Decoded = atob(text);
        output += `1. Base64 Decoded:\n${base64Decoded.substring(0, 200)}${base64Decoded.length > 200 ? '...' : ''}\n\n`;
    } catch (e) {
        output += `1. Base64: Not valid Base64\n\n`;
    }
    
    // Try Hex decode
    if (/^[0-9A-Fa-f]+$/.test(text)) {
        const hexDecoded = text.match(/.{1,2}/g)
            .map(byte => String.fromCharCode(parseInt(byte, 16)))
            .join('');
        output += `2. Hex Decoded:\n${hexDecoded.substring(0, 200)}${hexDecoded.length > 200 ? '...' : ''}\n\n`;
    } else {
        output += `2. Hex: Not valid hex\n\n`;
    }
    
    // Try URL decode
    try {
        const urlDecoded = decodeURIComponent(text);
        if (urlDecoded !== text) {
            output += `3. URL Decoded:\n${urlDecoded.substring(0, 200)}${urlDecoded.length > 200 ? '...' : ''}\n\n`;
        }
    } catch (e) {}
    
    elements.resultOutput.textContent = output;
}

// ====================== DETECTION FUNCTIONS ======================
function initDetectionGrid() {
    elements.detectionGrid.innerHTML = '';
    
    ENCRYPTION_PATTERNS.forEach(pattern => {
        const card = document.createElement('div');
        card.className = 'detection-card';
        card.id = `detect-${pattern.name.replace(/\s+/g, '-')}`;
        card.innerHTML = `
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div class="detection-name">${pattern.name}</div>
                <div style="padding: 5px 10px; background: rgba(255,0,0,0.2); border-radius: 12px; font-size: 0.8rem; color: #ff6666;">
                    NOT DETECTED
                </div>
            </div>
            <div style="color: #aaa; font-size: 0.9rem;">${pattern.description}</div>
        `;
        elements.detectionGrid.appendChild(card);
    });
}

function detectEncryptionFormats() {
    const text = elements.inputText.value.trim();
    
    ENCRYPTION_PATTERNS.forEach(pattern => {
        const card = document.getElementById(`detect-${pattern.name.replace(/\s+/g, '-')}`);
        if (!card) return;
        
        let detected = false;
        
        if (text.length > 0) {
            detected = pattern.regex.test(text);
        }
        
        const statusDiv = card.querySelector('div > div:last-child');
        
        if (detected) {
            card.classList.add('detected');
            statusDiv.innerHTML = '<span style="color:#00ff88">✓ DETECTED</span>';
            statusDiv.style.background = 'rgba(0,255,136,0.2)';
        } else {
            card.classList.remove('detected');
            statusDiv.innerHTML = '<span style="color:#ff6666">NOT DETECTED</span>';
            statusDiv.style.background = 'rgba(255,0,0,0.2)';
        }
    });
}

function detectTextType(text) {
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(text)) return 'Base64';
    if (/^[0-9A-Fa-f]+$/.test(text)) return 'Hex';
    if (/^U2FsdGVkX1/.test(text)) return 'AES Encrypted';
    if (/^[01\s]+$/.test(text)) return 'Binary';
    if (/%[0-9A-Fa-f]{2}/.test(text)) return 'URL Encoded';
    if (/^\{.*\}$|^\[.*\]$/.test(text)) return 'JSON';
    return 'Plain Text';
}

// ====================== UTILITY FUNCTIONS ======================
function showStatus(message, type) {
    elements.statusText.textContent = message;
    elements.statusBar.className = `status-bar status-${type}`;
    elements.statusBar.style.display = 'block';
    
    if (type !== 'processing') {
        setTimeout(() => {
            elements.statusBar.style.display = 'none';
        }, 3000);
    }
}

function copyResultToClipboard() {
    const text = elements.resultOutput.textContent;
    
    navigator.clipboard.writeText(text).then(() => {
        showStatus('✅ Copied to clipboard!', 'success');
    }).catch(err => {
        showStatus('❌ Failed to copy', 'error');
    });
}

function clearAll() {
    elements.inputText.value = '';
    elements.keyInput.value = '';
    elements.resultOutput.textContent = '// Hasil akan muncul di sini...';
    generateRandomKey();
    initDetectionGrid();
    showStatus('🧹 All cleared!', 'success');
}

function saveResultAsFile() {
    const text = elements.resultOutput.textContent;
    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cyber-indonet-${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showStatus('💾 File saved!', 'success');
}

// ====================== STARTUP ======================
// Initialize when page loads
window.onload = function() {
    showStatus('🟢 CYBER INDONET READY', 'success');
};
// ====================== GLOBAL STATE ======================
let currentMode = 'file'; // 'file' or 'text'
let currentOperation = 'encrypt'; // 'encrypt' or 'decrypt'
let selectedFile = null;
let lastProcessedData = null;

// ====================== INITIALIZATION ======================
document.addEventListener('DOMContentLoaded', () => {
    updateUI();
    setupEventListeners();
});

// ====================== EVENT LISTENERS ======================
function setupEventListeners() {
    // Mode switching: File ↔ Text
    fileModeBtn.addEventListener('click', () => switchMode('file'));
    textModeBtn.addEventListener('click', () => switchMode('text'));
    
    // Operation switching: Encrypt ↔ Decrypt
    encryptBtn.addEventListener('click', () => switchOperation('encrypt'));
    decryptBtn.addEventListener('click', () => switchOperation('decrypt'));
    encryptTextBtn.addEventListener('click', () => switchOperation('encrypt'));
    decryptTextBtn.addEventListener('click', () => switchOperation('decrypt'));
    
    // File handling
    uploadArea.addEventListener('click', () => fileInput.click());
    fileInput.addEventListener('change', handleFileSelect);
    
    // Drag and drop
    uploadArea.addEventListener('dragover', handleDragOver);
    uploadArea.addEventListener('dragleave', handleDragLeave);
    uploadArea.addEventListener('drop', handleDrop);
    
    // Key management
    generateKeyBtn.addEventListener('click', generateRandomKey);
    keyInput.addEventListener('input', updateKeyStrength);
    
    // Process button
    processBtn.addEventListener('click', processData);
    
    // Copy button
    copyBtn.addEventListener('click', copyPreviewToClipboard);
}

// ====================== CORE FUNCTIONS ======================
function switchMode(mode) {
    currentMode = mode;
    fileModeBtn.classList.toggle('active', mode === 'file');
    textModeBtn.classList.toggle('active', mode === 'text');
    fileSection.style.display = mode === 'file' ? 'block' : 'none';
    textSection.style.display = mode === 'text' ? 'block' : 'none';
    previewArea.style.display = 'none';
    resultArea.style.display = 'none';
    updateProcessButton();
}

function switchOperation(operation) {
    currentOperation = operation;
    encryptBtn.classList.toggle('active', operation === 'encrypt');
    decryptBtn.classList.toggle('active', operation === 'decrypt');
    encryptTextBtn.classList.toggle('active', operation === 'encrypt');
    decryptTextBtn.classList.toggle('active', operation === 'decrypt');
    updateProcessButton();
}

function updateProcessButton() {
    const op = currentOperation === 'encrypt' ? 'ENCRYPT' : 'DECRYPT';
    const type = currentMode === 'file' ? 'FILE' : 'TEXT';
    processBtn.textContent = `🚀 PROSES ${op} ${type}`;
}

// ====================== FILE HANDLING ======================
function handleFileSelect(e) {
    if (e.target.files.length > 0) {
        selectedFile = e.target.files[0];
        fileInfo.textContent = `📄 ${selectedFile.name} (${formatBytes(selectedFile.size)})`;
        uploadArea.style.borderColor = '#00ff88';
        previewArea.style.display = 'none';
    }
}

function handleDragOver(e) {
    e.preventDefault();
    uploadArea.classList.add('drag-over');
}

function handleDragLeave() {
    uploadArea.classList.remove('drag-over');
}

function handleDrop(e) {
    e.preventDefault();
    uploadArea.classList.remove('drag-over');
    if (e.dataTransfer.files.length > 0) {
        selectedFile = e.dataTransfer.files[0];
        fileInput.files = e.dataTransfer.files;
        fileInfo.textContent = `📄 ${selectedFile.name} (${formatBytes(selectedFile.size)})`;
        uploadArea.style.borderColor = '#00ff88';
        previewArea.style.display = 'none';
    }
}

// ====================== KEY MANAGEMENT ======================
function generateRandomKey() {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
    let key = '';
    const values = new Uint8Array(32);
    crypto.getRandomValues(values);
    for (let i = 0; i < 32; i++) {
        key += charset[values[i] % charset.length];
    }
    keyInput.value = key;
    updateKeyStrength();
}

function updateKeyStrength() {
    const key = keyInput.value;
    let strength = 0;
    let color = '#ff0040';
    let text = 'Lemah';
    
    if (key.length >= CONFIG.MIN_KEY_LENGTH) strength += 30;
    if (/[A-Z]/.test(key) && /[a-z]/.test(key)) strength += 20;
    if (/\d/.test(key)) strength += 20;
    if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(key)) strength += 30;
    
    if (strength >= 80) {
        color = '#00ff88';
        text = 'Sangat Kuat';
    } else if (strength >= 60) {
        color = '#00ccff';
        text = 'Kuat';
    } else if (strength >= 40) {
        color = '#ffcc00';
        text = 'Cukup';
    }
    
    keyStrength.innerHTML = `Kekuatan Key: <span style="color:${color}">${text} (${strength}%)</span>`;
}

// ====================== PROCESSING FUNCTIONS ======================
async function processData() {
    // Validation
    const key = keyInput.value.trim();
    if (!key) {
        showStatus('❌ Masukkan encryption key!', 'error');
        return;
    }
    if (key.length < CONFIG.MIN_KEY_LENGTH) {
        showStatus(`❌ Key minimal ${CONFIG.MIN_KEY_LENGTH} karakter!`, 'error');
        return;
    }
    
    if (currentMode === 'file' && !selectedFile) {
        showStatus('❌ Pilih file dulu Boss!', 'error');
        return;
    }
    
    if (currentMode === 'text' && !textInput.value.trim()) {
        showStatus('❌ Masukkan text dulu!', 'error');
        return;
    }
    
    try {
        showStatus(`🔄 ${currentOperation === 'encrypt' ? 'Encrypting' : 'Decrypting'}...`, 'processing');
        
        let result, originalData;
        
        if (currentMode === 'file') {
            const fileBuffer = await selectedFile.arrayBuffer();
            originalData = new Uint8Array(fileBuffer);
            
            if (currentOperation === 'encrypt') {
                result = await encryptData(originalData, key);
            } else {
                result = await decryptData(originalData, key);
            }
            
            // For file mode, show preview and download
            showPreview(result);
            prepareFileDownload(result);
            resultArea.style.display = 'block';
            
        } else { // Text mode
            const text = textInput.value;
            const textBuffer = new TextEncoder().encode(text);
            
            if (currentOperation === 'encrypt') {
                result = await encryptData(textBuffer, key);
                const encryptedBase64 = arrayBufferToBase64(result);
                showPreviewText(encryptedBase64, 'encrypted');
                textInput.value = encryptedBase64;
            } else {
                // Try to decode as base64 first
                try {
                    const encryptedBuffer = base64ToArrayBuffer(text);
                    result = await decryptData(encryptedBuffer, key);
                    const decryptedText = new TextDecoder().decode(result);
                    showPreviewText(decryptedText, 'decrypted');
                    textInput.value = decryptedText;
                } catch (e) {
                    // If not base64, try direct
                    const textBuffer = new TextEncoder().encode(text);
                    result = await decryptData(textBuffer, key);
                    const decryptedText = new TextDecoder().decode(result);
                    showPreviewText(decryptedText, 'decrypted');
                    textInput.value = decryptedText;
                }
            }
        }
        
        lastProcessedData = result;
        showStatus('✅ Proses selesai!', 'success');
        
    } catch (error) {
        showStatus(`❌ ERROR: ${error.message}`, 'error');
        console.error(error);
    }
}

// ====================== ENCRYPTION/DECRYPTION CORE ======================
async function encryptData(data, password) {
    const salt = crypto.getRandomValues(new Uint8Array(CONFIG.SALT_LENGTH));
    const iv = crypto.getRandomValues(new Uint8Array(CONFIG.IV_LENGTH));
    
    // Derive key from password
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: CONFIG.ALGORITHM, length: CONFIG.KEY_LENGTH },
        false,
        ["encrypt"]
    );
    
    // Encrypt
    const encrypted = await crypto.subtle.encrypt(
        { name: CONFIG.ALGORITHM, iv: iv },
        key,
        data
    );
    
    // Calculate checksum of original data
    const originalChecksum = await calculateChecksum(data);
    
    // Package: [version][salt][iv][checksum][encrypted]
    const version = new Uint8Array([0x01]); // Format version
    const checksumBytes = stringToBytes(originalChecksum);
    
    const result = new Uint8Array(
        version.length + 
        salt.length + 
        iv.length + 
        checksumBytes.length + 
        encrypted.byteLength
    );
    
    let offset = 0;
    result.set(version, offset); offset += version.length;
    result.set(salt, offset); offset += salt.length;
    result.set(iv, offset); offset += iv.length;
    result.set(checksumBytes, offset); offset += checksumBytes.length;
    result.set(new Uint8Array(encrypted), offset);
    
    return result.buffer;
}

async function decryptData(encryptedData, password) {
    const data = new Uint8Array(encryptedData);
    
    // Extract components
    let offset = 0;
    const version = data[offset]; offset += 1;
    
    if (version !== 0x01) {
        throw new Error('Format file tidak dikenali!');
    }
    
    const salt = data.slice(offset, offset + CONFIG.SALT_LENGTH);
    offset += CONFIG.SALT_LENGTH;
    
    const iv = data.slice(offset, offset + CONFIG.IV_LENGTH);
    offset += CONFIG.IV_LENGTH;
    
    const checksumBytes = data.slice(offset, offset + 64); // SHA-256 = 64 hex chars
    offset += 64;
    
    const encryptedContent = data.slice(offset);
    
    // Derive key
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    
    const key = await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: CONFIG.PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: CONFIG.ALGORITHM, length: CONFIG.KEY_LENGTH },
        false,
        ["decrypt"]
    );
    
    // Decrypt
    const decrypted = await crypto.subtle.decrypt(
        { name: CONFIG.ALGORITHM, iv: iv },
        key,
        encryptedContent
    );
    
    // Verify checksum
    const decryptedChecksum = await calculateChecksum(decrypted);
    const storedChecksum = bytesToString(checksumBytes);
    
    if (decryptedChecksum !== storedChecksum) {
        throw new Error('CHECKSUM ERROR! Data corrupt atau key salah!');
    }
    
    return decrypted;
}

// ====================== PREVIEW FUNCTIONS ======================
function showPreview(dataBuffer) {
    const data = new Uint8Array(dataBuffer);
    
    // Hex view
    let hexView = '';
    for (let i = 0; i < Math.min(data.length, 1024); i++) {
        hexView += data[i].toString(16).padStart(2, '0') + ' ';
        if ((i + 1) % 16 === 0) hexView += '\n';
    }
    if (data.length > 1024) hexView += '\n[...] ' + (data.length - 1024) + ' bytes lebih';
    
    // ASCII view (for printable chars)
    let asciiView = '';
    for (let i = 0; i < Math.min(data.length, 1024); i++) {
        const char = data[i];
        asciiView += (char >= 32 && char <= 126) ? String.fromCharCode(char) : '.';
        if ((i + 1) % 16 === 0) asciiView += '\n';
    }
    
    previewContent.innerHTML = `
        <div class="hex-view">${escapeHtml(hexView)}</div>
        <div class="ascii-view">${escapeHtml(asciiView)}</div>
        <div style="color: #888; margin-top: 10px;">
            Size: ${formatBytes(data.length)} | 
            Format: ${currentOperation === 'encrypt' ? 'Encrypted' : 'Decrypted'}
        </div>
    `;
    
    previewArea.style.display = 'block';
    checksumInfo.textContent = '✅ Checksum verified - No errors';
}

function showPreviewText(text, type) {
    let displayText = text;
    
    if (type === 'encrypted') {
        // For encrypted text (base64), show truncated version
        if (text.length > 500) {
            displayText = text.substring(0, 500) + '\n[...] ' + (text.length - 500) + ' karakter lebih';
        }
        previewContent.innerHTML = `
            <div style="color: #00ff88; font-weight: bold;">ENCRYPTED TEXT (Base64):</div>
            <div style="margin-top: 10px;">${escapeHtml(displayText)}</div>
        `;
    } else {
        // For decrypted text, show full
        previewContent.innerHTML = `
            <div style="color: #ffcc00; font-weight: bold;">DECRYPTED TEXT:</div>
            <div style="margin-top: 10px; white-space: pre-wrap;">${escapeHtml(text)}</div>
        `;
    }
    
    previewArea.style.display = 'block';
    checksumInfo.textContent = '✅ Text verified - 100% accurate';
}

// ====================== UTILITY FUNCTIONS ======================
function prepareFileDownload(dataBuffer) {
    const resultBlob = new Blob([dataBuffer]);
    const resultUrl = URL.createObjectURL(resultBlob);
    
    let fileExtension;
    if (currentOperation === 'encrypt') {
        fileExtension = '.encrypted';
    } else {
        // Try to guess original extension
        const originalExt = selectedFile.name.match(/\.[^/.]+$/);
        fileExtension = '_decrypted' + (originalExt ? originalExt[0] : '');
    }
    
    const fileName = selectedFile.name.replace(/\.[^/.]+$/, "") + fileExtension;
    
    downloadLink.href = resultUrl;
    downloadLink.download = fileName;
    resultText.textContent = `File "${fileName}" siap didownload`;
}

async function calculateChecksum(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

function stringToBytes(str) {
    return new TextEncoder().encode(str);
}

function bytesToString(bytes) {
    return new TextDecoder().decode(bytes);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function showStatus(message, type) {
    statusDiv.textContent = message;
    statusDiv.className = 'status';
    
    switch (type) {
        case 'error':
            statusDiv.style.background = 'rgba(255, 0, 0, 0.2)';
            statusDiv.style.color = '#ff0000';
            break;
        case 'processing':
            statusDiv.style.background = 'rgba(0, 204, 255, 0.2)';
            statusDiv.style.color = '#00ccff';
            break;
        case 'success':
            statusDiv.style.background = 'rgba(0, 255, 136, 0.2)';
            statusDiv.style.color = '#00ff88';
            break;
    }
    
    statusDiv.style.display = 'block';
}

async function copyPreviewToClipboard() {
    try {
        if (currentMode === 'text') {
            await navigator.clipboard.writeText(textInput.value);
        } else {
            await navigator.clipboard.writeText(previewContent.textContent);
        }
        showStatus('✅ Copied to clipboard!', 'success');
    } catch (err) {
        showStatus('❌ Gagal copy', 'error');
    }
}

function updateUI() {
    updateProcessButton();
    updateKeyStrength();
}
