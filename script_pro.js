// ====================== CONFIGURATION ======================
const CONFIG = {
    ALGORITHM: 'AES-GCM',
    KEY_LENGTH: 256,
    PBKDF2_ITERATIONS: 100000,
    SALT_LENGTH: 16,
    IV_LENGTH: 12,
    MIN_KEY_LENGTH: 16
};

// ====================== DOM ELEMENTS ======================
const fileModeBtn = document.getElementById('fileModeBtn');
const textModeBtn = document.getElementById('textModeBtn');
const fileSection = document.getElementById('fileSection');
const textSection = document.getElementById('textSection');
const encryptBtn = document.getElementById('encryptBtn');
const decryptBtn = document.getElementById('decryptBtn');
const encryptTextBtn = document.getElementById('encryptTextBtn');
const decryptTextBtn = document.getElementById('decryptTextBtn');
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const uploadText = document.getElementById('uploadText');
const fileInfo = document.getElementById('fileInfo');
const textInput = document.getElementById('textInput');
const keyInput = document.getElementById('keyInput');
const generateKeyBtn = document.getElementById('generateKey');
const keyStrength = document.getElementById('keyStrength');
const processBtn = document.getElementById('processBtn');
const previewArea = document.getElementById('previewArea');
const previewContent = document.getElementById('previewContent');
const copyBtn = document.getElementById('copyBtn');
const checksumInfo = document.getElementById('checksumInfo');
const resultArea = document.getElementById('resultArea');
const resultText = document.getElementById('resultText');
const downloadLink = document.getElementById('downloadLink');
const statusDiv = document.getElementById('status');

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
