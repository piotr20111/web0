// Alternative entry method - triple click on 404 text
let clickCount = 0;
let clickTimer;

document.addEventListener('click', function(e) {
    if (e.target.closest('.error-content')) {
        clickCount++;
        
        clearTimeout(clickTimer);
        clickTimer = setTimeout(() => {
            clickCount = 0;
        }, 500);
        
        if (clickCount === 3) {
            // Show the real app
            document.getElementById('errorScreen').style.display = 'none';
            document.getElementById('appContainer').style.display = 'block';
            
            // Initialize Google Sign-In after revealing the app
            if (!googleInitialized) {
                setTimeout(() => {
                    initializeGoogleSignIn();
                }, 100);
            }
            
            clickCount = 0;
        }
    }
});

// Firebase Configuration
const firebaseConfig = {
    apiKey: "AIzaSyC-lBAOsH8UGIIY3n1ntBs9Zn0Sq8K75aY",
    authDomain: "web0-586a2.firebaseapp.com",
    projectId: "web0-586a2",
    storageBucket: "web0-586a2.firebasestorage.app",
    messagingSenderId: "800486508903",
    appId: "1:800486508903:web:21789e6d686ea471d0c7c2"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();
const storage = firebase.storage();

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = '172651080134-hpk3392odvase3ro1ko6urgnec5r87nb.apps.googleusercontent.com';

// Global variables
let currentUser = null;
let currentNote = null;
let notes = [];
let failedPasswordAttempts = 0;
let lockoutEndTime = null;
let googleInitialized = false;
let isAuthenticated = false;
let navigationHistory = [];
let currentFolder = null;
let folders = [];
let videos = [];
let uploadQueue = [];
let currentView = 'grid';

// Disable Developer Tools EVERYWHERE
// Disable right-click context menu
document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    return false;
});

// Disable keyboard shortcuts for DevTools
document.addEventListener('keydown', (e) => {
    // F12
    if (e.key === 'F12') {
        e.preventDefault();
        return false;
    }
    // Ctrl+Shift+I (DevTools)
    if (e.ctrlKey && e.shiftKey && e.key === 'I') {
        e.preventDefault();
        return false;
    }
    // Ctrl+Shift+J (Console)
    if (e.ctrlKey && e.shiftKey && e.key === 'J') {
        e.preventDefault();
        return false;
    }
    // Ctrl+Shift+C (Inspect Element)
    if (e.ctrlKey && e.shiftKey && e.key === 'C') {
        e.preventDefault();
        return false;
    }
    // Ctrl+U (View Source)
    if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
        return false;
    }
    // F11 (Fullscreen can be used to access DevTools)
    if (e.key === 'F11') {
        e.preventDefault();
        return false;
    }
    // Ctrl+S (Save page)
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        return false;
    }
});

// Detect DevTools open
let devtools = {open: false, orientation: null};
const threshold = 160;
setInterval(() => {
    if (window.outerHeight - window.innerHeight > threshold || 
        window.outerWidth - window.innerWidth > threshold) {
        if (!devtools.open) {
            devtools.open = true;
            console.clear();
            document.body.innerHTML = '<h1 style="text-align:center; margin-top:50px;">Nieautoryzowany dostęp!</h1>';
            setTimeout(() => {
                window.location.reload();
            }, 2000);
        }
    } else {
        devtools.open = false;
    }
}, 500);

// Console protection
const consoleError = console.error;
const consoleLog = console.log;
const consoleWarn = console.warn;

console.log = function() {
    consoleLog.apply(console, arguments);
    console.clear();
};

console.error = function() {
    consoleError.apply(console, arguments);
    console.clear();
};

console.warn = function() {
    consoleWarn.apply(console, arguments);
    console.clear();
};

// Security Helper
const SecurityHelper = {
    addSecurityFields(data) {
        return {
            ...data,
            _lastModified: new Date().toISOString(),
            _version: 1,
            _deviceId: this.getDeviceId(),
            _sessionId: this.getSessionId()
        };
    },
    
    getDeviceId() {
        let deviceId = localStorage.getItem('deviceId');
        if (!deviceId) {
            deviceId = 'dev_' + Math.random().toString(36).substr(2, 9);
            localStorage.setItem('deviceId', deviceId);
        }
        return deviceId;
    },
    
    getSessionId() {
        if (!window.sessionId) {
            window.sessionId = 'ses_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        }
        return window.sessionId;
    }
};

// Secret key combination handler - CTRL+SHIFT+Z
document.addEventListener('keydown', function(e) {
    // Check for Ctrl+Shift+Z
    if (e.ctrlKey && e.shiftKey && e.key === 'Z') {
        e.preventDefault();
        
        // Show the real app
        document.getElementById('errorScreen').style.display = 'none';
        document.getElementById('appContainer').style.display = 'block';
        
        // Initialize Google Sign-In after revealing the app
        if (!googleInitialized) {
            setTimeout(() => {
                initializeGoogleSignIn();
            }, 100);
        }
    }
});

// Navigation functions
function goBack() {
    if (navigationHistory.length > 0) {
        const previousScreen = navigationHistory.pop();
        showScreen(previousScreen, false);
    } else {
        showScreen('passwordScreen', false);
    }
}

function backToHome() {
    // Hide all sections
    document.getElementById('notepadSection').style.display = 'none';
    document.getElementById('videosSection').style.display = 'none';
    document.getElementById('homeContent').style.display = 'block';
    document.getElementById('contentNav').style.display = 'none';
    
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelector('[data-section="home"]').classList.add('active');
}

// Initialize Google Sign-In
function initializeGoogleSignIn() {
    if (googleInitialized) return;
    
    try {
        google.accounts.id.initialize({
            client_id: GOOGLE_CLIENT_ID,
            callback: handleGoogleSignIn,
            auto_select: false,
            cancel_on_tap_outside: false,
            context: 'signin',
            ux_mode: 'popup',
            itp_support: true
        });
        
        // Render Google button
        const buttonDiv = document.getElementById('googleLoginBtn');
        
        google.accounts.id.renderButton(
            buttonDiv,
            {
                type: 'standard',
                theme: 'filled_blue',
                size: 'large',
                text: 'signin_with',
                shape: 'rectangular',
                logo_alignment: 'center',
                locale: 'pl'
            }
        );
        
        googleInitialized = true;
        consoleLog('Google Sign-In initialized successfully');
        
    } catch (error) {
        consoleError('Error initializing Google Sign-In:', error);
        showAlternativeLogin();
    }
}

// Alternative login if Google button fails
function showAlternativeLogin() {
    const buttonDiv = document.getElementById('googleLoginBtn');
    buttonDiv.innerHTML = `
        <button class="google-login-btn" onclick="useOAuthRedirect()">
            <img src="https://www.gstatic.com/firebasejs/ui/2.0.0/images/auth/google.svg" alt="Google">
            Zaloguj się przez Google
        </button>
    `;
}

// OAuth redirect method
function useOAuthRedirect() {
    consoleLog('Using OAuth redirect method...');
    
    const redirectUri = window.location.origin + window.location.pathname;
    const state = generateNonce();
    const nonce = generateNonce();
    
    sessionStorage.setItem('oauth_state', state);
    sessionStorage.setItem('oauth_nonce', nonce);
    
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${GOOGLE_CLIENT_ID}&` +
        `redirect_uri=${encodeURIComponent(redirectUri)}&` +
        `response_type=id_token&` +
        `scope=openid%20profile%20email&` +
        `state=${state}&` +
        `nonce=${nonce}`;
    
    window.location.href = authUrl;
}

// Generate nonce
function generateNonce() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

// Handle OAuth redirect
function handleOAuthRedirect() {
    const hash = window.location.hash;
    if (!hash) return;
    
    try {
        const params = new URLSearchParams(hash.substring(1));
        const idToken = params.get('id_token');
        const state = params.get('state');
        
        if (idToken && state === sessionStorage.getItem('oauth_state')) {
            consoleLog('Received token from OAuth redirect');
            
            sessionStorage.removeItem('oauth_state');
            sessionStorage.removeItem('oauth_nonce');
            
            // Show the app if coming from OAuth
            document.getElementById('errorScreen').style.display = 'none';
            document.getElementById('appContainer').style.display = 'block';
            
            handleGoogleSignIn({ credential: idToken });
            
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    } catch (error) {
        consoleError('Error handling OAuth redirect:', error);
    }
}

// Handle Google Sign-In response
async function handleGoogleSignIn(response) {
    consoleLog('Processing login response...');
    showLoading(true);
    
    try {
        // Decode JWT token
        const credential = parseJwt(response.credential);
        
        currentUser = {
            id: credential.sub,
            email: credential.email,
            name: credential.name,
            picture: credential.picture
        };
        
        consoleLog('Logged in as:', currentUser.name);
        consoleLog('User ID:', currentUser.id);
        
        // Store authentication state
        sessionStorage.setItem('authUser', JSON.stringify(currentUser));
        
        // Test Firestore connection
        try {
            const userRef = db.collection('users').doc(currentUser.id);
            const userDoc = await userRef.get();
            
            if (!userDoc.exists) {
                consoleLog('Creating new user...');
                // New user - create document first
                await userRef.set({
                    email: currentUser.email,
                    name: currentUser.name,
                    createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                    lastLogin: new Date().toISOString()
                });
                
                // Show password setup
                showScreen('passwordScreen');
                document.getElementById('passwordTitle').textContent = 'Utwórz hasło dostępu';
                document.getElementById('passwordConfirmGroup').style.display = 'block';
                document.getElementById('passwordStrength').style.display = 'block';
            } else {
                consoleLog('User exists, checking data...');
                // Existing user - check lockout
                const userData = userDoc.data();
                
                if (userData.lockoutEndTime && new Date(userData.lockoutEndTime) > new Date()) {
                    lockoutEndTime = new Date(userData.lockoutEndTime);
                    showLockout();
                } else {
                    // Reset failed attempts if any
                    failedPasswordAttempts = userData.failedAttempts || 0;
                    
                    // Check if user is already authenticated in this session
                    if (isAuthenticated) {
                        // Go directly to main panel
                        showScreen('mainPanel');
                        loadNotes();
                        loadFolders();
                    } else {
                        // Show password entry
                        showScreen('passwordScreen');
                        document.getElementById('passwordTitle').textContent = 'Wprowadź hasło';
                        document.getElementById('passwordConfirmGroup').style.display = 'none';
                        document.getElementById('passwordStrength').style.display = 'none';
                    }
                }
            }
            
            // Update UI with user info
            updateUserInfo();
            
        } catch (firestoreError) {
            consoleError('Firestore error:', firestoreError);
            
            if (firestoreError.code === 'permission-denied') {
                alert('Błąd uprawnień! Sprawdź reguły Firestore w Firebase Console.\n\n' +
                      '1. Przejdź do Firebase Console\n' +
                      '2. Wybierz Firestore Database → Rules\n' +
                      '3. Ustaw tymczasowe reguły: allow read, write: if true;\n' +
                      '4. Kliknij Publish i odczekaj 30 sekund');
            } else {
                alert('Błąd połączenia z bazą danych: ' + firestoreError.message);
            }
            
            showScreen('loginScreen');
            return;
        }
        
    } catch (error) {
        consoleError('Login error:', error);
        showError('Błąd logowania. Spróbuj ponownie.');
        showScreen('loginScreen');
    } finally {
        showLoading(false);
    }
}

// Parse JWT token
function parseJwt(token) {
    try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(function(c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        return JSON.parse(jsonPayload);
    } catch (error) {
        consoleError('Error parsing token:', error);
        throw new Error('Invalid token');
    }
}

// Update user info in UI
function updateUserInfo() {
    if (currentUser) {
        document.getElementById('userAvatar').src = currentUser.picture;
        document.getElementById('userName').textContent = currentUser.name;
        document.getElementById('sidebarAvatar').src = currentUser.picture;
        document.getElementById('sidebarUserName').textContent = currentUser.name;
    }
}

// Password handling
document.getElementById('passwordForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const password = document.getElementById('passwordInput').value;
    const confirmPassword = document.getElementById('passwordConfirm').value;
    const isNewUser = document.getElementById('passwordConfirmGroup').style.display !== 'none';
    
    showLoading(true);
    
    try {
        if (isNewUser) {
            // Create new password
            if (password !== confirmPassword) {
                showError('Hasła nie są identyczne', 'passwordError');
                showLoading(false);
                return;
            }
            
            if (password.length < 8) {
                showError('Hasło musi mieć minimum 8 znaków', 'passwordError');
                showLoading(false);
                return;
            }
            
            // Hash password
            const hashedPassword = await hashPassword(password);
            
            // Save to Firestore with security fields
            const userData = SecurityHelper.addSecurityFields({
                email: currentUser.email,
                name: currentUser.name,
                password: hashedPassword,
                createdAt: firebase.firestore.FieldValue.serverTimestamp(),
                failedAttempts: 0
            });
            
            await db.collection('users').doc(currentUser.id).update(userData);
            
            // Show PIN setup
            showScreen('pinScreen');
            document.getElementById('pinTitle').textContent = 'Utwórz 4-cyfrowy PIN';
            document.getElementById('pinConfirmContainer').style.display = 'block';
            
        } else {
            // Verify existing password
            const userDoc = await db.collection('users').doc(currentUser.id).get();
            const userData = userDoc.data();
            
            const isValid = await verifyPassword(password, userData.password);
            
            if (isValid) {
                // Reset failed attempts
                await db.collection('users').doc(currentUser.id).update({
                    failedAttempts: 0,
                    lockoutEndTime: null,
                    lastLogin: new Date().toISOString()
                });
                
                failedPasswordAttempts = 0;
                
                // Check if PIN exists
                if (!userData.pin) {
                    showScreen('pinScreen');
                    document.getElementById('pinTitle').textContent = 'Utwórz 4-cyfrowy PIN';
                    document.getElementById('pinConfirmContainer').style.display = 'block';
                } else {
                    showScreen('pinScreen');
                    document.getElementById('pinTitle').textContent = 'Wprowadź PIN';
                    document.getElementById('pinConfirmContainer').style.display = 'none';
                }
            } else {
                // Invalid password
                failedPasswordAttempts++;
                
                if (failedPasswordAttempts >= 2) {
                    // Lock account for 5 hours
                    const lockoutEnd = new Date();
                    lockoutEnd.setHours(lockoutEnd.getHours() + 5);
                    
                    await db.collection('users').doc(currentUser.id).update({
                        failedAttempts: failedPasswordAttempts,
                        lockoutEndTime: lockoutEnd.toISOString()
                    });
                    
                    lockoutEndTime = lockoutEnd;
                    showLockout();
                } else {
                    showError(`Nieprawidłowe hasło. Pozostała próba: ${2 - failedPasswordAttempts}`, 'passwordError');
                    
                    await db.collection('users').doc(currentUser.id).update({
                        failedAttempts: failedPasswordAttempts
                    });
                }
            }
        }
        
    } catch (error) {
        consoleError('Password error:', error);
        showError('Wystąpił błąd. Spróbuj ponownie.', 'passwordError');
    } finally {
        showLoading(false);
    }
});

// Password strength indicator
document.getElementById('passwordInput').addEventListener('input', (e) => {
    const password = e.target.value;
    const strengthBar = document.querySelector('.strength-fill');
    const strengthText = document.querySelector('.strength-text');
    
    if (document.getElementById('passwordStrength').style.display === 'none') return;
    
    let strength = 0;
    
    // Length check
    if (password.length >= 8) strength++;
    if (password.length >= 12) strength++;
    
    // Character variety
    if (/[a-z]/.test(password)) strength++;
    if (/[A-Z]/.test(password)) strength++;
    if (/[0-9]/.test(password)) strength++;
    if (/[^A-Za-z0-9]/.test(password)) strength++;
    
    // Update UI
    strengthBar.className = 'strength-fill';
    
    if (strength <= 2) {
        strengthBar.classList.add('weak');
        strengthText.textContent = 'Słabe';
    } else if (strength <= 4) {
        strengthBar.classList.add('medium');
        strengthText.textContent = 'Średnie';
    } else {
        strengthBar.classList.add('strong');
        strengthText.textContent = 'Silne';
    }
});

// Toggle password visibility
document.querySelectorAll('.toggle-password').forEach(btn => {
    btn.addEventListener('click', () => {
        const input = btn.parentElement.querySelector('input');
        const icon = btn.querySelector('i');
        
        if (input.type === 'password') {
            input.type = 'text';
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        } else {
            input.type = 'password';
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    });
});

// PIN input handling
const pinDigits = document.querySelectorAll('.pin-digit');
const pinDigitsConfirm = document.querySelectorAll('.pin-digit-confirm');

function setupPinInputs(inputs) {
    inputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            const value = e.target.value;
            
            if (!/^\d$/.test(value)) {
                e.target.value = '';
                return;
            }
            
            e.target.classList.add('filled');
            
            // Auto-focus next input
            if (index < inputs.length - 1) {
                inputs[index + 1].focus();
            }
        });
        
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !e.target.value && index > 0) {
                inputs[index - 1].focus();
            }
        });
    });
}

setupPinInputs(pinDigits);
setupPinInputs(pinDigitsConfirm);

// PIN form submission
document.getElementById('pinForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const pin = Array.from(pinDigits).map(d => d.value).join('');
    const confirmPin = Array.from(pinDigitsConfirm).map(d => d.value).join('');
    const isNewPin = document.getElementById('pinConfirmContainer').style.display !== 'none';
    
    if (pin.length !== 4) {
        showError('PIN musi składać się z 4 cyfr', 'pinError');
        return;
    }
    
    showLoading(true);
    
    try {
        if (isNewPin) {
            // Create new PIN
            if (pin !== confirmPin) {
                showError('PIN-y nie są identyczne', 'pinError');
                showLoading(false);
                return;
            }
            
            // Hash PIN
            const hashedPin = await hashPassword(pin);
            
            // Save to Firestore
            await db.collection('users').doc(currentUser.id).update({
                pin: hashedPin
            });
            
            // Check if user has rule
            const userDoc = await db.collection('users').doc(currentUser.id).get();
            const userData = userDoc.data();
            
            if (!userData.rule) {
                // Show rule setup
                showScreen('ruleScreen');
                document.getElementById('ruleTitle').textContent = 'Utwórz regułę bezpieczeństwa';
                document.getElementById('ruleConfirmContainer').style.display = 'block';
            } else {
                // Go to main panel
                isAuthenticated = true;
                showScreen('mainPanel');
                loadNotes();
                loadFolders();
            }
            
        } else {
            // Verify existing PIN
            const userDoc = await db.collection('users').doc(currentUser.id).get();
            const userData = userDoc.data();
            
            const isValid = await verifyPassword(pin, userData.pin);
            
            if (isValid) {
                // Check if rule exists
                if (!userData.rule) {
                    showScreen('ruleScreen');
                    document.getElementById('ruleTitle').textContent = 'Utwórz regułę bezpieczeństwa';
                    document.getElementById('ruleConfirmContainer').style.display = 'block';
                } else {
                    showScreen('ruleScreen');
                    document.getElementById('ruleTitle').textContent = 'Wprowadź regułę';
                    document.getElementById('ruleConfirmContainer').style.display = 'none';
                }
            } else {
                showError('Nieprawidłowy PIN', 'pinError');
                
                // Clear inputs
                pinDigits.forEach(input => {
                    input.value = '';
                    input.classList.remove('filled');
                });
                pinDigits[0].focus();
            }
        }
        
    } catch (error) {
        consoleError('PIN error:', error);
        showError('Wystąpił błąd. Spróbuj ponownie.', 'pinError');
    } finally {
        showLoading(false);
    }
});

// Rule input handling
const ruleDigit = document.getElementById('ruleDigit');
const ruleLetter = document.getElementById('ruleLetter');
const ruleDigitConfirm = document.getElementById('ruleDigitConfirm');
const ruleLetterConfirm = document.getElementById('ruleLetterConfirm');

// Auto-focus next input for rule
ruleDigit.addEventListener('input', (e) => {
    if (e.target.value && /^\d$/.test(e.target.value)) {
        ruleLetter.focus();
    }
});

ruleDigitConfirm.addEventListener('input', (e) => {
    if (e.target.value && /^\d$/.test(e.target.value)) {
        ruleLetterConfirm.focus();
    }
});

// Force uppercase for letters
ruleLetter.addEventListener('input', (e) => {
    e.target.value = e.target.value.toUpperCase();
});

ruleLetterConfirm.addEventListener('input', (e) => {
    e.target.value = e.target.value.toUpperCase();
});

// Rule form submission
document.getElementById('ruleForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const digit = ruleDigit.value;
    const letter = ruleLetter.value.toUpperCase();
    const rule = digit + letter;
    
    const digitConfirm = ruleDigitConfirm.value;
    const letterConfirm = ruleLetterConfirm.value.toUpperCase();
    const ruleConfirm = digitConfirm + letterConfirm;
    
    const isNewRule = document.getElementById('ruleConfirmContainer').style.display !== 'none';
    
    // Validate input
    if (!digit || !letter) {
        showError('Wprowadź cyfrę i literę', 'ruleError');
        return;
    }
    
    if (!/^\d$/.test(digit)) {
        showError('Pierwszy znak musi być cyfrą', 'ruleError');
        return;
    }
    
    if (!/^[A-Z]$/.test(letter)) {
        showError('Drugi znak musi być literą', 'ruleError');
        return;
    }
    
    showLoading(true);
    
    try {
        if (isNewRule) {
            // Create new rule
            if (rule !== ruleConfirm) {
                showError('Reguły nie są identyczne', 'ruleError');
                showLoading(false);
                return;
            }
            
            // Hash rule
            const hashedRule = await hashPassword(rule);
            
            // Save to Firestore
            await db.collection('users').doc(currentUser.id).update({
                rule: hashedRule
            });
            
            // Go to main panel
            isAuthenticated = true;
            showScreen('mainPanel');
            loadNotes();
            loadFolders();
            
        } else {
            // Verify existing rule
            const userDoc = await db.collection('users').doc(currentUser.id).get();
            const userData = userDoc.data();
            
            const isValid = await verifyPassword(rule, userData.rule);
            
            if (isValid) {
                isAuthenticated = true;
                showScreen('mainPanel');
                loadNotes();
                loadFolders();
            } else {
                showError('Nieprawidłowa reguła', 'ruleError');
                
                // Clear inputs
                ruleDigit.value = '';
                ruleLetter.value = '';
                ruleDigit.focus();
            }
        }
        
    } catch (error) {
        consoleError('Rule error:', error);
        showError('Wystąpił błąd. Spróbuj ponownie.', 'ruleError');
    } finally {
        showLoading(false);
    }
});

// Navigation
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', async (e) => {
        e.preventDefault();
        
        const section = item.dataset.section;
        
        if (section === 'home') {
            backToHome();
        } else if (section === 'notepad' || section === 'videos') {
            // Both notepad and videos require PIN modal
            document.getElementById('pinModal').classList.add('show');
            document.getElementById('accessCode').value = '';
            document.getElementById('accessCode').focus();
            // Store which section to open after authentication
            document.getElementById('pinModal').dataset.targetSection = section;
        }
    });
});

// Access form (@ + PIN + Rule)
document.getElementById('accessForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const accessCode = document.getElementById('accessCode').value;
    
    if (!accessCode.startsWith('@') || accessCode.length !== 7) {
        showError('Format: @[4-cyfrowy PIN][REGUŁA]', 'accessError');
        return;
    }
    
    const pin = accessCode.substring(1, 5);
    const rule = accessCode.substring(5, 7).toUpperCase();
    
    if (!/^\d{4}$/.test(pin)) {
        showError('PIN musi składać się z 4 cyfr', 'accessError');
        return;
    }
    
    if (!/^\d[A-Z]$/.test(rule)) {
        showError('Reguła musi być w formacie: cyfra + litera', 'accessError');
        return;
    }
    
    showLoading(true);
    
    try {
        const userDoc = await db.collection('users').doc(currentUser.id).get();
        const userData = userDoc.data();
        
        const isPinValid = await verifyPassword(pin, userData.pin);
        const isRuleValid = await verifyPassword(rule, userData.rule);
        
        if (isPinValid && isRuleValid) {
            closePinModal();
            // Check which section to open
            const targetSection = document.getElementById('pinModal').dataset.targetSection;
            if (targetSection === 'notepad') {
                showNotepad();
            } else if (targetSection === 'videos') {
                showVideosSection();
            }
        } else {
            showError('Nieprawidłowy kod dostępu', 'accessError');
        }
        
    } catch (error) {
        consoleError('Access error:', error);
        showError('Wystąpił błąd. Spróbuj ponownie.', 'accessError');
    } finally {
        showLoading(false);
    }
});

// Videos Section Functions
function showVideosSection() {
    document.getElementById('homeContent').style.display = 'none';
    document.getElementById('notepadSection').style.display = 'none';
    document.getElementById('videosSection').style.display = 'block';
    document.getElementById('contentNav').style.display = 'block';
    
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelector('[data-section="videos"]').classList.add('active');
    
    // Load videos if not loaded
    loadVideos();
}

// Load folders
async function loadFolders() {
    try {
        const foldersSnapshot = await db.collection('users').doc(currentUser.id)
            .collection('folders').orderBy('name').get();
        
        folders = [];
        foldersSnapshot.forEach(doc => {
            folders.push({ id: doc.id, ...doc.data() });
        });
        
        // Add default "All Videos" folder
        folders.unshift({
            id: 'all',
            name: 'Wszystkie filmy',
            videoCount: 0,
            isDefault: true
        });
        
        renderFoldersList();
        
        // Select first folder by default
        if (!currentFolder && folders.length > 0) {
            selectFolder(folders[0]);
        }
        
    } catch (error) {
        consoleError('Error loading folders:', error);
    }
}

// Render folders list
function renderFoldersList() {
    const foldersList = document.getElementById('foldersList');
    foldersList.innerHTML = '';
    
    folders.forEach(folder => {
        const folderItem = document.createElement('div');
        folderItem.className = 'folder-item';
        if (currentFolder && currentFolder.id === folder.id) {
            folderItem.classList.add('active');
        }
        
        folderItem.innerHTML = `
            <i class="fas fa-folder${folder.isDefault ? '' : '-open'} folder-icon"></i>
            <div class="folder-info">
                <div class="folder-name">${folder.name}</div>
                <div class="folder-count">${folder.videoCount || 0} ${folder.videoCount === 1 ? 'film' : 'filmów'}</div>
            </div>
        `;
        
        folderItem.addEventListener('click', () => selectFolder(folder));
        foldersList.appendChild(folderItem);
    });
}

// Select folder
function selectFolder(folder) {
    currentFolder = folder;
    renderFoldersList();
    
    document.getElementById('folderTitle').textContent = folder.name;
    document.getElementById('currentPath').textContent = `/ ${folder.name}`;
    
    loadVideos(folder.id === 'all' ? null : folder.id);
}

// Load videos
async function loadVideos(folderId = null) {
    try {
        showLoading(true);
        
        let query = db.collection('users').doc(currentUser.id).collection('videos');
        
        if (folderId) {
            query = query.where('folderId', '==', folderId);
        }
        
        const videosSnapshot = await query.orderBy('uploadedAt', 'desc').get();
        
        videos = [];
        videosSnapshot.forEach(doc => {
            videos.push({ id: doc.id, ...doc.data() });
        });
        
        renderVideos();
        
        // Update folder counts
        updateFolderCounts();
        
    } catch (error) {
        consoleError('Error loading videos:', error);
        // If error is because index doesn't exist, try without orderBy
        if (error.code === 'failed-precondition') {
            try {
                let query = db.collection('users').doc(currentUser.id).collection('videos');
                
                if (folderId) {
                    query = query.where('folderId', '==', folderId);
                }
                
                const videosSnapshot = await query.get();
                
                videos = [];
                videosSnapshot.forEach(doc => {
                    videos.push({ id: doc.id, ...doc.data() });
                });
                
                // Sort locally
                videos.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
                
                renderVideos();
                updateFolderCounts();
            } catch (retryError) {
                consoleError('Retry error:', retryError);
            }
        }
    } finally {
        showLoading(false);
    }
}

// Update folder video counts
async function updateFolderCounts() {
    const counts = {};
    videos.forEach(video => {
        const folderId = video.folderId || 'all';
        counts[folderId] = (counts[folderId] || 0) + 1;
    });
    
    folders.forEach(folder => {
        if (folder.id === 'all') {
            folder.videoCount = videos.length;
        } else {
            folder.videoCount = counts[folder.id] || 0;
        }
    });
    
    renderFoldersList();
}

// Render videos
function renderVideos() {
    const videosGrid = document.getElementById('videosGrid');
    const emptyState = document.getElementById('emptyState');
    
    if (videos.length === 0) {
        videosGrid.style.display = 'none';
        emptyState.style.display = 'flex';
        return;
    }
    
    videosGrid.style.display = '';
    emptyState.style.display = 'none';
    
    videosGrid.innerHTML = '';
    videosGrid.className = currentView === 'list' ? 'videos-grid list-view' : 'videos-grid';
    
    videos.forEach(video => {
        const videoCard = createVideoCard(video);
        videosGrid.appendChild(videoCard);
    });
}

// Create video card
function createVideoCard(video) {
    const card = document.createElement('div');
    card.className = currentView === 'list' ? 'video-card list-item' : 'video-card';
    
    const duration = formatDuration(video.duration);
    const uploadDate = new Date(video.uploadedAt).toLocaleDateString('pl-PL');
    const fileSize = formatFileSize(video.size);
    
    card.innerHTML = `
        <div class="video-thumbnail">
            <img src="${video.thumbnail || 'data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNDAwIiBoZWlnaHQ9IjIyNSIgdmlld0JveD0iMCAwIDQwMCAyMjUiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxyZWN0IHdpZHRoPSI0MDAiIGhlaWdodD0iMjI1IiBmaWxsPSIjMjUyNTI1Ii8+CjxwYXRoIGQ9Ik0xNzUgMTUwVjc1TDI1MCAxMTIuNUwxNzUgMTUwWiIgZmlsbD0iIzY2NjY2NiIvPgo8L3N2Zz4='}" alt="${video.title}">
            <span class="video-duration">${duration}</span>
        </div>
        <div class="video-info">
            <div class="video-title">${video.title}</div>
            <div class="video-meta">
                <span>${fileSize}</span>
                <span>${uploadDate}</span>
            </div>
        </div>
    `;
    
    card.addEventListener('click', () => playVideo(video));
    return card;
}

// Play video
function playVideo(video) {
    const modal = document.getElementById('videoPlayerModal');
    const player = document.getElementById('videoPlayer');
    
    document.getElementById('videoPlayerTitle').textContent = video.title;
    document.getElementById('videoSize').textContent = formatFileSize(video.size);
    document.getElementById('videoDuration').textContent = formatDuration(video.duration);
    document.getElementById('videoDate').textContent = new Date(video.uploadedAt).toLocaleString('pl-PL');
    
    player.src = video.url;
    modal.classList.add('show');
    
    // Play video
    player.play().catch(err => consoleError('Error playing video:', err));
}

// Close video player
function closeVideoPlayer() {
    const modal = document.getElementById('videoPlayerModal');
    const player = document.getElementById('videoPlayer');
    
    player.pause();
    player.src = '';
    modal.classList.remove('show');
}

// View controls
document.querySelectorAll('.view-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        currentView = btn.dataset.view;
        renderVideos();
    });
});

// Upload Modal Functions
function showUploadModal() {
    document.getElementById('uploadModal').classList.add('show');
    uploadQueue = [];
    renderUploadQueue();
}

function closeUploadModal() {
    document.getElementById('uploadModal').classList.remove('show');
    document.getElementById('videoFileInput').value = '';
    uploadQueue = [];
    renderUploadQueue();
}

// File input handling
document.getElementById('videoFileInput').addEventListener('change', (e) => {
    handleFileSelect(e.target.files);
});

// Drag and drop
const dropzone = document.getElementById('uploadDropzone');

dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('drag-over');
});

dropzone.addEventListener('dragleave', () => {
    dropzone.classList.remove('drag-over');
});

dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('drag-over');
    handleFileSelect(e.dataTransfer.files);
});

// Handle file selection
function handleFileSelect(files) {
    const videoFiles = Array.from(files).filter(file => {
        return file.type.startsWith('video/') && file.size <= 5 * 1024 * 1024 * 1024; // 5GB limit
    });
    
    if (videoFiles.length === 0) {
        showError('Wybierz pliki wideo (maks. 5GB)');
        return;
    }
    
    videoFiles.forEach(file => {
        if (!uploadQueue.find(f => f.name === file.name)) {
            uploadQueue.push(file);
        }
    });
    
    renderUploadQueue();
}

// Render upload queue
function renderUploadQueue() {
    const queueContainer = document.getElementById('uploadQueue');
    const queueList = document.getElementById('uploadQueueList');
    const startBtn = document.getElementById('startUploadBtn');
    
    if (uploadQueue.length === 0) {
        queueContainer.style.display = 'none';
        startBtn.disabled = true;
        return;
    }
    
    queueContainer.style.display = 'block';
    startBtn.disabled = false;
    
    queueList.innerHTML = '';
    
    uploadQueue.forEach((file, index) => {
        const item = document.createElement('div');
        item.className = 'upload-queue-item';
        
        item.innerHTML = `
            <div class="file-icon">
                <i class="fas fa-film"></i>
            </div>
            <div class="file-info">
                <div class="file-name">${file.name}</div>
                <div class="file-size">${formatFileSize(file.size)}</div>
            </div>
            <button class="remove-file" onclick="removeFromQueue(${index})">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        queueList.appendChild(item);
    });
}

// Remove from queue
function removeFromQueue(index) {
    uploadQueue.splice(index, 1);
    renderUploadQueue();
}

// Start upload
async function startUpload() {
    if (uploadQueue.length === 0) return;
    
    closeUploadModal();
    
    for (let i = 0; i < uploadQueue.length; i++) {
        const file = uploadQueue[i];
        await uploadVideo(file);
    }
    
    // Reload videos
    loadVideos(currentFolder && currentFolder.id !== 'all' ? currentFolder.id : null);
}

// Upload video with proper error handling
async function uploadVideo(file) {
    const uploadOverlay = document.getElementById('uploadOverlay');
    const progressFill = document.getElementById('uploadProgressFill');
    const uploadStatus = document.getElementById('uploadStatus');
    const uploadSpeed = document.getElementById('uploadSpeed');
    const uploadTimeLeft = document.getElementById('uploadTimeLeft');
    
    uploadOverlay.classList.add('show');
    document.getElementById('uploadFileName').textContent = file.name;
    
    try {
        // Create unique file name
        const timestamp = Date.now();
        const sanitizedFileName = file.name.replace(/[^a-zA-Z0-9.-]/g, '_');
        const fileName = `${timestamp}_${sanitizedFileName}`;
        const storageRef = storage.ref(`videos/${currentUser.id}/${fileName}`);
        
        // Create upload task
        const uploadTask = storageRef.put(file, {
            contentType: file.type,
            customMetadata: {
                'uploadedBy': currentUser.email,
                'originalName': file.name
            }
        });
        
        let startTime = Date.now();
        let lastBytes = 0;
        
        // Return promise to handle upload
        return new Promise((resolve, reject) => {
            uploadTask.on('state_changed', 
                (snapshot) => {
                    // Progress
                    const progress = (snapshot.bytesTransferred / snapshot.totalBytes) * 100;
                    progressFill.style.width = progress + '%';
                    uploadStatus.textContent = Math.round(progress) + '%';
                    
                    // Calculate speed
                    const currentTime = Date.now();
                    const elapsedSeconds = (currentTime - startTime) / 1000;
                    const bytesTransferred = snapshot.bytesTransferred - lastBytes;
                    const bytesPerSecond = bytesTransferred / elapsedSeconds;
                    const mbPerSecond = (bytesPerSecond / (1024 * 1024)).toFixed(1);
                    uploadSpeed.textContent = mbPerSecond + ' MB/s';
                    
                    // Calculate time remaining
                    const bytesRemaining = snapshot.totalBytes - snapshot.bytesTransferred;
                    const secondsRemaining = Math.ceil(bytesRemaining / bytesPerSecond);
                    const minutesRemaining = Math.ceil(secondsRemaining / 60);
                    
                    if (minutesRemaining > 1) {
                        uploadTimeLeft.textContent = `${minutesRemaining} min`;
                    } else {
                        uploadTimeLeft.textContent = `${secondsRemaining} sek`;
                    }
                    
                    lastBytes = snapshot.bytesTransferred;
                    startTime = currentTime;
                },
                (error) => {
                    // Error
                    consoleError('Upload error:', error);
                    uploadOverlay.classList.remove('show');
                    
                    let errorMessage = 'Błąd przesyłania: ';
                    switch (error.code) {
                        case 'storage/unauthorized':
                            errorMessage += 'Brak uprawnień do przesyłania';
                            break;
                        case 'storage/canceled':
                            errorMessage += 'Przesyłanie anulowane';
                            break;
                        case 'storage/unknown':
                            errorMessage += 'Nieznany błąd';
                            break;
                        default:
                            errorMessage += error.message;
                    }
                    
                    showError(errorMessage);
                    reject(error);
                },
                async () => {
                    // Complete
                    try {
                        const downloadURL = await uploadTask.snapshot.ref.getDownloadURL();
                        
                        // Get video duration
                        const duration = await getVideoDuration(file);
                        
                        // Generate thumbnail
                        const thumbnail = await generateVideoThumbnail(file);
                        
                        // Save to Firestore
                        const videoData = SecurityHelper.addSecurityFields({
                            title: file.name.replace(/\.[^/.]+$/, ''), // Remove extension
                            fileName: file.name,
                            storagePath: `videos/${currentUser.id}/${fileName}`,
                            size: file.size,
                            type: file.type,
                            url: downloadURL,
                            thumbnail: thumbnail,
                            duration: duration,
                            folderId: currentFolder && currentFolder.id !== 'all' ? currentFolder.id : null,
                            uploadedAt: new Date().toISOString()
                        });
                        
                        await db.collection('users').doc(currentUser.id)
                            .collection('videos').add(videoData);
                        
                        uploadOverlay.classList.remove('show');
                        resolve();
                        
                    } catch (saveError) {
                        consoleError('Error saving video data:', saveError);
                        uploadOverlay.classList.remove('show');
                        showError('Film został przesłany, ale wystąpił błąd zapisu danych');
                        reject(saveError);
                    }
                }
            );
        });
        
    } catch (error) {
        consoleError('Upload initialization error:', error);
        uploadOverlay.classList.remove('show');
        showError('Nie można rozpocząć przesyłania');
        throw error;
    }
}

// Get video duration
async function getVideoDuration(file) {
    return new Promise((resolve) => {
        const video = document.createElement('video');
        video.preload = 'metadata';
        
        video.onloadedmetadata = function() {
            window.URL.revokeObjectURL(video.src);
            resolve(video.duration);
        };
        
        video.onerror = function() {
            resolve(0);
        };
        
        video.src = URL.createObjectURL(file);
    });
}

// Generate video thumbnail
async function generateVideoThumbnail(file) {
    return new Promise((resolve) => {
        const video = document.createElement('video');
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        video.addEventListener('loadedmetadata', () => {
            // Seek to 10% of video duration for better thumbnail
            video.currentTime = video.duration * 0.1;
        });
        
        video.addEventListener('seeked', () => {
            // Set canvas size
            canvas.width = 400;
            canvas.height = 225; // 16:9 aspect ratio
            
            // Draw video frame to canvas
            ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
            
            // Convert to data URL
            canvas.toBlob((blob) => {
                if (blob) {
                    const reader = new FileReader();
                    reader.onloadend = () => {
                        window.URL.revokeObjectURL(video.src);
                        resolve(reader.result);
                    };
                    reader.readAsDataURL(blob);
                } else {
                    window.URL.revokeObjectURL(video.src);
                    resolve(null);
                }
            }, 'image/jpeg', 0.8);
        });
        
        video.addEventListener('error', () => {
            window.URL.revokeObjectURL(video.src);
            resolve(null);
        });
        
        video.src = URL.createObjectURL(file);
        
        // Timeout fallback
        setTimeout(() => {
            resolve(null);
        }, 10000);
    });
}

// Create new folder
function createNewFolder() {
    document.getElementById('newFolderModal').classList.add('show');
    document.getElementById('folderNameInput').value = '';
    document.getElementById('folderNameInput').focus();
}

function closeNewFolderModal() {
    document.getElementById('newFolderModal').classList.remove('show');
}

// New folder form
document.getElementById('newFolderForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const folderName = document.getElementById('folderNameInput').value.trim();
    
    if (!folderName) {
        showError('Wprowadź nazwę folderu');
        return;
    }
    
    showLoading(true);
    
    try {
        const folderData = SecurityHelper.addSecurityFields({
            name: folderName,
            createdAt: new Date().toISOString(),
            videoCount: 0
        });
        
        await db.collection('users').doc(currentUser.id)
            .collection('folders').add(folderData);
        
        closeNewFolderModal();
        loadFolders();
        
    } catch (error) {
        consoleError('Error creating folder:', error);
        showError('Nie udało się utworzyć folderu');
    } finally {
        showLoading(false);
    }
});

// Format helpers
function formatDuration(seconds) {
    if (!seconds || seconds === 0) return '0:00';
    
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hours > 0) {
        return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${minutes}:${secs.toString().padStart(2, '0')}`;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Notepad functions
function showNotepad() {
    document.getElementById('homeContent').style.display = 'none';
    document.getElementById('videosSection').style.display = 'none';
    document.getElementById('notepadSection').style.display = 'block';
    document.getElementById('contentNav').style.display = 'block';
    
    // Mark nav item as active
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelector('[data-section="notepad"]').classList.add('active');
}

async function loadNotes() {
    try {
        const notesSnapshot = await db.collection('users').doc(currentUser.id)
            .collection('notes').orderBy('updatedAt', 'desc').get();
        
        notes = [];
        notesSnapshot.forEach(doc => {
            notes.push({ id: doc.id, ...doc.data() });
        });
        
        renderNotesList();
        
        if (notes.length > 0) {
            selectNote(notes[0]);
        }
        
    } catch (error) {
        consoleError('Error loading notes:', error);
    }
}

function renderNotesList(filter = 'all') {
    const notesList = document.getElementById('notesList');
    notesList.innerHTML = '';
    
    let filteredNotes = notes;
    
    if (filter === 'starred') {
        filteredNotes = notes.filter(note => note.starred);
    } else if (filter === 'recent') {
        const lastWeek = new Date();
        lastWeek.setDate(lastWeek.getDate() - 7);
        filteredNotes = notes.filter(note => new Date(note.updatedAt) > lastWeek);
    }
    
    filteredNotes.forEach(note => {
        const noteItem = document.createElement('div');
        noteItem.className = 'note-item';
        if (currentNote && currentNote.id === note.id) {
            noteItem.classList.add('active');
        }
        
        const contentPreview = stripHtml(note.content || '').substring(0, 50) + '...';
        const updatedDate = new Date(note.updatedAt).toLocaleDateString('pl-PL');
        
        noteItem.innerHTML = `
            <div class="note-item-title">
                ${note.starred ? '<i class="fas fa-star star-icon"></i>' : ''}
                ${note.title || 'Bez tytułu'}
            </div>
            <div class="note-item-preview">${contentPreview}</div>
            <div class="note-item-date">${updatedDate}</div>
        `;
        
        noteItem.addEventListener('click', () => selectNote(note));
        notesList.appendChild(noteItem);
    });
}

function selectNote(note) {
    currentNote = note;
    
    // Update editor
    document.getElementById('noteTitle').value = note.title || '';
    document.getElementById('noteContent').innerHTML = note.content || '';
    
    // Update star button
    const starBtn = document.querySelector('.star-btn');
    if (note.starred) {
        starBtn.classList.add('starred');
        starBtn.querySelector('i').classList.remove('far');
        starBtn.querySelector('i').classList.add('fas');
    } else {
        starBtn.classList.remove('starred');
        starBtn.querySelector('i').classList.remove('fas');
        starBtn.querySelector('i').classList.add('far');
    }
    
    // Update list active state
    renderNotesList();
    
    updateCharCount();
    updateLastSaved(note.updatedAt);
}

async function createNewNote() {
    try {
        const noteData = SecurityHelper.addSecurityFields({
            title: 'Nowa notatka',
            content: '',
            starred: false,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        });
        
        const docRef = await db.collection('users').doc(currentUser.id)
            .collection('notes').add(noteData);
        
        const newNote = { id: docRef.id, ...noteData };
        notes.unshift(newNote);
        
        renderNotesList();
        selectNote(newNote);
        
        // Focus on title
        document.getElementById('noteTitle').focus();
        
    } catch (error) {
        consoleError('Error creating note:', error);
        showError('Nie udało się utworzyć notatki');
    }
}

async function saveNote() {
    if (!currentNote) return;
    
    const title = document.getElementById('noteTitle').value;
    const content = document.getElementById('noteContent').innerHTML;
    
    try {
        const noteData = {
            title: title,
            content: content,
            updatedAt: new Date().toISOString(),
            _lastModified: new Date().toISOString()
        };
        
        await db.collection('users').doc(currentUser.id)
            .collection('notes').doc(currentNote.id).update(noteData);
        
        // Update local data
        Object.assign(currentNote, noteData);
        
        // Update UI
        renderNotesList();
        updateLastSaved(noteData.updatedAt);
        
        // Show save animation
        const saveBtn = document.querySelector('.save-btn');
        saveBtn.innerHTML = '<i class="fas fa-check"></i>';
        setTimeout(() => {
            saveBtn.innerHTML = '<i class="fas fa-save"></i>';
        }, 2000);
        
    } catch (error) {
        consoleError('Error saving note:', error);
        showError('Nie udało się zapisać notatki');
    }
}

async function deleteNote() {
    if (!currentNote) return;
    
    if (!confirm('Czy na pewno chcesz usunąć tę notatkę?')) return;
    
    try {
        await db.collection('users').doc(currentUser.id)
            .collection('notes').doc(currentNote.id).delete();
        
        // Remove from local array
        notes = notes.filter(note => note.id !== currentNote.id);
        
        // Clear editor
        currentNote = null;
        document.getElementById('noteTitle').value = '';
        document.getElementById('noteContent').innerHTML = '';
        
        renderNotesList();
        
        // Select first note if exists
        if (notes.length > 0) {
            selectNote(notes[0]);
        }
        
    } catch (error) {
        consoleError('Error deleting note:', error);
        showError('Nie udało się usunąć notatki');
    }
}

async function toggleStar() {
    if (!currentNote) return;
    
    currentNote.starred = !currentNote.starred;
    
    try {
        await db.collection('users').doc(currentUser.id)
            .collection('notes').doc(currentNote.id).update({
                starred: currentNote.starred
            });
        
        // Update UI
        const starBtn = document.querySelector('.star-btn');
        if (currentNote.starred) {
            starBtn.classList.add('starred');
            starBtn.querySelector('i').classList.remove('far');
            starBtn.querySelector('i').classList.add('fas');
        } else {
            starBtn.classList.remove('starred');
            starBtn.querySelector('i').classList.remove('fas');
            starBtn.querySelector('i').classList.add('far');
        }
        
        renderNotesList();
        
    } catch (error) {
        consoleError('Error updating star:', error);
    }
}

// Search notes
document.getElementById('searchInput').addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    
    if (!query) {
        renderNotesList();
        return;
    }
    
    const filteredNotes = notes.filter(note => {
        const title = (note.title || '').toLowerCase();
        const content = stripHtml(note.content || '').toLowerCase();
        return title.includes(query) || content.includes(query);
    });
    
    const notesList = document.getElementById('notesList');
    notesList.innerHTML = '';
    
    filteredNotes.forEach(note => {
        const noteItem = document.createElement('div');
        noteItem.className = 'note-item';
        if (currentNote && currentNote.id === note.id) {
            noteItem.classList.add('active');
        }
        
        const contentPreview = stripHtml(note.content || '').substring(0, 50) + '...';
        const updatedDate = new Date(note.updatedAt).toLocaleDateString('pl-PL');
        
        noteItem.innerHTML = `
            <div class="note-item-title">
                ${note.starred ? '<i class="fas fa-star star-icon"></i>' : ''}
                ${note.title || 'Bez tytułu'}
            </div>
            <div class="note-item-preview">${contentPreview}</div>
            <div class="note-item-date">${updatedDate}</div>
        `;
        
        noteItem.addEventListener('click', () => selectNote(note));
        notesList.appendChild(noteItem);
    });
});

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        renderNotesList(btn.dataset.filter);
    });
});

// Editor functions
function formatText(command) {
    document.execCommand(command, false, null);
    document.getElementById('noteContent').focus();
}

function insertList(type) {
    const selection = window.getSelection();
    const range = selection.getRangeAt(0);
    
    const list = document.createElement(type);
    const listItem = document.createElement('li');
    listItem.innerHTML = '<br>';
    list.appendChild(listItem);
    
    range.insertNode(list);
    range.setStart(listItem, 0);
    range.collapse(true);
    selection.removeAllRanges();
    selection.addRange(range);
    
    document.getElementById('noteContent').focus();
}

function changeColor() {
    const color = prompt('Wprowadź kolor (np. #6366f1):');
    if (color) {
        document.execCommand('foreColor', false, color);
        document.getElementById('noteContent').focus();
    }
}

function insertLink() {
    const url = prompt('Wprowadź adres URL:');
    if (url) {
        document.execCommand('createLink', false, url);
        document.getElementById('noteContent').focus();
    }
}

// Character count
document.getElementById('noteContent').addEventListener('input', updateCharCount);

function updateCharCount() {
    const content = document.getElementById('noteContent').innerText;
    document.getElementById('charCount').textContent = `${content.length} znaków`;
}

// Auto-save
let autoSaveTimeout;
document.getElementById('noteContent').addEventListener('input', () => {
    clearTimeout(autoSaveTimeout);
    autoSaveTimeout = setTimeout(() => {
        if (currentNote) {
            saveNote();
        }
    }, 2000);
});

document.getElementById('noteTitle').addEventListener('input', () => {
    clearTimeout(autoSaveTimeout);
    autoSaveTimeout = setTimeout(() => {
        if (currentNote) {
            saveNote();
        }
    }, 2000);
});

// Logout
document.getElementById('logoutBtn').addEventListener('click', () => {
    if (confirm('Czy na pewno chcesz się wylogować?')) {
        google.accounts.id.disableAutoSelect();
        currentUser = null;
        currentNote = null;
        notes = [];
        videos = [];
        folders = [];
        isAuthenticated = false;
        sessionStorage.clear();
        
        // Reload page to reset state and show 404
        window.location.reload();
    }
});

// Helper functions
function showScreen(screenId, addToHistory = true) {
    // Add current screen to history if not already there
    const currentScreen = document.querySelector('.screen.active');
    if (addToHistory && currentScreen && currentScreen.id !== screenId) {
        navigationHistory.push(currentScreen.id);
    }
    
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

function showLoading(show) {
    const overlay = document.getElementById('loadingOverlay');
    if (show) {
        overlay.classList.add('show');
    } else {
        overlay.classList.remove('show');
    }
}

function showError(message, elementId = null) {
    if (elementId) {
        const errorElement = document.getElementById(elementId);
        errorElement.textContent = message;
        errorElement.classList.add('show');
        
        setTimeout(() => {
            errorElement.classList.remove('show');
        }, 5000);
    } else {
        alert(message);
    }
}

function showLockout() {
    showScreen('passwordScreen');
    document.getElementById('passwordForm').style.display = 'none';
    document.getElementById('lockoutMessage').style.display = 'block';
    
    updateLockoutTimer();
    setInterval(updateLockoutTimer, 1000);
}

function updateLockoutTimer() {
    if (!lockoutEndTime) return;
    
    const now = new Date();
    const timeLeft = lockoutEndTime - now;
    
    if (timeLeft <= 0) {
        document.getElementById('passwordForm').style.display = 'block';
        document.getElementById('lockoutMessage').style.display = 'none';
        lockoutEndTime = null;
        failedPasswordAttempts = 0;
    } else {
        const hours = Math.floor(timeLeft / (1000 * 60 * 60));
        const minutes = Math.floor((timeLeft % (1000 * 60 * 60)) / (1000 * 60));
        const seconds = Math.floor((timeLeft % (1000 * 60)) / 1000);
        
        document.getElementById('lockoutTime').textContent = 
            `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }
}

function closePinModal() {
    document.getElementById('pinModal').classList.remove('show');
    document.getElementById('accessCode').value = '';
    document.getElementById('accessError').classList.remove('show');
}

function stripHtml(html) {
    const tmp = document.createElement('div');
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || '';
}

function updateLastSaved(timestamp) {
    if (timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;
        
        let text;
        if (diff < 60000) {
            text = 'Zapisano przed chwilą';
        } else if (diff < 3600000) {
            const minutes = Math.floor(diff / 60000);
            text = `Zapisano ${minutes} min temu`;
        } else {
            text = `Zapisano ${date.toLocaleString('pl-PL')}`;
        }
        
        document.getElementById('lastSaved').textContent = text;
    }
}

// Simple password hashing
async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

async function verifyPassword(password, hash) {
    const passwordHash = await hashPassword(password);
    return passwordHash === hash;
}

// Check if returning user
window.addEventListener('load', async () => {
    consoleLog('Strona 0 - Inicjalizacja...');
    
    // Check for OAuth redirect first
    handleOAuthRedirect();
    
    // Check if user was previously authenticated
    const authUser = sessionStorage.getItem('authUser');
    if (authUser) {
        currentUser = JSON.parse(authUser);
        isAuthenticated = false; // Still require password verification
    }
    
    // If app is visible (after Ctrl+Shift+Z), initialize Google
    if (document.getElementById('appContainer').style.display !== 'none') {
        if (typeof google !== 'undefined' && google.accounts) {
            initializeGoogleSignIn();
        }
    }
    
    // Test Firebase Storage configuration
    try {
        const testRef = storage.ref('test.txt');
        consoleLog('Firebase Storage configured correctly');
    } catch (error) {
        consoleError('Firebase Storage configuration error:', error);
    }
    
    consoleLog('Strona 0 - Gotowa!');
});

// Prevent accidental navigation
window.addEventListener('beforeunload', (e) => {
    if (currentNote) {
        const title = document.getElementById('noteTitle').value;
        const content = document.getElementById('noteContent').innerHTML;
        
        if (title !== currentNote.title || content !== currentNote.content) {
            e.preventDefault();
            e.returnValue = '';
        }
    }
});

// Add favicon to prevent 404 error
const favicon = document.createElement('link');
favicon.rel = 'icon';
favicon.type = 'image/x-icon';
favicon.href = 'data:image/x-icon;base64,AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJlqiACZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJlqiACZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaoAAAAAAAAAAAAAAAAAAAAAAAmWqiAJlqov+Zaov/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/5lqi/+ZaqL/mWqiAAAAAAAAAAAAJlqiACZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqIAAAAAACZaogAmWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/JlqiAAAAAACZaov/mWqL/5lqi/+Zaov/mWqL/5lqi/+Zaov/mWqL/5lqi/+Zaov/mWqL/5lqi/+Zaov/mWqL/5lqi/8AAAAAJlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/AAAAACZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/wAAAAAmWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8AAAAAJlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/AAAAACZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/wAAAACZaov/mWqL/5lqi/+Zaov/mWqL/5lqi/+Zaov/mWqL/5lqi/+Zaov/mWqL/5lqi/+Zaov/mWqL/5lqi/8AAAAAJlqiACZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqIAAAAAACZaogAmWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/JlqiAAAAAAAAAAAAmWqiAJlqov+Zaov/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/Jlqi/5lqi/+ZaqL/mWqiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJlqogAmWqL/Jlqi/yZaov8mWqL/Jlqi/yZaov8mWqL/mWqiAAAAAAAAAAAAAAAAAPgfAADwDwAA4AcAAMADAADAAwAAgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIABAADAAwAAwAMAAOAHAADwDwAA';
document.head.appendChild(favicon);

// Log successful initialization
consoleLog('Strona 0 - Initialized successfully');
consoleLog('Firebase Project:', firebaseConfig.projectId);
consoleLog('Google Client ID:', GOOGLE_CLIENT_ID.substring(0, 20) + '...');
consoleLog('Naciśnij Ctrl+Shift+Z aby wejść do aplikacji');

// Disable text selection in certain areas
document.addEventListener('selectstart', function(e) {
    if (e.target.closest('.sidebar, .modal-header, .browser-header, .editor-toolbar')) {
        e.preventDefault();
    }
});

// Additional security - disable print
window.addEventListener('beforeprint', function(e) {
    e.preventDefault();
    e.stopPropagation();
    return false;
});

// Make removeFromQueue globally available
window.removeFromQueue = removeFromQueue;
