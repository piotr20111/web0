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

// Initialize app function
window.initializeApp = function() {
    console.log('Strona 0 - Initializing application...');
    if (!googleInitialized && typeof google !== 'undefined' && google.accounts) {
        initializeGoogleSignIn();
    }
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
        console.log('Google Sign-In initialized successfully');
        
    } catch (error) {
        console.error('Error initializing Google Sign-In:', error);
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
    console.log('Using OAuth redirect method...');
    
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
            console.log('Received token from OAuth redirect');
            
            sessionStorage.removeItem('oauth_state');
            sessionStorage.removeItem('oauth_nonce');
            
            // Show the app if coming from OAuth
            document.getElementById('errorScreen').style.display = 'none';
            document.getElementById('appContainer').style.display = 'block';
            
            handleGoogleSignIn({ credential: idToken });
            
            window.history.replaceState({}, document.title, window.location.pathname);
        }
    } catch (error) {
        console.error('Error handling OAuth redirect:', error);
    }
}

// Handle Google Sign-In response
async function handleGoogleSignIn(response) {
    console.log('Processing login response...');
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
        
        console.log('Logged in as:', currentUser.name);
        console.log('User ID:', currentUser.id);
        
        // Store authentication state
        sessionStorage.setItem('authUser', JSON.stringify(currentUser));
        
        // Test Firestore connection
        try {
            const userRef = db.collection('users').doc(currentUser.id);
            const userDoc = await userRef.get();
            
            if (!userDoc.exists) {
                console.log('Creating new user...');
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
                console.log('User exists, checking data...');
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
            console.error('Firestore error:', firestoreError);
            
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
        console.error('Login error:', error);
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
        console.error('Error parsing token:', error);
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
        console.error('Password error:', error);
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
        console.error('PIN error:', error);
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
            
        } else {
            // Verify existing rule
            const userDoc = await db.collection('users').doc(currentUser.id).get();
            const userData = userDoc.data();
            
            const isValid = await verifyPassword(rule, userData.rule);
            
            if (isValid) {
                isAuthenticated = true;
                showScreen('mainPanel');
                loadNotes();
            } else {
                showError('Nieprawidłowa reguła', 'ruleError');
                
                // Clear inputs
                ruleDigit.value = '';
                ruleLetter.value = '';
                ruleDigit.focus();
            }
        }
        
    } catch (error) {
        console.error('Rule error:', error);
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
        } else if (section === 'notepad') {
            // Notepad requires PIN modal
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
            }
        } else {
            showError('Nieprawidłowy kod dostępu', 'accessError');
        }
        
    } catch (error) {
        console.error('Access error:', error);
        showError('Wystąpił błąd. Spróbuj ponownie.', 'accessError');
    } finally {
        showLoading(false);
    }
});

// Notepad functions
function showNotepad() {
    document.getElementById('homeContent').style.display = 'none';
    document.getElementById('notepadSection').style.display = 'block';
    document.getElementById('contentNav').style.display = 'block';
    
    // Mark nav item as active
    document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
    document.querySelector('[data-section="notepad"]').classList.add('active');
}

async function loadNotes() {
    try {
        const notesSnapshot = await db.collection('users').doc(currentUser.id)
            .collection('notes').get();
        
        notes = [];
        notesSnapshot.forEach(doc => {
            notes.push({ id: doc.id, ...doc.data() });
        });
        
        // Sort by updated date
        notes.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
        
        renderNotesList();
        
        if (notes.length > 0) {
            selectNote(notes[0]);
        }
        
    } catch (error) {
        console.error('Error loading notes:', error);
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
        console.error('Error creating note:', error);
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
        console.error('Error saving note:', error);
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
        console.error('Error deleting note:', error);
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
        console.error('Error updating star:', error);
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
    console.log('Strona 0 - Inicjalizacja...');
    
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
    
    // Test Firebase connections
    try {
        // Test Firestore
        const testDoc = await db.collection('test').doc('test').get();
        console.log('Firestore connection: OK');
    } catch (error) {
        if (error.code === 'permission-denied') {
            console.log('Firestore: Permission denied (expected for test collection)');
        } else {
            console.error('Firestore error:', error);
        }
    }
    
    console.log('Strona 0 - Gotowa!');
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
console.log('Strona 0 - Initialized successfully');
console.log('Firebase Project:', firebaseConfig.projectId);
console.log('Google Client ID:', GOOGLE_CLIENT_ID.substring(0, 20) + '...');

// Disable text selection in certain areas
document.addEventListener('selectstart', function(e) {
    if (e.target.closest('.sidebar, .modal-header, .editor-toolbar')) {
        e.preventDefault();
    }
});

// Make functions globally available
window.goBack = goBack;
window.backToHome = backToHome;
window.createNewNote = createNewNote;
window.saveNote = saveNote;
window.deleteNote = deleteNote;
window.toggleStar = toggleStar;
window.formatText = formatText;
window.insertList = insertList;
window.changeColor = changeColor;
window.insertLink = insertLink;
window.closePinModal = closePinModal;
window.useOAuthRedirect = useOAuthRedirect;

// Final initialization message
console.log('Strona 0 - All functions loaded');
console.log('Press Ctrl+Shift+Z to enter the application');
console.log('Triple-click on 404 text as alternative');
