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
const auth = firebase.auth();
const db = firebase.firestore();

// Global variables
let currentUser = null;
let currentNote = null;
let notes = [];
let autoSaveTimeout;

// Show/Hide loading
function showLoading(show) {
    const loading = document.getElementById('loadingScreen');
    loading.style.display = show ? 'flex' : 'none';
}

// Show screen
function showScreen(screenId) {
    document.querySelectorAll('.screen').forEach(screen => {
        screen.classList.remove('active');
    });
    document.getElementById(screenId).classList.add('active');
}

// Show error
function showError(message, elementId) {
    const errorElement = document.getElementById(elementId);
    errorElement.textContent = message;
    errorElement.style.display = 'block';
    setTimeout(() => {
        errorElement.style.display = 'none';
    }, 5000);
}

// Toggle password visibility
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const icon = input.nextElementSibling.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Handle Login
async function handleLogin(event) {
    event.preventDefault();
    showLoading(true);
    
    const email = document.getElementById('emailInput').value;
    const password = document.getElementById('passwordLoginInput').value;
    
    try {
        const userCredential = await auth.signInWithEmailAndPassword(email, password);
        currentUser = userCredential.user;
        
        // Check if user has completed setup
        const userDoc = await db.collection('users').doc(currentUser.uid).get();
        
        if (!userDoc.exists) {
            // New user - start security setup
            showScreen('passwordScreen');
        } else {
            const userData = userDoc.data();
            if (!userData.securityPassword) {
                showScreen('passwordScreen');
            } else if (!userData.pin) {
                showScreen('pinScreen');
            } else if (!userData.securityQuestion) {
                showScreen('securityRuleScreen');
            } else {
                // User has completed setup
                await loadUserData();
                showScreen('mainApp');
            }
        }
    } catch (error) {
        console.error('Login error:', error);
        let errorMessage = 'Błąd logowania';
        
        switch (error.code) {
            case 'auth/user-not-found':
                errorMessage = 'Nie znaleziono użytkownika';
                break;
            case 'auth/wrong-password':
                errorMessage = 'Nieprawidłowe hasło';
                break;
            case 'auth/invalid-email':
                errorMessage = 'Nieprawidłowy adres email';
                break;
            case 'auth/too-many-requests':
                errorMessage = 'Zbyt wiele prób. Spróbuj później';
                break;
        }
        
        showError(errorMessage, 'loginError');
    } finally {
        showLoading(false);
    }
}

// Handle Register
async function handleRegister(event) {
    event.preventDefault();
    showLoading(true);
    
    const email = document.getElementById('registerEmailInput').value;
    const password = document.getElementById('registerPasswordInput').value;
    const confirmPassword = document.getElementById('registerPasswordConfirmInput').value;
    
    if (password !== confirmPassword) {
        showError('Hasła nie są identyczne', 'registerError');
        showLoading(false);
        return;
    }
    
    try {
        const userCredential = await auth.createUserWithEmailAndPassword(email, password);
        currentUser = userCredential.user;
        
        // Create user document in Firestore
        await db.collection('users').doc(currentUser.uid).set({
            email: email,
            createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            setupCompleted: false
        });
        
        // Start security setup
        showScreen('passwordScreen');
    } catch (error) {
        console.error('Register error:', error);
        let errorMessage = 'Błąd rejestracji';
        
        switch (error.code) {
            case 'auth/email-already-in-use':
                errorMessage = 'Ten adres email jest już używany';
                break;
            case 'auth/invalid-email':
                errorMessage = 'Nieprawidłowy adres email';
                break;
            case 'auth/weak-password':
                errorMessage = 'Hasło jest za słabe (min. 6 znaków)';
                break;
        }
        
        showError(errorMessage, 'registerError');
    } finally {
        showLoading(false);
    }
}

// Handle Reset Password
async function handleResetPassword(event) {
    event.preventDefault();
    showLoading(true);
    
    const email = document.getElementById('resetEmailInput').value;
    
    try {
        await auth.sendPasswordResetEmail(email);
        document.getElementById('resetSuccess').textContent = 'Link resetujący został wysłany na podany adres email';
        document.getElementById('resetSuccess').style.display = 'block';
        
        setTimeout(() => {
            showScreen('loginScreen');
        }, 3000);
    } catch (error) {
        console.error('Reset password error:', error);
        let errorMessage = 'Błąd resetowania hasła';
        
        switch (error.code) {
            case 'auth/user-not-found':
                errorMessage = 'Nie znaleziono użytkownika z tym adresem email';
                break;
            case 'auth/invalid-email':
                errorMessage = 'Nieprawidłowy adres email';
                break;
        }
        
        showError(errorMessage, 'resetError');
    } finally {
        showLoading(false);
    }
}

// Handle Password Setup
async function handlePasswordSubmit(event) {
    event.preventDefault();
    showLoading(true);
    
    const password = document.getElementById('passwordInput').value;
    const confirmPassword = document.getElementById('passwordConfirmInput').value;
    
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
    
    try {
        // Hash password
        const hashedPassword = await hashPassword(password);
        
        // Save to Firestore
        await db.collection('users').doc(currentUser.uid).update({
            securityPassword: hashedPassword
        });
        
        // Move to PIN setup
        showScreen('pinScreen');
    } catch (error) {
        console.error('Password setup error:', error);
        showError('Błąd zapisu hasła', 'passwordError');
    } finally {
        showLoading(false);
    }
}

// Password strength indicator
document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('passwordInput');
    if (passwordInput) {
        passwordInput.addEventListener('input', (e) => {
            const password = e.target.value;
            const strengthFill = document.querySelector('.strength-fill');
            const strengthValue = document.getElementById('strengthValue');
            
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
            strengthFill.className = 'strength-fill';
            
            if (strength <= 2) {
                strengthFill.style.width = '33%';
                strengthFill.style.backgroundColor = '#ef4444';
                strengthValue.textContent = 'Słabe';
            } else if (strength <= 4) {
                strengthFill.style.width = '66%';
                strengthFill.style.backgroundColor = '#f59e0b';
                strengthValue.textContent = 'Średnie';
            } else {
                strengthFill.style.width = '100%';
                strengthFill.style.backgroundColor = '#10b981';
                strengthValue.textContent = 'Silne';
            }
        });
    }
});

// PIN input handling
document.addEventListener('DOMContentLoaded', () => {
    const pinInputs = document.querySelectorAll('.pin-digit');
    pinInputs.forEach((input, index) => {
        input.addEventListener('input', (e) => {
            if (e.target.value.length === 1 && index < pinInputs.length - 1) {
                pinInputs[index + 1].focus();
            }
        });
        
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Backspace' && !e.target.value && index > 0) {
                pinInputs[index - 1].focus();
            }
        });
    });
});

// Handle PIN Setup
async function handlePinSubmit(event) {
    event.preventDefault();
    showLoading(true);
    
    const pinInputs = document.querySelectorAll('.pin-digit');
    const pin = Array.from(pinInputs).map(input => input.value).join('');
    
    if (pin.length !== 4) {
        showError('PIN musi składać się z 4 cyfr', 'pinError');
        showLoading(false);
        return;
    }
    
    try {
        // Hash PIN
        const hashedPin = await hashPassword(pin);
        
        // Save to Firestore
        await db.collection('users').doc(currentUser.uid).update({
            pin: hashedPin
        });
        
        // Move to security rule setup
        showScreen('securityRuleScreen');
    } catch (error) {
        console.error('PIN setup error:', error);
        showError('Błąd zapisu PIN', 'pinError');
    } finally {
        showLoading(false);
    }
}

// Handle Security Rule Setup
async function handleSecurityRuleSubmit(event) {
    event.preventDefault();
    showLoading(true);
    
    const question = document.getElementById('securityQuestion').value;
    const answer = document.getElementById('securityAnswer').value.toLowerCase().trim();
    
    if (!question || !answer) {
        showError('Wybierz pytanie i podaj odpowiedź', 'securityRuleError');
        showLoading(false);
        return;
    }
    
    try {
        // Hash answer
        const hashedAnswer = await hashPassword(answer);
        
        // Save to Firestore
        await db.collection('users').doc(currentUser.uid).update({
            securityQuestion: question,
            securityAnswer: hashedAnswer,
            setupCompleted: true
        });
        
        // Load user data and go to main app
        await loadUserData();
        showScreen('mainApp');
    } catch (error) {
        console.error('Security rule setup error:', error);
        showError('Błąd zapisu reguły bezpieczeństwa', 'securityRuleError');
    } finally {
        showLoading(false);
    }
}

// Load user data
async function loadUserData() {
    if (!currentUser) return;
    
    // Update user email in UI
    document.getElementById('userEmail').textContent = currentUser.email;
    
    // Load notes
    await loadNotes();
}

// Show section
function showSection(section) {
    document.querySelectorAll('.section').forEach(s => {
        s.classList.remove('active');
    });
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    if (section === 'home') {
        document.getElementById('homeSection').classList.add('active');
        document.querySelector('[onclick="showSection(\'home\')"]').classList.add('active');
    } else if (section === 'notepad') {
        document.getElementById('notepadSection').classList.add('active');
        document.querySelector('[onclick="showSection(\'notepad\')"]').classList.add('active');
        if (notes.length === 0) {
            loadNotes();
        }
    }
}

// Notepad functions
async function loadNotes() {
    if (!currentUser) return;
    
    try {
        const snapshot = await db.collection('users').doc(currentUser.uid)
            .collection('notes')
            .orderBy('updatedAt', 'desc')
            .get();
        
        notes = [];
        snapshot.forEach(doc => {
            notes.push({ id: doc.id, ...doc.data() });
        });
        
        renderNotesList();
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
        filteredNotes = notes.filter(note => new Date(note.updatedAt.toDate()) > lastWeek);
    }
    
    if (filteredNotes.length === 0) {
        notesList.innerHTML = '<div class="empty-notes">Brak notatek</div>';
        return;
    }
    
    filteredNotes.forEach(note => {
        const noteItem = document.createElement('div');
        noteItem.className = 'note-item';
        if (currentNote && currentNote.id === note.id) {
            noteItem.classList.add('active');
        }
        
        const date = note.updatedAt ? new Date(note.updatedAt.toDate()).toLocaleDateString('pl-PL') : '';
        
        noteItem.innerHTML = `
            <div class="note-title">${note.starred ? '<i class="fas fa-star"></i> ' : ''}${note.title || 'Bez tytułu'}</div>
            <div class="note-preview">${stripHtml(note.content || '').substring(0, 50)}...</div>
            <div class="note-date">${date}</div>
        `;
        
        noteItem.onclick = () => selectNote(note);
        notesList.appendChild(noteItem);
    });
}

function selectNote(note) {
    currentNote = note;
    
    // Show editor
    document.getElementById('editorPlaceholder').style.display = 'none';
    document.getElementById('editorContainer').style.display = 'block';
    
    // Update content
    document.getElementById('noteTitle').value = note.title || '';
    document.getElementById('noteContent').innerHTML = note.content || '';
    
    // Update star
    const starIcon = document.getElementById('starIcon');
    starIcon.className = note.starred ? 'fas fa-star' : 'far fa-star';
    
    // Update date
    if (note.updatedAt) {
        const date = new Date(note.updatedAt.toDate());
        document.getElementById('noteDate').textContent = `Ostatnia modyfikacja: ${date.toLocaleString('pl-PL')}`;
    }
    
    // Update list
    renderNotesList();
}

async function createNewNote() {
    try {
        const noteData = {
            title: '',
            content: '',
            starred: false,
            createdAt: firebase.firestore.FieldValue.serverTimestamp(),
            updatedAt: firebase.firestore.FieldValue.serverTimestamp()
        };
        
        const docRef = await db.collection('users').doc(currentUser.uid)
            .collection('notes').add(noteData);
        
        const newNote = { id: docRef.id, ...noteData, updatedAt: { toDate: () => new Date() } };
        notes.unshift(newNote);
        
        selectNote(newNote);
        document.getElementById('noteTitle').focus();
    } catch (error) {
        console.error('Error creating note:', error);
    }
}

async function saveNote() {
    if (!currentNote) return;
    
    const title = document.getElementById('noteTitle').value;
    const content = document.getElementById('noteContent').innerHTML;
    
    try {
        await db.collection('users').doc(currentUser.uid)
            .collection('notes').doc(currentNote.id).update({
                title: title,
                content: content,
                updatedAt: firebase.firestore.FieldValue.serverTimestamp()
            });
        
        // Update local data
        currentNote.title = title;
        currentNote.content = content;
        
        // Show save status
        const saveStatus = document.getElementById('saveStatus');
        saveStatus.style.display = 'block';
        setTimeout(() => {
            saveStatus.style.display = 'none';
        }, 2000);
        
        renderNotesList();
    } catch (error) {
        console.error('Error saving note:', error);
    }
}

async function deleteNote() {
    if (!currentNote) return;
    
    if (!confirm('Czy na pewno chcesz usunąć tę notatkę?')) return;
    
    try {
        await db.collection('users').doc(currentUser.uid)
            .collection('notes').doc(currentNote.id).delete();
        
        notes = notes.filter(note => note.id !== currentNote.id);
        currentNote = null;
        
        document.getElementById('editorPlaceholder').style.display = 'block';
        document.getElementById('editorContainer').style.display = 'none';
        
        renderNotesList();
    } catch (error) {
        console.error('Error deleting note:', error);
    }
}

async function toggleStar() {
    if (!currentNote) return;
    
    currentNote.starred = !currentNote.starred;
    
    try {
        await db.collection('users').doc(currentUser.uid)
            .collection('notes').doc(currentNote.id).update({
                starred: currentNote.starred
            });
        
        const starIcon = document.getElementById('starIcon');
        starIcon.className = currentNote.starred ? 'fas fa-star' : 'far fa-star';
        
        renderNotesList();
    } catch (error) {
        console.error('Error updating star:', error);
    }
}

// Auto-save
document.addEventListener('DOMContentLoaded', () => {
    const noteTitle = document.getElementById('noteTitle');
    const noteContent = document.getElementById('noteContent');
    
    if (noteTitle) {
        noteTitle.addEventListener('input', () => {
            clearTimeout(autoSaveTimeout);
            autoSaveTimeout = setTimeout(saveNote, 2000);
        });
    }
    
    if (noteContent) {
        noteContent.addEventListener('input', () => {
            clearTimeout(autoSaveTimeout);
            autoSaveTimeout = setTimeout(saveNote, 2000);
        });
    }
});

// Search notes
function searchNotes() {
    const query = document.getElementById('searchNotes').value.toLowerCase();
    
    if (!query) {
        renderNotesList();
        return;
    }
    
    const filtered = notes.filter(note => {
        const title = (note.title || '').toLowerCase();
        const content = stripHtml(note.content || '').toLowerCase();
        return title.includes(query) || content.includes(query);
    });
    
    const notesList = document.getElementById('notesList');
    notesList.innerHTML = '';
    
    if (filtered.length === 0) {
        notesList.innerHTML = '<div class="empty-notes">Nie znaleziono notatek</div>';
        return;
    }
    
    filtered.forEach(note => {
        const noteItem = document.createElement('div');
        noteItem.className = 'note-item';
        if (currentNote && currentNote.id === note.id) {
            noteItem.classList.add('active');
        }
        
        const date = note.updatedAt ? new Date(note.updatedAt.toDate()).toLocaleDateString('pl-PL') : '';
        
        noteItem.innerHTML = `
            <div class="note-title">${note.starred ? '<i class="fas fa-star"></i> ' : ''}${note.title || 'Bez tytułu'}</div>
            <div class="note-preview">${stripHtml(note.content || '').substring(0, 50)}...</div>
            <div class="note-date">${date}</div>
        `;
        
        noteItem.onclick = () => selectNote(note);
        notesList.appendChild(noteItem);
    });
}

// Filter notes
function filterNotes(filter) {
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    event.target.classList.add('active');
    renderNotesList(filter);
}

// Editor functions
function formatText(command) {
    document.execCommand(command, false, null);
    document.getElementById('noteContent').focus();
}

function insertLink() {
    const url = prompt('Wprowadź adres URL:');
    if (url) {
        document.execCommand('createLink', false, url);
        document.getElementById('noteContent').focus();
    }
}

function changeTextColor() {
    const color = document.getElementById('colorPicker').value;
    document.execCommand('foreColor', false, color);
    document.getElementById('noteContent').focus();
}

// Logout
function logout() {
    if (confirm('Czy na pewno chcesz się wylogować?')) {
        auth.signOut().then(() => {
            currentUser = null;
            notes = [];
            currentNote = null;
            showScreen('loginScreen');
            
            // Clear form inputs
            document.querySelectorAll('input').forEach(input => {
                if (input.type !== 'button' && input.type !== 'submit') {
                    input.value = '';
                }
            });
        });
    }
}

// Helper functions
function stripHtml(html) {
    const tmp = document.createElement('div');
    tmp.innerHTML = html;
    return tmp.textContent || tmp.innerText || '';
}

async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Auth state observer
auth.onAuthStateChanged((user) => {
    if (user) {
        currentUser = user;
        console.log('User logged in:', user.email);
    } else {
        currentUser = null;
        showScreen('loginScreen');
    }
});

// Initialize app
window.addEventListener('load', () => {
    showLoading(false);
    console.log('Strona 0 - Ready');
});

// Make functions globally available
window.handleLogin = handleLogin;
window.handleRegister = handleRegister;
window.handleResetPassword = handleResetPassword;
window.handlePasswordSubmit = handlePasswordSubmit;
window.handlePinSubmit = handlePinSubmit;
window.handleSecurityRuleSubmit = handleSecurityRuleSubmit;
window.togglePasswordVisibility = togglePasswordVisibility;
window.showScreen = showScreen;
window.showSection = showSection;
window.createNewNote = createNewNote;
window.deleteNote = deleteNote;
window.toggleStar = toggleStar;
window.formatText = formatText;
window.insertLink = insertLink;
window.changeTextColor = changeTextColor;
window.searchNotes = searchNotes;
window.filterNotes = filterNotes;
window.logout = logout;
