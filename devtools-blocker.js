// ============================================
// COMPLETE DEVTOOLS BLOCKER
// Works in browser and Electron
// ============================================

// 1. Disable right-click context menu
document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    return false;
});

// 3. Disable keyboard shortcuts (MODIFIED - excludes Ctrl+Shift+Z)
document.addEventListener('keydown', (e) => {
    // IMPORTANT: Allow Ctrl+Shift+Z to pass through
    if (e.ctrlKey && e.shiftKey && e.key === 'Z') {
        return; // Let this combination work
    }
    
    // F12 - Developer Tools
    if (e.key === 'F12') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+Shift+I - Developer Tools
    if (e.ctrlKey && e.shiftKey && e.key === 'I') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+Shift+J - Console
    if (e.ctrlKey && e.shiftKey && e.key === 'J') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+Shift+C - Inspect Element
    if (e.ctrlKey && e.shiftKey && e.key === 'C') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+U - View Source
    if (e.ctrlKey && e.key === 'u') {
        e.preventDefault();
        return false;
    }
    
    // F11 - Fullscreen (can be used to access DevTools)
    if (e.key === 'F11') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+S - Save Page
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+A - Select All (optional)
    if (e.ctrlKey && e.key === 'a') {
        e.preventDefault();
        return false;
    }
});

// Reszta kodu pozostaje bez zmian...
// 4. Detect DevTools by window size
let devtools = {open: false, orientation: null};
const threshold = 160;
const emitEvent = (state, orientation) => {
    if (typeof window.CustomEvent === 'function') {
        window.dispatchEvent(new CustomEvent('devtoolschange', {
            detail: {
                open: state,
                orientation: orientation
            }
        }));
    }
};

setInterval(() => {
    if (window.outerHeight - window.innerHeight > threshold || 
        window.outerWidth - window.innerWidth > threshold) {
        if (!devtools.open) {
            devtools.open = true;
            emitEvent(true, window.outerHeight - window.innerHeight > threshold ? 'vertical' : 'horizontal');
            console.clear();
            
            // Action when DevTools are detected
            document.body.innerHTML = `
                <div style="display: flex; align-items: center; justify-content: center; height: 100vh; background: #000; color: #fff; font-family: Arial;">
                    <div style="text-align: center;">
                        <h1 style="font-size: 48px; margin-bottom: 20px;">⚠️ Nieautoryzowany dostęp!</h1>
                        <p style="font-size: 24px;">Narzędzia deweloperskie są zablokowane.</p>
                        <p style="font-size: 18px; margin-top: 30px;">Strona zostanie odświeżona za 3 sekundy...</p>
                    </div>
                </div>
            `;
            
            setTimeout(() => {
                window.location.reload();
            }, 3000);
        }
    } else {
        if (devtools.open) {
            devtools.open = false;
            emitEvent(false, null);
        }
    }
}, 500);

// 5. Disable console methods
const disableConsole = () => {
    const methods = ['log', 'debug', 'info', 'warn', 'error', 'table', 'trace', 'dir'];
    
    methods.forEach(method => {
        const original = console[method];
        console[method] = function() {
            // Clear console immediately
            setTimeout(console.clear, 0);
        };
    });
};

// Apply console blocking
disableConsole();

// 6. Detect DevTools using debugger
let checkStatus;

const element = new Image();
Object.defineProperty(element, 'id', {
    get: function() {
        checkStatus = true;
        console.clear();
        document.body.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: center; height: 100vh; background: #000; color: #fff; font-family: Arial;">
                <h1>🚫 Dostęp zabroniony</h1>
            </div>
        `;
    }
});

setInterval(() => {
    checkStatus = false;
    console.log(element);
    console.clear();
}, 1000);

// 7. Disable print
window.addEventListener('beforeprint', (e) => {
    e.preventDefault();
    e.stopPropagation();
    return false;
});

// 8. Additional protection - detect console.log timing
let before = Date.now();
let after;
setInterval(() => {
    before = Date.now();
    debugger;
    after = Date.now();
    if (after - before > 100) {
        // DevTools are open (debugger paused)
        document.body.innerHTML = `
            <div style="display: flex; align-items: center; justify-content: center; height: 100vh; background: #000; color: #fff;">
                <h1>⛔ Wykryto debugger!</h1>
            </div>
        `;
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    }
}, 1000);

// 9. Listen for devtools state changes
window.addEventListener('devtoolschange', (e) => {
    console.log('DevTools are ' + (e.detail.open ? 'open' : 'closed'));
});

// 10. Disable drag and drop (prevents dragging elements to console)
document.addEventListener('dragstart', (e) => {
    e.preventDefault();
    return false;
});

// 12. Self-defending code
(function() {
    'use strict';
    
    // Prevents modification of this script
    const protection = () => {
        const script = document.currentScript;
        if (script) {
            script.remove();
        }
    };
    
    // Run protection after script loads
    setTimeout(protection, 0);
})();

console.log('%c⛔ STOP!', 'color: red; font-size: 50px; font-weight: bold;');
console.log('%cTo jest przeglądarka, funkcja programisty.', 'font-size: 20px;');
console.log('%cJeśli ktoś powiedział Ci, aby coś tutaj wkleić, jest to oszustwo i da tej osobie dostęp do Twojego konta.', 'font-size: 16px;');
console.log('%cNaciśnij Ctrl+Shift+Z aby wejść do aplikacji', 'font-size: 16px; color: #6366f1;');
