// ============================================
// COMPLETE DEVTOOLS BLOCKER
// Works in browser and Electron
// ============================================

// 1. Disable right-click context menu
document.addEventListener('contextmenu', (e) => {
    e.preventDefault();
    return false;
});

// 2. Disable keyboard shortcuts BUT allow Ctrl+Shift+Z
document.addEventListener('keydown', (e) => {
    // IMPORTANT: Skip Ctrl+Shift+Z - let it be handled by main app
    if (e.ctrlKey && e.shiftKey && (e.key === 'Z' || e.key === 'z')) {
        return; // Don't block this combination
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
    
    // F11 - Fullscreen
    if (e.key === 'F11') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+S - Save Page
    if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        return false;
    }
    
    // Ctrl+A - Select All
    if (e.ctrlKey && e.key === 'a') {
        e.preventDefault();
        return false;
    }
}, false);

// 3. Detect DevTools by window size
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

// 4. Disable console methods
const disableConsole = () => {
    const methods = ['log', 'debug', 'info', 'warn', 'error', 'table', 'trace', 'dir'];
    
    methods.forEach(method => {
        const original = console[method];
        console[method] = function() {
            // Allow specific app logs
            if (method === 'log' && arguments[0] && 
                (arguments[0].includes('Strona 0') || 
                 arguments[0].includes('Script loaded') ||
                 arguments[0].includes('Activated'))) {
                original.apply(console, arguments);
            }
            
            // Clear console immediately
            setTimeout(console.clear, 0);
        };
    });
};

// Apply console blocking
disableConsole();

// 5. Detect DevTools using debugger
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

// 6. Disable print
window.addEventListener('beforeprint', (e) => {
    e.preventDefault();
    e.stopPropagation();
    return false;
});

// 7. Additional protection - detect console.log timing
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

// 8. Listen for devtools state changes
window.addEventListener('devtoolschange', (e) => {
    console.log('DevTools are ' + (e.detail.open ? 'open' : 'closed'));
});

// 9. Disable drag and drop
document.addEventListener('dragstart', (e) => {
    e.preventDefault();
    return false;
});

// 10. Additional Electron-specific protections
if (typeof process !== 'undefined' && process.versions && process.versions.electron) {
    // In Electron environment
    console.log('Running in Electron');
}

// 11. Self-defending code
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

// 12. Display warning in console
console.log('%c⛔ STOP!', 'color: red; font-size: 50px; font-weight: bold;');
console.log('%cTo jest przeglądarka, funkcja programisty.', 'font-size: 20px;');
console.log('%cJeśli ktoś powiedział Ci, aby coś tutaj wkleić, jest to oszustwo i da tej osobie dostęp do Twojego konta.', 'font-size: 16px;');
console.log('%cAby wejść do aplikacji: Naciśnij Ctrl+Shift+Z lub kliknij 3x na tekście 404', 'font-size: 16px; color: #6366f1;');

// 13. Disable text selection
document.addEventListener('selectstart', function(e) {
    if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA' && !e.target.isContentEditable) {
        e.preventDefault();
    }
});
