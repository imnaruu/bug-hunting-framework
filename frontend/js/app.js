// Bug Hunter Framework - Main JavaScript

// Mobile menu toggle
function toggleSidebar() {
    const sidebar = document.querySelector('.sidebar');
    sidebar.classList.toggle('open');
}

// Set active navigation link
function setActiveNav() {
    const currentPage = window.location.pathname.split('/').pop() || 'index.html';
    const navLinks = document.querySelectorAll('.nav-link');
    
    navLinks.forEach(link => {
        const href = link.getAttribute('href');
        if (href === currentPage || (currentPage === '' && href === 'index.html')) {
            link.classList.add('active');
        } else {
            link.classList.remove('active');
        }
    });
}

// Tab functionality
function initTabs() {
    const tabs = document.querySelectorAll('.tab');
    
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            
            // Remove active class from all tabs and content
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            // Add active class to clicked tab and corresponding content
            tab.classList.add('active');
            document.getElementById(target).classList.add('active');
        });
    });
}

// Terminal typing effect
function typeInTerminal(element, text, speed = 50) {
    let i = 0;
    const interval = setInterval(() => {
        if (i < text.length) {
            element.textContent += text.charAt(i);
            i++;
        } else {
            clearInterval(interval);
        }
    }, speed);
}

// Animate numbers
function animateNumber(element, target, duration = 1000) {
    const start = 0;
    const increment = target / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            element.textContent = target;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 16);
}

// Format timestamp
function formatTimestamp(date) {
    const now = new Date();
    const diff = now - date;
    const seconds = Math.floor(diff / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ago`;
    if (hours > 0) return `${hours}h ago`;
    if (minutes > 0) return `${minutes}m ago`;
    return `${seconds}s ago`;
}

// Add terminal line
function addTerminalLine(terminalId, text, type = 'info') {
    const terminal = document.getElementById(terminalId);
    if (!terminal) return;
    
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.textContent = text;
    
    if (type === 'error') {
        line.style.color = '#ff3366';
    } else if (type === 'success') {
        line.style.color = '#00ff88';
    } else if (type === 'warning') {
        line.style.color = '#ffc107';
    }
    
    terminal.appendChild(line);
    terminal.scrollTop = terminal.scrollHeight;
}

// Clear terminal
function clearTerminal(terminalId) {
    const terminal = document.getElementById(terminalId);
    if (terminal) {
        terminal.innerHTML = '';
    }
}

// Show notification
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type}`;
    notification.innerHTML = `
        <span class="alert-icon">⚠</span>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Update status indicator
function updateStatus(isOnline) {
    const statusText = document.querySelector('.status-indicator span:last-child');
    const statusDot = document.querySelector('.status-dot');
    
    if (statusText && statusDot) {
        if (isOnline) {
            statusText.textContent = 'System Online';
            statusDot.style.background = '#00ff88';
        } else {
            statusText.textContent = 'System Offline';
            statusDot.style.background = '#ff3366';
        }
    }
}

// Simulate API call
async function mockApiCall(endpoint, delay = 1000) {
    return new Promise((resolve) => {
        setTimeout(() => {
            resolve({
                success: true,
                data: { message: `Response from ${endpoint}` }
            });
        }, delay);
    });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    setActiveNav();
    initTabs();
    
    // Update status
    updateStatus(true);
    
    // Add event listener for mobile menu
    const menuBtn = document.getElementById('menuBtn');
    if (menuBtn) {
        menuBtn.addEventListener('click', toggleSidebar);
    }
});

// Export functions for use in other scripts
window.BugHunter = {
    toggleSidebar,
    setActiveNav,
    initTabs,
    typeInTerminal,
    animateNumber,
    formatTimestamp,
    addTerminalLine,
    clearTerminal,
    showNotification,
    updateStatus,
    mockApiCall
};
