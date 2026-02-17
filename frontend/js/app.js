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

// Show helpful message when backend is offline
function showBackendOfflineMessage() {
    const message = `
        <div style="max-width: 600px;">
            <strong>Backend Server Not Running</strong><br><br>
            The backend server is not running. Please start it using:<br><br>
            <code style="background: #0a0e1a; padding: 10px; display: block; margin: 10px 0; border-radius: 4px;">
                ./start.sh
            </code>
            Or manually:<br>
            <code style="background: #0a0e1a; padding: 10px; display: block; margin: 10px 0; border-radius: 4px;">
                python3 -m backend.main
            </code>
            <br>
            Then refresh this page.
        </div>
    `;
    showNotification(message, 'error');
}


// ============================================
// API Integration Functions
// ============================================

const API_BASE_URL = window.location.origin + '/api';

// Generic API call wrapper
async function apiCall(endpoint, method = 'GET', data = null) {
    const options = {
        method,
        headers: {
            'Content-Type': 'application/json',
        }
    };
    
    if (data && (method === 'POST' || method === 'PUT')) {
        options.body = JSON.stringify(data);
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}${endpoint}`, options);
        const responseData = await response.json();
        
        if (!response.ok) {
            throw new Error(responseData.detail || 'API request failed');
        }
        
        return responseData;
    } catch (error) {
        console.error(`API Error: ${endpoint}`, error);
        throw error;
    }
}

// Health check
async function checkHealth() {
    try {
        const data = await apiCall('/health');
        updateStatus(true);
        return data;
    } catch (error) {
        updateStatus(false);
        throw error;
    }
}

// Recon API calls
async function detectTechnologies(targetId, url) {
    return await apiCall('/recon/detect', 'POST', {
        target_id: targetId,
        url: url
    });
}

async function getReconResults(targetId) {
    return await apiCall(`/recon/results/${targetId}`);
}

async function verifyScope(url) {
    return await apiCall('/recon/scope/verify', 'POST', {
        url: url
    });
}

async function getScopedTargets() {
    return await apiCall('/recon/scope/targets');
}

async function mapVersionRisks(technologies) {
    return await apiCall('/recon/version-risk', 'POST', {
        technologies: technologies
    });
}

// Baseline API calls
async function captureBaseline(targetId, url, sampleSize = 10) {
    return await apiCall('/baseline/capture', 'POST', {
        target_id: targetId,
        url: url,
        sample_size: sampleSize
    });
}

async function getBaseline(targetId) {
    return await apiCall(`/baseline/${targetId}`);
}

async function analyzeHeaders(url, headers) {
    return await apiCall('/baseline/analyze-headers', 'POST', {
        url: url,
        headers: headers
    });
}

// Testing API calls
async function testXSS(targetId, url, parameter, context = 'html') {
    return await apiCall('/testing/xss', 'POST', {
        target_id: targetId,
        url: url,
        parameter: parameter,
        context: context
    });
}

async function testSQLi(targetId, url, parameter) {
    return await apiCall('/testing/sqli', 'POST', {
        target_id: targetId,
        url: url,
        parameter: parameter
    });
}

async function testSSRF(targetId, url, parameter) {
    return await apiCall('/testing/ssrf', 'POST', {
        target_id: targetId,
        url: url,
        parameter: parameter
    });
}

async function testSSTI(targetId, url, parameter, templateEngine = null) {
    return await apiCall('/testing/ssti', 'POST', {
        target_id: targetId,
        url: url,
        parameter: parameter,
        template_engine: templateEngine
    });
}

async function getFindings(targetId = null) {
    const endpoint = targetId ? `/testing/findings?target_id=${targetId}` : '/testing/findings';
    return await apiCall(endpoint);
}

// Correlation API calls
async function correlateFindings(targetId) {
    return await apiCall('/correlate', 'POST', {
        target_id: targetId
    });
}

async function getAttackChains(targetId = null) {
    const endpoint = targetId ? `/correlate/chains?target_id=${targetId}` : '/correlate/chains';
    return await apiCall(endpoint);
}

async function translateBusinessImpact(findingIds) {
    return await apiCall('/correlate/impact', 'POST', {
        finding_ids: findingIds
    });
}

// Reports API calls
async function generateReport(targetId, title, format = 'markdown') {
    return await apiCall('/reports/generate', 'POST', {
        target_id: targetId,
        title: title,
        format: format
    });
}

async function getReports() {
    return await apiCall('/reports');
}

async function getReport(reportId) {
    return await apiCall(`/reports/${reportId}`);
}

async function logRetest(reportId, findingId, status, notes) {
    return await apiCall('/reports/retest', 'POST', {
        report_id: reportId,
        finding_id: findingId,
        status: status,
        notes: notes
    });
}

async function getConfidenceScore(findingId) {
    return await apiCall(`/reports/confidence/${findingId}`);
}

// ============================================
// Production Scan API Functions
// ============================================

// Start a complete production-grade scan
async function startScan(targetUrl, options = {}) {
    return await apiCall('/scan/start', 'POST', {
        target_url: targetUrl,
        endpoints: options.endpoints || null,
        parameters: options.parameters || null,
        scan_options: options.scan_options || null
    });
}

// Get real-time scan status
async function getScanStatus(scanId) {
    return await apiCall(`/scan/status/${scanId}`);
}

// Get complete scan results
async function getScanResults(scanId) {
    return await apiCall(`/scan/results/${scanId}`);
}

// List all scans
async function listScans() {
    return await apiCall('/scan/list');
}

// Poll scan status until complete
async function pollScanStatus(scanId, onProgress, intervalMs = 2000) {
    return new Promise((resolve, reject) => {
        const checkStatus = async () => {
            try {
                const status = await getScanStatus(scanId);
                
                // Call progress callback
                if (onProgress) {
                    onProgress(status);
                }
                
                // Check if scan is complete
                if (status.status === 'completed') {
                    resolve(status);
                } else if (status.status === 'failed' || status.status === 'cancelled') {
                    reject(new Error(`Scan ${status.status}: ${status.errors.join(', ')}`));
                } else {
                    // Continue polling
                    setTimeout(checkStatus, intervalMs);
                }
            } catch (error) {
                reject(error);
            }
        };
        
        // Start polling
        checkStatus();
    });
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    setActiveNav();
    initTabs();
    
    // Check API health on load
    checkHealth().catch((error) => {
        console.error('API health check failed:', error);
        // Show helpful message after a short delay
        setTimeout(() => {
            showBackendOfflineMessage();
        }, 500);
    });
    
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
    showBackendOfflineMessage,
    // API functions
    apiCall,
    checkHealth,
    detectTechnologies,
    getReconResults,
    verifyScope,
    getScopedTargets,
    mapVersionRisks,
    captureBaseline,
    getBaseline,
    analyzeHeaders,
    testXSS,
    testSQLi,
    testSSRF,
    testSSTI,
    getFindings,
    correlateFindings,
    getAttackChains,
    translateBusinessImpact,
    generateReport,
    getReports,
    getReport,
    logRetest,
    getConfidenceScore,
    // Production scan functions
    startScan,
    getScanStatus,
    getScanResults,
    listScans,
    pollScanStatus
};
