// Updated: script.js - User-specific history with proper cache clearing

// State management
let scanHistory = [];
let currentPage = 1;
const itemsPerPage = 10;
let currentInputType = 'url';
let isAnalyzing = false;

// =============================================
// HELPER FUNCTION TO GET CSRF TOKEN
// =============================================
function getCSRFToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    if (meta) {
        return meta.getAttribute('content');
    }
    
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'csrf_token') {
            return value;
        }
    }
    return null;
}

// =============================================
// CHECK IF USER IS LOGGED IN
// =============================================
function isUserLoggedIn() {
    const meta = document.querySelector('meta[name="user-logged-in"]');
    return meta ? meta.getAttribute('content') === 'true' : false;
}

// =============================================
// LOAD USER HISTORY FROM DATABASE
// =============================================
async function loadUserHistoryFromDB() {
    try {
        const response = await fetch('/api/user-history', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCSRFToken()
            }
        });
        
        const data = await response.json();
        
        if (data.success) {
            scanHistory = data.history;
            // Update localStorage cache with fresh data
            localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
        } else {
            console.error('Failed to load history:', data.error);
            // Fallback to localStorage
            scanHistory = JSON.parse(localStorage.getItem('phishguard_history')) || [];
        }
    } catch (error) {
        console.error('Error loading user history:', error);
        // Fallback to localStorage
        scanHistory = JSON.parse(localStorage.getItem('phishguard_history')) || [];
    }
    
    loadHistory();
    updateStats();
    updateHistoryCount();
}

// =============================================
// LOGOUT HANDLER - CLEAR CACHE
// =============================================
async function handleLogout(event) {
    event.preventDefault();
    
    try {
        const response = await fetch('/logout', {
            method: 'GET',
            headers: {
                'X-Requested-With': 'XMLHttpRequest'
            }
        });
        
        if (response.ok) {
            // IMPORTANT: Clear localStorage completely on logout
            localStorage.removeItem('phishguard_history');
            
            // Clear in-memory array
            scanHistory = [];
            
            // Update UI to show empty state
            loadHistory();
            updateStats();
            updateHistoryCount();
            
            showToast('Logged out successfully', 'success');
            
            setTimeout(() => {
                window.location.href = '/';
            }, 500);
        } else {
            window.location.href = '/logout';
        }
    } catch (error) {
        console.error('Logout error:', error);
        window.location.href = '/logout';
    }
}

// =============================================
// INITIALIZE APP
// =============================================
document.addEventListener('DOMContentLoaded', function() {
    // Check if user is logged in
    if (isUserLoggedIn()) {
        // Load history from database for logged-in user
        loadUserHistoryFromDB();
    } else {
        // For non-logged-in users, load from localStorage
        scanHistory = JSON.parse(localStorage.getItem('phishguard_history')) || [];
        loadHistory();
        updateStats();
        updateHistoryCount();
    }
    
    updateTimestamp();
    initializeEventListeners();
    
    // Initialize input type
    setInputType('url');
    
    // Initialize character counter
    const textarea = document.getElementById('analysisInput');
    if (textarea) {
        textarea.addEventListener('input', updateCharCounter);
    }
    
    // Initialize menu active state
    showSection('analyze');
    
    // Pre-load any resources
    preloadResources();
});

// Save report to history
function saveReportToHistory(data, inputText) {
    const verdict = data.verdict || 'Unknown';
    const riskLevel = data.risk_level || 'Unknown';
    const confidence = data.confidence || 0;
    const status = data.status || 'unknown';
    
    const report = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        type: currentInputType,
        content: inputText.length > 100 ? inputText.substring(0, 100) + '...' : inputText,
        verdict: verdict,
        riskLevel: riskLevel,
        confidence: confidence + "%",
        accuracy: data.analysis_source || (currentInputType === 'url' ? '98.7% (URL Model)' : '95.2% (Text Model)'),
        status: status
    };
    
    scanHistory.unshift(report);
    
    if (scanHistory.length > 100) {
        scanHistory = scanHistory.slice(0, 100);
    }
    
    // Save to localStorage as cache
    localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
    
    loadHistory();
    updateStats();
    updateHistoryCount();
}

// Preload resources for faster loading
function preloadResources() {
    const link = document.createElement('link');
    link.rel = 'prefetch';
    link.href = '/results';
    document.head.appendChild(link);
}

// Update timestamp
function updateTimestamp() {
    const timestamp = document.getElementById('analysisTimestamp');
    if (timestamp) {
        const now = new Date();
        timestamp.textContent = now.toLocaleString('en-US', {
            weekday: 'short',
            month: 'short',
            day: 'numeric',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        });
        
        const reportId = `PG-${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${String(now.getHours()).padStart(2,'0')}${String(now.getMinutes()).padStart(2,'0')}${String(now.getSeconds()).padStart(2,'0')}`;
        const reportIdEl = document.getElementById('reportId');
        if (reportIdEl) {
            reportIdEl.textContent = reportId;
        }
    }
}

// Toggle sidebar
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('overlay');
    if (sidebar) {
        sidebar.classList.toggle('active');
    }
    if (overlay) {
        overlay.classList.toggle('active');
    }
}

// Show section
function showSection(sectionId) {
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    
    document.querySelectorAll('.menu-item').forEach(item => {
        item.classList.remove('active');
    });
    
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
    }
    
    const sectionNames = {
        'analyze': 'Threat Analysis',
        'history': 'Scan History',
        'reports': 'Security Analytics'
    };
    const currentSection = document.getElementById('currentSection');
    if (currentSection) {
        currentSection.textContent = sectionNames[sectionId] || sectionId;
    }
    
    const activeMenuItem = document.querySelector(`[onclick="showSection('${sectionId}')"]`);
    if (activeMenuItem) {
        activeMenuItem.classList.add('active');
    }
    
    if (window.innerWidth <= 768) {
        toggleSidebar();
    }
}

// Set input type
function setInputType(type) {
    currentInputType = type;
    
    document.querySelectorAll('.type-tab').forEach(tab => {
        tab.classList.remove('active');
    });
    
    const activeTab = document.querySelector(`[onclick="setInputType('${type}')"]`);
    if (activeTab) {
        activeTab.classList.add('active');
    }
    
    const textarea = document.getElementById('analysisInput');
    const placeholders = {
        'url': 'Paste URL for analysis (e.g., https://example.com/login)...',
        'email': 'Paste email content including headers...',
        'message': 'Paste suspicious message or text...'
    };
    if (textarea) {
        textarea.placeholder = placeholders[type] || 'Enter content for analysis...';
    }
    
    showToast(`Input type set to ${type.toUpperCase()}`, 'info');
}

// Update character counter
function updateCharCounter() {
    const textarea = document.getElementById('analysisInput');
    const counter = document.getElementById('charCount');
    if (textarea && counter) {
        const count = textarea.value.length;
        counter.textContent = count.toLocaleString();
        
        if (count > 1000) {
            counter.style.color = 'var(--success)';
        } else if (count > 100) {
            counter.style.color = 'var(--warning)';
        } else {
            counter.style.color = 'var(--text-muted)';
        }
    }
}

// Clear input
function clearInput() {
    const textarea = document.getElementById('analysisInput');
    if (textarea) {
        textarea.value = '';
        updateCharCounter();
        showToast('Input cleared', 'info');
    }
}

// Paste from clipboard
async function pasteFromClipboard() {
    try {
        const text = await navigator.clipboard.readText();
        const textarea = document.getElementById('analysisInput');
        if (textarea) {
            textarea.value = text;
            textarea.focus();
            updateCharCounter();
            showToast('Content pasted from clipboard', 'success');
        }
    } catch (err) {
        showToast('Unable to paste from clipboard', 'error');
        console.error('Clipboard error:', err);
    }
}

// Clear search
function clearSearch() {
    const searchInput = document.getElementById('historySearch');
    if (searchInput) {
        searchInput.value = '';
        filterHistory();
    }
}

// Get verdict status
function getVerdictStatus(verdict) {
    const verdictLower = verdict.toLowerCase();
    if (verdictLower.includes('safe')) return 'safe';
    if (verdictLower.includes('suspicious') || verdictLower.includes('likely suspicious')) return 'suspicious';
    if (verdictLower.includes('phishing')) return 'phishing';
    return 'unknown';
}

// Update history count badge
function updateHistoryCount() {
    const badge = document.getElementById('historyCount');
    if (badge) {
        badge.textContent = scanHistory.length;
    }
}

// Load history table
function loadHistory() {
    const historyTable = document.getElementById('historyTable');
    const emptyState = document.getElementById('emptyHistory');
    if (!historyTable) return;
    
    const start = (currentPage - 1) * itemsPerPage;
    const end = start + itemsPerPage;
    const pageItems = scanHistory.slice(start, end);
    
    historyTable.innerHTML = '';
    
    if (pageItems.length === 0) {
        if (emptyState) emptyState.classList.add('active');
        updatePaginationInfo(0);
        return;
    }
    
    if (emptyState) emptyState.classList.remove('active');
    
    pageItems.forEach(item => {
        const row = document.createElement('tr');
        const statusClass = getStatusClass(item.verdict);
        const confidenceValue = item.confidence ? item.confidence.replace('%', '') : '0';
        
        row.innerHTML = `
            <td>${formatDateTime(item.timestamp)}</td>
            <td>
                <div class="type-badge type-${item.type}">
                    <i class="fas fa-${item.type === 'url' ? 'link' : item.type === 'email' ? 'envelope' : 'comment'}"></i>
                    ${item.type.toUpperCase()}
                </div>
            </td>
            <td>
                <div class="content-preview" title="${item.content.replace(/"/g, '&quot;')}">
                    ${item.content}
                </div>
            </td>
            <td>
                <span class="status-badge ${statusClass}">${item.verdict}</span>
            </td>
            <td>
                <div class="risk-level-indicator">
                    <div class="risk-bar" style="width: ${confidenceValue}%"></div>
                    <span>${item.riskLevel}</span>
                </div>
            </td>
            <td>
                <div class="confidence-circle">
                    <span>${item.confidence}</span>
                </div>
            </td>
            <td>
                <div class="action-buttons">
                    <button class="btn-icon small" onclick="viewReport(${item.id})" title="View">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn-icon small" onclick="deleteReport(${item.id})" title="Delete">
                        <i class="fas fa-trash-alt"></i>
                    </button>
                </div>
            </td>
        `;
        historyTable.appendChild(row);
    });
    
    updatePaginationInfo(scanHistory.length);
}

// Filter history
function filterHistory() {
    const searchInput = document.getElementById('historySearch');
    const filterSelect = document.getElementById('historyFilter');
    const riskFilter = document.getElementById('riskFilter');
    
    if (!searchInput || !filterSelect || !riskFilter) return;
    
    const searchTerm = searchInput.value.toLowerCase();
    const filterType = filterSelect.value;
    const riskFilterValue = riskFilter.value;
    
    const filtered = scanHistory.filter(item => {
        const matchesSearch = item.content.toLowerCase().includes(searchTerm) || 
                             item.verdict.toLowerCase().includes(searchTerm);
        const matchesType = filterType === 'all' || item.type === filterType;
        const matchesRisk = riskFilterValue === 'all' || getVerdictStatus(item.verdict) === riskFilterValue;
        return matchesSearch && matchesType && matchesRisk;
    });
    
    const historyTable = document.getElementById('historyTable');
    const emptyState = document.getElementById('emptyHistory');
    
    if (!historyTable) return;
    
    historyTable.innerHTML = '';
    
    if (filtered.length === 0) {
        if (emptyState) emptyState.classList.add('active');
        updatePaginationInfo(0);
        return;
    }
    
    if (emptyState) emptyState.classList.remove('active');
    
    filtered.slice(0, itemsPerPage).forEach(item => {
        const row = document.createElement('tr');
        const statusClass = getStatusClass(item.verdict);
        const confidenceValue = item.confidence ? item.confidence.replace('%', '') : '0';
        
        row.innerHTML = `
            <td>${formatDateTime(item.timestamp)}</td>
            <td>
                <div class="type-badge type-${item.type}">
                    <i class="fas fa-${item.type === 'url' ? 'link' : item.type === 'email' ? 'envelope' : 'comment'}"></i>
                    ${item.type.toUpperCase()}
                </div>
            </td>
            <td>
                <div class="content-preview" title="${item.content.replace(/"/g, '&quot;')}">
                    ${item.content}
                </div>
            </td>
            <td>
                <span class="status-badge ${statusClass}">${item.verdict}</span>
            </td>
            <td>
                <div class="risk-level-indicator">
                    <div class="risk-bar" style="width: ${confidenceValue}%"></div>
                    <span>${item.riskLevel}</span>
                </div>
            </td>
            <td>
                <div class="confidence-circle">
                    <span>${item.confidence}</span>
                </div>
            </td>
            <td>
                <div class="action-buttons">
                    <button class="btn-icon small" onclick="viewReport(${item.id})" title="View">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button class="btn-icon small" onclick="deleteReport(${item.id})" title="Delete">
                        <i class="fas fa-trash-alt"></i>
                    </button>
                </div>
            </td>
        `;
        historyTable.appendChild(row);
    });
    
    updatePaginationInfo(filtered.length);
}

// Update stats
function updateStats() {
    const totalScans = scanHistory.length;
    const safeScans = scanHistory.filter(item => 
        getVerdictStatus(item.verdict) === 'safe').length;
    const suspiciousScans = scanHistory.filter(item => 
        getVerdictStatus(item.verdict) === 'suspicious').length;
    const phishingScans = scanHistory.filter(item => 
        getVerdictStatus(item.verdict) === 'phishing').length;
    
    const totalScansEl = document.getElementById('totalScans');
    const safeScansEl = document.getElementById('safeScans');
    const suspiciousScansEl = document.getElementById('suspiciousScans');
    const phishingScansEl = document.getElementById('phishingScans');
    
    if (totalScansEl) totalScansEl.textContent = totalScans.toLocaleString();
    if (safeScansEl) safeScansEl.textContent = safeScans.toLocaleString();
    if (suspiciousScansEl) suspiciousScansEl.textContent = suspiciousScans.toLocaleString();
    if (phishingScansEl) phishingScansEl.textContent = phishingScans.toLocaleString();
    
    const safePercent = totalScans > 0 ? Math.round((safeScans / totalScans) * 100) : 0;
    const suspiciousPercent = totalScans > 0 ? Math.round((suspiciousScans / totalScans) * 100) : 0;
    const phishingPercent = totalScans > 0 ? Math.round((phishingScans / totalScans) * 100) : 0;
    
    const safePercentEl = document.getElementById('safePercent');
    const suspiciousPercentEl = document.getElementById('suspiciousPercent');
    const phishingPercentEl = document.getElementById('phishingPercent');
    const safeBar = document.getElementById('safeBar');
    const suspiciousBar = document.getElementById('suspiciousBar');
    const phishingBar = document.getElementById('phishingBar');
    
    if (safePercentEl) safePercentEl.textContent = safePercent + '%';
    if (suspiciousPercentEl) suspiciousPercentEl.textContent = suspiciousPercent + '%';
    if (phishingPercentEl) phishingPercentEl.textContent = phishingPercent + '%';
    if (safeBar) safeBar.style.height = safePercent + '%';
    if (suspiciousBar) suspiciousBar.style.height = suspiciousPercent + '%';
    if (phishingBar) phishingBar.style.height = phishingPercent + '%';
    
    const activityList = document.getElementById('activityList');
    if (activityList) {
        activityList.innerHTML = '';
        
        const recentActivity = scanHistory.slice(0, 5);
        if (recentActivity.length === 0) {
            activityList.innerHTML = `
                <div class="activity-item">
                    <i class="fas fa-info-circle"></i>
                    <div class="activity-content">
                        <div>No activity yet</div>
                        <div class="activity-time">Start your first analysis</div>
                    </div>
                </div>
            `;
        } else {
            recentActivity.forEach(item => {
                const activityItem = document.createElement('div');
                activityItem.className = 'activity-item';
                
                const icon = getVerdictStatus(item.verdict) === 'safe' ? 'check-circle' : 
                            getVerdictStatus(item.verdict) === 'suspicious' ? 'exclamation-triangle' : 
                            'skull-crossbones';
                
                activityItem.innerHTML = `
                    <i class="fas fa-${icon}"></i>
                    <div class="activity-content">
                        <div>${item.verdict} - ${item.type} analysis</div>
                        <div class="activity-time">${formatDateTime(item.timestamp)}</div>
                    </div>
                `;
                activityList.appendChild(activityItem);
            });
        }
    }
}

// Update pagination info
function updatePaginationInfo(totalItems) {
    const start = Math.min((currentPage - 1) * itemsPerPage + 1, totalItems);
    const end = Math.min(currentPage * itemsPerPage, totalItems);
    const totalPages = Math.ceil(totalItems / itemsPerPage);
    
    const startItemEl = document.getElementById('startItem');
    const endItemEl = document.getElementById('endItem');
    const totalItemsEl = document.getElementById('totalItems');
    
    if (startItemEl) startItemEl.textContent = start > 0 ? start : 0;
    if (endItemEl) endItemEl.textContent = end > 0 ? end : 0;
    if (totalItemsEl) totalItemsEl.textContent = totalItems;
    
    const pageNumbers = document.getElementById('pageNumbers');
    const prevBtn = document.getElementById('prevBtn');
    const nextBtn = document.getElementById('nextBtn');
    
    if (pageNumbers) {
        pageNumbers.innerHTML = '';
        
        const maxPages = 5;
        let startPage = Math.max(1, currentPage - Math.floor(maxPages / 2));
        let endPage = Math.min(totalPages, startPage + maxPages - 1);
        
        if (endPage - startPage + 1 < maxPages) {
            startPage = Math.max(1, endPage - maxPages + 1);
        }
        
        for (let i = startPage; i <= endPage; i++) {
            const pageBtn = document.createElement('button');
            pageBtn.className = `page-number ${i === currentPage ? 'active' : ''}`;
            pageBtn.textContent = i;
            pageBtn.onclick = () => goToPage(i);
            pageNumbers.appendChild(pageBtn);
        }
    }
    
    if (prevBtn) prevBtn.disabled = currentPage === 1;
    if (nextBtn) nextBtn.disabled = currentPage === totalPages || totalPages === 0;
}

// Pagination functions
function prevPage() {
    if (currentPage > 1) {
        currentPage--;
        loadHistory();
    }
}

function nextPage() {
    const totalPages = Math.ceil(scanHistory.length / itemsPerPage);
    if (currentPage < totalPages) {
        currentPage++;
        loadHistory();
    }
}

function goToPage(page) {
    currentPage = page;
    loadHistory();
}

// Helper functions
function getStatusClass(verdict) {
    return getVerdictStatus(verdict);
}

function formatDateTime(isoString) {
    try {
        const date = new Date(isoString);
        const now = new Date();
        const diffMs = now - date;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins}m ago`;
        if (diffHours < 24) return `${diffHours}h ago`;
        if (diffDays < 7) return `${diffDays}d ago`;
        
        return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
    } catch (e) {
        return 'Unknown time';
    }
}

function viewReport(id) {
    const report = scanHistory.find(item => item.id === id);
    if (report) {
        const analysisData = {
            input: report.content,
            inputType: report.type,
            result: {
                verdict: report.verdict,
                risk_level: report.riskLevel,
                confidence: parseInt(report.confidence),
                status: report.status,
                analysis_source: report.accuracy,
                summary: `Analysis from ${formatDateTime(report.timestamp)}`,
                primary_indicators: report.verdict === 'Phishing' ? 
                    ['Brand impersonation detected', 'Suspicious domain pattern'] : 
                    report.verdict === 'Suspicious' ? 
                    ['Suspicious URL pattern', 'Verify before proceeding'] : 
                    ['No threats detected'],
                brand_impersonation: report.verdict === 'Phishing' ? 'Brand detected' : null,
                threat_intelligence: report.type === 'url' ? {
                    "Google Safe Browsing": "Pending",
                    "VirusTotal": "Pending",
                    "Domain Age": "Pending",
                    "SSL Certificate": "Pending"
                } : {
                    "Google Safe Browsing": "—",
                    "VirusTotal": "—",
                    "Domain Age": "—",
                    "SSL Certificate": "—"
                }
            }
        };
        
        sessionStorage.setItem('phishguard_analysis_data', JSON.stringify(analysisData));
        window.location.href = '/results';
    }
}

function deleteReport(id) {
    if (confirm('Are you sure you want to delete this report? This action cannot be undone.')) {
        scanHistory = scanHistory.filter(item => item.id !== id);
        localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
        loadHistory();
        updateStats();
        updateHistoryCount();
        showToast('Report deleted', 'success');
    }
}

function clearHistory() {
    if (scanHistory.length === 0) {
        showToast('History is already empty', 'info');
        return;
    }
    
    if (confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
        scanHistory = [];
        localStorage.removeItem('phishguard_history');
        loadHistory();
        updateStats();
        updateHistoryCount();
        showToast('History cleared', 'success');
    }
}

function exportData() {
    if (scanHistory.length === 0) {
        showToast('No data to export', 'warning');
        return;
    }
    
    const dataStr = JSON.stringify(scanHistory, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `phishguard-history-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    URL.revokeObjectURL(url);
    showToast('Data exported successfully', 'success');
}

function updateTimeRange(range) {
    showToast(`Time range updated to ${range}`, 'info');
}

function showNotifications() {
    showToast('You have 3 unread notifications', 'info');
}

function showSettings() {
    showToast('Settings panel opening...', 'info');
}

// Toast notifications
function showToast(message, type = 'info', duration = 3000) {
    const container = document.getElementById('toastContainer');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: 'check-circle',
        error: 'exclamation-circle',
        warning: 'exclamation-triangle',
        info: 'info-circle'
    };
    
    toast.innerHTML = `
        <div class="toast-icon">
            <i class="fas fa-${icons[type] || 'info-circle'}"></i>
        </div>
        <div class="toast-content">
            <div class="toast-title">${type.charAt(0).toUpperCase() + type.slice(1)}</div>
            <div class="toast-message">${message}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.animation = 'slideInRight 0.3s ease reverse';
            setTimeout(() => toast.remove(), 300);
        }
    }, duration);
}

// Initialize event listeners
function initializeEventListeners() {
    document.addEventListener('click', (e) => {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('overlay');
        const mobileMenuBtn = document.querySelector('.mobile-menu-btn');
        
        if (window.innerWidth <= 768 && 
            sidebar && sidebar.classList.contains('active') &&
            !sidebar.contains(e.target) &&
            mobileMenuBtn && !mobileMenuBtn.contains(e.target)) {
            toggleSidebar();
        }
    });
    
    const searchInput = document.getElementById('historySearch');
    if (searchInput) {
        searchInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                e.preventDefault();
                filterHistory();
            }
        });
    }
}

// =============================================
// MAIN ANALYSIS FUNCTION
// =============================================
async function analyze(event) {
    if (event) event.preventDefault();
    
    if (isAnalyzing) {
        showToast("Analysis already in progress", "warning");
        return false;
    }

    const input = document.getElementById('analysisInput');
    const analyzeBtn = document.querySelector('.btn-analyze');

    if (!input || !input.value.trim()) {
        showToast("Please enter content to analyze", "error");
        return false;
    }

    const inputText = input.value.trim();
    
    if (analyzeBtn) {
        analyzeBtn.disabled = true;
        analyzeBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Analyzing...';
    }
    
    isAnalyzing = true;
    showToast("Processing your request...", "info");

    try {
        const csrfToken = getCSRFToken();
        const headers = {
            "Content-Type": "application/json"
        };
        
        if (csrfToken) {
            headers["X-CSRFToken"] = csrfToken;
        }
        
        const response = await fetch("/predict", {
            method: "POST",
            headers: headers,
            body: JSON.stringify({
                input: inputText,
                type: currentInputType
            })
        });

        const contentType = response.headers.get('content-type');
        if (!contentType || !contentType.includes('application/json')) {
            const text = await response.text();
            console.error('Received non-JSON response:', text.substring(0, 200));
            throw new Error('Server returned an unexpected response. Please try again.');
        }

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || "Analysis failed");
        }

        const analysisData = {
            input: inputText,
            inputType: currentInputType,
            result: result,
            timestamp: new Date().toISOString(),
            status: 'completed'
        };
        
        sessionStorage.setItem('phishguard_analysis_data', JSON.stringify(analysisData));
        
        // Save to history
        saveReportToHistory(result, inputText);
        
        showToast("Analysis completed! Redirecting...", "success");
        
        setTimeout(() => {
            window.location.href = '/results';
        }, 500);

    } catch (error) {
        console.error("Analysis error:", error);
        showToast(error.message || "Error during analysis", "error");
        
        if (analyzeBtn) {
            analyzeBtn.disabled = false;
            analyzeBtn.innerHTML = '<i class="fas fa-play"></i> Start Deep Analysis';
        }
        isAnalyzing = false;
    }

    return false;
}

// Make functions globally available
window.analyze = analyze;
window.toggleSidebar = toggleSidebar;
window.showSection = showSection;
window.setInputType = setInputType;
window.clearInput = clearInput;
window.pasteFromClipboard = pasteFromClipboard;
window.clearSearch = clearSearch;
window.filterHistory = filterHistory;
window.prevPage = prevPage;
window.nextPage = nextPage;
window.goToPage = goToPage;
window.viewReport = viewReport;
window.deleteReport = deleteReport;
window.clearHistory = clearHistory;
window.exportData = exportData;
window.updateTimeRange = updateTimeRange;
window.showNotifications = showNotifications;
window.showSettings = showSettings;
window.handleLogout = handleLogout;