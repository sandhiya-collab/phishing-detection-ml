// static/results.js
// Optimized results page with faster loading and proper animation

// State management
let scanHistory = JSON.parse(localStorage.getItem('phishguard_history')) || [];
let currentInputType = 'url';
let analysisData = null;
let loadingTimeout = null;

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Show loader immediately
    showLoader();
    
    // Start analysis process with timeout
    startAnalysisProcess();
});

function showLoader() {
    const loader = document.getElementById('fullscreenLoader');
    if (loader) {
        loader.classList.remove('hidden');
        
        // Animate progress bars immediately
        requestAnimationFrame(() => {
            animateProgressBars();
        });
    }
}

function animateProgressBars() {
    const fills = document.querySelectorAll('.progress-fill');
    
    // Set initial widths
    fills.forEach((fill, index) => {
        const targets = [80, 60, 40];
        fill.style.width = '0%';
        
        // Animate to target after a tiny delay
        setTimeout(() => {
            fill.style.transition = 'width 1.5s ease-in-out';
            fill.style.width = targets[index] + '%';
        }, 100);
    });
    
    // Continuous subtle animation
    setInterval(() => {
        fills.forEach((fill, index) => {
            const targets = [80, 60, 40];
            const currentWidth = parseInt(fill.style.width) || 0;
            
            if (currentWidth >= targets[index]) {
                fill.style.transition = 'width 1s ease-in-out';
                fill.style.width = (targets[index] - 5) + '%';
                
                setTimeout(() => {
                    fill.style.transition = 'width 1s ease-in-out';
                    fill.style.width = targets[index] + '%';
                }, 500);
            }
        });
    }, 2000);
}

function hideLoader() {
    const loader = document.getElementById('fullscreenLoader');
    if (loader) {
        // Fade out animation
        loader.style.transition = 'opacity 0.3s ease';
        loader.style.opacity = '0';
        
        setTimeout(() => {
            loader.classList.add('hidden');
            loader.style.opacity = '1';
            loader.style.transition = '';
        }, 300);
    }
    if (loadingTimeout) {
        clearTimeout(loadingTimeout);
    }
}

async function startAnalysisProcess() {
    // Set maximum loading time (5 seconds max - increased from 3)
    loadingTimeout = setTimeout(() => {
        hideLoader();
        if (!analysisData || !analysisData.result) {
            showFallbackResults();
        }
    }, 5000);
    
    try {
        // Get the analysis data from session storage
        analysisData = JSON.parse(sessionStorage.getItem('phishguard_analysis_data'));
    } catch (e) {
        console.error('Failed to parse session data', e);
    }
    
    if (!analysisData || !analysisData.input) {
        hideLoader();
        showToast('No analysis data found. Please return to main page.', 'error');
        setTimeout(() => {
            window.location.href = '/';
        }, 2000);
        return;
    }
    
    currentInputType = analysisData.inputType || 'url';
    
    // If we already have results, display them immediately
    if (analysisData.result) {
        clearTimeout(loadingTimeout);
        hideLoader();
        displayResults(analysisData.result, analysisData.input);
        
        // Fetch threat intelligence in background only for URLs
        if (currentInputType === 'url' && analysisData.input) {
            fetchThreatIntelligence(analysisData.input);
        }
    } 
    // If we have an error, display error state
    else if (analysisData.error) {
        clearTimeout(loadingTimeout);
        hideLoader();
        showErrorState(analysisData.error, analysisData.input);
    }
    // Otherwise, wait for results (polling)
    else {
        pollForResults();
    }
}

function pollForResults() {
    let attempts = 0;
    const maxAttempts = 15;
    
    const pollInterval = setInterval(() => {
        attempts++;
        
        try {
            const updatedData = JSON.parse(sessionStorage.getItem('phishguard_analysis_data'));
            
            if (updatedData && updatedData.result) {
                clearInterval(pollInterval);
                clearTimeout(loadingTimeout);
                hideLoader();
                
                analysisData = updatedData;
                displayResults(updatedData.result, updatedData.input);
                
                if (currentInputType === 'url' && updatedData.input) {
                    fetchThreatIntelligence(updatedData.input);
                }
            } else if (attempts >= maxAttempts) {
                clearInterval(pollInterval);
                clearTimeout(loadingTimeout);
                hideLoader();
                showFallbackResults(updatedData?.input || analysisData?.input);
            }
        } catch (e) {
            console.error('Polling error:', e);
        }
    }, 300);
}

function showFallbackResults(inputText) {
    // Show fallback results with demo data
    const fallbackResult = {
        verdict: "Analysis in Progress",
        status: "pending",
        risk_level: "Pending",
        confidence: 50,
        summary: "Your analysis is being processed. Results will appear shortly.",
        analysis_source: "System Processing",
        primary_indicators: ["Analysis pending", "Please wait"],
        threat_intelligence: currentInputType === 'url' ? {} : {
            "Google Safe Browsing": "—",
            "VirusTotal": "—",
            "Domain Age": "—",
            "SSL Certificate": "—"
        }
    };
    
    displayResults(fallbackResult, inputText || "Content under analysis");
    showToast("Analysis still processing. Check back in a moment.", "info");
}

function showErrorState(errorMessage, inputText) {
    const errorResult = {
        verdict: "Error",
        status: "error",
        risk_level: "Unknown",
        confidence: 0,
        summary: `Analysis failed: ${errorMessage || "Unknown error"}`,
        analysis_source: "Error",
        primary_indicators: ["Analysis failed", "Please try again"],
        threat_intelligence: currentInputType === 'url' ? {} : {
            "Google Safe Browsing": "—",
            "VirusTotal": "—",
            "Domain Age": "—",
            "SSL Certificate": "—"
        }
    };
    
    displayResults(errorResult, inputText);
    showToast("Analysis failed. Please try again.", "error");
}

// ===== FETCH THREAT INTELLIGENCE =====
async function fetchThreatIntelligence(url) {
    try {
        console.log("🔍 Fetching Threat Intelligence for:", url);
        
        const response = await fetch("/threat-intel", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ 
                url: url,
                type: currentInputType 
            })
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const data = await response.json();
        console.log("✅ Threat Intelligence received:", data);
        
        // Update UI with Threat Intelligence data
        updateThreatIntelligenceUI(data);
        
    } catch (error) {
        console.error("❌ Threat Intelligence failed:", error);
        // No toast notification - just log to console
    }
}

// ===== UPDATE THREAT INTELLIGENCE UI =====
function updateThreatIntelligenceUI(data) {
    // Update Google Safe Browsing
    const gsbInfo = document.getElementById('gsbInfo');
    if (gsbInfo && data.threat_intelligence) {
        const gsbMessage = data.threat_intelligence["Google Safe Browsing"] || "—";
        updateIntelElement(gsbInfo, gsbMessage);
    }
    
    // Update VirusTotal
    const vtInfo = document.getElementById('vtInfo');
    if (vtInfo && data.threat_intelligence) {
        const vtMessage = data.threat_intelligence["VirusTotal"] || "—";
        updateIntelElement(vtInfo, vtMessage);
    }
    
    // Update Domain Age
    const domainAgeInfo = document.getElementById('domainAgeInfo');
    if (domainAgeInfo && data.threat_intelligence) {
        const daMessage = data.threat_intelligence["Domain Age"] || "—";
        updateIntelElement(domainAgeInfo, daMessage);
    }
    
    // Update SSL Certificate - simplified
    const sslInfo = document.getElementById('sslInfo');
    if (sslInfo && data.threat_intelligence) {
        const sslMessage = data.threat_intelligence["SSL Certificate"] || "—";
        
        if (sslMessage.includes("Valid") || sslMessage.includes("✅")) {
            sslInfo.style.color = "var(--success)";
            sslInfo.innerHTML = `<i class="fas fa-lock"></i> ${sslMessage}`;
        } else if (sslMessage.includes("Timeout") || sslMessage.includes("unavailable") || sslMessage.includes("⏳")) {
            sslInfo.style.color = "var(--warning)";
            sslInfo.innerHTML = `<i class="fas fa-clock"></i> SSL check pending`;
        } else if (sslMessage.includes("HTTP")) {
            sslInfo.style.color = "var(--info)";
            sslInfo.innerHTML = `<i class="fas fa-globe"></i> ${sslMessage}`;
        } else {
            sslInfo.style.color = "var(--text-muted)";
            sslInfo.innerHTML = `<i class="fas fa-minus-circle"></i> ${sslMessage}`;
        }
    }
}

// Helper function to update intel elements
function updateIntelElement(element, message) {
    if (message.includes("✅") || message.includes("Clean")) {
        element.style.color = "var(--success)";
        element.innerHTML = `<i class="fas fa-check-circle"></i> ${message}`;
    } else if (message.includes("⚠️") || message.includes("Suspicious")) {
        element.style.color = "var(--warning)";
        element.innerHTML = `<i class="fas fa-exclamation-triangle"></i> ${message}`;
    } else if (message.includes("🚨") || message.includes("Malicious")) {
        element.style.color = "var(--danger)";
        element.innerHTML = `<i class="fas fa-skull-crossbones"></i> ${message}`;
    } else if (message.includes("unavailable") || message.includes("Unable")) {
        element.style.color = "var(--text-muted)";
        element.innerHTML = `<i class="fas fa-question-circle"></i> ${message}`;
    } else if (message.includes("⏳")) {
        element.style.color = "var(--warning)";
        element.innerHTML = `<i class="fas fa-spinner fa-spin"></i> ${message}`;
    } else {
        element.innerHTML = message;
    }
}

// ===== DISPLAY RESULTS WITH PROFESSIONAL STYLING =====
function displayResults(data, inputText) {
    const resultsContainer = document.getElementById('resultsContainer');
    if (!resultsContainer) return;
    
    const now = new Date();
    const timestamp = now.toLocaleString('en-US', {
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
    
    const confidenceValue = typeof data.confidence === "number" ? data.confidence : 0;
    const status = data.status || (data.verdict ? data.verdict.toLowerCase() : 'safe');
    const verdict = data.verdict || 'Safe';
    const riskLevel = data.risk_level || (
        verdict.toLowerCase() === 'phishing' ? 'Critical Risk' : 
        verdict.toLowerCase() === 'suspicious' ? 'Elevated Risk' : 
        'Minimal Risk'
    );
    const summary = data.summary || 'Analysis completed successfully.';
    const analysisSource = data.analysis_source || 'DeepSeek AI (Primary)';
    
    const indicators = data.primary_indicators || [];
    const brandImpersonation = data.brand_impersonation || null;
    
    // Get threat intelligence data or set defaults
    const threatIntel = data.threat_intelligence || {};
    const gsbMessage = threatIntel["Google Safe Browsing"] || (currentInputType === 'url' ? '⏳ Checking...' : '—');
    const vtMessage = threatIntel["VirusTotal"] || (currentInputType === 'url' ? '⏳ Checking...' : '—');
    const daMessage = threatIntel["Domain Age"] || (currentInputType === 'url' ? '⏳ Checking...' : '—');
    const sslMessage = threatIntel["SSL Certificate"] || (currentInputType === 'url' && inputText.startsWith('https') ? '⏳ Checking...' : '—');
    
    let recommendation = data.recommendation || '';
    if (!recommendation) {
        if (verdict.toLowerCase().includes('phishing')) {
            recommendation = 'Critical threat detected. Do not interact with this content. Immediately block the sender/domain and report to your security operations team.';
        } else if (verdict.toLowerCase().includes('suspicious')) {
            recommendation = 'Exercise heightened caution. Verify the source independently through official channels before proceeding. Do not enter any credentials or personal information.';
        } else {
            recommendation = 'No immediate action required. Continue following standard security protocols and best practices.';
        }
    }
    
    let riskFactors = data.risk_factors || [];
    if (riskFactors.length === 0 && verdict.toLowerCase() === 'phishing') {
        riskFactors = [
            'Brand impersonation detected',
            'Domain does not match official records',
            'Suspicious URL pattern identified',
            'Multiple threat indicators present'
        ];
        if (brandImpersonation) {
            riskFactors[0] = `Brand impersonation: attempts to mimic ${brandImpersonation}`;
        }
    } else if (riskFactors.length === 0 && verdict.toLowerCase() === 'suspicious') {
        riskFactors = [
            'Unusual URL structure detected',
            'Domain reputation requires verification',
            'Proceed with caution'
        ];
    }
    
    // Determine icon based on verdict
    let verdictIcon;
    let iconColor;
    
    if (verdict.toLowerCase().includes('phishing')) {
        verdictIcon = 'skull-crossbones';
        iconColor = 'var(--danger)';
    } else if (verdict.toLowerCase().includes('suspicious')) {
        verdictIcon = 'exclamation-triangle';
        iconColor = 'var(--warning)';
    } else {
        verdictIcon = 'check-circle';
        iconColor = 'var(--success)';
    }
    
    const html = `
        <section class="results-section animate__animated animate__fadeIn">
            <!-- Professional Header -->
            <div class="results-header-professional">
                <div class="header-left">
                    <h1><i class="fas fa-shield-alt"></i> Security Analysis Report</h1>
                    <div class="report-metadata">
                        <span class="metadata-item"><i class="far fa-clock"></i> ${timestamp}</span>
                        <span class="metadata-item"><i class="fas fa-fingerprint"></i> ${reportId}</span>
                        <span class="metadata-item"><i class="fas fa-microchip"></i> ${analysisSource}</span>
                    </div>
                </div>
                <div class="header-actions">
                    <button class="btn-outline" onclick="saveCurrentReport()" title="Save Report">
                        <i class="fas fa-save"></i> Save
                    </button>
                    <button class="btn-outline" onclick="window.location.href='/'" title="New Analysis">
                        <i class="fas fa-plus"></i> New
                    </button>
                </div>
            </div>

            <!-- Professional Verdict Card -->
            <div class="verdict-card-professional ${status}">
                <div class="verdict-icon-large" style="color: ${iconColor};">
                    <i class="fas fa-${verdictIcon}"></i>
                </div>
                <div class="verdict-content-professional">
                    <div class="verdict-label">Security Verdict</div>
                    <div class="verdict-value">${verdict}</div>
                    <div class="verdict-confidence">
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: ${confidenceValue}%"></div>
                        </div>
                        <span>${confidenceValue}% Confidence</span>
                    </div>
                </div>
                <div class="risk-level-professional">
                    <div class="risk-label">Risk Level</div>
                    <div class="risk-value">${riskLevel}</div>
                </div>
            </div>

            <!-- Content Analysis Card -->
            <div class="analysis-card">
                <div class="card-title">
                    <i class="fas fa-file-alt"></i>
                    <h3>Analyzed Content</h3>
                    <span class="type-badge type-${currentInputType}">
                        <i class="fas fa-${currentInputType === 'url' ? 'link' : currentInputType === 'email' ? 'envelope' : 'comment'}"></i>
                        ${currentInputType.toUpperCase()}
                    </span>
                </div>
                <div class="content-display-professional">
                    ${inputText}
                </div>
            </div>

            <!-- Threat Intelligence Grid -->
            <div class="intel-grid-professional">
                <div class="intel-card">
                    <div class="intel-header">
                        <i class="fas fa-robot"></i>
                        <h4>AI-ML Analysis</h4>
                    </div>
                    <div class="intel-body">
                        <div class="intel-row">
                            <span>Confidence Score</span>
                            <strong>${confidenceValue}%</strong>
                        </div>
                        <div class="intel-row">
                            <span>Primary Engine</span>
                            <strong>${analysisSource}</strong>
                        </div>
                        <div class="intel-row">
                            <span>ML Model</span>
                            <strong>DeepSeek LLM</strong>
                        </div>
                        ${brandImpersonation ? `
                        <div class="intel-row warning">
                            <span>Brand Impersonation</span>
                            <strong>${brandImpersonation}</strong>
                        </div>
                        ` : ''}
                    </div>
                </div>

                <div class="intel-card">
                    <div class="intel-header">
                        <i class="fab fa-google"></i>
                        <h4>Google Safe Browsing</h4>
                    </div>
                    <div class="intel-body">
                        <div id="gsbInfo" class="intel-value ${gsbMessage.includes('⏳') ? 'status-pending' : ''}">
                            ${gsbMessage.includes('⏳') ? '<i class="fas fa-spinner fa-spin"></i> ' : ''}${gsbMessage}
                        </div>
                    </div>
                </div>

                <div class="intel-card">
                    <div class="intel-header">
                        <i class="fas fa-shield-virus"></i>
                        <h4>VirusTotal</h4>
                    </div>
                    <div class="intel-body">
                        <div id="vtInfo" class="intel-value ${vtMessage.includes('⏳') ? 'status-pending' : ''}">
                            ${vtMessage.includes('⏳') ? '<i class="fas fa-spinner fa-spin"></i> ' : ''}${vtMessage}
                        </div>
                    </div>
                </div>

                <div class="intel-card">
                    <div class="intel-header">
                        <i class="fas fa-clock"></i>
                        <h4>Domain Age</h4>
                    </div>
                    <div class="intel-body">
                        <div id="domainAgeInfo" class="intel-value ${daMessage.includes('⏳') ? 'status-pending' : ''}">
                            ${daMessage.includes('⏳') ? '<i class="fas fa-spinner fa-spin"></i> ' : ''}${daMessage}
                        </div>
                    </div>
                </div>

                <div class="intel-card">
                    <div class="intel-header">
                        <i class="fas fa-lock"></i>
                        <h4>SSL Certificate</h4>
                    </div>
                    <div class="intel-body">
                        <div id="sslInfo" class="intel-value ${sslMessage.includes('⏳') ? 'status-pending' : ''}">
                            ${sslMessage.includes('⏳') ? '<i class="fas fa-spinner fa-spin"></i> ' : ''}${sslMessage}
                        </div>
                    </div>
                </div>
            </div>

            <!-- Risk Factors & Recommendations -->
            <div class="risk-recommendation-grid">
                <div class="risk-card">
                    <div class="card-title">
                        <i class="fas fa-exclamation-triangle"></i>
                        <h3>Risk Factors</h3>
                        <span class="risk-count">${riskFactors.length}</span>
                    </div>
                    <div class="risk-list-professional">
                        ${riskFactors.length > 0 ? 
                            riskFactors.map(factor => `
                                <div class="risk-item">
                                    <i class="fas fa-circle"></i>
                                    <span>${factor}</span>
                                </div>
                            `).join('') : 
                            '<div class="risk-item safe"><i class="fas fa-check-circle"></i><span>No significant risk factors detected</span></div>'
                        }
                    </div>
                </div>

                <div class="recommendation-card">
                    <div class="card-title">
                        <i class="fas fa-clipboard-check"></i>
                        <h3>Executive Summary & Recommendations</h3>
                    </div>
                    <div class="summary-text-professional">
                        ${summary}
                    </div>
                    <div class="recommendation-box-professional">
                        <div class="recommendation-icon ${status}">
                            <i class="fas fa-lightbulb"></i>
                        </div>
                        <div class="recommendation-text">
                            <strong>Recommended Action:</strong>
                            <p>${recommendation}</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Hidden fields for saving -->
            <input type="hidden" id="currentInputValue" value="${inputText.replace(/"/g, '&quot;')}">
            <input type="hidden" id="currentVerdict" value="${verdict}">
            <input type="hidden" id="currentRiskLevel" value="${riskLevel}">
            <input type="hidden" id="currentConfidence" value="${confidenceValue}%">
            <input type="hidden" id="currentStatus" value="${status}">
            <input type="hidden" id="currentType" value="${currentInputType}">
            <input type="hidden" id="currentAnalysisSource" value="${analysisSource}">
        </section>
    `;
    
    resultsContainer.innerHTML = html;
    resultsContainer.classList.add('active');
    
    // Scroll to top smoothly
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ===== SAVE CURRENT REPORT =====
function saveCurrentReport() {
    const input = document.getElementById('currentInputValue');
    const verdict = document.getElementById('currentVerdict');
    const riskLevel = document.getElementById('currentRiskLevel');
    const confidence = document.getElementById('currentConfidence');
    const status = document.getElementById('currentStatus');
    const type = document.getElementById('currentType');
    const analysisSource = document.getElementById('currentAnalysisSource');
    
    if (!input || !input.value) {
        showToast('No analysis results to save', 'warning');
        return;
    }
    
    const currentType = type?.value || 'url';
    const source = analysisSource?.value || 'DeepSeek AI';
    
    const report = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        type: currentType,
        content: input.value.length > 100 ? input.value.substring(0, 100) + '...' : input.value,
        verdict: verdict?.value || 'Unknown',
        riskLevel: riskLevel?.value || 'Unknown',
        confidence: confidence?.value || "0%",
        accuracy: source,
        status: status?.value || 'unknown'
    };
    
    let scanHistory = JSON.parse(localStorage.getItem('phishguard_history')) || [];
    
    const exists = scanHistory.some(item => 
        item.timestamp === report.timestamp && 
        item.content === report.content
    );
    
    if (!exists) {
        scanHistory.unshift(report);
        if (scanHistory.length > 100) {
            scanHistory = scanHistory.slice(0, 100);
        }
        localStorage.setItem('phishguard_history', JSON.stringify(scanHistory));
        showToast('Report saved to history', 'success');
    } else {
        showToast('Report already in history', 'info');
    }
}

// ===== SHOW TOAST NOTIFICATION =====
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

// Export functions to global scope
window.startAnalysisProcess = startAnalysisProcess;
window.displayResults = displayResults;
window.saveCurrentReport = saveCurrentReport;
window.showToast = showToast;
window.updateThreatIntelligenceUI = updateThreatIntelligenceUI;