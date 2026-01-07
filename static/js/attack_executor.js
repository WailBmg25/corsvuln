/**
 * Attack Executor - Client-side JavaScript
 * 
 * Handles attack button clicks, sends requests to the attack execution endpoint,
 * and displays results in real-time with collapsible details.
 * 
 * Requirements: 5.3, 5.4
 */

/**
 * Execute an attack against a vulnerable endpoint or test a secure endpoint
 * 
 * @param {string} attackType - Type of attack to execute (wildcard, reflection, etc.)
 * @param {Event} event - The click event object
 * @param {boolean} testSecure - If true, test the secure endpoint instead
 */
async function executeAttack(attackType, event, testSecure = false) {
    console.log(`Exécution de l'attaque ${attackType}${testSecure ? ' (test endpoint sécurisé)' : ''}...`);
    
    // Show warning banner
    const message = testSecure 
        ? `🛡️ TEST DE PROTECTION : Vous allez tester l'endpoint sécurisé ${attackType}.\n\nCela démontrera que l'attaque est correctement bloquée.\n\nVoulez-vous continuer ?`
        : `⚠️ ATTENTION : Vous êtes sur le point d'exécuter un script d'attaque ${attackType}.\n\nCela tentera d'exploiter l'endpoint vulnérable à des fins éducatives.\n\nVoulez-vous continuer ?`;
    
    if (!confirm(message)) {
        return;
    }
    
    // Get the button element - need to find the button that was clicked
    const buttonClass = testSecure ? '.btn-test-secure' : '.btn-attack';
    const button = event ? event.target.closest(buttonClass) : null;
    if (!button) {
        console.error('Bouton non trouvé');
        return;
    }
    
    const originalHTML = button.innerHTML;
    
    // Disable button and show loading state
    button.disabled = true;
    const loadingText = testSecure ? 'Test en cours...' : 'Exécution...';
    button.innerHTML = `<span class="loading"></span> <span class="btn-text">${loadingText}</span>`;
    
    // Show results section
    const resultsSection = document.getElementById('results-section');
    if (resultsSection) {
        resultsSection.style.display = 'block';
        
        // Scroll to results section
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    
    try {
        // Send POST request to execute attack
        const response = await fetch('/api/execute-attack', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                attack_type: attackType,
                test_secure_only: testSecure  // Add this parameter
            })
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Attack execution failed');
        }
        
        // Parse result
        const result = await response.json();
        
        // Display result with context about whether we're testing secure endpoint
        displayAttackResult(result, testSecure);
        
    } catch (error) {
        console.error('Erreur d\'exécution de l\'attaque:', error);
        
        // Display error
        displayAttackError(attackType, error.message, testSecure);
        
    } finally {
        // Re-enable button
        button.disabled = false;
        button.innerHTML = originalHTML;
    }
}

/**
 * Display attack result in the results section
 * 
 * @param {Object} result - Attack result object
 * @param {boolean} testSecure - Whether this was a test of secure endpoint
 */
function displayAttackResult(result, testSecure = false) {
    const resultsContainer = document.getElementById('results-container');
    
    // Create result card
    const resultCard = document.createElement('div');
    resultCard.className = `result-card ${result.success ? 'success' : 'failure'}`;
    resultCard.setAttribute('data-attack-type', result.attack_type);
    
    // Separate vulnerable and secure endpoint results
    const vulnResponses = result.response_details ? result.response_details.filter(r => r.type === 'VULNÉRABLE') : [];
    const secureResponses = result.response_details ? result.response_details.filter(r => r.type === 'SÉCURISÉ') : [];
    
    // Build result HTML with comparison
    resultCard.innerHTML = `
        <div class="result-header">
            <h3>Attaque ${capitalizeWords(result.attack_type.replace(/_/g, ' '))}</h3>
            <span class="result-status ${result.success ? 'success' : 'failure'}">
                ${result.success ? 'EXPLOITÉ ✓' : 'BLOQUÉ ✗'}
            </span>
        </div>
        
        <div class="result-details">
            <p><strong>Durée :</strong> ${result.duration_seconds.toFixed(2)} secondes</p>
            <p><strong>Requêtes envoyées :</strong> ${result.requests_sent}</p>
            ${result.vulnerable_endpoints && result.vulnerable_endpoints.length > 0 ? 
                `<p><strong>Endpoints vulnérables :</strong> ${result.vulnerable_endpoints.join(', ')}</p>` : ''}
        </div>
        
        ${vulnResponses.length > 0 || secureResponses.length > 0 ? `
        <div class="endpoint-result">
            ${vulnResponses.length > 0 ? `
            <div class="comparison-card vulnerable">
                <div class="comparison-header">
                    <span class="status-icon">✗</span>
                    <h5>🔴 Endpoint Vulnérable</h5>
                </div>
                ${vulnResponses.map(resp => `
                    <div class="comparison-content">
                        <p class="endpoint-path"><code>${escapeHtml(resp.endpoint || 'N/A')}</code></p>
                        <p class="result-text">${escapeHtml(resp.result || '')}</p>
                        <div class="status-badge vulnerable">
                            <strong>Statut:</strong> ${resp.status || 'N/A'}
                        </div>
                        ${resp.cors_headers ? `
                        <div class="cors-headers-display">
                            <strong>En-têtes CORS:</strong>
                            <pre><code>${formatCorsHeaders(resp.cors_headers)}</code></pre>
                        </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
            ` : ''}
            
            ${secureResponses.length > 0 ? `
            <div class="comparison-card secure">
                <div class="comparison-header">
                    <span class="status-icon">✓</span>
                    <h5>🟢 Endpoint Sécurisé</h5>
                </div>
                ${secureResponses.map(resp => `
                    <div class="comparison-content">
                        <p class="endpoint-path"><code>${escapeHtml(resp.endpoint || 'N/A')}</code></p>
                        <p class="result-text">${escapeHtml(resp.result || '')}</p>
                        <div class="status-badge secure">
                            <strong>Statut:</strong> ${resp.status || 'N/A'}
                        </div>
                        ${resp.cors_headers ? `
                        <div class="cors-headers-display">
                            <strong>En-têtes CORS:</strong>
                            <pre><code>${formatCorsHeaders(resp.cors_headers)}</code></pre>
                        </div>
                        ` : ''}
                    </div>
                `).join('')}
            </div>
            ` : ''}
        </div>
        ` : ''}
        
        ${result.stolen_data ? `
        <div class="stolen-data">
            <h4>${testSecure ? '🛡️ Résultat du Test de Protection' : '🔓 Données Volées'}</h4>
            <div class="inspector">
                <pre><code>${escapeHtml(JSON.stringify(result.stolen_data, null, 2))}</code></pre>
            </div>
        </div>
        ` : ''}
        
        ${result.request_details && result.request_details.length > 0 ? `
        <details class="inspector-details">
            <summary><strong>📤 Détails des Requêtes</strong></summary>
            <div class="inspector">
                ${result.request_details.map((req, index) => `
                    <div class="request-item">
                        <h5>Requête ${index + 1}</h5>
                        ${req.description ? `<p class="request-description">${escapeHtml(req.description)}</p>` : ''}
                        <p><strong>Méthode :</strong> ${req.method || 'GET'}</p>
                        <p><strong>URL :</strong> ${escapeHtml(req.url || '')}</p>
                        
                        ${req.headers ? `
                        <h6>En-têtes :</h6>
                        <pre><code>${formatHeaders(req.headers)}</code></pre>
                        ` : ''}
                        
                        ${req.body ? `
                        <h6>Corps :</h6>
                        <pre><code>${escapeHtml(typeof req.body === 'object' ? JSON.stringify(req.body, null, 2) : req.body)}</code></pre>
                        ` : ''}
                    </div>
                    ${index < result.request_details.length - 1 ? '<hr>' : ''}
                `).join('')}
            </div>
        </details>
        ` : ''}
        
        ${result.educational_notes ? `
        <div class="educational-note">
            <h4>📚 Notes Éducatives</h4>
            <pre class="educational-text">${escapeHtml(result.educational_notes)}</pre>
        </div>
        ` : ''}
        
        ${result.error ? `
        <div class="error-message">
            <h4>⚠️ Erreur</h4>
            <p>${escapeHtml(result.error)}</p>
        </div>
        ` : ''}
    `;
    
    // Add to results container (prepend to show newest first)
    resultsContainer.insertBefore(resultCard, resultsContainer.firstChild);
    
    // Scroll to the new result
    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Display attack error in the results section
 * 
 * @param {string} attackType - Type of attack that failed
 * @param {string} errorMessage - Error message
 */
function displayAttackError(attackType, errorMessage) {
    const resultsContainer = document.getElementById('results-container');
    
    const errorCard = document.createElement('div');
    errorCard.className = 'result-card failure';
    errorCard.innerHTML = `
        <div class="result-header">
            <h3>Attaque ${capitalizeWords(attackType.replace(/_/g, ' '))}</h3>
            <span class="result-status failure">ERREUR ✗</span>
        </div>
        
        <div class="error-message">
            <h4>⚠️ Erreur d'Exécution</h4>
            <p>${escapeHtml(errorMessage)}</p>
        </div>
    `;
    
    resultsContainer.insertBefore(errorCard, resultsContainer.firstChild);
    errorCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

/**
 * Format headers object as string
 * 
 * @param {Object} headers - Headers object
 * @returns {string} Formatted headers
 */
function formatHeaders(headers) {
    if (!headers || typeof headers !== 'object') {
        return '';
    }
    
    return Object.entries(headers)
        .map(([key, value]) => `${escapeHtml(key)}: ${escapeHtml(String(value))}`)
        .join('\n');
}

/**
 * Format CORS headers with syntax highlighting
 * 
 * @param {Object} headers - CORS headers object
 * @returns {string} Formatted CORS headers with HTML
 */
function formatCorsHeaders(headers) {
    if (!headers || typeof headers !== 'object') {
        return '';
    }
    
    return Object.entries(headers)
        .map(([key, value]) => 
            `<span class="cors-header-key">${escapeHtml(key)}</span>: <span class="cors-header-value">${escapeHtml(String(value))}</span>`
        )
        .join('\n');
}

/**
 * Escape HTML to prevent XSS
 * 
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
    if (text === null || text === undefined) {
        return '';
    }
    
    const div = document.createElement('div');
    div.textContent = String(text);
    return div.innerHTML;
}

/**
 * Capitalize first letter of each word
 * 
 * @param {string} text - Text to capitalize
 * @returns {string} Capitalized text
 */
function capitalizeWords(text) {
    return text.split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1))
        .join(' ');
}

/**
 * Clear all results
 */
function clearResults() {
    const resultsContainer = document.getElementById('results-container');
    resultsContainer.innerHTML = '';
    
    const resultsSection = document.getElementById('results-section');
    resultsSection.style.display = 'none';
}

// Add event listener for clear button if it exists
document.addEventListener('DOMContentLoaded', () => {
    const clearButton = document.getElementById('clear-results-btn');
    if (clearButton) {
        clearButton.addEventListener('click', clearResults);
    }
});
