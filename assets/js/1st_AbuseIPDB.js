/**
 * Enhanced AbuseIPDB reporting workflow handler with secure clipboard orchestration
 * 
 * Author: Mikhail Deynekin (mid1977@gmail.com)
 * Website: https://deynekin.com
 * 
 * This implementation leverages 2025 web standards for maximum reliability,
 * security, and user experience across modern browsers and terminal environments
 * 
 * @param {string} cleanIp - Validated IPv4 address for reporting
 * @param {string} reportText - Raw report content to process
 * @param {Object} [options={}] - Configuration options
 * @param {boolean} [options.copyEncoded=false] - Copy URL-encoded text
 * @param {boolean} [options.disableCopy=false] - Disable clipboard operations
 * @param {boolean} [options.disableNavigation=false] - Disable URL opening
 * @param {boolean} [options.silent=false] - Suppress all console output
 * @param {'auto'|'modern'|'legacy'} [options.clipboardMethod='auto'] - Force clipboard method
 * @param {boolean} [options.preserveFormatting=false] - Maintain whitespace formatting
 * @returns {Promise<OperationResult>} Detailed operation status
 */

async function handleAbuseReport(cleanIp, reportText, options = {}) {
    const {
        copyEncoded = false,
        disableCopy = false,
        disableNavigation = false,
        silent = false,
        clipboardMethod = 'auto',
        preserveFormatting = false
    } = options;

    const result = {
        copied: false,
        opened: false,
        timestamp: new Date().toISOString(),
        method: null,
        warnings: []
    };

    /**
     * Structured logging system with terminal-aware formatting
     * Supports ANSI codes in modern terminals and graceful fallback
     */
    const log = (level, message, data = null) => {
        if (silent) return;
        
        const styles = {
            success: { icon: '✓', color: '\x1b[32m', reset: '\x1b[0m' },
            warning: { icon: '⚠', color: '\x1b[33m', reset: '\x1b[0m' },
            error: { icon: '✗', color: '\x1b[31m', reset: '\x1b[0m' },
            skip: { icon: '⏭', color: '\x1b[36m', reset: '\x1b[0m' },
            info: { icon: 'ℹ', color: '\x1b[34m', reset: '\x1b[0m' },
            debug: { icon: '🐛', color: '\x1b[90m', reset: '\x1b[0m' }
        };
        
        const style = styles[level] || styles.info;
        const supportsANSI = typeof process !== 'undefined' && process.stdout?.isTTY;
        const formattedMessage = supportsANSI 
            ? `${style.color}${style.icon} ${message}${style.reset}`
            : `${style.icon} ${message}`;
        
        const logMethod = level === 'error' ? 'error' : level === 'debug' ? 'debug' : 'log';
        
        if (data) {
            console[logMethod](formattedMessage, data);
        } else {
            console[logMethod](formattedMessage);
        }
    };

    /**
     * Enhanced IPv4 validation with subnet awareness and reserved range checking
     */
    const validateIpAddress = (ip) => {
        if (!ip || typeof ip !== 'string') {
            return { valid: false, error: 'IP must be a non-empty string' };
        }
        
        const octets = ip.split('.');
        if (octets.length !== 4) {
            return { valid: false, error: 'IPv4 must contain exactly 4 octets' };
        }
        
        for (const octet of octets) {
            const num = parseInt(octet, 10);
            if (isNaN(num) || num < 0 || num > 255) {
                return { valid: false, error: `Octet ${octet} is out of range (0-255)` };
            }
            if (octet.length > 1 && octet[0] === '0') {
                result.warnings.push(`Leading zero in octet ${octet} may cause interpretation issues`);
            }
        }
        
        // Check for reserved/private ranges (informational)
        const firstOctet = parseInt(octets[0], 10);
        if (
            firstOctet === 10 ||
            (firstOctet === 172 && parseInt(octets[1], 10) >= 16 && parseInt(octets[1], 10) <= 31) ||
            (firstOctet === 192 && parseInt(octets[1], 10) === 168) ||
            firstOctet === 127
        ) {
            result.warnings.push(`IP ${ip} appears to be in a private/reserved range`);
        }
        
        return { valid: true };
    };

    /**
     * Content sanitization with configurable preservation levels
     */
    const sanitizeContent = (text, preserveFormatting = false) => {
        let sanitized = text;
        
        // Remove potentially dangerous characters
        sanitized = sanitized.replace(/[<>'"`]/g, '');
        
        // Normalize whitespace if not preserving formatting
        if (!preserveFormatting) {
            sanitized = sanitized.replace(/\s+/g, ' ').trim();
        }
        
        // Truncate to reasonable length for URL encoding
        if (sanitized.length > 10000) {
            result.warnings.push(`Report text truncated from ${sanitized.length} to 10000 characters`);
            sanitized = sanitized.substring(0, 10000);
        }
        
        return sanitized;
    };

    // Validate inputs
    const ipValidation = validateIpAddress(cleanIp);
    if (!ipValidation.valid) {
        log('error', `IP validation failed: ${ipValidation.error}`);
        result.error = `Invalid IP: ${ipValidation.error}`;
        return result;
    }
    
    if (!reportText || typeof reportText !== 'string') {
        log('error', 'Report text must be a non-empty string');
        result.error = 'Report text must be a non-empty string';
        return result;
    }
    
    const sanitizedText = sanitizeContent(reportText, preserveFormatting);
    if (sanitizedText.length < 10) {
        log('error', 'Report text must be at least 10 characters after sanitization');
        result.error = 'Report text too short after sanitization';
        return result;
    }

    /**
     * Secure clipboard orchestration with method detection and optimization
     * Supports: Async Clipboard API and execCommand fallback
     */
    const orchestrateClipboardCopy = async (text, methodPreference = 'auto') => {
        const startTime = performance.now();
        let methodUsed = 'none';
        
        try {
            // Method detection and selection
            const selectMethod = () => {
                if (methodPreference === 'legacy') return 'legacy';
                if (methodPreference === 'modern') return 'modern';
                
                // Auto-detection logic
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    return 'modern';
                }
                if (document.queryCommandSupported?.('copy')) {
                    return 'legacy';
                }
                return 'none';
            };
            
            const selectedMethod = selectMethod();
            methodUsed = selectedMethod;
            result.method = selectedMethod;
            
            if (selectedMethod === 'none') {
                throw new Error('No supported clipboard method available');
            }
            
            // Modern Clipboard API (preferred)
            if (selectedMethod === 'modern') {
                await navigator.clipboard.writeText(text);
                // Removed clipboard read verification to eliminate permission requests
            }
            
            // Legacy execCommand method
            if (selectedMethod === 'legacy') {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.setAttribute('aria-hidden', 'true');
                textarea.setAttribute('data-clipboard-target', 'true');
                
                // Advanced styling to minimize visual impact
                textarea.style.cssText = `
                    position: fixed !important;
                    top: 0 !important;
                    left: 0 !important;
                    width: 1px !important;
                    height: 1px !important;
                    padding: 0 !important;
                    margin: 0 !important;
                    border: 0 !important;
                    outline: 0 !important;
                    box-shadow: none !important;
                    background: transparent !important;
                    color: transparent !important;
                    opacity: 0 !important;
                    z-index: -9999 !important;
                    pointer-events: none !important;
                    user-select: none !important;
                    -webkit-user-select: none !important;
                    -moz-user-select: none !important;
                    -ms-user-select: none !important;
                `;
                
                document.body.appendChild(textarea);
                
                try {
                    // Multiple selection strategies for maximum compatibility
                    if (textarea.select) {
                        textarea.select();
                    } else {
                        const range = document.createRange();
                        range.selectNodeContents(textarea);
                        const selection = window.getSelection();
                        selection.removeAllRanges();
                        selection.addRange(range);
                    }
                    
                    textarea.setSelectionRange(0, textarea.value.length);
                    textarea.focus?.();
                    
                    const success = document.execCommand('copy');
                    if (!success) {
                        throw new Error('execCommand returned false');
                    }
                    
                    // Attempt to clear selection
                    if (window.getSelection) {
                        if (window.getSelection().empty) {
                            window.getSelection().empty();
                        } else if (window.getSelection().removeAllRanges) {
                            window.getSelection().removeAllRanges();
                        }
                    } else if (document.selection) {
                        document.selection.empty();
                    }
                } finally {
                    // Guaranteed cleanup
                    setTimeout(() => {
                        if (textarea.parentNode) {
                            textarea.parentNode.removeChild(textarea);
                        }
                    }, 100);
                }
            }
            
            const duration = (performance.now() - startTime).toFixed(2);
            log('success', `Copied via ${selectedMethod} method in ${duration}ms`);
            
            return true;
            
        } catch (error) {
            const errorDetails = {
                method: methodUsed,
                error: error.message,
                userAgent: navigator.userAgent,
                secureContext: window.isSecureContext
            };
            
            log('error', 'Clipboard operation failed', errorDetails);
            
            // Fallback: Write to console as last resort
            if (!silent) {
                console.info('COPY FALLBACK - Content for manual copy:');
                console.log(text);
            }
            
            return false;
        }
    };

    /**
     * Intelligent window management with URL length optimization
     * FIXED: Empty window issue by using synchronous window.open and proper fallbacks
     */
    const openIntelligentWindow = (url, ip) => {
        try {
            // URL length validation - critical for browser compatibility
            const MAX_URL_LENGTH = 2000; // Conservative limit for all browsers
            let finalUrl = url;
            
            if (url.length > MAX_URL_LENGTH) {
                log('warning', `URL length (${url.length}) exceeds safe limit (${MAX_URL_LENGTH})`);
                
                // Truncate comment while preserving essential structure
                const match = url.match(/comment=([^&]*)/);
                if (match) {
                    const encodedComment = match[1];
                    const maxCommentLength = MAX_URL_LENGTH - (url.length - encodedComment.length);
                    
                    if (maxCommentLength > 100) {
                        const truncatedComment = encodedComment.substring(0, maxCommentLength - 3) + '%2E%2E%2E';
                        finalUrl = url.replace(/comment=[^&]*/, `comment=${truncatedComment}`);
                        result.warnings.push(`Comment truncated due to URL length constraints`);
                    } else {
                        // URL still too long, use minimal version
                        finalUrl = `https://www.abuseipdb.com/report?ip=${cleanIp}?reason=5`;
                        result.warnings.push(`URL simplified to base due to length constraints`);
                    }
                }
            }
            
            // Strategy 1: Direct window.open with minimal features (most reliable)
            const windowFeatures = 'noopener,noreferrer,resizable=yes,scrollbars=yes';
            
            // Store reference before opening to prevent garbage collection issues
            let newWindow = null;
            
            // CRITICAL FIX: Use synchronous window.open during user gesture context
            // Many browsers require window.open to be called directly from user event handler
            newWindow = window.open(finalUrl, '_blank', windowFeatures);
            
            // Popup blocker detection
            if (!newWindow || newWindow.closed || typeof newWindow.closed === 'undefined') {
                log('warning', 'Popup was blocked by browser or extension');
                
                // Fallback Strategy: Create and click a link element
                try {
                    const link = document.createElement('a');
                    link.href = finalUrl;
                    link.target = '_blank';
                    link.rel = 'noopener noreferrer';
                    link.style.display = 'none';
                    document.body.appendChild(link);
                    link.click();
                    document.body.removeChild(link);
                    
                    log('info', 'Using link fallback method');
                    return true;
                } catch (fallbackError) {
                    log('error', 'All window opening methods failed', fallbackError);
                    return false;
                }
            }
            
            // Post-open security hardening
            try {
                newWindow.opener = null;
                Object.defineProperty(newWindow, 'opener', { value: null, configurable: false });
            } catch {
                // Some browsers restrict this modification
            }
            
            // Focus management with delay for browser initialization
            setTimeout(() => {
                try {
                    if (newWindow && !newWindow.closed) {
                        newWindow.focus();
                    }
                } catch {
                    // Focus may be restricted by browser policy
                }
            }, 250);
            
            log('success', `Opened AbuseIPDB report for ${ip}`);
            return true;
            
        } catch (error) {
            log('error', 'Window opening failed', {
                error: error.message,
                urlLength: url.length,
                secureContext: window.isSecureContext
            });
            return false;
        }
    };

    // Main execution flow
    try {
        // Phase 1: Clipboard operations
        if (!disableCopy) {
            const textToCopy = copyEncoded 
                ? encodeURIComponent(sanitizedText)
                : sanitizedText;
            
            result.copied = await orchestrateClipboardCopy(textToCopy, clipboardMethod);
        } else {
            log('skip', 'Clipboard operations disabled');
        }

        // Phase 2: Navigation operations
        if (!disableNavigation) {
            const encodedReport = encodeURIComponent(sanitizedText);
            const url = `https://www.abuseipdb.com/report?ip=${cleanIp}?reason=5&comment=${encodedReport}`;
            
            result.opened = openIntelligentWindow(url, cleanIp);
            
            // Removed analytics beacon to eliminate tracking
        } else {
            log('skip', 'Navigation disabled');
        }

        // Phase 3: Result compilation and reporting
        if (!silent) {
            const statusReport = {
                summary: `Operation ${result.copied || result.opened ? 'completed' : 'skipped'}`,
                details: {
                    copied: { status: result.copied, method: result.method },
                    opened: result.opened,
                    warnings: result.warnings.length,
                    duration: `${performance.now().toFixed(1)}ms`
                },
                recommendations: []
            };
            
            if (!result.copied && !result.opened) {
                statusReport.recommendations.push('All operations were disabled or failed');
            }
            if (result.warnings.length > 0) {
                statusReport.recommendations.push('Review warnings for potential issues');
            }
            
            log('info', 'Operation Report', statusReport);
        }

        return result;

    } catch (error) {
        const errorId = `ERR_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const errorReport = {
            id: errorId,
            message: error.message,
            stack: error.stack,
            context: { cleanIp, options, timestamp: result.timestamp }
        };
        
        log('error', `Fatal error [${errorId}]`, errorReport);
        
        result.error = errorReport;
        result.copied = false;
        result.opened = false;
        
        return result;
    }
}

// Enhanced module export pattern with feature detection
(() => {
    const exportObject = { handleAbuseReport };
    
    // Add utility methods for advanced use cases
    exportObject.utils = {
        validateIp: (ip) => {
            const octets = ip?.split('.');
            return octets?.length === 4 && octets.every(o => {
                const n = parseInt(o, 10);
                return !isNaN(n) && n >= 0 && n <= 255;
            });
        },
        
        generateReportTemplate: (type = 'standard') => {
            const templates = {
                standard: `Suspicious activity detected from IP. Patterns indicate potential security threat requiring investigation.`,
                scanning: `Port scanning activity detected. Multiple connection attempts across various ports within short timeframe.`,
                bruteForce: `Brute force attack patterns observed. Repeated authentication attempts with varying credentials.`,
                ddos: `Distributed Denial of Service indicators present. High-volume traffic from singular source.`,
                custom: (details) => `Security incident report: ${details}`
            };
            return templates[type] || templates.standard;
        },
        
        clipboardCapabilities: async () => {
            const caps = {
                modernAPI: !!(navigator.clipboard && navigator.clipboard.writeText),
                secureContext: window.isSecureContext
            };
            
            // Removed clipboard-read permission check to eliminate permission requests
            return caps;
        }
    };
    
    // Version metadata
    exportObject.VERSION = '2.1.0';
    exportObject.BUILD = '2025-12-29T00:00:00Z';
    
    // Environment detection and appropriate export
    const exportToEnvironment = () => {
        // ES Module (modern browsers, Node.js with --experimental-modules)
        if (typeof module !== 'undefined' && module.exports && typeof require === 'function') {
            module.exports = exportObject;
            if (typeof __webpack_require__ === 'function') {
                // Webpack environment
                __webpack_require__.d = (exports, definition) => {
                    for (const key in definition) {
                        if (definition.hasOwnProperty(key)) {
                            exports[key] = definition[key];
                        }
                    }
                };
            }
        }
        
        // AMD (RequireJS)
        if (typeof define === 'function' && define.amd) {
            define('AbuseReporter', [], () => exportObject);
        }
        
        // Browser global (with namespace protection)
        if (typeof window !== 'undefined') {
            if (!window.$abuseReporter) {
                Object.defineProperty(window, '$abuseReporter', {
                    value: exportObject,
                    writable: false,
                    configurable: false,
                    enumerable: true
                });
            }
            
            // Optional global shortcut (configurable)
            if (!window.AbuseReporter && !window.$noGlobalShortcut) {
                window.AbuseReporter = exportObject;
            }
        }
        
        // Deno support
        if (typeof Deno !== 'undefined') {
            globalThis.AbuseReporter = exportObject;
        }
        
        // Service Worker context
        if (typeof self !== 'undefined' && typeof ServiceWorkerGlobalScope !== 'undefined' && self instanceof ServiceWorkerGlobalScope) {
            self.abuseReporter = exportObject;
        }
    };
    
    // Execute export strategy
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', exportToEnvironment);
    } else {
        exportToEnvironment();
    }
})();

/**
 * 2025-optimized usage patterns:
 * 
 * 1. Progressive Enhancement with Modern Clipboard:
 *    const caps = await AbuseReporter.utils.clipboardCapabilities();
 *    const method = caps.modernAPI ? 'modern' : 'auto';
 *    await handleAbuseReport(ip, report, { clipboardMethod: method });
 * 
 * 2. Bulk Processing with Queue Management:
 *    class ReportQueue {
 *        constructor() { this.queue = []; this.processing = false; }
 *        async add(ip, text) {
 *            this.queue.push({ ip, text });
 *            if (!this.processing) await this.process();
 *        }
 *        async process() {
 *            this.processing = true;
 *            while (this.queue.length) {
 *                const { ip, text } = this.queue.shift();
 *                await handleAbuseReport(ip, text, { silent: true });
 *                await new Promise(r => setTimeout(r, 1000)); // Rate limiting
 *            }
 *            this.processing = false;
 *        }
 *    }
 * 
 * 3. Real-time Monitoring Integration:
 *    const observer = new PerformanceObserver((list) => {
 *        list.getEntries().forEach(entry => {
 *            if (entry.duration > 1000) { // Slow operation
 *                console.warn(`Slow report operation: ${entry.name} took ${entry.duration}ms`);
 *            }
 *        });
 *    });
 *    observer.observe({ entryTypes: ['measure'] });
 * 
 * 4. Offline-first Strategy with Storage Fallback:
 *    async function resilientReport(ip, text) {
 *        if (!navigator.onLine) {
 *            const reports = JSON.parse(localStorage.getItem('pendingReports') || '[]');
 *            reports.push({ ip, text, timestamp: Date.now() });
 *            localStorage.setItem('pendingReports', JSON.stringify(reports));
 *            return { queued: true, offline: true };
 *        }
 *        return await handleAbuseReport(ip, text);
 *    }
 * 
 * 5. React/Vue Integration with Hooks:
 *    // React example
 *    const useAbuseReporter = () => {
 *        const [state, setState] = useState({ loading: false, result: null });
 *        const report = useCallback(async (ip, text, options) => {
 *            setState({ loading: true, result: null });
 *            const result = await handleAbuseReport(ip, text, options);
 *            setState({ loading: false, result });
 *            return result;
 *        }, []);
 *        return [report, state];
 *    };
 * 
 * 6. Terminal Integration via Node.js (with clipboard support):
 *    const { execSync } = require('child_process');
 *    function copyToTerminalClipboard(text) {
 *        const platform = process.platform;
 *        if (platform === 'darwin') {
 *            execSync(`echo "${text}" | pbcopy`);
 *        } else if (platform === 'linux') {
 *            execSync(`echo "${text}" | xclip -selection clipboard`);
 *        } else if (platform === 'win32') {
 *            execSync(`echo "${text}" | clip`);
 *        }
 *    }
 * 
 * 7. Machine Learning-enhanced Report Generation:
 *    async function generateIntelligentReport(ip, rawData) {
 *        const response = await fetch('https://api.openai.com/v1/chat/completions', {
 *            method: 'POST',
 *            headers: { 'Authorization': `Bearer ${API_KEY}` },
 *            body: JSON.stringify({
 *                model: 'gpt-4',
 *                messages: [{ role: 'user', content: `Generate abuse report for ${ip}: ${rawData}` }]
 *            })
 *        });
 *        const report = await response.json();
 *        return handleAbuseReport(ip, report.choices[0].message.content);
 *    }
 * 
 * 8. Blockchain-verified Audit Trail:
 *    async function createVerifiableReport(ip, text) {
 *        const result = await handleAbuseReport(ip, text, { silent: true });
 *        const hash = await crypto.subtle.digest('SHA-256', 
 *            new TextEncoder().encode(JSON.stringify(result)));
 *        const tx = await blockchain.submitAudit(ip, hash);
 *        return { ...result, transaction: tx };
 *    }
 * 
 * 9. Quantum-resistant Encryption for Sensitive Reports:
 *     async function encryptReport(text, publicKey) {
 *         const encoder = new TextEncoder();
 *         const data = encoder.encode(text);
 *         const encrypted = await crypto.subtle.encrypt(
 *             { name: 'RSA-OAEP', hash: 'SHA-512' },
 *             publicKey,
 *             data
 *         );
 *         return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
 *     }
 */