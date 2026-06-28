/**
 * Universal URL navigation with intelligent clipboard orchestration
 * Opens URL in new tab and optionally copies text to clipboard
 * 
 * @version 3.2.0
 * @author Mikhail Deynekin (mid1977@gmail.com)
 * @website https://deynekin.com
 * @license MIT
 * @copyright 2025
 * 
 * @param {string} url - Valid URL to open
 * @param {string|Object} [clipboardContent=null] - Content to copy (string or structured object)
 * @param {Object} [options={}] - Advanced configuration options
 * @param {boolean} [options.silent=false] - Suppress console output
 * @param {'auto'|'modern'|'legacy'} [options.clipboardMethod='auto'] - Force clipboard method
 * @param {string} [options.target='_blank'] - Window target attribute
 * @param {string} [options.features='noopener,noreferrer'] - Window features
 * @param {number} [options.timeout=5000] - Operation timeout in ms
 * @param {Function} [options.onBeforeOpen] - Callback before URL opening
 * @param {Function} [options.onAfterCopy] - Callback after clipboard operation
 * @returns {Promise<OperationResult>} Detailed operation status
 */
async function openUrlWithOptionalCopy(url, clipboardContent = null, options = {}) {
    const {
        silent = false,
        clipboardMethod = 'auto',
        target = '_blank',
        features = 'noopener,noreferrer',
        timeout = 5000,
        onBeforeOpen = null,
        onAfterCopy = null
    } = options;

    const result = {
        opened: false,
        copied: false,
        timestamp: new Date().toISOString(),
        method: null,
        warnings: [],
        metrics: {
            navigationStart: null,
            navigationEnd: null,
            clipboardStart: null,
            clipboardEnd: null
        }
    };

    /**
     * Modern logging system with terminal-aware formatting
     * Supports 2025 ANSI standards and graceful fallbacks
     */
    const log = (level, message, data = null) => {
        if (silent) return;
        
        const styles = {
            success: { icon: '✅', color: '\x1b[32m', reset: '\x1b[0m' },
            warning: { icon: '⚠️', color: '\x1b[33m', reset: '\x1b[0m' },
            error: { icon: '❌', color: '\x1b[31m', reset: '\x1b[0m' },
            skip: { icon: '⏭️', color: '\x1b[36m', reset: '\x1b[0m' },
            info: { icon: 'ℹ️', color: '\x1b[34m', reset: '\x1b[0m' },
            debug: { icon: '🐛', color: '\x1b[90m', reset: '\x1b[0m' }
        };
        
        const style = styles[level] || styles.info;
        const supportsANSI = typeof process !== 'undefined' && process.stdout?.isTTY;
        
        // Enhanced 2025 terminal formatting with emoji fallback
        const formattedMessage = supportsANSI 
            ? `${style.color}${style.icon}  ${message}${style.reset}`
            : `${style.icon} ${message}`;
        
        const logMethod = level === 'error' ? 'error' : 
                         level === 'debug' ? 'debug' : 
                         level === 'warn' ? 'warn' : 'log';
        
        // Structured logging for modern terminals
        if (data && typeof data === 'object') {
            console[logMethod](formattedMessage, '\n', JSON.stringify(data, null, 2));
        } else if (data) {
            console[logMethod](formattedMessage, data);
        } else {
            console[logMethod](formattedMessage);
        }
    };

    /**
     * Advanced URL validation with modern standards (2025)
     * Supports IPv6, internationalized domains, and custom protocols
     */
    const validateAndNormalizeUrl = (inputUrl) => {
        if (!inputUrl || typeof inputUrl !== 'string') {
            return { valid: false, error: 'URL must be a non-empty string' };
        }
        
        try {
            // Normalize URL for consistency
            let normalized = inputUrl.trim();
            
            // Add protocol if missing (assume https for web URLs)
            if (!normalized.match(/^[a-zA-Z][a-zA-Z\d+\-.]*:/)) {
                if (normalized.startsWith('//')) {
                    normalized = `https:${normalized}`;
                } else if (normalized.includes('.') && !normalized.startsWith('/')) {
                    normalized = `https://${normalized}`;
                } else {
                    return { valid: false, error: 'URL must include protocol' };
                }
            }
            
            // Modern URL parsing with comprehensive validation
            const urlObj = new URL(normalized);
            
            // Security validation for web URLs
            if (['http:', 'https:', 'ftp:', 'ws:', 'wss:'].includes(urlObj.protocol)) {
                // Validate hostname
                if (!urlObj.hostname) {
                    return { valid: false, error: 'URL must have a valid hostname' };
                }
                
                // Check for potentially unsafe protocols in specific contexts
                if (urlObj.protocol === 'ftp:' && typeof window !== 'undefined') {
                    result.warnings.push('FTP protocol may not be supported in browser context');
                }
            }
            
            // URL length validation (browser limits vary)
            if (normalized.length > 2000) {
                result.warnings.push(`URL length (${normalized.length}) exceeds recommended limit (2000 chars)`);
            }
            
            return {
                valid: true,
                url: normalized,
                parsed: urlObj,
                isSecure: urlObj.protocol === 'https:'
            };
            
        } catch (error) {
            return {
                valid: false,
                error: `Invalid URL format: ${error.message}`
            };
        }
    };

    /**
     * Content preparation with format detection and optimization
     * Supports plain text, HTML, and structured data
     */
    const prepareClipboardContent = (content) => {
        if (!content) return null;
        
        // Handle different content types
        if (typeof content === 'string') {
            return {
                text: content,
                html: null,
                type: 'text/plain'
            };
        }
        
        if (typeof content === 'object' && content !== null) {
            // Structured clipboard data (2025 standard)
            const prepared = {
                text: content.text || '',
                html: content.html || null,
                type: content.type || 'text/plain',
                metadata: content.metadata || {}
            };
            
            // Validate MIME types
            const allowedTypes = ['text/plain', 'text/html', 'text/rtf', 'image/png'];
            if (!allowedTypes.includes(prepared.type)) {
                result.warnings.push(`Clipboard type ${prepared.type} may not be supported`);
            }
            
            return prepared;
        }
        
        // Fallback to string conversion
        try {
            const text = String(content);
            return {
                text,
                html: null,
                type: 'text/plain'
            };
        } catch (error) {
            throw new Error(`Cannot convert content to clipboard format: ${error.message}`);
        }
    };

    /**
     * Enhanced clipboard orchestration with 2025 standards
     * Supports Clipboard API v2 and legacy methods
     */
    const orchestrateClipboardCopy = async (content, methodPreference = 'auto') => {
        result.clipboardStart = performance.now();
        let methodUsed = 'none';
        
        try {
            const preparedContent = prepareClipboardContent(content);
            if (!preparedContent) {
                throw new Error('No valid content provided for clipboard');
            }
            
            // Method selection strategy
            const selectMethod = () => {
                if (methodPreference === 'legacy') return 'legacy';
                if (methodPreference === 'modern') return 'modern';
                
                // Auto-detection with capability testing
                if (navigator.clipboard && 
                    typeof navigator.clipboard.write === 'function' &&
                    'write' in navigator.clipboard) {
                    return 'modern'; // Clipboard API v2
                }
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    return 'modern'; // Clipboard API v1
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
                throw new Error('No supported clipboard method available in this environment');
            }
            
            // Modern Clipboard API (2025 standards)
            if (selectedMethod === 'modern') {
                // Clipboard API v2 with multiple formats
                if (typeof navigator.clipboard.write === 'function') {
                    const clipboardItems = [];
                    
                    // Text content
                    if (preparedContent.text) {
                        clipboardItems.push(
                            new ClipboardItem({
                                'text/plain': new Blob([preparedContent.text], { type: 'text/plain' })
                            })
                        );
                    }
                    
                    // HTML content
                    if (preparedContent.html) {
                        clipboardItems.push(
                            new ClipboardItem({
                                'text/html': new Blob([preparedContent.html], { type: 'text/html' })
                            })
                        );
                    }
                    
                    await navigator.clipboard.write(clipboardItems);
                } 
                // Clipboard API v1 fallback
                else if (navigator.clipboard.writeText) {
                    await navigator.clipboard.writeText(preparedContent.text);
                }
            }
            
            // Legacy execCommand method (extended compatibility)
            if (selectedMethod === 'legacy') {
                const textarea = document.createElement('textarea');
                textarea.value = preparedContent.text;
                textarea.setAttribute('aria-hidden', 'true');
                textarea.setAttribute('data-clipboard-target', 'true');
                textarea.setAttribute('data-clipboard-method', 'legacy');
                
                // 2025 defensive styling - ensures element is never visible
                textarea.style.cssText = `
                    all: unset !important;
                    position: absolute !important;
                    top: -9999px !important;
                    left: -9999px !important;
                    width: 1px !important;
                    height: 1px !important;
                    opacity: 0 !important;
                    pointer-events: none !important;
                    user-select: none !important;
                    -webkit-user-select: none !important;
                    -moz-user-select: none !important;
                    -ms-user-select: none !important;
                    contain: strict !important;
                    visibility: hidden !important;
                `;
                
                // Add to DOM with shadow DOM for isolation in modern browsers
                let container = document.body;
                if (typeof document.attachShadow === 'function') {
                    const shadow = document.createElement('div').attachShadow({ mode: 'closed' });
                    shadow.appendChild(textarea);
                    container = shadow.host;
                }
                
                document.body.appendChild(container);
                
                try {
                    // Multiple selection strategies
                    if (typeof textarea.select === 'function') {
                        textarea.select();
                    } else {
                        const range = document.createRange();
                        range.selectNodeContents(textarea);
                        const selection = window.getSelection();
                        if (selection) {
                            selection.removeAllRanges();
                            selection.addRange(range);
                        }
                    }
                    
                    textarea.setSelectionRange(0, textarea.value.length);
                    
                    // Focus management
                    if (typeof textarea.focus === 'function') {
                        textarea.focus({ preventScroll: true });
                    }
                    
                    // Execute copy command
                    const success = document.execCommand('copy');
                    if (!success) {
                        throw new Error('execCommand returned false');
                    }
                    
                    // Clean selection
                    if (window.getSelection) {
                        if (typeof window.getSelection().removeAllRanges === 'function') {
                            window.getSelection().removeAllRanges();
                        } else if (typeof window.getSelection().empty === 'function') {
                            window.getSelection().empty();
                        }
                    }
                } finally {
                    // Guaranteed cleanup with timeout fallback
                    const cleanup = () => {
                        if (container.parentNode) {
                            container.parentNode.removeChild(container);
                        }
                    };
                    
                    // Immediate cleanup with fallback
                    try {
                        cleanup();
                    } catch {
                        setTimeout(cleanup, 0);
                    }
                }
            }
            
            result.clipboardEnd = performance.now();
            const duration = (result.clipboardEnd - result.clipboardStart).toFixed(2);
            
            log('success', `Copied ${preparedContent.type} via ${selectedMethod} in ${duration}ms`);
            
            // Execute callback if provided
            if (typeof onAfterCopy === 'function') {
                try {
                    onAfterCopy(preparedContent, selectedMethod);
                } catch (callbackError) {
                    log('warning', 'onAfterCopy callback error', callbackError);
                }
            }
            
            return true;
            
        } catch (error) {
            result.clipboardEnd = performance.now();
            
            const errorDetails = {
                method: methodUsed,
                error: error.message,
                userAgent: navigator.userAgent,
                secureContext: window.isSecureContext,
                clipboardTypes: navigator.clipboard?.types || [],
                permissions: (await navigator.permissions?.query({ name: 'clipboard-write' }))?.state
            };
            
            log('error', 'Clipboard operation failed', errorDetails);
            
            // Emergency fallback for terminal environments
            if (typeof process !== 'undefined' && process.stdout) {
                const contentText = typeof content === 'string' ? content : JSON.stringify(content);
                log('info', 'Terminal fallback - content available for manual copy:');
                console.log(contentText);
            }
            
            return false;
        }
    };

    /**
     * Intelligent window management with 2025 security standards
     * Supports advanced features and fallbacks
     */
    const openIntelligentWindow = (targetUrl, windowOptions = {}) => {
        result.navigationStart = performance.now();
        
        try {
            // Pre-open callback
            if (typeof onBeforeOpen === 'function') {
                try {
                    onBeforeOpen(targetUrl, windowOptions);
                } catch (callbackError) {
                    log('warning', 'onBeforeOpen callback error', callbackError);
                }
            }
            
            // Modern window opening with enhanced features
            const defaultFeatures = {
                noopener: true,
                noreferrer: true,
                resizable: 'yes',
                scrollbars: 'yes',
                toolbar: 'no',
                location: 'no',
                status: 'no',
                menubar: 'no'
            };
            
            const mergedFeatures = { ...defaultFeatures, ...windowOptions };
            
            // Convert features object to string
            const featuresString = Object.entries(mergedFeatures)
                .map(([key, value]) => value === true ? key : `${key}=${value}`)
                .join(',');
            
            // Primary strategy: window.open with modern API
            let newWindow = null;
            
            // Use window.open in user gesture context
            newWindow = window.open(targetUrl, target, featuresString);
            
            // Popup blocker detection and fallback strategies
            if (!newWindow || newWindow.closed || typeof newWindow.closed === 'undefined') {
                log('warning', 'Popup blocked - attempting fallback strategies');
                
                // Strategy 1: Form submission (most compatible)
                try {
                    const form = document.createElement('form');
                    form.action = targetUrl;
                    form.target = target;
                    form.method = 'GET';
                    form.style.display = 'none';
                    form.rel = 'noopener noreferrer';
                    
                    document.body.appendChild(form);
                    form.submit();
                    document.body.removeChild(form);
                    
                    log('info', 'Using form submission fallback');
                    result.navigationEnd = performance.now();
                    return true;
                } catch (formError) {
                    log('debug', 'Form fallback failed', formError);
                }
                
                // Strategy 2: Programmatic link click
                try {
                    const link = document.createElement('a');
                    link.href = targetUrl;
                    link.target = target;
                    link.rel = 'noopener noreferrer';
                    link.setAttribute('aria-hidden', 'true');
                    link.style.cssText = `
                        position: absolute;
                        top: -9999px;
                        left: -9999px;
                        opacity: 0;
                        pointer-events: none;
                    `;
                    
                    document.body.appendChild(link);
                    
                    // Simulate click with multiple methods
                    if (typeof link.click === 'function') {
                        link.click();
                    } else {
                        const event = new MouseEvent('click', {
                            view: window,
                            bubbles: true,
                            cancelable: true
                        });
                        link.dispatchEvent(event);
                    }
                    
                    // Cleanup with delay
                    setTimeout(() => {
                        if (link.parentNode) {
                            link.parentNode.removeChild(link);
                        }
                    }, 1000);
                    
                    log('info', 'Using link click fallback');
                    result.navigationEnd = performance.now();
                    return true;
                } catch (linkError) {
                    log('debug', 'Link fallback failed', linkError);
                }
                
                // Strategy 3: Window location (if same tab is acceptable)
                if (target === '_self' || target === '_parent' || target === '_top') {
                    try {
                        window.location.href = targetUrl;
                        result.navigationEnd = performance.now();
                        return true;
                    } catch (locationError) {
                        log('error', 'Location fallback failed', locationError);
                    }
                }
                
                // All strategies failed
                log('error', 'All window opening methods failed');
                result.navigationEnd = performance.now();
                return false;
            }
            
            // Post-open security hardening
            try {
                // Nullify opener reference
                if (newWindow.opener) {
                    newWindow.opener = null;
                    Object.defineProperty(newWindow, 'opener', {
                        value: null,
                        writable: false,
                        configurable: false,
                        enumerable: false
                    });
                }
                
                // Add security headers if possible
                if (newWindow.document) {
                    newWindow.document.addEventListener('DOMContentLoaded', () => {
                        try {
                            const meta = newWindow.document.createElement('meta');
                            meta.httpEquiv = 'Content-Security-Policy';
                            meta.content = "default-src 'self'";
                            newWindow.document.head.appendChild(meta);
                        } catch {
                            // Silently fail on cross-origin restrictions
                        }
                    });
                }
            } catch (securityError) {
                // Security hardening may fail due to cross-origin restrictions
                log('debug', 'Security hardening limited', securityError);
            }
            
            // Focus management with intelligent timing
            setTimeout(() => {
                try {
                    if (newWindow && !newWindow.closed) {
                        newWindow.focus();
                        
                        // Additional focus reinforcement for stubborn browsers
                        if (newWindow.document && newWindow.document.hasFocus && !newWindow.document.hasFocus()) {
                            setTimeout(() => newWindow.focus(), 100);
                        }
                    }
                } catch (focusError) {
                    // Focus may be restricted by browser policy
                    log('debug', 'Focus management restricted', focusError);
                }
            }, 300);
            
            result.navigationEnd = performance.now();
            const duration = (result.navigationEnd - result.navigationStart).toFixed(2);
            
            log('success', `Window opened in ${duration}ms`);
            return true;
            
        } catch (error) {
            result.navigationEnd = performance.now();
            
            log('error', 'Window opening failed', {
                error: error.message,
                url: targetUrl,
                target,
                secureContext: window.isSecureContext
            });
            
            return false;
        }
    };

    // Main execution flow with timeout protection
    try {
        // Phase 1: Input validation
        const urlValidation = validateAndNormalizeUrl(url);
        if (!urlValidation.valid) {
            log('error', `URL validation failed: ${urlValidation.error}`);
            result.error = `Invalid URL: ${urlValidation.error}`;
            return result;
        }

        const normalizedUrl = urlValidation.url;
        
        // Phase 2: Clipboard operations (conditional)
        if (clipboardContent !== null && clipboardContent !== undefined) {
            // Set timeout for clipboard operation
            const clipboardPromise = orchestrateClipboardCopy(clipboardContent, clipboardMethod);
            const timeoutPromise = new Promise((_, reject) => 
                setTimeout(() => reject(new Error('Clipboard operation timeout')), timeout)
            );
            
            result.copied = await Promise.race([clipboardPromise, timeoutPromise]);
        } else {
            log('skip', 'Clipboard copy skipped (no content provided)');
        }

        // Phase 3: Navigation operations
        const windowOptions = {
            target,
            features: typeof features === 'string' ? features : Object.entries(features)
                .map(([key, value]) => `${key}=${value}`)
                .join(',')
        };
        
        result.opened = openIntelligentWindow(normalizedUrl, windowOptions);

        // Phase 4: Metrics and reporting
        if (!silent) {
            const totalTime = performance.now() - Math.min(
                result.navigationStart || Infinity,
                result.clipboardStart || Infinity
            );
            
            const metricsReport = {
                summary: 'Operation completed',
                metrics: {
                    totalTime: `${totalTime.toFixed(1)}ms`,
                    navigationTime: result.navigationEnd && result.navigationStart 
                        ? `${(result.navigationEnd - result.navigationStart).toFixed(1)}ms`
                        : 'N/A',
                    clipboardTime: result.clipboardEnd && result.clipboardStart 
                        ? `${(result.clipboardEnd - result.clipboardStart).toFixed(1)}ms`
                        : 'N/A',
                    urlLength: normalizedUrl.length,
                    secure: urlValidation.isSecure
                },
                operations: {
                    opened: result.opened,
                    copied: result.copied,
                    method: result.method
                },
                warnings: result.warnings.length > 0 ? result.warnings : 'None'
            };
            
            log('info', 'Performance Report', metricsReport);
        }

        return result;

    } catch (error) {
        const errorId = `URL_ERR_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const errorReport = {
            id: errorId,
            message: error.message,
            stack: error.stack,
            context: { url, clipboardContent, options, timestamp: result.timestamp }
        };
        
        log('error', `Fatal error [${errorId}]`, errorReport);
        
        result.error = errorReport;
        result.opened = false;
        result.copied = false;
        
        return result;
    }
}

// Enhanced export pattern with versioning and feature detection
(() => {
    const exportObject = { 
        handleAbuseReport, // Original function
        openUrlWithOptionalCopy // New function
    };
    
    // Add utility methods
    exportObject.utils = {
        ...exportObject.utils,
        
        // URL utilities
        validateUrl: (url) => {
            try {
                new URL(url);
                return true;
            } catch {
                return false;
            }
        },
        
        normalizeUrl: (url, defaultProtocol = 'https') => {
            if (!url) return null;
            if (url.startsWith('//')) return `${defaultProtocol}:${url}`;
            if (!url.match(/^[a-zA-Z][a-zA-Z\d+\-.]*:/)) {
                return `${defaultProtocol}://${url}`;
            }
            return url;
        },
        
        // Clipboard capabilities detection
        detectClipboardCapabilities: async () => {
            const caps = {
                modernAPI: !!(navigator.clipboard && navigator.clipboard.writeText),
                modernWrite: !!(navigator.clipboard && typeof navigator.clipboard.write === 'function'),
                secureContext: window.isSecureContext,
                permissions: null
            };
            
            // Check permissions if available
            if (navigator.permissions && typeof navigator.permissions.query === 'function') {
                try {
                    const clipboardWrite = await navigator.permissions.query({ name: 'clipboard-write' });
                    caps.permissions = clipboardWrite.state;
                } catch {
                    // Permission API not fully supported
                }
            }
            
            return caps;
        },
        
        // Window capabilities
        detectWindowFeatures: () => {
            return {
                popupBlocker: 'open' in window && (() => {
                    const testWindow = window.open('', '_blank', 'width=1,height=1');
                    if (!testWindow) return true;
                    testWindow.close();
                    return false;
                })(),
                screen: {
                    width: window.screen?.width || 0,
                    height: window.screen?.height || 0,
                    availWidth: window.screen?.availWidth || 0,
                    availHeight: window.screen?.availHeight || 0
                }
            };
        }
    };
    
    // Version metadata
    exportObject.VERSION = {
        core: '3.0.0',
        api: '2025.1',
        build: new Date().toISOString(),
        features: ['clipboard-v2', 'secure-navigation', 'terminal-friendly', 'async-timeouts']
    };
    
    // Environment-aware export
    const exportToEnvironment = () => {
        // CommonJS
        if (typeof module !== 'undefined' && module.exports && typeof require === 'function') {
            module.exports = exportObject;
        }
        
        // AMD
        if (typeof define === 'function' && define.amd) {
            define('UrlClipboardOrchestrator', [], () => exportObject);
        }
        
        // Browser global with namespace protection
        if (typeof window !== 'undefined') {
            if (!window.$urlUtils) {
                Object.defineProperty(window, '$urlUtils', {
                    value: exportObject,
                    writable: false,
                    configurable: false,
                    enumerable: true
                });
            }
            
            // Global shortcut with conflict protection
            if (!window.UrlClipboardOrchestrator && !window.$noGlobalShortcut) {
                window.UrlClipboardOrchestrator = exportObject;
            }
        }
        
        // GlobalThis for modern environments
        if (typeof globalThis !== 'undefined') {
            globalThis.UrlClipboardOrchestrator = exportObject;
        }
        
        // Worker contexts
        if (typeof self !== 'undefined') {
            self.urlClipboardOrchestrator = exportObject;
        }
    };
    
    // Execute export
    if (typeof document !== 'undefined' && document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', exportToEnvironment);
    } else {
        exportToEnvironment();
    }
})();

/**
 * 2025 Usage Examples:
 * 
 * 1. Basic URL opening with text copy:
 *    await openUrlWithOptionalCopy(
 *        'https://example.com',
 *        'Text to copy',
 *        { silent: true }
 *    );
 * 
 * 2. URL only (no clipboard):
 *    await openUrlWithOptionalCopy('https://example.com');
 * 
 * 3. Advanced clipboard with HTML content:
 *    await openUrlWithOptionalCopy(
 *        'https://example.com',
 *        {
 *            text: 'Plain text',
 *            html: '<b>HTML content</b>',
 *            type: 'text/html'
 *        },
 *        { clipboardMethod: 'modern' }
 *    );
 * 
 * 4. Custom window features:
 *    await openUrlWithOptionalCopy(
 *        'https://example.com',
 *        'Copy me',
 *        {
 *            target: '_blank',
 *            features: 'width=800,height=600,resizable=yes',
 *            onBeforeOpen: (url) => console.log(`Opening: ${url}`),
 *            onAfterCopy: (content) => console.log(`Copied: ${content.text}`)
 *        }
 *    );
 * 
 * 5. Integration with existing AbuseIPDB workflow:
 *    async function enhancedAbuseReport(ip, text) {
 *        const reportResult = await handleAbuseReport(ip, text);
 *        const url = `https://www.abuseipdb.com/check/${ip}`;
 *        const urlResult = await openUrlWithOptionalCopy(url, text);
 *        return { report: reportResult, lookup: urlResult };
 *    }
 * 
 * 6. Bulk processing with queue:
 *    class UrlBatchProcessor {
 *        constructor() {
 *            this.queue = [];
 *            this.results = [];
 *        }
 *        async add(url, text = null) {
 *            this.queue.push({ url, text });
 *            if (this.queue.length === 1) this.process();
 *        }
 *        async process() {
 *            while (this.queue.length) {
 *                const { url, text } = this.queue.shift();
 *                const result = await openUrlWithOptionalCopy(url, text, { silent: true });
 *                this.results.push(result);
 *                await new Promise(r => setTimeout(r, 100)); // Rate limiting
 *            }
 *        }
 *    }
 * 
 * 7. React/Vue integration:
 *    // React hook
 *    const useUrlWithCopy = () => {
 *        const [state, setState] = useState({ loading: false, result: null });
 *        const execute = useCallback(async (url, text, options) => {
 *            setState({ loading: true, result: null });
 *            const result = await openUrlWithOptionalCopy(url, text, options);
 *            setState({ loading: false, result });
 *            return result;
 *        }, []);
 *        return [execute, state];
 *    };
 * 
 * 8. Terminal/Node.js adaptation:
 *    if (typeof process !== 'undefined' && process.stdout) {
 *        const open = require('open');
 *        const { execSync } = require('child_process');
 *        
 *        async function terminalUrlWithCopy(url, text) {
 *            await open(url);
 *            if (text) {
 *                const platform = process.platform;
 *                if (platform === 'darwin') {
 *                    execSync(`echo "${text.replace(/"/g, '\\"')}" | pbcopy`);
 *                } else if (platform === 'linux') {
 *                    execSync(`echo "${text.replace(/"/g, '\\"')}" | xclip -selection clipboard`);
 *                } else if (platform === 'win32') {
 *                    execSync(`echo "${text}" | clip`);
 *                }
 *            }
 *        }
 *    }
 */