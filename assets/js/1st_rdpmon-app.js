/**
 * RDP Monitor Application JavaScript
 * Main application logic for RDP Security Monitoring Dashboard
 * 
 * @version 3.2.0
 * @author Mikhail Deynekin (mid1977@gmail.com)
 * @website https://deynekin.com
 * @license MIT
 * @copyright 2025
 */

// Debug mode flag
const DEBUG = true;
let isInitialized = false;

// Global application namespace with encapsulated state
const RDP_Monitor_App = (function() {
	/**
	 * Application State Management
	 * Centralized state object for managing application data and settings
	 */
	const APP_STATE = {
		// Data collections
		data: null,
		addrData: [],
		sessionData: [],
		propData: [],
		databaseStats: {},
		
		// UI state
		filteredAddrData: [],
		currentFilter: 'all',
		currentSort: { field: 'last', direction: 'desc' },
		currentPage: 1,
		pageSize: 10,
		
		// Auto-refresh management
		autoRefreshInterval: 30,
		autoRefreshTimer: null,
		
		// Chart management
		charts: {
			timeline: null,
			distribution: null
		},
		currentTimelinePeriod: 'month',
		chartDistributionLimit: 10,
		
		// Navigation state
		currentTab: 'connections',
		theme: 'light',
		
		/**
		 * User Settings Configuration
		 * Persistent settings with local storage integration
		 */
		settings: {
			// IP Information Service
			ipInfoService: 'ripe',
			
			// Chart preferences
			defaultChartPeriod: 'month',
			chartItemsLimit: 10,
			
			// UI preferences
			themeMode: 'auto',
			tableDensity: 'normal',
			animationLevel: 'minimal',
			pageWidth: 'full',
			
			// Application behavior
			autoRefreshInterval: 30,
			itemsPerPage: 10
		}
	};

	/**
	 * DOM Elements Cache
	 * Centralized reference to all DOM elements for performance optimization
	 */
	const DOM = {};

/**
 * Initialize Application
 * Main entry point for setting up the RDP Monitor dashboard
 * 
 * @param {Object} config - Configuration object with template variables
 */
function init(config) {
    if (isInitialized) {
        DEBUG && console.log('⚠️ Application already initialized, skipping...');
        return;
    }
    
    DEBUG && console.log('🚀 Initializing RDP Monitor Application v3.2.0...');
    
    // Store global configuration
    if (config) {
        window.GIT_URL = config.gitUrl;
        window.TEMPLATE_VARS = config.templateVars;
        window.parsePowerShellJSON = config.parsePowerShellJSON;
    }
    
    // Cache DOM elements FIRST
    cacheDOMElements();
    
    // Load persistent settings
    SettingsManager.loadSettings();
    
    // Apply settings IMMEDIATELY after loading
    SettingsManager.applySettings();

    // Initialize period button styles
    updatePeriodButtonStyles();
    
    // Parse data from PowerShell template
    parseData();
    
    // Initialize all application modules
    initTabs();
    initEventListeners();
    SettingsManager.initEventListeners();
    
    // Apply initial UI state
    applyFilter('all');
    calculateStats();
    updateMetrics();
    updateConnectionsTable();
    updateSessionsTable();
    
    // Initialize charts with current settings
    initCharts();
    
    // Start auto-refresh system
    startAutoRefresh();
    updateTime();
    
    isInitialized = true;
    DEBUG && console.log('✅ RDP Monitor Application initialized successfully');
}

	/**
	 * Cache DOM Elements
	 * Performance optimization by storing DOM references
	 */
	function cacheDOMElements() {
		DEBUG && console.log('🔄 Caching DOM elements...');
		
		// Header elements
		DOM.lastUpdated = document.getElementById('last-updated');
		DOM.attackCount = document.getElementById('attack-count');
		DOM.legitCount = document.getElementById('legit-count');
		DOM.failTotal = document.getElementById('fail-total');
		DOM.activeCount = document.getElementById('active-count');
		DOM.attackProgress = document.getElementById('attack-progress');
		DOM.legitProgress = document.getElementById('legit-progress');
		DOM.failRate = document.getElementById('fail-rate');
		DOM.generationTime = document.getElementById('generation-time');
		
		// Table elements
		DOM.dataTable = document.getElementById('data-table');
		DOM.sessionsTable = document.getElementById('sessions-table');
		DOM.tableCount = document.getElementById('table-count');
		DOM.totalRecords = document.getElementById('total-records');
		DOM.sessionCount = document.getElementById('session-count');
		DOM.pageInfo = document.getElementById('page-info');
		DOM.prevPage = document.getElementById('prev-page');
		DOM.nextPage = document.getElementById('next-page');
		DOM.tableSearch = document.getElementById('table-search');
		
		// Control elements
		DOM.refreshInterval = document.getElementById('refresh-interval');
		DOM.intervalValue = document.getElementById('interval-value');
		DOM.footerInterval = document.getElementById('footer-interval');
		DOM.refreshBtn = document.getElementById('refresh-btn');
		DOM.themeToggle = document.getElementById('theme-toggle');
		DOM.themeIcon = document.getElementById('theme-icon');
		DOM.filterAll = document.getElementById('filter-all');
		DOM.filterAttack = document.getElementById('filter-attack');
		DOM.filterLegit = document.getElementById('filter-legit');
		DOM.exportBtn = document.getElementById('export-btn');
		
		// Chart elements
		DOM.timelineChart = document.getElementById('timelineChart');
		DOM.distributionChart = document.getElementById('distributionChart');
		DOM.distributionLimit = document.getElementById('distribution-limit');
		DOM.distributionLegend = document.getElementById('distribution-legend');
		
		// Tab elements
		DOM.tabConnections = document.getElementById('tab-connections');
		DOM.tabSessions = document.getElementById('tab-sessions');
		DOM.tabMetrics = document.getElementById('tab-metrics');
		DOM.tabSettings = document.getElementById('tab-settings');
		DOM.connectionsTab = document.getElementById('connections-tab');
		DOM.sessionsTab = document.getElementById('sessions-tab');
		DOM.metricsTab = document.getElementById('metrics-tab');
		DOM.settingsTab = document.getElementById('settings-tab');
		
		// Metrics elements
		DOM.lastAddrChange = document.getElementById('last-addr-change');
		DOM.lastSessionChange = document.getElementById('last-session-change');
		DOM.totalCollections = document.getElementById('total-collections');
		DOM.totalAddrRecords = document.getElementById('total-addr-records');
		DOM.totalSessionRecords = document.getElementById('total-session-records');
		DOM.uniqueIps = document.getElementById('unique-ips');
		DOM.reportGenerated = document.getElementById('report-generated');
		DOM.autoRefreshStatus = document.getElementById('auto-refresh-status');
		DOM.dbPath = document.getElementById('db-path');
		
		// Settings elements
		DOM.ipInfoService = document.getElementById('ip-info-service');
		DOM.defaultChartPeriod = document.getElementById('default-chart-period');
		DOM.chartItemsLimit = document.getElementById('chart-items-limit');
		DOM.pageSizeSelect = document.getElementById('page-size-select');
		DOM.settingsRefreshInterval = document.getElementById('settings-refresh-interval');
		DOM.settingsIntervalValue = document.getElementById('settings-interval-value');
		DOM.saveSettings = document.getElementById('save-settings');
		DOM.resetSettings = document.getElementById('reset-settings');
		DOM.clearStorage = document.getElementById('clear-storage');
		
		// Footer elements
		DOM.dbInfo = document.getElementById('db-info');
		DOM.reportId = document.getElementById('report-id');
		
		DEBUG && console.log(`✅ DOM elements cached: ${Object.keys(DOM).length} elements`);
	}

	/**
	 * Utility Functions
	 * Collection of helper functions for common operations
	 */
	const Utils = {
		/**
		 * Format date string to localized display format
		 * 
		 * @param {string} dateString - ISO date string
		 * @returns {string} Formatted date string
		 */
		formatDate: (dateString) => {
			try {
				if (!dateString || dateString === 'null' || dateString === 'undefined') return 'N/A';
				const date = new Date(dateString);
				if (isNaN(date.getTime())) return 'Invalid date';
				return date.toLocaleDateString() + ' ' + date.toLocaleTimeString([], { 
					hour: '2-digit', 
					minute: '2-digit',
					second: '2-digit'
				});
			} catch {
				return dateString || 'N/A';
			}
		},
		
		/**
		 * Format duration object to human-readable string
		 * 
		 * @param {Object} duration - Duration object with Days, Hours, Minutes, Seconds
		 * @returns {string} Formatted duration string
		 */
		formatDuration: (duration) => {
			if (!duration || typeof duration !== 'object') return 'N/A';
			const days = duration.Days || 0;
			const hours = duration.Hours || 0;
			const minutes = duration.Minutes || 0;
			const seconds = duration.Seconds || 0;
			
			if (days > 0) return `${days}d ${hours}h ${minutes}m`;
			if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
			if (minutes > 0) return `${minutes}m ${seconds}s`;
			if (seconds > 0) return `${seconds}s`;
			return '<1s';
		},
		
		/**
		 * Format session duration for display
		 * 
		 * @param {Object} duration - Session duration object
		 * @returns {string} Formatted session duration
		 */
		formatSessionDuration: (duration) => {
			if (!duration || typeof duration !== 'object') return 'N/A';
			const totalMinutes = duration.TotalMinutes || 0;
			if (totalMinutes > 60) {
				const hours = Math.floor(totalMinutes / 60);
				const minutes = Math.round(totalMinutes % 60);
				return `${hours}h ${minutes}m`;
			}
			return `${Math.round(totalMinutes)}m`;
		},
		
		/**
		 * Get color scheme for connection type
		 * 
		 * @param {string} type - Connection type (attack, legit, mixed, unknown)
		 * @returns {Object} Color configuration object
		 */
		getTypeColor: (type) => {
			if (!type) type = 'Unknown';
			switch(type.toLowerCase()) {
				case 'attack': return { 
					bg: 'bg-danger-100 dark:bg-danger-900/30', 
					text: 'text-danger-700 dark:text-danger-300', 
					icon: 'fa-skull-crossbones' 
				};
				case 'legit': return { 
					bg: 'bg-success-100 dark:bg-success-900/30', 
					text: 'text-success-700 dark:text-success-300', 
					icon: 'fa-check-circle' 
				};
				case 'mixed': return { 
					bg: 'bg-blue-100 dark:bg-blue-900/30', 
					text: 'text-blue-700 dark:text-blue-300', 
					icon: 'fa-exchange-alt' 
				};
				default: return { 
					bg: 'bg-gray-100 dark:bg-gray-800', 
					text: 'text-gray-700 dark:text-gray-300', 
					icon: 'fa-question-circle' 
				};
			}
		},
		
		/**
		 * Get color scheme for session type
		 * 
		 * @param {string} type - Session type
		 * @returns {Object} Color configuration object
		 */
		getSessionTypeColor: (type) => {
			if (!type) type = 'Unknown';
			switch(type.toLowerCase()) {
				case 'long': return { 
					bg: 'bg-purple-100 dark:bg-purple-900/30', 
					text: 'text-purple-700 dark:text-purple-300' 
				};
				case 'short': return { 
					bg: 'bg-yellow-100 dark:bg-yellow-900/30', 
					text: 'text-yellow-700 dark:text-yellow-300' 
				};
				case 'remote': return { 
					bg: 'bg-blue-100 dark:bg-blue-900/30', 
					text: 'text-blue-700 dark:text-blue-300' 
				};
				case 'local': return { 
					bg: 'bg-green-100 dark:bg-green-900/30', 
					text: 'text-green-700 dark:text-green-300' 
				};
				default: return { 
					bg: 'bg-gray-100 dark:bg-gray-800', 
					text: 'text-gray-700 dark:text-gray-300' 
				};
			}
		},
		
		/**
		 * Copy text to clipboard with visual feedback
		 * 
		 * @param {string} text - Text to copy
		 */
		copyToClipboard: (text) => {
			navigator.clipboard.writeText(text).then(() => {
				const notification = document.createElement('div');
				notification.className = 'fixed top-4 right-4 px-4 py-2 bg-green-500 text-white rounded-lg shadow-lg z-50 fade-in';
				notification.textContent = `Copied: ${text.substring(0, 20)}...`;
				document.body.appendChild(notification);
				setTimeout(() => {
					notification.style.opacity = '0';
					notification.style.transition = 'opacity 0.3s';
					setTimeout(() => notification.remove(), 300);
				}, 2000);
			}).catch(err => {
				DEBUG && console.error('Failed to copy:', err);
			});
		},
		
		/**
		 * Copy attack description to clipboard
		 * 
		 * @param {string} description - Attack description text
		 */
		copyAttackDescription: (description) => {
			navigator.clipboard.writeText(description).then(() => {
				const notification = document.createElement('div');
				notification.className = 'fixed top-4 right-4 px-4 py-2 bg-green-500 text-white rounded-lg shadow-lg z-50 fade-in';
				notification.innerHTML = '<i class="fas fa-check mr-2"></i>Attack description copied to clipboard';
				document.body.appendChild(notification);
				setTimeout(() => {
					notification.style.opacity = '0';
					setTimeout(() => notification.remove(), 300);
				}, 2000);
			}).catch(err => {
				DEBUG && console.error('Failed to copy:', err);
			});
		},
		
		/**
		 * Open AbuseIPDB check for IP address
		 * 
		 * @param {string} ip - IP address to check
		 */
		openAbuseIPDBCheck: (ip) => {
			const cleanIp = ip.replace(/"/g, '');
			DEBUG && console.log('🔍 Opening AbuseIPDB check for IP:', cleanIp);
			(async () => {
				await openUrlWithOptionalCopy(`https://www.abuseipdb.com/check/${cleanIp}`);
			})();
		},
		
		/**
		 * Open AbuseIPDB report for IP address
		 * 
		 * @param {string} ip - IP address to report
		 * @param {string} attackDescription - Description of the attack
		 */
		openAbuseIPDBReport: (ip, attackDescription = '') => {
			(async () => {
				try {
					const cleanIp = ip.replace(/"/g, '');
					const reportText = `${attackDescription}\n\nReported via RDP Monitor: ${window.GIT_URL || 'https://github.com/paulmann/RDPAudit'}`;
					
					if (typeof AbuseReporter !== 'undefined') {
						const caps = await AbuseReporter.utils.clipboardCapabilities();
						const method = caps.modernAPI ? 'modern' : 'auto';
						
						await handleAbuseReport(cleanIp, reportText, { 
							clipboardMethod: method,
							copyEncoded: false
						});
					} else {
						// Fallback to simple URL open
						window.open(`https://www.abuseipdb.com/report/${cleanIp}`, '_blank');
					}
				} catch (error) {
					DEBUG && console.error('Error in main execution:', error);
				}
			})();
		},
		
		/**
		 * Open IP information using configured service
		 * 
		 * @param {string} ip - IP address to lookup
		 */
		openIpInfo: (ip) => {
			// Get service from saved settings, localStorage, or default
			let service = 'ripe'; // Default fallback
			
			// Check localStorage first for immediate access
			const savedSettings = localStorage.getItem('rdpmon-settings');
			if (savedSettings) {
				try {
					const parsed = JSON.parse(savedSettings);
					service = parsed.ipInfoService || 'ripe';
					DEBUG && console.log('🌐 Using saved IP service:', service);
				} catch (e) {
					DEBUG && console.error('Error parsing saved settings:', e);
				}
			}
			
			// Use APP_STATE as backup
			if (APP_STATE.settings && APP_STATE.settings.ipInfoService) {
				service = APP_STATE.settings.ipInfoService;
			}
			
			const url = getIpServiceUrl(service, ip);
			DEBUG && console.log('🌐 Opening IP info URL:', url);
			
			(async () => {
				await openUrlWithOptionalCopy(url);
			})();
		},
		
		/**
		 * Open GitHub project page
		 */
		openGitHubProject: () => {
			DEBUG && console.log('🐙 Opening GitHub project');
			(async () => {
				await openUrlWithOptionalCopy(window.GIT_URL || 'https://github.com/paulmann/RDPAudit');
			})();
		},
		
		/**
		 * Show confirmation dialog for IP blocking
		 * 
		 * @param {string} ip - IP address to block
		 */
		blockIPInFirewall: (ip) => {
			if (confirm(`Block IP address ${ip} in Windows Firewall?\n\nThis will create a firewall rule to block all incoming RDP connections from this IP.`)) {
				const notification = document.createElement('div');
				notification.className = 'fixed top-4 right-4 px-4 py-2 bg-red-500 text-white rounded-lg shadow-lg z-50 fade-in';
				notification.innerHTML = `<i class="fas fa-shield-alt mr-2"></i>Blocking IP: ${ip}`;
				document.body.appendChild(notification);
				setTimeout(() => {
					notification.style.opacity = '0';
					setTimeout(() => notification.remove(), 300);
				}, 3000);
			}
		},
		
		/**
		 * Debounce function for performance optimization
		 * 
		 * @param {Function} func - Function to debounce
		 * @param {number} wait - Debounce wait time in ms
		 * @returns {Function} Debounced function
		 */
		debounce: (func, wait) => {
			let timeout;
			return (...args) => {
				clearTimeout(timeout);
				timeout = setTimeout(() => func.apply(this, args), wait);
			};
		},
		
		/**
		 * Show notification toast
		 * 
		 * @param {string} message - Notification message
		 * @param {string} type - Notification type (success, error, warning)
		 */
		showNotification: (message, type = 'success') => {
			const notification = document.createElement('div');
			notification.className = `fixed top-4 right-4 px-4 py-3 rounded-lg shadow-lg z-50 flex items-center space-x-2 fade-in ${
				type === 'error' ? 'bg-red-500' : 
				type === 'warning' ? 'bg-yellow-500' : 'bg-green-500'
			} text-white`;
			notification.innerHTML = `
				<i class="fas ${type === 'error' ? 'fa-exclamation-circle' : 
							   type === 'warning' ? 'fa-exclamation-triangle' : 'fa-check-circle'}"></i>
				<span>${message}</span>
			`;
			document.body.appendChild(notification);
			
			setTimeout(() => {
				notification.style.opacity = '0';
				notification.style.transition = 'opacity 0.3s';
				setTimeout(() => notification.remove(), 300);
			}, 3000);
		},
		
		/**
		 * Escape HTML to prevent XSS attacks
		 * 
		 * @param {string} text - Text to escape
		 * @returns {string} Escaped HTML string
		 */
		escapeHtml: (text) => {
			if (!text) return '';
			const map = {
				'&': '&amp;',
				'<': '&lt;',
				'>': '&gt;',
				'"': '&quot;',
				"'": '&#039;',
				'`': '&#096;',
				'\n': '\\n',
				'\r': '\\r',
				'\t': '\\t'
			};
			return String(text).replace(/[&<>"'`\n\r\t]/g, function(m) { return map[m]; });
		}
	};

	/**
	 * Data Processing Functions
	 */
	
	/**
	 * Parse data from PowerShell template
	 */
	function parseData() {
		try {
			// Parse the data from PowerShell
			const jsonData = window.parsePowerShellJSON(window.TEMPLATE_VARS.DATA_JSON);
			
			APP_STATE.data = jsonData;
			APP_STATE.addrData = jsonData.AddrData || [];
			APP_STATE.sessionData = jsonData.SessionData || [];
			APP_STATE.propData = jsonData.PropData || [];
			APP_STATE.databaseStats = jsonData.DatabaseStats || {};
			
			DEBUG && console.log('📊 Data parsed:', {
				addrData: APP_STATE.addrData.length,
				sessionData: APP_STATE.sessionData.length,
				propData: APP_STATE.propData.length
			});
		} catch (error) {
			DEBUG && console.error('❌ Error parsing data:', error);
			Utils.showNotification('Error parsing data', 'error');
		}
	}
	
	/**
	 * Apply filter to connection data
	 * 
	 * @param {string} filterType - Filter type (all, attack, legit)
	 */
	function applyFilter(filterType) {
		DEBUG && console.log('🔍 Applying filter:', filterType);
		APP_STATE.currentFilter = filterType;
		switch(filterType) {
			case 'attack':
				APP_STATE.filteredAddrData = APP_STATE.addrData.filter(item => 
					item.ConnectionType && item.ConnectionType.toLowerCase() === 'attack'
				);
				break;
			case 'legit':
				APP_STATE.filteredAddrData = APP_STATE.addrData.filter(item => 
					item.ConnectionType && item.ConnectionType.toLowerCase() === 'legit'
				);
				break;
			default:
				APP_STATE.filteredAddrData = [...APP_STATE.addrData];
		}
		APP_STATE.currentPage = 1;
		applySort();
	}
	
/**
 * Apply sorting to filtered data
 * 
 * @param {string} field - Field to sort by
 */
function applySort(field = APP_STATE.currentSort.field) {
    DEBUG && console.log('📊 Applying sort:', field, 'current direction:', APP_STATE.currentSort.direction);
    
    // If clicking on same field, toggle direction
    // If clicking on different field, set to descending
    if (APP_STATE.currentSort.field === field) {
        APP_STATE.currentSort.direction = APP_STATE.currentSort.direction === 'asc' ? 'desc' : 'asc';
    } else {
        APP_STATE.currentSort.field = field;
        APP_STATE.currentSort.direction = 'desc'; // Changed from 'asc' to 'desc'
    }
    
    DEBUG && console.log('📊 New sort state:', APP_STATE.currentSort);
    
    APP_STATE.filteredAddrData.sort((a, b) => {
        let aVal, bVal;
        
        switch (field) {
            case 'ip':
                aVal = (a.IP || '').toLowerCase();
                bVal = (b.IP || '').toLowerCase();
                break;
            case 'type':
                aVal = (a.ConnectionType || '').toLowerCase();
                bVal = (b.ConnectionType || '').toLowerCase();
                break;
            case 'fails':
                aVal = parseInt(a.FailCount) || 0;
                bVal = parseInt(b.FailCount) || 0;
                break;
            case 'first':
                aVal = a.FirstLocal ? new Date(a.FirstLocal).getTime() : 0;
                bVal = b.FirstLocal ? new Date(b.FirstLocal).getTime() : 0;
                break;
            case 'last':
                aVal = a.LastLocal ? new Date(a.LastLocal).getTime() : 0;
                bVal = b.LastLocal ? new Date(b.LastLocal).getTime() : 0;
                break;
            case 'users':
                // Sort by number of users attempted
                const aUsers = Array.isArray(a.UserNames) ? a.UserNames.length : 0;
                const bUsers = Array.isArray(b.UserNames) ? b.UserNames.length : 0;
                aVal = aUsers;
                bVal = bUsers;
                break;
            default:
                aVal = a[field] || '';
                bVal = b[field] || '';
        }
        
        // For ascending order
        if (APP_STATE.currentSort.direction === 'asc') {
            if (typeof aVal === 'string' && typeof bVal === 'string') {
                return aVal.localeCompare(bVal);
            }
            return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
        } 
        // For descending order (default)
        else {
            if (typeof aVal === 'string' && typeof bVal === 'string') {
                return bVal.localeCompare(aVal);
            }
            return bVal < aVal ? -1 : bVal > aVal ? 1 : 0;
        }
    });
    
    // Save sort preference
    SettingsManager.saveSortPreference();
    
    // Update sort icons in ALL headers
    document.querySelectorAll('.sortable').forEach(header => {
        const icon = header.querySelector('i');
        if (icon) {
            if (header.dataset.sort === APP_STATE.currentSort.field) {
                icon.className = `fas fa-sort-${APP_STATE.currentSort.direction === 'asc' ? 'up' : 'down'} ml-1`;
            } else {
                icon.className = 'fas fa-sort ml-1';
            }
        }
    });
    
    updateConnectionsTable();
}
	
	/**
	 * Search connection data
	 * 
	 * @param {string} query - Search query
	 */
	function searchData(query) {
		if (!query || !query.trim()) {
			applyFilter(APP_STATE.currentFilter);
			return;
		}
		
		const searchLower = query.toLowerCase();
		APP_STATE.filteredAddrData = APP_STATE.addrData.filter(item => {
			// Search in IP
			if (item.IP && item.IP.toLowerCase().includes(searchLower)) return true;
			
			// Search in Hostname
			if (item.Hostname && item.Hostname.toLowerCase().includes(searchLower)) return true;
			
			// Search in UserNames array
			if (item.UserNames && Array.isArray(item.UserNames)) {
				return item.UserNames.some(user => 
					user && user.toLowerCase().includes(searchLower)
				);
			}
			
			return false;
		});
		
		APP_STATE.currentPage = 1;
		updateConnectionsTable();
	}
	
	/**
	 * Calculate and display statistics
	 */
	function calculateStats() {
		const total = APP_STATE.addrData.length;
		const attacks = APP_STATE.addrData.filter(item => 
			item.ConnectionType && item.ConnectionType.toLowerCase() === 'attack'
		).length;
		const legit = APP_STATE.addrData.filter(item => 
			item.ConnectionType && item.ConnectionType.toLowerCase() === 'legit'
		).length;
		
		const totalFails = APP_STATE.addrData.reduce((sum, item) => 
			sum + (parseInt(item.FailCount) || 0), 0
		);
		
		const totalSuccess = APP_STATE.addrData.reduce((sum, item) => 
			sum + (parseInt(item.SuccessCount) || 0), 0
		);
		
		const failRate = totalSuccess + totalFails > 0 ? 
			((totalFails / (totalFails + totalSuccess)) * 100).toFixed(1) : 0;
		
		// Update DOM elements
		DOM.attackCount.textContent = attacks.toLocaleString();
		DOM.legitCount.textContent = legit.toLocaleString();
		DOM.failTotal.textContent = totalFails.toLocaleString();
		DOM.failRate.textContent = `${failRate}%`;
		
		// Update progress bars
		DOM.attackProgress.style.width = total > 0 ? `${(attacks / total) * 100}%` : '0%';
		DOM.legitProgress.style.width = total > 0 ? `${(legit / total) * 100}%` : '0%';
		
		// Update active sessions count
		const activeSessions = APP_STATE.sessionData.filter(session => 
			!session.EndTime || session.EndTime === 'null' || session.EndTime === 'undefined'
		).length;
		DOM.activeCount.textContent = activeSessions.toLocaleString();
	}

/**
 * Update period button styles based on current theme
 */
function updatePeriodButtonStyles() {
// Add event listeners for timeline period buttons
document.querySelectorAll('.period-btn').forEach(btn => {
    btn.addEventListener('click', function() {
        const period = this.dataset.period;
        
        // Remove active class from all period buttons
        document.querySelectorAll('.period-btn').forEach(b => {
            b.classList.remove('active', 'bg-primary-500', 'text-white', 
                               'dark:bg-primary-600', 'border-primary-500');
            b.classList.add('text-gray-800', 'dark:text-white', 'border-transparent');
        });
        
        // Add active styling based on current theme
        this.classList.remove('text-gray-800', 'dark:text-white', 'border-transparent');
        this.classList.add('active');
        
        if (APP_STATE.theme === 'dark') {
            this.classList.add('bg-primary-600', 'text-white', 'border-primary-500');
        } else {
            this.classList.add('bg-primary-500', 'text-white', 'border-primary-500');
        }
        
        // Update period and refresh chart
        APP_STATE.currentTimelinePeriod = period;
        updateCharts();
        
        DEBUG && console.log('📅 Timeline period changed to:', period);
        
        // Save preference
        const currentSettings = JSON.parse(localStorage.getItem('rdpmon-settings') || '{}');
        currentSettings.timelinePeriod = period;
        localStorage.setItem('rdpmon-settings', JSON.stringify(currentSettings));
    });
});

// Load saved timeline period preference
const savedSettings = localStorage.getItem('rdpmon-settings');
if (savedSettings) {
    try {
        const parsed = JSON.parse(savedSettings);
        if (parsed.timelinePeriod) {
            APP_STATE.currentTimelinePeriod = parsed.timelinePeriod;
            
            // Update button styling based on saved preference
            const savedBtn = document.querySelector(`[data-period="${parsed.timelinePeriod}"]`);
            if (savedBtn) {
                document.querySelectorAll('.period-btn').forEach(b => {
                    b.classList.remove('active', 'bg-primary-500', 'text-white', 
                                      'dark:bg-primary-600', 'border-primary-500');
                    b.classList.add('text-gray-800', 'dark:text-white', 'border-transparent');
                });
                
                savedBtn.classList.remove('text-gray-800', 'dark:text-white', 'border-transparent');
                savedBtn.classList.add('active');
                
                if (APP_STATE.theme === 'dark') {
                    savedBtn.classList.add('bg-primary-600', 'text-white', 'border-primary-500');
                } else {
                    savedBtn.classList.add('bg-primary-500', 'text-white', 'border-primary-500');
                }
            }
        }
    } catch (e) {
        DEBUG && console.error('Error loading timeline period:', e);
    }
}    
    DEBUG && console.log('🎨 Period button styles updated for theme:', APP_STATE.theme);
}
	
	/**
	 * Update metrics display
	 */
	function updateMetrics() {
		// Update database metrics
		DOM.totalAddrRecords.textContent = APP_STATE.addrData.length.toLocaleString();
		DOM.totalSessionRecords.textContent = APP_STATE.sessionData.length.toLocaleString();
		
		// Count unique IPs
		const uniqueIPs = new Set(APP_STATE.addrData.map(item => item.IP).filter(ip => ip));
		DOM.uniqueIps.textContent = uniqueIPs.size.toLocaleString();
		
		// Update database change times
		const lastAddrChange = APP_STATE.databaseStats.LastAddrChange;
		const lastSessionChange = APP_STATE.databaseStats.LastSessionChange;
		
		DOM.lastAddrChange.textContent = lastAddrChange ? Utils.formatDate(lastAddrChange) : 'N/A';
		DOM.lastSessionChange.textContent = lastSessionChange ? Utils.formatDate(lastSessionChange) : 'N/A';
		
		// Update other metrics
		DOM.reportGenerated.textContent = window.TEMPLATE_VARS.GENERATION_TIME;
		DOM.autoRefreshStatus.textContent = `${window.TEMPLATE_VARS.AUTO_REFRESH_INTERVAL}s`;
		DOM.dbPath.textContent = (window.TEMPLATE_VARS.DATABASE_PATH || '').substring(0, 50) + '...';
		
		// Update total records in header
		DOM.totalRecords.textContent = APP_STATE.addrData.length.toLocaleString();
		
		// Update session count
		DOM.sessionCount.textContent = APP_STATE.sessionData.length.toLocaleString();
		
		// Update generation time
		if (DOM.generationTime) {
			DOM.generationTime.textContent = window.TEMPLATE_VARS.GENERATION_TIME;
		}
	}
	
	/**
	 * UI Management Functions
	 */
	
	/**
	 * Initialize tab navigation
	 */
	function initTabs() {
		DEBUG && console.log('📑 Initializing tabs...');
		// Set active tab
		const activeTab = APP_STATE.currentTab || 'connections';
		switchTab(activeTab);
	}
	
	/**
	 * Initialize chart.js charts
	 */
	function initCharts() {
		DEBUG && console.log('📈 Initializing charts...');
		
		if (APP_STATE.addrData.length === 0) {
			DEBUG && console.log('📈 No data available for charts');
			return;
		}
		
		try {
			// Destroy existing charts to prevent canvas reuse error
			if (APP_STATE.charts.timeline) {
				APP_STATE.charts.timeline.destroy();
				APP_STATE.charts.timeline = null;
			}
			if (APP_STATE.charts.distribution) {
				APP_STATE.charts.distribution.destroy();
				APP_STATE.charts.distribution = null;
			}
			
			// Timeline Chart
			const timelineCtx = DOM.timelineChart.getContext('2d');
			APP_STATE.charts.timeline = new Chart(timelineCtx, {
				type: 'line',
				data: {
					labels: [],
					datasets: [{
						label: 'Failed Attempts',
						data: [],
						borderColor: 'rgb(239, 68, 68)',
						backgroundColor: 'rgba(239, 68, 68, 0.1)',
						tension: 0.4,
						fill: true,
						borderWidth: 2
					}, {
						label: 'Successful Logins',
						data: [],
						borderColor: 'rgb(34, 197, 94)',
						backgroundColor: 'rgba(34, 197, 94, 0.1)',
						tension: 0.4,
						fill: true,
						borderWidth: 2
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: false,
					interaction: {
						intersect: false,
						mode: 'index'
					},
					plugins: {
						legend: {
							position: 'top',
							labels: {
								color: APP_STATE.theme === 'dark' ? '#e2e8f0' : '#475569',
								font: { size: 12 }
							}
						},
						tooltip: {
							mode: 'index',
							intersect: false,
							backgroundColor: APP_STATE.theme === 'dark' ? 'rgba(30, 41, 59, 0.9)' : 'rgba(255, 255, 255, 0.9)',
							titleColor: APP_STATE.theme === 'dark' ? '#e2e8f0' : '#475569',
							bodyColor: APP_STATE.theme === 'dark' ? '#e2e8f0' : '#475569',
							borderColor: APP_STATE.theme === 'dark' ? 'rgba(51, 65, 85, 0.3)' : 'rgba(203, 213, 225, 0.3)',
							borderWidth: 1
						}
					},
					scales: {
						x: {
							grid: {
								color: APP_STATE.theme === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)',
								drawBorder: false
							},
							ticks: {
								color: APP_STATE.theme === 'dark' ? '#94a3b8' : '#64748b',
								maxRotation: 0
							}
						},
						y: {
							beginAtZero: true,
							grid: {
								color: APP_STATE.theme === 'dark' ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)',
								drawBorder: false
							},
							ticks: {
								color: APP_STATE.theme === 'dark' ? '#94a3b8' : '#64748b',
								precision: 0
							}
						}
					}
				}
			});
			
			// Distribution Chart
			const distributionCtx = DOM.distributionChart.getContext('2d');
			APP_STATE.charts.distribution = new Chart(distributionCtx, {
				type: 'doughnut',
				data: {
					labels: [],
					datasets: [{
						data: [],
						backgroundColor: [
							'rgba(239, 68, 68, 0.8)',
							'rgba(34, 197, 94, 0.8)',
							'rgba(59, 130, 246, 0.8)',
							'rgba(168, 85, 247, 0.8)',
							'rgba(245, 158, 11, 0.8)',
							'rgba(14, 165, 233, 0.8)',
							'rgba(236, 72, 153, 0.8)',
							'rgba(20, 184, 166, 0.8)'
						],
						borderColor: APP_STATE.theme === 'dark' ? 'rgba(30, 41, 59, 0.8)' : 'rgba(255, 255, 255, 0.8)',
						borderWidth: 2,
						hoverOffset: 15
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: false,
					cutout: '60%',
					plugins: {
						legend: { display: false },
						tooltip: {
							callbacks: {
								label: function(context) {
									const label = context.label || '';
									const value = context.raw || 0;
									const total = context.dataset.data.reduce((a, b) => a + b, 0);
									const percentage = Math.round((value / total) * 100);
									return `${label}: ${value} (${percentage}%)`;
								}
							}
						}
					}
				}
			});
			
			// Initialize charts with data
			updateCharts();
			
			// Add event listeners for timeline period buttons
			document.querySelectorAll('.timeline-period').forEach(btn => {
				btn.addEventListener('click', function() {
					document.querySelectorAll('.timeline-period').forEach(b => b.classList.remove('active'));
					this.classList.add('active');
					APP_STATE.currentTimelinePeriod = this.dataset.period;
					updateCharts();
				});
			});
			
			// Add event listener for distribution limit selector
if (DOM.distributionLimit) {
    DOM.distributionLimit.addEventListener('change', function() {
        const value = parseInt(this.value) || 0;
        DEBUG && console.log('📊 Distribution limit changed to:', value);
        APP_STATE.chartDistributionLimit = value;
        APP_STATE.settings.chartItemsLimit = value; // Сохраняем в настройки
        updateCharts();
    });
}
			
			DEBUG && console.log('✅ Charts initialized successfully');
		} catch (error) {
			DEBUG && console.error('❌ Error initializing charts:', error);
			Utils.showNotification('Error initializing charts', 'error');
		}
	}
	
/**
 * Update charts with current data and apply distribution limit
 * Handles both timeline and distribution charts with proper limit management
 */
function updateCharts() {
    // Safety check: ensure charts are initialized
    if (!APP_STATE.charts.timeline || !APP_STATE.charts.distribution) {
        DEBUG && console.warn('⚠️ Charts not initialized, skipping update');
        return;
    }
    
    // Check if there's data to display
    if (APP_STATE.addrData.length === 0) {
        DEBUG && console.warn('⚠️ No data available for charts');
        return;
    }
    
    try {
// ------------------------------------------------------------
// TIMELINE CHART UPDATE
// ------------------------------------------------------------

// Update timeline based on selected period
let days;
let labelFormat;
switch(APP_STATE.currentTimelinePeriod) {
    case 'day': 
        days = 1; 
        labelFormat = 'hour';
        break;
    case 'week': 
        days = 7; 
        labelFormat = 'weekday';
        break;
    case 'month': 
        days = 30; 
        labelFormat = 'monthDay';
        break;
    case 'year': 
        days = 365; 
        labelFormat = 'month';
        break;
    default: 
        days = 30;
        labelFormat = 'monthDay';
}

const today = new Date();
const labels = [];
const failData = [];
const successData = [];

// Generate data for the selected time period
for (let i = days - 1; i >= 0; i--) {
    const date = new Date(today);
    date.setDate(date.getDate() - i);
    
    // Format label based on time period with year when needed
    let label;
    const currentYear = today.getFullYear();
    const dateYear = date.getFullYear();
    
    switch(labelFormat) {
        case 'hour':
            // For single day: show hours with minutes
            label = date.toLocaleTimeString([], { 
                hour: '2-digit', 
                minute: '2-digit',
                hour12: false 
            });
            break;
        case 'weekday':
            // For week: show weekday abbreviation and day
            // Add year if different from current year
            const weekdayLabel = date.toLocaleDateString('en-US', { 
                weekday: 'short', 
                day: 'numeric' 
            });
            label = dateYear !== currentYear ? 
                `${weekdayLabel} ${dateYear}` : 
                weekdayLabel;
            break;
        case 'monthDay':
            // For month: show month abbreviation and day
            // Add year if different from current year
            const monthDayLabel = date.toLocaleDateString('en-US', { 
                month: 'short', 
                day: 'numeric' 
            });
            label = dateYear !== currentYear ? 
                `${monthDayLabel} ${dateYear}` : 
                monthDayLabel;
            break;
        case 'month':
            // For year: show month abbreviation
            // Always show year for year view
            const monthLabel = date.toLocaleDateString('en-US', { 
                month: 'short' 
            });
            label = `${monthLabel} ${dateYear}`;
            break;
    }
    
    labels.push(label);
    
    // For year view, aggregate by month
    let dayData;
    if (APP_STATE.currentTimelinePeriod === 'year') {
        // Get start and end of month for aggregation
        const monthStart = new Date(date.getFullYear(), date.getMonth(), 1);
        const monthEnd = new Date(date.getFullYear(), date.getMonth() + 1, 0);
        monthEnd.setHours(23, 59, 59, 999);
        
        dayData = APP_STATE.addrData.filter(item => {
            if (!item.LastLocal) return false;
            const itemDate = new Date(item.LastLocal);
            return itemDate >= monthStart && itemDate <= monthEnd;
        });
    } else {
        // For day/week/month: filter by exact date
        const dateStr = date.toISOString().split('T')[0];
        dayData = APP_STATE.addrData.filter(item => {
            if (!item.LastLocal) return false;
            const itemDate = new Date(item.LastLocal);
            return itemDate.toISOString().split('T')[0] === dateStr;
        });
    }
    
    // Calculate metrics
    failData.push(dayData.reduce((sum, item) => sum + (parseInt(item.FailCount) || 0), 0));
    successData.push(dayData.reduce((sum, item) => sum + (parseInt(item.SuccessCount) || 0), 0));
}

// Update timeline chart data
APP_STATE.charts.timeline.data.labels = labels;
APP_STATE.charts.timeline.data.datasets[0].data = failData;
APP_STATE.charts.timeline.data.datasets[1].data = successData;

// Update chart title based on period
let chartTitle = 'Activity Timeline';
if (APP_STATE.currentTimelinePeriod === 'year') {
    chartTitle = `${today.getFullYear()} Activity Timeline`;
} else if (APP_STATE.currentTimelinePeriod === 'month') {
    chartTitle = `${today.toLocaleDateString('en-US', { month: 'long' })} Activity Timeline`;
}

// Update chart title if plugin exists
if (APP_STATE.charts.timeline.options.plugins.title) {
    APP_STATE.charts.timeline.options.plugins.title.text = chartTitle;
}

APP_STATE.charts.timeline.update();
        
        DEBUG && console.log('📈 Timeline chart updated:', {
            period: APP_STATE.currentTimelinePeriod,
            days: days,
            dataPoints: labels.length
        });
        
        // ------------------------------------------------------------
        // DISTRIBUTION CHART UPDATE
        // ------------------------------------------------------------
        
        // Calculate type statistics from connection data
        const typeStats = {};
        APP_STATE.addrData.forEach(item => {
            const type = item.ConnectionType?.toLowerCase() || 'unknown';
            typeStats[type] = (typeStats[type] || 0) + 1;
        });
        
        DEBUG && console.log('📊 Distribution chart statistics:', {
            rawStats: typeStats,
            chartLimit: APP_STATE.chartDistributionLimit,
            uniqueTypes: Object.keys(typeStats).length
        });
        
        // Convert to sorted array of objects for easier manipulation
        let sortedTypes = Object.entries(typeStats)
            .sort((a, b) => b[1] - a[1]) // Sort by count descending
            .map(([type, count]) => ({
                type: type.charAt(0).toUpperCase() + type.slice(1), // Capitalize type name
                count,
                originalType: type // Keep original for reference
            }));
        
        DEBUG && console.log('📊 Types sorted by frequency:', sortedTypes);
        
        // Apply distribution limit based on user selection
        let finalTypes = [];
        
        if (APP_STATE.chartDistributionLimit === 0) {
            // Case 1: Show all types (limit = 0 or "All")
            finalTypes = [...sortedTypes];
            DEBUG && console.log('📊 Showing all types (limit = 0)');
            
        } else if (sortedTypes.length <= APP_STATE.chartDistributionLimit) {
            // Case 2: Fewer types than limit, show all
            finalTypes = [...sortedTypes];
            DEBUG && console.log(`📊 Showing all ${sortedTypes.length} types (less than limit ${APP_STATE.chartDistributionLimit})`);
            
        } else {
            // Case 3: More types than limit, apply limit and add "Other" category
            const visibleTypes = sortedTypes.slice(0, APP_STATE.chartDistributionLimit);
            const hiddenTypes = sortedTypes.slice(APP_STATE.chartDistributionLimit);
            
            // Calculate total count of hidden types
            const otherCount = hiddenTypes.reduce((sum, item) => sum + item.count, 0);
            
            // Prepare final array with visible types
            finalTypes = [...visibleTypes];
            
            // Add "Other" category if there are hidden types with data
            if (otherCount > 0) {
                finalTypes.push({
                    type: 'Other',
                    count: otherCount,
                    originalType: 'other',
                    isAggregated: true
                });
                
                DEBUG && console.log('📊 Applied limit:', {
                    limit: APP_STATE.chartDistributionLimit,
                    visible: visibleTypes.length,
                    hidden: hiddenTypes.length,
                    otherCount: otherCount
                });
            } else {
                DEBUG && console.log('📊 No data in hidden types, skipping "Other" category');
            }
        }
        
        // Calculate total for percentage calculations
        const total = finalTypes.reduce((sum, item) => sum + item.count, 0);
        
        // Prepare data for chart.js
        const labelsData = finalTypes.map(item => item.type);
        const dataValues = finalTypes.map(item => item.count);
        
        DEBUG && console.log('📊 Final chart data:', {
            labels: labelsData,
            data: dataValues,
            total: total,
            itemCount: finalTypes.length
        });
        
        // Update distribution chart
        APP_STATE.charts.distribution.data.labels = labelsData;
        APP_STATE.charts.distribution.data.datasets[0].data = dataValues;
        
        // Update chart visualization
        APP_STATE.charts.distribution.update();
        
        // ------------------------------------------------------------
        // UPDATE DISTRIBUTION LEGEND
        // ------------------------------------------------------------
        
        if (DOM.distributionLegend) {
            let legendHtml = '<div class="flex flex-wrap gap-2 justify-center">';
            
            finalTypes.forEach((item, index) => {
                // Calculate percentage
                const percentage = total > 0 ? Math.round((item.count / total) * 100) : 0;
                
                // Get color from chart configuration
                const color = APP_STATE.charts.distribution.data.datasets[0].backgroundColor[
                    Math.min(index, APP_STATE.charts.distribution.data.datasets[0].backgroundColor.length - 1)
                ];
                
                // Build legend item
                legendHtml += `
                    <div class="flex items-center px-3 py-1 rounded-full text-xs" 
                         style="background: ${color}22; border: 1px solid ${color}44"
                         title="${item.isAggregated ? 'Aggregated category' : item.originalType}">
                        <div class="w-3 h-3 rounded-full mr-2" style="background: ${color}"></div>
                        <span class="font-medium text-gray-800 dark:text-white">${item.type}</span>
                        <span class="ml-2 text-gray-600 dark:text-gray-300">
                            ${item.count.toLocaleString()} (${percentage}%)
                        </span>
                    </div>
                `;
            });
            
            legendHtml += '</div>';
            DOM.distributionLegend.innerHTML = legendHtml;
            
            DEBUG && console.log('📊 Legend updated with', finalTypes.length, 'items');
        }
        
        // ------------------------------------------------------------
        // CHART THEME ADJUSTMENT
        // ------------------------------------------------------------
        
        // Update chart colors based on current theme
        const isDarkTheme = APP_STATE.theme === 'dark';
        
        // Update timeline chart theme
        APP_STATE.charts.timeline.options.plugins.tooltip.backgroundColor = isDarkTheme 
            ? 'rgba(30, 41, 59, 0.9)' 
            : 'rgba(255, 255, 255, 0.9)';
            
        APP_STATE.charts.timeline.options.scales.x.grid.color = isDarkTheme 
            ? 'rgba(255, 255, 255, 0.1)' 
            : 'rgba(0, 0, 0, 0.1)';
            
        APP_STATE.charts.timeline.options.scales.y.grid.color = isDarkTheme 
            ? 'rgba(255, 255, 255, 0.1)' 
            : 'rgba(0, 0, 0, 0.1)';
        
        // Trigger theme update
        APP_STATE.charts.timeline.update();
        APP_STATE.charts.distribution.update();
        
        DEBUG && console.log('✅ All charts updated successfully', {
            theme: APP_STATE.theme,
            timelinePeriod: APP_STATE.currentTimelinePeriod,
            distributionLimit: APP_STATE.chartDistributionLimit,
            totalConnections: APP_STATE.addrData.length
        });
        
    } catch (error) {
        DEBUG && console.error('❌ Error updating charts:', {
            error: error.message,
            stack: error.stack,
            currentLimit: APP_STATE.chartDistributionLimit,
            dataLength: APP_STATE.addrData.length
        });
        
        // Show user-friendly error notification
        if (!error.handled) {
            Utils.showNotification('Error updating charts. Please refresh the page.', 'error');
            error.handled = true;
        }
    }
}
	
	/**
	 * Update connections table with current data
	 */
	function updateConnectionsTable() {
		DEBUG && console.log('📋 Updating connections table...');
		
		const startIndex = (APP_STATE.currentPage - 1) * APP_STATE.pageSize;
		const endIndex = startIndex + APP_STATE.pageSize;
		const pageData = APP_STATE.filteredAddrData.slice(startIndex, endIndex);
		const totalPages = Math.ceil(APP_STATE.filteredAddrData.length / APP_STATE.pageSize);
		
		DOM.dataTable.innerHTML = '';
		
		if (pageData.length === 0) {
			const row = document.createElement('tr');
			row.innerHTML = `
				<td colspan="8" class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
					<i class="fas fa-inbox text-3xl mb-2"></i>
					<p class="font-medium">No data to display</p>
					<p class="text-sm mt-1">Try changing your filter or search criteria</p>
				</td>
			`;
			DOM.dataTable.appendChild(row);
		} else {
			pageData.forEach(item => {
				const typeColors = Utils.getTypeColor(item.ConnectionType);
				const row = document.createElement('tr');
				row.className = 'hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors fade-in';
				
				// Add glow effect for high-risk attacks
				if (item.ConnectionType && item.ConnectionType.toLowerCase() === 'attack' && item.FailCount > 50) {
					row.classList.add('attack-glow');
				}
				
				const usernames = Array.isArray(item.UserNames) ? item.UserNames : [];
				const durationFormatted = Utils.formatDuration(item.Duration);
				const firstLocal = Utils.formatDate(item.FirstLocal);
				const lastLocal = Utils.formatDate(item.LastLocal);
				
				// Escape values to prevent JavaScript injection
				const escapedIP = Utils.escapeHtml(item.IP || '');
				const escapedHostname = Utils.escapeHtml(item.Hostname || '');
				const escapedConnectionType = Utils.escapeHtml(item.ConnectionType || '');
				const escapedUsernames = Utils.escapeHtml(usernames.join(', '));
				
				row.innerHTML = `
					<td class="px-4 py-3 whitespace-nowrap">
						<div class="flex items-center">
							<div class="ml-4">
								<div class="text-sm font-medium text-gray-900 dark:text-white">${escapedIP || 'Unknown'}</div>
								<div class="text-xs text-gray-500 dark:text-gray-400">${escapedHostname || 'Not resolved'}</div>
							</div>
							<div class="ml-2 flex space-x-1">
								<button class="p-1 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 copy-ip-btn" 
										title="Copy IP" data-ip="${escapedIP}">
									<i class="fas fa-copy"></i>
								</button>
								<button class="p-1 text-blue-500 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 abuseipdb-check-btn" 
										title="Check on AbuseIPDB" data-ip="${escapedIP}">
									<i class="fas fa-search"></i>
								</button>
								<button class="p-1 text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 abuseipdb-report-btn" 
										title="Report to AbuseIPDB" data-ip="${escapedIP}">
									<i class="fas fa-flag"></i>
								</button>
							</div>
						</div>
					</td>
					<td class="px-4 py-3 whitespace-nowrap">
						<span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${typeColors.bg} ${typeColors.text}">
							<i class="fas ${typeColors.icon} mr-1"></i>
							${escapedConnectionType || 'Unknown'}
						</span>
					</td>
					<td class="px-4 py-3 whitespace-nowrap">
						<div class="flex items-center">
							<div class="w-24 bg-gray-200 dark:bg-gray-700 rounded-full h-2 mr-3">
								<div class="h-2 rounded-full bg-danger-500" style="width: ${Math.min((parseInt(item.FailCount) || 0) * 2, 100)}%"></div>
							</div>
							<span class="text-sm font-medium text-gray-900 dark:text-white">${parseInt(item.FailCount) || 0}</span>
						</div>
					</td>
					<td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-white hidden lg:table-cell">
						${parseInt(item.SuccessCount) || 0}
					</td>
					<td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-white hidden md:table-cell">
						${firstLocal}
					</td>
					<td class="px-4 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-white hidden md:table-cell">
						<div class="flex items-center">
							${lastLocal}
						</div>
					</td>
					<td class="px-4 py-3 hidden xl:table-cell">
						<div class="text-sm text-gray-900 dark:text-white max-w-xs truncate" title="${escapedUsernames}">
							${usernames.slice(0, 3).join(', ')}${usernames.length > 3 ? '...' : ''}
						</div>
					</td>
					<td class="px-4 py-3 whitespace-nowrap text-sm font-medium">
						<button class="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300 mr-3 view-details-btn" 
								data-ip="${escapedIP}" title="View details">
							<i class="fas fa-eye"></i>
						</button>
						<button class="text-danger-600 hover:text-danger-900 dark:text-danger-400 dark:hover:text-danger-300 block-ip-btn" 
								data-ip="${escapedIP}" title="Block IP">
							<i class="fas fa-ban"></i>
						</button>
					</td>
				`;
				
				DOM.dataTable.appendChild(row);
			});
			
			// Add event listeners to the new buttons
			setTimeout(() => {
				document.querySelectorAll('.copy-ip-btn').forEach(btn => {
					btn.addEventListener('click', (e) => {
						const ip = e.currentTarget.getAttribute('data-ip');
						DEBUG && console.log('📋 Copy IP button clicked:', ip);
						Utils.copyToClipboard(ip.replace(/"/g, ''));
					});
				});
				
				document.querySelectorAll('.abuseipdb-check-btn').forEach(btn => {
					btn.addEventListener('click', (e) => {
						const ip = e.currentTarget.getAttribute('data-ip');
						DEBUG && console.log('🔍 AbuseIPDB check button clicked:', ip);
						Utils.openAbuseIPDBCheck(ip);
					});
				});
				
				document.querySelectorAll('.abuseipdb-report-btn').forEach(btn => {
					btn.addEventListener('click', async (e) => {
						const ip = e.currentTarget.getAttribute('data-ip');
						DEBUG && console.log('🚩 AbuseIPDB report button clicked:', ip);
						const item = APP_STATE.addrData.find(d => d.IP === ip);
						
						if (item) {
							const usernames = Array.isArray(item.UserNames) ? item.UserNames : [];
							const attackDescription = `RDP Attack Report\n\n` +
								`IP Address: ${item.IP}\n` +
								`Hostname: ${item.Hostname || 'Not resolved'}\n` +
								`Connection Type: ${item.ConnectionType}\n` +
								`Failed Attempts: ${item.FailCount}\n` +
								`Successful Logins: ${item.SuccessCount}\n` +
								`First Seen: ${Utils.formatDate(item.FirstLocal)}\n` +
								`Last Seen: ${Utils.formatDate(item.LastLocal)}\n` +
								`Usernames Attempted: ${usernames.join(', ') || 'None'}\n` +
								`Duration: ${Utils.formatDuration(item.Duration)}\n\n` +
								`This attack was detected by RDP Monitor security system.`;
							
							Utils.openAbuseIPDBReport(ip, attackDescription);
						} else {
							Utils.openAbuseIPDBReport(ip, 'RDP attack detected by RDP Monitor security system.');
						}
					});
				});
				
				document.querySelectorAll('.view-details-btn').forEach(btn => {
					btn.addEventListener('click', (e) => {
						const ip = e.currentTarget.getAttribute('data-ip');
						DEBUG && console.log('👁️ View details button clicked:', ip);
						showDetails(ip);
					});
				});
				
				document.querySelectorAll('.block-ip-btn').forEach(btn => {
					btn.addEventListener('click', (e) => {
						const ip = e.currentTarget.getAttribute('data-ip');
						DEBUG && console.log('🚫 Block IP button clicked:', ip);
						blockIP(ip);
					});
				});
			}, 0);
		}
		
		// Update pagination info
		DOM.tableCount.textContent = APP_STATE.filteredAddrData.length.toLocaleString();
		DOM.pageInfo.textContent = `Page ${APP_STATE.currentPage} of ${totalPages || 1}`;
		DOM.prevPage.disabled = APP_STATE.currentPage === 1;
		DOM.nextPage.disabled = APP_STATE.currentPage === totalPages || totalPages === 0;
		
		// Apply table density setting
		SettingsManager.applyTableDensity();
		
		DEBUG && console.log(`✅ Table updated: ${APP_STATE.filteredAddrData.length} items, page ${APP_STATE.currentPage}/${totalPages}`);
	}
	
	/**
	 * Update sessions table with current data
	 */
	function updateSessionsTable() {
		DOM.sessionsTable.innerHTML = '';
		
		if (APP_STATE.sessionData.length === 0) {
			const row = document.createElement('tr');
			row.innerHTML = `
				<td colspan="7" class="px-6 py-8 text-center text-gray-500 dark:text-gray-400">
					<i class="fas fa-desktop text-3xl mb-2"></i>
					<p class="font-medium">No session data available</p>
				</td>
			`;
			DOM.sessionsTable.appendChild(row);
			return;
		}
		
		APP_STATE.sessionData.forEach(item => {
			const typeColors = Utils.getSessionTypeColor(item.SessionType);
			const row = document.createElement('tr');
			row.className = 'hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors fade-in';
			
			const sessionId = item.SessionId ? item.SessionId.toString().substring(0, 8) + '...' : 'N/A';
			const startTime = Utils.formatDate(item.StartTime);
			const endTime = item.EndTime ? Utils.formatDate(item.EndTime) : 'Active';
			const duration = Utils.formatSessionDuration(item.Duration);
			
			row.innerHTML = `
				<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
					${sessionId}
				</td>
				<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
					${Utils.escapeHtml(item.User || 'Unknown')}
				</td>
				<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
					${Utils.escapeHtml(item.IP || 'Local')}
				</td>
				<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
					${startTime}
				</td>
				<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
					${endTime}
				</td>
				<td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
					${duration}
				</td>
				<td class="px-6 py-4 whitespace-nowrap">
					<span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${typeColors.bg} ${typeColors.text}">
						${Utils.escapeHtml(item.SessionType || 'Unknown')}
					</span>
				</td>
			`;
			
			DOM.sessionsTable.appendChild(row);
		});
	}
	
	/**
	 * Update time display
	 */
	function updateTime() {
		const now = new Date();
		const timeString = now.toLocaleTimeString([], { 
			hour: '2-digit', 
			minute: '2-digit', 
			second: '2-digit' 
		});
		const dateString = now.toLocaleDateString();
		
		// Update the time display
		DOM.lastUpdated.textContent = timeString;
		
		// Update the tooltip with full date and time
		const tooltipContainer = DOM.lastUpdated.closest('.tooltip');
		if (tooltipContainer) {
			tooltipContainer.setAttribute('data-tip', `Last update: ${dateString} ${timeString}`);
		}
	}
	
	/**
	 * Initialize event listeners
	 */
	function initEventListeners() {
		DEBUG && console.log('🔌 Initializing event listeners...');
		
		// Theme toggle - fixed to use SettingsManager.applyTheme()
		DOM.themeToggle.addEventListener('click', () => {
			DEBUG && console.log('🎨 Theme toggle clicked');
			// Toggle theme mode in settings
			const currentMode = APP_STATE.settings.themeMode;
			let newMode;
			
			if (currentMode === 'auto') {
				newMode = 'dark';
			} else if (currentMode === 'dark') {
				newMode = 'light';
			} else {
				newMode = 'auto';
			}
			
			// Update setting
			APP_STATE.settings.themeMode = newMode;
			
			// Update UI buttons
			document.querySelectorAll('.theme-mode-btn').forEach(btn => {
				btn.classList.remove('active', 'bg-primary-500', 'text-white');
				btn.classList.add('text-gray-800', 'dark:text-white');
				if (btn.dataset.mode === newMode) {
					btn.classList.remove('text-gray-800', 'dark:text-white');
					btn.classList.add('active', 'bg-primary-500', 'text-white');
				}
			});
			
			// Apply theme immediately
			SettingsManager.applyTheme();
			
			// Save settings
			SettingsManager.saveSettingsImmediately();
			
			Utils.showNotification(`Theme changed to ${newMode} mode`);
		});
		
		// Tab navigation
		document.querySelectorAll('.tab-button').forEach(button => {
			button.addEventListener('click', (e) => {
				const tabName = e.currentTarget.getAttribute('data-tab');
				DEBUG && console.log('📑 Tab clicked:', tabName);
				switchTab(tabName);
			});
		});
		
		// Filter buttons
		DOM.filterAll.addEventListener('click', () => {
			DEBUG && console.log('🔍 Filter: all');
			DOM.filterAll.classList.add('tab-active');
			DOM.filterAttack.classList.remove('tab-active');
			DOM.filterLegit.classList.remove('tab-active');
			applyFilter('all');
		});
		
		DOM.filterAttack.addEventListener('click', () => {
			DEBUG && console.log('🔍 Filter: attack');
			DOM.filterAll.classList.remove('tab-active');
			DOM.filterAttack.classList.add('tab-active');
			DOM.filterLegit.classList.remove('tab-active');
			applyFilter('attack');
		});
		
		DOM.filterLegit.addEventListener('click', () => {
			DEBUG && console.log('🔍 Filter: legit');
			DOM.filterAll.classList.remove('tab-active');
			DOM.filterAttack.classList.remove('tab-active');
			DOM.filterLegit.classList.add('tab-active');
			applyFilter('legit');
		});
		
		// Sort headers - FIXED: added proper event delegation and sorting logic
		document.querySelectorAll('.sortable').forEach(header => {
			header.addEventListener('click', () => {
				const sortField = header.dataset.sort;
				DEBUG && console.log('📊 Sort header clicked:', sortField);
				if (sortField) {
					applySort(sortField);
				}
			});
		});
		
		// Search with debounce
		DOM.tableSearch.addEventListener('input', Utils.debounce((e) => {
			DEBUG && console.log('🔍 Search input:', e.target.value);
			searchData(e.target.value);
		}, 300));
		
		// Pagination
		DOM.prevPage.addEventListener('click', () => {
			if (APP_STATE.currentPage > 1) {
				APP_STATE.currentPage--;
				DEBUG && console.log('⬅️ Previous page:', APP_STATE.currentPage);
				updateConnectionsTable();
			}
		});
		
		DOM.nextPage.addEventListener('click', () => {
			const totalPages = Math.ceil(APP_STATE.filteredAddrData.length / APP_STATE.pageSize);
			if (APP_STATE.currentPage < totalPages) {
				APP_STATE.currentPage++;
				DEBUG && console.log('➡️ Next page:', APP_STATE.currentPage);
				updateConnectionsTable();
			}
		});
		
		// Refresh interval control
		DOM.refreshInterval.addEventListener('input', (e) => {
			const value = e.target.value;
			DOM.intervalValue.textContent = `${value}s`;
			DOM.footerInterval.textContent = value;
			APP_STATE.autoRefreshInterval = parseInt(value);
			DEBUG && console.log('⏱️ Refresh interval changed:', value);
			restartAutoRefresh();
		});
		
		// Manual refresh button
		DOM.refreshBtn.addEventListener('click', () => {
			DEBUG && console.log('🔄 Manual refresh clicked');
			DOM.refreshBtn.classList.add('animate-spin');
			setTimeout(() => {
				DOM.refreshBtn.classList.remove('animate-spin');
				updateTime();
				Utils.showNotification('Data refreshed successfully');
			}, 500);
		});
		
		// Export button
		DOM.exportBtn.addEventListener('click', exportData);
		
		// Window resize for responsive charts
		window.addEventListener('resize', () => {
			if (APP_STATE.charts.timeline) APP_STATE.charts.timeline.resize();
			if (APP_STATE.charts.distribution) APP_STATE.charts.distribution.resize();
		});
		
		DEBUG && console.log('✅ Event listeners initialized');
	}
	
	/**
	 * Switch between application tabs
	 * 
	 * @param {string} tabName - Tab to switch to
	 */
	function switchTab(tabName) {
		DEBUG && console.log('🔄 Switching tab to:', tabName);
		
		// Update tab styles
		document.querySelectorAll('.tab-button').forEach(btn => {
			btn.classList.remove('border-primary-500', 'text-primary-600', 'dark:text-primary-400', 'tab-active');
			btn.classList.add('border-transparent', 'text-gray-500', 'dark:text-gray-400');
		});
		
		// Hide all tab contents
		DOM.connectionsTab.classList.add('hidden');
		DOM.sessionsTab.classList.add('hidden');
		DOM.metricsTab.classList.add('hidden');
		DOM.settingsTab.classList.add('hidden');
		
		// Show selected tab and update button style
		switch(tabName) {
			case 'connections':
				DOM.tabConnections.classList.remove('border-transparent', 'text-gray-500', 'dark:text-gray-400');
				DOM.tabConnections.classList.add('border-primary-500', 'text-primary-600', 'dark:text-primary-400', 'tab-active');
				DOM.connectionsTab.classList.remove('hidden');
				break;
			case 'sessions':
				DOM.tabSessions.classList.remove('border-transparent', 'text-gray-500', 'dark:text-gray-400');
				DOM.tabSessions.classList.add('border-primary-500', 'text-primary-600', 'dark:text-primary-400', 'tab-active');
				DOM.sessionsTab.classList.remove('hidden');
				break;
			case 'metrics':
				DOM.tabMetrics.classList.remove('border-transparent', 'text-gray-500', 'dark:text-gray-400');
				DOM.tabMetrics.classList.add('border-primary-500', 'text-primary-600', 'dark:text-primary-400', 'tab-active');
				DOM.metricsTab.classList.remove('hidden');
				break;
			case 'settings':
				DOM.tabSettings.classList.remove('border-transparent', 'text-gray-500', 'dark:text-gray-400');
				DOM.tabSettings.classList.add('border-primary-500', 'text-primary-600', 'dark:text-primary-400', 'tab-active');
				DOM.settingsTab.classList.remove('hidden');
				break;
		}
		
		APP_STATE.currentTab = tabName;
	}
	
	/**
	 * Start auto-refresh timer
	 */
	function startAutoRefresh() {
		if (APP_STATE.autoRefreshTimer) {
			clearInterval(APP_STATE.autoRefreshTimer);
		}
		
		APP_STATE.autoRefreshTimer = setInterval(() => {
			updateTime();
		}, APP_STATE.autoRefreshInterval * 1000);
	}
	
	/**
	 * Restart auto-refresh with new interval
	 */
	function restartAutoRefresh() {
		startAutoRefresh();
	}
	
	/**
	 * Settings Management Module
	 * Handles persistent settings with localStorage integration
	 */
	const SettingsManager = {
/**
 * Load settings from localStorage
 */
loadSettings: () => {
    try {
        const savedSettings = localStorage.getItem('rdpmon-settings');
        if (savedSettings) {
            const parsedSettings = JSON.parse(savedSettings);
            
            // CRITICAL: Merge settings properly, preserving defaults for missing values
            APP_STATE.settings = {
                // Defaults
                ipInfoService: 'ripe',
                defaultChartPeriod: 'month',
                chartItemsLimit: 1000,
                themeMode: 'auto',
                tableDensity: 'normal',
                animationLevel: 'minimal',
                pageWidth: 'full',
                autoRefreshInterval: 30,
                itemsPerPage: 10,
                // Override with saved values
                ...parsedSettings
            };
            
            DEBUG && console.log('⚙️ Settings loaded from localStorage:', parsedSettings);
            
            // Update DOM elements with loaded settings - DO THIS HERE
            if (DOM.ipInfoService && parsedSettings.ipInfoService) {
                DOM.ipInfoService.value = parsedSettings.ipInfoService;
            }
            if (DOM.defaultChartPeriod && parsedSettings.defaultChartPeriod) {
                DOM.defaultChartPeriod.value = parsedSettings.defaultChartPeriod;
            }
            if (DOM.chartItemsLimit && parsedSettings.chartItemsLimit) {
                DOM.chartItemsLimit.value = parsedSettings.chartItemsLimit;
            }
            if (DOM.pageSizeSelect && parsedSettings.itemsPerPage) {
                DOM.pageSizeSelect.value = parsedSettings.itemsPerPage;
            }
            if (DOM.settingsRefreshInterval && parsedSettings.autoRefreshInterval) {
                DOM.settingsRefreshInterval.value = parsedSettings.autoRefreshInterval;
                DOM.settingsIntervalValue.textContent = `${parsedSettings.autoRefreshInterval}s`;
            }
            
            // Load current sort setting if exists
            if (parsedSettings.currentSort) {
                APP_STATE.currentSort = parsedSettings.currentSort;
            }
        } else {
            DEBUG && console.log('⚙️ No saved settings found, using defaults');
        }
        
        DEBUG && console.log('⚙️ Final settings:', APP_STATE.settings);
    } catch (error) {
        DEBUG && console.error('❌ Error loading settings:', error);
    }
},
		
		/**
		 * Save sort preference to localStorage
		 */
		saveSortPreference: () => {
			try {
				const currentSettings = JSON.parse(localStorage.getItem('rdpmon-settings')) || {};
				currentSettings.currentSort = APP_STATE.currentSort;
				localStorage.setItem('rdpmon-settings', JSON.stringify(currentSettings));
				DEBUG && console.log('📊 Sort preference saved:', APP_STATE.currentSort);
			} catch (error) {
				DEBUG && console.error('❌ Error saving sort preference:', error);
			}
		},
		
		/**
		 * Apply page width setting
		 */
		applyPageWidth: () => {
			const container = document.getElementById('main-container');
			if (container) {
				// Remove existing width classes
				container.classList.remove('max-w-full', 'max-w-7xl', 'max-w-4xl');
				
				// Apply new width based on setting
				switch(APP_STATE.settings.pageWidth) {
					case 'full':
						container.classList.add('max-w-full');
						break;
					case 'normal':
						container.classList.add('max-w-7xl');
						break;
					case 'narrow':
						container.classList.add('max-w-4xl');
						break;
					default:
						container.classList.add('max-w-full');
				}
				DEBUG && console.log('📏 Page width applied:', APP_STATE.settings.pageWidth);
			}
		},
		
		/**
		 * Reset settings to defaults
		 */
		resetSettings: () => {
			if (confirm('Reset all settings to defaults?')) {
				APP_STATE.settings = {
					ipInfoService: 'ripe',
					defaultChartPeriod: 'month',
					chartItemsLimit: 10,
					themeMode: 'auto',
					tableDensity: 'normal',
					animationLevel: 'minimal',
					pageWidth: 'full',
					autoRefreshInterval: 30,
					itemsPerPage: 10
				};
				
				DEBUG && console.log('🔄 Settings reset to defaults');
				
				// Update UI elements with default values
				if (DOM.ipInfoService) DOM.ipInfoService.value = APP_STATE.settings.ipInfoService;
				if (DOM.defaultChartPeriod) DOM.defaultChartPeriod.value = APP_STATE.settings.defaultChartPeriod;
				if (DOM.chartItemsLimit) DOM.chartItemsLimit.value = APP_STATE.settings.chartItemsLimit;
				if (DOM.pageSizeSelect) DOM.pageSizeSelect.value = APP_STATE.settings.itemsPerPage;
				if (DOM.settingsRefreshInterval) {
					DOM.settingsRefreshInterval.value = APP_STATE.settings.autoRefreshInterval;
					DOM.settingsIntervalValue.textContent = `${APP_STATE.settings.autoRefreshInterval}s`;
				}
				
				// Apply settings
				SettingsManager.applySettings();
				SettingsManager.highlightUIPreferences();
				
				// Save to localStorage
				localStorage.setItem('rdpmon-settings', JSON.stringify(APP_STATE.settings));
				
				Utils.showNotification('Settings reset to defaults');
			}
		},
		
		/**
		 * Save settings to localStorage
		 */
		saveSettings: () => {
			try {
				// Collect settings from UI elements first
				APP_STATE.settings = {
					ipInfoService: DOM.ipInfoService?.value || 'ripe',
					defaultChartPeriod: DOM.defaultChartPeriod?.value || 'month',
					chartItemsLimit: parseInt(DOM.chartItemsLimit?.value || 1000),
					themeMode: document.querySelector('.theme-mode-btn.active')?.dataset.mode || 'auto',
					tableDensity: document.querySelector('.table-density-btn.active')?.dataset.density || 'normal',
					animationLevel: document.querySelector('.animation-level-btn.active')?.dataset.level || 'minimal',
					pageWidth: document.querySelector('.page-width-btn.active')?.dataset.width || 'full',
					autoRefreshInterval: parseInt(DOM.settingsRefreshInterval?.value || 30),
					itemsPerPage: parseInt(DOM.pageSizeSelect?.value || 10),
					currentSort: APP_STATE.currentSort // Keep current sort setting
				};
				
				localStorage.setItem('rdpmon-settings', JSON.stringify(APP_STATE.settings));
				DEBUG && console.log('💾 Settings saved:', APP_STATE.settings);
				
				// Update UI elements with current settings
				if (DOM.ipInfoService) {
					DOM.ipInfoService.value = APP_STATE.settings.ipInfoService;
				}
				if (DOM.defaultChartPeriod) {
					DOM.defaultChartPeriod.value = APP_STATE.settings.defaultChartPeriod;
				}
				if (DOM.chartItemsLimit) {
					DOM.chartItemsLimit.value = APP_STATE.settings.chartItemsLimit;
				}
				if (DOM.pageSizeSelect) {
					DOM.pageSizeSelect.value = APP_STATE.settings.itemsPerPage;
				}
				if (DOM.settingsRefreshInterval) {
					DOM.settingsRefreshInterval.value = APP_STATE.settings.autoRefreshInterval;
					DOM.settingsIntervalValue.textContent = `${APP_STATE.settings.autoRefreshInterval}s`;
				}
				
				// Update theme mode buttons
				document.querySelectorAll('.theme-mode-btn').forEach(btn => {
					btn.classList.remove('active', 'bg-primary-500', 'text-white');
					btn.classList.add('text-gray-800', 'dark:text-white');
					if (btn.dataset.mode === APP_STATE.settings.themeMode) {
						btn.classList.remove('text-gray-800', 'dark:text-white');
						btn.classList.add('active', 'bg-primary-500', 'text-white');
					}
				});
				
				// Update table density buttons
				document.querySelectorAll('.table-density-btn').forEach(btn => {
					btn.classList.remove('active', 'bg-primary-500', 'text-white');
					btn.classList.add('text-gray-800', 'dark:text-white');
					if (btn.dataset.density === APP_STATE.settings.tableDensity) {
						btn.classList.remove('text-gray-800', 'dark:text-white');
						btn.classList.add('active', 'bg-primary-500', 'text-white');
					}
				});
				
				// Update animation level buttons
				document.querySelectorAll('.animation-level-btn').forEach(btn => {
					btn.classList.remove('active', 'bg-primary-500', 'text-white');
					btn.classList.add('text-gray-800', 'dark:text-white');
					if (btn.dataset.level === APP_STATE.settings.animationLevel) {
						btn.classList.remove('text-gray-800', 'dark:text-white');
						btn.classList.add('active', 'bg-primary-500', 'text-white');
					}
				});
				
				// Update page width buttons
				document.querySelectorAll('.page-width-btn').forEach(btn => {
					btn.classList.remove('active', 'bg-primary-500', 'text-white');
					btn.classList.add('text-gray-800', 'dark:text-white');
					if (btn.dataset.width === APP_STATE.settings.pageWidth) {
						btn.classList.remove('text-gray-800', 'dark:text-white');
						btn.classList.add('active', 'bg-primary-500', 'text-white');
					}
				});
				
				// Apply all settings immediately
				SettingsManager.applySettings();
				
				// Show notification
				Utils.showNotification('Settings saved successfully');
			} catch (error) {
				DEBUG && console.error('❌ Error saving settings:', error);
				Utils.showNotification('Error saving settings', 'error');
			}
		},
		
/**
 * Apply all settings to UI
 */
applySettings: () => {
    DEBUG && console.log('⚙️ Applying settings...');
    
    // Apply theme FIRST - это критически важно
    SettingsManager.applyTheme();
    
    // Apply auto-refresh interval
    if (DOM.refreshInterval) {
        DOM.refreshInterval.value = APP_STATE.settings.autoRefreshInterval;
        DOM.intervalValue.textContent = `${APP_STATE.settings.autoRefreshInterval}s`;
        DOM.footerInterval.textContent = APP_STATE.settings.autoRefreshInterval;
        restartAutoRefresh();
    }

    // Apply chart items limit
    if (DOM.distributionLimit) {
        DOM.distributionLimit.value = APP_STATE.settings.chartItemsLimit;
        APP_STATE.chartDistributionLimit = APP_STATE.settings.chartItemsLimit;
        DEBUG && console.log('📊 Applied distribution limit:', APP_STATE.settings.chartItemsLimit);
    }
    
    // Apply chart items limit
    if (DOM.distributionLimit) {
        DOM.distributionLimit.value = APP_STATE.settings.chartItemsLimit;
        APP_STATE.chartDistributionLimit = APP_STATE.settings.chartItemsLimit;
    }
    
    // Apply page size
    if (APP_STATE.settings.itemsPerPage) {
        APP_STATE.pageSize = APP_STATE.settings.itemsPerPage;
        updateConnectionsTable();
    }
    
    // Apply page width setting
    SettingsManager.applyPageWidth();
    
    // Apply table density
    SettingsManager.applyTableDensity();
    
    // Apply animation level
    SettingsManager.applyAnimationLevel();
    
    // Apply sort preference if exists
    if (APP_STATE.settings.currentSort) {
        APP_STATE.currentSort = APP_STATE.settings.currentSort;
        // Apply the sort immediately
        applySort(APP_STATE.currentSort.field);
    }
    
    // Update charts if needed
    if (APP_STATE.charts.timeline) {
        updateCharts();
    }
    
    // Highlight UI preferences
    SettingsManager.highlightUIPreferences();
    
    DEBUG && console.log('✅ Settings applied');
},
		
/**
 * Apply theme setting
 */
applyTheme: () => {
    const { themeMode } = APP_STATE.settings;
    DEBUG && console.log('🎨 Applying theme:', themeMode);
    
    if (themeMode === 'auto') {
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        document.documentElement.classList.toggle('dark', prefersDark);
        APP_STATE.theme = prefersDark ? 'dark' : 'light';
    } else {
        document.documentElement.classList.toggle('dark', themeMode === 'dark');
        APP_STATE.theme = themeMode;
    }
    
    // Update theme toggle icon
    if (DOM.themeIcon) {
        DOM.themeIcon.className = APP_STATE.theme === 'dark' ? 
            'fas fa-sun' : 'fas fa-moon';
    }
    
    // Update period button styles
    updatePeriodButtonStyles();
    
    DEBUG && console.log('✅ Theme applied:', APP_STATE.theme);
},
		
		/**
		 * Apply table density setting
		 */
		applyTableDensity: () => {
			const table = document.querySelector('#data-table');
			if (!table) return;
			
			// Remove previous density classes
			table.parentElement.parentElement.classList.remove('table-compact', 'table-normal', 'table-comfortable');
			
			// Apply new density
			table.parentElement.parentElement.classList.add(`table-${APP_STATE.settings.tableDensity}`);
			DEBUG && console.log('📊 Table density applied:', APP_STATE.settings.tableDensity);
		},
		
		/**
		 * Apply animation level setting
		 */
		applyAnimationLevel: () => {
			const { animationLevel } = APP_STATE.settings;
			
			// Remove all animation classes first
			document.body.classList.remove('animation-none', 'animation-minimal', 'animation-full');
			
			// Apply the selected level
			if (animationLevel !== 'full') {
				document.body.classList.add(`animation-${animationLevel}`);
			}
			DEBUG && console.log('🎬 Animation level applied:', animationLevel);
		},
		
		/**
		 * Highlight active UI preference buttons
		 */
		highlightUIPreferences: () => {
			// Theme mode buttons
			document.querySelectorAll('.theme-mode-btn').forEach(btn => {
				btn.classList.remove('active', 'bg-primary-500', 'text-white');
				btn.classList.add('text-gray-800', 'dark:text-white');
				if (btn.dataset.mode === APP_STATE.settings.themeMode) {
					btn.classList.remove('text-gray-800', 'dark:text-white');
					btn.classList.add('active', 'bg-primary-500', 'text-white');
				}
			});
			
			// Table density buttons
			document.querySelectorAll('.table-density-btn').forEach(btn => {
				btn.classList.remove('active', 'bg-primary-500', 'text-white');
				btn.classList.add('text-gray-800', 'dark:text-white');
				if (btn.dataset.density === APP_STATE.settings.tableDensity) {
					btn.classList.remove('text-gray-800', 'dark:text-white');
					btn.classList.add('active', 'bg-primary-500', 'text-white');
				}
			});
			
			// Animation level buttons
			document.querySelectorAll('.animation-level-btn').forEach(btn => {
				btn.classList.remove('active', 'bg-primary-500', 'text-white');
				btn.classList.add('text-gray-800', 'dark:text-white');
				if (btn.dataset.level === APP_STATE.settings.animationLevel) {
					btn.classList.remove('text-gray-800', 'dark:text-white');
					btn.classList.add('active', 'bg-primary-500', 'text-white');
				}
			});
			
			// Page width buttons
			document.querySelectorAll('.page-width-btn').forEach(btn => {
				btn.classList.remove('active', 'bg-primary-500', 'text-white');
				btn.classList.add('text-gray-800', 'dark:text-white');
				if (btn.dataset.width === APP_STATE.settings.pageWidth) {
					btn.classList.remove('text-gray-800', 'dark:text-white');
					btn.classList.add('active', 'bg-primary-500', 'text-white');
				}
			});
			
			DEBUG && console.log('✅ UI preferences highlighted');
		},
		
		/**
		 * Save settings immediately without UI feedback
		 */
		saveSettingsImmediately: () => {
			try {
				localStorage.setItem('rdpmon-settings', JSON.stringify(APP_STATE.settings));
				DEBUG && console.log('💾 Settings saved immediately');
			} catch (error) {
				DEBUG && console.error('❌ Error saving settings:', error);
			}
		},
		
		/**
		 * Initialize settings event listeners
		 */
		initEventListeners: () => {
			DEBUG && console.log('🔌 Initializing settings event listeners...');
			
			// Save settings button
			if (DOM.saveSettings) {
				DOM.saveSettings.addEventListener('click', () => {
					DEBUG && console.log('💾 Save settings button clicked');
					// Collect current settings from UI
					APP_STATE.settings = {
						ipInfoService: DOM.ipInfoService.value,
						defaultChartPeriod: DOM.defaultChartPeriod.value,
						chartItemsLimit: parseInt(DOM.chartItemsLimit.value),
						themeMode: document.querySelector('.theme-mode-btn.active')?.dataset.mode || 'auto',
						tableDensity: document.querySelector('.table-density-btn.active')?.dataset.density || 'normal',
						animationLevel: document.querySelector('.animation-level-btn.active')?.dataset.level || 'minimal',
						autoRefreshInterval: parseInt(DOM.settingsRefreshInterval.value),
						itemsPerPage: parseInt(DOM.pageSizeSelect.value) || 10
					};
					SettingsManager.saveSettings();
				});
			}
			
			// Reset settings button
			if (DOM.resetSettings) {
				DOM.resetSettings.addEventListener('click', SettingsManager.resetSettings);
			}
			
			// Clear storage button
			if (DOM.clearStorage) {
				DOM.clearStorage.addEventListener('click', () => {
					if (confirm('Clear all local storage data? This will reset all settings and cached data.')) {
						localStorage.clear();
						sessionStorage.clear();
						location.reload();
					}
				});
			}
			
			// Settings refresh interval slider
			if (DOM.settingsRefreshInterval) {
				DOM.settingsRefreshInterval.addEventListener('input', (e) => {
					DOM.settingsIntervalValue.textContent = `${e.target.value}s`;
				});
			}
			
			// Page size selector
			if (DOM.pageSizeSelect) {
				DOM.pageSizeSelect.addEventListener('change', (e) => {
					APP_STATE.settings.itemsPerPage = parseInt(e.target.value);
					APP_STATE.pageSize = APP_STATE.settings.itemsPerPage;
					APP_STATE.currentPage = 1;
					updateConnectionsTable();
					SettingsManager.saveSettingsImmediately();
				});
			}
			
			// Theme mode buttons - apply immediately
			document.querySelectorAll('.theme-mode-btn').forEach(btn => {
				btn.addEventListener('click', function() {
					DEBUG && console.log('🎨 Theme mode button clicked:', this.dataset.mode);
					// Update visual state
					document.querySelectorAll('.theme-mode-btn').forEach(b => {
						b.classList.remove('active', 'bg-primary-500', 'text-white');
						b.classList.add('text-gray-800', 'dark:text-white');
					});
					this.classList.remove('text-gray-800', 'dark:text-white');
					this.classList.add('active', 'bg-primary-500', 'text-white');
					
					// Update setting
					APP_STATE.settings.themeMode = this.dataset.mode;
					
					// Apply theme immediately
					SettingsManager.applyTheme();
					
					// Save settings
					SettingsManager.saveSettingsImmediately();
					
					Utils.showNotification(`Theme changed to ${this.dataset.mode} mode`);
				});
			});
			
			// Table density buttons - apply immediately
			document.querySelectorAll('.table-density-btn').forEach(btn => {
				btn.addEventListener('click', function() {
					DEBUG && console.log('📊 Table density button clicked:', this.dataset.density);
					// Update visual state
					document.querySelectorAll('.table-density-btn').forEach(b => {
						b.classList.remove('active', 'bg-primary-500', 'text-white');
						b.classList.add('text-gray-800', 'dark:text-white');
					});
					this.classList.remove('text-gray-800', 'dark:text-white');
					this.classList.add('active', 'bg-primary-500', 'text-white');
					
					// Update setting
					APP_STATE.settings.tableDensity = this.dataset.density;
					
					// Apply table density immediately
					SettingsManager.applyTableDensity();
					
					// Save settings
					SettingsManager.saveSettingsImmediately();
					
					Utils.showNotification(`Table density changed to ${this.dataset.density}`);
				});
			});
			
			// Animation level buttons - apply immediately
			document.querySelectorAll('.animation-level-btn').forEach(btn => {
				btn.addEventListener('click', function() {
					DEBUG && console.log('🎬 Animation level button clicked:', this.dataset.level);
					// Update visual state
					document.querySelectorAll('.animation-level-btn').forEach(b => {
						b.classList.remove('active', 'bg-primary-500', 'text-white');
						b.classList.add('text-gray-800', 'dark:text-white');
					});
					this.classList.remove('text-gray-800', 'dark:text-white');
					this.classList.add('active', 'bg-primary-500', 'text-white');
					
					// Update setting
					APP_STATE.settings.animationLevel = this.dataset.level;
					
					// Apply animation level
					SettingsManager.applyAnimationLevel();
					
					// Save settings
					SettingsManager.saveSettingsImmediately();
					
					Utils.showNotification(`Animation level changed to ${this.dataset.level}`);
				});
			});
			
			// Page width buttons - apply immediately
			document.querySelectorAll('.page-width-btn').forEach(btn => {
				btn.addEventListener('click', function() {
					DEBUG && console.log('📏 Page width button clicked:', this.dataset.width);
					// Update visual state
					document.querySelectorAll('.page-width-btn').forEach(b => {
						b.classList.remove('active', 'bg-primary-500', 'text-white');
						b.classList.add('text-gray-800', 'dark:text-white');
					});
					this.classList.remove('text-gray-800', 'dark:text-white');
					this.classList.add('active', 'bg-primary-500', 'text-white');
					
					// Update setting
					APP_STATE.settings.pageWidth = this.dataset.width;
					
					// Apply page width immediately
					SettingsManager.applyPageWidth();
					
					// Save settings
					SettingsManager.saveSettingsImmediately();
					
					Utils.showNotification(`Page width changed to ${this.dataset.width}`);
				});
			});
			
			// Clear storage button
			if (DOM.clearStorage) {
				DOM.clearStorage.addEventListener('click', () => {
					if (confirm('Clear all local storage data? This will reset all settings and cached data.')) {
						localStorage.clear();
						sessionStorage.clear();
						location.reload();
					}
				});
			}
			
			DEBUG && console.log('✅ Settings event listeners initialized');
		}
	};

	/**
	 * Action Functions
	 */
	
	/**
	 * Show connection details modal
	 * 
	 * @param {string} ip - IP address to show details for
	 */
	function showDetails(ip) {
		DEBUG && console.log('👁️ Showing details for IP:', ip);
		
		const item = APP_STATE.addrData.find(d => d.IP === ip);
		if (item) {
			const usernames = Array.isArray(item.UserNames) ? item.UserNames : [];
			const typeColors = Utils.getTypeColor(item.ConnectionType);
			
			// Generate attack description for copying
			const attackDescription = `IP Address: ${item.IP}\n` +
				`Hostname: ${item.Hostname || 'Not resolved'}\n` +
				`Connection Type: ${item.ConnectionType}\n` +
				`Failed Attempts: ${item.FailCount}\n` +
				`Successful Logins: ${item.SuccessCount}\n` +
				`First Seen: ${Utils.formatDate(item.FirstLocal)}\n` +
				`Last Seen: ${Utils.formatDate(item.LastLocal)}\n` +
				`Usernames Attempted: ${usernames.join(', ') || 'None'}\n` +
				`Duration: ${Utils.formatDuration(item.Duration)}\n\n` +
				`Generated by RDP Monitor: ${window.GIT_URL || 'https://github.com/paulmann/RDPAudit'}`;
			
			// Get current information service from localStorage or default
			let infoService = 'ripe';
			const savedSettings = localStorage.getItem('rdpmon-settings');
			if (savedSettings) {
				try {
					const parsed = JSON.parse(savedSettings);
					infoService = parsed.ipInfoService || 'ripe';
				} catch (e) {
					DEBUG && console.error('Error parsing saved settings:', e);
				}
			}
			
			let infoUrl = '';
			let infoName = '';
			
			switch(infoService) {
				case 'whois':
					infoUrl = `https://whois.domaintools.com/${item.IP}`;
					infoName = 'Whois';
					break;
				case 'ripe':
					infoUrl = `https://stat.ripe.net/resource/${item.IP}`;
					infoName = 'RIPE NCC';
					break;
				default:
					infoUrl = `https://whois.domaintools.com/${item.IP}`;
					infoName = 'Whois';
			}
			
			const modal = `
				<div class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4 modal-overlay">
					<div class="glass-card rounded-2xl p-6 max-w-2xl w-full max-h-[90vh] overflow-y-auto modal-content">
						<div class="flex justify-between items-center mb-6 pb-4 border-b border-gray-200 dark:border-gray-700">
							<div>
								<h3 class="text-xl font-bold text-gray-800 dark:text-white">Connection Details</h3>
								<p class="text-sm text-gray-500 dark:text-gray-400 mt-1">Complete information and actions</p>
							</div>
							<button class="close-modal-btn p-2 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg text-gray-800 dark:text-white transition-colors">
								<i class="fas fa-times text-lg"></i>
							</button>
						</div>
						
						<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
							<div class="space-y-4">
								<div>
									<label class="text-sm font-medium text-gray-500 dark:text-gray-400">IP Address</label>
									<div class="flex items-center mt-1">
										<code class="font-mono text-lg font-bold text-gray-800 dark:text-white">${Utils.escapeHtml(item.IP || 'Unknown')}</code>
										<button class="copy-ip-modal-btn ml-2 p-1 text-gray-500 hover:text-primary-500 transition-colors" title="Copy IP" data-ip="${Utils.escapeHtml(item.IP || '')}">
											<i class="fas fa-copy"></i>
										</button>
									</div>
								</div>
								
								<div>
									<label class="text-sm font-medium text-gray-500 dark:text-gray-400">Hostname</label>
									<p class="font-medium text-gray-800 dark:text-white mt-1">${Utils.escapeHtml(item.Hostname || 'Not resolved')}</p>
								</div>
								
								<div>
									<label class="text-sm font-medium text-gray-500 dark:text-gray-400">Connection Type</label>
									<div class="mt-1">
										<span class="inline-flex items-center px-3 py-1.5 rounded-full text-sm font-medium ${typeColors.bg} ${typeColors.text}">
											<i class="fas ${typeColors.icon} mr-2"></i>
											${Utils.escapeHtml(item.ConnectionType || 'Unknown')}
										</span>
									</div>
								</div>
							</div>
							
							<div class="space-y-4">
								<div class="grid grid-cols-2 gap-4">
									<div>
										<label class="text-sm font-medium text-gray-500 dark:text-gray-400">Failed</label>
										<p class="text-2xl font-bold text-danger-600 dark:text-danger-400 mt-1">${parseInt(item.FailCount) || 0}</p>
									</div>
									<div>
										<label class="text-sm font-medium text-gray-500 dark:text-gray-400">Successful</label>
										<p class="text-2xl font-bold text-success-600 dark:text-success-400 mt-1">${parseInt(item.SuccessCount) || 0}</p>
									</div>
								</div>
								
								<div>
									<label class="text-sm font-medium text-gray-500 dark:text-gray-400">Duration</label>
									<p class="font-medium text-gray-800 dark:text-white mt-1">${Utils.formatDuration(item.Duration)}</p>
								</div>
								
								<div>
									<label class="text-sm font-medium text-gray-500 dark:text-gray-400">Users Attempted</label>
									<p class="font-medium text-gray-800 dark:text-white mt-1 truncate" title="${Utils.escapeHtml(usernames.join(', '))}">
										${usernames.slice(0, 3).join(', ')}${usernames.length > 3 ? `... (+${usernames.length - 3} more)` : ''}
									</p>
								</div>
							</div>
						</div>
						
						<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
							<div>
								<label class="text-sm font-medium text-gray-500 dark:text-gray-400">First Seen</label>
								<p class="font-medium text-gray-800 dark:text-white mt-1">${Utils.formatDate(item.FirstLocal)}</p>
							</div>
							<div>
								<label class="text-sm font-medium text-gray-500 dark:text-gray-400">Last Seen</label>
								<p class="font-medium text-gray-800 dark:text-white mt-1">${Utils.formatDate(item.LastLocal)}</p>
							</div>
						</div>
						
						<div class="pt-6 border-t border-gray-200 dark:border-gray-700">
							<h4 class="text-lg font-semibold text-gray-800 dark:text-white mb-4">Quick Actions</h4>
							<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
								<button class="copy-ip-action-btn px-4 py-2 glass-card rounded-xl hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-gray-800 dark:text-white flex items-center justify-center" data-ip="${Utils.escapeHtml(item.IP || '')}">
									<i class="fas fa-copy mr-2"></i>Copy IP
								</button>
								
								<button class="copy-attack-description-btn px-4 py-2 glass-card rounded-xl hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-gray-800 dark:text-white flex items-center justify-center" data-description="${Utils.escapeHtml(attackDescription)}">
									<i class="fas fa-file-alt mr-2"></i>Copy Report
								</button>
								
								<button class="open-info-service-btn px-4 py-2 glass-card rounded-xl hover:bg-blue-50 dark:hover:bg-blue-900/20 transition-colors text-gray-800 dark:text-white flex items-center justify-center" data-ip="${Utils.escapeHtml(item.IP || '')}">
									<i class="fas fa-search mr-2"></i>${infoName}
								</button>
								
								<button class="open-abuseipdb-check-btn px-4 py-2 glass-card rounded-xl hover:bg-orange-50 dark:hover:bg-orange-900/20 transition-colors text-gray-800 dark:text-white flex items-center justify-center" data-ip="${Utils.escapeHtml(item.IP || '')}">
									<i class="fas fa-shield-alt mr-2"></i>AbuseIPDB
								</button>
								
								<button class="open-abuseipdb-report-btn px-4 py-2 glass-card rounded-xl hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors text-gray-800 dark:text-white flex items-center justify-center" 
									data-ip="${Utils.escapeHtml(item.IP || '')}" 
									data-description="${Utils.escapeHtml(attackDescription)}">
									<i class="fas fa-flag mr-2"></i>Report to AbuseIPDB
								</button>
								
								<button class="open-github-btn px-4 py-2 glass-card rounded-xl hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors text-gray-800 dark:text-white flex items-center justify-center">
									<i class="fab fa-github mr-2"></i>GitHub
								</button>
							</div>
							
							<div class="mt-6">
								<button class="block-ip-modal-btn w-full px-4 py-3 bg-danger-500 hover:bg-danger-600 text-white rounded-xl transition-all duration-300 hover:scale-[1.02] flex items-center justify-center font-medium" data-ip="${Utils.escapeHtml(item.IP || '')}">
									<i class="fas fa-ban mr-2"></i>Block this IP in Firewall
								</button>
							</div>
						</div>
					</div>
				</div>
			`;
			
			// Remove existing modal if any
			const existingModal = document.querySelector('.modal-overlay');
			if (existingModal) {
				existingModal.remove();
			}
			
			document.body.insertAdjacentHTML('beforeend', modal);
			
			// Add event listeners to modal buttons
			const modalElement = document.querySelector('.modal-overlay');
			
			if (modalElement) {
				const closeBtn = modalElement.querySelector('.close-modal-btn');
				if (closeBtn) {
					closeBtn.addEventListener('click', () => {
						DEBUG && console.log('❌ Closing modal');
						modalElement.remove();
					});
				}
				
				// Copy IP button in header
				modalElement.querySelector('.copy-ip-modal-btn')?.addEventListener('click', (e) => {
					const ip = e.currentTarget.getAttribute('data-ip');
					DEBUG && console.log('📋 Copy IP (modal header):', ip);
					Utils.copyToClipboard(ip);
				});
				
				// Copy IP action button
				modalElement.querySelector('.copy-ip-action-btn')?.addEventListener('click', (e) => {
					const ip = e.currentTarget.getAttribute('data-ip');
					DEBUG && console.log('📋 Copy IP (action):', ip);
					Utils.copyToClipboard(ip);
				});
				
				// Copy attack description button
				modalElement.querySelector('.copy-attack-description-btn')?.addEventListener('click', (e) => {
					const description = e.currentTarget.getAttribute('data-description');
					DEBUG && console.log('📋 Copy attack description');
					Utils.copyAttackDescription(description);
				});
				
				// Open info service button
				modalElement.querySelector('.open-info-service-btn')?.addEventListener('click', (e) => {
					const ip = e.currentTarget.getAttribute('data-ip');
					DEBUG && console.log('🌐 Open IP info:', ip);
					Utils.openIpInfo(ip);
				});
				
				// Open AbuseIPDB check button
				modalElement.querySelector('.open-abuseipdb-check-btn')?.addEventListener('click', (e) => {
					const ip = e.currentTarget.getAttribute('data-ip');
					DEBUG && console.log('🔍 Open AbuseIPDB check:', ip);
					Utils.openAbuseIPDBCheck(ip);
				});
				
				// Open AbuseIPDB report button
				modalElement.querySelector('.open-abuseipdb-report-btn')?.addEventListener('click', (e) => {
					const ip = e.currentTarget.getAttribute('data-ip');
					const description = e.currentTarget.getAttribute('data-description');
					DEBUG && console.log('🚩 Open AbuseIPDB report:', ip);
					Utils.openAbuseIPDBReport(ip, description);
				});
				
				// Open GitHub button
				modalElement.querySelector('.open-github-btn')?.addEventListener('click', () => {
					DEBUG && console.log('🐙 Open GitHub');
					Utils.openGitHubProject();
				});
				
				// Block IP button
				modalElement.querySelector('.block-ip-modal-btn')?.addEventListener('click', (e) => {
					const ip = e.currentTarget.getAttribute('data-ip');
					DEBUG && console.log('🚫 Block IP (modal):', ip);
					Utils.blockIPInFirewall(ip);
				});
				
				// Close modal when clicking outside
				modalElement.addEventListener('click', (e) => {
					if (e.target === modalElement) {
						DEBUG && console.log('❌ Closing modal (outside click)');
						modalElement.remove();
					}
				});
				
				// Close modal with Escape key
				document.addEventListener('keydown', function handleEscape(e) {
					if (e.key === 'Escape' && modalElement) {
						DEBUG && console.log('❌ Closing modal (Escape key)');
						modalElement.remove();
						document.removeEventListener('keydown', handleEscape);
					}
				});
				
				DEBUG && console.log('✅ Modal event listeners attached');
			} else {
				DEBUG && console.error('❌ Modal element not found');
			}
		} else {
			DEBUG && console.error('❌ Item not found for IP:', ip);
			Utils.showNotification('Connection details not found', 'error');
		}
	}
	
	/**
	 * Block IP in firewall (placeholder function)
	 * 
	 * @param {string} ip - IP address to block
	 */
	function blockIP(ip) {
		DEBUG && console.log('🚫 Block IP function called:', ip);
		Utils.blockIPInFirewall(ip);
	}
	
	/**
	 * Export data as JSON file
	 */
	function exportData() {
		DEBUG && console.log('📤 Exporting data...');
		
		const exportData = {
			AddrData: APP_STATE.addrData,
			SessionData: APP_STATE.sessionData,
			PropData: APP_STATE.propData,
			DatabaseStats: APP_STATE.databaseStats,
			ExportTime: new Date().toISOString(),
			Settings: APP_STATE.settings
		};
		
		const dataStr = JSON.stringify(exportData, null, 2);
		const dataBlob = new Blob([dataStr], { type: 'application/json' });
		const url = URL.createObjectURL(dataBlob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `rdpmon-complete-report-${new Date().toISOString().slice(0, 10)}.json`;
		document.body.appendChild(a);
		a.click();
		document.body.removeChild(a);
		URL.revokeObjectURL(url);
		
		Utils.showNotification('Data exported successfully');
	}

	/**
	 * Public API
	 * Expose selected functions and modules for external use
	 */
	return {
		init: init,
		Utils: Utils,
		SettingsManager: SettingsManager,
		APP_STATE: APP_STATE // Expose for debugging
	};
})();

/**
 * Make application globally available
 * Ensures compatibility with various module systems
 */
if (typeof window !== 'undefined') {
	window.RDP_Monitor_App = RDP_Monitor_App;
}

/**
 * AMD/RequireJS compatibility
 */
if (typeof define === 'function' && define.amd) {
	define([], function() {
		return RDP_Monitor_App;
	});
}

/**
 * CommonJS/Node.js compatibility
 */
if (typeof module !== 'undefined' && module.exports) {
	module.exports = RDP_Monitor_App;
}

/**
 * Initialize application when DOM is fully loaded
 */
document.addEventListener('DOMContentLoaded', () => {
    DEBUG && console.log('📄 DOM fully loaded, initializing app...');
    
    // Prevent double initialization
    if (window.APP_INITIALIZED) {
        DEBUG && console.log('⚠️ App already initialized, skipping...');
        return;
    }
    
    if (typeof RDP_Monitor_App !== 'undefined') {
        RDP_Monitor_App.init({
            gitUrl: window.GIT_URL,
            templateVars: window.TEMPLATE_VARS,
            parsePowerShellJSON: window.parsePowerShellJSON
        });
        window.APP_INITIALIZED = true;
    } else {
        DEBUG && console.error('❌ RDP_Monitor_App not defined');
    }
});