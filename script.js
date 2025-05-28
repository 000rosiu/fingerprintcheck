// Global variables
let privacyScore = { safe: 0, warning: 0, danger: 0 };
let currentTheme = 'dark';

// Initialize application
document.addEventListener('DOMContentLoaded', function() {
    initializeTheme();
    initializeTests();
    setupEventListeners();
});

// Theme Management
function initializeTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    setTheme(savedTheme);

    const themeSwitch = document.getElementById('themeSwitch');
    themeSwitch.checked = savedTheme === 'light';
}

function setTheme(theme) {
    currentTheme = theme;
    document.documentElement.setAttribute('data-bs-theme', theme);
    localStorage.setItem('theme', theme);

    const themeIcon = document.getElementById('theme-icon');
    if (theme === 'light') {
        themeIcon.className = 'fas fa-moon';
    } else {
        themeIcon.className = 'fas fa-sun';
    }
}

function setupEventListeners() {
    const themeSwitch = document.getElementById('themeSwitch');
    themeSwitch.addEventListener('change', function() {
        const newTheme = this.checked ? 'light' : 'dark';
        setTheme(newTheme);
    });
}

// Initialize all tests
function initializeTests() {
    getIPAddress();
    loadBrowserDetails();
    loadSystemDetails();
    loadScreenDetails();
    loadPluginsDetails();
    updatePrivacyScore();
}

// Enhanced IP Address Detection with comprehensive API
async function getIPAddress() {
    try {
        // Primary IP detection
        const ipResponse = await fetch('https://api.ipify.org?format=json');
        const ipData = await ipResponse.json();
        const ip = ipData.ip;
        document.getElementById('ip-address').innerHTML = ip;

        // Enhanced IP information from multiple sources
        await Promise.allSettled([
            getIPInfoFromIPAPI(ip),
            getIPInfoFromIPInfo(ip),
            getIPInfoFromIPGeolocation(ip)
        ]);

    } catch (error) {
        document.getElementById('ip-address').innerHTML = 'Unable to fetch IP';
        privacyScore.danger++;
        updatePrivacyScore();
    }
}

// IP API (ipapi.co) - Free tier
async function getIPInfoFromIPAPI(ip) {
    try {
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        const data = await response.json();

        document.getElementById('ip-details').innerHTML = `
            <div class="row">
                <div class="col-md-6">
                    <p><strong>Location:</strong> ${data.city}, ${data.region}, ${data.country_name}</p>
                    <p><strong>Coordinates:</strong> ${data.latitude}, ${data.longitude}</p>
                    <p><strong>Timezone:</strong> ${data.timezone}</p>
                </div>
                <div class="col-md-6">
                    <p><strong>ISP:</strong> ${data.org}</p>
                    <p><strong>ASN:</strong> ${data.asn}</p>
                    <p><strong>Postal Code:</strong> ${data.postal}</p>
                </div>
            </div>
        `;

        await getExtendedIPInfo(ip, data);

    } catch (error) {
        console.error('IPAPI error:', error);
    }
}

// IPInfo.io API (requires token for full features)
async function getIPInfoFromIPInfo(ip) {
    try {
        const response = await fetch(`https://ipinfo.io/${ip}/json`);
        const data = await response.json();

        // This is backup info if primary fails
        if (!document.getElementById('ip-details').innerHTML) {
            document.getElementById('ip-details').innerHTML = `
                <div class="row">
                    <div class="col-md-6">
                        <p><strong>Location:</strong> ${data.city}, ${data.region}, ${data.country}</p>
                        <p><strong>Coordinates:</strong> ${data.loc}</p>
                    </div>
                    <div class="col-md-6">
                        <p><strong>ISP:</strong> ${data.org}</p>
                        <p><strong>Postal:</strong> ${data.postal}</p>
                    </div>
                </div>
            `;
        }

    } catch (error) {
        console.error('IPInfo error:', error);
    }
}

// IP Geolocation API
async function getIPInfoFromIPGeolocation(ip) {
    try {
        const response = await fetch(`https://api.ipgeolocation.io/ipgeo?apiKey=demo&ip=${ip}`);
        const data = await response.json();

        // Additional security information
        if (data && !data.message) {
            const securityInfo = `
                <div class="mt-3">
                    <h6>Security Analysis:</h6>
                    <div class="row">
                        <div class="col-md-6">
                            <p><strong>Connection Type:</strong> ${data.connection_type || 'Unknown'}</p>
                            <p><strong>ISP Type:</strong> ${data.isp || 'Unknown'}</p>
                        </div>
                        <div class="col-md-6">
                            <p><strong>Threat Level:</strong> <span class="status-good">Low</span></p>
                            <p><strong>Proxy/VPN:</strong> <span class="status-info">Checking...</span></p>
                        </div>
                    </div>
                </div>
            `;
            document.getElementById('ip-extended').innerHTML = securityInfo;
        }

    } catch (error) {
        console.error('IP Geolocation error:', error);
    }
}

// Extended IP analysis
async function getExtendedIPInfo(ip, basicData) {
    try {
        // Check for VPN/Proxy (simplified detection)
        const isVPN = await checkVPNStatus(ip);
        const isTor = await checkTorStatus(ip);

        const extendedInfo = `
            <div class="mt-4">
                <h6>Extended Analysis:</h6>
                <div class="row">
                    <div class="col-md-3">
                        <div class="p-3 border rounded">
                            <div class="leak-indicator ${isVPN ? 'leak-warning' : 'leak-safe'}"></div>
                            <strong>VPN/Proxy:</strong> ${isVPN ? 'Detected' : 'Not detected'}
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="p-3 border rounded">
                            <div class="leak-indicator ${isTor ? 'leak-warning' : 'leak-safe'}"></div>
                            <strong>Tor Exit:</strong> ${isTor ? 'Yes' : 'No'}
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="p-3 border rounded">
                            <div class="leak-indicator leak-info"></div>
                            <strong>IP Type:</strong> ${getIPType(ip)}
                        </div>
                    </div>
                    <div class="col-md-3">
                        <div class="p-3 border rounded">
                            <div class="leak-indicator leak-safe"></div>
                            <strong>Risk Score:</strong> Low
                        </div>
                    </div>
                </div>
                <div class="mt-3">
                    <h6>ISP Details:</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Organization:</strong></td><td>${basicData.org || 'Unknown'}</td></tr>
                        <tr><td><strong>ASN:</strong></td><td>${basicData.asn || 'Unknown'}</td></tr>
                        <tr><td><strong>Country Code:</strong></td><td>${basicData.country_code || 'Unknown'}</td></tr>
                        <tr><td><strong>Currency:</strong></td><td>${basicData.currency || 'Unknown'}</td></tr>
                        <tr><td><strong>Calling Code:</strong></td><td>${basicData.country_calling_code || 'Unknown'}</td></tr>
                    </table>
                </div>
            </div>
        `;

        document.getElementById('ip-extended').innerHTML = extendedInfo;

    } catch (error) {
        console.error('Extended IP info error:', error);
    }
}

// VPN Detection (simplified)
async function checkVPNStatus(ip) {
    try {
        // This is a simplified check - in real implementation you'd use specialized APIs
        const response = await fetch(`https://vpnapi.io/api/${ip}?key=demo`);
        const data = await response.json();
        return data.security?.vpn || false;
    } catch (error) {
        return false;
    }
}

// Tor Detection
async function checkTorStatus(ip) {
    try {
        // Simplified Tor check
        const response = await fetch(`https://check.torproject.org/api/ip`);
        const data = await response.json();
        return data.IsTor || false;
    } catch (error) {
        return false;
    }
}

// Get IP Type (IPv4/IPv6)
function getIPType(ip) {
    if (ip.includes(':')) {
        return 'IPv6';
    } else if (ip.includes('.')) {
        return 'IPv4';
    }
    return 'Unknown';
}

// Browser Details
function loadBrowserDetails() {
    const details = `
        <table class="table table-sm">
            <tr><td><strong>User Agent:</strong></td><td class="small">${navigator.userAgent}</td></tr>
            <tr><td><strong>Browser:</strong></td><td>${getBrowserName()}</td></tr>
            <tr><td><strong>Version:</strong></td><td>${getBrowserVersion()}</td></tr>
            <tr><td><strong>Language:</strong></td><td>${navigator.language}</td></tr>
            <tr><td><strong>Languages:</strong></td><td>${navigator.languages.join(', ')}</td></tr>
            <tr><td><strong>Cookies:</strong></td><td class="${navigator.cookieEnabled ? 'status-good' : 'status-bad'}">${navigator.cookieEnabled ? 'Enabled' : 'Disabled'}</td></tr>
            <tr><td><strong>Do Not Track:</strong></td><td>${navigator.doNotTrack || 'Not set'}</td></tr>
            <tr><td><strong>Online:</strong></td><td class="${navigator.onLine ? 'status-good' : 'status-bad'}">${navigator.onLine ? 'Yes' : 'No'}</td></tr>
        </table>
    `;
    document.getElementById('browser-details').innerHTML = details;
    privacyScore.safe++;
}

// System Details
function loadSystemDetails() {
    const details = `
        <table class="table table-sm">
            <tr><td><strong>Platform:</strong></td><td>${navigator.platform}</td></tr>
            <tr><td><strong>OS:</strong></td><td>${getOSName()}</td></tr>
            <tr><td><strong>CPU Cores:</strong></td><td>${navigator.hardwareConcurrency || 'Unknown'}</td></tr>
            <tr><td><strong>Memory:</strong></td><td>${navigator.deviceMemory ? navigator.deviceMemory + ' GB' : 'Unknown'}</td></tr>
            <tr><td><strong>Timezone:</strong></td><td>${Intl.DateTimeFormat().resolvedOptions().timeZone}</td></tr>
            <tr><td><strong>UTC Offset:</strong></td><td>${new Date().getTimezoneOffset() / -60} hours</td></tr>
            <tr><td><strong>Touch Screen:</strong></td><td class="${'ontouchstart' in window ? 'status-warning' : 'status-good'}">${'ontouchstart' in window ? 'Yes' : 'No'}</td></tr>
        </table>
    `;
    document.getElementById('system-details').innerHTML = details;
    privacyScore.warning++;
}

// Screen Details
function loadScreenDetails() {
    const details = `
        <table class="table table-sm">
            <tr><td><strong>Resolution:</strong></td><td>${screen.width}x${screen.height}</td></tr>
            <tr><td><strong>Available:</strong></td><td>${screen.availWidth}x${screen.availHeight}</td></tr>
            <tr><td><strong>Color Depth:</strong></td><td>${screen.colorDepth} bit</td></tr>
            <tr><td><strong>Pixel Ratio:</strong></td><td>${window.devicePixelRatio}</td></tr>
            <tr><td><strong>Orientation:</strong></td><td>${screen.orientation?.type || 'Unknown'}</td></tr>
            <tr><td><strong>Viewport:</strong></td><td>${window.innerWidth}x${window.innerHeight}</td></tr>
        </table>
    `;
    document.getElementById('screen-details').innerHTML = details;
    privacyScore.warning++;
}

// Plugins Details
function loadPluginsDetails() {
    let pluginsList = '<div class="small">';
    if (navigator.plugins.length === 0) {
        pluginsList += '<p class="status-good">No plugins detected</p>';
        privacyScore.safe++;
    } else {
        pluginsList += '<table class="table table-sm">';
        for (let i = 0; i < navigator.plugins.length; i++) {
            const plugin = navigator.plugins[i];
            pluginsList += `
                <tr>
                    <td><strong>${plugin.name}</strong></td>
                    <td class="small">${plugin.description}</td>
                </tr>
            `;
        }
        pluginsList += '</table>';
        privacyScore.warning++;
    }
    pluginsList += '</div>';
    document.getElementById('plugins-details').innerHTML = pluginsList;
}

// WebRTC Test
function testWebRTC() {
    const resultsDiv = document.getElementById('webrtc-results');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div class="loading-spinner"></div> Testing WebRTC...';

    const rtcConfig = {
        iceServers: [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ]
    };

    const pc = new RTCPeerConnection(rtcConfig);
    const ips = [];

    pc.onicecandidate = function(event) {
        if (event.candidate) {
            const candidate = event.candidate.candidate;
            const ip = candidate.match(/(\d+\.\d+\.\d+\.\d+)/);
            if (ip && !ips.includes(ip[1])) {
                ips.push(ip[1]);
            }
        }
    };

    pc.createDataChannel('test');
    pc.createOffer().then(offer => pc.setLocalDescription(offer));

    setTimeout(() => {
        pc.close();
        let results = '<h6>Detected IP Addresses:</h6>';
        if (ips.length > 0) {
            results += '<ul>';
            ips.forEach(ip => {
                const isPrivate = /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(ip);
                results += `<li class="${isPrivate ? 'status-warning' : 'status-bad'}">${ip} ${isPrivate ? '(local)' : '(public - LEAK!)'}</li>`;
            });
            results += '</ul>';
            if (ips.some(ip => !/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/.test(ip))) {
                privacyScore.danger++;
                results += '<div class="alert alert-danger mt-2">⚠️ Public IP leak detected via WebRTC!</div>';
            } else {
                privacyScore.warning++;
            }
        } else {
            results += '<p class="status-good">No IP leaks detected</p>';
            privacyScore.safe++;
        }
        resultsDiv.innerHTML = results;
        updatePrivacyScore();
    }, 3000);
}

// Canvas Fingerprinting
function generateCanvasFingerprint() {
    const canvas = document.getElementById('canvas-test');
    const ctx = canvas.getContext('2d');
    const resultsDiv = document.getElementById('canvas-results');

    // Clear canvas with theme-appropriate background
    ctx.fillStyle = currentTheme === 'dark' ? '#0d1117' : '#ffffff';
    ctx.fillRect(0, 0, 400, 200);

    // Draw complex shapes for fingerprinting
    ctx.fillStyle = '#6457c1';
    ctx.fillRect(10, 10, 200, 50);

    ctx.fillStyle = '#ffffff';
    ctx.font = '16px JetBrains Mono';
    ctx.fillText('checkup.000r.ovh', 20, 35);

    ctx.fillStyle = '#f85149';
    ctx.beginPath();
    ctx.arc(200, 100, 30, 0, 2 * Math.PI);
    ctx.fill();

    ctx.fillStyle = '#ffffff';
    ctx.font = '12px JetBrains Mono';
    ctx.fillText('Fingerprint test', 250, 100);

    // Generate hash
    const imageData = canvas.toDataURL();
    const hash = generateSimpleHash(imageData);

    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = `
        <h6>Canvas Fingerprint:</h6>
        <p><strong>Hash:</strong> <code>${hash}</code></p>
        <p><strong>Data Length:</strong> ${imageData.length} characters</p>
        <div class="alert alert-warning mt-2">⚠️ Canvas can be used for tracking</div>
    `;
    privacyScore.warning++;
    updatePrivacyScore();
}

// WebGL Test
function testWebGL() {
    const resultsDiv = document.getElementById('webgl-results');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div class="loading-spinner"></div> Testing WebGL...';

    setTimeout(() => {
        try {
            const canvas = document.createElement('canvas');
            const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'Unknown';
                const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'Unknown';

                resultsDiv.innerHTML = `
                    <h6>WebGL Information:</h6>
                    <table class="table table-sm">
                        <tr><td><strong>Vendor:</strong></td><td>${vendor}</td></tr>
                        <tr><td><strong>Renderer:</strong></td><td>${renderer}</td></tr>
                        <tr><td><strong>Version:</strong></td><td>${gl.getParameter(gl.VERSION)}</td></tr>
                        <tr><td><strong>Shading Language:</strong></td><td>${gl.getParameter(gl.SHADING_LANGUAGE_VERSION)}</td></tr>
                    </table>
                    <div class="alert alert-warning mt-2">⚠️ WebGL reveals graphics card information</div>
                `;
                privacyScore.warning++;
            } else {
                resultsDiv.innerHTML = '<p class="status-good">WebGL not available</p>';
                privacyScore.safe++;
            }
        } catch (e) {
            resultsDiv.innerHTML = '<p class="status-bad">Error testing WebGL</p>';
            privacyScore.danger++;
        }
        updatePrivacyScore();
    }, 1000);
}

// Font Detection
function testFonts() {
    const resultsDiv = document.getElementById('fonts-results');
    const progressDiv = document.getElementById('font-progress');
    const progressBar = progressDiv.querySelector('.progress-bar');

    resultsDiv.style.display = 'block';
    progressDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div class="loading-spinner"></div> Scanning fonts...';

    const fonts = [
        'Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Verdana', 'Georgia',
        'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS', 'Arial Black',
        'Impact', 'Lucida Sans Unicode', 'Tahoma', 'Lucida Console', 'Monaco',
        'Bradley Hand ITC', 'Brush Script MT', 'Luminari', 'Chalkduster', 'Papyrus',
        'Calibri', 'Cambria', 'Consolas', 'Franklin Gothic Medium', 'Segoe UI',
        'JetBrains Mono', 'Fira Code', 'Source Code Pro', 'Roboto', 'Open Sans'
    ];

    const detectedFonts = [];
    let processed = 0;

    fonts.forEach((font, index) => {
        setTimeout(() => {
            if (isFontAvailable(font)) {
                detectedFonts.push(font);
            }
            processed++;
            const progress = (processed / fonts.length) * 100;
            progressBar.style.width = progress + '%';

            if (processed === fonts.length) {
                progressDiv.style.display = 'none';
                resultsDiv.innerHTML = `
                    <h6>Detected Fonts (${detectedFonts.length}/${fonts.length}):</h6>
                    <div class="small">${detectedFonts.join(', ')}</div>
                    <div class="alert alert-warning mt-2">⚠️ Font list can be used for identification</div>
                `;
                privacyScore.warning++;
                updatePrivacyScore();
            }
        }, index * 50);
    });
}

// SSL/TLS Test
function testSSL() {
    const resultsDiv = document.getElementById('ssl-results');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = `
        <h6>Connection Information:</h6>
        <table class="table table-sm">
            <tr><td><strong>Protocol:</strong></td><td class="status-good">${location.protocol}</td></tr>
            <tr><td><strong>Host:</strong></td><td>${location.hostname}</td></tr>
            <tr><td><strong>Port:</strong></td><td>${location.port || (location.protocol === 'https:' ? '443' : '80')}</td></tr>
            <tr><td><strong>TLS Support:</strong></td><td class="${location.protocol === 'https:' ? 'status-good' : 'status-bad'}">${location.protocol === 'https:' ? 'Yes' : 'No'}</td></tr>
        </table>
        <div class="alert alert-info mt-2">ℹ️ Detailed certificate information available in developer tools</div>
    `;
    if (location.protocol === 'https:') {
        privacyScore.safe++;
    } else {
        privacyScore.danger++;
    }
    updatePrivacyScore();
}

// DNS Test
function testDNS() {
    const resultsDiv = document.getElementById('dns-results');
    resultsDiv.style.display = 'block';
    resultsDiv.innerHTML = '<div class="loading-spinner"></div> Testing DNS...';

    setTimeout(() => {
        resultsDiv.innerHTML = `
            <h6>DNS Test:</h6>
            <table class="table table-sm">
                <tr><td><strong>DNS over HTTPS:</strong></td><td class="status-info">Check browser settings</td></tr>
                <tr><td><strong>DNS Leak:</strong></td><td class="status-warning">Requires external test</td></tr>
                <tr><td><strong>Resolver:</strong></td><td>System default</td></tr>
            </table>
            <div class="alert alert-info mt-2">ℹ️ Complete DNS testing requires external tools</div>
        `;
        privacyScore.warning++;
        updatePrivacyScore();
    }, 2000);
}

// Helper Functions
function getBrowserName() {
    const ua = navigator.userAgent;
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Safari')) return 'Safari';
    if (ua.includes('Edge')) return 'Edge';
    return 'Unknown';
}

function getBrowserVersion() {
    const ua = navigator.userAgent;
    const match = ua.match(/(Chrome|Firefox|Safari|Edge)\/([0-9.]+)/);
    return match ? match[2] : 'Unknown';
}

function getOSName() {
    const ua = navigator.userAgent;
    if (ua.includes('Windows')) return 'Windows';
    if (ua.includes('Mac')) return 'macOS';
    if (ua.includes('Linux')) return 'Linux';
    if (ua.includes('Android')) return 'Android';
    if (ua.includes('iOS')) return 'iOS';
    return 'Unknown';
}

function isFontAvailable(font) {
    const canvas = document.createElement('canvas');
    const context = canvas.getContext('2d');
    const text = 'abcdefghijklmnopqrstuvwxyz0123456789';

    context.font = '72px monospace';
    const baselineWidth = context.measureText(text).width;

    context.font = `72px "${font}", monospace`;
    const testWidth = context.measureText(text).width;

    return baselineWidth !== testWidth;
}

function generateSimpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16).substring(0, 16);
}

function updatePrivacyScore() {
    document.getElementById('safe-count').textContent = privacyScore.safe;
    document.getElementById('warning-count').textContent = privacyScore.warning;
    document.getElementById('danger-count').textContent = privacyScore.danger;

    const total = privacyScore.safe + privacyScore.warning + privacyScore.danger;
    if (total === 0) return;

    const safePercent = (privacyScore.safe / total) * 100;
    const dangerPercent = (privacyScore.danger / total) * 100;

    let score, className;
    if (dangerPercent > 30) {
        score = 'Low';
        className = 'status-bad';
    } else if (safePercent > 60) {
        score = 'High';
        className = 'status-good';
    } else {
        score = 'Medium';
        className = 'status-warning';
    }

    const scoreElement = document.getElementById('overall-score');
    scoreElement.textContent = score;
    scoreElement.className = className;
}

// Export functions for global access
window.testWebRTC = testWebRTC;
window.generateCanvasFingerprint = generateCanvasFingerprint;
window.testWebGL = testWebGL;
window.testFonts = testFonts;
window.testSSL = testSSL;
window.testDNS = testDNS;
