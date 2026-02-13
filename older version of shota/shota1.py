#!/usr/bin/env python3
"""
███████╗██╗  ██╗ ██████╗ ████████╗ █████╗ 
██╔════╝██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗
███████╗███████║██║   ██║   ██║   ███████║
╚════██║██╔══██║██║   ██║   ██║   ██╔══██║
███████║██║  ██║╚██████╔╝   ██║   ██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

Simple HTTP Offensive Testing Artillery v2.0
Universal security testing framework for ethical hackers

Author: Redzhardtekk
License: MIT
GitHub: https://github.com/redzhardtekk/shota
"""

import requests
import json
import time
import sys
import argparse
import re
import urllib.parse
import itertools
import difflib
import statistics
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
import hashlib

# ========================================
# COLORS & STYLING
# ========================================
class Style:
    # Colors
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    
    # Styles
    BOLD = '\033[1m'
    DIM = '\033[2m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Emojis
    FIRE = '🔥'
    TARGET = '🎯'
    ROCKET = '🚀'
    SKULL = '💀'
    WARNING = '⚠️'
    CHECK = '✅'
    CROSS = '❌'
    INFO = 'ℹ️'
    SEARCH = '🔍'
    BOOM = '💥'
    LOCK = '🔒'
    KEY = '🔑'
    CHART = '📊'
    GEAR = '⚙️'

def banner():
    """Epic ASCII banner"""
    art = f"""
{Style.CYAN}{Style.BOLD}
 ███████╗██╗  ██╗ ██████╗ ████████╗ █████╗ 
 ██╔════╝██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗
 ███████╗███████║██║   ██║   ██║   ███████║
 ╚════██║██╔══██║██║   ██║   ██║   ██╔══██║
 ███████║██║  ██║╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝{Style.RESET}
                                                
 {Style.MAGENTA}Simple HTTP Offensive Testing Artillery{Style.RESET}
 {Style.WHITE}Universal security testing framework v2.0{Style.RESET}
 {Style.YELLOW}By Redzhardtekk | MIT License | Educational Use{Style.RESET}

 {Style.GRAY}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Style.RESET}
    """
    print(art)

def log(msg, color=Style.WHITE, icon=''):
    """Pretty logging"""
    print(f"{color}{icon} {msg}{Style.RESET}")

def log_success(msg):
    log(msg, Style.GREEN, Style.CHECK)

def log_error(msg):
    log(msg, Style.RED, Style.CROSS)

def log_warning(msg):
    log(msg, Style.YELLOW, Style.WARNING)

def log_info(msg):
    log(msg, Style.CYAN, Style.INFO)

def log_critical(msg):
    log(msg, Style.RED + Style.BOLD, Style.SKULL)

# ========================================
# TEMPLATE ENGINE
# ========================================
class TemplateEngine:
    """Variable substitution & fuzzing engine"""
    
    def __init__(self):
        self.variables = {}
        self.fuzz_modes = {
            'range': self._fuzz_range,
            'list': self._fuzz_list,
            'wordlist': self._fuzz_wordlist
        }
    
    def set_variable(self, key: str, value: str):
        """
        Parse variable values:
        - "1,2,3" = list
        - "1..10" = range
        - "@file.txt" = wordlist
        """
        if value.startswith('@'):
            # Wordlist from file
            self.variables[key] = self._load_wordlist(value[1:])
        elif '..' in value:
            # Range: 1..100
            start, end = map(int, value.split('..'))
            self.variables[key] = list(range(start, end + 1))
        elif ',' in value:
            # List: a,b,c
            self.variables[key] = value.split(',')
        else:
            # Single value
            self.variables[key] = [value]
    
    def _load_wordlist(self, filepath: str) -> List[str]:
        """Load wordlist from file"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            log_error(f"Wordlist not found: {filepath}")
            return []
    
    def _fuzz_range(self, start: int, end: int) -> List[int]:
        """Generate numeric range"""
        return list(range(start, end + 1))
    
    def _fuzz_list(self, items: List[str]) -> List[str]:
        """Return list as-is"""
        return items
    
    def _fuzz_wordlist(self, filepath: str) -> List[str]:
        """Load from file"""
        return self._load_wordlist(filepath)
    
    def render(self, template: str) -> List[str]:
        """
        Expand template with variables
        Example: "user={{ID}}" with ID=1..3 → ["user=1", "user=2", "user=3"]
        """
        # Find all {{VAR}} patterns
        pattern = re.compile(r'\{\{(\w+)\}\}')
        vars_in_template = pattern.findall(template)
        
        if not vars_in_template:
            return [template]
        
        # Get all variable values
        var_values = []
        for var_name in vars_in_template:
            if var_name in self.variables:
                var_values.append(self.variables[var_name])
            else:
                log_warning(f"Variable {{{{var_name}}}} not defined, using placeholder")
                var_values.append([f'{{{{var_name}}}}'])
        
        # Generate all combinations
        results = []
        for combo in itertools.product(*var_values):
            result = template
            for var_name, value in zip(vars_in_template, combo):
                result = result.replace(f'{{{{{var_name}}}}}', str(value))
            results.append(result)
        
        return results

# ========================================
# PAYLOAD PROCESSOR
# ========================================
class PayloadProcessor:
    """Detect and prepare different payload types"""
    
    @staticmethod
    def detect_type(payload: str) -> str:
        """Auto-detect payload type"""
        payload = payload.strip()
        
        # JSON
        if (payload.startswith('{') or payload.startswith('[')) and \
           (payload.endswith('}') or payload.endswith(']')):
            try:
                json.loads(payload)
                return 'json'
            except:
                pass
        
        # XML
        if payload.startswith('<?xml') or \
           (payload.startswith('<') and payload.endswith('>')):
            return 'xml'
        
        # URL-encoded form data
        if '=' in payload and '&' in payload:
            return 'form'
        
        # GraphQL
        if 'query' in payload.lower() or 'mutation' in payload.lower():
            return 'graphql'
        
        # Default
        return 'raw'
    
    @staticmethod
    def prepare_headers(payload_type: str, base_headers: Dict) -> Dict:
        """Set appropriate Content-Type"""
        headers = base_headers.copy()
        
        content_types = {
            'json': 'application/json',
            'xml': 'application/xml',
            'form': 'application/x-www-form-urlencoded',
            'graphql': 'application/json',
            'raw': 'text/plain'
        }
        
        if 'Content-Type' not in headers:
            headers['Content-Type'] = content_types.get(payload_type, 'text/plain')
        
        return headers

# ========================================
# PATTERN DETECTOR
# ========================================
class PatternDetector:
    """Advanced vulnerability pattern detection"""
    
    # Regex patterns for sensitive data
    PATTERNS = {
        'api_key': r'(api[_-]?key|apikey|api[_-]?token)[\s:=]+([\'"])?([a-zA-Z0-9_\-]{20,})(\2)?',
        'jwt': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'google_api': r'AIza[0-9A-Za-z_-]{35}',
        'private_key': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
        'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'ipv4': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'sql_error': r'(SQL syntax|mysql_fetch|pg_query|ORA-\d{5}|SQLite|ODBC|JET Database)',
        'php_error': r'(Fatal error|Parse error|Warning.*in.*line|Notice.*in.*line)',
        'stack_trace': r'(at\s+[\w\.]+\([\w\.]+:\d+\)|Traceback.*most recent call)',
        'version': r'(version|v)[\s:=]+(\d+\.\d+\.\d+)',
        'password': r'(password|passwd|pwd)[\s:=]+([\'"])?([^\s\'"]{6,})(\2)?',
    }
    
    ERROR_KEYWORDS = [
        'error', 'exception', 'stack trace', 'warning', 'fatal',
        'sql', 'mysql', 'postgresql', 'oracle', 'sqlite',
        'denied', 'forbidden', 'unauthorized', 'access denied',
        'debug', 'trace', 'dump', 'verbose'
    ]
    
    @classmethod
    def detect(cls, response: requests.Response) -> List[Dict]:
        """Detect patterns in response"""
        findings = []
        text = response.text
        text_lower = text.lower()
        
        # Regex-based detection
        for name, pattern in cls.PATTERNS.items():
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                findings.append({
                    'type': 'regex_match',
                    'pattern': name,
                    'match': match.group(0)[:100],  # Truncate
                    'severity': cls._get_severity(name)
                })
        
        # Keyword-based detection
        for keyword in cls.ERROR_KEYWORDS:
            if keyword in text_lower:
                findings.append({
                    'type': 'keyword_match',
                    'keyword': keyword,
                    'severity': 'MEDIUM'
                })
                break  # Don't spam with all keywords
        
        # Status code analysis
        if response.status_code >= 500:
            findings.append({
                'type': 'server_error',
                'detail': f'HTTP {response.status_code}',
                'severity': 'HIGH'
            })
        
        return findings
    
    @staticmethod
    def _get_severity(pattern_name: str) -> str:
        """Map pattern to severity"""
        critical = ['api_key', 'aws_key', 'private_key', 'password']
        high = ['jwt', 'google_api']
        
        if pattern_name in critical:
            return 'CRITICAL'
        elif pattern_name in high:
            return 'HIGH'
        else:
            return 'MEDIUM'

# ========================================
# RESPONSE ANALYZER
# ========================================
class ResponseAnalyzer:
    """Deep response analysis"""
    
    @staticmethod
    def analyze(response: requests.Response, duration: float, payload: str) -> Dict:
        """Comprehensive response analysis"""
        analysis = {
            'status_code': response.status_code,
            'duration': round(duration, 3),
            'size': len(response.content),
            'headers': dict(response.headers),
            'timestamp': datetime.now().isoformat(),
            'payload': payload,
            'url': response.url
        }
        
        # Category
        if response.status_code >= 500:
            analysis['category'] = 'Server Error'
            analysis['severity'] = 'ERROR'
        elif response.status_code >= 400:
            analysis['category'] = 'Client Error'
            analysis['severity'] = 'WARNING'
        elif response.status_code >= 300:
            analysis['category'] = 'Redirect'
            analysis['severity'] = 'INFO'
        elif response.status_code >= 200:
            analysis['category'] = 'Success'
            analysis['severity'] = 'SUCCESS'
        else:
            analysis['category'] = 'Informational'
            analysis['severity'] = 'INFO'
        
        # Parse body
        content_type = response.headers.get('Content-Type', '').lower()
        
        if 'application/json' in content_type:
            try:
                analysis['body_type'] = 'json'
                analysis['body_parsed'] = response.json()
            except:
                analysis['body_type'] = 'json_invalid'
                analysis['body_raw'] = response.text
        elif 'text/html' in content_type:
            analysis['body_type'] = 'html'
            analysis['body_raw'] = response.text
        elif 'xml' in content_type:
            analysis['body_type'] = 'xml'
            analysis['body_raw'] = response.text
        else:
            analysis['body_type'] = 'raw'
            analysis['body_raw'] = response.text
        
        # Pattern detection
        analysis['findings'] = PatternDetector.detect(response)
        
        # Response hash (for deduplication)
        analysis['response_hash'] = hashlib.md5(response.content).hexdigest()
        
        return analysis
    
    @staticmethod
    def compare(response1: Dict, response2: Dict) -> Dict:
        """Compare two responses"""
        diff = {
            'status_diff': response1['status_code'] != response2['status_code'],
            'size_diff': abs(response1['size'] - response2['size']),
            'timing_diff': abs(response1['duration'] - response2['duration']),
            'hash_diff': response1.get('response_hash') != response2.get('response_hash')
        }
        
        # Detailed text diff
        if 'body_raw' in response1 and 'body_raw' in response2:
            differ = difflib.Differ()
            diff['text_diff'] = list(differ.compare(
                response1['body_raw'].splitlines()[:50],  # First 50 lines
                response2['body_raw'].splitlines()[:50]
            ))
        
        return diff

# ========================================
# AUTHENTICATION MANAGER
# ========================================
class AuthManager:
    """Handle authentication workflows"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.token = None
        self.refresh_token = None
        self.cookies = {}
    
    def login(self, url: str, method: str = 'POST', data: Dict = None, 
              json_data: Dict = None, extract_token: str = None):
        """
        Perform login request
        
        Args:
            url: Login endpoint
            method: HTTP method
            data: Form data
            json_data: JSON data
            extract_token: JSON path to extract token (e.g., "data.access_token")
        """
        try:
            if method.upper() == 'POST':
                if json_data:
                    response = self.session.post(url, json=json_data)
                else:
                    response = self.session.post(url, data=data)
            else:
                response = self.session.get(url)
            
            # Extract token if path provided
            if extract_token and response.status_code == 200:
                try:
                    result = response.json()
                    keys = extract_token.split('.')
                    for key in keys:
                        result = result[key]
                    self.token = result
                    
                    # Auto-inject Bearer token
                    self.session.headers['Authorization'] = f'Bearer {self.token}'
                    
                    log_success(f"Authenticated successfully")
                    log_info(f"Token: {self.token[:20]}...")
                    
                except (KeyError, json.JSONDecodeError) as e:
                    log_error(f"Failed to extract token: {e}")
            
            # Store cookies
            self.cookies = dict(self.session.cookies)
            
            return response
            
        except Exception as e:
            log_error(f"Login failed: {e}")
            return None

# ========================================
# MAIN SHOTA ENGINE
# ========================================
class Shota:
    """Main testing engine"""
    
    def __init__(self, target_url: str, args):
        self.target_url = target_url
        self.args = args
        self.session = requests.Session()
        self.results = []
        self.stats = defaultdict(int)
        self.template_engine = TemplateEngine()
        self.auth_manager = AuthManager(self.session)
        
        # Setup
        self._setup_session()
        self._setup_output_dir()
    
    def _setup_session(self):
        """Configure HTTP session"""
        # Base headers
        self.session.headers.update({
            'User-Agent': self.args.user_agent,
            'Accept': '*/*'
        })
        
        # Custom headers
        if self.args.header:
            for header in self.args.header:
                if ':' in header:
                    key, value = header.split(':', 1)
                    self.session.headers[key.strip()] = value.strip()
        
        # Proxy
        if self.args.proxy:
            self.session.proxies = {
                'http': self.args.proxy,
                'https': self.args.proxy
            }
        
        # SSL
        self.session.verify = not self.args.no_verify
    
    def _setup_output_dir(self):
        """Create output directory"""
        Path(self.args.output_dir).mkdir(exist_ok=True)
    
    def _load_payloads(self) -> List[str]:
        """Load payloads from file"""
        try:
            with open(self.args.payload_file, 'r', encoding='utf-8') as f:
                payloads = [line.rstrip('\n\r') for line in f if line.strip()]
            
            log_success(f"Loaded {len(payloads)} payload(s) from {self.args.payload_file}")
            
            # Template expansion
            if self.args.var:
                for var_def in self.args.var:
                    if '=' in var_def:
                        key, value = var_def.split('=', 1)
                        self.template_engine.set_variable(key, value)
                
                # Expand all payloads
                expanded = []
                for payload in payloads:
                    expanded.extend(self.template_engine.render(payload))
                
                log_info(f"Expanded to {len(expanded)} payload(s) with variables")
                payloads = expanded
            
            # Limit
            if self.args.limit:
                payloads = payloads[:self.args.limit]
                log_info(f"Limited to first {self.args.limit} payloads")
            
            return payloads
            
        except FileNotFoundError:
            log_error(f"Payload file not found: {self.args.payload_file}")
            sys.exit(1)
    
    def _shoot_single(self, payload: str, index: int, total: int) -> Dict:
        """Fire single request"""
        # Display
        if not self.args.quiet:
            log(f"\n{'='*70}", Style.CYAN)
            log(f"{Style.TARGET} SHOT {index}/{total}", Style.BOLD + Style.CYAN)
            log(f"{'='*70}", Style.CYAN)
        
        # Detect payload type
        payload_type = PayloadProcessor.detect_type(payload)
        
        if not self.args.quiet:
            log_info(f"Payload type: {payload_type.upper()}")
        
        # Prepare request
        headers = PayloadProcessor.prepare_headers(payload_type, dict(self.session.headers))
        
        # Build URL with query params if GET
        url = self.target_url
        data = payload
        params = None
        
        if self.args.method == 'GET':
            if payload_type == 'form':
                # Parse form data to params
                params = dict(urllib.parse.parse_qsl(payload))
                data = None
            else:
                # Append to URL
                separator = '&' if '?' in url else '?'
                url = f"{url}{separator}{payload}"
                data = None
        
        # Verbose output
        if self.args.verbose and not self.args.quiet:
            log(f"\n{Style.YELLOW}📤 REQUEST:{Style.RESET}")
            log(f"   Method  : {self.args.method}")
            log(f"   URL     : {url}")
            if params:
                log(f"   Params  : {params}")
            if data and len(str(data)) < 200:
                log(f"   Payload : {data}")
        
        # Fire!
        start_time = time.time()
        
        try:
            response = self.session.request(
                method=self.args.method,
                url=url,
                headers=headers,
                data=data,
                params=params,
                timeout=self.args.timeout,
                allow_redirects=not self.args.no_redirects
            )
            
            duration = time.time() - start_time
            
            # Analyze
            analysis = ResponseAnalyzer.analyze(response, duration, payload)
            
            # Display
            if not self.args.quiet:
                self._display_response(analysis)
            
            # Stats
            self.stats['total'] += 1
            self.stats[f'status_{response.status_code}'] += 1
            
            if analysis['findings']:
                self.stats['findings'] += len(analysis['findings'])
            
            return analysis
            
        except requests.Timeout:
            log_error(f"⏰ Timeout after {self.args.timeout}s")
            self.stats['timeouts'] += 1
            return {'error': 'timeout', 'payload': payload}
        
        except requests.RequestException as e:
            log_error(f"{Style.BOOM} Request failed: {e}")
            self.stats['errors'] += 1
            return {'error': str(e), 'payload': payload}
    
    def _display_response(self, analysis: Dict):
        """Pretty print response"""
        log(f"\n{Style.GREEN}📥 RESPONSE:{Style.RESET}")
        
        # Status with color
        status = analysis['status_code']
        if status >= 500:
            color = Style.RED
        elif status >= 400:
            color = Style.YELLOW
        elif status >= 300:
            color = Style.CYAN
        else:
            color = Style.GREEN
        
        log(f"   Status  : {status} ({analysis['category']})", color)
        log(f"   Time    : {analysis['duration']}s")
        log(f"   Size    : {analysis['size']} bytes")
        
        # Content-Type
        ct = analysis['headers'].get('Content-Type', 'unknown')
        log(f"   Type    : {ct}")
        
        # Findings
        if analysis.get('findings'):
            log(f"\n{Style.MAGENTA}{Style.SEARCH} FINDINGS:{Style.RESET}")
            for finding in analysis['findings'][:10]:  # Show max 10
                severity = finding.get('severity', 'UNKNOWN')
                
                severity_colors = {
                    'CRITICAL': Style.RED + Style.BOLD,
                    'HIGH': Style.RED,
                    'MEDIUM': Style.YELLOW,
                    'LOW': Style.CYAN
                }
                
                color = severity_colors.get(severity, Style.WHITE)
                
                ftype = finding.get('type', 'unknown')
                detail = finding.get('match') or finding.get('keyword') or finding.get('detail', '')
                
                log(f"   [{severity}] {ftype}: {detail[:80]}", color)
        
        # Body preview
        if self.args.verbose:
            log(f"\n{Style.WHITE}📄 RESPONSE BODY:{Style.RESET}")
            
            if 'body_parsed' in analysis:
                body_str = json.dumps(analysis['body_parsed'], indent=2)
            else:
                body_str = analysis.get('body_raw', '')
            
            max_display = 500
            if len(body_str) > max_display:
                preview = body_str[:max_display] + f"\n... ({len(body_str) - max_display} more chars)"
            else:
                preview = body_str
            
            for line in preview.split('\n'):
                log(f"   {line}", Style.WHITE)
    
    def _save_results(self):
        """Save results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.args.output_dir}/shota_{timestamp}.json"
        
        output = {
            'target': self.target_url,
            'timestamp': timestamp,
            'config': {
                'method': self.args.method,
                'delay': self.args.delay,
                'timeout': self.args.timeout,
                'payload_file': self.args.payload_file
            },
            'stats': dict(self.stats),
            'results': self.results
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2)
        
        log_success(f"Results saved: {filename}")
        
        return filename
    
    def _print_summary(self):
        """Print execution summary"""
        log(f"\n{'='*70}", Style.CYAN)
        log(f"{Style.CHART} SHOOTING SUMMARY", Style.BOLD + Style.CYAN)
        log(f"{'='*70}", Style.CYAN)
        
        total = self.stats.get('total', 0)
        timeouts = self.stats.get('timeouts', 0)
        errors = self.stats.get('errors', 0)
        findings = self.stats.get('findings', 0)
        
        log(f"Total shots   : {total}")
        
        # Status codes
        for key, value in sorted(self.stats.items()):
            if key.startswith('status_'):
                status_code = key.split('_')[1]
                log(f"HTTP {status_code}      : {value}")
        
        if timeouts > 0:
            log_warning(f"Timeouts      : {timeouts}")
        
        if errors > 0:
            log_error(f"Errors        : {errors}")
        
        if findings > 0:
            log_critical(f"\n{Style.SKULL} Total Findings: {findings}")
        
        log(f"\n{Style.CHECK} Barrage complete!", Style.GREEN + Style.BOLD)
    
    def run(self):
        """Main execution loop"""
        # Banner
        if not self.args.quiet:
            banner()
        
        # Info
        log_info(f"Target: {self.target_url}")
        log_info(f"Method: {self.args.method}")
        log_info(f"Payload file: {self.args.payload_file}")
        log_info(f"Delay: {self.args.delay}s between shots\n")
        
        # Ethical reminder
        if not self.args.quiet:
            log(f"{Style.WARNING}  ETHICAL TESTING REMINDER:", Style.YELLOW + Style.BOLD)
            log("   • Only test systems you have permission to test")
            log("   • Respect rate limits and server resources")
            log("   • Document findings responsibly")
            log("   • Report vulnerabilities through proper channels\n")
            
            if not self.args.yes:
                input(f"{Style.BOLD}Press ENTER to start shooting...{Style.RESET} ")
        
        # Authentication
        if self.args.auth_login:
            log_info("Performing authentication...")
            
            auth_data = {}
            if self.args.auth_user:
                auth_data['username'] = self.args.auth_user
            if self.args.auth_pass:
                auth_data['password'] = self.args.auth_pass
            
            self.auth_manager.login(
                url=self.args.auth_login,
                json_data=auth_data if auth_data else None,
                extract_token=self.args.auth_token_path
            )
        
        # Load payloads
        payloads = self._load_payloads()
        
        if not self.args.quiet:
            log(f"\n{Style.ROCKET} Starting barrage of {len(payloads)} shots...\n", 
                Style.BOLD + Style.GREEN)
        
        # Fire!
        for i, payload in enumerate(payloads, 1):
            result = self._shoot_single(payload, i, len(payloads))
            self.results.append(result)
            
            # Rate limiting
            if i < len(payloads) and self.args.delay > 0:
                if not self.args.quiet:
                    log(f"\n⏸️  Cooldown {self.args.delay}s...", Style.CYAN)
                time.sleep(self.args.delay)
        
        # Save & summarize
        self._save_results()
        
        if not self.args.quiet:
            self._print_summary()

# ========================================
# CLI INTERFACE
# ========================================
def main():
    parser = argparse.ArgumentParser(
        description='SHOTA v2.0 - Simple HTTP Offensive Testing Artillery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  shota.py https://api.example.com/endpoint -p payloads.txt

  # With variables (fuzzing)
  shota.py https://api.com/user/{{ID}} -p payloads.txt --var ID=1..100

  # With authentication
  shota.py https://api.com/protected \\
    --auth-login https://api.com/login \\
    --auth-user admin --auth-pass test123 \\
    --auth-token-path "data.access_token"

  # Advanced fuzzing
  shota.py "https://api.com/search?q={{FUZZ}}" \\
    --var FUZZ=@wordlists/xss.txt \\
    -m GET

  # Custom headers & proxy
  shota.py https://api.com \\
    -H "Cookie: session=abc123" \\
    -H "X-API-Key: secret" \\
    --proxy http://127.0.0.1:8080

For more info: https://github.com/redzhardtekk/shota
        """
    )
    
    # Required
    parser.add_argument('url', help='Target URL (supports {{VARIABLES}})')
    
    # Payload options
    parser.add_argument('-p', '--payload-file', default='payloads.txt',
                       help='Payload file (default: payloads.txt)')
    parser.add_argument('--var', action='append',
                       help='Variable: KEY=VALUE (1..10, a,b,c, @file.txt)')
    parser.add_argument('--limit', type=int,
                       help='Limit number of payloads to test')
    
    # HTTP options
    parser.add_argument('-m', '--method', default='POST',
                       help='HTTP method (default: POST)')
    parser.add_argument('-H', '--header', action='append',
                       help='Custom header (repeatable)')
    parser.add_argument('-d', '--delay', type=float, default=1.0,
                       help='Delay between requests (default: 1.0s)')
    parser.add_argument('-t', '--timeout', type=int, default=15,
                       help='Request timeout (default: 15s)')
    parser.add_argument('--proxy', help='HTTP(S) proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--no-verify', action='store_true',
                       help='Disable SSL verification')
    parser.add_argument('--no-redirects', action='store_true',
                       help='Don\'t follow redirects')
    parser.add_argument('--user-agent', default='SHOTA/2.0',
                       help='User-Agent header')
    
    # Authentication
    parser.add_argument('--auth-login', help='Login URL')
    parser.add_argument('--auth-user', help='Username for login')
    parser.add_argument('--auth-pass', help='Password for login')
    parser.add_argument('--auth-token-path', 
                       help='JSON path to extract token (e.g., "data.access_token")')
    
    # Output options
    parser.add_argument('-o', '--output-dir', default='results',
                       help='Output directory (default: results)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Minimal output')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (show response bodies)')
    parser.add_argument('-y', '--yes', action='store_true',
                       help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    # Create and run shooter
    shooter = Shota(args.url, args)
    shooter.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log_error("\n\n⚠️  Shooting interrupted by user (Ctrl+C)")
        sys.exit(0)
    except Exception as e:
        log_error(f"\n💥 Fatal error: {e}")
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
