#!/usr/bin/env python3
"""
███████╗██╗  ██╗ ██████╗ ████████╗ █████╗ 
██╔════╝██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗
███████╗███████║██║   ██║   ██║   ███████║
╚════██║██╔══██║██║   ██║   ██║   ██╔══██║
███████║██║  ██║╚██████╔╝   ██║   ██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

SHOTA v3.0 - Silent Assassin Edition HARDENED
Advanced HTTP Security Testing Framework

Author: Redzhardtekk (Enhanced by redzXconcept)
License: MIT
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
import os
import base64
import hashlib
import threading
import socket
import gzip
import pickle
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union, Set
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, field, asdict
from functools import lru_cache
import warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

VERSION = "3.0.0"

# ============================================
# COLORS & STYLES
# ============================================
class C:
    """Compact color codes"""
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
    B = '\033[94m'; M = '\033[95m'; C = '\033[96m'
    W = '\033[97m'; GR = '\033[90m'
    BOLD = '\033[1m'; DIM = '\033[2m'
    RESET = '\033[0m'; CLEAR = '\033[2J\033[H'

# ============================================
# DATA STRUCTURES
# ============================================
@dataclass
class ShotResult:
    """Immutable shot result container"""
    idx: int
    payload: str
    status: Optional[int] = None
    time: Optional[float] = None
    size: Optional[int] = None
    hash: Optional[str] = None
    findings: List[Dict] = field(default_factory=list)
    error: Optional[str] = None
    error_msg: Optional[str] = None
    unique: bool = False
    diff: Optional[Dict] = None
    headers: Dict = field(default_factory=dict)
    body_preview: str = ""
    retry_count: int = 0
    
    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}

@dataclass
class Stats:
    """Real-time statistics tracker"""
    total: int = 0
    success: int = 0
    timeouts: int = 0
    errors: int = 0
    findings: int = 0
    payloads_with_findings: int = 0
    unique_responses: int = 0
    retries: int = 0
    status_codes: Counter = field(default_factory=Counter)
    
    def increment(self, key: str, amount: int = 1):
        setattr(self, key, getattr(self, key) + amount)
    
    def to_dict(self) -> Dict:
        d = asdict(self)
        d['status_codes'] = dict(self.status_codes)
        return d

# ============================================
# BANNER & LOGGING
# ============================================
def banner(silent=False):
    if silent: return
    art = f"""{C.C}{C.BOLD}
 ███████╗██╗  ██╗ ██████╗ ████████╗ █████╗ 
 ██╔════╝██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗
 ███████╗███████║██║   ██║   ██║   ███████║
 ╚════██║██╔══██║██║   ██║   ██║   ██╔══██║
 ███████║██║  ██║╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝{C.RESET}

{C.M}SHOTA v{VERSION} - Silent Assassin HARDENED{C.RESET}
{C.Y}Production-Grade HTTP Security Testing Framework{C.RESET}
{C.GR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.RESET}
"""
    print(art)

def log(msg, color=C.W, icon='', end='\n', silent=False):
    if not silent:
        print(f"{color}{icon}{msg}{C.RESET}", end=end, flush=True)

# ============================================
# ADVANCED PATTERN DETECTOR
# ============================================
class PatternDetector:
    """Optimized pattern detection with compiled regex"""
    
    # Pre-compiled patterns for performance
    PATTERNS = {
        'aws_key': (re.compile(r'AKIA[0-9A-Z]{16}'), 'CRITICAL'),
        'aws_secret': (re.compile(r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})'), 'CRITICAL'),
        'google_api': (re.compile(r'AIza[0-9A-Za-z_-]{35}'), 'CRITICAL'),
        'github_token': (re.compile(r'gh[pousr]_[a-zA-Z0-9]{36,255}'), 'CRITICAL'),
        'slack_token': (re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}'), 'CRITICAL'),
        'private_key': (re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 'CRITICAL'),
        'jwt': (re.compile(r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_.\-]*'), 'HIGH'),
        'api_key': (re.compile(r'(api[_-]?key|apikey|api[_-]?token)[\s"\':=]+(["\'])?([a-zA-Z0-9_\-]{20,})(\2)?', re.I), 'HIGH'),
        'password_hash': (re.compile(r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}'), 'HIGH'),
        'mysql_error': (re.compile(r'(SQL syntax.*MySQL|Warning.*mysql_.*|MySQLSyntaxErrorException)', re.I), 'HIGH'),
        'postgresql_error': (re.compile(r'(PostgreSQL.*ERROR|Warning.*\bpg_.*|PSQLException)', re.I), 'HIGH'),
        'mssql_error': (re.compile(r'(Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|SQLServer JDBC Driver)', re.I), 'HIGH'),
        'oracle_error': (re.compile(r'(ORA-\d{5}|Oracle error|Oracle.*Driver)', re.I), 'HIGH'),
        'sqlite_error': (re.compile(r'(SQLite/JDBCDriver|System\.Data\.SQLite\.SQLiteException)', re.I), 'HIGH'),
        'php_error': (re.compile(r'(Fatal error|Parse error|Warning.*in\s+.*\.php|Notice.*in\s+.*\.php)', re.I), 'MEDIUM'),
        'python_error': (re.compile(r'(Traceback \(most recent call last\)|File ".*\.py", line \d+)', re.I), 'MEDIUM'),
        'java_error': (re.compile(r'(Exception in thread|\.java:\d+\)|at\s+[\w\.]+\([\w\.]+\.java:\d+\))'), 'MEDIUM'),
        'dotnet_error': (re.compile(r'(System\.\w+Exception|at\s+\w+\.\w+\.)', re.I), 'MEDIUM'),
        'email': (re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'), 'LOW'),
        'ipv4': (re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'), 'LOW'),
        'credit_card': (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'), 'CRITICAL'),
        'ssn': (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 'CRITICAL'),
        'version': (re.compile(r'(version|v)[\s:=]+(\d+\.\d+\.\d+)', re.I), 'LOW'),
        'server': (re.compile(r'Server:\s*(.+)', re.I), 'LOW'),
        'xxe_indicator': (re.compile(r'<!ENTITY|SYSTEM|PUBLIC', re.I), 'MEDIUM'),
        'debug_mode': (re.compile(r'(DEBUG|VERBOSE|TRACE)\s*[:=]\s*(true|1|yes|on)', re.I), 'MEDIUM'),
        'stack_trace': (re.compile(r'(at\s+[\w\.]+\([\w\.]+:\d+\)|Traceback)', re.I), 'MEDIUM'),
        'cloudflare': (re.compile(r'(cloudflare|cf-ray)', re.I), 'LOW'),
        'waf_block': (re.compile(r'(blocked by|security policy|web application firewall|waf)', re.I), 'HIGH'),
    }
    
    KEYWORDS = {
        'error': 'MEDIUM', 'exception': 'MEDIUM', 'fatal': 'HIGH',
        'warning': 'LOW', 'database': 'MEDIUM', 'sql': 'MEDIUM',
        'admin': 'LOW', 'password': 'MEDIUM', 'token': 'MEDIUM',
        'unauthorized': 'MEDIUM', 'forbidden': 'MEDIUM', 'denied': 'MEDIUM',
    }
    
    @classmethod
    def detect(cls, response: requests.Response, quick_mode: bool = False) -> List[Dict]:
        """Detect patterns with optional quick mode for performance"""
        findings = []
        text = response.text
        
        # Fast path: only check critical patterns in quick mode
        patterns_to_check = cls.PATTERNS.items()
        if quick_mode:
            patterns_to_check = [(k, v) for k, v in cls.PATTERNS.items() 
                                if v[1] in ('CRITICAL', 'HIGH')]
        
        for name, (pattern, severity) in patterns_to_check:
            for match in pattern.finditer(text):
                findings.append({
                    'type': name,
                    'severity': severity,
                    'match': match.group(0)[:100],
                    'position': match.start()
                })
                if quick_mode and len(findings) >= 10:
                    return findings  # Early exit in quick mode
        
        # Keyword search (case-insensitive)
        text_lower = text.lower()
        seen_keywords = set()
        for keyword, severity in cls.KEYWORDS.items():
            if keyword in text_lower and keyword not in seen_keywords:
                findings.append({
                    'type': 'keyword',
                    'keyword': keyword,
                    'severity': severity
                })
                seen_keywords.add(keyword)
        
        # Status code analysis
        if response.status_code >= 500:
            findings.append({
                'type': 'server_error',
                'severity': 'HIGH',
                'status': response.status_code
            })
        elif response.status_code == 403:
            findings.append({
                'type': 'forbidden',
                'severity': 'MEDIUM',
                'detail': 'Access forbidden - possible WAF/auth'
            })
        elif response.status_code == 401:
            findings.append({
                'type': 'unauthorized',
                'severity': 'MEDIUM',
                'detail': 'Authentication required'
            })
        
        # Header analysis
        dangerous_headers = {
            'X-Debug': 'MEDIUM',
            'X-Powered-By': 'LOW',
            'Server': 'LOW',
            'X-AspNet-Version': 'MEDIUM',
            'X-AspNetMvc-Version': 'MEDIUM',
        }
        for header, severity in dangerous_headers.items():
            if header in response.headers:
                findings.append({
                    'type': 'header_disclosure',
                    'severity': severity,
                    'header': header,
                    'value': response.headers[header][:100]
                })
        
        return findings

# ============================================
# WORDLIST MANAGER
# ============================================
class WordlistManager:
    """Intelligent wordlist loading with caching & compression"""
    
    CACHE_DIR = Path.home() / '.shota' / 'cache'
    
    def __init__(self, enable_cache: bool = True):
        self.enable_cache = enable_cache
        self.cache = {}
        if enable_cache:
            self.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    
    def _get_cache_key(self, filepath: str) -> str:
        """Generate cache key from file path + mtime"""
        try:
            stat = os.stat(filepath)
            return hashlib.md5(
                f"{filepath}{stat.st_mtime}{stat.st_size}".encode()
            ).hexdigest()
        except:
            return hashlib.md5(filepath.encode()).hexdigest()
    
    def _load_from_cache(self, cache_key: str) -> Optional[List[str]]:
        """Load from disk cache"""
        cache_file = self.CACHE_DIR / f"{cache_key}.pkl.gz"
        try:
            if cache_file.exists():
                with gzip.open(cache_file, 'rb') as f:
                    return pickle.load(f)
        except Exception:
            pass
        return None
    
    def _save_to_cache(self, cache_key: str, data: List[str]):
        """Save to compressed disk cache"""
        try:
            cache_file = self.CACHE_DIR / f"{cache_key}.pkl.gz"
            with gzip.open(cache_file, 'wb', compresslevel=6) as f:
                pickle.dump(data, f)
        except Exception:
            pass
    
    def load(self, filepath: str, fallback_paths: List[str] = None) -> List[str]:
        """
        Load wordlist with smart fallback and caching
        
        Args:
            filepath: Primary file path
            fallback_paths: List of alternative paths to try
        
        Returns:
            List of lines (comments stripped)
        """
        # Check memory cache first
        if filepath in self.cache:
            return self.cache[filepath]
        
        # Build search paths
        script_dir = os.path.dirname(os.path.abspath(__file__))
        search_paths = [
            filepath,
            os.path.join('wordlists', filepath),
            os.path.join('.', 'wordlists', filepath),
            os.path.join(script_dir, 'wordlists', filepath),
            os.path.join(script_dir, '..', 'wordlists', filepath),
        ]
        if fallback_paths:
            search_paths.extend(fallback_paths)
        
        # Find existing file
        existing_file = None
        for path in search_paths:
            if os.path.exists(path):
                existing_file = path
                break
        
        if not existing_file:
            return []
        
        # Check disk cache
        if self.enable_cache:
            cache_key = self._get_cache_key(existing_file)
            cached = self._load_from_cache(cache_key)
            if cached:
                self.cache[filepath] = cached
                return cached
        
        # Load from file
        try:
            with open(existing_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = [
                    line.rstrip('\n\r')
                    for line in f
                    if line.strip() and not line.startswith('#')
                ]
            
            # Cache it
            self.cache[filepath] = lines
            if self.enable_cache:
                cache_key = self._get_cache_key(existing_file)
                self._save_to_cache(cache_key, lines)
            
            return lines
        except Exception:
            return []

# ============================================
# TEMPLATE ENGINE
# ============================================
class TemplateEngine:
    """Advanced template rendering with inline encoding"""
    
    def __init__(self, wordlist_manager: WordlistManager):
        self.vars = {}
        self.wl_manager = wordlist_manager
        self.encoders = {
            'url': urllib.parse.quote,
            'url2x': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'hex': lambda x: ''.join(f'{ord(c):02x}' for c in x),
            'html': lambda x: x.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;'),
            'upper': str.upper,
            'lower': str.lower,
        }
    
    def set_var(self, key: str, value: str):
        """Parse and set variable value"""
        if value.startswith('@'):
            # Wordlist from file
            self.vars[key] = self.wl_manager.load(value[1:])
        elif '..' in value and all(p.lstrip('-').isdigit() for p in value.split('..')):
            # Range: 1..100 or -5..5
            start, end = map(int, value.split('..'))
            self.vars[key] = list(range(start, end + 1))
        elif ',' in value:
            # List: a,b,c
            self.vars[key] = [v.strip() for v in value.split(',')]
        else:
            # Single value
            self.vars[key] = [value]
    
    def render(self, template: str) -> List[str]:
        """
        Render template with variable substitution and encoding
        
        Syntax:
            {{VAR}}           - Simple substitution
            {{VAR:url}}       - URL encode
            {{VAR:base64}}    - Base64 encode
            {{VAR:url:base64}} - Chain encoders
        """
        # Pattern: {{VAR:encoder1:encoder2:...}}
        pattern = re.compile(r'\{\{(\w+)(?::([a-z0-9_:]+))?\}\}')
        
        vars_in_template = pattern.findall(template)
        if not vars_in_template:
            return [template]
        
        # Extract variable values
        var_values = []
        for var_name, _ in vars_in_template:
            if var_name in self.vars:
                var_values.append(self.vars[var_name])
            else:
                var_values.append([f'{{{{{var_name}}}}}'])  # Keep placeholder
        
        # Generate all combinations
        results = []
        for combo in itertools.product(*var_values):
            result = template
            for (var_name, encoders_chain), value in zip(vars_in_template, combo):
                # Apply encoding chain
                encoded_value = str(value)
                if encoders_chain:
                    for encoder_name in encoders_chain.split(':'):
                        if encoder_name in self.encoders:
                            encoded_value = self.encoders[encoder_name](encoded_value)
                
                # Replace placeholder
                placeholder = f'{{{{{var_name}{":" + encoders_chain if encoders_chain else ""}}}}}'
                result = result.replace(placeholder, encoded_value)
            
            results.append(result)
        
        return results

# ============================================
# PAYLOAD PROCESSOR
# ============================================
class PayloadProcessor:
    """Smart payload type detection and header preparation"""
    
    @staticmethod
    @lru_cache(maxsize=256)
    def detect_type(payload: str) -> str:
        """Cached payload type detection"""
        p = payload.strip()
        
        # JSON
        if (p.startswith('{') or p.startswith('[')) and (p.endswith('}') or p.endswith(']')):
            try:
                json.loads(p)
                return 'json'
            except:
                pass
        
        # XML
        if p.startswith('<?xml') or (p.startswith('<') and p.endswith('>') and '</' in p):
            return 'xml'
        
        # Form data
        if '=' in p and ('&' in p or p.count('=') == 1):
            return 'form'
        
        # GraphQL
        if re.search(r'\b(query|mutation)\s*[{\(]', p, re.I):
            return 'graphql'
        
        # Base64
        try:
            if len(p) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', p) and len(p) > 20:
                base64.b64decode(p)
                return 'base64'
        except:
            pass
        
        return 'raw'
    
    @staticmethod
    def prepare_headers(ptype: str, base_headers: Dict) -> Dict:
        """Prepare headers based on payload type"""
        headers = base_headers.copy()
        content_types = {
            'json': 'application/json',
            'xml': 'application/xml',
            'form': 'application/x-www-form-urlencoded',
            'graphql': 'application/json',
            'base64': 'text/plain',
            'raw': 'text/plain'
        }
        if 'Content-Type' not in headers:
            headers['Content-Type'] = content_types.get(ptype, 'text/plain')
        return headers

# ============================================
# RESPONSE DIFFER
# ============================================
class ResponseDiffer:
    """Advanced response comparison with similarity detection"""
    
    @staticmethod
    def body_similarity(text1: str, text2: str) -> float:
        """Calculate text similarity using difflib"""
        if not text1 or not text2:
            return 0.0
        return difflib.SequenceMatcher(None, text1[:5000], text2[:5000]).ratio()
    
    @classmethod
    def compare(cls, baseline: ShotResult, current: ShotResult) -> Dict:
        """
        Compare two responses and detect anomalies
        
        Returns:
            Dictionary with anomaly details and severity
        """
        diff = {
            'status_changed': baseline.status != current.status,
            'size_delta': abs((baseline.size or 0) - (current.size or 0)),
            'time_delta': abs((baseline.time or 0) - (current.time or 0)),
            'hash_changed': baseline.hash != current.hash,
            'findings_delta': len(current.findings) - len(baseline.findings),
        }
        
        # Calculate body similarity
        if baseline.body_preview and current.body_preview:
            diff['similarity'] = cls.body_similarity(
                baseline.body_preview,
                current.body_preview
            )
        
        # Anomaly classification
        if diff['status_changed']:
            diff['anomaly'] = 'STATUS_CHANGE'
            diff['severity'] = 'HIGH'
        elif diff['findings_delta'] > 0:
            diff['anomaly'] = 'NEW_FINDINGS'
            diff['severity'] = 'HIGH'
        elif diff['size_delta'] > 1000:
            diff['anomaly'] = 'SIZE_ANOMALY'
            diff['severity'] = 'MEDIUM'
        elif diff['time_delta'] > 5:
            diff['anomaly'] = 'TIMING_ANOMALY'
            diff['severity'] = 'MEDIUM'
        elif diff.get('similarity', 1.0) < 0.5:
            diff['anomaly'] = 'CONTENT_DRIFT'
            diff['severity'] = 'MEDIUM'
        else:
            diff['anomaly'] = 'NONE'
            diff['severity'] = 'LOW'
        
        return diff

# ============================================
# AUTH MANAGER
# ============================================
class AuthManager:
    """Enhanced authentication with multiple strategies"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.token = None
        self.cookies = {}
        self.auth_type = None
    
    def login(self, url: str, 
              data: Dict = None,
              json_data: Dict = None,
              token_path: str = None,
              method: str = 'POST',
              headers: Dict = None) -> bool:
        """
        Authenticate and extract token
        
        Args:
            url: Login endpoint
            data: Form data (for application/x-www-form-urlencoded)
            json_data: JSON data (for application/json)
            token_path: Dot-notation path to token (e.g., "data.access_token")
            method: HTTP method
            headers: Additional headers
        
        Returns:
            True if login successful
        """
        try:
            req_headers = headers or {}
            
            if method.upper() == 'POST':
                if json_data:
                    r = self.session.post(url, json=json_data, headers=req_headers, timeout=30)
                else:
                    r = self.session.post(url, data=data, headers=req_headers, timeout=30)
            else:
                r = self.session.get(url, headers=req_headers, timeout=30)
            
            # Extract token if path provided
            if r.status_code == 200 and token_path:
                try:
                    result = r.json()
                    # Navigate nested dict using dot notation
                    for key in token_path.split('.'):
                        result = result[key]
                    self.token = result
                    
                    # Auto-detect auth type and set header
                    if 'bearer' in token_path.lower() or len(self.token) > 50:
                        self.session.headers['Authorization'] = f'Bearer {self.token}'
                        self.auth_type = 'bearer'
                    else:
                        self.session.headers['X-Auth-Token'] = self.token
                        self.auth_type = 'token'
                    
                    return True
                except (json.JSONDecodeError, KeyError, TypeError):
                    pass
            
            # Success without token extraction
            if r.status_code in (200, 201, 204):
                self.cookies = dict(r.cookies)
                self.auth_type = 'session'
                return True
            
            return False
            
        except Exception:
            return False
    
    def refresh_token(self, refresh_url: str, refresh_token: str = None) -> bool:
        """Refresh authentication token"""
        try:
            payload = {'refresh_token': refresh_token or self.token}
            r = self.session.post(refresh_url, json=payload, timeout=30)
            
            if r.status_code == 200:
                try:
                    data = r.json()
                    new_token = data.get('access_token') or data.get('token')
                    if new_token:
                        self.token = new_token
                        if self.auth_type == 'bearer':
                            self.session.headers['Authorization'] = f'Bearer {self.token}'
                        return True
                except:
                    pass
            return False
        except:
            return False

# ============================================
# WAF DETECTOR
# ============================================
class WAFDetector:
    """Detect Web Application Firewalls"""
    
    WAF_SIGNATURES = {
        'cloudflare': [r'cloudflare', r'cf-ray', r'__cfduid'],
        'akamai': [r'akamai', r'akamaighost'],
        'aws_waf': [r'x-amzn-requestid', r'x-amz-'],
        'imperva': [r'incapsula', r'visid_incap'],
        'f5': [r'bigip', r'f5'],
        'fortinet': [r'fortigate', r'fortiweb'],
        'sucuri': [r'sucuri', r'x-sucuri'],
        'wordfence': [r'wordfence'],
        'barracuda': [r'barra'],
    }
    
    @classmethod
    def detect(cls, response: requests.Response) -> Optional[str]:
        """Detect WAF from response headers and body"""
        text = response.text.lower()
        headers_str = ' '.join(f"{k}:{v}" for k, v in response.headers.items()).lower()
        combined = f"{headers_str} {text[:1000]}"
        
        for waf_name, patterns in cls.WAF_SIGNATURES.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.I):
                    return waf_name
        
        return None

# ============================================
# RETRY MANAGER
# ============================================
class RetryManager:
    """Smart retry with exponential backoff"""
    
    def __init__(self, max_retries: int = 3, base_delay: float = 1.0):
        self.max_retries = max_retries
        self.base_delay = base_delay
    
    def should_retry(self, error_type: str, retry_count: int) -> bool:
        """Determine if request should be retried"""
        if retry_count >= self.max_retries:
            return False
        
        # Retry on network errors, not on auth/client errors
        retryable = {'timeout', 'connection', 'network', 'dns'}
        return any(r in error_type.lower() for r in retryable)
    
    def get_delay(self, retry_count: int) -> float:
        """Calculate exponential backoff delay"""
        return self.base_delay * (2 ** retry_count)

# ============================================
# MAIN SHOTA ENGINE
# ============================================
class Shota:
    """Production-grade HTTP testing engine"""
    
    def __init__(self, url: str, args):
        self.url = url
        self.args = args
        self.session = requests.Session()
        self.results: List[ShotResult] = []
        self.stats = Stats()
        self.wl_manager = WordlistManager(enable_cache=not args.no_cache)
        self.template = TemplateEngine(self.wl_manager)
        self.auth = AuthManager(self.session)
        self.retry_mgr = RetryManager(max_retries=args.retries)
        self.baseline: Optional[ShotResult] = None
        self.unique_responses: Dict[str, ShotResult] = {}
        self.start_time = None
        self.lock = threading.Lock()
        self.waf_detected = None
        self._setup()
    
    def _setup(self):
        """Configure session and environment"""
        # Headers
        self.session.headers.update({
            'User-Agent': self.args.user_agent,
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        })
        
        # Custom headers
        if self.args.header:
            for h in self.args.header:
                if ':' in h:
                    k, v = h.split(':', 1)
                    self.session.headers[k.strip()] = v.strip()
        
        # Proxy
        if self.args.proxy:
            self.session.proxies = {
                'http': self.args.proxy,
                'https': self.args.proxy
            }
        
        # SSL & redirects
        self.session.verify = not self.args.no_verify
        self.session.allow_redirects = not self.args.no_redirects
        
        # Output directory
        Path(self.args.output_dir).mkdir(parents=True, exist_ok=True)
    
    def _load_payloads(self) -> List[str]:
        """Load and expand payloads with template rendering"""
        # Try to find payload file
        payloads = self.wl_manager.load(
            self.args.payload_file,
            fallback_paths=[f'wordlists/{self.args.payload_file}']
        )
        
        if not payloads:
            log(f"Payload file not found: {self.args.payload_file}\n",
                C.R, '❌ ', silent=self.args.silent)
            sys.exit(1)
        
        log(f"Loaded {len(payloads)} payloads\n",
            C.G, '✅ ', silent=self.args.silent)
        
        # Template expansion
        if self.args.var:
            for vdef in self.args.var:
                if '=' in vdef:
                    k, v = vdef.split('=', 1)
                    self.template.set_var(k, v)
            
            expanded = []
            for p in payloads:
                expanded.extend(self.template.render(p))
            
            log(f"Expanded to {len(expanded)} payloads\n",
                C.C, '🚀 ', silent=self.args.silent)
            payloads = expanded
        
        # Limit
        if self.args.limit:
            payloads = payloads[:self.args.limit]
        
        if not payloads:
            log("No payloads to process!\n", C.R, '❌ ', silent=self.args.silent)
            sys.exit(1)
        
        return payloads
    
    def _shoot_single(self, payload: str, idx: int, total: int) -> ShotResult:
        """
        Fire single request with retry logic
        
        Returns:
            ShotResult object
        """
        retry_count = 0
        last_error = None
        
        while True:
            try:
                result = self._execute_request(payload, idx, total, retry_count)
                
                # Update stats (thread-safe)
                with self.lock:
                    self.stats.total += 1
                    if result.status:
                        self.stats.success += 1
                        self.stats.status_codes[result.status] += 1
                        
                        if result.findings:
                            self.stats.findings += len(result.findings)
                            self.stats.payloads_with_findings += 1
                        
                        if result.unique:
                            self.stats.unique_responses += 1
                
                return result
                
            except (requests.Timeout, socket.timeout) as e:
                last_error = 'timeout'
                if self.retry_mgr.should_retry(last_error, retry_count):
                    retry_count += 1
                    self.stats.retries += 1
                    delay = self.retry_mgr.get_delay(retry_count)
                    
                    if not self.args.silent and self.args.verbose:
                        log(f"Retry {retry_count}/{self.retry_mgr.max_retries} after {delay:.1f}s\n",
                            C.Y, '🔄 ')
                    
                    time.sleep(delay)
                    continue
                else:
                    self.stats.timeouts += 1
                    return ShotResult(
                        idx=idx, payload=payload,
                        error='timeout',
                        error_msg=f'Timeout after {self.args.timeout}s',
                        retry_count=retry_count
                    )
            
            except requests.RequestException as e:
                last_error = str(e)
                if self.retry_mgr.should_retry(last_error, retry_count):
                    retry_count += 1
                    self.stats.retries += 1
                    time.sleep(self.retry_mgr.get_delay(retry_count))
                    continue
                else:
                    self.stats.errors += 1
                    return ShotResult(
                        idx=idx, payload=payload,
                        error='request_exception',
                        error_msg=str(e)[:100],
                        retry_count=retry_count
                    )
            
            except Exception as e:
                self.stats.errors += 1
                return ShotResult(
                    idx=idx, payload=payload,
                    error='unexpected',
                    error_msg=str(e)[:100],
                    retry_count=retry_count
                )
    
    def _execute_request(self, payload: str, idx: int, total: int, retry_count: int) -> ShotResult:
        """Execute HTTP request and analyze response"""
        
        # Display progress
        if not self.args.silent and not self.args.quiet:
            if self.args.progress:
                self._display_progress(idx, total)
            elif self.args.verbose:
                log(f"\n{'─'*60}\n", C.GR)
                log(f"Shot {idx}/{total}\n", C.C, '🎯 ')
        
        # Prepare request
        ptype = PayloadProcessor.detect_type(payload)
        headers = PayloadProcessor.prepare_headers(ptype, dict(self.session.headers))
        
        url = self.url
        data = payload
        params = None
        
        # Handle GET requests
        if self.args.method.upper() == 'GET':
            if ptype == 'form':
                params = dict(urllib.parse.parse_qsl(payload))
                data = None
            else:
                sep = '&' if '?' in url else '?'
                url = f"{url}{sep}{payload}"
                data = None
        
        # Verbose logging
        if self.args.verbose and not self.args.silent:
            log(f"{self.args.method} {url[:80]}\n", C.Y, '📤 ')
            if data and len(str(data)) < 150:
                log(f"Data: {data}\n", C.GR, '   ')
        
        # Execute request
        start = time.time()
        r = self.session.request(
            method=self.args.method,
            url=url,
            headers=headers,
            data=data,
            params=params,
            timeout=self.args.timeout,
            stream=self.args.stream
        )
        duration = time.time() - start
        
        # Read response (stream mode)
        if self.args.stream:
            content = b''
            for chunk in r.iter_content(chunk_size=8192):
                content += chunk
                if len(content) > 1024 * 1024:  # 1MB limit in stream mode
                    break
            r._content = content
        
        # Detect WAF (first request only)
        if not self.waf_detected and idx == 1:
            self.waf_detected = WAFDetector.detect(r)
            if self.waf_detected and not self.args.silent:
                log(f"WAF detected: {self.waf_detected.upper()}\n", C.Y, '🛡️  ')
        
        # Analyze response
        body_hash = hashlib.md5(r.content).hexdigest()
        
        # Extract body preview
        try:
            if 'json' in r.headers.get('Content-Type', ''):
                body_preview = json.dumps(r.json(), indent=2)[:1000]
            else:
                body_preview = r.text[:1000]
        except:
            body_preview = r.text[:1000] if hasattr(r, 'text') else ''
        
        # Detect patterns
        findings = PatternDetector.detect(r, quick_mode=self.args.quick)
        
        # Build result
        result = ShotResult(
            idx=idx,
            payload=payload,
            status=r.status_code,
            time=round(duration, 3),
            size=len(r.content),
            hash=body_hash,
            findings=findings,
            headers=dict(r.headers),
            body_preview=body_preview,
            retry_count=retry_count,
        )
        
        # Diff analysis
        if self.args.diff and self.baseline:
            result.diff = ResponseDiffer.compare(self.baseline, result)
        
        # Set baseline (first successful request)
        if not self.baseline and idx == 1 and result.status:
            self.baseline = result
        
        # Track unique responses
        if body_hash not in self.unique_responses:
            self.unique_responses[body_hash] = result
            result.unique = True
        
        # Display result
        if not self.args.silent:
            self._display_result(result, r)
        
        return result
    
    def _display_progress(self, idx: int, total: int):
        """Display progress bar"""
        pct = int((idx / total) * 50)
        bar = '█' * pct + '░' * (50 - pct)
        
        # Add stats to progress bar
        stats_str = f" | ✓{self.stats.success} ⚠{self.stats.errors} 💀{self.stats.findings}"
        
        log(f"\r[{bar}] {idx}/{total}{stats_str}", C.C, '', end='')
        
        if idx == total:
            log("")  # Newline at end
    
    def _display_result(self, result: ShotResult, response: requests.Response):
        """Display single result"""
        if self.args.progress:
            return  # Progress bar mode, skip individual display
        
        if self.args.quiet and not result.findings:
            return  # Quiet mode, only show findings
        
        # Status line
        if result.status:
            color = C.G if result.status < 400 else C.Y if result.status < 500 else C.R
            status_line = f"{result.status} | {result.time}s | {result.size}B"
            
            if result.unique:
                status_line += f" | {C.M}★UNIQUE{C.RESET}"
            
            if result.retry_count > 0:
                status_line += f" | {C.Y}↻{result.retry_count}{C.RESET}"
            
            log(f"{status_line}\n", color, '📥 ')
        
        # Findings summary
        if result.findings:
            severity_counts = Counter(f['severity'] for f in result.findings)
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if sev in severity_counts:
                    sev_color = C.R if sev in ['CRITICAL', 'HIGH'] else C.Y if sev == 'MEDIUM' else C.GR
                    log(f"{sev}: {severity_counts[sev]}  ", sev_color, '', end='')
            log("\n")
            
            # Detailed findings
            if self.args.verbose:
                for f in result.findings[:5]:
                    ftype = f.get('type', 'unknown')
                    match = f.get('match', f.get('keyword', ''))
                    if match:
                        log(f"  [{f['severity']}] {ftype}: {str(match)[:60]}\n", C.GR, '')
        
        # Diff anomaly
        if result.diff and result.diff['anomaly'] != 'NONE':
            log(f"Anomaly: {result.diff['anomaly']} ({result.diff['severity']})\n",
                C.M, '🔔 ')
        
        # Body preview (verbose)
        if self.args.verbose and result.body_preview:
            preview = result.body_preview[:250]
            log(f"Body: {preview}\n", C.DIM, '📄 ')
    
    def _save_results(self):
        """Save results to JSON file"""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = Path(self.args.output_dir) / f"shota_{ts}.json"
        
        duration = time.time() - self.start_time if self.start_time else 0
        
        output = {
            'meta': {
                'version': VERSION,
                'target': self.url,
                'timestamp': ts,
                'duration': round(duration, 2),
                'method': self.args.method,
                'waf_detected': self.waf_detected,
            },
            'stats': self.stats.to_dict(),
            'unique_responses': len(self.unique_responses),
            'results': [r.to_dict() for r in self.results]
        }
        
        try:
            with open(fname, 'w', encoding='utf-8') as f:
                json.dump(output, f, indent=2)
            
            log(f"\n💾 Saved: {fname}\n", C.G, silent=self.args.silent)
            return fname
        except Exception as e:
            log(f"\n❌ Error saving: {e}\n", C.R, silent=self.args.silent)
            return None
    
    def _print_summary(self):
        """Print execution summary"""
        if self.args.silent:
            return
        
        log(f"\n{'═'*70}\n", C.C)
        log("SUMMARY\n", C.BOLD + C.C, '📊 ')
        log(f"{'═'*70}\n", C.C)
        
        duration = time.time() - self.start_time if self.start_time else 0
        rate = self.stats.total / duration if duration > 0 else 0
        
        log(f"Total: {self.stats.total} | Success: {self.stats.success} | "
            f"Time: {duration:.1f}s | Rate: {rate:.1f}/s\n", C.W)
        
        # Status codes
        if self.stats.status_codes:
            log("Status codes: ", C.W, '', end='')
            for code, count in sorted(self.stats.status_codes.items()):
                code_str = str(code)
                color = C.G if code_str.startswith('2') else C.Y if code_str.startswith('4') else C.R
                log(f"{code}×{count}  ", color, '', end='')
            log("\n")
        
        # Issues
        if self.stats.timeouts > 0 or self.stats.errors > 0 or self.stats.retries > 0:
            log("\nIssues: ", C.Y + C.BOLD, '⚠️  ')
            if self.stats.timeouts > 0:
                log(f"Timeouts: {self.stats.timeouts}  ", C.Y, '', end='')
            if self.stats.errors > 0:
                log(f"Errors: {self.stats.errors}  ", C.R, '', end='')
            if self.stats.retries > 0:
                log(f"Retries: {self.stats.retries}", C.GR, '', end='')
            log("\n")
        
        # Findings
        if self.stats.findings > 0:
            log(f"\nFindings: {self.stats.findings} "
                f"({self.stats.payloads_with_findings} payloads)\n",
                C.R + C.BOLD, '💀 ')
        
        # Unique responses
        if self.stats.unique_responses > 0:
            log(f"Unique responses: {self.stats.unique_responses}\n", C.M, '🎯 ')
        
        # WAF
        if self.waf_detected:
            log(f"WAF detected: {self.waf_detected.upper()}\n", C.Y, '🛡️  ')
        
        log(f"\n{'═'*70}\n", C.C)
    
    def run(self):
        """Main execution flow"""
        # Banner
        if not self.args.silent:
            banner()
        
        # Info
        if not self.args.silent and not self.args.quiet:
            log(f"Target: {self.url}\n", C.C, '🎯 ')
            log(f"Method: {self.args.method}\n", C.C, '⚙️  ')
            log(f"Payloads: {self.args.payload_file}\n", C.C, '📁 ')
            log(f"Delay: {self.args.delay}s | Threads: {self.args.threads}\n", C.C, '⏱️  ')
            
            if self.args.var:
                vars_str = ', '.join(v.split('=')[0] for v in self.args.var)
                log(f"Variables: {vars_str}\n", C.C, '🔧 ')
        
        # Ethical reminder
        if not self.args.silent and not self.args.yes:
            log("\n⚖️  Ethical Testing Reminder:\n", C.Y + C.BOLD)
            log("  • Only test authorized systems\n")
            log("  • Respect rate limits & resources\n")
            log("  • Document & report responsibly\n\n")
            
            try:
                input(f"{C.BOLD}Press ENTER to continue...{C.RESET} ")
            except KeyboardInterrupt:
                log("\n\n⚠️  Aborted\n", C.R)
                sys.exit(0)
        
        # Authentication
        if self.args.auth_url:
            if not self.args.silent:
                log("Authenticating...\n", C.C, '🔐 ')
            
            auth_data = {}
            if self.args.auth_user:
                auth_data['username'] = self.args.auth_user
            if self.args.auth_pass:
                auth_data['password'] = self.args.auth_pass
            
            success = self.auth.login(
                self.args.auth_url,
                json_data=auth_data if auth_data else None,
                token_path=self.args.auth_token
            )
            
            if success:
                log(f"Authenticated ({self.auth.auth_type})\n", C.G, '✅ ')
            else:
                log("Auth failed (continuing anyway)\n", C.Y, '⚠️ ')
        
        # Load payloads
        payloads = self._load_payloads()
        
        if not self.args.silent:
            log(f"\n🚀 Firing {len(payloads)} shots...\n\n", C.G + C.BOLD)
        
        self.start_time = time.time()
        
        # Execute shots (multi-threaded or sequential)
        if self.args.threads > 1:
            self._run_concurrent(payloads)
        else:
            self._run_sequential(payloads)
        
        # Finalize
        if self.args.progress and not self.args.silent:
            log("\n")
        
        self._save_results()
        self._print_summary()
    
    def _run_sequential(self, payloads: List[str]):
        """Run shots sequentially"""
        for i, payload in enumerate(payloads, 1):
            result = self._shoot_single(payload, i, len(payloads))
            self.results.append(result)
            
            # Rate limiting
            if i < len(payloads) and self.args.delay > 0:
                time.sleep(self.args.delay)
    
    def _run_concurrent(self, payloads: List[str]):
        """Run shots concurrently with thread pool"""
        total = len(payloads)
        
        with ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            # Submit all tasks
            futures = {
                executor.submit(self._shoot_single, payload, i, total): (payload, i)
                for i, payload in enumerate(payloads, 1)
            }
            
            # Collect results
            for future in as_completed(futures):
                payload, idx = futures[future]
                try:
                    result = future.result()
                    with self.lock:
                        self.results.append(result)
                except Exception as e:
                    log(f"Thread error: {e}\n", C.R, '💥 ', silent=self.args.silent)
                
                # Rate limiting (approximate in concurrent mode)
                if self.args.delay > 0:
                    time.sleep(self.args.delay / self.args.threads)
        
        # Sort results by index
        self.results.sort(key=lambda x: x.idx)

# ============================================
# CLI
# ============================================
def main():
    parser = argparse.ArgumentParser(
        description=f'SHOTA v{VERSION} - Silent Assassin HARDENED',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic scan
  shota3.py https://api.example.com -p payloads.txt

  # Fuzzing with variables
  shota3.py https://api.com/user/{{ID}} --var ID=1..100 -m GET

  # Multi-threaded scan
  shota3.py https://api.com -p sqli.txt --threads 10 -d 0.1

  # With authentication
  shota3.py https://api.com/protected \\
    --auth-url https://api.com/login \\
    --auth-user admin --auth-pass test \\
    --auth-token "data.access_token"

  # Silent mode with progress bar
  shota3.py https://api.com -p xss.txt --progress --silent -y

  # Advanced fuzzing with encoding
  shota3.py "https://api.com?q={{XSS:url:base64}}" \\
    --var XSS=@xss-payloads.txt -m GET --quick
"""
    )
    
    # Required
    parser.add_argument('url', help='Target URL (supports {{VARS}})')
    
    # Payload options
    parser.add_argument('-p', '--payload-file', default='payloads.txt',
                       help='Payload file (default: payloads.txt)')
    parser.add_argument('--var', action='append',
                       help='Variable (KEY=VALUE, 1..10, a,b,c, @file.txt)')
    parser.add_argument('--limit', type=int,
                       help='Limit number of payloads')
    
    # HTTP options
    parser.add_argument('-m', '--method', default='POST',
                       help='HTTP method (default: POST)')
    parser.add_argument('-H', '--header', action='append',
                       help='Custom header (repeatable)')
    parser.add_argument('-d', '--delay', type=float, default=1.0,
                       help='Delay between requests (default: 1.0s)')
    parser.add_argument('-t', '--timeout', type=int, default=15,
                       help='Request timeout (default: 15s)')
    parser.add_argument('--threads', type=int, default=1,
                       help='Concurrent threads (default: 1)')
    parser.add_argument('--retries', type=int, default=3,
                       help='Max retries on network errors (default: 3)')
    parser.add_argument('--proxy', help='HTTP(S) proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--no-verify', action='store_true',
                       help='Disable SSL verification')
    parser.add_argument('--no-redirects', action='store_true',
                       help='Disable redirects')
    parser.add_argument('--user-agent', default=f'SHOTA/{VERSION}',
                       help='User-Agent header')
    parser.add_argument('--stream', action='store_true',
                       help='Stream responses (memory-efficient)')
    
    # Authentication
    parser.add_argument('--auth-url', help='Login URL')
    parser.add_argument('--auth-user', help='Username')
    parser.add_argument('--auth-pass', help='Password')
    parser.add_argument('--auth-token', help='Token JSON path (e.g., data.token)')
    
    # Output options
    parser.add_argument('-o', '--output-dir', default='results',
                       help='Output directory (default: results)')
    parser.add_argument('-q', '--quiet', action='store_true',
                       help='Quiet mode (only findings)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('-s', '--silent', action='store_true',
                       help='Silent mode (zero output)')
    parser.add_argument('-y', '--yes', action='store_true',
                       help='Skip confirmation')
    parser.add_argument('--progress', action='store_true',
                       help='Progress bar mode')
    parser.add_argument('--diff', action='store_true',
                       help='Enable response diffing')
    parser.add_argument('--quick', action='store_true',
                       help='Quick mode (less pattern checks)')
    parser.add_argument('--no-cache', action='store_true',
                       help='Disable wordlist caching')
    
    args = parser.parse_args()
    
    # Run
    shota = Shota(args.url, args)
    shota.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n\n⚠️  Interrupted by user\n", C.R)
        sys.exit(0)
    except Exception as e:
        log(f"\n\n💥 Fatal error: {e}\n", C.R)
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
