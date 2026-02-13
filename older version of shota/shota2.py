#!/usr/bin/env python3
"""
███████╗██╗  ██╗ ██████╗ ████████╗ █████╗ 
██╔════╝██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗
███████╗███████║██║   ██║   ██║   ███████║
╚════██║██╔══██║██║   ██║   ██║   ██╔══██║
███████║██║  ██║╚██████╔╝   ██║   ██║  ██║
╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝

SHOTA v2.2.1 - Simple HTTP Offensive Testing Artillery
The Silent Assassin Edition - Fixed & Hardened

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
import os
import base64
import hashlib
import threading
import socket
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Union
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs, urlencode
import warnings
warnings.filterwarnings('ignore')

VERSION = "2.2.1"

# ============================================
# COLORS & STYLES
# ============================================
class Color:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'
    B = '\033[94m'; M = '\033[95m'; C = '\033[96m'
    W = '\033[97m'; GR = '\033[90m'
    BOLD = '\033[1m'; DIM = '\033[2m'
    RESET = '\033[0m'; CLEAR = '\033[2J\033[H'

# ============================================
# BANNER
# ============================================
def banner(silent=False):
    if silent: return
    art = f"""{Color.C}{Color.BOLD}
 ███████╗██╗  ██╗ ██████╗ ████████╗ █████╗ 
 ██╔════╝██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗
 ███████╗███████║██║   ██║   ██║   ███████║
 ╚════██║██╔══██║██║   ██║   ██║   ██╔══██║
 ███████║██║  ██║╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝{Color.RESET}

{Color.M}SHOTA v{VERSION} - The Silent Assassin{Color.RESET}
{Color.Y}Universal HTTP Security Testing Framework{Color.RESET}
{Color.GR}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{Color.RESET}
"""
    print(art)

def log(msg, c=Color.W, icon='', end='\n', silent=False):
    if not silent:
        print(f"{c}{icon}{msg}{Color.RESET}", end=end, flush=True)

# ============================================
# ADVANCED PATTERN DETECTOR
# ============================================
class PatternDetector:
    """Advanced vulnerability pattern detection with regex"""
    
    PATTERNS = {
        'aws_key': (r'AKIA[0-9A-Z]{16}', 'CRITICAL'),
        'aws_secret': (r'aws[_-]?secret[_-]?access[_-]?key["\']?\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})', 'CRITICAL'),
        'google_api': (r'AIza[0-9A-Za-z_-]{35}', 'CRITICAL'),
        'github_token': (r'ghp_[a-zA-Z0-9]{36}', 'CRITICAL'),
        'slack_token': (r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}', 'CRITICAL'),
        'private_key': (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', 'CRITICAL'),
        'jwt': (r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_.\-]*', 'HIGH'),
        'api_key': (r'(api[_-]?key|apikey|api[_-]?token)[\s"\':=]+(["\'])?([a-zA-Z0-9_\-]{20,})(\2)?', 'HIGH'),
        'password_hash': (r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}', 'HIGH'),
        'mysql_error': (r'(SQL syntax.*MySQL|Warning.*mysql_.*|MySQLSyntaxErrorException)', 'HIGH'),
        'postgresql_error': (r'(PostgreSQL.*ERROR|Warning.*\bpg_.*|PSQLException)', 'HIGH'),
        'mssql_error': (r'(Driver.*SQL[\-\_\ ]*Server|OLE DB.*SQL Server|SQLServer JDBC Driver)', 'HIGH'),
        'oracle_error': (r'(ORA-\d{5}|Oracle error|Oracle.*Driver)', 'HIGH'),
        'sqlite_error': (r'(SQLite/JDBCDriver|System\.Data\.SQLite\.SQLiteException)', 'HIGH'),
        'php_error': (r'(Fatal error|Parse error|Warning.*in\s+.*\.php|Notice.*in\s+.*\.php)', 'MEDIUM'),
        'python_error': (r'(Traceback \(most recent call last\)|File ".*\.py", line \d+)', 'MEDIUM'),
        'java_error': (r'(Exception in thread|\.java:\d+\)|at\s+[\w\.]+\([\w\.]+\.java:\d+\))', 'MEDIUM'),
        'dotnet_error': (r'(System\.\w+Exception|at\s+\w+\.\w+\.)', 'MEDIUM'),
        'email': (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'LOW'),
        'ipv4': (r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'LOW'),
        'credit_card': (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', 'CRITICAL'),
        'ssn': (r'\b\d{3}-\d{2}-\d{4}\b', 'CRITICAL'),
        'version': (r'(version|v)[\s:=]+(\d+\.\d+\.\d+)', 'LOW'),
        'server': (r'Server:\s*(.+)', 'LOW'),
        'xxe_indicator': (r'<!ENTITY|SYSTEM|PUBLIC', 'MEDIUM'),
        'debug_mode': (r'(DEBUG|VERBOSE|TRACE)\s*[:=]\s*(true|1|yes|on)', 'MEDIUM'),
        'stack_trace': (r'(at\s+[\w\.]+\([\w\.]+:\d+\)|Traceback)', 'MEDIUM'),
    }
    
    KEYWORDS = {
        'error': 'MEDIUM', 'exception': 'MEDIUM', 'fatal': 'HIGH',
        'warning': 'LOW', 'database': 'MEDIUM', 'sql': 'MEDIUM',
        'admin': 'LOW', 'password': 'MEDIUM', 'token': 'MEDIUM',
    }
    
    @classmethod
    def detect(cls, response: requests.Response) -> List[Dict]:
        findings = []
        text = response.text
        
        for name, (pattern, severity) in cls.PATTERNS.items():
            matches = re.finditer(pattern, text, re.I | re.M)
            for match in matches:
                findings.append({
                    'type': name, 'severity': severity,
                    'match': match.group(0)[:100], 'position': match.start()
                })
        
        text_lower = text.lower()
        for keyword, severity in cls.KEYWORDS.items():
            if keyword in text_lower and not any(f['type'] == 'keyword' and keyword in str(f.get('match', '')) for f in findings):
                findings.append({'type': 'keyword', 'keyword': keyword, 'severity': severity})
        
        if response.status_code >= 500:
            findings.append({'type': 'server_error', 'severity': 'HIGH', 'status': response.status_code})
        if response.status_code == 403:
            findings.append({'type': 'forbidden', 'severity': 'MEDIUM', 'detail': 'Access forbidden'})
        
        dangerous_headers = ['X-Debug', 'X-Powered-By', 'Server']
        for header in dangerous_headers:
            if header in response.headers:
                findings.append({
                    'type': 'header_disclosure', 'severity': 'LOW',
                    'header': header, 'value': response.headers[header]
                })
        
        return findings

# ============================================
# ADVANCED TEMPLATE ENGINE
# ============================================
class TemplateEngine:
    def __init__(self):
        self.vars = {}
        self.encoders = {
            'url': urllib.parse.quote,
            'url_double': lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'hex': lambda x: ''.join(f'{ord(c):02x}' for c in x),
            'html': lambda x: x.replace('<', '&lt;').replace('>', '&gt;'),
        }
    
    def set_var(self, key: str, value: str):
        if value.startswith('@'):
            self.vars[key] = self._load_wordlist(value[1:])
        elif '..' in value and value.replace('..', '').replace('-', '').isdigit():
            parts = value.split('..')
            self.vars[key] = list(range(int(parts[0]), int(parts[1]) + 1))
        elif ',' in value:
            self.vars[key] = [v.strip() for v in value.split(',')]
        else:
            self.vars[key] = [value]
    
    def _load_wordlist(self, filepath: str) -> List[str]:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        paths = [
            filepath, os.path.join('wordlists', filepath),
            os.path.join('.', 'wordlists', filepath),
            os.path.join(script_dir, 'wordlists', filepath),
            os.path.join(script_dir, '..', 'wordlists', filepath),
        ]
        for path in paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = [l.strip() for l in f if l.strip() and not l.startswith('#')]
                    return lines
                except Exception:
                    continue
        return []
    
    def render(self, template: str, encode: Optional[str] = None) -> List[str]:
        pattern = re.compile(r'\{\{(\w+)(?::(\w+))?\}\}')
        
        def replace_var(match):
            var_name, encoder_name = match.group(1), match.group(2)
            if var_name not in self.vars:
                return match.group(0)
            values = self.vars[var_name]
            if encoder_name and encoder_name in self.encoders:
                values = [self.encoders[encoder_name](str(v)) for v in values]
            return values
        
        vars_in_template = pattern.findall(template)
        if not vars_in_template:
            return [template]
        
        var_values = []
        for var_name, _ in vars_in_template:
            var_values.append(self.vars.get(v, [f'{{{{{v}}}}}']) for v in [var_name])
        var_values = [self.vars.get(v[0], [f'{{{{{v[0}}}}}']) for v in vars_in_template]
        
        results = []
        for combo in itertools.product(*var_values):
            result = template
            for (var_name, encoder_name), value in zip(vars_in_template, combo):
                placeholder = f'{{{{{var_name}{":" + encoder_name if encoder_name else ""}}}}}'
                if encoder_name and encoder_name in self.encoders:
                    value = self.encoders[encoder_name](str(value))
                result = result.replace(placeholder, str(value))
            results.append(result)
        return results

# ============================================
# PAYLOAD PROCESSOR
# ============================================
class PayloadProcessor:
    @staticmethod
    def detect_type(payload: str) -> str:
        p = payload.strip()
        if (p.startswith('{') or p.startswith('[')) and (p.endswith('}') or p.endswith(']')):
            try:
                json.loads(p)
                return 'json'
            except:
                pass
        if p.startswith('<?xml') or (p.startswith('<') and p.endswith('>')):
            return 'xml'
        if '=' in p and ('&' in p or p.count('=') == 1):
            return 'form'
        if 'query' in p.lower() or 'mutation' in p.lower():
            return 'graphql'
        try:
            if len(p) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', p):
                base64.b64decode(p)
                return 'base64'
        except:
            pass
        return 'raw'
    
    @staticmethod
    def prepare_headers(ptype: str, base_headers: Dict) -> Dict:
        headers = base_headers.copy()
        content_types = {
            'json': 'application/json', 'xml': 'application/xml',
            'form': 'application/x-www-form-urlencoded',
            'graphql': 'application/json', 'base64': 'text/plain', 'raw': 'text/plain'
        }
        if 'Content-Type' not in headers:
            headers['Content-Type'] = content_types.get(ptype, 'text/plain')
        return headers

# ============================================
# RESPONSE DIFFER
# ============================================
class ResponseDiffer:
    @staticmethod
    def compare(baseline: Dict, current: Dict) -> Dict:
        diff = {
            'status_changed': baseline.get('status') != current.get('status'),
            'size_delta': abs(baseline.get('size', 0) - current.get('size', 0)),
            'time_delta': abs(baseline.get('time', 0) - current.get('time', 0)),
            'hash_changed': baseline.get('hash') != current.get('hash'),
            'findings_delta': len(current.get('findings', [])) - len(baseline.get('findings', [])),
        }
        if diff['status_changed']:
            diff['anomaly'], diff['severity'] = 'STATUS_CHANGE', 'HIGH'
        elif diff['size_delta'] > 1000:
            diff['anomaly'], diff['severity'] = 'SIZE_ANOMALY', 'MEDIUM'
        elif diff['time_delta'] > 3:
            diff['anomaly'], diff['severity'] = 'TIMING_ANOMALY', 'MEDIUM'
        elif diff['findings_delta'] > 0:
            diff['anomaly'], diff['severity'] = 'NEW_FINDINGS', 'HIGH'
        else:
            diff['anomaly'], diff['severity'] = 'NONE', 'LOW'
        return diff

# ============================================
# AUTH MANAGER
# ============================================
class AuthManager:
    def __init__(self, session: requests.Session):
        self.session = session
        self.token = None
        self.cookies = {}
    
    def login(self, url: str, data: Dict = None, json_data: Dict = None, 
              token_path: str = None, method: str = 'POST'):
        try:
            if method.upper() == 'POST':
                if json_data:
                    r = self.session.post(url, json=json_data)
                else:
                    r = self.session.post(url, data=data)
            else:
                r = self.session.get(url)
            
            if r.status_code == 200 and token_path:
                result = r.json()
                for key in token_path.split('.'):
                    result = result[key]
                self.token = result
                self.session.headers['Authorization'] = f'Bearer {self.token}'
                return True
            return r.status_code == 200
        except Exception:
            return False

# ============================================
# MAIN SHOTA ENGINE
# ============================================
class Shota:
    def __init__(self, url: str, args):
        self.url = url
        self.args = args
        self.session = requests.Session()
        self.results = []
        self.stats = defaultdict(int)
        self.template = TemplateEngine()
        self.auth = AuthManager(self.session)
        self.baseline = None
        self.unique_responses = {}
        self.start_time = None
        self._setup()
    
    def _setup(self):
        self.session.headers.update({
            'User-Agent': self.args.user_agent, 'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9', 'Accept-Encoding': 'gzip, deflate',
        })
        if self.args.header:
            for h in self.args.header:
                if ':' in h:
                    k, v = h.split(':', 1)
                    self.session.headers[k.strip()] = v.strip()
        if self.args.proxy:
            self.session.proxies = {'http': self.args.proxy, 'https': self.args.proxy}
        self.session.verify = not self.args.no_verify
        self.session.allow_redirects = not self.args.no_redirects
        Path(self.args.output_dir).mkdir(exist_ok=True)
    
    def _load_payloads(self) -> List[str]:
        paths = [self.args.payload_file, f'wordlists/{self.args.payload_file}']
        pfile = None
        for p in paths:
            if os.path.exists(p):
                pfile = p
                break
        
        if not pfile:
            log(f"Payload file not found: {self.args.payload_file}\n", Color.R, '❌ ', silent=self.args.silent)
            tried = ' | '.join(paths)
            log(f"Tried: {tried}\n", Color.GR, '   ', silent=self.args.silent)
            sys.exit(1)
        
        try:
            with open(pfile, 'r', encoding='utf-8', errors='ignore') as f:
                payloads = [l.rstrip('\n\r') for l in f if l.strip() and not l.startswith('#')]
        except Exception as e:
            log(f"Error reading payload file: {e}\n", Color.R, '❌ ', silent=self.args.silent)
            sys.exit(1)
        
        log(f"Loaded {len(payloads)} payloads from {pfile}\n", Color.G, '✅ ', silent=self.args.silent)
        
        if self.args.var:
            for vdef in self.args.var:
                if '=' in vdef:
                    k, v = vdef.split('=', 1)
                    self.template.set_var(k, v)
            expanded = []
            for p in payloads:
                expanded.extend(self.template.render(p))
            log(f"Expanded to {len(expanded)} payloads\n", Color.C, '🚀 ', silent=self.args.silent)
            payloads = expanded
        
        if self.args.limit:
            payloads = payloads[:self.args.limit]
        
        if not payloads:
            log("No payloads to process!\n", Color.R, '❌ ', silent=self.args.silent)
            sys.exit(1)
        
        return payloads
    
    def _shoot(self, payload: str, idx: int, total: int) -> Dict:
        if not self.args.silent and not self.args.quiet:
            if self.args.progress:
                pct = int((idx / total) * 50)
                bar = '█' * pct + '░' * (50 - pct)
                if idx == total:
                    bar = '█' * 50
                log(f"\r[{bar}] {idx}/{total}", Color.C, '', end='', silent=False)
                if idx == total:
                    log("", silent=False)
            else:
                log(f"\n{'─'*60}\n", Color.GR, silent=False)
                log(f"Shot {idx}/{total}\n", Color.C, '🎯 ', silent=False)
        
        ptype = PayloadProcessor.detect_type(payload)
        headers = PayloadProcessor.prepare_headers(ptype, dict(self.session.headers))
        
        url = self.url
        data = payload
        params = None
        
        if self.args.method == 'GET':
            if ptype == 'form':
                params = dict(urllib.parse.parse_qsl(payload))
                data = None
            else:
                sep = '&' if '?' in url else '?'
                url = f"{url}{sep}{payload}"
                data = None
        
        if self.args.verbose and not self.args.silent:
            log(f"{self.args.method} {url[:70]}\n", Color.Y, '📤 ')
            if data and len(str(data)) < 100:
                log(f"Data: {data}\n", Color.GR, '   ')
        
        start = time.time()
        
        try:
            r = self.session.request(
                method=self.args.method, url=url, headers=headers,
                data=data, params=params, timeout=self.args.timeout
            )
            dur = time.time() - start
            
            analysis = {
                'idx': idx, 'payload': payload, 'status': r.status_code,
                'time': round(dur, 3), 'size': len(r.content),
                'hash': hashlib.md5(r.content).hexdigest(),
                'headers': dict(r.headers), 'findings': PatternDetector.detect(r),
                'url': r.url, 'type': ptype,
            }
            
            try:
                if 'json' in r.headers.get('Content-Type', ''):
                    analysis['body'] = r.json()
                else:
                    analysis['body'] = r.text[:1000]
            except:
                analysis['body'] = r.text[:1000]
            
            if self.args.diff and self.baseline:
                analysis['diff'] = ResponseDiffer.compare(self.baseline, analysis)
            
            if not self.baseline and idx == 1:
                self.baseline = analysis
            
            if analysis['hash'] not in self.unique_responses:
                self.unique_responses[analysis['hash']] = analysis
                analysis['unique'] = True
            else:
                analysis['unique'] = False
            
            if not self.args.silent:
                self._display(analysis, r)
            
            self.stats['total'] += 1
            self.stats[f'status_{r.status_code}'] += 1
            if analysis['findings']:
                self.stats['findings'] += len(analysis['findings'])
                self.stats['payloads_with_findings'] += 1
            if analysis.get('unique'):
                self.stats['unique_responses'] += 1
            
            return analysis
            
        except requests.Timeout:
            self.stats['timeouts'] += 1
            err_msg = f"Timeout ({self.args.timeout}s)"
            if not self.args.silent:
                log(f"Shot {idx}: {err_msg}\n", Color.Y, '⏰ ')
            return {'idx': idx, 'payload': payload, 'error': 'timeout', 'error_msg': err_msg}
        
        except requests.RequestException as e:
            self.stats['errors'] += 1
            err_msg = str(e)[:60]
            if not self.args.silent:
                log(f"Shot {idx}: Error - {err_msg}\n", Color.R, '💥 ')
            return {'idx': idx, 'payload': payload, 'error': 'request_exception', 'error_msg': err_msg}
        
        except Exception as e:
            self.stats['errors'] += 1
            err_msg = str(e)[:60]
            if not self.args.silent:
                log(f"Shot {idx}: Unexpected error - {err_msg}\n", Color.R, '💥 ')
            return {'idx': idx, 'payload': payload, 'error': 'unexpected', 'error_msg': err_msg}
    
    def _display(self, a: Dict, r: requests.Response):
        if self.args.quiet:
            if a.get('findings'):
                log(f"[{a['idx']}] {a['status']} | {len(a['findings'])} findings\n", Color.Y, '🔍 ')
            return
        
        c = Color.G if a['status'] < 400 else Color.Y if a['status'] < 500 else Color.R
        status_line = f"{a['status']} | {a['time']}s | {a['size']}B"
        if a.get('unique'):
            status_line += f" | {Color.M}UNIQUE{Color.RESET}"
        log(f"{status_line}\n", c, '📥 ')
        
        if a.get('findings'):
            severity_counts = Counter(f['severity'] for f in a['findings'])
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if sev in severity_counts:
                    sev_c = Color.R if sev in ['CRITICAL', 'HIGH'] else Color.Y if sev == 'MEDIUM' else Color.GR
                    log(f"{sev}: {severity_counts[sev]}  ", sev_c, '', end='')
            log("\n")
            if self.args.verbose:
                for f in a['findings'][:5]:
                    ftype = f.get('type', 'unknown')
                    match = f.get('match', f.get('keyword', ''))
                    if match:
                        log(f"  [{f['severity']}] {ftype}: {str(match)[:50]}\n", Color.GR, '')
        
        if a.get('diff') and a['diff']['anomaly'] != 'NONE':
            log(f"Anomaly: {a['diff']['anomaly']}\n", Color.M, '🔔 ')
        
        if self.args.verbose and 'body' in a:
            preview = str(a['body'])[:200]
            log(f"Body: {preview}\n", Color.DIM, '📄 ')
    
    def _save(self):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{self.args.output_dir}/shota_{ts}.json"
        
        duration = time.time() - self.start_time if self.start_time else 0
        
        output = {
            'meta': {
                'version': VERSION, 'target': self.url, 'timestamp': ts,
                'duration': round(duration, 2), 'method': self.args.method,
            },
            'stats': dict(self.stats),
            'unique_responses': list(self.unique_responses.keys()),
            'results': self.results
        }
        
        try:
            with open(fname, 'w') as f:
                json.dump(output, f, indent=2)
            log(f"\nSaved: {fname}\n", Color.G, '💾 ', silent=self.args.silent)
            return fname
        except Exception as e:
            log(f"Error saving results: {e}\n", Color.R, '❌ ', silent=self.args.silent)
            return None
    
    def _summary(self):
        if self.args.silent:
            return
        
        log(f"\n{'═'*60}\n", Color.C)
        log(f"SUMMARY\n", Color.BOLD + Color.C, '📊 ')
        log(f"{'═'*60}\n", Color.C)
        
        duration = time.time() - self.start_time if self.start_time else 0
        total = self.stats['total']
        rate = total/duration if duration > 0 else 0
        
        log(f"Total: {total} | Time: {duration:.1f}s | Rate: {rate:.1f}/s\n", Color.W, '')
        
        for k, v in sorted(self.stats.items()):
            if k.startswith('status_'):
                code = k.split('_')[1]
                c = Color.G if code.startswith('2') else Color.Y if code.startswith('4') else Color.R
                log(f"HTTP {code}: {v}  ", c, '', end='')
        log("\n\n")
        
        if self.stats.get('timeouts', 0) > 0 or self.stats.get('errors', 0) > 0:
            log(f"Issues: ", Color.Y + Color.BOLD, '⚠️ ')
            if self.stats.get('timeouts', 0) > 0:
                log(f"Timeouts: {self.stats['timeouts']}  ", Color.Y, '', end='')
            if self.stats.get('errors', 0) > 0:
                log(f"Errors: {self.stats['errors']}", Color.R, '')
            log("\n")
        
        if self.stats.get('findings', 0) > 0:
            log(f"Findings: {self.stats['findings']} ({self.stats['payloads_with_findings']} payloads)\n", Color.R + Color.BOLD, '💀 ')
        
        if self.stats.get('unique_responses', 0) > 0:
            log(f"Unique responses: {self.stats['unique_responses']}\n", Color.M, '🎯 ')
        
        log(f"\n{'═'*60}\n", Color.C)
    
    def run(self):
        if not self.args.silent:
            banner()
        
        if not self.args.silent and not self.args.quiet:
            log(f"Target: {self.url}\n", Color.C, '🎯 ')
            log(f"Method: {self.args.method}\n", Color.C, '⚙️  ')
            log(f"File: {self.args.payload_file}\n", Color.C, '📁 ')
            log(f"Delay: {self.args.delay}s\n", Color.C, '⏱️  ')
            if self.args.var:
                log(f"Variables: {', '.join(v.split('=')[0] for v in self.args.var)}\n", Color.C, '🔧 ')
        
        if not self.args.silent and not self.args.yes:
            log("\nEthical Testing Reminder:\n", Color.Y + Color.BOLD, '⚖️  ')
            log("  • Only authorized systems\n")
            log("  • Respect rate limits\n")
            log("  • Document responsibly\n\n")
            try:
                input(f"{Color.BOLD}Press ENTER to continue...{Color.RESET} ")
            except KeyboardInterrupt:
                log("\n\nAborted.\n", Color.R)
                sys.exit(0)
        
        if self.args.auth_url:
            if not self.args.silent:
                log("Authenticating...\n", Color.C, '🔐 ')
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
                log("Authenticated\n", Color.G, '✅ ')
            else:
                log("Auth failed (continuing anyway)\n", Color.Y, '⚠️ ')
        
        payloads = self._load_payloads()
        
        if not self.args.silent:
            log(f"\nFiring {len(payloads)} shots...\n\n", Color.G + Color.BOLD, '🚀 ')
        
        self.start_time = time.time()
        
        for i, p in enumerate(payloads, 1):
            res = self._shoot(p, i, len(payloads))
            self.results.append(res)
            if i < len(payloads) and self.args.delay > 0:
                time.sleep(self.args.delay)
        
        if self.args.progress and not self.args.silent:
            log("\n")
        
        self._save()
        self._summary()

# ============================================
# CLI
# ============================================
def main():
    parser = argparse.ArgumentParser(
        description=f'SHOTA v{VERSION} - The Silent Assassin',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} https://api.com -p payloads.txt
  {sys.argv[0]} https://api.com/user/{{{{ID}}}} --var ID=1..100 -m GET
  {sys.argv[0]} https://api.com/search?q={{{{XSS}}}} --var XSS=@xss.txt -m GET --silent
  {sys.argv[0]} https://api.com --auth-url https://api.com/login --auth-user admin -p api.txt
  {sys.argv[0]} https://api.com -p payloads.txt --progress -d 0.1
""")
    
    parser.add_argument('url', help='Target URL (supports {{{{VARS}}}})')
    parser.add_argument('-p', '--payload-file', default='payloads.txt', help='Payload file')
    parser.add_argument('--var', action='append', help='Variable (KEY=VALUE, 1..10, a,b,c, @file)')
    parser.add_argument('--limit', type=int, help='Limit payloads')
    parser.add_argument('-m', '--method', default='POST', help='HTTP method (default: POST)')
    parser.add_argument('-H', '--header', action='append', help='Custom header (repeatable)')
    parser.add_argument('-d', '--delay', type=float, default=1.0, help='Delay between requests (default: 1.0s)')
    parser.add_argument('-t', '--timeout', type=int, default=15, help='Timeout (default: 15s)')
    parser.add_argument('--proxy', help='Proxy (http://127.0.0.1:8080)')
    parser.add_argument('--no-verify', action='store_true', help='Disable SSL verification')
    parser.add_argument('--no-redirects', action='store_true', help='Disable redirects')
    parser.add_argument('--user-agent', default=f'SHOTA/{VERSION}', help='User-Agent')
    parser.add_argument('--auth-url', help='Login URL')
    parser.add_argument('--auth-user', help='Username')
    parser.add_argument('--auth-pass', help='Password')
    parser.add_argument('--auth-token', help='Token JSON path (e.g., data.token)')
    parser.add_argument('-o', '--output-dir', default='results', help='Output directory')
    parser.add_argument('-q', '--quiet', action='store_true', help='Quiet (only findings)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose (full output)')
    parser.add_argument('-s', '--silent', action='store_true', help='Silent (zero output, save only)')
    parser.add_argument('-y', '--yes', action='store_true', help='Skip confirmation')
    parser.add_argument('--progress', action='store_true', help='Progress bar mode')
    parser.add_argument('--diff', action='store_true', help='Compare responses (anomaly detection)')
    
    args = parser.parse_args()
    
    shota = Shota(args.url, args)
    shota.run()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("\n\nInterrupted by user\n", Color.R, '⚠️  ')
        sys.exit(0)
    except Exception as e:
        log(f"\n\nFatal error: {e}\n", Color.R, '💥 ')
        if '--verbose' in sys.argv or '-v' in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)
