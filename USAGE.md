# 📖 SHOTA v3.0 - Complete Usage Guide

<div align="center">

<img src="https://res.cloudinary.com/dwiozm4vz/image/upload/v1770970613/zvemb4fhak7ukfcppo3w.jpg" alt="SHOTA Logo" width="300"/>

**Master the Silent Assassin**  
*From Zero to Production-Grade Testing*

</div>

---

## 📚 Table of Contents

1. [Basic Usage](#1-basic-usage)
2. [Variable Fuzzing](#2-variable-fuzzing)
3. [Multi-threading](#3-multi-threading)
4. [Authentication](#4-authentication)
5. [Encoding Chains](#5-encoding-chains)
6. [WAF Evasion](#6-waf-evasion)
7. [Response Analysis](#7-response-analysis)
8. [Advanced Techniques](#8-advanced-techniques)
9. [Real-World Scenarios](#9-real-world-scenarios)
10. [Automation & Scripting](#10-automation--scripting)
11. [Performance Tuning](#11-performance-tuning)
12. [Troubleshooting](#12-troubleshooting)

---

## 1. Basic Usage

### 1.1 Simple POST Request

```bash
# Create a basic payload file
cat > test-payloads.txt << 'EOF'
{"username": "admin", "password": "test123"}
{"username": "user", "password": "pass"}
{"username": "root", "password": "toor"}
EOF

# Run SHOTA
python shota3.py https://api.example.com/login -p test-payloads.txt
```

**Expected output:**
```
🎯 Target: https://api.example.com/login
⚙️  Method: POST
📁 Payloads: test-payloads.txt

🚀 Firing 3 shots...

📥 200 | 0.234s | 1024B
📥 401 | 0.189s | 512B
📥 500 | 0.567s | 2048B
  [HIGH] mysql_error: You have an error in your SQL syntax
```

---

### 1.2 GET Request

```bash
# Simple GET with query parameter
python shota3.py https://api.example.com/search?q=test -m GET -p payloads.txt
```

---

### 1.3 Custom Headers

```bash
python shota3.py https://api.example.com/api \
  -H "Content-Type: application/json" \
  -H "X-API-Key: secret-key-123" \
  -H "User-Agent: CustomBot/1.0" \
  -p payloads.txt
```

**Pro tip:** Use `-H` multiple times for many headers.

---

### 1.4 Output Modes

```bash
# Normal mode (default)
python shota3.py https://api.com -p payloads.txt

# Verbose mode (show full bodies)
python shota3.py https://api.com -p payloads.txt -v

# Quiet mode (only findings)
python shota3.py https://api.com -p payloads.txt -q

# Silent mode (zero output, save only)
python shota3.py https://api.com -p payloads.txt -s

# Progress bar mode
python shota3.py https://api.com -p payloads.txt --progress
```

---

## 2. Variable Fuzzing

### 2.1 Numeric Range

```bash
# Test user IDs 1-1000
python shota3.py "https://api.example.com/user/{{ID}}/profile" \
  --var ID=1..1000 \
  -m GET \
  -p simple.txt
```

**What happens:**
- `{{ID}}` replaced with 1, 2, 3, ..., 1000
- 1000 requests sent
- Each with different ID

**Result:** Find IDOR vulnerabilities

---

### 2.2 List of Values

```bash
# Test multiple API versions
python shota3.py "https://api.example.com/{{VERSION}}/users" \
  --var VERSION=v1,v2,v3,beta,alpha,dev \
  -m GET \
  -p payloads.txt
```

**Use case:** API version enumeration

---

### 2.3 Wordlist from File

```bash
# Create username wordlist
cat > usernames.txt << 'EOF'
admin
administrator
root
test
guest
demo
EOF

# Fuzz with wordlist
python shota3.py "https://api.example.com/user/{{USER}}" \
  --var USER=@usernames.txt \
  -m GET
```

**Note:** `@` prefix loads from file

---

### 2.4 Multi-Variable Fuzzing (Cartesian Product)

```bash
# Test all combinations
python shota3.py "https://api.example.com/{{TYPE}}/{{ID}}" \
  --var TYPE=users,posts,comments,files \
  --var ID=1..10 \
  -m GET
```

**Math:** 4 types × 10 IDs = **40 requests**

**Generated URLs:**
```
/users/1, /users/2, ..., /users/10
/posts/1, /posts/2, ..., /posts/10
/comments/1, /comments/2, ..., /comments/10
/files/1, /files/2, ..., /files/10
```

---

### 2.5 Negative Ranges

```bash
# Test from -10 to 10
python shota3.py "https://api.com/offset/{{NUM}}" \
  --var NUM=-10..10 \
  -m GET
```

**Use case:** Testing edge cases with negative numbers

---

## 3. Multi-threading

### 3.1 Basic Multi-threading

```bash
# Use 10 threads
python shota3.py https://api.example.com \
  -p payloads.txt \
  --threads 10
```

**Performance:** ~7x faster than sequential

---

### 3.2 Thread Count Guidelines

| Threads | Use Case | Speed | Risk |
|---------|----------|-------|------|
| 1 | Default, safe | 1x | Low |
| 5 | Moderate speed | 3x | Low |
| 10 | Recommended max | 7x | Medium |
| 20 | Fast scanning | 10x | High (may trigger WAF) |
| 50+ | Mass scanning | 15x+ | Very High |

**Warning:** High thread count may trigger rate limiting or WAF blocks.

---

### 3.3 Multi-threading + Rate Limiting

```bash
# 20 threads but with 0.1s delay per thread
python shota3.py https://api.com \
  -p payloads.txt \
  --threads 20 \
  -d 0.1
```

**Math:** Effective delay = 0.1s × 20 threads = 2s between bursts

---

### 3.4 Progress Bar Mode (Recommended for Multi-threading)

```bash
python shota3.py https://api.com \
  -p payloads.txt \
  --threads 50 \
  --progress
```

**Output:**
```
[████████████████████████████░░░░░] 567/1000 | ✓520 ⚠12 💀35
```

**Symbols:**
- ✓ Success count
- ⚠ Error count
- 💀 Findings count

---

## 4. Authentication

### 4.1 Manual Bearer Token

```bash
python shota3.py https://api.example.com/protected \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -p payloads.txt
```

---

### 4.2 Manual Cookie-based Auth

```bash
python shota3.py https://app.example.com/dashboard \
  -H "Cookie: session=abc123def456; user_id=42; role=admin" \
  -p payloads.txt
```

---

### 4.3 Auto-Login (Recommended)

```bash
# SHOTA logs in, extracts token, then tests
python shota3.py https://api.example.com/admin \
  --auth-url https://api.example.com/auth/login \
  --auth-user admin@example.com \
  --auth-pass MySecureP@ss123 \
  --auth-token "access_token" \
  -p admin-payloads.txt
```

**How it works:**
1. POST to `/auth/login` with credentials
2. Extract token from JSON response
3. Add `Authorization: Bearer <token>` header
4. Use for all subsequent requests

---

### 4.4 Token Path Examples

```bash
# Simple (root level)
--auth-token "token"

# Nested (one level)
--auth-token "data.access_token"

# Deep nested (multiple levels)
--auth-token "response.user.auth.credentials.bearer_token"
```

**JSON response examples:**

```json
// Simple: --auth-token "token"
{"token": "eyJhbGc..."}

// Nested: --auth-token "data.access_token"
{"data": {"access_token": "eyJhbGc..."}}

// Deep: --auth-token "response.user.auth.credentials.bearer_token"
{
  "response": {
    "user": {
      "auth": {
        "credentials": {
          "bearer_token": "eyJhbGc..."
        }
      }
    }
  }
}
```

---

### 4.5 Auth Types Auto-Detection

SHOTA v3.0 auto-detects auth type:

```python
# Bearer token (if "bearer" in path or token length > 50)
Authorization: Bearer <token>

# Generic token (if shorter)
X-Auth-Token: <token>

# Session (if no token path provided)
Uses cookies from login response
```

---

## 5. Encoding Chains

### 5.1 Basic Encoding

```bash
# URL encode
python shota3.py "https://api.com?q={{FUZZ:url}}" \
  --var FUZZ=@xss.txt \
  -m GET
```

**Available encoders:**
- `url` - URL encode
- `url2x` - Double URL encode
- `base64` - Base64 encode
- `hex` - Hex encode
- `html` - HTML entity encode
- `upper` - Uppercase
- `lower` - Lowercase

---

### 5.2 Chained Encoding (WAF Bypass)

```bash
# URL encode THEN Base64 encode
python shota3.py "https://api.com?search={{XSS:url:base64}}" \
  --var XSS=@xss-payloads.txt \
  -m GET
```

**Example transformation:**
```
Input:    <script>alert(1)</script>
url:      %3Cscript%3Ealert%281%29%3C%2Fscript%3E
base64:   JTNDc2NyaXB0JTNFYWxlcnQlMjgxJTI5JTNDJTI...
```

---

### 5.3 Triple Encoding

```bash
# URL → Base64 → Hex
python shota3.py "https://api.com?data={{PAYLOAD:url:base64:hex}}" \
  --var PAYLOAD=' OR 1=1-- \
  -m GET
```

**Use case:** Bypass sophisticated WAFs

---

### 5.4 Multiple Variables with Different Encodings

```bash
python shota3.py "https://api.com?user={{USER:url}}&pass={{PASS:base64}}" \
  --var USER=admin,root,test \
  --var PASS=password,123456,admin \
  -m GET
```

**Result:** Each variable encoded differently

---

## 6. WAF Evasion

### 6.1 WAF Detection

SHOTA v3.0 automatically detects WAFs:

```bash
python shota3.py https://protected.example.com -p payloads.txt
```

**Output:**
```
🛡️  WAF detected: CLOUDFLARE
```

**Detected WAFs:**
- Cloudflare
- Akamai
- AWS WAF
- Imperva (Incapsula)
- F5 BIG-IP
- Fortinet FortiWeb
- Sucuri
- Wordfence
- Barracuda

---

### 6.2 Evasion Technique 1: Encoding Chains

```bash
# Double URL encode bypasses many WAFs
python shota3.py "https://waf-protected.com?q={{SQLI:url2x}}" \
  --var SQLI=@sqli.txt \
  -m GET
```

---

### 6.3 Evasion Technique 2: Slow Down

```bash
# Bypass rate-based WAF detection
python shota3.py https://protected.com \
  -p payloads.txt \
  --threads 5 \
  -d 2.0
```

**Logic:** Slower = less suspicious

---

### 6.4 Evasion Technique 3: Randomize User-Agent

```bash
# Create script to rotate User-Agents
for ua in "Mozilla/5.0" "Chrome/91.0" "Safari/14.0"; do
  python shota3.py https://protected.com \
    --user-agent "$ua" \
    -p payloads.txt \
    --limit 100
done
```

---

### 6.5 Evasion Technique 4: Case Variation

```bash
# Use upper/lower encoding
python shota3.py "https://api.com?cmd={{CMD:upper}}" \
  --var CMD=@commands.txt \
  -m GET

python shota3.py "https://api.com?cmd={{CMD:lower}}" \
  --var CMD=@commands.txt \
  -m GET
```

**Bypasses:** Case-sensitive WAF rules

---

## 7. Response Analysis

### 7.1 Response Diffing

```bash
# Enable diff mode to detect anomalies
python shota3.py https://api.example.com \
  -p payloads.txt \
  --diff
```

**Output:**
```
📥 200 | 0.156s | 2048B
🔔 Anomaly: SIZE_ANOMALY (MEDIUM)
```

**Anomaly types:**
- `STATUS_CHANGE` - Different status code (HIGH)
- `NEW_FINDINGS` - New vulnerability patterns (HIGH)
- `SIZE_ANOMALY` - Body size delta > 1KB (MEDIUM)
- `TIMING_ANOMALY` - Response time delta > 5s (MEDIUM)
- `CONTENT_DRIFT` - Body similarity < 50% (MEDIUM)

---

### 7.2 Unique Response Tracking

```bash
python shota3.py https://api.com \
  -p payloads.txt \
  --threads 10
```

**Output:**
```
📥 200 | 0.234s | 1024B | ★UNIQUE
```

**Symbol `★UNIQUE`** means:
- First time seeing this response hash
- Body content is different from all previous

**Use case:** Identify payloads that trigger different code paths

---

### 7.3 Pattern Detection

All responses auto-scanned for 30+ patterns:

```bash
python shota3.py https://api.com -p payloads.txt -v
```

**Example finding:**
```
CRITICAL: 2  HIGH: 3  MEDIUM: 1

  [CRITICAL] aws_key: AKIAIOSFODNN7EXAMPLE
  [CRITICAL] private_key: -----BEGIN RSA PRIVATE KEY-----
  [HIGH] jwt: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  [HIGH] mysql_error: You have an error in your SQL syntax
  [HIGH] api_key: api_key=sk_live_51H8xJ2K...
  [MEDIUM] email: admin@internal-company.com
```

---

### 7.4 Quick Mode (Performance)

```bash
# Check only CRITICAL and HIGH patterns
python shota3.py https://api.com \
  -p payloads.txt \
  --quick \
  --threads 50
```

**Speed:** ~2x faster pattern matching

**Trade-off:** Miss MEDIUM/LOW severity findings

---

## 8. Advanced Techniques

### 8.1 Streaming Large Responses

```bash
# Handle 100MB+ responses without OOM
python shota3.py https://api.com/export \
  -p payloads.txt \
  --stream
```

**Memory limit:** Caps at 1MB per response in stream mode

**Use case:** Testing file download endpoints

---

### 8.2 Smart Retries

```bash
# Auto-retry on network errors
python shota3.py https://flaky-api.com \
  -p payloads.txt \
  --retries 5
```

**Retry logic:**
- Exponential backoff: 1s, 2s, 4s, 8s, 16s
- Only retries network errors (timeout, DNS, connection)
- Skips client errors (400, 401, 403, etc.)

---

### 8.3 Proxy Integration (Burp Suite)

```bash
# Route all traffic through Burp
python shota3.py https://api.example.com \
  -p payloads.txt \
  --proxy http://127.0.0.1:8080 \
  --no-verify
```

**Setup:**
1. Open Burp Suite
2. Proxy → Options → Bind to port 8080
3. Intercept → OFF (or capture manually)
4. Run SHOTA with `--proxy`

**Benefit:** Inspect/modify traffic in real-time

---

### 8.4 SSL Certificate Issues

```bash
# Disable SSL verification (testing environments only!)
python shota3.py https://localhost:8443/api \
  --no-verify \
  -p payloads.txt
```

**Warning:** Only use on internal/test systems

---

### 8.5 Disable Redirects

```bash
# Don't follow redirects
python shota3.py https://api.com \
  -p payloads.txt \
  --no-redirects
```

**Use case:** Detect authentication bypass via redirect

---

### 8.6 Limit Payloads (Testing)

```bash
# Test first 10 payloads only
python shota3.py https://api.com \
  --limit 10 \
  -p large-wordlist.txt
```

**Use case:** Quick validation before full scan

---

### 8.7 Wordlist Caching

```bash
# First run: loads from disk (~150ms)
python shota3.py https://api.com -p huge-wordlist.txt

# Second run: loads from cache (~15ms)
python shota3.py https://api.com -p huge-wordlist.txt
```

**Cache location:** `~/.shota/cache/*.pkl.gz`

**Disable:**
```bash
python shota3.py https://api.com -p wordlist.txt --no-cache
```

---

## 9. Real-World Scenarios

### 9.1 IDOR Testing (Insecure Direct Object Reference)

```bash
# Enumerate 10,000 user profiles
python shota3.py "https://api.example.com/user/{{ID}}/profile" \
  --var ID=1..10000 \
  --threads 50 \
  -m GET \
  -d 0.05 \
  --progress \
  --diff
```

**Look for:**
- ✅ Status 200 when unauthorized
- ✅ Different response sizes
- ✅ Anomaly: STATUS_CHANGE

**Remediation:** Implement proper authorization checks

---

### 9.2 SQL Injection Testing

```bash
# Multi-threaded SQLi scan
python shota3.py https://vulnerable-app.com/search \
  -p wordlists/sqli.txt \
  --threads 10 \
  --retries 3 \
  -v
```

**Auto-detected patterns:**
```
[HIGH] mysql_error: You have an error in your SQL syntax
[HIGH] postgresql_error: ERROR: syntax error at or near
[HIGH] mssql_error: Unclosed quotation mark after the character string
[HIGH] oracle_error: ORA-01756: quoted string not properly terminated
```

---

### 9.3 XSS Testing with WAF Bypass

```bash
# Encoding chain to bypass WAF
python shota3.py "https://app.com/search?q={{XSS:url:base64}}" \
  --var XSS=@wordlists/xss.txt \
  -m GET \
  --threads 20 \
  --diff \
  -v
```

**Check verbose output for:**
- Reflected payloads in response body
- Different response sizes (indicates filtering)

---

### 9.4 API Enumeration

```bash
# Map all API endpoints
python shota3.py "https://api.com/{{VERSION}}/{{RESOURCE}}" \
  --var VERSION=v1,v2,v3,beta,alpha \
  --var RESOURCE=@wordlists/api-generic.txt \
  -m GET \
  --threads 30
```

**Result:** Discover hidden/deprecated endpoints

---

### 9.5 Authentication Bypass

```bash
# Test multiple auth bypass techniques
cat > auth-bypass.txt << 'EOF'
{"username": "admin", "password": "' OR '1'='1"}
{"username": "admin'--", "password": "any"}
{"username": "admin", "password": "admin' UNION SELECT NULL--"}
EOF

python shota3.py https://api.com/login \
  -p auth-bypass.txt \
  -v
```

---

### 9.6 JWT Secret Brute-forcing

```bash
# Fuzz JWT secret
python shota3.py https://api.com/auth/verify \
  -p jwt-secrets.txt \
  --threads 50 \
  --retries 5 \
  --diff
```

**Look for:** Successful authentication with guessed secret

---

### 9.7 File Upload Vulnerabilities

```bash
# Test malicious filenames
cat > filenames.txt << 'EOF'
test.php
../../../etc/passwd
test.php.png
test.php%00.png
<?php phpinfo(); ?>
test.phar
EOF

python shota3.py https://app.com/upload \
  -p filenames.txt \
  -v
```

---

### 9.8 Rate Limit Testing

```bash
# Hammer endpoint to find rate limit
python shota3.py https://api.com/endpoint \
  -p simple-payload.txt \
  --var REQ=1..10000 \
  --threads 100 \
  --progress
```

**Watch for:**
- Status 429 (Too Many Requests)
- WAF block messages
- Timing anomalies

---

### 9.9 Moodle LMS Security Audit

```bash
# Test unauthenticated Moodle AJAX endpoints
python shota3.py https://school.example.com/lib/ajax/service.php \
  -p wordlists/api-moodle.txt \
  --threads 10 \
  -v
```

**Look for:**
- Information disclosure
- Unauthenticated data access
- Configuration exposure

---

### 9.10 Multi-Stage Attack Chain

```bash
# Stage 1: Login
python shota3.py https://api.com/protected \
  --auth-url https://api.com/login \
  --auth-user attacker@test.com \
  --auth-pass P@ssw0rd \
  --auth-token "access_token" \
  -p stage1.txt

# Stage 2: Privilege escalation
python shota3.py https://api.com/admin/users \
  -H "Authorization: Bearer <token_from_stage1>" \
  -p stage2.txt

# Stage 3: Data exfiltration
python shota3.py "https://api.com/data/{{ID}}" \
  --var ID=1..1000 \
  -H "Authorization: Bearer <token>" \
  --threads 50 \
  --stream
```

---

## 10. Automation & Scripting

### 10.1 Bash Script Integration

```bash
#!/bin/bash
# mass-scan.sh

TARGETS=(
  "https://api1.example.com"
  "https://api2.example.com"
  "https://api3.example.com"
)

for target in "${TARGETS[@]}"; do
  echo "🎯 Scanning $target..."
  
  python shota3.py "$target" \
    -p payloads.txt \
    --threads 20 \
    --progress \
    --silent \
    -y \
    -o "results/$(echo $target | md5sum | cut -d' ' -f1)"
  
  echo "✅ Complete: $target"
done

echo "🎉 All scans finished!"
```

**Run:**
```bash
chmod +x mass-scan.sh
./mass-scan.sh
```

---

### 10.2 CI/CD Integration (GitHub Actions)

```yaml
# .github/workflows/security-scan.yml
name: Security Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: 3.9
      
      - name: Install SHOTA
        run: |
          pip install -r requirements.txt
      
      - name: Run Security Scan
        run: |
          python shota3.py ${{ secrets.API_URL }} \
            -p payloads.txt \
            --threads 10 \
            --silent \
            -y
      
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: shota-results
          path: results/
```

---

### 10.3 Cron Job (Continuous Testing)

```bash
# Add to crontab
crontab -e

# Daily security check at 2 AM
0 2 * * * cd /opt/shota && python shota3.py https://api.example.com -p payloads.txt -s -y >> /var/log/shota.log 2>&1

# Weekly comprehensive scan on Sunday 3 AM
0 3 * * 0 cd /opt/shota && python shota3.py https://api.example.com -p full-wordlist.txt --threads 50 -s -y
```

---

### 10.4 Python Wrapper

```python
#!/usr/bin/env python3
import subprocess
import json
from datetime import datetime

def run_shota_scan(target, payloads, threads=10):
    """Run SHOTA scan and parse results"""
    
    cmd = [
        'python', 'shota3.py',
        target,
        '-p', payloads,
        '--threads', str(threads),
        '--silent',
        '-y'
    ]
    
    subprocess.run(cmd)
    
    # Parse latest result
    import glob
    latest_result = max(glob.glob('results/shota_*.json'))
    
    with open(latest_result) as f:
        data = json.load(f)
    
    return data

# Use it
results = run_shota_scan(
    target='https://api.example.com',
    payloads='payloads.txt',
    threads=20
)

if results['stats']['findings'] > 0:
    print(f"⚠️  Found {results['stats']['findings']} vulnerabilities!")
    # Send alert, create ticket, etc.
```

---

### 10.5 Parallel Multi-Target Scanning

```bash
#!/bin/bash
# parallel-scan.sh

cat targets.txt | xargs -P 10 -I {} bash -c "
  echo 'Scanning {}...'
  python shota3.py {} -p payloads.txt --threads 5 -s -y
"
```

**Explanation:**
- `xargs -P 10`: Run 10 parallel processes
- Each target gets its own SHOTA instance
- Total concurrency: 10 targets × 5 threads = 50 concurrent requests

---

## 11. Performance Tuning

### 11.1 Thread vs Delay Trade-off

```bash
# Scenario A: High speed (may trigger WAF)
python shota3.py https://api.com -p payloads.txt --threads 50 -d 0

# Scenario B: Balanced (recommended)
python shota3.py https://api.com -p payloads.txt --threads 10 -d 0.2

# Scenario C: Stealth mode
python shota3.py https://api.com -p payloads.txt --threads 1 -d 2.0
```

| Scenario | Threads | Delay | Speed | Stealthiness |
|----------|---------|-------|-------|--------------|
| A | 50 | 0s | ⚡⚡⚡⚡⚡ | 🥷 |
| B | 10 | 0.2s | ⚡⚡⚡ | 🥷🥷🥷 |
| C | 1 | 2s | ⚡ | 🥷🥷🥷🥷🥷 |

---

### 11.2 Memory Optimization

```bash
# For large wordlists (100K+ lines)
python shota3.py https://api.com \
  -p huge-wordlist.txt \
  --stream \
  --quick \
  --threads 20
```

**Flags used:**
- `--stream`: Cap response size at 1MB
- `--quick`: Skip MEDIUM/LOW patterns
- `--threads 20`: Balance speed vs memory

**Result:** ~70% less memory usage

---

### 11.3 Network Optimization

```bash
# Increase timeout for slow targets
python shota3.py https://slow-api.com \
  -p payloads.txt \
  -t 60 \
  --retries 5
```

```bash
# Decrease timeout for fast targets
python shota3.py https://fast-api.com \
  -p payloads.txt \
  -t 5 \
  --threads 50
```

---

### 11.4 Wordlist Optimization

```bash
# Benchmark wordlist loading
time python shota3.py https://api.com -p wordlist.txt --limit 1

# First run: ~150ms (load from disk)
# Second run: ~15ms (load from cache)

# Clear cache if needed
rm -rf ~/.shota/cache/
```

---

## 12. Troubleshooting

### Problem 1: "Connection refused"

```bash
# Test connectivity
curl -I https://api.example.com

# If target is up, increase timeout
python shota3.py https://api.example.com -t 60 -p payloads.txt
```

---

### Problem 2: "SSL verification failed"

```bash
# Temporary fix (testing only!)
python shota3.py https://localhost:8443 --no-verify -p payloads.txt

# Better fix: Add cert to system trust store
sudo cp server.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

---

### Problem 3: "Rate limited / 429 Too Many Requests"

```bash
# Reduce threads and increase delay
python shota3.py https://api.com \
  --threads 5 \
  -d 2.0 \
  -p payloads.txt
```

---

### Problem 4: "No findings detected"

```bash
# Enable verbose mode
python shota3.py https://api.com -v -p payloads.txt

# Check raw JSON
cat results/shota_*.json | jq '.results[] | select(.status == 200)'

# Verify patterns are correct
grep -i "error" results/shota_*.json
```

---

### Problem 5: "Timeout on every request"

```bash
# Increase timeout dramatically
python shota3.py https://api.com -t 120 -p payloads.txt

# Enable retries
python shota3.py https://api.com --retries 10 -p payloads.txt
```

---

### Problem 6: "Memory issues / OOM"

```bash
# Enable streaming
python shota3.py https://api.com --stream -p payloads.txt

# Reduce threads
python shota3.py https://api.com --threads 5 -p payloads.txt

# Use quick mode
python shota3.py https://api.com --quick -p payloads.txt
```

---

### Problem 7: "WAF blocking all requests"

```bash
# Strategy 1: Slow down
python shota3.py https://api.com --threads 1 -d 5.0 -p payloads.txt

# Strategy 2: Use encoding
python shota3.py "https://api.com?q={{FUZZ:url2x}}" \
  --var FUZZ=@payloads.txt

# Strategy 3: Randomize user-agent
python shota3.py https://api.com \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
  -p payloads.txt
```

---

### Problem 8: "Authentication keeps failing"

```bash
# Debug auth process
python shota3.py https://api.com \
  --auth-url https://api.com/login \
  --auth-user test@example.com \
  --auth-pass password \
  --auth-token "token" \
  -v

# Check token path
# Try: "token", "data.token", "access_token", etc.

# Verify credentials work manually
curl -X POST https://api.com/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test@example.com","password":"password"}'
```

---

## 📊 Quick Reference

### Essential Commands

```bash
# Basic scan
python shota3.py <URL> -p <file>

# Fast scan
python shota3.py <URL> -p <file> --threads 20 --progress

# Stealth scan
python shota3.py <URL> -p <file> --threads 1 -d 2.0

# Fuzzing
python shota3.py "<URL>/{{VAR}}" --var VAR=1..100 -m GET

# Authenticated
python shota3.py <URL> --auth-url <LOGIN> --auth-user <USER> --auth-pass <PASS>

# WAF bypass
python shota3.py "<URL>?q={{VAR:url:base64}}" --var VAR=@payloads.txt
```

---

## 🎓 Best Practices

1. ✅ **Always get authorization** before testing
2. ✅ **Start with low threads** (1-5) and scale up
3. ✅ **Use verbose mode** (-v) for learning
4. ✅ **Review JSON results** after every scan
5. ✅ **Route through Burp** (--proxy) for inspection
6. ✅ **Save results** to version control
7. ✅ **Document findings** immediately
8. ✅ **Test incrementally** - don't blast production
9. ✅ **Respect rate limits** - use -d flag
10. ✅ **Report responsibly** - follow disclosure policies

---

## 📚 Additional Resources

- 📖 **[Main README](README.md)** - Feature overview
- 📊 **[Changelog](CHANGELOG_v3.0.md)** - v3.0 technical details
- 💬 **[GitHub Discussions](https://github.com/redzhardtekk/shota/discussions)**
- 🐛 **[Issue Tracker](https://github.com/redzhardtekk/shota/issues)**

---

<div align="center">

**Happy Ethical Hacking! 🎯🔥**

*Made with 🔥 by Redzhardtekk • Enhanced by redzXconcept*

[⬆ Back to top](#-shota-v30---complete-usage-guide)

</div>
