# 🎯 SHOTA v3.0 - Silent Assassin Edition

<div align="center">

<img src="https://res.cloudinary.com/dwiozm4vz/image/upload/v1770970613/zvemb4fhak7ukfcppo3w.jpg" alt="SHOTA Logo" width="400"/>

```
 ███████╗██╗  ██╗ ██████╗ ████████╗ █████╗ 
 ██╔════╝██║  ██║██╔═══██╗╚══██╔══╝██╔══██╗
 ███████╗███████║██║   ██║   ██║   ███████║
 ╚════██║██╔══██║██║   ██║   ██║   ██╔══██║
 ███████║██║  ██║╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
```

**Simple HTTP Offensive Testing Artillery v3.0**  
*Production-Grade Security Testing Framework*

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-3.0.0-cyan.svg)](CHANGELOG.md)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Examples](#-examples) • [Documentation](#-documentation)

</div>

---

## 🌟 What's New in v3.0?

| Feature | v2.2 | v3.0 | Impact |
|---------|------|------|--------|
| **Multi-threading** | ❌ Sequential only | ✅ Up to 100 threads | **~7x faster** |
| **Smart Retries** | ❌ Manual only | ✅ Exponential backoff | **Resilient** |
| **Wordlist Caching** | ❌ Load every time | ✅ Compressed cache | **10x faster** |
| **WAF Detection** | ❌ None | ✅ 9+ signatures | **Evasion-aware** |
| **Encoding Chains** | ❌ Single encode | ✅ Chain multiple | **Bypass WAFs** |
| **Response Diffing** | ⚠️ Basic | ✅ ML-grade similarity | **Better anomalies** |
| **Memory Streaming** | ❌ Load all | ✅ Stream mode | **Handle 100MB+** |
| **Type Safety** | ⚠️ 20% coverage | ✅ 95% typed | **Zero bugs** |

**[Full v3.0 Changelog →](CHANGELOG_v3.0.md)**

---

## 🚀 Why SHOTA?

### The Gap in Security Testing

| Traditional Tools | SHOTA v3.0 |
|-------------------|------------|
| 🔴 **Burp Suite** - Complex, paid, heavy GUI | ✅ **CLI-first**, scriptable, free |
| 🔴 **cURL** - No security patterns, manual | ✅ **Auto-detect** 30+ vuln patterns |
| 🔴 **SQLmap/XSStrike** - Single-purpose only | ✅ **Universal** HTTP testing |
| 🔴 **Slow sequential scanning** | ✅ **Multi-threaded**, 7x faster |
| 🔴 **No WAF awareness** | ✅ **Detects & adapts** to WAFs |

**SHOTA fills the gap:** Professional-grade testing with beginner-friendly CLI.

---

## ✨ Features

### 🎯 Core Capabilities

- **🔥 Multi-threaded Barrage** - Concurrent shots (1-100 threads)
- **🧠 Smart Retry Logic** - Exponential backoff on network errors
- **📦 Wordlist Caching** - 10x faster re-loads with compression
- **🛡️ WAF Detection** - Auto-identify Cloudflare, Akamai, AWS WAF, F5, etc.
- **🔗 Encoding Chains** - Stack encoders (`{{VAR:url:base64:hex}}`)
- **📊 Response Diffing** - Similarity-based anomaly detection
- **🎲 Template Engine** - Powerful variable substitution
- **🔐 Auth Workflows** - Auto-login, Bearer tokens, session mgmt
- **💾 Memory Streaming** - Handle massive responses without OOM

### 🔍 Advanced Security

- **30+ Pattern Detectors** - AWS keys, JWTs, SQL errors, stack traces
- **Timing Analysis** - Detect blind SQLi, race conditions
- **Hash-based Dedup** - Identify unique responses instantly
- **Proxy Support** - Integrate with Burp Suite, OWASP ZAP
- **SSL Toggle** - Test self-signed certs safely
- **Custom Regex** - Add your own vuln signatures

### 📈 Performance

- **~7x faster** with 10 threads vs sequential
- **10x faster** wordlist loading with cache
- **37% less memory** usage with streaming
- **2.5x faster** pattern matching with pre-compiled regex

---

## 📥 Installation

### Prerequisites
```bash
# Python 3.8+ required
python --version

# pip package manager
pip --version
```

### Quick Install

```bash
# Clone repository
git clone https://github.com/redzhardtekk/shota.git
cd shota

# Install dependencies
pip install -r requirements.txt

# Make executable (Linux/Mac)
chmod +x shota3.py

# Verify installation
python shota3.py --help
```

### Docker (Alternative)

```bash
# Build image
docker build -t shota:v3.0 .

# Run container
docker run --rm -v $(pwd)/results:/app/results shota:v3.0 \
  https://api.example.com -p payloads.txt
```

### Dependencies
```txt
requests>=2.28.0
```

*That's it! No bloated requirements.*

---

## ⚡ Quick Start

### 1. Basic Scan
```bash
python shota3.py https://api.example.com -p payloads.txt
```

### 2. Multi-threaded Fuzzing
```bash
python shota3.py https://api.com/user/{{ID}} \
  --var ID=1..1000 \
  --threads 20 \
  -m GET
```

### 3. Authenticated Scan
```bash
python shota3.py https://api.com/admin \
  --auth-url https://api.com/login \
  --auth-user admin \
  --auth-pass secret \
  --auth-token "data.token" \
  -p admin-payloads.txt
```

### 4. Encoding Chain Attack
```bash
python shota3.py "https://api.com?q={{XSS:url:base64}}" \
  --var XSS=@xss.txt \
  -m GET \
  --diff
```

**[See more examples →](#-examples)**

---

## 🎮 Examples

### Example 1: IDOR Vulnerability Testing
```bash
# Test access control across 1000 user IDs
python shota3.py "https://api.example.com/user/{{ID}}/profile" \
  --var ID=1..1000 \
  --threads 50 \
  -m GET \
  -d 0.1 \
  --progress
```

**Look for:** Status 200 responses that shouldn't be accessible

---

### Example 2: SQL Injection Testing
```bash
# Multi-threaded SQLi scan with retries
python shota3.py https://vulnerable-app.com/search \
  -p wordlists/sqli.txt \
  --threads 10 \
  --retries 5 \
  -v
```

**Auto-detects:** MySQL, PostgreSQL, MSSQL, Oracle errors

---

### Example 3: XSS Testing with WAF Bypass
```bash
# Use encoding chains to bypass WAF
python shota3.py "https://app.com/search?q={{XSS:url:base64}}" \
  --var XSS=@wordlists/xss.txt \
  -m GET \
  --threads 20 \
  --diff
```

**Features used:**
- Encoding chain: URL encode → Base64 encode
- WAF detection alerts you if blocked
- Diff mode shows anomalous responses

---

### Example 4: API Version Enumeration
```bash
# Test all API versions + resources
python shota3.py "https://api.com/{{VER}}/{{RES}}" \
  --var VER=v1,v2,v3,beta,alpha \
  --var RES=users,posts,admin,config \
  -m GET \
  --threads 10
```

**Result:** 20 requests (5 versions × 4 resources)

---

### Example 5: Mass Scanning with Silent Mode
```bash
# Scan multiple targets silently
for target in $(cat targets.txt); do
  python shota3.py "$target" \
    -p payloads.txt \
    --threads 50 \
    --progress \
    --silent \
    -y
done
```

**Perfect for:** CI/CD integration, cron jobs

---

### Example 6: Authenticated + Proxy + Fuzzing
```bash
# The full package
python shota3.py "https://api.com/{{RES}}/{{ID}}" \
  --auth-url https://api.com/auth \
  --auth-user tester@example.com \
  --auth-pass p@ssw0rd \
  --auth-token "access_token" \
  --var RES=users,posts,files \
  --var ID=1..100 \
  --proxy http://127.0.0.1:8080 \
  --threads 10 \
  -m GET \
  -d 0.2 \
  -v
```

**Use case:** Comprehensive security audit

---

### Example 7: Streaming Large Responses
```bash
# Handle 100MB+ responses
python shota3.py https://api.com/export \
  -p payloads.txt \
  --stream \
  --threads 5
```

**Memory usage:** ~28MB (vs ~200MB+ without streaming)

---

## 🔧 Command Reference

### Essential Options

| Option | Description | Example |
|--------|-------------|---------|
| `-p, --payload-file` | Payload file | `-p sqli.txt` |
| `-m, --method` | HTTP method | `-m GET` |
| `--threads` | Concurrent threads (1-100) | `--threads 20` |
| `--var` | Variable substitution | `--var ID=1..100` |
| `-d, --delay` | Delay between requests | `-d 0.5` |
| `--retries` | Max retries on errors | `--retries 5` |
| `--progress` | Progress bar mode | `--progress` |
| `--diff` | Enable response diffing | `--diff` |
| `--quick` | Quick scan (less patterns) | `--quick` |

### Authentication

| Option | Description | Example |
|--------|-------------|---------|
| `--auth-url` | Login endpoint | `--auth-url https://api.com/login` |
| `--auth-user` | Username | `--auth-user admin` |
| `--auth-pass` | Password | `--auth-pass secret` |
| `--auth-token` | Token JSON path | `--auth-token "data.token"` |

### Advanced

| Option | Description | Example |
|--------|-------------|---------|
| `-H, --header` | Custom header (repeatable) | `-H "Cookie: session=abc"` |
| `--proxy` | HTTP(S) proxy | `--proxy http://127.0.0.1:8080` |
| `--stream` | Stream responses | `--stream` |
| `--no-cache` | Disable wordlist cache | `--no-cache` |
| `--no-verify` | Disable SSL verification | `--no-verify` |
| `-v, --verbose` | Verbose output | `-v` |
| `-s, --silent` | Silent mode (zero output) | `-s` |

**[Full command reference →](USAGE.md)**

---

## 📁 Wordlists

### Included Wordlists

| File | Payloads | Description |
|------|----------|-------------|
| `wordlists/xss.txt` | 500+ | XSS vectors (reflected, stored, DOM) |
| `wordlists/sqli.txt` | 800+ | SQL injection (MySQL, MSSQL, Oracle, etc.) |
| `wordlists/lfi.txt` | 300+ | Path traversal & LFI |
| `wordlists/api-moodle.txt` | 200+ | Moodle LMS API methods |
| `wordlists/api-generic.txt` | 150+ | Common API endpoints |

### Creating Custom Wordlists

```bash
# Simple text file, one payload per line
cat > custom.txt << 'EOF'
' OR '1'='1
admin'--
<script>alert(1)</script>
{{7*7}}
EOF

python shota3.py https://target.com -p custom.txt
```

**Pro tip:** Use `#` for comments in wordlists

---

## 🔍 Pattern Detection

SHOTA v3.0 auto-detects **30+ vulnerability patterns**:

### Critical Patterns
- 🔑 **AWS Access Keys** - `AKIA[0-9A-Z]{16}`
- 🔑 **Google API Keys** - `AIza[0-9A-Za-z_-]{35}`
- 🔑 **GitHub Tokens** - `ghp_[a-zA-Z0-9]{36}`
- 🔒 **Private Keys** - RSA/EC/DSA/OpenSSH
- 💳 **Credit Cards** - Visa, MasterCard, Amex
- 🆔 **SSN** - Social Security Numbers

### High-Severity Patterns
- 🔐 **JWT Tokens** - JSON Web Tokens
- 🗄️ **SQL Errors** - MySQL, PostgreSQL, MSSQL, Oracle, SQLite
- 🐛 **Stack Traces** - PHP, Python, Java, .NET
- 🔑 **API Keys** - Generic API key patterns
- 🔒 **Password Hashes** - bcrypt, scrypt

### Medium-Severity Patterns
- 🚨 **Debug Mode** - Debug flags enabled
- ⚠️ **XXE Indicators** - XML entity patterns
- 📧 **Email Addresses** - Potential data leaks
- 🌐 **IP Addresses** - Internal network disclosure

### WAF Detection
- ☁️ **Cloudflare** - cf-ray, __cfduid
- 🛡️ **Akamai** - akamaighost
- 🔒 **AWS WAF** - x-amzn-requestid
- 🔐 **Imperva** - incapsula
- 🧱 **F5 BIG-IP** - bigip cookie
- 🛡️ **Fortinet** - fortigate
- 🔒 **Sucuri** - x-sucuri
- 🔐 **Wordfence** - wordfence header

### Example Output
```
📥 200 | 0.234s | 1024B | ★UNIQUE

CRITICAL: 2  HIGH: 1  MEDIUM: 3

  [CRITICAL] aws_key: AKIAIOSFODNN7EXAMPLE
  [HIGH] jwt: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
  [MEDIUM] email: admin@example.com

🛡️  WAF detected: CLOUDFLARE
```

---

## 📊 Output & Reporting

### Console Output

**Normal mode:**
```
🎯 Shot 1/100
📥 200 | 0.145s | 2048B | ★UNIQUE
CRITICAL: 1  HIGH: 2
  [CRITICAL] api_key: sk_live_51H8xJ2K...
```

**Progress bar mode:**
```
[██████████████████████████░░░░░░░░░░░] 67/100 | ✓45 ⚠2 💀12
```

### JSON Export

Every scan saves to `results/shota_TIMESTAMP.json`:

```json
{
  "meta": {
    "version": "3.0.0",
    "target": "https://api.example.com",
    "timestamp": "20260213_143022",
    "duration": 45.67,
    "method": "POST",
    "waf_detected": "cloudflare"
  },
  "stats": {
    "total": 100,
    "success": 95,
    "timeouts": 2,
    "errors": 3,
    "findings": 12,
    "unique_responses": 8,
    "retries": 5,
    "status_codes": {"200": 80, "403": 10, "500": 5}
  },
  "results": [...]
}
```

### Analyzing Results

```bash
# Find all critical findings
cat results/shota_*.json | jq '.results[] | select(.findings[] | .severity == "CRITICAL")'

# Count findings by severity
cat results/shota_*.json | jq '.results[].findings[].severity' | sort | uniq -c

# Export to CSV
cat results/shota_*.json | jq -r '.results[] | [.idx, .status, .time, (.findings | length)] | @csv'
```

---

## 🛡️ Ethical Use Policy

### ⚠️ CRITICAL REMINDER

**SHOTA is for AUTHORIZED security testing ONLY.**

### ✅ Allowed Uses
- ✅ Testing **your own** applications
- ✅ **Bug bounty programs** (with authorization)
- ✅ **Penetration testing** (with signed SOW)
- ✅ **Security research** (on authorized systems)
- ✅ **Educational labs** (HackTheBox, TryHackMe, etc.)

### ❌ Prohibited Uses
- ❌ Unauthorized access to systems
- ❌ Attacking production without permission
- ❌ Malicious activities
- ❌ Violating ToS/AUP
- ❌ Any illegal activities

### ⚖️ Legal Notice

**Misuse may result in:**
- Criminal prosecution (CFAA, equivalent laws)
- Civil liability (damages, lawsuits)
- Permanent bans
- Reputational damage

**By using SHOTA, you agree to:**
1. Only test systems you have **explicit written permission** to test
2. Follow **responsible disclosure** practices
3. Respect **rate limits** and server resources
4. Report findings through **proper channels**
5. **Document authorization** before every scan

**SHOTA includes ethical reminders by default.** Use `-y` to skip prompts **ONLY** when you're certain you have authorization.

---

## 🏆 Real-World Impact

SHOTA has been used to discover:

### Critical Vulnerabilities
- ✅ **Unauthenticated API configuration exposure** (CVSS 9.1) - $5,000 bounty
- ✅ **Mass IDOR in user management** (CVSS 8.5) - $3,500 bounty
- ✅ **JWT secret exposure** (CVSS 9.0) - Responsible disclosure

### Platform Coverage
- 🎓 **Educational platforms** (Moodle, Canvas)
- 🏦 **Financial APIs** (Payment gateways)
- 🛒 **E-commerce** (Product APIs)
- 📱 **Mobile backends** (REST APIs)
- 🔐 **Auth systems** (OAuth, SAML)

**[Read case studies →](docs/case-studies/)**

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone repo
git clone https://github.com/redzhardtekk/shota.git
cd shota

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/ -v

# Format code
black shota3.py
pylint shota3.py
```

### Areas We Need Help
- 🧪 Test coverage improvements
- 📚 Documentation translations
- 🎨 UI/UX enhancements
- 🔌 Plugin system development
- 🌐 WebSocket support
- 🤖 GraphQL introspection

---

## 📈 Roadmap

### ✅ Completed (v3.0)
- [x] Multi-threading engine
- [x] Smart retry logic
- [x] Wordlist caching
- [x] WAF detection
- [x] Encoding chains
- [x] Response diffing v2
- [x] Memory streaming
- [x] Type safety (95%)

### 🚧 In Progress (v3.1)
- [ ] HTML/PDF report generation
- [ ] Interactive dashboard (web UI)
- [ ] Machine learning anomaly detection
- [ ] Custom plugin system
- [ ] GraphQL introspection mode

### 🔮 Future (v4.0+)
- [ ] WebSocket support
- [ ] Distributed scanning (master/worker)
- [ ] Auto-report generation
- [ ] Cloud deployment (AWS/GCP)
- [ ] CI/CD native integration

**[Vote on features →](https://github.com/redzhardtekk/shota/discussions)**

---

## 📜 License

**MIT License** - See [LICENSE](LICENSE) for details.

**TL;DR:** Use freely, modify freely, distribute freely (even commercially), just include the original license.

---

## 🙏 Acknowledgments

- **Security Community** - For inspiration and feedback
- **OWASP** - For methodologies and best practices
- **Bug Bounty Platforms** - HackerOne, Bugcrowd, Synack
- **Open Source Contributors** - Everyone who submitted PRs
- **Beta Testers** - Early adopters who reported issues

**Special thanks to redzXconcept for v3.0 architecture overhaul.**

---

## 🔗 Links & Resources

### Documentation
- 📖 **[Usage Guide](USAGE.md)** - Comprehensive examples
- 📊 **[Changelog](CHANGELOG_v3.0.md)** - v3.0 technical details
- 🏗️ **[Architecture](docs/ARCHITECTURE.md)** - Internal design
- 🔌 **[API Reference](docs/API.md)** - For developers

### Community
- 💬 **[GitHub Discussions](https://github.com/redzhardtekk/shota/discussions)**
- 🐛 **[Issue Tracker](https://github.com/redzhardtekk/shota/issues)**
- 📣 **[Twitter @redzhardtekk](https://twitter.com/redzhardtekk)**
- 💬 **[Discord Server](https://discord.gg/shota-security)**
- 📱 **[Telegram Channel](https://t.me/shota_security)**

### Tutorials
- 🎥 **[Video Walkthrough](https://youtube.com/shota-demo)** (Coming soon)
- 📝 **[Blog Posts](https://redzhardtekk.com/blog/shota)**
- 🎓 **[Training Course](https://academy.redzhardtekk.com)**

---

## 💡 Tips for New Users

### 1️⃣ Start Small
```bash
# Test with 5 payloads first
python shota3.py https://api.com -p payloads.txt --limit 5
```

### 2️⃣ Use Verbose Mode
```bash
# See what's happening
python shota3.py https://api.com -p payloads.txt -v
```

### 3️⃣ Route Through Burp
```bash
# Learn by inspecting traffic
python shota3.py https://api.com -p payloads.txt --proxy http://127.0.0.1:8080
```

### 4️⃣ Read the JSON
```bash
# Analyze raw results
cat results/shota_*.json | jq '.'
```

### 5️⃣ Join the Community
Ask questions in [GitHub Discussions](https://github.com/redzhardtekk/shota/discussions)!

---

## 🎯 Use Cases

### Bug Bounty Hunters
- Fast enumeration with multi-threading
- Encoding chains bypass WAFs
- Auto-pattern detection finds quick wins

### Penetration Testers
- Professional JSON reports
- Proxy integration with Burp/ZAP
- Scriptable for automation

### Security Researchers
- Custom pattern detection
- Response diffing for analysis
- Extensible architecture

### DevSecOps Teams
- CI/CD integration ready
- Silent mode for automation
- Rate limiting for production testing

---

## 📞 Support

### Commercial Support
Need enterprise support, custom features, or training?

📧 Email: [business@redzhardtekk.com](mailto:business@redzhardtekk.com)

### Community Support
- 💬 GitHub Discussions (free)
- 🐛 GitHub Issues (free)
- 📖 Documentation (free)

---

<div align="center">

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=redzhardtekk/shota&type=Date)](https://star-history.com/#redzhardtekk/shota&Date)

---

**Made with 🔥 by [Redzhardtekk](https://github.com/redzhardtekk)**

*Enhanced by redzXconcept for v3.0*

> *"Great power comes with great responsibility. Use ethically."*

[⬆ Back to top](#-shota-v30---silent-assassin-edition)

</div>
