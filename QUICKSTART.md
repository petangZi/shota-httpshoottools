# 🚀 SHOTA Quick Start Guide

Get started in 60 seconds!

---

## Installation

```bash
# 1. Install Python dependencies
pip install requests

# 2. Make executable (optional, Linux/Mac only)
chmod +x shota.py

# 3. Test installation
python shota.py --help
```

---

## Test on Your Moodle Instance

### Step 1: Create Simple Payload File

```bash
cat > test.txt << 'EOF'
[{"index":0,"methodname":"tool_mobile_get_public_config","args":{}}]
[{"index":0,"methodname":"core_webservice_get_site_info","args":{}}]
[{"index":0,"methodname":"core_course_get_categories","args":{"criteria":[]}}]
EOF
```

### Step 2: Run Basic Test

```bash
python shota.py https://virtualclass.smpm12gkb.sch.id/lib/ajax/service.php \
  -p test.txt \
  -d 2
```

### Step 3: Use Pre-built Moodle Wordlist

```bash
python shota.py https://virtualclass.smpm12gkb.sch.id/lib/ajax/service.php \
  -p wordlists/api-moodle.txt \
  -d 2 \
  -v
```

---

## Test Other Targets

### Test with IDOR Fuzzing

```bash
# Create simple payload
echo '{"userid": {{ID}}}' > idor.txt

# Fuzz user IDs 1-10
python shota.py https://api.example.com/user \
  -p idor.txt \
  --var ID=1..10
```

### Test XSS

```bash
python shota.py "https://app.example.com/search?q={{XSS}}" \
  --var XSS=@wordlists/xss.txt \
  -m GET
```

### Test with Authentication

```bash
# Manual auth (paste your session cookie)
python shota.py https://api.example.com/protected \
  -H "Cookie: session=YOUR_SESSION_HERE" \
  -p test.txt
```

---

## Understanding Output

### Console Output

```
🎯 SHOT 1/3
======================================================================
📤 REQUEST:
   Method  : POST
   URL     : https://api.example.com/test
   Payload : {"test":"value"}

📥 RESPONSE:
   Status  : 200 (Success)
   Time    : 0.45s
   Size    : 1247 bytes
   Type    : application/json

🔍 FINDINGS:
   [CRITICAL] api_key: AIzaSyD...
   [MEDIUM] sql_error: mysql_fetch_array()
```

### Results File

Check `results/` directory for JSON files:

```bash
ls -lt results/

# View latest results
cat results/shota_*.json | jq '.stats'
```

---

## Common Commands Cheat Sheet

```bash
# Basic
python shota.py <URL> -p <FILE>

# With delay
python shota.py <URL> -p <FILE> -d 2

# GET request
python shota.py <URL> -p <FILE> -m GET

# With variables
python shota.py <URL> -p <FILE> --var ID=1..100

# Verbose
python shota.py <URL> -p <FILE> -v

# Quiet (automation)
python shota.py <URL> -p <FILE> -q -y

# With auth cookie
python shota.py <URL> -p <FILE> -H "Cookie: session=abc123"

# Through proxy (Burp)
python shota.py <URL> -p <FILE> --proxy http://127.0.0.1:8080
```

---

## Next Steps

1. ✅ Read full [README.md](README.md) for all features
2. ✅ Check [USAGE.md](USAGE.md) for advanced examples
3. ✅ Explore wordlists in `wordlists/` directory
4. ✅ Review results in `results/` directory
5. ✅ Join community for support

---

## Troubleshooting

### Error: "requests module not found"
```bash
pip install requests
```

### Error: "Permission denied"
```bash
chmod +x shota.py
# OR just use: python shota.py
```

### Error: "Payload file not found"
```bash
# Make sure file exists
ls -la payloads.txt

# Or specify full path
python shota.py <URL> -p /full/path/to/payloads.txt
```

---

## Safety Reminders

⚠️ **Before running SHOTA:**

1. ✅ Do you have **permission** to test this system?
2. ✅ Is this a **test/dev environment** (not production)?
3. ✅ Have you set an appropriate **delay** (`-d` flag)?
4. ✅ Are you **documenting** your findings?

---

**Ready to hack (ethically)? 🎯🔥**

For help: `python shota.py --help`
