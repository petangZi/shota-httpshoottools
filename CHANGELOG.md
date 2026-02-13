# Changelog

All notable changes to SHOTA will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.0] - 2026-02-10

### Added - MAJOR RELEASE 🎉

#### Core Features
- 🎯 Universal HTTP request engine with all methods support (GET, POST, PUT, DELETE, PATCH, etc.)
- 🤖 Automatic payload type detection (JSON, XML, Form-data, GraphQL, Raw)
- 🎨 Beautiful ASCII art banner and color-coded CLI output
- 📊 Comprehensive JSON result logging
- ⚡ Template engine with variable substitution (`{{VAR}}`)
- 🔍 Advanced pattern detection engine

#### Advanced Capabilities
- **Variable Fuzzing:**
  - Numeric ranges: `--var ID=1..100`
  - Lists: `--var TYPE=a,b,c`
  - Wordlists: `--var PAYLOAD=@file.txt`
  - Multi-variable Cartesian expansion

- **Pattern Detection:**
  - API keys (AWS, Google, generic)
  - JWT tokens
  - Private keys (RSA, EC, DSA)
  - Email addresses
  - SQL errors (MySQL, PostgreSQL, Oracle, SQLite)
  - PHP errors and stack traces
  - Version disclosure
  - IP addresses

- **Authentication:**
  - Auto-login workflow
  - Bearer token extraction
  - Custom header support
  - Session management

- **Response Analysis:**
  - Status code categorization
  - Content-type detection
  - Body parsing (JSON, XML, HTML)
  - Response hashing for deduplication
  - Timing analysis
  - Size analysis

#### CLI Improvements
- Comprehensive argument parser with extensive options
- Ethical reminder before execution
- Progress indicators
- Summary statistics
- Colorized, structured output
- Quiet mode for automation (`-q`)
- Verbose mode for debugging (`-v`)
- Yes flag to skip confirmation (`-y`)

#### Wordlists
- `wordlists/xss.txt` - 25+ XSS payloads
- `wordlists/sqli.txt` - 35+ SQL injection vectors
- `wordlists/api-moodle.txt` - 20+ Moodle API endpoints
- `wordlists/lfi.txt` - 20+ path traversal/LFI payloads

#### Documentation
- Comprehensive README.md with badges and examples
- Detailed USAGE.md with real-world scenarios
- QUICKSTART.md for immediate setup
- LICENSE with ethical use clause
- Example payload files

### Changed
- Complete rewrite from v1.0
- Improved code organization (modular classes)
- Enhanced error handling
- Better type hints and documentation

### Security
- Built-in rate limiting (configurable delay)
- Ethical reminder on every run
- SSL verification (with toggle option)
- Timeout protection
- No destructive defaults

---

## [1.0.0] - 2026-02-10

### Added - Initial Release
- Basic HTTP POST request functionality
- Simple payload file support
- JSON response handling
- Basic error detection
- Console output
- Results JSON export

### Known Limitations (Addressed in v2.0)
- No variable support
- Limited to POST requests
- Basic pattern detection
- No authentication handling
- Limited CLI options

---

## [Unreleased]

### Planned Features
- [ ] HTML report generation
- [ ] PDF export
- [ ] Response diffing UI
- [ ] WebSocket support
- [ ] GraphQL introspection automation
- [ ] Docker container
- [ ] Batch mode for multiple targets
- [ ] Integration with CI/CD pipelines
- [ ] Plugin system for custom analyzers
- [ ] GUI version (web-based)
- [ ] Real-time collaborative testing
- [ ] Automated payload generation using ML

---

## Version Numbering

SHOTA follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version (X.0.0): Incompatible API changes
- **MINOR** version (0.X.0): Backwards-compatible new features
- **PATCH** version (0.0.X): Backwards-compatible bug fixes

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to propose changes.

---

## Upgrade Guide

### From v1.0 to v2.0

**Breaking Changes:**
- Command-line argument structure changed
- Payload file format remains compatible
- Results JSON structure enhanced (backwards incompatible)

**Migration Steps:**
1. Update to Python 3.8+ if needed
2. Install new dependencies: `pip install -r requirements.txt`
3. Review new CLI arguments: `python shota.py --help`
4. Update scripts to use new argument names
5. Test with small payload sets first

**New Capabilities You Can Use:**
- Add `--var` flags for fuzzing
- Use `-v` for verbose output
- Try built-in wordlists in `wordlists/`
- Enable auto-authentication with `--auth-*` flags

---

## Support

- **Bug Reports:** [GitHub Issues](https://github.com/redzhardtekk/shota/issues)
- **Feature Requests:** [GitHub Discussions](https://github.com/redzhardtekk/shota/discussions)
- **Security Issues:** Email security@shota.dev (PGP key available)

---

*This changelog is maintained by the SHOTA development team.*
