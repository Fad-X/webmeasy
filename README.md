# webmeasy

A fast web application enumeration tool written in Rust for mapping external attack surfaces.

## Features

- **Subdomain Enumeration** — Powered by `subfinder` (passive: CT logs, search engines, DNS datasets, APIs)
- **HTTP Probing** — `httpx` integration for protocol detection, status codes, titles, and web technologies
- **Nuclei Integration** — Template-based vulnerability scanning across discovered assets
- **Backup & Config Fuzzing** — Discovers exposed backup files, configuration artifacts, and sensitive data
- **Git Exposure Detection** — Identifies exposed `.git` / `.svn` directories and source code leaks
- **Professional PDF Reports** — Clean, sorted A4 PDF output for reporting
- **Dependency Auto-Install** — Automatically installs `subfinder`, `httpx`, and `nuclei` if missing
- **JSON Export** — Structured JSON output for further processing

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing & tech detection | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Vulnerability scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| [Go](https://go.dev/dl/) | For installing the above | — |

> **Tip:** Run `webmeasy --install-deps` to install all missing tools automatically.

## Build from source

```bash
cargo build --release
```

Binary at `target/release/webmeasy`

## Usage

### Full scan with PDF report

```bash
webmeasy -d example.com --all --pdf report.pdf -o report.json
```

### Subdomains + live host probing

```bash
webmeasy -d example.com -s -p
```

### Subdomains + Nuclei scan + PDF output

```bash
webmeasy -d example.com -s -n --pdf findings.pdf
```

### Backup file fuzzing + .git check

```bash
webmeasy -d example.com -f -g --pdf report.pdf
```

### Install dependencies

```bash
webmeasy --install-deps
```

## Command Line Options

| Flag | Long | Description |
|------|------|-------------|
| `-d` | `--domain` | Target domain to enumerate |
| `-s` | `--subdomains` | Subdomain enumeration via subfinder |
| `-p` | `--probe` | Probe live hosts with httpx (protocol, status, tech) |
| `-n` | `--nuclei` | Run Nuclei vulnerability scan |
| `-f` | `--fuzz` | Fuzz for backup files and configurations |
| `-g` | `--git` | Check for exposed .git / .svn directories |
| `-a` | `--all` | Run all modules |
| `-w` | `--wordlist` | Custom wordlist for subfinder / fuzzer |
| `-o` | `--output` | JSON report output path |
| | `--pdf` | PDF report output path |
| | `--nuclei-templates` | Custom Nuclei templates directory |
| | `--install-deps` | Install missing tools (subfinder, httpx, nuclei) |

## Modules

### Subdomain Enumeration (`subfinder`)

Uses subfinder for passive enumeration from:
- Certificate Transparency logs
- Search engines (Google, Bing, DuckDuckGo, etc.)
- DNS datasets and threat intelligence feeds
- 80+ sources with recursive discovery

### HTTP Probing (`httpx`)

Probes every discovered host to determine:
- Protocol (HTTP/HTTPS)
- Status code and redirect chain
- Page title
- Web server software
- Web technology stack (CMS, frameworks, CDNs)

### Nuclei Vulnerability Scanning

Template-based scanning for:
- CVEs and known vulnerabilities
- Misconfigurations and security headers
- Technology-specific exposures
- Default credentials

### Backup & Config Fuzzing

Checks 400+ paths for:
- Environment files (`.env`, `.env.local`, `.env.production`)
- Database dumps (`.sql`, `.sqlite`, `.db`)
- Archives (`.zip`, `.tar.gz`, `.rar`, `.7z`)
- Config files (`wp-config.php`, `web.config`, `config.json`)
- Backup extensions (`.bak`, `.old`, `.backup`, `~`)
- Certificates/keys (`.pem`, `.key`, `.crt`)
- Admin panels (phpMyAdmin, Adminer, server-status)

### Git Exposure Detection

Probes 21 paths over both HTTP/HTTPS:
- `.git/HEAD`, `.git/config`, `.git/index`
- `.git/logs/`, `.git/refs/`, `.git/objects/`, `.git/hooks/`
- `.gitignore`, `.gitmodules`, `.svn/entries`
- Content validation to avoid false positives
- Severity classification (CRITICAL for config with remotes)

## Reports

### PDF Report (`--pdf report.pdf`)

Professional A4 PDF with:
- Cover page with target and date
- Executive summary with finding counts
- Live hosts with technologies (sorted)
- Full subdomain list (sorted)
- Nuclei findings sorted by severity
- Backup/config findings (sorted by URL)
- Git exposures sorted by severity

### JSON Report (`-o report.json`)

Machine-readable export with all findings and summary statistics.

## Output Example

```
[*] Starting subdomain enumeration...
    [~] Running subfinder (CT logs, search engines, DNS datasets, APIs)...
    [+] subfinder returned 127 subdomains

[*] Probing live hosts with httpx...
    [+] httpx found 43 live hosts
    https://www.example.com [200] Example Domain | Cloudflare, HTTP/3
    https://api.example.com [200] API Gateway | Nginx, Express.js
    https://admin.example.com [403] Admin Panel | Apache

[*] Running Nuclei vulnerability scan...
    [+] 12 findings across 43 hosts

[+] PDF report saved to: report.pdf
[+] JSON report saved to: report.json
```

## License

MIT
