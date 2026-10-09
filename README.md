# webmeasy

A fast web application enumeration tool written in Rust for mapping external attack surfaces.

## Features

- **Subdomain Enumeration**: Uses subfinder for passive subdomain discovery with active DNS brute-force fallback
- **Nuclei Integration**: Template-based vulnerability scanning across discovered assets
- **Backup & Config Fuzzing**: Discovers exposed backup files, configuration artifacts, and sensitive data
- **Git Exposure Detection**: Identifies exposed `.git` directories and source code leaks
- **Beautiful Output**: Color-coded terminal output with progress bars
- **JSON Reports**: Export detailed findings in JSON format

## Installation

### Prerequisites

- Rust 1.70+
- [subfinder](https://github.com/projectdiscovery/subfinder) - For subdomain enumeration
- [nuclei](https://github.com/projectdiscovery/nuclei) - For vulnerability scanning (optional)

### Build from source

```bash
cargo build --release
```

The binary will be at `target/release/webmeasy`

## Usage

### Run all scans
```bash
webmeasy -d example.com --all
```

### Subdomain enumeration only
```bash
webmeasy -d example.com -s
```

### Run with Nuclei vulnerability scan
```bash
webmeasy -d example.com -s -n
```

### Fuzz for backup files
```bash
webmeasy -d example.com -f
```

### Check for exposed .git
```bash
webmeasy -d example.com -g
```

### Full scan with custom wordlist and output
```bash
webmeasy -d example.com --all -w /path/to/wordlist.txt -o report.json
```

## Command Line Options

| Option | Long | Description |
|--------|------|-------------|
| `-d` | `--domain` | Target domain to enumerate |
| `-s` | `--subdomains` | Enable subdomain enumeration |
| `-n` | `--nuclei` | Run Nuclei vulnerability scan |
| `-f` | `--fuzz` | Fuzz for backup files and configurations |
| `-g` | `--git` | Check for exposed .git directories |
| `-a` | `--all` | Run all enumeration modules |
| `-w` | `--wordlist` | Custom wordlist path |
| `-o` | `--output` | Output file path (JSON format) |
| | `--nuclei-templates` | Custom Nuclei templates directory |

## Modules

### Subdomain Enumeration

Uses subfinder for passive enumeration from multiple sources:
- Certificate Transparency logs
- Search engines
- DNS datasets
- Various APIs

Falls back to active DNS brute-force with built-in wordlist.

### Nuclei Vulnerability Scanning

Integrates with Nuclei for template-based scanning:
- CVE detection
- Misconfiguration detection
- Exposure detection
- Technology fingerprinting
- Default credentials

### Backup & Config Fuzzing

Checks for:
- Environment files (.env, .env.local, etc.)
- Database dumps (.sql, .sqlite, .db)
- Archive files (.zip, .tar.gz, .rar)
- Configuration files (wp-config.php, web.config, etc.)
- Backup files (.bak, .old, .backup)
- Certificate and key files (.pem, .key, .crt)
- Log and debug files
- Admin panels (phpMyAdmin, Adminer, etc.)

### Git Exposure Detection

Checks for:
- `.git/HEAD` - Git reference
- `.git/config` - Git configuration (may contain credentials)
- `.git/index` - Git index file
- `.git/logs/` - Git logs
- `.git/refs/` - Git references
- `.git/objects/` - Git objects (source code)
- `.git/hooks/` - Git hooks
- `.svn/` - SVN exposure
- `.gitignore`, `.gitmodules`

## Output

### Terminal Output

Colored, structured output showing:
- Progress bars for each scan phase
- Summary statistics
- Detailed findings with severity levels

### JSON Report

When using `-o`, generates a JSON report with:
- All discovered subdomains
- Nuclei vulnerability findings
- Fuzzing results
- Git exposure findings
- Summary statistics

## Wordlists

Built-in wordlists included:
- `wordlists/subdomains.txt` - Common subdomain names (500+ entries)
- `wordlists/backups.txt` - Backup and configuration file paths (200+ entries)

Custom wordlists can be specified with `-w` flag.

## Examples

### Quick subdomain scan
```bash
webmeasy -d example.com -s
```

### Security assessment
```bash
webmeasy -d example.com --all -o assessment.json
```

### Scan with custom Nuclei templates
```bash
webmeasy -d example.com -n --nuclei-templates /path/to/templates
```

## License

MIT