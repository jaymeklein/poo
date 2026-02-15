# Passive Ownership OSINT (`P.O.O`)

Passive Ownership OSINT is a **non-intrusive** command-line tool to collect public ownership and infrastructure signals for a target domain/host.

---

## What it does

The tool collects and saves:

- Domain WHOIS (`raw/whois_domain.txt`)
- Domain RDAP (`raw/rdap_domain.json`)
- DNS records for root domain and target host (`raw/dns_*.txt`)
- Resolved target IPs (`processed/target_ipv4.txt`, `processed/target_ipv6.txt`)
- WHOIS for first resolved IPv4 (`raw/whois_target_ip.txt`)
- Live TLS certificate and chain (`raw/tls_live_cert.txt`, `raw/tls_chain.txt`)
- Certificate Transparency history from crt.sh (`processed/ct_history.tsv`)
- Target HTTP headers/body (`raw/http_headers_target.txt`, `raw/http_body_target.html`)
- Legal/entity indicators extracted from page content (`processed/legal_entity_indicators.txt`)
- Wayback index data (`raw/wayback_index.json`)
- Summary report (`notes/ownership_summary.md`)
- Runtime environment metadata (`notes/environment.txt`)

---

## Requirements

- Python 3.10+
- Tools:
  - `whois`
  - `dig` (from `dnsutils`)
  - `openssl`
- Internet access for public endpoints:
  - `rdap.org`
  - `crt.sh`
  - `web.archive.org`

Install dependencies on Kali:

```bash
sudo apt update
sudo apt install -y whois dnsutils openssl
```

---

## Usage

### Show help

```bash
python3 poo.py
```

(If no arguments are passed, the tool prints banner + help page.)

### Basic run

```bash
python3 poo.py \
  --root-domain example.org \
  --target-host example.org \
  --target-url "https://app.example.org"
```

### Custom case ID and output directory

```bash
python3 poo.py \
  --root-domain example.org \
  --target-host app.example.org \
  --target-url "https://app.example.org" \
  --case-id case_manual_001 \
  --output-dir ./investigation
```

### Verbose logs (debug)

```bash
python3 poo.py \
  --root-domain example.org \
  --target-host www.example.org \
  --target-url "https://www.example.org" \
  --verbose
```

---

## CLI options

- `--root-domain` (required): Root domain (example: `example.org`)
- `--target-host` (required): Host to analyze (example: `app.example.org`)
- `--target-url` (required): URL used for HTTP header/body collection
- `--case-id` (optional): Custom case folder name
- `--output-dir` (optional): Base path where case folder is created (default: current directory)
- `--verbose` (optional): Enables debug-level logs

---

## Output structure

Each run creates:

```text
<output-dir>/<case-id>/
  raw/
    whois_domain.txt
    rdap_domain.json
    dns_root_records.txt
    dns_target_records.txt
    whois_target_ip.txt
    tls_live_cert.txt
    tls_chain.txt
    http_headers_target.txt
    http_body_target.html
    wayback_index.json
  processed/
    target_ipv4.txt
    target_ipv6.txt
    ct_history.tsv
    legal_entity_indicators.txt
  notes/
    environment.txt
    ownership_summary.md
  evidence/
```

---

## Logging behavior

The tool uses structured terminal logs with levels:

- `INFO`: Current step/action
- `SUCCESS`: Completed step
- `WARNING`: Recoverable issues (also collected in summary)
- `ERROR`: Blocking failures

Example log line:

```text
2026-02-15 14:11:08 | INFO    | Collecting RDAP for root domain
```

---

## Important limitations

- This tool performs **passive/public-source collection only**.
- It is not an exploitation scanner.
- Data quality depends on third-party source availability and accuracy.
- Some targets may block or rate-limit requests.

---

## Troubleshooting

### Missing required tools

If you see errors about missing tools:

```bash
sudo apt install -y whois dnsutils openssl
```

### Empty or partial outputs

Possible causes:

- DNS resolution failures
- Target not reachable
- External data source temporary outage (RDAP / CRT / Wayback)

Re-run with verbose logging:

```bash
python3 poo.py ... --verbose
```

### Permission problems writing files

Run in a writable directory or set a writable `--output-dir`.

---

## Legal and ethical use

Use only with explicit authorization and within legal boundaries applicable to your jurisdiction.
This project is intended for defensive investigation and incident response workflows.
