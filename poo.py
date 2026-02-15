import argparse
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib import error, request

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
LEGAL_INDICATOR_PATTERN = re.compile(
    r"cnpj|cpf|raz[aã]o social|empresa|endere[cç]o|telefone|email|respons[aá]vel|termos|privacidade",
    re.IGNORECASE,
)

BANNER = r"""
██████╗   ██████╗   ██████╗
██╔══██╗ ██╔═══██╗ ██╔═══██╗
██████╔╝ ██║   ██║ ██║   ██║
██╔═══╝  ██║   ██║ ██║   ██║
██║      ╚██████╔╝ ╚██████╔╝
╚═╝       ╚═════╝   ╚═════╝
           P.O.O
Passive Ownership OSINT
""".strip("\n")

SUCCESS_LEVEL = 25
logging.addLevelName(SUCCESS_LEVEL, "SUCCESS")


def _success(self: logging.Logger, message: str, *args, **kwargs) -> None:
    if self.isEnabledFor(SUCCESS_LEVEL):
        self._log(SUCCESS_LEVEL, message, args, **kwargs)


if not hasattr(logging.Logger, "success"):
    setattr(logging.Logger, "success", _success)

LOGGER = logging.getLogger("poo")


def setup_logging(verbose: bool) -> None:
    LOGGER.setLevel(logging.DEBUG if verbose else logging.INFO)
    LOGGER.handlers.clear()
    LOGGER.propagate = False

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s", "%Y-%m-%d %H:%M:%S"))
    LOGGER.addHandler(handler)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def default_case_id() -> str:
    return f"case_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def append_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(content)


def run_cmd(cmd: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def fetch_url(url: str) -> tuple[int | None, dict[str, str], str, str | None]:
    req = request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with request.urlopen(req, timeout=45) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            headers = {k: v for k, v in resp.headers.items()}
            return resp.status, headers, body, None
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        headers = {k: v for k, v in exc.headers.items()}
        return exc.code, headers, body, f"HTTPError: {exc}"
    except Exception as exc:
        return None, {}, "", str(exc)


def fetch_json(url: str) -> tuple[object | None, str | None]:
    status, _, body, err = fetch_url(url)
    if err and status is None:
        return None, err
    try:
        return json.loads(body), None
    except Exception as exc:
        return None, f"JSON parse error: {exc}"


def require_tools(tools: Iterable[str]) -> list[str]:
    missing: list[str] = []
    for tool in tools:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def collect_whois(target: str, output: Path) -> str | None:
    code, out, err = run_cmd(["whois", target])
    write_text(output, out + ("\n" + err if err else ""))
    if code != 0:
        return f"whois returned non-zero ({code}) for {target}"
    return None


def collect_dig(name: str, record_types: list[str], output: Path) -> list[str]:
    warnings: list[str] = []
    all_lines: list[str] = []
    for record_type in record_types:
        code, out, err = run_cmd(["dig", "+nocmd", name, record_type, "+noall", "+answer"])
        all_lines.append(f"# {name} {record_type}\n{out.strip()}\n")
        if code != 0:
            warnings.append(f"dig failed for {name} {record_type} (exit {code})")
        if err.strip():
            all_lines.append(f"# STDERR\n{err.strip()}\n")
    write_text(output, "\n".join(all_lines).strip() + "\n")
    return warnings


def collect_short_dns(name: str, rrtype: str, output: Path) -> list[str]:
    code, out, err = run_cmd(["dig", "+short", rrtype, name])
    values = [line.strip() for line in out.splitlines() if line.strip()]
    write_text(output, "\n".join(values) + ("\n" if values else ""))
    warnings: list[str] = []
    if code != 0:
        warnings.append(f"dig +short {rrtype} failed for {name} (exit {code})")
    if err.strip():
        append_text(output, "\n# STDERR\n" + err + "\n")
    return values


def collect_tls_cert(target_host: str, output: Path) -> str | None:
    first = subprocess.run(
        ["openssl", "s_client", "-connect", f"{target_host}:443", "-servername", target_host],
        input="\n",
        capture_output=True,
        text=True,
    )
    second = subprocess.run(
        [
            "openssl",
            "x509",
            "-noout",
            "-subject",
            "-issuer",
            "-dates",
            "-serial",
            "-fingerprint",
            "-sha256",
            "-ext",
            "subjectAltName",
        ],
        input=first.stdout,
        capture_output=True,
        text=True,
    )
    content = second.stdout
    if second.stderr.strip():
        content += "\n# STDERR\n" + second.stderr
    write_text(output, content)
    if second.returncode != 0:
        return f"openssl x509 parse failed for {target_host} (exit {second.returncode})"
    return None


def collect_tls_chain(target_host: str, output: Path) -> str | None:
    proc = subprocess.run(
        ["openssl", "s_client", "-connect", f"{target_host}:443", "-servername", target_host, "-showcerts"],
        input="\n",
        capture_output=True,
        text=True,
    )
    content = proc.stdout
    if proc.stderr.strip():
        content += "\n# STDERR\n" + proc.stderr
    write_text(output, content)
    if proc.returncode != 0:
        return f"openssl s_client chain failed for {target_host} (exit {proc.returncode})"
    return None


def collect_ct_history(root_domain: str, output: Path) -> str | None:
    data, err = fetch_json(f"https://crt.sh/?q=%25.{root_domain}&output=json")
    if err:
        write_text(output, "")
        return f"crt.sh query failed: {err}"
    rows = []
    if isinstance(data, list):
        seen = set()
        for row in data:
            if not isinstance(row, dict):
                continue
            issuer = str(row.get("issuer_name", ""))
            common_name = str(row.get("common_name", ""))
            name_value = str(row.get("name_value", "")).replace("\n", ",")
            not_before = str(row.get("not_before", ""))
            not_after = str(row.get("not_after", ""))
            key = (issuer, common_name, name_value, not_before, not_after)
            if key in seen:
                continue
            seen.add(key)
            rows.append("\t".join(key))
    rows.sort()
    write_text(output, "\n".join(rows) + ("\n" if rows else ""))
    return None


def build_summary(
    notes_path: Path,
    root_domain: str,
    target_host: str,
    target_url: str,
    warnings: list[str],
) -> None:
    lines = [
        "# Ownership Summary",
        "",
        f"- Generated (UTC): {utc_now()}",
        f"- Root domain: {root_domain}",
        f"- Target host: {target_host}",
        f"- Target URL: {target_url}",
        "",
        "## Evidence Files",
        "- raw/whois_domain.txt",
        "- raw/rdap_domain.json",
        "- raw/dns_root_records.txt",
        "- raw/dns_target_records.txt",
        "- processed/target_ipv4.txt",
        "- processed/target_ipv6.txt",
        "- raw/whois_target_ip.txt",
        "- raw/tls_live_cert.txt",
        "- raw/tls_chain.txt",
        "- processed/ct_history.tsv",
        "- raw/http_headers_target.txt",
        "- raw/http_body_target.html",
        "- processed/legal_entity_indicators.txt",
        "- raw/wayback_index.json",
        "",
        "## Attribution Notes",
        "- Fill registrar/abuse contact from raw/whois_domain.txt.",
        "- Fill hosting provider/ASN from raw/whois_target_ip.txt.",
        "- Fill TLS relationships from raw/tls_live_cert.txt + processed/ct_history.tsv.",
        "- Cross-check any discovered legal identifiers with relevant public registries.",
        "",
        "## Warnings",
    ]
    if warnings:
        lines.extend([f"- {item}" for item in warnings])
    else:
        lines.append("- None")
    write_text(notes_path, "\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Passive ownership OSINT collector (authorization-first, non-intrusive).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 passive_ownership_osint.py \\\n"
            "    --root-domain regularizaagora.org \\\n"
            "    --target-host pgmei.regularizaagora.org \\\n"
            "    --target-url \"https://pgmei.regularizaagora.org/fatura/36461594000185\"\n\n"
            "  python3 passive_ownership_osint.py \\\n"
            "    --root-domain example.org \\\n"
            "    --target-host app.example.org \\\n"
            "    --target-url \"https://app.example.org\" \\\n"
            "    --case-id case_manual_001 \\\n"
            "    --output-dir ./investigation"
        ),
    )
    parser.add_argument("--root-domain", required=True, help="Root domain, e.g. regularizaagora.org")
    parser.add_argument("--target-host", required=True, help="Target host, e.g. pgmei.regularizaagora.org")
    parser.add_argument("--target-url", required=True, help="Target URL to collect headers/body")
    parser.add_argument("--case-id", default="", help="Optional custom case ID")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose (debug) logs")
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Base directory where case folder will be created (default: current dir)",
    )
    return parser


def main() -> int:
    parser = build_parser()
    print(BANNER)

    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    args = parser.parse_args()
    setup_logging(args.verbose)
    LOGGER.info("Starting Passive Ownership OSINT run")

    case_id = args.case_id.strip() or default_case_id()
    base_dir = Path(args.output_dir).resolve()
    case_dir = base_dir / case_id

    raw_dir = case_dir / "raw"
    processed_dir = case_dir / "processed"
    evidence_dir = case_dir / "evidence"
    notes_dir = case_dir / "notes"

    LOGGER.info("Preparing case directories: %s", case_dir)
    for directory in (raw_dir, processed_dir, evidence_dir, notes_dir):
        directory.mkdir(parents=True, exist_ok=True)
    LOGGER.success("Case directories ready")

    warnings: list[str] = []

    def add_warning(message: str) -> None:
        warnings.append(message)
        LOGGER.warning(message)

    LOGGER.info("Checking required tools: whois, dig, openssl")
    missing = require_tools(["whois", "dig", "openssl"])
    if missing:
        LOGGER.error("Missing required tools: %s", ", ".join(missing))
        LOGGER.error("Install with: sudo apt install -y whois dnsutils openssl")
        return 1
    LOGGER.success("All required tools are installed")

    LOGGER.info("Writing environment metadata")
    env_meta = [
        f"UTC: {utc_now()}",
        f"User: {os.getenv('USER') or os.getenv('USERNAME') or 'unknown'}",
        f"Hostname: {socket.gethostname()}",
        f"Platform: {platform.platform()}",
        f"Python: {sys.version.split()[0]}",
        f"Case ID: {case_id}",
        f"Root domain: {args.root_domain}",
        f"Target host: {args.target_host}",
        f"Target URL: {args.target_url}",
    ]
    write_text(notes_dir / "environment.txt", "\n".join(env_meta) + "\n")
    LOGGER.success("Environment metadata saved")

    LOGGER.info("Collecting WHOIS for root domain")
    warning = collect_whois(args.root_domain, raw_dir / "whois_domain.txt")
    if warning:
        add_warning(warning)
    else:
        LOGGER.success("WHOIS root domain collected")

    LOGGER.info("Collecting RDAP for root domain")
    rdap, rdap_err = fetch_json(f"https://rdap.org/domain/{args.root_domain}")
    if rdap_err:
        add_warning(f"RDAP failed: {rdap_err}")
        write_text(raw_dir / "rdap_domain.json", "{}\n")
    else:
        write_text(raw_dir / "rdap_domain.json", json.dumps(rdap, ensure_ascii=False, indent=2) + "\n")
        LOGGER.success("RDAP collected")

    LOGGER.info("Collecting DNS records for root domain")
    for item in collect_dig(
        args.root_domain,
        ["A", "AAAA", "NS", "MX", "TXT", "SOA", "CAA"],
        raw_dir / "dns_root_records.txt",
    ):
        add_warning(item)
    LOGGER.success("Root DNS records collected")

    LOGGER.info("Collecting DNS records for target host")
    for item in collect_dig(args.target_host, ["A", "AAAA", "CNAME"], raw_dir / "dns_target_records.txt"):
        add_warning(item)
    LOGGER.success("Target DNS records collected")

    LOGGER.info("Resolving target IP addresses")
    ipv4_list = collect_short_dns(args.target_host, "A", processed_dir / "target_ipv4.txt")
    collect_short_dns(args.target_host, "AAAA", processed_dir / "target_ipv6.txt")
    LOGGER.success("DNS resolution completed")

    if ipv4_list:
        LOGGER.info("Collecting WHOIS for target IPv4: %s", ipv4_list[0])
        warning = collect_whois(ipv4_list[0], raw_dir / "whois_target_ip.txt")
        if warning:
            add_warning(warning)
        else:
            LOGGER.success("Target IP WHOIS collected")
    else:
        add_warning("No IPv4 resolved for target host; skipped whois_target_ip")
        write_text(raw_dir / "whois_target_ip.txt", "")

    LOGGER.info("Collecting live TLS certificate")
    warning = collect_tls_cert(args.target_host, raw_dir / "tls_live_cert.txt")
    if warning:
        add_warning(warning)
    else:
        LOGGER.success("Live TLS certificate collected")

    LOGGER.info("Collecting TLS chain")
    warning = collect_tls_chain(args.target_host, raw_dir / "tls_chain.txt")
    if warning:
        add_warning(warning)
    else:
        LOGGER.success("TLS chain collected")

    LOGGER.info("Collecting certificate transparency history")
    warning = collect_ct_history(args.root_domain, processed_dir / "ct_history.tsv")
    if warning:
        add_warning(warning)
    else:
        LOGGER.success("CT history collected")

    LOGGER.info("Fetching target URL headers/body")
    status, headers, body, http_err = fetch_url(args.target_url)
    headers_text = ""
    if status is not None:
        headers_text += f"HTTP {status}\n"
    for key, value in headers.items():
        headers_text += f"{key}: {value}\n"
    if http_err:
        headers_text += f"\nERROR: {http_err}\n"
        add_warning(f"Target URL fetch issue: {http_err}")

    write_text(raw_dir / "http_headers_target.txt", headers_text)
    write_text(raw_dir / "http_body_target.html", body)
    LOGGER.success("HTTP artifacts saved")

    LOGGER.info("Extracting legal/entity indicators from page content")
    indicator_lines = []
    for index, line in enumerate(body.splitlines(), start=1):
        if LEGAL_INDICATOR_PATTERN.search(line):
            indicator_lines.append(f"{index}: {line.strip()}")
    write_text(
        processed_dir / "legal_entity_indicators.txt",
        "\n".join(indicator_lines) + ("\n" if indicator_lines else ""),
    )
    LOGGER.success("Indicator extraction completed (%d matches)", len(indicator_lines))

    LOGGER.info("Collecting Wayback index")
    wayback, wayback_err = fetch_json(
        "https://web.archive.org/cdx/search/cdx?"
        f"url={args.root_domain}/*&output=json&fl=timestamp,original,statuscode,mimetype&filter=statuscode:200&limit=200"
    )
    if wayback_err:
        add_warning(f"Wayback query failed: {wayback_err}")
        write_text(raw_dir / "wayback_index.json", "[]\n")
    else:
        write_text(raw_dir / "wayback_index.json", json.dumps(wayback, ensure_ascii=False, indent=2) + "\n")
        LOGGER.success("Wayback index collected")

    LOGGER.info("Building ownership summary")
    build_summary(
        notes_path=notes_dir / "ownership_summary.md",
        root_domain=args.root_domain,
        target_host=args.target_host,
        target_url=args.target_url,
        warnings=warnings,
    )
    LOGGER.success("Ownership summary saved")

    LOGGER.success("Case directory: %s", case_dir)
    LOGGER.info("Warnings: %d", len(warnings))
    if warnings:
        for item in warnings:
            LOGGER.warning("- %s", item)

    LOGGER.success("Collection finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
