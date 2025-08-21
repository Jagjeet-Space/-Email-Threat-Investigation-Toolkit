#!/usr/bin/env python3

import argparse
import sys
import os
import pyfiglet
from termcolor import colored
import json

# --- ALL MODULES IMPORTED FROM .utils ---
from .utils.analyze_headers import analyze_headers, print_headers_pretty
from .utils import ioc_extractor
from .utils import attachment_analyzer

# Import pretty printer from ioc_extractor and provide a colorer
try:
    from .utils.ioc_extractor import print_iocs_pretty as _pretty_print
except Exception:
    # Minimal fallback if import fails (keeps CLI usable)
    def _pretty_print(result, meta, colorer):
        print("[*] IOC SUMMARY")
        for section in ("headers", "body"):
            data = result.get(section, {})
            print(f"- {section}:")
            for k in ("ips", "urls", "domains"):
                print(f"  {k}: {len(data.get(k, []))}")

def _colorer(text, color=None):
    try:
        return colored(text, color) if color else text
    except Exception:
        return text

def _normalize_result(value):
    """
    Normalize extractor output to (result, meta).
    Accepts:
      - (result, meta) tuple
      - [result, meta] list
      - result dict (meta=None)
    """
    if isinstance(value, tuple) and len(value) == 2:
        return value[0], value[1]
    if isinstance(value, list) and len(value) == 2 and isinstance(value, dict):
        return value, value[1]
    if isinstance(value, dict):
        return value, None
    return {}, None

def _print_as_csv(result):
    import csv
    rows = []
    # headers
    for x in result.get("headers", {}).get("ips", []):
        rows.append(("headers", "ip", str(x)))
    for x in result.get("headers", {}).get("urls", []):
        rows.append(("headers", "url", str(x)))
    for x in result.get("headers", {}).get("domains", []):
        rows.append(("headers", "domain", str(x)))
    # body
    for x in result.get("body", {}).get("ips", []):
        rows.append(("body", "ip", str(x)))
    for x in result.get("body", {}).get("urls", []):
        rows.append(("body", "url", str(x)))
    for x in result.get("body", {}).get("domains", []):
        rows.append(("body", "domain", str(x)))
    # attachments
    for fname, info in (result.get("attachments") or {}).items():
        i = (info.get("iocs") or {})
        for x in i.get("ips", []):
            rows.append((f"attachment:{fname}", "ip", str(x)))
        for x in i.get("urls", []):
            rows.append((f"attachment:{fname}", "url", str(x)))
        for x in i.get("domains", []):
            rows.append((f"attachment:{fname}", "domain", str(x)))
    w = csv.writer(sys.stdout)
    w.writerow(["section", "type", "indicator"])
    w.writerows(rows)

def _emit_output(value, fmt="json"):
    result, meta = _normalize_result(value)
    if fmt == "json":
        print(json.dumps(value, indent=2, ensure_ascii=False))
    elif fmt == "pretty":
        _pretty_print(result, meta, _colorer)  # pass colorer to match signature
    elif fmt == "csv":
        _print_as_csv(result)
    else:
        print(json.dumps(value, indent=2, ensure_ascii=False))

def _emit_headers(result, fmt="json"):
    if fmt == "json":
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif fmt == "pretty":
        print_headers_pretty(result)
    elif fmt == "csv":
        import csv
        hdrs = result.get("headers", {}) or {}
        auth = result.get("authentication", {}) or {}
        align = result.get("alignment", {}) or {}
        row = {
            "subject": hdrs.get("subject"),
            "from": hdrs.get("from"),
            "to": hdrs.get("to"),
            "date": hdrs.get("date"),
            "spf": auth.get("spf"),
            "dkim": auth.get("dkim"),
            "dmarc": auth.get("dmarc"),
            "verdict": result.get("verdict"),
            "from_domain": align.get("from_domain"),
            "spf_mailfrom": align.get("spf_mailfrom"),
            "dkim_d": align.get("dkim_d"),
            "spf_aligned": align.get("spf_aligned"),
            "dkim_aligned": align.get("dkim_aligned"),
        }
        w = csv.DictWriter(sys.stdout, fieldnames=list(row.keys()))
        w.writeheader()
        w.writerow(row)
    else:
        print(json.dumps(result, indent=2, ensure_ascii=False))

def print_banner(version):
    """Prints the main ASCII banner with version and author."""
    banner = pyfiglet.figlet_format("PhishScan", font="slant")
    print(colored(banner, "cyan"))
    print(colored(f"  v{version} - A professional email header & body analyzer", "white"))
    print(colored("  Developed by Jagjeet", "magenta", attrs=["bold"]))
    print("=" * 70)

def section_title(title):
    """Prints a professional-looking section title."""
    print("\n" + "~" * 70)
    print(" " * ((70 - len(title)) // 2) + colored(title, "yellow", attrs=["bold"]))
    print("~" * 70 + "\n")

def run_header_analysis(file_path, fmt="json"):
    """Runs email header analysis and renders in requested format."""
    section_title("EMAIL HEADER ANALYSIS")
    try:
        # Keep analyzer quiet; pretty output is handled by the renderer
        result = analyze_headers(file_path, quiet=True)
    except Exception as e:
        print(colored(f"[!] Header analysis failed: {e}", "red"))
        return
    _emit_headers(result, fmt=fmt)

def run_ioc_extraction(file_path, fmt="json"):
    """Runs IOC extraction and prints based on requested format."""
    section_title("IOC EXTRACTION")
    try:
        value = ioc_extractor.get_iocs_from_file_or_content(file_path)
    except Exception as e:
        print(colored(f"[!] IOC extraction failed: {e}", "red"))
        return
    _emit_output(value, fmt=fmt)

def run_attachment_analysis(file_path, args):
    """Runs attachment analysis with selected options."""
    section_title("ATTACHMENT ANALYSIS")
    try:
        report = attachment_analyzer.analyze_attachments(
            file_path=file_path,
            do_magic=args.magic,
            do_entropy=args.entropy,
            save_dir=args.save_attachments,
            scan_with_clamav=args.scan_with_clamav,
        )
        # Pretty print attachment report (module’s own pretty)
        attachment_analyzer.print_pretty(report)
    except Exception as e:
        print(colored(f"[!] Attachment analysis failed: {e}", "red"))
        return

def run_full_analysis(file_path, args):
    """Runs all analysis sequentially, respecting --format for IOCs and headers."""
    fmt = getattr(args, "format", "json")
    run_ioc_extraction(file_path, fmt=fmt)
    run_header_analysis(file_path, fmt=fmt)
    run_attachment_analysis(file_path, args)
    print("\n" + "=" * 70)
    print(colored("Analysis complete.", "green", attrs=["bold"]))
    print("=" * 70)

def main():
    parser = argparse.ArgumentParser(description="Analyze an .eml file for phishing indicators.")
    subparsers = parser.add_subparsers(dest="command")

    # headers subcommand
    parser_headers = subparsers.add_parser("headers", help="Analyze only email headers")
    parser_headers.add_argument("-f", "--file", required=True)
    parser_headers.add_argument("--format", choices=["json", "pretty", "csv"], default="json",
                                help="Output format (default: json)")

    # iocs subcommand
    parser_iocs = subparsers.add_parser("iocs", help="Extract only IOCs")
    parser_iocs.add_argument("-f", "--file", required=True)
    parser_iocs.add_argument("--format", choices=["json", "pretty", "csv"], default="json",
                              help="Output format (default: json)")

    # attachments subcommand
    parser_attachments = subparsers.add_parser("attachments", help="Analyze email attachments")
    parser_attachments.add_argument("-f", "--file", required=True)
    parser_attachments.add_argument("--pretty", action="store_true",
                                    help="Pretty-print attachment analysis report.")
    parser_attachments.add_argument("--save-attachments", help="Directory to save attachments safely.")
    parser_attachments.add_argument("--scan-with-clamav", action="store_true",
                                    help="Scan saved attachments with ClamAV (requires clamscan in PATH).")
    parser_attachments.add_argument("--magic", action="store_true",
                                    help="Use libmagic to detect actual file type (if available).")
    parser_attachments.add_argument("--entropy", action="store_true",
                                    help="Compute Shannon entropy for attachments.")
    parser_attachments.add_argument("--format", choices=["json", "pretty", "csv"], default="json",
                                    help="Output format (default: json)")
    
    # full subcommand
    parser_full = subparsers.add_parser("full", help="Run full analysis")
    parser_full.add_argument("-f", "--file", required=True)
    parser_full.add_argument("--save-attachments", help="Directory to save attachments safely.")
    parser_full.add_argument("--scan-with-clamav", action="store_true", help="Scan saved attachments with ClamAV.")
    parser_full.add_argument("--magic", action="store_true", help="Use libmagic to detect actual file type.")
    parser_full.add_argument("--entropy", action="store_true", help="Compute Shannon entropy for attachments.")
    parser_full.add_argument("--format", choices=["json", "pretty", "csv"], default="json",
                             help="Output format (default: json)")

    args = parser.parse_args()

    # Determine file path
    file_path = args.file if hasattr(args, 'file') and args.file else None
    if not file_path:
        print(colored("[!] Error: You must provide a file path with -f.", "red"))
        sys.exit(1)
    if not os.path.isfile(file_path):
        print(colored(f"\n[!] Error: The file '{file_path}' does not exist.", "red"))
        sys.exit(1)

    # Print banner once
    print_banner("0.1.0")

    # Dispatch
    if args.command == "attachments":
        run_attachment_analysis(file_path, args)
    elif args.command == "headers":
        run_header_analysis(file_path, fmt=getattr(args, "format", "json"))
    elif args.command == "iocs":
        run_ioc_extraction(file_path, fmt=getattr(args, "format", "json"))
    else:
        # No subcommand or "full"
        run_full_analysis(file_path, args)

if __name__ == "__main__":
    main()
