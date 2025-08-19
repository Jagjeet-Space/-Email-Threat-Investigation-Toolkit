#!/usr/bin/env python3

import argparse
import sys
import os
import pyfiglet
from termcolor import colored
import json

# --- ALL MODULES IMPORTED FROM .utils ---
from .utils.analyze_headers import analyze_headers
from .utils import ioc_extractor
from .utils import attachment_analyzer


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


def run_header_analysis(file_path):
    """Runs email header analysis and pretty-prints results."""
    section_title("EMAIL HEADER ANALYSIS")
    try:
        headers = analyze_headers(file_path)  # must return a dict
    except Exception as e:
        print(colored(f"[!] Header analysis failed: {e}", "red"))
        return

    if not headers or not isinstance(headers, dict):
        print(colored("[!] No header data returned from analyze_headers().", "red"))
        return

    # Print all headers except any special report keys
    for key, value in headers.items():
        if key in ('Authentication-Results', 'Domain-Verification-Report'):
            continue
        val = str(value)
        color = "green"
        if "fail" in val.lower():
            color = "red"
        elif "none" in val.lower() or "not found" in val.lower():
            color = "yellow"
        print(f"{key}: {colored(value, color)}")

    # Print SPF/DKIM/domain verification if present
    report = headers.get('Domain-Verification-Report')
    if report and isinstance(report, dict):
        print(colored("\n--- Domain & SPF/DKIM Verification ---", "yellow"))
        for k, v in report.items():
            vs = str(v)
            c = "green" if "match" in vs.lower() else ("red" if "mismatch" in vs.lower() else "yellow")
            print(f"{k}: {colored(v, c)}")


def run_ioc_extraction(file_path):
    """Runs IOC extraction and prints JSON output."""
    section_title("IOC EXTRACTION")
    try:
        extracted_iocs = ioc_extractor.get_iocs_from_file_or_content(file_path)
    except Exception as e:
        print(colored(f"[!] IOC extraction failed: {e}", "red"))
        return

    print(json.dumps(extracted_iocs, indent=2))


def run_attachment_analysis(file_path, args):
    """Runs attachment analysis with selected options."""
    section_title("ATTACHMENT ANALYSIS")
    try:
        # Pass all relevant arguments from the main parser to the analyzer
        report = attachment_analyzer.analyze_attachments(
            file_path=file_path,
            do_magic=args.magic,
            do_entropy=args.entropy,
            save_dir=args.save_attachments,
            scan_with_clamav=args.scan_with_clamav,
        )
        # Use the pretty-print function from the attachment_analyzer module
        attachment_analyzer.print_pretty(report)

    except Exception as e:
        print(colored(f"[!] Attachment analysis failed: {e}", "red"))
        return


def run_full_analysis(file_path, args):
    """Runs all analysis sequentially."""
    run_ioc_extraction(file_path)
    run_header_analysis(file_path)
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

    # iocs subcommand
    parser_iocs = subparsers.add_parser("iocs", help="Extract only IOCs")
    parser_iocs.add_argument("-f", "--file", required=True)

    # attachments subcommand
    parser_attachments = subparsers.add_parser(
        "attachments", help="Analyze email attachments"
    )
    parser_attachments.add_argument("-f", "--file", required=True)
    parser_attachments.add_argument("--pretty", action="store_true", help="Pretty-print attachment analysis report.")
    parser_attachments.add_argument("--save-attachments", help="Directory to save attachments safely.")
    parser_attachments.add_argument("--scan-with-clamav", action="store_true", help="Scan saved attachments with ClamAV (requires clamscan in PATH).")
    parser_attachments.add_argument("--magic", action="store_true", help="Use libmagic to detect actual file type (if available).")
    parser_attachments.add_argument("--entropy", action="store_true", help="Compute Shannon entropy for attachments.")
    
    # full subcommand
    parser_full = subparsers.add_parser("full", help="Run full analysis")
    parser_full.add_argument("-f", "--file", required=True)
    parser_full.add_argument("--save-attachments", help="Directory to save attachments safely.")
    parser_full.add_argument("--scan-with-clamav", action="store_true", help="Scan saved attachments with ClamAV.")
    parser_full.add_argument("--magic", action="store_true", help="Use libmagic to detect actual file type.")
    parser_full.add_argument("--entropy", action="store_true", help="Compute Shannon entropy for attachments.")


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
        run_header_analysis(file_path)
    elif args.command == "iocs":
        run_ioc_extraction(file_path)
    else:
        # No subcommand or "full"
        run_full_analysis(file_path, args)


if __name__ == "__main__":
    main()
