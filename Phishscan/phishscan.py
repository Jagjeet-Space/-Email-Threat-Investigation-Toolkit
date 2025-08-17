import argparse
import sys
import os
import pyfiglet
from termcolor import colored
from .utils import header_parser # <-- Import your module

# --- Removed dummy functions: they are now in header_parser.py ---
# We will add similar imports for url_analyzer and attachment_scanner later.

def print_banner(version):
    """Prints a professional ASCII banner for branding."""
    banner = pyfiglet.figlet_format("PhishScan", font="slant")
    print(colored(banner, "cyan"))
    print(colored(f"  v{version} - A professional email header & body analyzer", "white"))
    print("-" * 60)

def main():
    """Main function to handle arguments and run the analysis."""
    parser = argparse.ArgumentParser(
        description="Analyze an .eml file for phishing indicators."
    )
    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the .eml file to analyze."
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version="PhishScan v0.1.0"
    )

    args = parser.parse_args()
    
    # Check if the file exists
    if not os.path.isfile(args.file):
        print(colored(f"\n[!] Error: The file '{args.file}' does not exist.", "red"))
        sys.exit(1)
        
    print_banner("0.1.0")
    
    print(f"\n[+] Analyzing file: {args.file}\n")
    
    # Call your REAL header analysis function
    print(colored("\n[+] Analyzing email headers...", "yellow"))
    headers = header_parser.analyze_headers(args.file)
    
    # --- Dummy functions for the rest of the analysis (to be replaced later) ---
    urls, iocs = (["https://malicious-site.com/login", "https://safe-site.com/resource"], 
                  {"IPs": ["10.0.0.1", "192.168.1.1"], "Domains": ["malicious-site.com"], "Hashes": []})
    attachments = ([{"filename": "invoice.pdf", "type": "PDF", "is_malicious": False}])

    print("\n" + "="*60)
    print(colored("Summary Report", "green"))
    print("="*60)
    
    # --- Print Header Summary based on YOUR real data ---
    print(colored("\n--- Header Analysis ---", "yellow"))
    if "error" in headers:
        print(colored(f"[!] Error parsing headers: {headers['error']}", "red"))
    else:
        for key, value in headers.items():
            if key in ['Authentication-Results', 'Domain-Verification-Report']:
                continue
            color = "green"
            if "fail" in str(value).lower():
                color = "red"
            elif "none" in str(value).lower():
                color = "yellow"
            print(f"{key}: {colored(value, color)}")
        
        # Print detailed verification results separately
        if 'Domain-Verification-Report' in headers:
            print(colored("\n--- Domain & SPF/DKIM Verification ---", "yellow"))
            report = headers['Domain-Verification-Report']
            for k, v in report.items():
                if "Match" in v:
                    print(f"{k}: {colored(v, 'green')}")
                elif "Mismatch" in v:
                    print(f"{k}: {colored(v, 'red')}")
                else:
                    print(f"{k}: {colored(v, 'yellow')}")
    
    # The rest of the report (URL, IOC, Attachment) uses the dummy data for now
    print(colored("\n--- URL & Domain Analysis (Dummy Data) ---", "yellow"))
    for url in urls:
        color = "red" if "malicious" in url else "green"
        print(f"URL Found: {colored(url, color)}")
        
    print(colored("\n--- Indicators of Compromise (IOCs) (Dummy Data) ---", "yellow"))
    if any(iocs.values()):
        for key, value in iocs.items():
            if value:
                print(f"{key}: {colored(', '.join(value), 'red')}")
            else:
                print(f"{key}: {colored('None found', 'green')}")
    else:
        print(colored("No IOCs found.", "green"))
        
    print(colored("\n--- Attachment Summary (Dummy Data) ---", "yellow"))
    for att in attachments:
        color = "red" if att["is_malicious"] else "green"
        print(f"File: {att['filename']} ({att['type']}) - Malicious: {colored(att['is_malicious'], color)}")

    print("\n" + "="*60)
    print(colored("\nAnalysis complete.", "green"))
    
if __name__ == "__main__":
    main()
