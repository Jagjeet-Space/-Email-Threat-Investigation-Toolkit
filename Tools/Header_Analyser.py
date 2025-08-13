#!/usr/bin/env python3
import email
import sys
import json
import dns.resolver
from email.policy import default
import re

def parse_email_headers(input_stream):
    """
    Parses email headers from a file-like object and returns them as a dictionary.
    """
    try:
        msg = email.message_from_binary_file(input_stream, policy=default)
    except Exception as e:
        return {'error': f'Failed to parse email: {e}'}

    headers_to_extract = [
        'From', 'To', 'Subject', 'Date', 'Return-Path', 'Reply-To',
        'Message-ID', 'Authentication-Results'
    ]

    parsed_headers = {}
    for header in headers_to_extract:
        # Use get_all for headers that can appear multiple times
        value = msg.get_all(header)
        if value:
            # Join multiple values with a comma for readability
            parsed_headers[header] = ', '.join(value)
        else:
            parsed_headers[header] = 'Not Found'

    return parsed_headers

def extract_domain_from_header(header_value):
    """
    Extracts the domain from a header value (e.g., 'user@example.com' -> 'example.com').
    """
    if not header_value or header_value == 'Not Found':
        return None
    
    # Use a regex to find the domain part, handling different formats
    match = re.search(r'@([a-zA-Z0-9.-]+)', header_value)
    if match:
        return match.group(1)
    
    return None

def verify_email_records(domain, auth_results_header):
    """
    Checks DNS records and compares them to the email's Authentication-Results header.
    """
    verification_results = {
        'spf_dns_record': 'Not Checked',
        'dkim_dns_record': 'Not Checked',
        'spf_match_status': 'Not Checked',
        'dkim_match_status': 'Not Checked'
    }

    # --- SPF Verification ---
    try:
        spf_records = dns.resolver.resolve(domain, 'TXT')
        found_spf = [record.to_text() for record in spf_records if 'v=spf1' in record.to_text().lower()]
        
        if found_spf:
            verification_results['spf_dns_record'] = found_spf[0]
            if 'spf=pass' in auth_results_header.lower():
                verification_results['spf_match_status'] = "Match: SPF header claims PASS, and a DNS record was found."
            elif 'spf=fail' in auth_results_header.lower() or 'spf=none' in auth_results_header.lower():
                verification_results['spf_match_status'] = "Mismatch: Header claims SPF failed, but DNS record exists."
            else:
                verification_results['spf_match_status'] = "No clear match: Header is ambiguous, but DNS record exists."
        else:
            verification_results['spf_dns_record'] = 'No SPF record found in DNS.'
            if 'spf=none' in auth_results_header.lower():
                verification_results['spf_match_status'] = "Match: Header claims SPF=none, consistent with no DNS record."
            elif 'spf=fail' in auth_results_header.lower():
                 verification_results['spf_match_status'] = "Match: Header claims SPF=fail, consistent with no DNS record."
            else:
                verification_results['spf_match_status'] = "Mismatch: Header claims SPF passed, but no DNS record was found."
                
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        verification_results['spf_dns_record'] = 'DNS query failed or no SPF record exists.'
        if 'spf=none' in auth_results_header.lower():
            verification_results['spf_match_status'] = "Match: Header claims SPF=none, consistent with DNS query failure."
        else:
            verification_results['spf_match_status'] = "Mismatch: Header claims SPF passed, but DNS query failed."

    # --- DKIM Verification ---
    # NOTE: This is a simplified check. A full check requires parsing the DKIM-Signature header for the selector.
    try:
        dkim_domain = f"default._domainkey.{domain}"
        dkim_records = dns.resolver.resolve(dkim_domain, 'TXT')
        verification_results['dkim_dns_record'] = dkim_records[0].to_text()
        
        if 'dkim=pass' in auth_results_header.lower():
             verification_results['dkim_match_status'] = "Match: DKIM header claims PASS, and a DNS record was found."
        else:
            verification_results['dkim_match_status'] = "Mismatch: Header is ambiguous, but DNS record exists."
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        verification_results['dkim_dns_record'] = 'No DKIM record found (DNS query failed or incorrect selector).'
        if 'dkim=fail' in auth_results_header.lower() or 'dkim=none' in auth_results_header.lower():
            verification_results['dkim_match_status'] = "Match: Header claims DKIM failed, consistent with no DNS record."
        else:
            verification_results['dkim_match_status'] = "Mismatch: Header claims DKIM passed, but no DNS record was found."

    return verification_results

if __name__ == "__main__":
    if sys.stdin.isatty():
        print("Please pipe an email to standard input (e.g., 'cat email.eml | ./script.py')", file=sys.stderr)
        sys.exit(1)

    parsed_data = parse_email_headers(sys.stdin.buffer)

    if 'error' in parsed_data:
        print(json.dumps(parsed_data, indent=2))
        sys.exit(1)
    
    # Extract the domain from the 'From' header for verification
    from_header_value = parsed_data.get('From', '')
    sender_domain = extract_domain_from_header(from_header_value)
    
    if sender_domain:
        auth_results_header = parsed_data.get('Authentication-Results', '')
        verification = verify_email_records(sender_domain, auth_results_header)
        parsed_data['Domain-Verification-Report'] = verification
    
    print(json.dumps(parsed_data, indent=2))