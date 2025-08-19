#!/usr/bin/env python3
import re
import sys
import json
import os
from typing import Dict, Set, Any, Tuple, Optional

# Email parsing
import email
from email import policy
from email.parser import BytesParser

# Optional colorized output
try:
    from termcolor import colored
except Exception:
    def colored(text, color=None):
        return text

# Optional libs (graceful fallbacks)
# tldextract
try:
    import tldextract
except Exception:
    tldextract = None

# libmagic (file type detection)
try:
    import magic  # python-magic (linux/mac) or python-magic-bin (windows)
except Exception:
    magic = None

# PDF
try:
    from PyPDF2 import PdfReader
except Exception:
    PdfReader = None

# Word
try:
    import docx
except Exception:
    docx = None

# Excel
try:
    import openpyxl
except Exception:
    openpyxl = None

import hashlib


# ---------------------------
# IOC extraction primitives
# ---------------------------

def find_iocs(text: str) -> Dict[str, Set[str]]:
    """
    Finds and returns a dictionary of unique IOCs from a given string.
    Returns sets for internal use; callers should convert to lists before JSON.
    """
    # Broad domain candidate pattern (will normalize via tldextract)
    broad_domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.){1,}[a-zA-Z]{2,}\b'
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    url_pattern = r'https?://[^\s<>"\']+'

    iocs = {
        "ips": set(re.findall(ip_pattern, text or "")),
        "urls": set(re.findall(url_pattern, text or "")),
        "domains": set()
    }

    domain_candidates = re.findall(broad_domain_pattern, text or "")
    if tldextract is not None:
        for candidate in domain_candidates:
            ext = tldextract.extract(candidate)
            if ext.domain and ext.suffix:
                full_domain = f"{ext.domain}.{ext.suffix}"
                iocs["domains"].add(full_domain)
    else:
        # Fallback: trust candidates as-is if tldextract missing
        for candidate in domain_candidates:
            iocs["domains"].add(candidate.lower())

    return iocs


# ---------------------------
# File content parsers
# ---------------------------

def _detect_mime(file_path: str) -> Optional[str]:
    if magic is None:
        # Fallback to naive guess by extension when libmagic is not available
        ext = os.path.splitext(file_path)[1].lower()
        if ext in {".txt", ".log", ".csv", ".md"}:
            return "text/plain"
        if ext == ".pdf":
            return "application/pdf"
        if ext == ".docx":
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
        if ext == ".xlsx":
            return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        return "application/octet-stream"
    try:
        return magic.from_file(file_path, mime=True)
    except Exception:
        return None


def parse_file_content(file_path: str) -> str:
    """
    Parses a file for text content based on its type.
    Supports text, PDF, DOCX, XLSX with graceful degradation if libs are missing.
    """
    try:
        mime_type = _detect_mime(file_path) or "application/octet-stream"
        print(f"[*] Detected file type: {mime_type}", file=sys.stderr)

        # Plain text
        if mime_type.startswith("text/"):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return f.read()

        # PDF
        if "application/pdf" in mime_type:
            if PdfReader is None:
                print("[!] PyPDF2 not available; skipping PDF text extraction", file=sys.stderr)
                return ""
            content = ""
            with open(file_path, "rb") as f:
                reader = PdfReader(f)
                for page in reader.pages:
                    # PdfReader.extract_text() in recent versions is page.extract_text()
                    content += page.extract_text() or ""
            return content

        # Word (docx)
        if "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in mime_type:
            if docx is None:
                print("[!] python-docx not available; skipping DOCX text extraction", file=sys.stderr)
                return ""
            d = docx.Document(file_path)
            return " ".join([para.text for para in d.paragraphs])

        # Excel (xlsx)
        if "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in mime_type:
            if openpyxl is None:
                print("[!] openpyxl not available; skipping XLSX text extraction", file=sys.stderr)
                return ""
            wb = openpyxl.load_workbook(file_path, data_only=True)
            content = ""
            for sheet in wb.worksheets:
                for row in sheet.iter_rows():
                    for cell in row:
                        if cell.value is not None:
                            content += f"{cell.value} "
            return content

        # Unknown/binary
        return ""

    except Exception as e:
        print(f"[!] Error parsing file {file_path}: {e}", file=sys.stderr)
        return ""


# ---------------------------
# Email parsing and IOC attribution
# ---------------------------

def _email_meta(msg) -> Dict[str, Any]:
    return {
        "subject": msg.get("Subject"),
        "from": msg.get("From"),
        "to": msg.get("To"),
        "date": msg.get("Date"),
        "message_id": msg.get("Message-ID") or msg.get("Message-Id"),
    }


def get_iocs_from_file_or_content(input_data, is_file_path=True) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Primary function to get IOCs from a file path or raw content,
    with header analysis and expanded file support.

    Returns:
        (attributed_iocs: dict, meta: dict|None)
    """
    attributed_iocs: Dict[str, Any] = {
        "headers": {},
        "body": {"ips": set(), "urls": set(), "domains": set()},
        "attachments": {}
    }
    meta: Optional[Dict[str, Any]] = None

    # Email file path flow
    if is_file_path and os.path.exists(input_data) and (input_data.lower().endswith(".eml") or input_data.lower().endswith(".msg")):
        print(f"[*] Processing email file: {input_data}", file=sys.stderr)
        with open(input_data, "rb") as fp:
            msg = BytesParser(policy=policy.default).parse(fp)

        # Capture minimal metadata for banner
        meta = _email_meta(msg)

        # Headers IOC extraction
        header_text = ""
        for key, value in msg.items():
            header_text += f"{key}: {value}\n"
        header_iocs = find_iocs(header_text)
        attributed_iocs["headers"] = {k: sorted(v) for k, v in header_iocs.items()}

        # Body IOC extraction
        email_body_text = ""
        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype in ("text/plain", "text/html"):
                    try:
                        email_body_text += part.get_content() or ""
                    except Exception:
                        # Some odd parts may fail to decode
                        pass
        else:
            try:
                email_body_text = msg.get_content() or ""
            except Exception:
                email_body_text = ""

        body_iocs = find_iocs(email_body_text)
        attributed_iocs["body"] = {k: sorted(v) for k, v in body_iocs.items()}

        # Attachments IOC extraction
        for part in msg.walk():
            if part.get_content_disposition() == "attachment":
                filename = part.get_filename() or "unnamed_attachment"
                safe_name = filename.replace(os.sep, "_")
                temp_filename = f"temp_{safe_name}"
                try:
                    with open(temp_filename, "wb") as f:
                        f.write(part.get_payload(decode=True) or b"")
                    print(f"[*] Analyzing attachment: {filename}", file=sys.stderr)

                    # Hashes
                    with open(temp_filename, "rb") as f:
                        data = f.read()
                        md5_hash = hashlib.md5(data).hexdigest()
                        sha256_hash = hashlib.sha256(data).hexdigest()

                    # File type
                    mime_type = _detect_mime(temp_filename) or "application/octet-stream"

                    # Extract content if likely text-like
                    attachment_content = ""
                    likely_binary = any(sig in (mime_type or "") for sig in ["application/x-msdownload"])
                    # Keep octet-stream cautious: many legit docs appear as octet-stream, so try to parse anyway via parse_file_content
                    if not likely_binary:
                        attachment_content = parse_file_content(temp_filename)

                    attachment_iocs = find_iocs(attachment_content)

                    attributed_iocs["attachments"][filename] = {
                        "hashes": {"md5": md5_hash, "sha256": sha256_hash},
                        "mimetype": mime_type,
                        "iocs": {k: sorted(v) for k, v in attachment_iocs.items()}
                    }
                finally:
                    try:
                        if os.path.exists(temp_filename):
                            os.remove(temp_filename)
                    except Exception:
                        pass

    else:
        # Non-email path or raw content flow
        if is_file_path and os.path.exists(input_data):
            text_content = parse_file_content(input_data)
        else:
            text_content = input_data if not is_file_path else ""
        if text_content:
            found_iocs = find_iocs(text_content)
            attributed_iocs["body"] = {k: sorted(v) for k, v in found_iocs.items()}

    return attributed_iocs, meta


# ---------------------------
# Pretty printer (polished)
# ---------------------------

def _plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


def _section(title):
    print(colored(title, "cyan"))


def _print_list(label, items, indent="  "):
    items = sorted(items or [])
    if not items:
        print(f"{indent}{label}: -")
        return
    print(f"{indent}{label}:")
    for it in items:
        print(f"{indent}  - {it}")


def print_iocs_pretty(attributed_iocs: Dict[str, Any], meta: Dict[str, Any] | None = None):
    # Banner
    print(colored("[*] ioc_analyzer v1.0", "cyan"))
    if meta:
        subj = meta.get("subject") or "-"
        frm = meta.get("from") or "-"
        to = meta.get("to") or "-"
        dt = meta.get("date") or "-"
        print(f"Subject: {subj}")
        print(f"From:    {frm}")
        print(f"To:      {to}")
        print(f"Date:    {dt}")
        print("")

    # Headers IOCs
    headers = attributed_iocs.get("headers", {}) or {}
    h_ips = headers.get("ips", []) or []
    h_urls = headers.get("urls", []) or []
    h_domains = headers.get("domains", []) or []
    _section("[*] Header IOC summary")
    print(f"  {_plural(len(h_ips), 'IP')}, {_plural(len(h_urls), 'URL')}, {_plural(len(h_domains), 'domain')}")
    _print_list("IPs", h_ips)
    _print_list("URLs", h_urls)
    _print_list("Domains", h_domains)
    print("")

    # Body IOCs
    body = attributed_iocs.get("body", {}) or {}
    b_ips = body.get("ips", []) or []
    b_urls = body.get("urls", []) or []
    b_domains = body.get("domains", []) or []
    _section("[*] Body IOC summary")
    print(f"  {_plural(len(b_ips), 'IP')}, {_plural(len(b_urls), 'URL')}, {_plural(len(b_domains), 'domain')}")
    _print_list("IPs", b_ips)
    _print_list("URLs", b_urls)
    _print_list("Domains", b_domains)
    print("")

    # Attachments
    atts = attributed_iocs.get("attachments", {}) or {}
    _section("[*] Attachments")
    if not atts:
        print("  None")
        return

    for fname, info in atts.items():
        print(f"- {fname}")
        hashes = (info.get("hashes") or {})
        md5 = hashes.get("md5") or "-"
        sha256 = hashes.get("sha256") or "-"
        mimetype = info.get("mimetype") or "-"
        print(f"    Type:   {mimetype}")
        print(f"    MD5:    {md5}")
        print(f"    SHA256: {sha256}")

        iocs = info.get("iocs", {}) or {}
        a_ips = iocs.get("ips", []) or []
        a_urls = iocs.get("urls", []) or []
        a_domains = iocs.get("domains", []) or []
        print(f"    IOC counts: {_plural(len(a_ips), 'IP')}, {_plural(len(a_urls), 'URL')}, {_plural(len(a_domains), 'domain')}")
        if a_ips:
            _print_list("IPs", a_ips, indent="    ")
        if a_urls:
            _print_list("URLs", a_urls, indent="    ")
        if a_domains:
            _print_list("Domains", a_domains, indent="    ")
        print("")


# ---------------------------
# CLI
# ---------------------------

def main():
    import argparse
    ap = argparse.ArgumentParser(description="Extract and display IOCs from files or .eml emails (pretty console output).")
    ap.add_argument("input", help="Path to a file (e.g., .eml, .txt, .pdf, .docx, .xlsx) or raw text if --raw is set")
    ap.add_argument("--raw", action="store_true", help="Treat input as raw text instead of a file path")
    ap.add_argument("--json-out", help="Write the IOC result to a JSON file")
    ap.add_argument("--print-json", action="store_true", help="Also print the JSON to console (in addition to pretty output)")
    args = ap.parse_args()

    if args.raw:
        result, meta = get_iocs_from_file_or_content(args.input, is_file_path=False)
    else:
        if not os.path.exists(args.input):
            print(f"[!] File not found: {args.input}", file=sys.stderr)
            sys.exit(1)
        result, meta = get_iocs_from_file_or_content(args.input, is_file_path=True)

    # Pretty output
    print_iocs_pretty(result, meta)

    # Optional JSON
    if args.print_json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(colored(f"[*] Wrote JSON to {args.json_out}", "green"))
        except Exception as e:
            print(f"[!] Failed to write JSON: {e}", file=sys.stderr)
            sys.exit(2)

    sys.exit(0)


if __name__ == "__main__":
    main()
