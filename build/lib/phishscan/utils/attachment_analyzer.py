#!/usr/bin/env python3
import sys
import os
import json
import math
import argparse
import hashlib
import pathlib
import mimetypes
import subprocess
import shlex
from collections import Counter
from datetime import datetime
from typing import Optional, List, Dict, Any

import email
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header

# Optional libs: termcolor, python-magic
try:
    from termcolor import colored
except Exception:
    def colored(text, color=None):
        return text

try:
    import magic as libmagic  # python-magic
except Exception:
    libmagic = None


TOOL_NAME = "attachment_analyzer"
TOOL_VERSION = "1.2.0"


def human_size(n: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units) - 1:
        f /= 1024.0
        i += 1
    return f"{f:.1f}{units[i]}"


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def decode_str(s: Optional[str]) -> Optional[str]:
    if s is None:
        return None
    try:
        # Properly decode RFC2047 headers e.g. Subject
        return str(make_header(decode_header(s)))
    except Exception:
        return s


def safe_filename(name: str) -> str:
    # Keep only basename and strip weird control chars
    base = pathlib.Path(name).name
    # Replace path separators and nulls
    safe = base.replace(os.sep, "_").replace("\x00", "")
    # Optionally limit length
    return safe[:255] if len(safe) > 255 else safe


def guess_extension(mimetype: str) -> str:
    ext = mimetypes.guess_extension(mimetype) or ""
    # Handle common mismatches
    if not ext and mimetype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
        ext = ".docx"
    return ext


def bytes_hashes(data: Optional[bytes], max_bytes_for_hash: int = 0) -> Dict[str, Optional[str]]:
    if not data:
        return {"md5": None, "sha256": None}
    if max_bytes_for_hash and len(data) > max_bytes_for_hash:
        # Skip hashing for very large blobs if requested
        return {"md5": None, "sha256": None}
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    return {"md5": md5_hash, "sha256": sha256_hash}


def detect_magic_from_path(path: str) -> Optional[str]:
    if libmagic is None:
        return None
    try:
        ms = libmagic.Magic(mime=True)
        return ms.from_file(path)
    except Exception:
        return None


def clamav_scan(path: str, timeout: int = 45) -> Optional[str]:
    # Requires clamscan to be present in PATH
    try:
        cmd = f"clamscan --no-summary {shlex.quote(path)}"
        res = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=timeout)
        out = res.stdout.strip()
        # Typical: "<path>: OK" or "<path>: <Malware.Name> FOUND"
        if ": " in out:
            return out.split(": ", 1)[1]
        return out or None
    except Exception:
        return None


def extract_email_metadata(msg) -> Dict[str, Any]:
    # Extract basic headers with decoding
    subject = decode_str(msg.get("Subject"))
    from_ = decode_str(msg.get("From"))
    to_ = decode_str(msg.get("To"))
    date_raw = msg.get("Date")
    msg_id = msg.get("Message-ID") or msg.get("Message-Id")

    # Parse Date to ISO8601 if possible
    date_iso = None
    if date_raw:
        try:
            # email.utils.parsedate_to_datetime is available in 3.3+
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(date_raw)
            # Convert to UTC ISO if aware
            if dt.tzinfo:
                date_iso = dt.astimezone().isoformat()
            else:
                date_iso = dt.isoformat()
        except Exception:
            date_iso = None

    authres = msg.get_all("Authentication-Results") or []
    dkim_sig = msg.get_all("DKIM-Signature") or []
    arc_seal = msg.get_all("ARC-Seal") or []
    arc_msg_sig = msg.get_all("ARC-Message-Signature") or []

    return {
        "subject": subject,
        "from": from_,
        "to": to_,
        "date": date_iso or date_raw,
        "message_id": msg_id,
        "authentication_results": authres,
        "dkim_signature_present": bool(dkim_sig),
        "arc_present": bool(arc_seal or arc_msg_sig),
    }


def should_block_mime_or_ext(mimetype: str, filename: Optional[str], allow_all: bool) -> bool:
    if allow_all:
        return False
    block_mimes = {
        "application/x-msdownload",
        "application/x-dosexec",
        "application/x-ms-installer",
        "application/x-sh",
        "application/java-archive",
    }
    block_exts = {".exe", ".dll", ".scr", ".js", ".vbs", ".jar", ".bat", ".cmd", ".ps1", ".lnk"}
    if mimetype in block_mimes:
        return True
    if filename:
        ext = pathlib.Path(filename).suffix.lower()
        if ext in block_exts:
            return True
    return False


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Parse and analyze attachments in .eml files")
    p.add_argument("eml", help="Path to .eml file")

    # Selection and filtering
    p.add_argument("--include-inline", action="store_true", help="Include inline parts as attachments")
    p.add_argument("--min-size-bytes", type=int, default=0, help="Only include parts >= this size")
    p.add_argument("--max-bytes", type=int, default=0, help="Skip hashing content above this size")

    # Output and saving
    p.add_argument("--json-out", help="Write JSON report to this path")
    p.add_argument("--pretty", action="store_true", help="Pretty-print a human-friendly summary")
    p.add_argument("--summary", action="store_true", help="Print high-level summary (counts, types, flags)")
    p.add_argument("--save-dir", help="Directory to save attachments safely")

    # Analysis toggles
    p.add_argument("--magic", action="store_true", help="Use libmagic to detect actual file type (if available)")
    p.add_argument("--entropy", action="store_true", help="Compute Shannon entropy for attachments")
    p.add_argument("--scan-with-clamav", action="store_true", help="Scan saved attachments with ClamAV")
    p.add_argument("--allow-all", action="store_true", help="Do not block risky types/extensions")

    # Operational
    p.add_argument("--timeout", type=int, default=45, help="Timeout (s) for external scans per file")
    return p.parse_args()


def analyze_attachments(
    file_path: str,
    include_inline: bool = False,
    min_size_bytes: int = 0,
    max_bytes_for_hash: int = 0,
    do_magic: bool = False,
    do_entropy: bool = False,
    save_dir: Optional[str] = None,
    scan_with_clamav: bool = False,
    clamav_timeout: int = 45,
    allow_all: bool = False,
) -> Dict[str, Any]:
    # Read and parse email
    try:
        with open(file_path, "rb") as f:
            raw_email = f.read()
    except Exception as e:
        raise RuntimeError(f"Failed to read file: {e}")

    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    except Exception as e:
        raise RuntimeError(f"Failed to parse email: {e}")

    email_meta = extract_email_metadata(msg)

    attachments: List[Dict[str, Any]] = []
    part_index = 0

    for part in msg.walk():
        # Skip containers
        if part.get_content_maintype() == "multipart":
            continue

        disposition = part.get_content_disposition()  # 'attachment' | 'inline' | None
        filename = part.get_filename()
        if filename:
            filename = decode_str(filename)

        # Filter inline parts unless requested
        if not include_inline and disposition == "inline":
            continue

        # Capture parts that are attachments by disposition even without filename
        if not filename and disposition not in ("attachment",):
            # Skip nameless non-attachment parts by default
            continue

        # Decode payload
        try:
            content = part.get_payload(decode=True)
        except Exception:
            content = None

        size = len(content) if content else 0
        if size < (min_size_bytes or 0):
            continue

        mimetype = part.get_content_type()
        cte = part.get("Content-Transfer-Encoding")
        cid = part.get("Content-Id")
        if cid:
            cid = cid.strip("<>")

        # Generate synthetic filename if missing
        synth_name = None
        if not filename:
            ext = guess_extension(mimetype)
            synth_name = f"part-{part_index}{ext}"
            filename = synth_name

        norm_name = safe_filename(filename)

        # Hashes (may be skipped by max_bytes_for_hash)
        hashes = bytes_hashes(content, max_bytes_for_hash=max_bytes_for_hash)

        # Build base record
        record: Dict[str, Any] = {
            "index": part_index,
            "filename": filename,
            "normalized_filename": norm_name,
            "size": size,
            "mimetype": mimetype,
            "disposition": disposition,
            "content_id": cid,
            "content_transfer_encoding": cte,
            "hashes": hashes,
            "flags": [],
        }

        # Blocklist check
        if should_block_mime_or_ext(mimetype, filename, allow_all=allow_all):
            record["flags"].append("blocked_by_policy")

        # Save file if requested
        save_path = None
        if save_dir:
            try:
                os.makedirs(save_dir, exist_ok=True)
                save_path = os.path.join(save_dir, norm_name)
                with open(save_path, "wb") as w:
                    w.write(content or b"")
                record["save_path"] = save_path
            except Exception as e:
                record["flags"].append(f"save_error:{e}")

        # libmagic detection on saved path preferred; else temp emulate by writing
        if do_magic:
            magic_type = None
            temp_written = False
            temp_path = None
            try:
                if save_path:
                    magic_type = detect_magic_from_path(save_path)
                elif libmagic is not None and content is not None:
                    # Write minimal temp for detection
                    import tempfile
                    fd, temp_path = tempfile.mkstemp(prefix="att_", suffix="_magic")
                    with os.fdopen(fd, "wb") as tf:
                        tf.write(content)
                    temp_written = True
                    magic_type = detect_magic_from_path(temp_path)
            except Exception:
                pass
            finally:
                if temp_written and temp_path:
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
            record["magic"] = magic_type

            # Mismatch flag between declared mimetype and magic
            if magic_type and (magic_type != mimetype):
                record["flags"].append("mime_magic_mismatch")

        # Entropy
        if do_entropy:
            try:
                ent = shannon_entropy(content or b"")
                record["entropy"] = round(ent, 4)
                if ent >= 7.8 and size >= 10 * 1024:  # heuristic
                    record["flags"].append("high_entropy")
            except Exception:
                record["entropy"] = None

        # ClamAV scan (requires file on disk)
        if scan_with_clamav:
            path_for_scan = save_path
            if not path_for_scan and content is not None:
                # Write a temp file to scan if not saved
                import tempfile
                fd, tmp = tempfile.mkstemp(prefix="att_", suffix="_scan")
                with os.fdopen(fd, "wb") as tf:
                    tf.write(content)
                path_for_scan = tmp
                temp_cleanup = True
            else:
                temp_cleanup = False

            try:
                res = clamav_scan(path_for_scan, timeout=clamav_timeout)
                if res:
                    record.setdefault("scan", {})["clamav"] = res
                    if "FOUND" in res:
                        record["flags"].append("clamav_detected")
            finally:
                if 'temp_cleanup' in locals() and temp_cleanup:
                    try:
                        os.remove(path_for_scan)
                    except Exception:
                        pass

        attachments.append(record)
        part_index += 1

    # Deduplicate by sha256 if available
    sha_map = {}
    for rec in attachments:
        sha = rec.get("hashes", {}).get("sha256")
        if sha:
            sha_map.setdefault(sha, []).append(rec["index"])
    for sha, idxs in sha_map.items():
        if len(idxs) > 1:
            for rec in attachments:
                if rec["index"] in idxs:
                    rec["flags"].append("duplicate_hash")

    # Build summary
    by_type = {}
    flagged = 0
    total_size = 0
    largest = None
    for rec in attachments:
        total_size += rec.get("size", 0)
        by_type[rec.get("mimetype")] = by_type.get(rec.get("mimetype"), 0) + 1
        if rec.get("flags"):
            flagged += 1
        if not largest or rec.get("size", 0) > largest.get("size", 0):
            largest = rec

    report: Dict[str, Any] = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "email_summary": email_meta,
        "stats": {
            "total_attachments": len(attachments),
            "total_size_bytes": total_size,
            "by_mimetype": by_type,
            "flagged_attachments": flagged,
            "largest_index": largest.get("index") if largest else None,
            "largest_size": largest.get("size") if largest else None,
            "largest_filename": largest.get("filename") if largest else None,
        },
        "attachments": attachments,
    }
    return report


def print_pretty(report: Dict[str, Any]) -> None:
    meta = report.get("email_summary", {})
    stats = report.get("stats", {})
    print(colored(f"[*] {TOOL_NAME} v{TOOL_VERSION}", "cyan"))
    print(f"Subject: {meta.get('subject')}")
    print(f"From:    {meta.get('from')}")
    print(f"To:      {meta.get('to')}")
    print(f"Date:    {meta.get('date')}")
    print("")

    total = stats.get("total_attachments", 0)
    total_size = stats.get("total_size_bytes", 0)
    print(colored(f"[*] Found {total} attachment(s), total {human_size(total_size)}", "cyan"))

    if total == 0:
        return

    for att in report.get("attachments", []):
        line1 = f"- [{att.get('index')}] {att.get('filename')} ({human_size(att.get('size', 0))})"
        mt = att.get("mimetype")
        disp = att.get("disposition")
        flags = ", ".join(att.get("flags") or [])
        hashes = att.get("hashes") or {}
        sha = hashes.get("sha256")
        md5 = hashes.get("md5")
        print(line1)
        print(f"    Type: {mt} | Disposition: {disp}")
        if md5 or sha:
            print(f"    MD5: {md5 or '-'} | SHA256: {sha or '-'}")
        if att.get("magic") is not None:
            print(f"    Magic: {att.get('magic')}")
        if "entropy" in att:
            print(f"    Entropy: {att.get('entropy')}")
        if att.get("content_id"):
            print(f"    CID: {att.get('content_id')}")
        if att.get("save_path"):
            print(f"    Saved: {att.get('save_path')}")
        if flags:
            print(colored(f"    Flags: {flags}", "yellow"))
        scan = att.get("scan", {})
        if scan.get("clamav"):
            status = scan["clamav"]
            color = "red" if "FOUND" in status else "green"
            print(colored(f"    ClamAV: {status}", color))
        print("")

    if stats.get("by_mimetype"):
        print("By mimetype:")
        for mt, cnt in stats["by_mimetype"].items():
            print(f"  - {mt}: {cnt}")
        print("")


def print_summary(report: Dict[str, Any]) -> None:
    stats = report.get("stats", {})
    print(colored("[*] Summary", "cyan"))
    print(f"Total attachments: {stats.get('total_attachments', 0)}")
    print(f"Total size:        {human_size(stats.get('total_size_bytes', 0))}")
    print(f"Flagged:           {stats.get('flagged_attachments', 0)}")
    if stats.get("largest_index") is not None:
        print(f"Largest:           [{stats.get('largest_index')}] {stats.get('largest_filename')} "
              f"({human_size(stats.get('largest_size', 0))})")


def main():
    args = parse_args()

    try:
        report = analyze_attachments(
            file_path=args.eml,
            include_inline=args.include_inline,
            min_size_bytes=args.min_size_bytes,
            max_bytes_for_hash=args.max_bytes,
            do_magic=args.magic,
            do_entropy=args.entropy,
            save_dir=args.save_dir,
            scan_with_clamav=args.scan_with_clamav,
            clamav_timeout=args.timeout,
            allow_all=args.allow_all,
        )
    except RuntimeError as e:
        print(colored(f"[!] {e}", "red"))
        sys.exit(2)

    # Console outputs
    if args.pretty:
        print_pretty(report)
    if args.summary:
        print_summary(report)

    # Always print a concise line if neither pretty nor summary requested
    if not args.pretty and not args.summary:
        total = report.get("stats", {}).get("total_attachments", 0)
        print(colored(f"[*] Found {total} attachment(s). Use --pretty or --summary for details.", "cyan"))

    # JSON out
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
            print(colored(f"[*] Wrote JSON to {args.json_out}", "green"))
        except Exception as e:
            print(colored(f"[!] Failed to write JSON: {e}", "red"))
            sys.exit(3)

    sys.exit(0)


if __name__ == "__main__":
    main()
