import re
import json
from typing import Dict, Any, Optional, Tuple, List
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime

# Optional dependencies (all use best-effort)
try:
    import dns.resolver
except Exception:
    dns = None

try:
    from termcolor import colored as _colored
except Exception:
    def _colored(t, color=None): return t


# -----------------------
# Utilities
# -----------------------

def _decode_header_value(h: Optional[str]) -> Optional[str]:
    if not h:
        return None
    try:
        return str(make_header(decode_header(h)))
    except Exception:
        return h

def _parse_eml_bytes(path: str):
    with open(path, "rb") as f:
        raw = f.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return raw, msg

def _normalize_domain(d: Optional[str]) -> str:
    return (d or "").strip("<> ").strip().rstrip(".").lower()

def _extract_from_domain(msg) -> Optional[str]:
    addrs = getaddresses(msg.get_all("From", []))
    if not addrs:
        return None
    # take the first From address with a domain
    for _, addr in addrs:
        if "@" in addr:
            return _normalize_domain(addr.split("@", 1)[1])
    return None

def _gather_headers(msg) -> Dict[str, str]:
    # Return a curated, joined map of key headers (as strings)
    r: Dict[str, str] = {}
    for key in ("Subject", "From", "To", "Date", "Return-Path", "Received-SPF"):
        vals = msg.get_all(key) or []
        if vals:
            r[key] = " | ".join(str(v) for v in vals)
    # Include all Authentication-Results lines joined (for reference only)
    ars = msg.get_all("Authentication-Results") or []
    if ars:
        r["Authentication-Results"] = " || ".join(ars)
    return r

def _pick_trusted_ar(msg) -> Optional[str]:
    # Deterministic, minimal choice: take the first Authentication-Results seen
    ars = msg.get_all("Authentication-Results") or []
    if not ars:
        return None
    # ensure string, not list
    first = ars[0]
    return str(first)

def _parse_ar_status(ar_line: Optional[str], mech: str) -> Optional[str]:
    if not ar_line:
        return None
    m = re.search(rf"{mech}\s*=\s*([a-zA-Z0-9_-]+)", ar_line, flags=re.IGNORECASE)
    return m.group(1).lower() if m else None

def _parse_ar_param(ar_line: Optional[str], key: str) -> Optional[str]:
    if not ar_line:
        return None
    m = re.search(rf"{re.escape(key)}\s*=\s*([^;\s]+)", ar_line, flags=re.IGNORECASE)
    return m.group(1) if m else None

def _detect_spf_fallback(received_spf_line: Optional[str]) -> Optional[str]:
    if not received_spf_line:
        return None
    low = received_spf_line.lower()
    if "pass" in low:
        return "pass"
    if "fail" in low:
        return "fail"
    if "softfail" in low:
        return "softfail"
    if "neutral" in low:
        return "neutral"
    return None

def _has_dkim_signature(msg) -> bool:
    return bool(msg.get_all("DKIM-Signature"))

def _dmarc_dns(domain: Optional[str], timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    if not domain or dns is None:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        name = f"_dmarc.{domain}"
        answers = resolver.resolve(name, "TXT")
        txt = "".join(part.decode() if isinstance(part, bytes) else part
                      for r in answers for part in r.strings)
        tags: Dict[str, str] = {}
        for seg in re.split(r"\s*;\s*", txt.strip()):
            if "=" in seg:
                k, v = seg.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return {"domain": domain, "raw": txt, "tags": tags}
    except Exception:
        return None

def _color_status(name: str, val: Optional[str]) -> str:
    v = (val or "").lower()
    if v in ("pass", "authenticated"):
        return _colored(f"{name}: {v.upper()}", "green")
    if v in ("fail", "permerror", "temperror", "softfail", "unauthenticated"):
        return _colored(f"{name}: {v.upper()}", "red")
    if v in ("none", "neutral", "record_present", "partially_authenticated", "unknown"):
        return _colored(f"{name}: {v.upper()}", "yellow")
    return f"{name}: {val or '-'}"

def _fmt_kv(k: str, v: Optional[str]) -> str:
    return f"{_colored(k+':','yellow')} {v or '-'}"


# -----------------------
# Core analysis
# -----------------------

def analyze_headers(
    file_path: str,
    quiet: bool = True,
    dns_timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Minimal, robust header analysis. Returns a result dict suitable for pretty/json/csv.
    """
    raw, msg = _parse_eml_bytes(file_path)

    # Curated key headers
    key_headers = _gather_headers(msg)

    # Basic message context
    subject = _decode_header_value(msg.get("Subject"))
    from_hdr = _decode_header_value(msg.get("From"))
    to_hdr = _decode_header_value(msg.get("To"))
    date_hdr = msg.get("Date")
    date_iso = None
    if date_hdr:
        try:
            dt = parsedate_to_datetime(date_hdr)
            date_iso = dt.astimezone().isoformat() if dt.tzinfo else dt.isoformat()
        except Exception:
            date_iso = date_hdr

    # Authentication-Results (trusted single line)
    ar_used = _pick_trusted_ar(msg)  # always string or None

    # SPF
    spf_status = _parse_ar_status(ar_used, "spf")
    if not spf_status:
        spf_status = _detect_spf_fallback(key_headers.get("Received-SPF"))
    if not spf_status:
        spf_status = "none"

    # DKIM
    dkim_status = _parse_ar_status(ar_used, "dkim")
    if not dkim_status:
        dkim_status = "pass" if _has_dkim_signature(msg) else "none"

    # DMARC
    dmarc_status = _parse_ar_status(ar_used, "dmarc")
    dmarc_dns_info = None
    if not dmarc_status or dmarc_status == "none":
        # try DNS presence to report record existence (not a pass/fail)
        from_dom_for_dns = _extract_from_domain(msg)
        dmarc_dns_info = _dmarc_dns(from_dom_for_dns, timeout=dns_timeout)
        if dmarc_dns_info:
            dmarc_status = "record_present"
        else:
            dmarc_status = dmarc_status or "none"

    # Alignment (robust, suffix match)
    from_domain = _extract_from_domain(msg)
    spf_mailfrom = _parse_ar_param(ar_used, "smtp.mailfrom")
    dkim_d = _parse_ar_param(ar_used, "header.d")

    from_n = _normalize_domain(from_domain)
    spf_n = _normalize_domain(spf_mailfrom)
    dkim_n = _normalize_domain(dkim_d)

    spf_aligned = bool(spf_n and from_n and spf_n.endswith(from_n))
    dkim_aligned = bool(dkim_n and from_n and dkim_n.endswith(from_n))

    # Verdict
    if dmarc_status == "pass":
        verdict = "authenticated"
        issues: List[str] = []
        reasons: List[str] = []
    else:
        issues = []
        reasons = []
        if spf_status != "pass" and dkim_status != "pass":
            verdict = "unauthenticated"
            issues.extend(["SPF", "DKIM"])
            reasons.append("Neither SPF nor DKIM passed")
        else:
            verdict = "partially_authenticated"
            if spf_status != "pass":
                issues.append("SPF")
                reasons.append("SPF did not pass")
            if dkim_status != "pass":
                issues.append("DKIM")
                reasons.append("DKIM did not pass")
        if dmarc_status in ("none", "record_present"):
            issues.append("DMARC")
            reasons.append("DMARC not passed or not evaluated")

    result: Dict[str, Any] = {
        "verdict": verdict,
        "issues": list(dict.fromkeys(issues)),
        "reasons": reasons,
        "headers": {
            "subject": subject,
            "from": from_hdr,
            "to": to_hdr,
            "date": date_iso or date_hdr,
            "message_id": msg.get("Message-ID") or msg.get("Message-Id"),
        },
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
        },
        "alignment": {
            "from_domain": from_domain,
            "spf_mailfrom": spf_mailfrom,
            "dkim_d": dkim_d,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        },
        "key_headers": key_headers,
        "authserv_used": ar_used,  # always string or None
        "dmarc": {
            "dns_record": dmarc_dns_info,
        },
        "arc_present": bool(msg.get_all("ARC-Seal") or msg.get_all("ARC-Message-Signature")),
    }
    return result


# -----------------------
# Pretty printer (lean)
# -----------------------

def _extract_authserv_id_safe(ar_used: Optional[str]) -> Optional[str]:
    if not ar_used:
        return None
    # take text before first ';'
    return ar_used.split(";", 1)[0].strip() or None

def print_headers_pretty(result: Dict[str, Any]) -> None:
    hdrs = result.get("headers", {}) or {}
    auth = result.get("authentication", {}) or {}
    verdict = result.get("verdict", "")
    reasons = result.get("reasons", []) or []
    issues = result.get("issues", []) or []
    key_headers = result.get("key_headers", {}) or {}
    ars_used = result.get("authserv_used") or None
    alignment = result.get("alignment", {}) or {}

    print(_colored("[*] Header", "cyan"))
    print(_fmt_kv("Subject", hdrs.get("subject")))
    print(_fmt_kv("From", hdrs.get("from")))
    print(_fmt_kv("To", hdrs.get("to")))
    print(_fmt_kv("Date", hdrs.get("date")))
    print("")

    print(_colored("[*] Authentication", "cyan"))
    print("  " + _color_status("SPF", auth.get("spf")))
    print("  " + _color_status("DKIM", auth.get("dkim")))
    print("  " + _color_status("DMARC", auth.get("dmarc")))
    print("  " + _color_status("Verdict", verdict))
    print("")

    print(_colored("[*] Alignment", "cyan"))
    print(f"  From domain:    {alignment.get('from_domain') or '-'}")
    print(f"  SPF MAIL FROM:  {alignment.get('spf_mailfrom') or '-'}")
    print(f"  DKIM d= domain: {alignment.get('dkim_d') or '-'}")
    flags = []
    flags.append("SPF aligned" if alignment.get("spf_aligned") else "SPF not aligned")
    flags.append("DKIM aligned" if alignment.get("dkim_aligned") else "DKIM not aligned")
    print("  " + ", ".join(flags))
    print("")

    print(_colored("[*] Key headers", "cyan"))
    if key_headers.get("Return-Path"):
        print(f"  {_colored('Return-Path:','yellow')} {key_headers['Return-Path']}")
    if key_headers.get("Received-SPF"):
        print(f"  {_colored('Received-SPF:','yellow')} {key_headers['Received-SPF']}")
    if ars_used:
        authserv_id = _extract_authserv_id_safe(ars_used) or "-"
        print(f"  {_colored('Authentication-Results (used):','yellow')} {ars_used}")
        print(f"  {_colored('Authserv-ID:','yellow')} {authserv_id}")
    print("")

    risky = []
    if "SPF" in issues and "DKIM" in issues:
        risky.append("Neither SPF nor DKIM passed")
    if auth.get("dmarc") in ("none", "record_present"):
        risky.append("DMARC not passed (check alignment)")
    if risky or reasons:
        print(_colored("[*] Risk flags", "cyan"))
        for r in (risky or reasons):
            print("  - " + _colored(r, "red"))
