import json
import re
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime

# Optional deps
try:
    import dns.resolver
except Exception:
    dns = None

try:
    import dkim as dkim_lib
except Exception:
    dkim_lib = None

try:
    from termcolor import colored
except Exception:
    def colored(t, color=None): return t


# -----------------------
# Core helpers
# -----------------------

def _dec(h):
    if h is None:
        return None
    try:
        return str(make_header(decode_header(h)))
    except Exception:
        return h


def _parse_eml(path):
    with open(path, "rb") as f:
        raw = f.read()
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    return raw, msg


def extract_from_domains(msg):
    addrs = getaddresses(msg.get_all("From", []))
    domains = []
    for _, addr in addrs:
        if "@" in addr:
            domains.append(addr.split("@", 1)[1].strip().strip(">"))
    # de-duplicate, preserve order
    return list(dict.fromkeys(d for d in domains if d))


def parse_authentication_results(msg):
    # Very tolerant parsing of Authentication-Results into key=value tokens
    ars = msg.get_all("Authentication-Results") or []
    parsed = []
    token_re = re.compile(r"([a-zA-Z][a-zA-Z0-9_-]*)=([^;\s]+)")
    for ar in ars:
        entry = {"raw": ar, "tokens": {}}
        for m in token_re.finditer(ar):
            k = m.group(1).lower()
            v = m.group(2)
            entry["tokens"].setdefault(k, []).append(v)
        parsed.append(entry)
    return parsed


def pick_authserv(ars, prefer_contains=None):
    # Choose which Authentication-Results to trust
    if prefer_contains:
        for ar in ars:
            if prefer_contains in ar["raw"]:
                return ar
    return ars[0] if ars else None


def ar_result(ars_entry, mech):
    # Return list of results like ['pass', 'fail'] found for given mech
    if not ars_entry:
        return []
    raw = ars_entry["raw"]
    m = re.findall(fr"{mech}\s*=\s*([a-zA-Z0-9_-]+)", raw, flags=re.IGNORECASE)
    return [r.lower() for r in m]


def ar_param(ars_entry, key):
    if not ars_entry:
        return []
    return ars_entry["tokens"].get(key.lower(), [])


# -----------------------
# Authentication checks
# -----------------------

def check_spf(headers_ci, ars_best=None):
    # Prefer Authentication-Results spf=
    ar_spf = ar_result(ars_best, "spf") if ars_best else []
    if ar_spf:
        res = ar_spf[0]
        text = f"SPF (A-R): {res.upper()}"
        color = "green" if res == "pass" else ("red" if res == "fail" else "yellow")
        return res, colored(text, color)

    # Fallback: Received-SPF
    spf_header = headers_ci.get("received-spf")
    if spf_header:
        low = spf_header.lower()
        if "pass" in low:
            return "pass", colored("SPF (Received-SPF): PASS", "green")
        if "fail" in low:
            return "fail", colored("SPF (Received-SPF): FAIL", "red")
        if "softfail" in low:
            return "softfail", colored("SPF (Received-SPF): SOFTFAIL", "yellow")
        if "neutral" in low:
            return "neutral", colored("SPF (Received-SPF): NEUTRAL", "yellow")
        return "unknown", colored("SPF: Unknown from Received-SPF", "yellow")

    return "none", colored("SPF: No result found (no A-R, no Received-SPF)", "yellow")


def check_dkim(raw_email, msg, ars_best=None, attempt_verify=False):
    # Prefer Authentication-Results dkim=
    ar_dkim = ar_result(ars_best, "dkim") if ars_best else []
    ar_details = {
        "header.d": ar_param(ars_best, "header.d") if ars_best else [],
        "header.s": ar_param(ars_best, "header.s") if ars_best else [],
    }
    if ar_dkim:
        res = ar_dkim[0]
        d_val = ar_details["header.d"] if ar_details["header.d"] else None
        s_val = ar_details["header.s"] if ar_details["header.s"] else None
        detail = ""
        if d_val:
            detail += f" d={d_val}"
        if s_val:
            detail += f" s={s_val}"
        color = "green" if res == "pass" else ("red" if res == "fail" else "yellow")
        return res, colored(f"DKIM (A-R): {res.upper()}{detail}", color), ar_details

    # Optional direct verification if available
    if attempt_verify and dkim_lib is not None:
        try:
            ok = dkim_lib.verify(raw_email)
            return ("pass" if ok else "fail",
                    colored(f"DKIM (direct): {'PASS' if ok else 'FAIL'}", "green" if ok else "red"),
                    ar_details)
        except Exception:
            return "none", colored("DKIM: Not present or cannot verify", "yellow"), ar_details

    # Fallback: Signature presence only
    dkim_headers = msg.get_all("DKIM-Signature") or []
    if dkim_headers:
        return "none", colored("DKIM: Signature present (verification not performed)", "yellow"), ar_details
    return "none", colored("DKIM: Not present", "yellow"), ar_details


def parse_dmarc_record(domain, timeout=5.0):
    if dns is None:
        return None
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        name = f"_dmarc.{domain}"
        answers = resolver.resolve(name, "TXT")
        txt = "".join(part.decode() if isinstance(part, bytes) else part
                      for r in answers for part in r.strings)
        tags = {}
        for seg in re.split(r"\s*;\s*", txt.strip()):
            if "=" in seg:
                k, v = seg.split("=", 1)
                tags[k.strip().lower()] = v.strip()
        return {"domain": domain, "raw": txt, "tags": tags}
    except Exception:
        return None


def check_dmarc(msg, ars_best=None, dns_lookup=True):
    # Prefer A-R dmarc=
    ar_dmarc = ar_result(ars_best, "dmarc") if ars_best else []
    ar_org = {
        "header.from": ar_param(ars_best, "header.from") if ars_best else [],
        "policy.p": ar_param(ars_best, "policy.p") if ars_best else [],
    }
    if ar_dmarc:
        res = ar_dmarc[0]
        from_val = ar_org["header.from"] if ar_org["header.from"] else None
        pol_val = ar_org["policy.p"] if ar_org["policy.p"] else None
        detail = ""
        if from_val:
            detail += f" from={from_val}"
        if pol_val:
            detail += f" p={pol_val}"
        color = "green" if res == "pass" else ("red" if res == "fail" else "yellow")
        return res, colored(f"DMARC (A-R): {res.upper()}{detail}", color), None

    # If no A-R, attempt DNS to report policy presence (not a pass/fail)
    domains = extract_from_domains(msg)
    dmarc_info = None
    if dns_lookup and domains:
        dmarc_info = parse_dmarc_record(domains)

    if dmarc_info:
        tags = dmarc_info["tags"]
        pol = tags.get("p")
        return "record_present", colored(f"DMARC: record found p={pol or 'n/a'}", "cyan"), dmarc_info

    return "none", colored("DMARC: No record found (no A-R, DNS lookup none)", "yellow"), None


# -----------------------
# Main analysis function
# -----------------------

def analyze_headers(file_path, output_json=False, prefer_authserv_contains=None, dkim_verify=False, dns_timeout=5.0):
    raw_email, msg = _parse_eml(file_path)

    # Case-insensitive headers map (single value per header name)
    hdrs_ci = {}
    for k, v in msg.items():
        hdrs_ci[k.lower()] = str(v) if v is not None else ""

    # Authentication-Results parsing
    ars = parse_authentication_results(msg)
    ars_best = pick_authserv(ars, prefer_contains=prefer_authserv_contains)

    # Checks
    print(colored("[*] Performing SPF check...", "cyan"))
    spf_status, spf_text = check_spf(hdrs_ci, ars_best)
    print(spf_text)

    print(colored("\n[*] Performing DKIM check...", "cyan"))
    dkim_status, dkim_text, dkim_details = check_dkim(
        raw_email, msg, ars_best=ars_best, attempt_verify=dkim_verify
    )
    print(dkim_text)

    print(colored("\n[*] Performing DMARC check...", "cyan"))
    dmarc_status, dmarc_text, dmarc_info = check_dmarc(msg, ars_best=ars_best, dns_lookup=True)
    print(dmarc_text)

    # DKIM signatures present (list d= and s=) for context
    dkim_sigs = []
    for h in msg.get_all("DKIM-Signature") or []:
        d = re.search(r"\bd=([^;]+)", h)
        s = re.search(r"\bs=([^;]+)", h)
        dkim_sigs.append({"d": d.group(1) if d else None, "s": s.group(1) if s else None})

    # ARC presence
    arc_present = bool(msg.get_all("ARC-Seal") or msg.get_all("ARC-Message-Signature"))

    # Key headers subset (string-safe joins)
    key_headers = {}
    def _join(vals):
        return " | ".join([str(x) for x in vals]) if vals else None

    for k in ("From", "To", "Subject", "Return-Path", "Received-SPF"):
        s = _join(msg.get_all(k) or [])
        if s:
            key_headers[k] = s
    if ars:
        key_headers["Authentication-Results"] = " || ".join([a["raw"] for a in ars if a.get("raw")])

    # Verdict logic
    issues = []
    reasons = []

    # If A-R says DMARC=pass, treat as authenticated
    if ar_result(ars_best, "dmarc")[:1] == ["pass"]:
        verdict = "authenticated"
    else:
        if dkim_status != "pass" and spf_status != "pass":
            verdict = "unauthenticated"
            issues.extend(["SPF", "DKIM"])
            reasons.append("Neither SPF nor DKIM passed")
        else:
            verdict = "partially_authenticated"
            if dkim_status != "pass":
                issues.append("DKIM")
                reasons.append("DKIM did not pass")
            if spf_status != "pass":
                issues.append("SPF")
                reasons.append("SPF did not pass")
        # DMARC record presence but no DMARC pass suggests alignment may be failing
        if dmarc_status in ("none", "record_present"):
            issues.append("DMARC")
            reasons.append("DMARC not passed or not evaluated")

    print(colored("\n[*] Overall Analysis Result:", "cyan"))
    if issues:
        print(colored(f"Issues: {', '.join(dict.fromkeys(issues))}", "red"))
        for r in reasons:
            print(colored(f"- {r}", "red"))
    else:
        print(colored("No major issues detected.", "green"))

    # Authentication summary
    print(colored("\n[*] Authentication Details:", "cyan"))
    print(f"SPF: {spf_status}")
    print(f"DKIM: {dkim_status}")
    print(f"DMARC: {dmarc_status}")

    # Metadata
    date_iso = None
    if msg.get("Date"):
        try:
            dt = parsedate_to_datetime(msg.get("Date"))
            date_iso = dt.astimezone().isoformat() if dt.tzinfo else dt.isoformat()
        except Exception:
            pass

    result = {
        "verdict": verdict,
        "issues": list(dict.fromkeys(issues)),
        "reasons": reasons,
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
        },
        "authentication_results": [a["raw"] for a in ars],
        "dkim": {
            "signatures": dkim_sigs,
            "ar_details": dkim_details,
        },
        "dmarc": {
            "dns_record": dmarc_info or None,
        },
        "arc_present": arc_present,
        "from_domains": extract_from_domains(msg),
        "headers": {
            "subject": _dec(msg.get("Subject")),
            "from": _dec(msg.get("From")),
            "to": _dec(msg.get("To")),
            "date": date_iso or msg.get("Date"),
            "message_id": msg.get("Message-ID") or msg.get("Message-Id"),
        },
        "key_headers": key_headers,
    }

    if output_json:
        print(colored("\n[*] Overall Analysis Result (JSON):", "cyan"))
        print(json.dumps(result, indent=2, ensure_ascii=False))

    return result


# -----------------------
# Polished pretty-printer
# -----------------------

def _first(lst, default=None):
    return lst[0] if lst else default

def _extract_authserv_id(ar_raw: str | None) -> str | None:
    # Heuristic: authserv-id is the first token before the first semicolon
    if not ar_raw:
        return None
    head = ar_raw.split(";", 1).strip()
    return head or None

def _color_status(name: str, val: str) -> str:
    v = (val or "").lower()
    if v == "pass" or v == "authenticated":
        return colored(f"{name}: {val.upper()}", "green")
    if v in ("fail", "permerror", "temperror", "softfail", "unauthenticated"):
        return colored(f"{name}: {val.upper()}", "red")
    if v in ("none", "neutral", "record_present", "partially_authenticated", "unknown"):
        return colored(f"{name}: {val.upper()}", "yellow")
    return f"{name}: {val}"

def _fmt_kv(k, v):
    return f"{colored(k+':','yellow')} {v}"

def print_headers_pretty(result: dict):
    hdrs = result.get("headers", {})
    verdict = result.get("verdict", "")
    auth = result.get("authentication", {})
    ars_raw_list = result.get("authentication_results", []) or []
    dkim = result.get("dkim", {}) or {}
    from_domains = result.get("from_domains", []) or []
    key_headers = result.get("key_headers", {}) or {}

    # Banner with core metadata
    print(colored("[*] header_analyzer v1.0", "cyan"))
    print(_fmt_kv("Subject", hdrs.get("subject") or "-"))
    print(_fmt_kv("From", hdrs.get("from") or "-"))
    print(_fmt_kv("To", hdrs.get("to") or "-"))
    print(_fmt_kv("Date", hdrs.get("date") or "-"))
    print("")

    # Authentication summary (compact)
    print(colored("[*] Authentication summary", "cyan"))
    print("  " + _color_status("SPF", auth.get("spf", "-")))
    print("  " + _color_status("DKIM", auth.get("dkim", "-")))
    print("  " + _color_status("DMARC", auth.get("dmarc", "-")))
    # Show which A-R was used (best) if available
    ar_used = _first(ars_raw_list)
    authserv_id = _extract_authserv_id(ar_used) if ar_used else None
    if authserv_id:
        print(f"  {colored('Authserv-ID:','yellow')} {authserv_id}")
    print("")

    # Alignment hints (From vs smtp.mailfrom vs DKIM d=)
    print(colored("[*] Alignment hints", "cyan"))
    from_dom = _first(from_domains, "-")
    smtp_mailfrom = None
    header_d = None
    if ar_used:
        m = re.search(r"smtp\.mailfrom=([^;\s]+)", ar_used, flags=re.IGNORECASE)
        if m:
            smtp_mailfrom = m.group(1)
        m2 = re.search(r"header\.d=([^;\s]+)", ar_used, flags=re.IGNORECASE)
        if m2:
            header_d = m2.group(1)
    print(f"  From domain:      {from_dom or '-'}")
    print(f"  SPF MAIL FROM:    {smtp_mailfrom or '-'}")
    print(f"  DKIM d= domain:   {header_d or _first(dkim.get('ar_details', {}).get('header.d', [])) or '-'}")

    spf_pass = (auth.get("spf") == "pass")
    dkim_pass = (auth.get("dkim") == "pass")
    aligned_notes = []
    if spf_pass and smtp_mailfrom and from_dom and smtp_mailfrom.lower().endswith(from_dom.lower()):
        aligned_notes.append("SPF aligned")
    if dkim_pass and header_d and from_dom and header_d.lower().endswith(from_dom.lower()):
        aligned_notes.append("DKIM aligned")
    if aligned_notes:
        print("  " + colored(", ".join(aligned_notes), "green"))
    else:
        print("  " + colored("No alignment confirmed", "yellow"))
    print("")

    # Key headers (curated)
    print(colored("[*] Key headers", "cyan"))
    for k in ("From", "To", "Subject", "Return-Path", "Received-SPF", "Authentication-Results"):
        if k in key_headers and key_headers[k]:
            print(f"  {colored(k+':','yellow')} {key_headers[k]}")
    print("")

    # Verdict
    print(colored("[*] Verdict", "cyan"))
    print("  " + _color_status("Result", verdict))
    reasons = result.get("reasons", []) or []
    for r in reasons:
        print("  - " + colored(r, "red"))
    issues = result.get("issues", []) or []
    if issues:
        print("  " + colored("Issues: " + ", ".join(issues), "red"))

    # One-liner summary
    spf_s = auth.get("spf", "-")
    dkim_s = auth.get("dkim", "-")
    dmarc_s = auth.get("dmarc", "-")
    print("")
    print(colored(f"[*] Summary: {verdict} | SPF={spf_s} DKIM={dkim_s} DMARC={dmarc_s} | from={from_dom} mailfrom={smtp_mailfrom or '-'}", "cyan"))
