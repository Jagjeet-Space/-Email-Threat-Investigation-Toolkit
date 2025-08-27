Email Header Analyzer is one of three scripts that helps in email header analysis. It extract key headers like SPF, DKIM and DMARC authnetication results, checks domain allignment and produces a verdict on whether the email is authenticated or un-authenticated. Also it can analyze normal headers in an email body like sender, reciver etc.

Down below is a full script, we will analyze key secripts modules and function that what each of thwm do.




## Phase 1 Imports andd Optional Dependencies  
```
import re
import json
from typing import Dict, Any, Optional, Tuple, List
from email import policy
from email.parser import BytesParser
from email.header import decode_header, make_header
from email.utils import getaddresses, parsedate_to_datetime
```

- Purpose: Use Python's standard email library to parse raw .eml files.
- *re* regex fro parsing headers
- *json* for structured output
- *typing* improves code clarity with type hints

```
try:
    import dns.resolver
except Exception:
    dns = None
```

- *dnspython* for DMARC DNS lookups will be performed
- If missing, script still works but skips DNS checks.

```
try:
    from termcolor import colored as _colored
except Exception:
    def _colored(t, color=None): return t
```
- Adds colored output for the CLI
- If *termcolor* is missing, text is printed without colors


## Phase 2 Utility Functions

### Header decoding and parsing helpers
```
def _decode_header_value(h): ...
```
- Converts encoded MIME headers like UTF-8 into readable text

```
def _parse_eml_bytes(path): ...
```
- Reads the email file as bytes
- Parses it itno an email.message.EmaiMessage object # Not understood

```
def _normalize_domain(d): ...
```
- Cleans up a domain strings (removes spaces <>, trailing dots, lowercase.

```
def _extract_from_domain(msg): ...
```
- Pulls the sender domain from the *From* header
- Used later for alignment checks and DMARC lookups 


### Key header collection

```
def _gather_headers(msg): ...
```
- Collects Subject, From, To, Date, Return-Path, Received-SPF, Auuthentication-Results into a dictionary.
- If a header appears multiple times, joins them inot one string

Authentication Results helpers

```
def _pick_trusted_ar(msg): ...
```
- Returns the first Authentication-Results header 
- Ensures only a single line is processed

```
def _parse_ar_status(ar_line, mech): ...
```
- Extracts pass, fail, none etc for SPF, DKIM, DMARC from AR line

```
def _parse_ar_param(ar_line, key): ...
```
- Extracts specific parameters like smtp.mailform or header.d= used for allignment checks # didnt understand

### DNS + signature checks 

```
def _has_dkim_signature(msg): ...
```
- Returns True if a DKIM-Signature header is present

```
  def _dmarc_dns(domain, timeout): ...
```
- If DNS is available, queries _dmarc.<domain> TXT records
- Parses DMARC tags (v=DMARC1; p=reject, etc)
- Returns dictionary or None

### Output formatting helpers

```
def _color_status(name, val): ...
```
- Green if PASS, RED if FAIL, yellow if NONE/NEUTRAL
- Adds CLI colors to make results visually clear

```
def _fmt_kv(k, v): ...
```
- Prints headers consistently in key: value format  # didnt understadn that

## Phase 3 Main Analysis Function

```
def analyze_headers(file_path, quiet=True, dns_timeout=5.0) -> Dict[str, Any]:
```

- Core function that does everthing:
  1. Parses email
  2. Extract headers and metedta
  3. Determine SPF, DKIM and DMARC status
  4. Checks domain alignment
  5. Builds a structured result dictionary
 
  ### Key Steps

  1. Parse email & collect basic headers

``` 
raw, msg = _parse_eml_bytes(file_path)
key_headers = _gather_headers(msg)
subject = _decode_header_value(msg.get("Subject"))
```
  2. Get Authentication-Reuslt line

```
ar_used = _pick_trusted_ar(msg)
```
  3. SPF cehck
     - First try AR line > `spf+pass/fails/none`
     - Fallback to `Received-SPF`
  4. DKIM check
     - First try AR line > `dkim=pass/fail/none`
     - Fallback to has `DKIM-Signature header`
  5. DMARC check
     - Try AR line > `dmarc=pass/fail/none`
     - If not present, DNS lookup to see if record exists.
     - If record exists > status = `record_present`
     - Else > status = `none`
  6. Domain alignment
     - Compares the `Form` domain with:
        - SPF's smtp.mailform domain
        - DKIM's header.d domain
     - Flags whether SPF/DKIM are aligned (`True` or `False`
  7. Verdict comoutation
```
if dmarc_status == "pass":
    verdict = "authenticated"
elif neither SPF nor DKIM pass:
    verdict = "unauthenticated"
else:
    verdict = "partially_authenticated"
```
  - Adds issue list: eg ["SPF", "DKIM", "DMARC"]
  - Adds human-readable reasons
  8. Build final result dictionary
    ```
    result = {
    "verdict": ...,
    "issues": ...,
    "headers": {...},
    "authentication": {...},
    "alignment": {...},
    ...
}
    ```
  
## Phase 4 Pretty Printing 

```
def print_headers_pretty(result):
```
- Takes analyze_headers() output and print it in human-readable format
- Shows:
   - Header info: Subject, From, To, Date
   - Authentication: SPF / DKIM / DMARC results, verdict
   - Alignment: whether sender matches SPF/DKIM domains
   - Key headers: Return-Path, Received-SPF, AR used
   - Risk flags: if neither SPF nor DKIM pass, or DMARC is missing.
Color-coded for CLI output using termcolor.








