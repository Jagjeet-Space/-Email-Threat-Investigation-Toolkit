This script is a complete IOC (Indicator of Compromise) standalone extraction utility. It's designed to analyze .eml or .msg email files, as well as text, PDF, Word, or Excel files, extracting IPs, URLs, and domains from headers, body content, and attachments. It also supports pretty CLI output, CSV/JSON exports, and attachment metadat (hashes + mimetype).Here is link to [ioc_extarctor.py](../../phishscan/utils/ioc_extractor.py) script.

With integrated to phishscan.py its output all IOCs relaetd to that .eml file.

### Purpose 
- Parse and anlayze email files (.eml, .msg) or arbitrary documents (.txt, .pdf, .docx, .xlsx)
- Extract IOCs (IPs, URLs, domains) from:
  - Email headers
  - Email body text (plain or HTML)
  - Attachments (with optional type detection and hashing)
- Output result in:
  - Pretty colored CLI output (default)
  - JSON format (for API/autmation)
  - CSV format (for spreadsheets)


## Main Features

### 1. Automatic file type detection
- Uses *python-magic* (if available) or extension fallback.
- Supports PDFs Word docs, Excel sheets, and text files.
### 2. Email Parsing
- Uses Python's email library (ByteParser with RFC policy).
- Extract headers, body, and attachments.
### 3. IOC Extraction
- Regex + tldextract (if installed) for accurate domain parsing.
- Collects IPs, URLs, and domains separately for headers, body and attachments.
### 4 Attachment Analysis
- Saves temprarily, computes MD5 and SHA256.
- Reads content (if text-like) for IOC scanning.
- Detects mimetype.
### 5 Graceful Degradation
- If optional libs (tldextract, PyPDF2, python-docx, openpyxl, magic) are missing, the script skips those features but still works.
### CLI Usabilty
- Colored output (using *termcolor*) with *--no-color* toggle.
- *--format* allows switching between pretty, JSON, and CSV.
- Can save results to a JSON file using *--json-out.*


## Key Functions

### IOC Extraction

```
find_iocs(text: str) -> Dict[str, Set[str]]
```
- Scans text for:
  - IP addresses (IPv4)
  - URLs (http/https)
  - Domains (normalized via *tldextract* if available)
- Returns a dicct with sets for internal deduplication.


### File Parsing 

```python
parse_file_content(file_path: str, quiet: bool = False) -> str
```
- Detects file type using *magic* or extension.
- Extracts text depending on file format:
  - Plain text > direct read
  - PDF > uses *PyPDF2.PdfReader*
  - DOCX > uses *python-docx*
  - XLSX > uses *openpyxl*
- Returns raw text (or empty if unsupported).


###  Email IOC Extraction

```python
get_iocs_from_file_or_content(input_data, is_file_path=True, quiet=False)
 -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]
```
- If input is an email file:
  - Extracts headers > scans for IOCs
  - Extract body > scans text parts for IOCs
  - Extracts attachments > saves temporarily > computes hashes + IOCs
- If input is a non-email file or raw textx:
  - Extracts content and scans for IOCs (no header/attachment breakdown).
- Returns *(attributed_iocs, meta)* where:
  - *attributed_iocs* is structured IOC data
  - *meta* is email metadata (subject, from, to, date, etc.)



### Pretty Output
```python
print_iocs_pretty(attributed_iocs: Dict[str, Any], meta: Optional[Dict[str, Any]], colorer)
```

- Displays:
  - IOC summary for headers, body, and attachments.
  - Counts (IPs, URLs, domains).
  - Lists each indicator clearly.
  - Shows attachment mimetype and hashes.


### Command-Line Interface
Basic usage
```python
python analyze_headers.py email.eml
```
- Parses email, extracts IOCs, prints colorized summary.

### Options

- `--raw`
Treat input as raw text instead of a file path.

- `--format {pretty,json,csv}`
Choose output format. Default = pretty.

- `--json-out FILE`
Save results to JSON file.

- `--print-json`
Print JSON to console even if `--format pretty` or CSV is used.

- `--quiet` or `-q`
Suppress diagnostic messages.

- `--no-color`
Disable colored output.

### Examples 
```python
# Pretty output (default)
python analyze_headers.py phishing.eml

# JSON output to console
python analyze_headers.py phishing.eml --format json

# Save JSON to file while printing pretty output
python analyze_headers.py phishing.eml --json-out result.json

# CSV output
python analyze_headers.py phishing.eml --format csv

# Treat input as raw text
python analyze_headers.py "http://malicious.example" --raw
```


## Integration with PhishScan

- This script can be used standalone or imported into PhishScan (ioc_extractor module).
- In PhishScan CLI (phishscan.py), this module provides:
- `get_iocs_from_file_or_content()` for IOC scanning
- `print_iocs_pretty()` for human-readable output







