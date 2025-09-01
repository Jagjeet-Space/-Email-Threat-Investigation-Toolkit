This script is a complete IOC (Indicator of Compromise) extraction utility. It's designed to analyze .eml or .msg email files, as well as text, PDF, Word, or Excel files, extracting IPs, URLs, and domains from headers, body content, and attachments. It also supports pretty CLI output, CSV/JSON exports, and attachment metadat (hashes + mimetype)

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


