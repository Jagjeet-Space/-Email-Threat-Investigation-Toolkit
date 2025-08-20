# PhishScan

A professional CLI tool to analyze email headers,body and attachments for catching phishing indicators.

Below is chart that how Phishscan work.



                +---------------------+
                |  Input: .eml Email  |
                +---------------------+
                           |
                           v
                 +--------------------+
                 |  Header Analyzer   |
                 |  - SPF/DKIM/DMARC  |
                 |  - Key headers     |
                 +--------------------+
                           |
                           v
                 +--------------------+
                 |   IOC Extractor     |
                 |  - URLs            |
                 |  - IPs             |
                 |  - Domains         |
                 +--------------------+
                           |
                           v
                 +--------------------+
                 | Attachment Analyzer |
                 |  - Extract parts    |
                 |  - Hashes/Entropy   |
                 |  - Magic/ClamAV     |
                 +--------------------+
                           |
                           v
                 +--------------------+
                 |  Output / Reports   |
                 |  - Pretty Console  |
                 |  - JSON Summary    |
                 |  - Saved Attachments|
                 +--------------------+


                 

| Module                  | Inputs                         | Outputs                           | Connected To            |
| ----------------------- | ------------------------------ | --------------------------------- | ----------------------- |
| **Header Analyzer**     | `.eml` email file              | Verdict, Key headers, Auth status | IOC Extractor, Reports  |
| **IOC Extractor**       | Key headers, body, attachments | IPs, URLs, Domains, Threat links  | Reports                 |
| **Attachment Analyzer** | `.eml` email file              | Attachment info, hashes, flags    | Reports                 |
| **Reports / Output**    | Data from all modules          | JSON, console output, saved files | End user / SOC analysts |




# Data Flow Explanation

**Input:** Email in .eml format is fed into the toolkit.

**Header Analysis:** Extracts sender info, authentication (SPF/DKIM/DMARC), and key headers.

**IOC Extraction:** Looks through headers, body, and attachments for indicators of compromise (URLs, IPs, domains).

**Attachment Analysis:** Extracts, hashes, scans, and analyzes attachments (entropy, magic type, ClamAV scan).

**Output:** Everything is consolidated in a structured JSON report and optionally printed in a human-friendly console format. Attachments may also be saved to disk.




## Installation

`pip install phishscan`

## Usage

`phishscan -f <path_to_email.eml>`
