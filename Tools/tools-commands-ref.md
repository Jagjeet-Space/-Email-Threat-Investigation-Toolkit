# 🎯 Tools & Commands Reference

> **Comprehensive reference for tools and commands used in email threat investigation**

## 📧 Email Analysis Tools

### Command Line Tools

#### **Email File Processing**
```bash
# View raw email content
cat suspicious_email.eml

# Extract headers only (first 50 lines typically)
head -50 suspicious_email.eml

# Search for specific patterns
grep -i "authentication-results" suspicious_email.eml
grep -E "spf|dkim|dmarc" suspicious_email.eml -i

# Extract all URLs from email
grep -oP 'https?://\S+' suspicious_email.eml

# Extract all IP addresses  
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" suspicious_email.eml

# Extract all email addresses
grep -oE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b" suspicious_email.eml
```

#### **Email Header Parsing**
```bash
# Python one-liner for header extraction
python3 -c "import email; import sys; msg = email.message_from_file(sys.stdin); print('\n'.join([f'{k}: {v}' for k, v in msg.items()]))" < email.eml

# Extract specific headers
python3 -c "import email; import sys; msg = email.message_from_file(sys.stdin); print('From:', msg['From']); print('Return-Path:', msg['Return-Path']); print('Reply-To:', msg['Reply-To'])" < email.eml
```

---

## 🌐 DNS Investigation Tools

### Command Line DNS Tools

#### **SPF Record Analysis**
```bash
# Check SPF record for domain
dig TXT domain.com | grep "v=spf1"

# More specific SPF lookup
dig TXT domain.com | grep -i spf

# Check multiple DNS servers
dig @8.8.8.8 TXT domain.com | grep spf
dig @1.1.1.1 TXT domain.com | grep spf
```

#### **DMARC Policy Lookup**
```bash
# Check DMARC policy
dig TXT _dmarc.domain.com

# Formatted DMARC output
dig TXT _dmarc.domain.com | grep "v=DMARC1" | tr ';' '\n'
```

#### **DKIM Selector Lookup** (if selector known)
```bash
# Common DKIM selectors to try
dig TXT default._domainkey.domain.com
dig TXT google._domainkey.domain.com
dig TXT k1._domainkey.domain.com
dig TXT selector1._domainkey.domain.com
```

#### **Mail Server Investigation**
```bash
# Get mail exchange servers
dig MX domain.com

# Get all DNS records
dig ANY domain.com

# Reverse DNS lookup
dig -x IP_ADDRESS

# Trace DNS resolution
dig +trace domain.com
```

---

## 🔍 Domain & IP Investigation

### WHOIS Lookups
```bash
# Domain WHOIS
whois domain.com

# IP WHOIS
whois IP_ADDRESS

# Extract registration date
whois domain.com | grep -i "creation\|created\|registered"

# Extract registrar info
whois domain.com | grep -i "registrar"

# Extract nameservers
whois domain.com | grep -i "name server\|nameserver"
```

### Geolocation Tools
```bash
# IP geolocation (requires curl)
curl ipinfo.io/IP_ADDRESS

# More detailed geolocation
curl "http://ip-api.com/json/IP_ADDRESS"

# GeoIP lookup using geoiplookup (if installed)
geoiplookup IP_ADDRESS
```

### Network Analysis
```bash
# Traceroute to IP
traceroute IP_ADDRESS

# Network route analysis
mtr IP_ADDRESS

# Port scanning (use responsibly)
nmap -p 25,80,443 IP_ADDRESS
```

---

## 🛡️ Online Analysis Tools

### Email Header Analyzers
| Tool | URL | Use Case |
|------|-----|----------|
| **MXToolbox** | https://mxtoolbox.com/EmailHeaders.aspx | Comprehensive header analysis |
| **Google Admin Toolbox** | https://toolbox.googleapps.com/apps/messageheader/ | Google Workspace users |
| **Microsoft Header Analyzer** | https://mha.azurewebsites.net/ | Microsoft-focused analysis |
| **Mail Header Analyzer** | https://mailheader.org/ | Simple, clean interface |

### Reputation Checking
| Service | URL | Purpose |
|---------|-----|---------|
| **VirusTotal** | https://virustotal.com | URL/IP/Domain reputation |
| **AbuseIPDB** | https://abuseipdb.com | IP reputation database |
| **URLVoid** | https://urlvoid.com | URL reputation checker |
| **Talos Intelligence** | https://talosintelligence.com | Cisco threat intelligence |
| **IBM X-Force** | https://exchange.xforce.ibmcloud.com | IBM threat intelligence |

### DNS Tools
| Tool | URL | Function |
|------|-----|----------|
| **DNSChecker** | https://dnschecker.org | Global DNS propagation |
| **MXToolbox** | https://mxtoolbox.com | DNS record lookup |
| **What's My DNS** | https://whatsmydns.net | DNS propagation checker |
| **DNS Dumpster** | https://dnsdumpster.com | DNS reconnaissance |

---

## 🐍 Python Scripts

### Quick Email Analysis 
```python
#!/usr/bin/env python3
import email
import sys

# Parse email from stdin
msg = email.message_from_file(sys.stdin)

# Extract key headers
headers = ['From', 'To', 'Subject', 'Date', 'Return-Path', 'Reply-To', 'Message-ID']
for header in headers:
    value = msg.get(header, 'Not Found')
    print(f"{header}: {value}")

# Extract authentication results
auth_results = msg.get('Authentication-Results', 'No authentication results')
print(f"\nAuthentication-Results: {auth_results}")
```

### IOC Extraction Script
```python
#!/usr/bin/env python3
import re
import sys

content = sys.stdin.read()

# Regex patterns
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
url_pattern = r'https?://[^\s<>"]{2,}'
domain_pattern = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'

# Extract IOCs
ips = re.findall(ip_pattern, content)
urls = re.findall(url_pattern, content)
domains = re.findall(domain_pattern, content)

print("IPs found:", set(ips))
print("URLs found:", set(urls))
print("Domains found:", set(domains))
```

---

## 📊 Data Processing Commands

### CSV/Text Processing
```bash
# Create IOC list from email
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" *.eml | sort -u > suspicious_ips.txt

# Extract domains to CSV
echo "Domain,Source,Date" > domains.csv
grep -oE "\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b" *.eml | awk -F: '{print $2","$1","$(date +%Y-%m-%d)}' >> domains.csv

# Combine multiple IOC files
cat *.txt | sort | uniq > combined_iocs.txt
```

### Log Analysis
```bash
# Search mail logs for specific domain
grep "suspicious-domain.com" /var/log/mail.log

# Check for authentication failures
grep -i "spf\|dkim\|dmarc" /var/log/mail.log | grep -i fail

# Extract unique sender IPs from logs
awk '/from/ {print $6}' /var/log/mail.log | sort | uniq -c | sort -nr
```

---

## 🔧 Automation Scripts

### Bulk Email Analysis
```bash
#!/bin/bash
# analyze_emails.sh - Bulk email analysis script

for email_file in *.eml; do
    echo "Analyzing: $email_file"
    echo "====================" 
    
    # Extract key info
    echo "From: $(grep '^From:' "$email_file")"
    echo "Subject: $(grep '^Subject:' "$email_file")"
    
    # Check authentication
    auth=$(grep -i "authentication-results" "$email_file")
    if [[ $auth == *"fail"* ]]; then
        echo "❌ Authentication FAILED"
    else
        echo "✅ Authentication OK"
    fi
    
    # Extract IOCs
    urls=$(grep -oE 'https?://[^\s<>"]+' "$email_file" | wc -l)
    echo "URLs found: $urls"
    
    echo ""
done
```

### Reputation Checking Script
```bash
#!/bin/bash
# check_reputation.sh - Check IP/domain reputation

check_ip() {
    ip=$1
    echo "Checking IP: $ip"
    
    # AbuseIPDB check (requires API key)
    # curl -G https://api.abuseipdb.com/api/v2/check \
    #   --data-urlencode "ipAddress=$ip" \
    #   -H "Key: YOUR_API_KEY"
    
    # VirusTotal check (requires API key)
    # curl -X GET "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=YOUR_API_KEY&ip=$ip"
    
    # Free geolocation
    curl -s "http://ip-api.com/json/$ip" | python3 -m json.tool
}

# Usage: ./check_reputation.sh 192.168.1.1
check_ip $1
```

---

## 📱 Browser Extensions & Tools

### Useful Browser Extensions
- **MXToolbox**: Quick DNS/email tools
- **VirusTotal**: Right-click URL scanning  
- **ClearURLs**: Remove tracking parameters
- **uBlock Origin**: Block malicious domains

### Email Client Tools
- **Thunderbird**: View source, analyze headers
- **Outlook**: Message properties, internet headers
- **Gmail**: Show original, download .eml files

---

## 🚨 Incident Response Commands

### Quick IOC Blocking
```bash
# Add domain to hosts file (local blocking)
echo "127.0.0.1 malicious-domain.com" >> /etc/hosts

# Firewall blocking (iptables)
iptables -A OUTPUT -d MALICIOUS_IP -j DROP

# DNS blocking (if using Pi-hole)
echo "MALICIOUS_DOMAIN" >> /etc/pihole/blacklist.txt
pihole -g
```

### Evidence Collection
```bash
# Create investigation folder with timestamp
mkdir "investigation_$(date +%Y%m%d_%H%M%S)"

# Copy email with metadata preserved
cp --preserve=timestamps suspicious_email.eml investigation_folder/

# Create evidence hash
sha256sum suspicious_email.eml > evidence_hashes.txt

# Archive investigation
tar -czf "investigation_$(date +%Y%m%d_%H%M%S).tar.gz" investigation_folder/
```

---

## 🎓 Learning Resources

### Command Line References
```bash
# Get help for any command
man dig
dig --help
whois --help

# Quick DNS record type reference
# A     - IPv4 address
# AAAA  - IPv6 address  
# MX    - Mail exchange
# TXT   - Text records (SPF, DMARC, DKIM)
# NS    - Name servers
# CNAME - Canonical name (alias)
```

### Regex Patterns for IOCs
```bash
# IP addresses
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" 

# URLs
grep -oE "https?://[^\s<>\"']+"

# Email addresses  
grep -oE "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"

# Domains
grep -oE "\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"

# MD5 hashes
grep -oE "\b[a-fA-F0-9]{32}\b"

# SHA256 hashes
grep -oE "\b[a-fA-F0-9]{64}\b"
```

---

## 💡 Pro Tips

### Efficiency Tips
- **Use aliases** for common commands:
  ```bash
  alias checkspf='dig TXT'
  alias checkdmarc='dig TXT _dmarc.'
  alias whoisip='whois'
  ```

- **Create investigation templates**:
  ```bash
  mkdir investigation_template/{evidence,analysis,iocs,reports}
  ```

- **Use tmux/screen** for long-running investigations

### Safety Reminders
- ⚠️ **Never click suspicious links during investigation**
- 🔒 **Use isolated analysis environment when possible**
- 📝 **Document every step of your investigation**
- 🔄 **Verify findings with multiple sources**
- 📊 **Always validate IOCs before taking action**

---

*📚 Keep this reference handy during investigations - master these tools to become a more effective SOC analyst!*