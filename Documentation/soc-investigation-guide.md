# 🔍 SOC Investigation Guide

> **A comprehensive step-by-step guide for SOC Level 1 analysts investigating suspicious emails**

## 📋 Table of Contents

1. [Initial Assessment](#1-initial-assessment)
2. [Header Analysis](#2-header-analysis)  
3. [Authentication Validation](#3-authentication-validation)
4. [IOC Extraction](#4-ioc-extraction)
5. [Documentation & Reporting](#5-documentation--reporting)

---

## 1️⃣ Initial Assessment

### 🎯 Objectives
- Determine email legitimacy
- Identify immediate threats
- Assess urgency level

### 📝 Checklist

#### Visual Inspection
- [ ] **Sender Information**: Check for typos, suspicious domains, or spoofed addresses
- [ ] **Subject Line**: Look for urgency tactics, poor grammar, or generic subjects
- [ ] **Content Analysis**: Identify social engineering attempts, threats, or urgent requests
- [ ] **Links & Attachments**: Note presence without clicking (analyze separately)

#### Red Flags to Watch For
🚩 **Urgent language**: "Act now", "Immediate action required", "Account will be closed"  
🚩 **Suspicious sender**: Free email domains for business communications  
🚩 **Generic greetings**: "Dear Customer" instead of your name  
🚩 **Poor grammar/spelling**: Professional organizations maintain quality standards  
🚩 **Mismatched URLs**: Hover over links to see actual destinations  

### 📊 Initial Risk Assessment
```
HIGH RISK    🔴 Multiple red flags, clear phishing indicators
MEDIUM RISK  🟡 Some suspicious elements, requires further analysis  
LOW RISK     🟢 Appears legitimate, minimal or no red flags
```

---

## 2️⃣ Header Analysis

### 🎯 Objectives
- Trace email origin and path
- Identify spoofing attempts
- Analyze relay information

### 🔧 Tools Required
- Email client with header viewing capability
- Command line tools: `dig`, `nslookup`, `whois`
- Online tools: MXToolbox, whatismyipaddress.com

### 📝 Analysis Steps

#### Step 1: Extract Full Headers
```bash
# For .eml files
cat email.eml | head -50

# For Outlook (.msg files)  
# Use Outlook > File > Properties > Internet headers
```

#### Step 2: Analyze Key Header Fields

##### **Return-Path Analysis**
```
Return-Path: <bounce@suspicious-domain.com>
```
- [ ] Does the return path domain match the sender domain?
- [ ] Is the domain recently registered? (Check with `whois domain.com`)
- [ ] Is the domain on any blacklists?

##### **Received Headers Analysis** (Read bottom-to-top)
```
Received: from mail.legitimate-bank.com (mail.fake-bank.com [192.168.1.100])
```
- [ ] Do server names match their IP addresses?
- [ ] Are there any unusual routing patterns?
- [ ] Check IP geolocation - does it match expected origin?

##### **Message-ID Analysis**
```
Message-ID: <20231201123456.abc123@domain.com>
```
- [ ] Does the domain in Message-ID match sender domain?
- [ ] Is the format consistent with legitimate email servers?

#### Step 3: Reverse DNS Lookups
```bash
# Check if IP resolves to claimed domain
dig -x 192.168.1.100

# Check domain's actual mail servers
dig MX legitimate-bank.com
```

### 🔍 Common Header Spoofing Indicators
- Mismatched sender domains and Return-Path
- Unusual routing through unexpected countries/servers
- Generic or malformed Message-IDs
- Missing standard email headers

---

## 3️⃣ Authentication Validation

### 🎯 Objectives
- Verify SPF compliance
- Check DKIM signatures
- Evaluate DMARC policy

### 📊 Authentication Methods

#### **SPF (Sender Policy Framework)**
```bash
# Check SPF record
dig TXT domain.com | grep "v=spf1"

# Common SPF results:
# PASS ✅ - IP authorized to send for this domain
# FAIL ❌ - IP not authorized (strong phishing indicator)  
# SOFTFAIL ⚠️ - IP questionable but not explicitly denied
# NEUTRAL 🔄 - No SPF policy or unclear result
```

#### **DKIM (DomainKeys Identified Mail)**
```bash
# Look for DKIM-Signature in headers
grep "DKIM-Signature:" email_headers.txt

# DKIM Results:
# PASS ✅ - Valid digital signature
# FAIL ❌ - Invalid or tampered signature
# NONE 🔄 - No DKIM signature present
```

#### **DMARC (Domain-based Message Authentication)**
```bash
# Check DMARC policy
dig TXT _dmarc.domain.com

# DMARC Actions:
# PASS ✅ - SPF or DKIM aligned and passed
# FAIL ❌ - Authentication failed, check policy action
```

### 🚨 Critical Authentication Red Flags
- **SPF FAIL** + **DKIM FAIL** = High probability of spoofing
- **DMARC policy = reject** but email delivered = Potential security gap
- Missing authentication headers from legitimate organizations

---

## 4️⃣ IOC Extraction

### 🎯 Objectives
- Identify malicious indicators
- Build threat intelligence
- Enable blocking/monitoring

### 🔍 Types of IOCs to Extract

#### **Network Indicators**
```bash
# Extract URLs from email
grep -oP 'https?://\S+' email.eml

# Extract IP addresses  
grep -oP '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b' email.eml

# Extract domains
grep -oP '(?<=@)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' email.eml
```

#### **File-Based Indicators**
- Attachment filenames and extensions
- File hashes (MD5, SHA1, SHA256)
- Suspicious file types (.exe, .scr, .zip with executables)

#### **Email-Specific Indicators**
- Sender email addresses and domains
- Reply-to addresses (if different from sender)
- Message-IDs and other unique identifiers
- Subject line patterns

### 📋 IOC Validation Process
1. **URL Reputation**: Check with VirusTotal, URLVoid
2. **IP Reputation**: Verify with AbuseIPDB, Talos Intelligence
3. **Domain Analysis**: Registration date, registrar, nameservers
4. **File Hash Lookup**: Search in malware databases

---

## 5️⃣ Documentation & Reporting

### 🎯 Objectives
- Create actionable reports
- Document investigation steps
- Provide recommendations

### 📝 Required Documentation

#### **Executive Summary** (For Management)
```markdown
**Incident**: Phishing email targeting credential harvesting
**Risk Level**: HIGH
**Affected Systems**: Email gateway, potentially 50 users
**Recommended Actions**: Block sender domain, user awareness training
**Timeline**: Detected 2023-12-01 14:30, investigation completed 15:45
```

#### **Technical Analysis Report**
- Detailed header analysis findings
- Authentication check results (SPF/DKIM/DMARC)
- IOC extraction results with context
- Attack vector and technique analysis

#### **IOC Summary Table**
| Type | Indicator | Risk Level | Action Taken |
|------|-----------|------------|-------------|
| Domain | fake-bank.com | HIGH | Blocked in firewall |
| IP | 192.168.1.100 | MEDIUM | Added to watch list |
| URL | http://fake-bank.com/login | HIGH | Blocked in web filter |

### 🔄 Recommended Actions

#### **Immediate Actions**
- [ ] Block malicious domains/IPs in security tools
- [ ] Remove email from all affected inboxes
- [ ] Notify potentially affected users
- [ ] Document lessons learned

#### **Long-term Improvements**
- [ ] Update email security policies
- [ ] Enhance user security awareness training
- [ ] Review authentication mechanisms
- [ ] Consider additional email security tools

---

## 🎓 Investigation Best Practices

### ✅ Do's
- Always work on isolated systems when analyzing suspicious content
- Document every step of your investigation process
- Verify findings with multiple sources
- Collaborate with team members for complex cases
- Keep detailed timestamps for all activities

### ❌ Don'ts
- Never click on suspicious links during investigation
- Don't rely on a single indicator for decision-making
- Avoid making assumptions without evidence
- Never skip documenting your methodology
- Don't investigate in production environments

---

## 📞 Escalation Guidelines

### When to Escalate to SOC Level 2
- **Complex Attack Patterns**: Multi-stage campaigns, APT indicators
- **System Compromise Evidence**: Signs of successful payload execution
- **High-Value Targets**: C-level executives, financial personnel affected
- **Unknown Techniques**: Novel attack methods requiring deeper analysis
- **Widespread Impact**: Mass compromise affecting multiple departments

### Escalation Information to Include
- Complete investigation timeline
- All collected evidence and IOCs
- Analysis methodology used
- Preliminary findings and assessment
- Recommended next steps

---

*📚 This guide is part of the Email Threat Investigation Toolkit - helping SOC analysts develop systematic investigation skills.*