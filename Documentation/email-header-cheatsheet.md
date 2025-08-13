# 📧 Email Header Analysis Cheat Sheet

> **Quick reference guide for SOC analysts performing email header analysis**

## 🔍 Essential Header Fields

### 📬 **Basic Email Information**

| Header Field | Purpose | What to Look For |
|-------------|---------|------------------|
| **From** | Claimed sender address | Spoofed domains, typos in legitimate domains |
| **To** | Recipient address | Multiple recipients, unusual distribution lists |
| **Subject** | Email subject line | Social engineering tactics, urgency indicators |
| **Date** | Send timestamp | Future dates, time zone inconsistencies |
| **Message-ID** | Unique email identifier | Format consistency, domain matching |

### 🛣️ **Email Routing & Path**

| Header Field | Purpose | Analysis Points |
|-------------|---------|-----------------|
| **Return-Path** | Bounce/error recipient | Domain mismatch with sender |
| **Reply-To** | Response destination | Different from sender (potential trap) |
| **Received** | Server relay chain | Read BOTTOM-TO-TOP for email journey |
| **X-Originating-IP** | Original sender IP | Geolocation, reputation check |

### 🔒 **Authentication Headers**

| Header Field | Purpose | Possible Values |
|-------------|---------|-----------------|
| **Received-SPF** | SPF validation result | PASS, FAIL, SOFTFAIL, NEUTRAL, NONE |
| **DKIM-Signature** | Digital signature | Present/absent, validation status |
| **Authentication-Results** | Combined auth status | SPF, DKIM, DMARC results summary |

---

## 🚨 Red Flag Indicators

### ⚠️ **Sender Spoofing Signs**
- **From domain ≠ Return-Path domain**
- **Reply-To domain ≠ From domain** 
- **Message-ID domain ≠ Sender domain**
- **Free email service used for business communications**

### 🛣️ **Suspicious Routing Patterns**
- **Multiple unexpected country hops**
- **Routing through known malicious IPs**
- **Unusual delays between hops**
- **Missing standard received headers**

### 🔐 **Authentication Failures**
```bash
# Critical failure patterns
SPF: FAIL + DKIM: FAIL = HIGH RISK ⚡
DMARC: FAIL with policy=reject = HIGH RISK ⚡
Multiple authentication failures = HIGH RISK ⚡
```

---

## 🔧 Command Line Investigation Tools

### 🌐 **DNS Lookups**

```bash
# Check SPF record
dig TXT domain.com | grep "v=spf1"

# Check DMARC policy  
dig TXT _dmarc.domain.com

# Check DKIM selector (if known)
dig TXT selector._domainkey.domain.com

# Reverse DNS lookup
dig -x IP_ADDRESS

# Get mail exchange servers
dig MX domain.com
```

### 🔍 **Domain Investigation**

```bash
# WHOIS lookup for domain info
whois domain.com

# Check domain registration date
whois domain.com | grep -i "creation\|created"

# Get nameservers
dig NS domain.com

# Trace route to IP
traceroute IP_ADDRESS
```

### 📊 **IP Address Analysis**

```bash
# Get geographical info
curl ipinfo.io/IP_ADDRESS

# Check IP reputation (example with AbuseIPDB API)
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=IP_ADDRESS" \
  -H "Key: YOUR_API_KEY"
```

---

## 📝 Header Analysis Workflow

### Step 1: Extract Headers
```bash
# From .eml file
head -100 suspicious_email.eml

# From command line mail
cat /var/mail/username | head -100
```

### Step 2: Key Field Analysis
```bash
# Quick SPF/DKIM check
grep -i "received-spf\|dkim\|authentication-results" headers.txt

# Extract all IP addresses
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" headers.txt

# Extract all domains  
grep -oE "[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" headers.txt
```

### Step 3: Authentication Analysis
```bash
# Check SPF record for domain
dig TXT sender-domain.com | grep spf1

# Verify claimed sending IP is authorized
# Compare with extracted IPs from headers
```

---

## 📋 Investigation Checklist

### ✅ **Initial Review**
- [ ] Sender address legitimacy
- [ ] Subject line social engineering tactics
- [ ] Urgency or threat language
- [ ] Generic vs. personalized content

### 🔍 **Header Deep Dive**
- [ ] Return-Path matches sender domain
- [ ] Reply-To is consistent with sender
- [ ] Message-ID format and domain alignment
- [ ] Received headers show logical path

### 🛡️ **Authentication Validation**
- [ ] SPF record exists and result
- [ ] DKIM signature present and valid
- [ ] DMARC policy compliance
- [ ] Overall authentication summary

### 🌐 **Infrastructure Analysis**
- [ ] Sending IP reputation and location  
- [ ] Domain age and registration details
- [ ] MX records consistency
- [ ] Nameserver reputation

---

## 🎯 Common Phishing Patterns

### 📧 **PayPal/Financial Phishing**
```
From: service@paypaI.com        # Note: Capital 'i' not 'l'
Subject: Your account has been limited
Authentication: Multiple failures
Urgency: "Act within 24 hours"
```

### 🏢 **Business Email Compromise**
```
From: CEO Name <ceo@company.com>    # Spoofed executive
Reply-To: ceo@similar-domain.co     # Different reply address
Subject: Urgent Wire Transfer
Content: "Please send $50,000 to..."
```

### 🔒 **Credential Harvesting**
```
From: security@microsoft.com       # Spoofed Microsoft
Subject: Security alert for your account
Links: fake-microsoft-login.com    # Malicious domain
Authentication: SPF/DKIM/DMARC fails
```

---

## 📊 Quick Decision Matrix

| SPF | DKIM | DMARC | Risk Level | Action |
|-----|------|-------|------------|--------|
| ✅ PASS | ✅ PASS | ✅ PASS | 🟢 LOW | Allow, minimal monitoring |
| ✅ PASS | ❌ FAIL | ⚠️ SOFTFAIL | 🟡 MEDIUM | Review content, verify sender |
| ❌ FAIL | ❌ FAIL | ❌ FAIL | 🔴 HIGH | Block, investigate immediately |
| ❌ FAIL | ✅ PASS | ✅ PASS | 🟡 MEDIUM | Investigate SPF issues |

---

## 🛠️ Useful Online Tools

### 🔍 **Header Analyzers**
- **MXToolbox Header Analyzer**: https://mxtoolbox.com/EmailHeaders.aspx
- **Google Admin Toolbox**: https://toolbox.googleapps.com/apps/messageheader/
- **Mail Header Analyzer**: https://mha.azurewebsites.net/

### 🌐 **Domain/IP Reputation**
- **VirusTotal**: https://virustotal.com
- **AbuseIPDB**: https://abuseipdb.com
- **Talos Intelligence**: https://talosintelligence.com
- **URLVoid**: https://urlvoid.com

### 🔐 **DNS Tools**
- **DNSChecker**: https://dnschecker.org
- **MXToolbox**: https://mxtoolbox.com
- **What's My DNS**: https://whatsmydns.net

---

*📚 Keep this cheat sheet handy during investigations - speed and accuracy are key in SOC operations!*

---

**📖 Part of the Email Threat Investigation Toolkit**  
*Helping SOC analysts master email security analysis*