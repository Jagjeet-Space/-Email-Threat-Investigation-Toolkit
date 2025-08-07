# 🔍 Email Threat Investigation Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/yourusername/email-threat-investigation-toolkit.svg)](https://github.com/yourusername/email-threat-investigation-toolkit/stargazers)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/yourusername/email-threat-investigation-toolkit/issues)

> **A comprehensive SOC Level 1 analyst toolkit for investigating email-based threats including phishing, spoofing, and credential harvesting attacks.**

## 🎯 Project Overview

This repository demonstrates real-world email threat investigation capabilities by simulating the analysis of suspicious emails that would typically be handled by SOC Level 1 analysts. The project showcases technical skills in email forensics, threat detection, and incident response procedures.

### 🚀 Key Features

- **📧 Real-world Email Samples**: 2 phishing emails + 1 legitimate email for comparison
- **🔎 Deep Technical Analysis**: Header inspection, SPF/DKIM/DMARC validation, IOC extraction
- **📊 Professional Documentation**: Detailed analysis reports following SOC procedures
- **🛠️ Automation Tools**: Python scripts for email parsing and IOC extraction
- **📚 Learning Resources**: Cheat sheets and investigation guides

## 📁 Repository Structure

```
Email-Threat-Investigation-Toolkit/
│
├── 📧 Samples/                    # Email samples for analysis
│   ├── Phishing/                  # Malicious email samples
│   └── Safe/                      # Legitimate email samples
│
├── 📋 Analysis/                   # Detailed investigation reports
│   ├── Phishing_Sample_01/
│   ├── Phishing_Sample_02/
│   └── Legitimate_Email_01/
│
├── 🚨 IOCs/                       # Indicators of Compromise
│   ├── extracted_iocs.csv
│   ├── malicious_domains.txt
│   ├── suspicious_ips.txt
│   └── malicious_urls.txt
│
├── 🛠️ Tools/                      # Analysis automation scripts
│   ├── email_analyzer.py
│   ├── ioc_extractor.py
│   └── header_parser.py
│
├── 📚 Documentation/              # Reference guides and cheat sheets
│   ├── email_header_cheatsheet.md
│   ├── soc_investigation_guide.md
│   └── tools_commands_reference.md
│
└── 📊 Results/                    # Investigation findings
    ├── spf_dkim_dmarc_results.md
    ├── investigation_timeline.md
    └── final_report.md
```

## 🎯 Investigation Methodology

This project follows a structured SOC analyst approach:

### 1️⃣ **Initial Assessment**
- Email content review
- Sender reputation check
- Urgency and social engineering indicators

### 2️⃣ **Technical Analysis**
- **Header Inspection**: Received paths, authentication results
- **SPF Validation**: Sender Policy Framework compliance
- **DKIM Analysis**: DomainKeys Identified Mail signature verification
- **DMARC Evaluation**: Domain-based Message Authentication compliance

### 3️⃣ **Threat Intelligence**
- IOC extraction (IPs, domains, URLs, hashes)
- Threat actor pattern identification
- Campaign correlation analysis

### 4️⃣ **Documentation & Reporting**
- Detailed technical findings
- Risk assessment and recommendations
- Executive summary for stakeholders

## 🔧 Tools & Technologies Used

### Core Analysis Tools
- **Email Clients**: Thunderbird, Outlook for .eml/.msg analysis
- **Command Line**: `dig`, `nslookup`, `whois` for DNS investigation
- **Online Services**: VirusTotal, AbuseIPDB, URLVoid for reputation checks

### Programming & Automation
- **Python 3.8+**: Email parsing, IOC extraction, automation
- **Libraries**: `email`, `re`, `dns.resolver`, `requests`
- **Data Analysis**: `pandas`, `csv` for IOC management

### Documentation Tools
- **Markdown**: Professional documentation formatting
- **Git**: Version control and project management
- **GitHub**: Portfolio hosting and collaboration

## 📈 Learning Outcomes

After completing this project, you will demonstrate proficiency in:

✅ **Email Forensics**: Header analysis, authentication mechanism understanding  
✅ **Threat Detection**: Identifying phishing indicators and attack patterns  
✅ **IOC Management**: Extracting and cataloging indicators of compromise  
✅ **Technical Documentation**: Creating professional SOC reports  
✅ **Automation**: Building tools to streamline investigation processes  
✅ **Risk Assessment**: Evaluating and communicating threat levels  

## 🚀 Quick Start Guide

### Prerequisites
```bash
# Python 3.8 or higher
python --version

# Required packages
pip install -r requirements.txt
```

### Running the Analysis
```bash
# Automated email analysis
python Tools/email_analyzer.py Samples/Phishing/phishing_sample_01.eml

# IOC extraction
python Tools/ioc_extractor.py Samples/Phishing/

# Header parsing
python Tools/header_parser.py Samples/Phishing/phishing_sample_01.eml
```

## 📊 Sample Investigation Results

| Email Sample       | Threat Level | SPF    | DKIM      | DMARC  | IOCs Found |
| ------------------ | ------------ | ------ | --------- | ------ | ---------- |
| Phishing Sample 01 | **HIGH**     | ❌ FAIL | ❌ FAIL    | ❌ FAIL | 15         |
| Phishing Sample 02 | **HIGH**     | ❌ FAIL | ❌ NEUTRAL | ❌ FAIL | 12         |
| Legitimate Email   | **LOW**      | ✅ PASS | ✅ PASS    | ✅ PASS | 0          |

## 🎓 For Recruiters & Hiring Managers

This project demonstrates:

- **Technical Expertise**: Email security protocols, threat analysis capabilities
- **Problem-Solving Skills**: Methodical investigation approach, root cause analysis
- **Documentation Standards**: Professional reporting, clear technical communication
- **Automation Mindset**: Tool development for efficiency and accuracy
- **Cybersecurity Awareness**: Understanding of current threat landscape

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## ⚠️ Disclaimer

**Important**: All email samples in this repository are sanitized and use dummy data for educational purposes only. No actual malicious links or payloads are included. This project is intended for cybersecurity education and portfolio demonstration.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Connect With Me

- **LinkedIn**: [Your LinkedIn Profile](https://linkedin.com/in/yourprofile)
- **Email**: your.email@example.com
- **Portfolio**: [Your Portfolio Website](https://yourportfolio.com)

---

**⭐ If you found this project helpful, please consider giving it a star!**

*Built with 💙 by [Your Name] - Aspiring SOC Analyst*