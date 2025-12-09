# Digital Dust - Cybersecurity Portfolio

## About Me

Cybersecurity student at Auckland University of Technology (AUT) majoring in **Cybersecurity and Networks**

Currently building practical investigation skills through hands-on malware analysis, threat intelligence, and incident response scenarios while pursuing industry certifications.

**Location:** Auckland, New Zealand  
**Focus Areas:** SOC Analysis, DFIR, Malware Analysis, Threat Hunting  
**Certifications in Progress:** CompTIA Security+ (Target: Q1 2026)

---

## Learning Technical Skills

**SIEM & Detection:**
- Log analysis and correlation
- SIEM platforms (Wazuh, Splunk fundamentals)
- Alert triage and investigation
- Detection rule creation

**Threat Intelligence:**
- OSINT (VirusTotal, Hybrid Analysis, AbuseIPDB)
- IOC extraction and documentation
- Malware behavior analysis
- MITRE ATT&CK framework mapping

**Incident Response:**
- Phishing analysis
- Malware investigation
- Forensic artifact collection
- Attack chain reconstruction
- Containment and remediation

**Technical Tools:**
- **Scripting:** PowerShell, Bash, Python
- **Networking:** Cisco networking, Wireshark, packet analysis
- **Forensics:** FTK Imager, Volatility, log parsers
- **Platforms:** Windows, Linux, VMware

---

## Featured Investigations

### [SOC146 - Phishing Mail Detected - Excel 4.0 Macros](./LetsDefend/SOC146/)
**Severity:** High | **Type:** Exchange | **Malware:** Trojan.Buzus.Iba

Analyzed sophisticated multi-stage phishing attack using Excel 4.0 macros (evasion technique) to deliver trojan malware. Mapped **17 MITRE ATT&CK techniques** across 9 tactics. Identified C2 infrastructure spanning multiple countries.

**Key Findings:**
- Excel 4.0 macros bypassed standard email security
- Multi-stage payload: Excel file → DLL side-loading → C2 communication
- API hooking for credential theft
- Persistence via registry modification
- International C2 servers (Sri Lanka, Romania)

**Skills Demonstrated:** Email header analysis, malware reverse engineering, threat intelligence correlation, MITRE ATT&CK mapping, IOC documentation, incident containment

---

### [SOC165 - Possible SQL Injection Payload Detected](./LetsDefend/SOC165/)
**Severity:** High | **Type:** Web Attack | **Status:** Blocked

Manual SQL injection attempts targeting web application search functionality. Attacker tested 5 distinct injection techniques over 4-minute period. All attempts blocked by application security controls.

**Techniques Observed:**
- Error-based SQLi, Boolean-based blind SQLi, Tautology attacks
- MITRE: T1190 (Exploit Public-Facing Application)

**Skills Demonstrated:** Web attack analysis, SQL injection recognition, log correlation, attacker TTP identification

---

### [SOC166 - Javascript Code Detected in Requested URL](./LetsDefend/SOC166/)
**Severity:** Medium | **Type:** Web Attack | **Status:** Blocked

JavaScript injection attempt via URL parameter. Server security controls detected malicious input and redirected (HTTP 302), preventing XSS execution.

**Skills Demonstrated:** XSS payload analysis, HTTP response code interpretation, URL decoding, defensive control validation

---

## Current Learning Projects

- **Home Lab:** Building SOC environment with Wazuh SIEM, attacker/victim VMs, and network monitoring
- **Security+ Certification:** CompTIA Security+ study (targeting early/mid 2026)
- **Continuous Training:** LetsDefend, TryHackMe, CyberDefenders challenges

---

## Additional Resources

The [Notes](./Notes/) folder contains:
- **Dynamic Malware Analysis** - Techniques and methodologies
- **Procmon Quick Guide** - Windows process monitoring reference
- Personal study materials and quick-reference guides

---

## Education & Certifications

**Current Education:**
- Bachelor of Computer and Information Sciences (Cybersecurity & Networks)
- Auckland University of Technology (AUT)
- Expected Graduation: June 2026

**Certifications & Training:**
- CompTIA Security+ *(In Progress - Q1 2026)*
- Cisco Networking Academy - Network Security Badge
- LetsDefend SOC Analyst Training *(In Progress)*
- TryHackMe SOC Level 1 Path *(In Progress)*

---

## 📬 Contact

**LinkedIn:** [Link](https://www.linkedin.com/in/rochelle-mitchell-683816250/)

**Location:** Auckland, New Zealand

Open to SOC Analyst / Junior DFIR opportunities in New Zealand and Australia.

---

## Portfolio Statistics

- **Investigations Documented:** 4+ (growing)
- **MITRE ATT&CK Techniques Mapped:** 20+
- **Malware Families Analyzed:** 3+
- **Repository Last Updated:** December 2025

---

*This portfolio demonstrates practical cybersecurity investigation skills developed through hands-on analysis and documentation. All investigations are based on training scenarios and sanitized data.*
