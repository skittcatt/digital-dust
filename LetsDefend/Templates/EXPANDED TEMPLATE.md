# [Alert ID] - [Alert Title]

## Executive Summary
[2-3 sentence overview: What happened, was it malicious, what was the outcome]

Example: External attacker attempted SQL injection against internal web server. Attack was blocked by WAF. No system compromise occurred. Source IP has history of malicious activity and has been blocked at perimeter firewall.

---

## Alert Details

| Field                    | Value                       |
| ------------------------ | --------------------------- |
| **Alert ID**             | SOC###                      |
| **Date/Time**            | YYYY-MM-DD HH:MM (timezone) |
| **Severity**             | Critical/High/Medium/Low    |
| **Source IP**            | X.X.X.X                     |
| **Source Hostname**      | [if available]              |
| **Destination IP**       | X.X.X.X                     |
| **Destination Hostname** | [hostname]                  |
| **Protocol**             | HTTP/HTTPS/SMB/etc          |
| **Attack Type**          | [Phishing/Malware/XSS/etc]  |

### Additional Context
- **User-Agent:** [full user agent string]
- **Request Method:** GET/POST/etc
- **Requested URL:** [full URL]
- **HTTP Response Code:** [200/302/403/etc]
- **Other relevant fields:** [anything else noteworthy]

---

## Initial Analysis

### User-Agent Breakdown
[Analyze the user agent if present]

**Operating System:**
- Windows NT X.X = [Windows version]
- [Note if EOL/outdated]

**Browser:**
- [Browser name and version]
- [Note if outdated - compare to current version]

**Architecture:**
- [32-bit/64-bit indicators]

**Red Flags:**
- [List any suspicious elements: outdated OS, unusual browser, inconsistencies]

---

## Investigation Process

### Step 1: Log Analysis
[What logs did you check? What did you find?]

**Logs Reviewed:**
- [Source: Web server logs, firewall logs, etc]
- [Time range checked]

**Key Findings:**
- [Finding 1]
- [Finding 2]
- [Pattern observed: manual vs automated, timing, etc]

**Notable Observations:**
- [HTTP response codes and what they mean]
- [Response sizes]
- [Successful vs failed attempts]

---

### Step 2: Threat Intelligence

**VirusTotal:**
- Detection ratio: X/XX vendors flagged as malicious
- Categories: [Phishing/Malware/Suspicious/etc]
- First submission: [date]
- Last analysis: [date]
- **Key findings:** [what stood out]

**AbuseIPDB:**
- Confidence score: X%
- Reports: X reports
- Categories: [Brute force/Port scan/Web app attack/etc]
- Last reported: [date]
- **Key findings:** [abuse history]

**Additional OSINT:**
- **WHOIS Lookup:**
  - Country: [XX]
  - Organization: [name]
  - Network: [range]
  - Status: [residential/hosting/vpn/etc]

- **Other tools used:** [Cisco Talos, URLhaus, Hybrid Analysis, etc]

---

### Step 3: Payload/Indicator Analysis

**[For URLs/Domains]**
```
Full URL: [URL]

Breakdown:
- Domain: [domain]
- Path: [path structure]
- Parameters: [query parameters]
- Suspicious elements: [what looks wrong]
```

**[For malware/files]**
- File hash: [MD5/SHA256]
- File type: [.exe/.pdf/.docx/etc]
- Sandbox results: [behavior observed]

**[For scripts/code]**
```
Payload: [the actual malicious code]

Intent: [what was it trying to do]
Technique: [injection type, encoding used, etc]
Severity if successful: [potential impact]
```

---

### Step 4: Scope Assessment

**Affected Systems:**
- [List systems that were targeted or compromised]

**User Impact:**
- Users affected: [number/names]
- Systems accessed: [list]
- Data accessed: [Y/N - what data]

**Lateral Movement Check:**
- Other systems accessed from compromised host: [Y/N]
- Unusual network connections: [Y/N - details]
- Privilege escalation attempts: [Y/N - details]

---

## MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name | Evidence |
|--------|--------------|----------------|----------|
| [Tactic name] | [T####] | [Technique name] | [Where you saw this] |
| [Tactic name] | [T####] | [Technique name] | [Where you saw this] |

**Example:**
| Tactic | Technique ID | Technique Name | Evidence |
|--------|--------------|----------------|----------|
| Initial Access | T1566.002 | Phishing: Spearphishing Link | Malicious URL sent via email |
| Execution | T1059.007 | JavaScript | XSS payload in URL parameter |

---

## Timeline of Events

| Time (UTC) | Event | Source |
|------------|-------|--------|
| HH:MM | [What happened] | [Log source] |
| HH:MM | [What happened] | [Log source] |
| HH:MM | [What happened] | [Log source] |

**Pattern Analysis:**
- [Manual vs automated]
- [Time intervals between attempts]
- [Progression of attacker behavior]

---

## Indicators of Compromise (IOCs)

### Network Indicators
- **IP Addresses:**
  - X.X.X.X (attacker source)
  - X.X.X.X (C2 server if applicable)

- **Domains/URLs:**
  - example[.]com
  - malicious[.]url/path

### Host Indicators
- **File Hashes:**
  - MD5: [hash]
  - SHA256: [hash]

- **File Paths:**
  - C:\Path\to\malicious\file.exe

- **Registry Keys:**
  - [if applicable]

- **Processes:**
  - [suspicious process names]

### Other Indicators
- **User-Agent strings:** [if distinctive]
- **Email addresses:** [phishing sender]
- **Patterns:** [URL patterns, naming conventions]

---

## Conclusion

**Verdict:** 
- ☑ True Positive - Malicious
- ☐ True Positive - Suspicious  
- ☐ False Positive - Legitimate activity
- ☐ False Positive - Misconfiguration

**Attack Success:**
- ☑ Attack Blocked/Failed
- ☐ Attack Successful - System Compromised
- ☐ Unknown

**Justification:**
[2-3 sentences explaining your verdict with supporting evidence]

---

## Response Actions Taken

### Immediate Actions
- [x] Alert created (timestamp)
- [x] Endpoint isolated/contained (if applicable)
- [x] User notified (if applicable)
- [ ] Credentials reset
- [ ] [Other immediate actions]

### Investigation Actions
- [x] Logs analyzed
- [x] Threat intelligence gathered
- [x] Scope assessed
- [x] IOCs documented

### Containment Actions
- [ ] Source IP blocked at firewall
- [ ] Malicious domain blocked at DNS/proxy
- [ ] Affected user account disabled
- [ ] Endpoint quarantined
- [ ] [Other containment measures]

---

## Recommendations

### Immediate (Critical - within 24 hours)
1. [Action item with specific details]
2. [Action item with specific details]

### Short-term (within 1 week)
1. [Action item]
2. [Action item]

### Long-term (ongoing/strategic)
1. [Action item]
2. [Action item]

**Example:**
### Immediate
1. Block source IP X.X.X.X at perimeter firewall
2. Reset credentials for user "ellie@letsdefend.io"
3. Scan endpoint HOSTNAME for additional IOCs

### Short-term
1. Update Windows 7 systems to Windows 10/11 (EOL OS)
2. Deploy browser updates across organization (Chrome 79 → current)
3. Email security awareness training for affected user

### Long-term
1. Implement WAF rules to block similar XSS patterns
2. Enable MFA for all user accounts
3. Review and update incident response playbook

---

## Lessons Learned

**What went well:**
- [Detection mechanisms that worked]
- [Response procedures that were effective]

**What could be improved:**
- [Gaps identified]
- [Response delays]
- [Missing visibility]

**Questions for follow-up:**
- [Unresolved questions]
- [Areas needing clarification]

---

## References

**Tools Used:**
- VirusTotal: [URL]
- AbuseIPDB: [URL]
- Hybrid Analysis: [URL]
- [Other tools]

**Related Alerts:**
- [Link to related investigations if any]

**Documentation:**
- MITRE ATT&CK: https://attack.mitre.org/
- [Vendor documentation]
- [Playbook references]

---

## Appendix

### Screenshots
[Reference to screenshots if included separately]

### Raw Logs
```
[Include relevant raw log excerpts if needed for evidence]
```

### Additional Notes
[Any other relevant information that doesn't fit elsewhere]

---

**Investigation completed by:** [Your name]  
**Date:** [YYYY-MM-DD]  
**Review status:** [Peer reviewed/Management approved/etc]