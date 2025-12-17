# [Alert ID] - [Quick Title]

## Quick Capture (First 30 seconds)

**Alert triggered:** [timestamp]

**Key details:**
- Source IP: 
- Dest IP: 
- Hostname: 
- User: 
- What triggered: 

**First impression:** [Looks like phishing/malware/false positive/etc]

---

## Checklist - Critical Questions

**The Big 5:**
-  Is this malicious? (Y/N/Unknown)
-  Was it successful? (Y/N/Partial)
-  Is it still happening? (Y/N)
-  Are other systems affected? (Y/N)
-  Do we need to contain NOW? (Y/N)

**If YES to containment:**
-  Isolate endpoint
-  Block source IP
-  Disable user account
-  Alert senior analyst/manager

---

## Raw Notes Section

**Time:** [HH:MM]
**Action:** [What I'm checking]
**Finding:** [What I found]

**Time:** 
**Action:** 
**Finding:** 

**Time:** 
**Action:** 
**Finding:** 

[Keep adding as you investigate]

---

## Log Analysis Workspace

**Source to check:**
-  Firewall logs
-  Proxy logs  
-  EDR/Endpoint logs
-  SIEM alerts
-  Web server logs
-  Email gateway logs
-  DNS logs
-  AD logs (if Windows)

**Search queries used:**
```
[Paste your actual search queries here so you can repeat if needed]

Example:
index=firewall src_ip=X.X.X.X earliest=-24h
```

**Key log findings:**
- [Finding 1]
- [Finding 2]
- [Pattern noticed]

---

## Threat Intel Quick Checks

### VirusTotal
URL: https://www.virustotal.com/gui/ip-address/[IP]
-  Checked
- Detection: X/XX
- Notes: 

### AbuseIPDB  
URL: https://www.abuseipdb.com/check/[IP]
-  Checked
- Confidence: X%
- Reports: X
- Notes:

### URLhaus (if URL/domain)
URL: https://urlhaus.abuse.ch/
-  Checked
- Listed: Y/N
- Notes:

### Cisco Talos
URL: https://talosintelligence.com/reputation_center/lookup?search=[IP]
-  Checked
- Reputation: 
- Notes:

### WHOIS
- Country:
- Org:
- Type: [Residential/Hosting/VPN/etc]

### Shodan (if needed)
- Open ports:
- Services:
- Notes:

**Quick verdict from OSINT:** [Clean/Suspicious/Malicious]

---

## User-Agent Analysis (if web traffic)

**Raw UA string:**
```
[paste full user agent]
```

**Breakdown:**
- OS: 
  - Version: 
  - EOL?: Y/N
- Browser: 
  - Version:
  - Current version: [check]
  - Outdated?: Y/N
- Red flags:

---

## URL/Payload Analysis (if applicable)

**Full URL:**
```
[paste complete URL]
```

**Breakdown:**
- Protocol: http/https
- Domain: 
- Path: 
- Parameters: 
- Suspicious parts: [highlight weird stuff]

**For malicious URLs:**
- Typosquatting?: Y/N
- Lookalike domain?: Y/N
- Compromised legit site?: Y/N
- Known malicious?: Y/N

**For files:**
- Filename:
- Hash (MD5):
- Hash (SHA256):
- File type:

---

## Scope Check

**Who's affected?**
- User(s): 
- System(s): 
- Number of attempts: 
- Time range: 

**Did it spread?**
-  Checked other endpoints
-  Checked for lateral movement
-  Checked for data exfil
-  Checked for persistence

**Other victims from same source?**
Query: 
Results:

---

## Timeline Building

| Time | Event | Source | Notes |
|------|-------|--------|-------|
| | | | |
| | | | |
| | | | |

**Pattern noticed:**
- Manual or automated?
- Time gaps between actions?
- Escalation in activity?

---

## IOC Collection

**As you find them, dump them here:**

**IPs:**
- 
- 

**Domains/URLs:**
- 
- 

**Hashes:**
- 
- 

**File paths:**
- 
- 

**Processes:**
- 
- 

**Email addresses:**
- 
- 

**User accounts:**
- 
- 

---

## MITRE ATT&CK Quick Map

**Tactics observed:**
-  Initial Access - T####
-  Execution - T####  
-  Persistence - T####
-  Privilege Escalation - T####
-  Defense Evasion - T####
-  Credential Access - T####
-  Discovery - T####
-  Lateral Movement - T####
-  Collection - T####
-  Exfiltration - T####
-  Command & Control - T####

[Just mark the ones you see, add technique IDs as you identify them]

---

## Decision Points

**Is this malicious?**
- Evidence for: 
- Evidence against:
- **Decision:** [YES/NO/UNSURE]

**Was attack successful?**
- Evidence it worked:
- Evidence it failed:
- **Decision:** [SUCCESS/BLOCKED/PARTIAL]

**Severity assessment:**
- Impact if successful: [Critical/High/Med/Low]
- Actual impact: [Critical/High/Med/Low]
- Urgency: [Immediate/Hours/Days]

---

## Containment Actions

**What needs to happen NOW:**
-  Block IP: [IP address]
-  Isolate endpoint: [hostname]
-  Disable account: [username]
-  Reset credentials: [username]
-  Quarantine file: [path]
-  Kill process: [process name]

**Time actions taken:**
- [HH:MM] - [Action completed]
- [HH:MM] - [Action completed]

---

## Questions/Blockers

**Stuff I'm not sure about:**
- 

**Need to ask:**
- 

**Waiting on:**
- 

**Follow-up needed:**
- 

---

## Recommendations (Draft)

**Immediate:**
1. 
2. 

**Short-term:**
1. 
2. 

**Long-term:**
1. 
2. 

---

## Screenshot Checklist

**Need to capture:**
-  Alert details
-  VirusTotal results
-  Log excerpts showing attack
-  Timeline visualization
-  SIEM dashboard
-  Containment confirmation
-  [Other specific evidence]

**Saved to:** [folder path]

---

## Final Verdict (Before closing)

**Verdict:** [Malicious/Benign/Suspicious]

**Confidence:** [High/Medium/Low]

**One-line summary:**
[Single sentence describing what happened]

**Ready to write formal report:** [Y/N]

---

## Handoff Notes (if escalating)

**Escalating to:** [Name/Team]
**Reason:** 
**What I've done:** 
**What's needed:** 
**Time-sensitive items:** 
