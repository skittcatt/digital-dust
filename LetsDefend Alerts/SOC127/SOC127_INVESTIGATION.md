# SOC127 - SQL Injection Detected

## Quick Capture (First 30 seconds)

**Alert triggered:** Mar, 07, 2024, 12:51 PM

**Key details:**
- Source IP: 118.194.247.28
- Dest IP: 172.16.20.12
- Hostname: WebServer1000
- User: Unknown
- What triggered: Suspicious string in request URL

**First impression:** Certainly looks like a malicious GET request with obfuscated lines.

---
## Checklist - Critical Questions

**The Big 5:**
- Is this malicious? Y
- Was it successful? Partial
- Is it still happening? N
- Are other systems affected? N
- Do we need to contain NOW? N

---
## Raw Notes Section

**Time:** 11:45
**Action:** Decoding detected URL string
**Finding:** Decoded string:
`GET /?douj=3034 AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert("XSS")</script>',table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC xp_cmdshell('cat ../../../etc/passwd')# HTTP/1.1 200 865`

**Time:** 11:52
**Action:** Investigating log management
**Finding:** Lots of logs originating from IP source address 118.194.247.28.

**Time:** 12:01
**Action:** Investigating the RAW logs
**Finding:** Putting all of the logs into CyberChef to URL decode. The attacker is using CHR() and CHAR() as well as hex code to obfuscate the code. There is a bit of time taken to decode all of the hidden code (would've been quicker with tools rather than manual entry). 

**Time:** 14:27
**Action:** Quick check of threat intel websites
**Finding:** Nothing conclusive.

**Time:** 14:41
**Action:** Investigating user-agent
**Finding:** Seems normal and up-to-date for March 2024. Has the potential to be spoofed. We can see from the previous log, the request makes a request to itself and we can see its UA is curl/7.68.0, indicating that the server could be a Linux machine. 

**Time:** 14:55
**Action:** Looking over raw logs again.
**Finding:** All of the responses are HTTP STATUS: 200, indicating a success, but as all the response sizes are the same (865 bytes), it inclines me to believe that the attacker did not get their desired response. We also see many different techniques from the attacker (boolean, UNION, time-based). This attack did not work against the device.

**Time:** 16:05
**Action:** Completing investigation.
**Finding:** As we are still unsure on the status of the attack, it should be escalated to have a deeper forensics investigation done. We must block the IP source address as they could attempt to target another system.

---
## Log Analysis Workspace

**Source to check:**
-  Firewall logs - Y
-  Proxy logs - Y
-  EDR/Endpoint logs - Unable
-  SIEM alerts - Y
-  Web server logs - N/A
-  Email gateway logs - N/A

---
## Threat Intel Quick Checks

### VirusTotal
URL: [Source IP Check](https://www.virustotal.com/gui/ip-address/118.194.247.28)
- Checked - Y
- Detection: 7/95
- Notes: Originates from China. For the flagged vendors, the warnings were for malware and phishing. Some venders were not able to check the IP.

### AbuseIPDB  
URL: [Source IP Check](https://www.abuseipdb.com/check/118.194.247.28)
- Checked - Y
- Confidence: 0%
- Reports: 4,323 times from 496 distinct sources
- Notes: Most recent report is from 10 months ago - could be outdated information or not used anymore in abusive activities. Related to many brute-force and SSH attacks.

### Cisco Talos
URL: [Source IP Check](https://talosintelligence.com/reputation_center/lookup?search=118.194.247.28)
- Checked: Y
- Reputation: Neutral / Neutral
- Notes: Nothing of note, not much information available.

**Quick verdict from OSINT:** [Inconclusive]

---
## User-Agent Analysis

**Raw UA string:**
```
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36
```

**Breakdown:**
- OS: Windows 10
	- Version: 64-bit
	- EOL?: N
- Browser: Chrome
	- Version: 122.0.0.0
	- Current version: (For March 7th 2024) Yes, roughly 2 weeks old.
	- Outdated?: N
- Red flags: Seems like a standard up-to-date UA for the timestamp of the alert. Potential to be spoofed.

---
## Scope Check

**Who's affected?**
- User(s): WebServer1000
- System(s): WebServer1000
- Number of attempts: At least 22, if potential port-scanning activity at the beginning is not counted.
- Time range: 3 minutes.

**Did it spread?**
-  Checked other endpoints - N
-  Checked for lateral movement - N
-  Checked for data exfil - Unsure
-  Checked for persistence - N

**Other victims from same source?**
Results: N

---
## Timeline Building

| Time              | Event          | Source         | Notes                                                                                                                              |
| ----------------- | -------------- | -------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| 11:56AM - 12:46PM | Firewall Event | 118.194.247.28 | Potential port-scanning activity, many empty raw logs coming from this source address to different destination ports.              |
| 12:50PM           | Proxy Event    | 118.194.247.28 | Attacker confirms port 80 (HTTP) and requests the server to return the HTTP protocol version. It appears that the UA was returned. |
| 12:51PM - 12:53PM | Proxy Event    | 118.194.247.28 | Attacker begins attempting several SQLi attack tactics. Every attack returns HTTP status 200 and response size of 865 bytes.       |

**Pattern noticed:**
- Manual or automated?
	- Automated, 22 attempts spanned over 2 minutes.
- Time gaps between actions?
	- Millisecond difference between attempts.
- Escalation in activity?
	- Different SQLi tactics used.

---
## IOC Collection

**IPs:**
- 118.194.247.28 - Source Address
- 172.16.20.12 - Destination Address

**User accounts:**
- WebServer1000 - Source Hostname

---
## MITRE ATT&CK 

**Reconnaissance**
- **T1595.002** - Active Scanning: Vulnerability Scanning.
	- Attacker used SQLmap to systematically scan for SQL injection vulnerabilities.
	- Tested multiple injection types across different database systems.
	- User-Agent clearly identified automated scanning tool.

**Initial Access (Attempted)**
- **T1190** - Exploit Public-Facing Application.
	- Attempted to exploit SQL injection in web application.
	- Target: /index.php endpoint with user-supplied parameter.
	- Result: Assumed failure (all attempts returned identical responses).

**Credential Access (Attempted)**
- **T1552.001** - Unsecured Credentials: Credentials In Files.
	- Payload included command to read /etc/passwd file.
	- Intent: Extract system credentials if code execution achieved.
	- Result: Assumed failure (further investigation needed).
- **T1189** - Drive-by Compromise (Secondary).
	- Evidence: XSS payload `<script>alert("XSS")</script>` included.
	- Likely testing multiple vulnerabilities simultaneously.

---
## Decision Points

**Is this malicious?**
- Evidence for: Multiple attempts to inject SQL queries.
- Evidence against: None presented.
- **Decision:** [YES]

**Was attack successful?**
- Evidence it worked: HTTP status = 200 on all attempts.
- Evidence it failed: All of the response sizes were 865 bytes which can indicate that the page was loading blankly. We also note that there are multiple tactics used with the same response of 200 and size of 865 bytes. 
- **Decision:** [PARTIAL] - The server at the very least responded with a success, we must investigate if any information was compromised.

**Severity assessment:**
- Impact if successful: Critical.
- Actual impact: Medium.
- Urgency: As soon as possible as we are still unsure on the success of the attack.

---
## Containment Actions

**What needs to happen ASAP:**
-  Block IP: 118.194.247.28
-  Isolate endpoint: WebServer1000 (not appearing on EDR)
-  Reset credentials: [Unknown as device not appearing on EDR]

---

## Questions/Blockers (WIP)

**Stuff I'm not sure about:**
- Was data exfiltrated despite identical responses? (Requires deeper log analysis)
- Why is WebServer1000 not appearing in EDR? (Configuration issue or system offline?)
- Are there other web servers vulnerable to same attack?

**Need to ask:**
- Web application team: "Does application log SQL errors separately?"
- Infrastructure team: "Why is WebServer1000 not reporting to EDR?"
- Security team: "Is WAF deployed? If yes, why didn't it block SQLmap?"

**Waiting on:**
- EDR connectivity restored for WebServer1000
- Application-level logs from web server
- Database query logs (if available)

**Follow-up needed:**
- Manual security testing of /index.php endpoint
- Review application security controls (input validation, parameterized queries)
- Check other web servers for similar scanning activity from this IP
- Implement WAF if not present
- Create detection rule for SQLmap User-Agent signature
---
## Something to Note - Learning Point

**Encountered confusing playbook wording regarding SQL injection success.**

**Situation:**
- SQLmap tested multiple injection techniques.
- All returned HTTP 200, 865 bytes.
- No data extracted, no compromise.

**My answer:** Attack FAILED (no data theft, identical responses)
**Playbook answer:** Attack "SUCCESSFUL" (requests reached database)

**Resolution:**
Playbook uses confusing technical definition: "successful" = confirmed interaction with database layer. In SOC/IR context, attack is only "successful" if objective achieved (data theft, compromise, access).

**My interpretation for incident response:**
- HTTP 200 = server processed request (didn't crash)
- Identical response sizes = same error/default page
- No variance = no data extracted
- **Conclusion: Attack FAILED from security impact perspective**

**Key takeaway:** 
Always assess "success" based on attacker objective achievement, not just technical request processing. HTTP 200 ≠ successful attack.

---
## Final Verdict (Before closing)

**Verdict:** [Malicious]

**Confidence:** [High]

**One-line summary:**
An attacker originating from China was attempting to perform a SQL injection attack on WebServer1000 (172.16.20.12) using different techniques. All responses came back as 200/successful with a response size of 865 bytes, except for the initial request for the HTTP protocol, which returned 902 bytes and the user-agent. This attack seems to be unsuccessful for the attacker, but further escalation is still recommended as the system still returned successful responses, even without any information.

**Ready to write formal report:** [Y]

---
