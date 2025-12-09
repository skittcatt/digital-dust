# SOC165 - Possible SQL Injection Payload Detected

## Quick Capture (First 30 seconds)

**Alert triggered:** Feb, 25, 2022, 11:34AM

**Key details:**
- Source IP: 
167.99.169.17
- Dest IP:   
172.16.17.18
- Hostname: 
WebServer1001
- User: 
webadmin
- What triggered: 
Requested URL Contains OR 1 = 1

**First impression:** Looks like a SQL injection payload

---

## Checklist - Critical Questions

**The Big 5:**
- Is this malicious? (Y/N/Unknown) - Y
- Was it successful? (Y/N/Partial) - N
- Is it still happening? (Y/N) - N
- Are other systems affected? (Y/N) - N
- Do we need to contain NOW? (Y/N) - N

**If YES to containment:**
- [ ] Isolate endpoint
- [ ] Block source IP
- [ ] Disable user account
- [ ] Alert senior analyst/manager

---

## Raw Notes Section

**Time:** 10:20AM
**Action:** Checking alert details
**Finding:** Multiple SQL injection attempts, all returned 500 errors

**Time:** 10:32AM
**Action:** Reviewing logs for pattern
**Finding:** 6 attempts in 4 minutes, manual testing pattern. Attacker probing for SQLi vulnerability

**Time:** 10:44AM
**Action:** Threat intel on source IP
**Finding:** DigitalOcean IP with 14,900 abuse reports. Known for attacks

**Time:** 10:59AM
**Action:** User-Agent analysis
**Finding:** Windows 7 + Firefox 40 = likely spoofed, 6.5 years outdated

**Time:** 11:06AM
**Action:** Checking if attack succeeded
**Finding:** All requests returned HTTP 500 - application rejected malformed input

**Time:** 11:14AM
**Action:** Scope check - other victims?
**Finding:** Only targeted 172.16.17.18, no lateral movement detected

---
## Log Analysis Workspace

**Log Management Timeline**

> **Feb 25, 2022, 11:30AM**
>> **Request URL:** https://172.16.17[.]18/
>> **User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>> **Request Method:** GET
>> **Device Action:** Permitted
>> **HTTP Response Size:** 3547
>> **HTTP Response Status:** 200

> **Feb 25, 2022, 11:32AM**
>> **Request URL:** https://172.16.17[.]18/search/?q=%27
>> **Decoded URL:** [https://172.16.17[.]18/search/?q=']
>> **User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>> **Request Method:** GET
>> **Device Action:** Permitted
>> **HTTP Response Size:** 948
>> **HTTP Response Status:** 500

> **Feb 25, 2022, 11:32AM**
>> **Request URL:** https://172.16.17[.]18/search/?q=%27%20OR%20%271
>> **Decoded URL:** [https://172.16.17[.]18/search/?q=' OR '1]
>> **User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>> **Request Method:** GET
>> **Device Action:** Permitted
>> **HTTP Response Size:** 948
>> **HTTP Response Status:** 500

> **Feb 25, 2022, 11:33AM**
>> **Request URL:** https://172.16.17[.]18/search/?q=%27%20OR%20%27x%27%3D%27x
>> **Decoded URL:** [https://172.16.17[.]18/search/?q=' OR 'x'='x]
>> **User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>> **Request Method:** GET
>> **Device Action:** Permitted
>> **HTTP Response Size:** 948
>> **HTTP Response Status:** 500

> **Feb 25, 2022, 11:33AM**
>> **Request URL:** https://172.16.17[.]18/search/?q=1%27%20ORDER%20BY%203--%2B
>> **Decoded URL:** [https://172.16.17[.]18/search/?q=1' ORDER BY 3--+]
>> **User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>> **Request Method:** GET
>> **Device Action:** Permitted
>> **HTTP Response Size:** 948
>> **HTTP Response Status:** 500

> **Feb 25, 2022, 11:34AM**
>> **Request URL:** https://172.16.17[.]18/search/?q=%22%20OR%201%20%3D%201%20--%20-
>> **Decoded URL:** [https://172.16.17[.]18/search/?q=" OR 1 = 1 -- -]
>> **User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>> **Request Method:** GET
>> **Device Action:** Permitted
>> **HTTP Response Size:** 948
>> **HTTP Response Status:** 500

**Key log findings:**
- Initial request (11:30) legitimate - HTTP 200, 3547 bytes returned
- 5 subsequent SQLi attempts (11:32-11:34) all failed - HTTP 500 'Internal Server Error'
- Response size consistent at 948 bytes = error page
- Attacker tested multiple SQLi techniques:
  1. Single quote (') - basic injection test
  2. ' OR '1 - boolean-based blind SQLi
  3. ' OR 'x'='x - tautology attack
  4. ORDER BY 3 - column enumeration attempt
  5. " OR 1 = 1 -- - comment-based injection
- Pattern: Manual testing, not automated scanner (2min intervals)
- No successful data exfiltration detected

---

## Threat Intel Quick Checks

### VirusTotal
URL: [VirusTotal - IP address - 167.99.169.17](https://www.virustotal.com/gui/ip-address/167.99.169.17)
- [x] Checked
- Detection: 5/95
- Notes: 
	- Network Name: DIGITALOCEAN-167-99-0-0
	- WhoIs Server: whois.arin.net
	- Community notes indicate attempted SSH brute force attacks from this IP.

### AbuseIPDB  
URL: [167.99.169.17 | DigitalOcean, LLC | AbuseIPDB](https://www.abuseipdb.com/check/167.99.169.17)
- [x] Checked
- Confidence: 0%
- Reports: 14,900
- Notes: Reports indicate SQL injection, brute force, SSH and web attacks

### ~~URLhaus (if URL/domain)~~
~~URL: https://urlhaus.abuse.ch/~~
- [ ] ~~Checked~~
- ~~Listed: Y/N~~
- ~~Notes:~~

### Cisco Talos
URL: [Reputation Lookup || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence](https://talosintelligence.com/reputation_center/lookup?search=167.99.169.17)
- [x] Checked
- Reputation: Neutral
- Notes: No notes

### WHOIS
URL: [167.99.169.17 WHOIS IP Address Lookup - Who.is](https://who.is/whois-ip/ip-address/167.99.169.17)
- Country: USA
- Network Name: DIGITALOCEAN-167-99-0-0
- Org: DigitalOcean, LLC (DO-13)
- Type: Cloud Hosting Service

### ~~Shodan (if needed)~~
- ~~Open ports:~~
- ~~Services:~~
- ~~Notes:~~

**Quick verdict from OSINT:** IP address is from a cloud-hosting website, not intentionally malicious. Someone using the cloud system to attack.

---

## User-Agent Analysis (if web traffic)

**Raw UA string:**
```
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
```

**Breakdown:**
- OS: Windows NT 6.1
  - Version: Windows 7
  - EOL?: Y, since January 2020
- Browser: rv:40.0 Gecko/20100101 inside Firefox/40.1
  - Version: Firefox 40.1, Gecko Engine 40.0
  - Current version: Firefox 97.0~98.0
  - Outdated?:  Y, ~57 versions behind/~6.5 years behind- Red flags: Outdated OS and outdated browser. 

Attackers often spoof their User-Agent to older OS/browsers to deliberately look like an old browser to avoid detection. Could be using an automated tool, could be possible due to the repeat attempted within 4 minutes, see [Log Analysis Workspace].

---

## URL/Payload Analysis (if applicable)

**Full URL:**
```
https://172.16.17.18/search/?q=%22%20OR%201%20%3D%201%20--%20-
```
**Breakdown:**
- Protocol: https
- Domain: 172.16.17.18
- Path: /search/
- Parameters: /?q=%22%20OR%201%20%3D%201%20--%20-
- Suspicious parts: 
The parameter using lots of %, plugging it into a URL decoder gives us:
```
https://172.16.17.18/search//?q=" OR 1 = 1 -- -
```
Gives us strong indication of 'Contains OR 1=1' to override security.

~~**For malicious URLs:**~~
- ~~Typosquatting?: N/A~~
- ~~Lookalike domain?: N/A~~
- ~~Compromised legit site?: N/A~~
- ~~Known malicious?: N/A~~

~~**For files:**~~
- ~~Filename: N/A~~
- ~~Hash (MD5): N/A~~
- ~~Hash (SHA256): N/A~~
- ~~File type: N/A~~

---

## Scope Check

**Who's affected?**
- User(s): webadmin
- System(s): WebServer1001
- Number of attempts: 6
- Time range: 4 minutes

**Did it spread?**
- [ ] Checked other endpoints
- [ ] Checked for lateral movement
- [ ] Checked for data exfil
- [ ] Checked for persistence

**Other victims from same source?**
Query: 

> Log Management
> Source Address: 167.99.169.17

Results: Only logs directed to dest. address 172.16.17.18.

---

## Timeline Building

| Time    | Event                         | Source   | Notes                          |
| ------- | ----------------------------- | -------- | ------------------------------ |
| 11:30AM | Legitimate access to homepage | Web logs | HTTP 200 (Allowed), 3547 bytes |
| 11:32AM | SQLi test #1 - single quote   | Web logs | HTTP 500, 948 bytes, blocked   |
| 11:32AM | SQLi test #2 - OR '1          | Web logs | HTTP 500, 948 bytes, blocked   |
| 11:33AM | SQLi test #3 - OR 'x'='x      | Web logs | HTTP 500, 948 bytes, blocked   |
| 11:33AM | SQLi test #4 - ORDER BY       | Web logs | HTTP 500, 948 bytes, blocked   |
| 11:34AM | SQLi test #5 - OR 1=1         | Web logs | HTTP 500, 948 bytes, blocked   |

**Pattern noticed:**
- Manual testing: 2-minute intervals between attempts
- Progressive complexity: started simple, increased sophistication
- Attacker methodically testing different SQLi techniques
- All attempts failed - application has input validation
---
## IOC Collection

**Network Indicators:**
- **Source IP:** 167.99.169.17 (DigitalOcean hosting, 14,900 abuse reports)
- **Destination IP:** 172.16.17.18 (WebServer1001)
- **User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1 (likely spoofed)

**Attack Indicators:**
- **Attack Pattern:** Manual SQL injection testing
- **Target Endpoint:** /search/ (query parameter vulnerable)
- **Timeframe:** 4-minute attack window (11:30-11:34)
- **Payloads Used:** 5 distinct SQLi techniques

**Hosting Provider:**
- DigitalOcean (167.99.0.0/16 subnet)
- Consider blocking entire range if attacks continue

---
## MITRE ATT&CK Quick Map

**Tactics observed:**
- Initial Access - T1190 (Exploit Public-Facing Application)
	- Attempted SQL injection against web search function
- Discovery - T1046 (Network Service Scanning)
	- Initial recon with legitimate request before attacks
- Credential Access - T1212 (Exploitation for Credential Access)
	- SQLi often used to dump password hashes from database

---
## Decision Points

**Is this malicious?**
- Evidence for: 
  - Multiple SQL injection payloads
  - Classic SQLi syntax (' OR 1=1, ORDER BY, etc)
  - Source IP has 14,900 abuse reports
  - Spoofed/outdated User-Agent
  - Progressive attack pattern
- Evidence against: 
  - None - clearly malicious
- **Decision:** YES - Confirmed SQL injection attempt

**Was attack successful?**
- Evidence it worked:
  - None
- Evidence it failed: 
  - All requests returned HTTP 500 (Internal Server Error)
  - No data exfiltration detected
  - No follow-up activity
  - Response size consistent with error page (948 bytes)
  - No successful HTTP 200 responses after initial legit request
- **Decision:** BLOCKED - Application rejected all injection attempts

**Severity assessment:**
- Impact if successful: HIGH (database compromise, data theft, unauthorized access)
- Actual impact: LOW (all attempts blocked, no compromise)
- Urgency: MEDIUM (should block IP, but no active compromise)

---

## Containment Actions

**Immediate Actions**
- [ ] Block IP: 167.99.169.17 at perimeter firewall
- [ ] Review WAF/input validation rules (already working, but verify)
- [ ] Check for any other DigitalOcean IPs targeting same endpoint
- [ ] Alert web application team about attempted SQLi
- [ ] Monitor for additional attempts from different IPs

**Not needed:**
- Isolate endpoint: No compromise occurred
- Disable account: No account compromised
- Reset credentials: No credential theft

---

## Questions/Blockers

**Stuff I'm not sure about:**
- Actual attacker identity (behind cloud hosting)
- Whether this is targeted attack or opportunistic scanning

**Need to ask:**
- Does business require DigitalOcean cloud access? (for blocking decision)
- When was last pentest of this application?

**Follow-up needed:**
- Monitor for attacks from different IPs targeting same vulnerability
- Verify no successful SQLi attempts in historical logs

---
## Recommendations (Draft)

**Immediate:**
1. Block source IP 167.99.169.17 at firewall (high confidence malicious)
2. Block entire DigitalOcean subnet if pattern continues: 167.99.0.0/16
3. Verify WAF rules are logging all blocked SQLi attempts
4. Check application logs for any HTTP 200 responses with SQLi patterns

**Short-term:**
1. Review search function code for additional input validation
2. Implement rate limiting on search endpoint (5 attempts in 4 min = too permissive)
3. Deploy parameterized queries if not already implemented
4. Add SIEM alert for multiple HTTP 500s from same source IP
5. Consider geo-blocking if business doesn't require access from attacker's region

**Long-term:**
1. Implement Web Application Firewall (WAF) if not present
2. Regular penetration testing of web applications
3. Security code review for all database query functions
4. Implement database activity monitoring
5. Security awareness training for developers (secure coding practices) 

---
## Final Verdict (Before closing)

**Verdict:** Malicious

**Confidence:** High

**One-line summary:**
External attacker from DigitalOcean cloud service attempted SQL injection against WebServer1001 search function; all five injection attempts failed with HTTP 500 errors due to existing input validation.

**Ready to write formal report:** Y

---

