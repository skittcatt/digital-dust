# SOC166 - JavaScript Code Detected in Requested URL

## Quick Capture (First 30 seconds)

**Alert triggered:** Feb 26, 2022, 06:56 PM (18:56)

**Key details:**
- Source IP: 
112.85.42.13
- Dest IP: 
172.16.17.17
- Hostname: 
WebServer1002
- User: 
[External - unknown]
- What triggered: 
JavaScript code in URL parameter (XSS attempt)

**First impression:** Cross-Site Scripting (XSS) attack attempt against web server

---
## Checklist - Critical Questions

**The Big 5:**
-  Is this malicious? (Y/N/Unknown) - Y
-  Was it successful? (Y/N/Partial) - N
-  Is it still happening? (Y/N) - N
-  Are other systems affected? (Y/N) - N
-  Do we need to contain NOW? (Y/N) - N (already blocked)

**If YES to containment:**
-  Isolate endpoint (N/A - external attack)
-  Block source IP (recommended)
-  Disable user account (N/A)
-  Alert senior analyst/manager

---
## Raw Notes Section

**Action:** Reviewing alert details
**Finding:** XSS payload in search parameter, attacker testing for vulnerability

**Action:** Analyzing User-Agent
**Finding:** Windows 7 + Firefox 40 = at least 2 years (as of 2022) outdated, likely spoofed

**Action:** Checking log management
**Finding:** Multiple XSS attempts, all blocked with HTTP 302 redirects

**Action:** Pattern analysis in logs
**Finding:** Manual testing pattern, 8 attacks within 22 minutes

**Action:** Threat intel on source IP
**Finding:** China Unicom Jiangsu, AbuseIPDB shows SSH brute force history

**Action:** Response code analysis
**Finding:** All malicious requests = HTTP 302 (redirect), only legitimate request = HTTP 200

**Action:** Assessing attack success
**Finding:** Server configured to redirect on malicious input, attack completely blocked

---
## Log Analysis Workspace

**Source to check:**
-  Firewall logs
-  Proxy logs  
-  EDR/Endpoint logs (N/A - external attack)
-  Web server logs
-  Email gateway logs (N/A)
-  DNS logs
-  AD logs (N/A)

**Log Management Timeline:**

>Feb, 26, 2022, 06:34 PM
>>**Request URL:** https://172.16.17.17/
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 1024
>>**HTTP Response Status:** 200

>Feb, 26, 2022, 06:35 PM
>>**Request URL:** https://172.16.17.17/about-us/
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 3531
>>**HTTP Response Status:** 200

>Feb, 26, 2022, 06:45 PM
>>**Request URL:** https://172.16.17.17/search/?q=test
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 885
>>**HTTP Response Status:** 200

>Feb, 26, 2022, 06:46 PM
>>**Request URL:** https://172.16.17.17/search/?q=prompt(8)
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 0
>>**HTTP Response Status:** 302

>Feb, 26, 2022, 06:46 PM
>>**Request URL:** [https://172.16.17.17/search/?q=<$img%20src%20=q%20onerror=prompt(8)$>]
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 0
>>**HTTP Response Status:** 302

>Feb, 26, 2022, 06:50 PM
>>**Request URL:** [https://172.16.17.17/search/?q=<$script>$for((i)in(self))eval(i)(1)<$/script>]
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 0
>>**HTTP Response Status:** 302

>Feb, 26, 2022, 06:53 PM
>>**Request URL:** [https://172.16.17.17/search/?q=<$svg><$script%20?>$alert(1)]
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 0
>>**HTTP Response Status:** 302

>Feb, 26, 2022, 06:56 PM
>>**Request URL:** [https://172.16.17.17/search/?q=<$script>javascript:$alert(1)]
>>**User-Agent:** Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
>>**Request Method:** GET
>>**Device Action:** Permitted
>>**HTTP Response Size:** 0
>>**HTTP Response Status:** 302

**Key log findings:**
- Legitimate request (q=test): HTTP 200, 885 bytes
- All XSS attempts: HTTP 302, 0 bytes
	- HTTP 302 = server redirecting away from malicious input
	- Consistent 0 byte response = no data returned, attack failed
- Target: /search endpoint (common XSS target)
- Only legitimate query returned data

**Defense mechanism:**
- Server configured to detect malicious patterns
- Redirects user when JavaScript/scripts detected
- Likely WAF or input validation triggering redirect
- Effective defense - no XSS executed

---
## Threat Intel Quick Checks

### VirusTotal
URL: https://www.virustotal.com/gui/ip-address/112.85.42.13
- Detection: 0/95
- Notes: 
  - Network Name: UNICOM-JS
  - WhoIs information shows China Unicom Jiangsu province network
  - Service provider network
  - Communicating files: [xjtzt6.exe] , [c61df176fc90fd089ca36c316e4d29393f77c424c8455c69ef7fc4203427c8b0]
  
### AbuseIPDB  
URL: https://www.abuseipdb.com/check/112.85.42.13
- Confidence: 0%
- Reports: 45,434
- Notes: 
  - Failed SSH login attempts reported
  - Brute-force attack history
  - Pattern of malicious activity

### WHOIS
- Country: CN (China)
- Network: 112.80.0.0 - 112.87.255.255
- Org: China Unicom Jiangsu province
- Type: ISP/Service provider
- Status: Allocated Portable

### Cisco Talos
URL: [Reputation Lookup || Cisco Talos Intelligence Group - Comprehensive Threat Intelligence](https://talosintelligence.com/reputation_center/lookup?search=112.85.42.13)
- Reputation: Neutral
- Notes: Nothing of note

**Quick verdict from OSINT:** 
Source IP from Chinese ISP with history of SSH brute force attacks. Not inherently malicious infrastructure, but originating from compromised host or malicious user on residential/business connection.

---
## User-Agent Analysis (if web traffic)

**Raw UA string:**
```
Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1
```

**Breakdown:**
- OS: Windows NT 6.1
  - Version: Windows 7
  - EOL?: Y - End of Life since January 2020
- Browser: Firefox 40.1
  - Version: Firefox 40.1 (Gecko engine rv:40.0)
  - Current version: Firefox 97-98+ (at time of alert, 2022)
  - Outdated?: Y - Approximately 57 versions behind, ~7 years outdated
- Architecture: WOW64 (32-bit browser on 64-bit Windows)
- Build date: Gecko/20100101 (placeholder date, not actual build)
- Red flags: 
  - Extremely outdated OS and browser combination
  - At least 2-year-old software versions
  - Likely spoofed to appear as old system
  - Common attacker tactic to avoid detection/fingerprinting

**Assessment:**
- Almost certainly spoofed User-Agent
- Attackers use old UA strings to:
  - Avoid modern browser security features in detection
  - Blend in with legacy systems
  - Test if targets are vulnerable to old exploits
- Manual testing pattern supports human attacker, not automated tool

---
## URL/Payload Analysis (if applicable)

**Full URL:**
```
https://172.16.17.17/search/?q=<$script>javascript:$alert(1)<$/script>
```

**Breakdown:**
- Protocol: https
- Domain: 172.16.17.17 (internal IP address)
- Path: /search/
- Parameters: ?q=[XSS payload]
- Suspicious parts: 
  - `<script>` tags in query parameter
  - `javascript:` protocol handler
  - `alert(1)` - classic XSS test payload

**XSS Payload Analysis:**

**Intent:** Reflected Cross-Site Scripting (XSS)
- Inject JavaScript into search parameter
- If successful, script executes in victim's browser
- `alert(1)` is standard proof-of-concept payload

**Attack flow if successful:**
1. Malicious URL sent to victim
2. Victim clicks link
3. Server reflects JavaScript in response page
4. JavaScript executes in victim's browser context
5. Attacker can then:
   - Steal session cookies
   - Capture credentials
   - Redirect user
   - Deface page
   - Deploy more sophisticated attacks

**This specific payload:**
- Type: Reflected XSS test
- Target: Search functionality (q= parameter)
- Technique: Script tag injection
- Severity if successful: Medium-High
  - Session hijacking possible
  - Credential theft possible
  - Requires social engineering (victim must click malicious link)

**Why it failed:**
- Server detected malicious pattern
- HTTP 302 redirect triggered
- Likely WAF or input validation
- No JavaScript returned in response (0 bytes)

---
## Scope Check

**Who's affected?**
- User(s): N/A (external attacker, no internal users affected)
- System(s): WebServer1002 (targeted, but not compromised)
- Number of attempts: Multiple (exact count in logs)
- Time range: Multiple attempts over period with ~10 min intervals

**Did it spread?**
-  Checked other endpoints - No other systems targeted
-  Checked for lateral movement - N/A (no compromise)
-  Checked for data exfil - N/A (no compromise)
-  Checked for persistence - N/A (no compromise)

**Other victims from same source?**
Query: Source IP 112.85.42.13

Results: 
- Only targeted 172.16.17.17 (WebServer1002)
- No other internal systems accessed
- No successful attacks detected

---

## Timeline Building

| Time        | Event                          | Source   | Notes                                        |
| ----------- | ------------------------------ | -------- | -------------------------------------------- |
| 18:46 (est) | Legitimate test request        | Web logs | q=test, HTTP 200, 885 bytes, recon           |
| 18:56       | XSS attempt #1 (alert trigger) | Web logs | JavaScript payload, HTTP 302, blocked        |
| 19:06 (est) | XSS attempt #2                 | Web logs | Different payload variant, HTTP 302, blocked |
| 19:16 (est) | XSS attempt #3                 | Web logs | Another variant, HTTP 302, blocked           |

**Pattern noticed:**
- Manual testing: 8 attemps within 22 minutes
- Progressive testing: Started with legitimate request, then attacked
- Attack methodology: Testing if XSS vulnerability exists
- Attacker behavior: Stopped after consistent failures
- Not automated: Time gaps too irregular for scanner
- Human attacker: Testing different payloads manually

---
## IOC Collection

**Network Indicators:**
- **IP Addresses:**
  - 112.85.42.13 (attacker source, China Unicom Jiangsu)
  - 172.16.17.17 (targeted internal server)

- **Domains/URLs:**
  - N/A (attack against IP address)

**Attack Indicators:**
- **Attack Pattern:** Manual XSS testing
- **Target Endpoint:** /search/ (query parameter)
- **Payloads Used:** JavaScript injection attempts
- **User-Agent:** Windows 7 + Firefox 40 (spoofed)
- **Timeframe:** Multiple attempts over ~30+ minutes
- **Response Pattern:** All HTTP 302 (all blocked)

**Hosting/Network:**
- China Unicom Jiangsu (112.80.0.0 - 112.87.255.255)
- ISP network (not dedicated attack infrastructure)
- History of SSH brute force from this IP

---
## MITRE ATT&CK Quick Map

**Tactics observed:**
-  Initial Access - T1190 (Exploit Public-Facing Application)
>- Attempted XSS against web server search function
-  Execution - T1059.007 (Command and Scripting Interpreter: JavaScript)
>- Attempted to inject and execute JavaScript in browser context
-  Discovery - T1046 (Network Service Scanning)
>- Initial recon request (q=test) before attack attempts

**If successful, would enable:**
- Credential Access (session hijacking)
- Collection (steal data from page)
- Command & Control (JavaScript-based C2)

---

## Decision Points

**Is this malicious?**
- Evidence for: 
  - XSS payload in URL parameter (`<script>` tags)
  - Multiple attack attempts with JavaScript
  - Source IP has abuse history (SSH brute force)
  - Spoofed/outdated User-Agent
  - Progressive testing pattern (recon → attack)
  - Manual testing indicates human attacker
- Evidence against: 
  - None - clearly malicious
- **Decision:** YES - Confirmed Cross-Site Scripting attack attempt

**Was attack successful?**
- Evidence it worked:
  - None
- Evidence it failed: 
  - All XSS attempts returned HTTP 302 (redirect)
  - 0 byte responses = no JavaScript returned
  - No successful HTTP 200 responses with attack payloads
  - Server behavior changed when malicious input detected
  - No follow-up activity (attacker stopped trying)
  - Defensive controls working as designed
- **Decision:** BLOCKED - Server security controls rejected all XSS attempts

**Severity assessment:**
- Impact if successful: MEDIUM-HIGH 
  - Session hijacking possible
  - Credential theft possible
  - Would require social engineering (victim clicking link)
- Actual impact: LOW 
  - All attempts blocked
  - No compromise
  - Effective defense demonstrated
- Urgency: LOW 
  - Attack failed
  - No active threat
  - Should still block IP and review defenses

---
## Containment Actions

**Immediate Actions:**
-  Attack already blocked by server defenses
-  Block source IP: 112.85.42.13 at firewall (recommended)
-  Consider blocking China Unicom Jiangsu subnet if attacks continue
-  Alert web application team about attempted XSS
-  Verify WAF/security controls are logging all attempts

**Not needed:**
- Isolate endpoint: No internal systems compromised
- Disable accounts: No account access occurred
- Reset credentials: No credential theft

**Verification actions:**
-  Confirm WAF rules are active and logging
-  Review other recent requests to /search endpoint
-  Check for any successful XSS attempts in historical logs
-  Verify input validation is working correctly

---
## Questions/Blockers

**Stuff I'm not sure about:**
- Exact WAF/security control causing the HTTP 302 redirects
- Where the redirect sends users (main page? error page?)
- If this is part of larger campaign targeting multiple sites

**Need to ask:**
- Web team: "What security control is causing HTTP 302 on malicious input?"
- Web team: "Is /search endpoint using parameterized queries/proper input validation?"
- Security team: "Have we seen attacks from China Unicom networks before?"

**Follow-up needed:**
- Monitor for additional XSS attempts from different IPs
- Verify no successful XSS attempts in historical logs
- Review all endpoints for XSS vulnerabilities
- Consider rate limiting on search endpoint

---

## Recommendations

**Immediate:**
1. Block source IP 112.85.42.13 at perimeter firewall
2. Review WAF/input validation rules (currently working, but verify configuration)
3. Check application logs for any HTTP 200 responses with XSS patterns
4. Verify logging is capturing all blocked attack attempts
5. Monitor for attacks from different IPs against same endpoint

**Short-term:**
1. Review search function code for proper input validation
    - Ensure input sanitization on all user inputs
    - Implement Content Security Policy (CSP) headers
    - Use output encoding for displayed search results
2. Implement rate limiting on /search endpoint
    - Multiple attempts in 30 minutes should trigger temporary block
3. Add SIEM alert for multiple HTTP 302s from single source IP
4. Penetration test /search and other endpoints for XSS vulnerabilities
5. Consider geo-blocking if business doesn't require access from high-risk regions

**Long-term:**
1. Implement/enhance Web Application Firewall (WAF) if not fully deployed
2. Regular security code reviews for all web applications
3. Automated vulnerability scanning of web applications
4. Security awareness training for developers:
    - OWASP Top 10
    - Secure coding practices
    - XSS prevention techniques
5. Implement security headers:
    - Content-Security-Policy
    - X-XSS-Protection
    - X-Content-Type-Options
6. Regular penetration testing schedule
7. Bug bounty program to find vulnerabilities before attackers

---
## Final Verdict

**Verdict:** Malicious - Blocked XSS Attack

**Confidence:** High

**One-line summary:** External attacker from China Unicom network (112.85.42.13) manually tested multiple Cross-Site Scripting payloads against WebServer1002 search function; all attempts blocked by server security controls with HTTP 302 redirects; no compromise occurred.

**Ready to write formal report:** Y

---
## Handoff Notes

**Escalating to:** N/A - Resolved at Tier 1

**Reason:**
- Attack blocked by existing controls
- No compromise occurred
- Recommend IP block and monitoring

**What I've done:**
- Confirmed XSS attack attempt via log analysis
- Verified all attempts blocked (HTTP 302 responses)
- Identified attack pattern (manual testing, 8 attacks in 22 minutes)
- Gathered threat intel on source IP (abuse history)
- Documented IOCs and timeline
- No system compromise detected

**What's needed:**
- Firewall team: Block source IP 112.85.42.13
- Web team: Verify WAF configuration and review search endpoint security
- Monitoring: Watch for similar XSS attempts from different sources

**Time-sensitive items:**
- None - attack was unsuccessful, no active compromise
- IP block can be done during normal operations
