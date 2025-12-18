# SOC146 - Phishing Mail Detected - Excel 4.0 Macros

## Quick Capture (First 30 seconds)

**Alert triggered:** Jun, 13, 2021, 02:13 PM

**Key details:**
- Source Address: [trenton@tritowncomputers.com]
	- SMTP Address: [24.213.228.54]
- Dest Address: [lars@letsdefend.io]
- Hostname: LarsPRD
- User: Lars
- What triggered: Email

**First impression:** Potential phishing email

---
## Checklist - Critical Questions

**The Big 5:**
-  Is this malicious? Y
-  Was it successful? Y
-  Is it still happening? N
-  Are other systems affected? N
-  Do we need to contain NOW? Y - Done

**If YES to containment:**
-  Isolate endpoint - Complete
-  Block source IP - TBA
-  Disable user account - TBA
-  Alert senior analyst/manager - TBA

---
## Raw Notes Section

**Time:** 08:30AM
**Action:** Initial Email
**Finding:** Attachment in email. Potentially malicious. 

**Time:** 08:32AM
**Action:** OSINT for tritowncomputers.com
**Finding:** Found a legitimate website but the email provided in the website ends with [@gmail.com]. Doesn't match with the senders email.

**Time:** 08:34AM
**Action:** Checking attachment & SMTP address with Hybrid Analysis and VirusTotal
**Finding:** The files seem to be hidden inside the zip file. My personal system has strong safeguards in place so cannot extract the folder, no SSH to VM available either.

**Time:** 08:57AM
**Action:** Checking EDR and Log Management
**Finding:** Inconclusive currently, going to investigate other sections then come back.

**Time:** 09:03AM
**Action:** Reanalyzing Hybrid Analysis
**Finding:** Discovering the files that are hidden from my personal device, iroto.dll, research-1646684671.xls (excel file) and iroto1.dll.

**Time:** 09:06AM
**Action:** Putting the discovered files through Virus Total
**Finding:** See results in [Threat Intel Workspace].

**Time:** 10:01AM
**Action:** Investigation if user accessed the file
**Finding:** At 13/06/25 14:20 and 14:20, user had accessed both URLs that are suspected to be the C2 servers. Contained the device.

**Time:** 10:25AM
**Action:** Going through Playbook
**Finding:** Deleting email, adding artifacts, closing alert.

---
## Log Analysis Workspace

**Source to check:**
-  Firewall logs - Y
-  Proxy logs - Y
-  EDR/Endpoint logs - Y
-  SIEM alerts - Y
-  Web server logs - Y
-  Email gateway logs - Y
-  DNS logs - Y

---
## Threat Intel Quick Checks

### VirusTotal
URL: [VirusTotal - Download Link CHECK](https://www.virustotal.com/gui/url/037806093bfc1991a4911f636bee8503b2ba90187499b8d9300e80bd93154bc5/detection)
- Detection: 06/98
- Notes: As this is only the download link to the file, it isn't 100% accurate. We still see traces of some kind of malware, potentially spyware.
- SHA-256: [5227d46686367b2ecd044c9269f1857c5d1c2205b1fe174bd4dc63bcb9337099]
- Serving IP Address: [52.219.178.226]

URL: [VirusTotal - File - research-1646684671.xls](https://www.virustotal.com/gui/file/1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820)
- Detection: 38/62
- Notes: Contacts two specific URLS, [royalpalm.sparkblue.lk] and [nws.visionconsulting.ro]. Has indications of a trojan. Searches through the user files and seems to embed/delete files. Also searches through registry.
- SHA-256: [1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820]

URL: [VirusTotal - File - iroto.dll](https://www.virustotal.com/gui/file/055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946)
- Detection: 14/72
- Notes: Malicious, it is a .dll (dynamic link library) which contains a set of coded instructions and data that can harm the system. In this case, its injecting itself into the registry. It is also attempting to detect if it is inside a virtual machine/sandbox to not activate itself.
- SHA-256: [055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946]

URL: [VirusTotal - File - iroto1.dll](https://www.virustotal.com/gui/file/e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b)
- Detection: 13/72
- Notes: Very similar to iroto.dll, also creates and drops files - most likely for persistence.
- SHA-256: [e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b]

URL: [VirusTotal - IP address - 24.213.228.54](https://www.virustotal.com/gui/ip-address/24.213.228.54)
- Detection: 0/95
- Notes: Nothing of note, last analysis was 22 hours ago (as of writing). Based in the US, but we do know that one of the malicious files communicates with a Romanian webserver. Does have a 10/65 for a file referring to it, and many domain names that resolved to this IP address (including tritowncomputers.com).

### Hybrid Analysis
URL: [Hybrid Analysis - Initial Zip File](https://hybrid-analysis.com/sample/6cec2bf8e5bde0a9d885ca6276d5a3d77affe4225824836a762984e7ecdc8a40)
- Threat Score: 100/100
- AV Detection: 7%
- Labeled as: Trojan.Generic
- Notes: MetaDefender has 2 indications for it being malicious and a trojan. We can see the three bundled files that are inside.

URL: [Hybrid Analysis - research-1646684671.xls](https://hybrid-analysis.com/sample/1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820#)
- Threat Score: 100/100
- AV Detection: 74%
- Labeled as: Trojan.Generic
- Notes: We see here that CrowdStrike Falcon is considering it 100% malicious and MetaDefender 13/27. CSF doesn't have further details from the anti-virus results section but MD sees mostly trojan alerts. In the sandbox reports we can see that it appears as a contract excel file but there are functions operating in the background such as resvr32.exe to not be detected and communicating with a webserver (C2 server) to receive commands. This is working alongside with the other two .dll files to execute these commands.

URL: [Hybrid Analysis - iroto.dll](https://hybrid-analysis.com/sample/055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946)
- Threat Score: 100/100
- AV Detection: 9%
- Labeled as: Trojan.Buzus.Iba
- Notes: Doesn't come up as a threat for the Windows 11 and Windows 7 (32-bit, HWP support) systems, could be due to the file detecting that it is inside a virtual machine.

URL: [Hybrid Analysis - iroto1.dll](https://hybrid-analysis.com/sample/e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b)
- Threat Score: 100/100
- AV Detection: 8%
- Labeled as: Trojan.Buzus.Iba
- Notes: Hooks API calls and into the running process for persistence. Works alongside iroto.dll and excel file.

### WhoIs Lookup
NetRange: [24.213.128.0 - 24.213.255.255](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%252224.213.128.0%2520-%252024.213.255.255%2522)
CIDR: [24.213.128.0/17](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A24.213.128.0%252F17)
NetName: [RR-COMMERCIAL-NYC-3](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253ARR-COMMERCIAL-NYC-3)
NetHandle: [NET-24-213-128-0-1](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253ANET-24-213-128-0-1)
Parent: [NET24 (NET-24-0-0-0-0)](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522NET24%2520\(NET-24-0-0-0-0\)%2522)
NetType: [Direct Allocation](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522Direct%2520Allocation%2522)
Organization: [Charter Communications Inc (CC-3517)](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522Charter%2520Communications%2520Inc%2520\(CC-3517\)%2522)
RegDate: [2003-03-06](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A2003-03-06)
Updated: [2003-08-29](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A2003-08-29)
Ref: [https://rdap.arin.net/registry/ip/24.213.128.0](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522https%253A%252F%252Frdap.arin.net%252Fregistry%252Fip%252F24.213.128.0%2522)
OrgName: [Charter Communications Inc](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522Charter%2520Communications%2520Inc%2522)
OrgId: [CC-3517](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253ACC-3517)
Address: [6175 S. Willow Dr](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%25226175%2520S.%2520Willow%2520Dr%2522)
City: [Greenwood Village](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522Greenwood%2520Village%2522)
StateProv: [CO](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253ACO)
PostalCode: [80111](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A80111)
Country: [US](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253AUS)
RegDate: [2018-10-10](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A2018-10-10)
Updated: [2022-09-14](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A2022-09-14)
Comment: [Legacy Time Warner Cable IP Assets](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522Legacy%2520Time%2520Warner%2520Cable%2520IP%2520Assets%2522)
Ref: [https://rdap.arin.net/registry/entity/CC-3517](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522https%253A%252F%252Frdap.arin.net%252Fregistry%252Fentity%252FCC-3517%2522)
OrgTechHandle: [IPADD1-ARIN](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253AIPADD1-ARIN)
OrgTechName: [IPAddressing](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253AIPAddressing)
OrgTechPhone: [+1-866-248-7662](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%252B1-866-248-7662)
OrgTechEmail: [PublicIPAddressing@charter.com](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253APublicIPAddressing%2540charter.com)
OrgTechRef: [https://rdap.arin.net/registry/entity/IPADD1-ARIN](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522https%253A%252F%252Frdap.arin.net%252Fregistry%252Fentity%252FIPADD1-ARIN%2522)
OrgAbuseHandle: [ABUSE19-ARIN](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253AABUSE19-ARIN)
OrgAbuseName: [Abuse](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253AAbuse)
OrgAbusePhone: [+1-877-777-2263](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%252B1-877-777-2263)
OrgAbuseEmail: [abuse@charter.net](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253Aabuse%2540charter.net)
OrgAbuseRef: [https://rdap.arin.net/registry/entity/ABUSE19-ARIN](https://www.virustotal.com/gui/search/entity%253Aip%2520whois%253A%2522https%253A%252F%252Frdap.arin.net%252Fregistry%252Fentity%252FABUSE19-ARIN%2522)

### ~~AbuseIPDB~~  
~~URL: https://www.abuseipdb.com/check/[IP]~~
-  ~~Checked~~
- ~~Confidence: X%~~
- ~~Reports: X~~
- ~~Notes:~~

### ~~URLhaus (if URL/domain)~~
~~URL: https://urlhaus.abuse.ch/~~
-  ~~Checked~~
- ~~Listed: Y/N~~
- ~~Notes:~~

### ~~Cisco Talos~~
~~URL: https://talosintelligence.com/reputation_center/lookup?search=[IP]~~
-  ~~Checked~~
- ~~Reputation:~~ 
- ~~Notes:~~

**Quick verdict from OSINT:** 
	**Malicious - High Confidence**
**Summary:**
- Spoofed sender (tritowncomputers.com used by attacker, real business uses @gmail)
- SMTP from residential ISP (Charter Communications) - not legitimate business mail server
- Multi-stage malware (Zip → Excel → DLLs → C2)
- 100/100 threat scores on all files (Hybrid Analysis)
- Active C2 communication confirmed (user accessed both C2 URLs)
- Known malware family: Trojan.Buzus.**Iba**

---
## Scope Check

**Who's affected?**
- User(s): Lars
- System(s): LarsPRD
- Number of attempts: 1
- Time range: ~9 minutes

**Did it spread?**
-  Checked other endpoints - N
-  Checked for lateral movement - N
-  Checked for data exfil - Y
-  Checked for persistence - Y

**Other victims from same source?**
Query: N/A
Results: N/A

---
## Timeline Building

| Time           | Event                                                                                                      | Source              | Notes                                                  |
| -------------- | ---------------------------------------------------------------------------------------------------------- | ------------------- | ------------------------------------------------------ |
| 13/06/21 14:11 | Email received from [trenton@tritowncomputer.com] by user                                                  | Email Security      | Initial access                                         |
| 13/06/21 14:13 | SIEM alert for phishing alert                                                                              | Monitoring          | Alert                                                  |
| 13/06/21 14:20 | Website [https://royalpalm.sparkblue.lk/vCNhYrq3Yg8/dot.html] opened as result of user opening excel file. | Endpoint Management | Malicious website suspected to be the C2 server        |
| 13/06/21 14:21 | Website [https://nws.visionconsulting.ro/N1G1KCXA/dot.html] opened as result of user opening excel file.   | Endpoint Management | Malicious website suspected to be the second C2 server |

---
## IOC Collection

### Network Indicators

**Email Infrastructure:**
- SMTP IP: 24.213.228.54 (Charter Communications, Colorado, US)
- Sender email: trenton@tritowncomputers.com
- Sender domain: tritowncomputers.com
**Command & Control:**
- C2 Domain 1: [royalpalm.sparkblue[.]lk] (Sri Lanka TLD)
  - Full URL: [https://royalpalm.sparkblue[.]lk/vCNhYrq3Yg8/dot.html]
  - Accessed: 13/06/21 14:20
- C2 Domain 2: [nws.visionconsulting[.]ro] (Romania TLD)
  - Full URL: [https://nws.visionconsulting[.]ro/N1G1KCXA/dot.html]
  - Accessed: 13/06/21 14:21
- File hosting IP: 52.219.178.226 (AWS hosting)
**Internal:**
- Victim IP: 172.16.17.57 (LarsPRD)
### File Indicators

**Primary Attachment:**
- Filename: 11f44531fb088d31307d87b01e8eabff.zip.zip
- SHA-256: [need hash of zip file itself]
- Contains: research-1646684671.xls, iroto.dll, iroto1.dll
**Excel File (Dropper):**
- Filename: research-1646684671.xls
- Type: Microsoft Excel (Excel 4.0 Macros)
- SHA-256: [1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820]
- Detection: 38/62 (VirusTotal), 74% (Hybrid Analysis)
- Label: Trojan.Generic
**DLL Payload #1:**
- Filename: iroto.dll
- Type: Windows Dynamic Link Library
- SHA-256: [055b9e9af987aec9ba7adb0eef947f39b516a213d663cc52a71c7f0af146a946]
- Detection: 14/72 (VirusTotal), 9% (Hybrid Analysis)
- Label: Trojan.Buzus.Iba
- Behavior: Registry injection, VM detection, API hooking
**DLL Payload #2:**
- Filename: iroto1.dll
- Type: Windows Dynamic Link Library
- SHA-256: [e05c717b43f7e204f315eb8c298f9715791385516335acd8f20ec9e26c3e9b0b]
- Detection: 13/72 (VirusTotal), 8% (Hybrid Analysis)
- Label: Trojan.Buzus.Iba
- Behavior: File dropping, persistence, API hooking
**Download URL:**
- URL: [Download Link !DO NOT OPEN IN ACTUAL DEVICE!](https://files-ld.s3.us-east-2.amazonaws.com/11f44531fb088d31307d87b01e8eabff.zip.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Content-Sha256=UNSIGNED-PAYLOAD&X-Amz-Credential=AKIA6DVNZHVQL3MSEK46%2F20251208%2Fus-east-2%2Fs3%2Faws4_request&X-Amz-Date=20251208T194723Z&X-Amz-Expires=60&X-Amz-Signature=854fcec0f4e51de83ab7dda5e5c35e51a9f15d16d2bf87b59cfd56c3ac7b9f06&X-Amz-SignedHeaders=host&x-amz-checksum-mode=ENABLED&x-id=GetObject)
- SHA-256: [5227d46686367b2ecd044c9269f1857c5d1c2205b1fe174bd4dc63bcb9337099]
- Serving IP: 52.219.178.226
- Detection: 6/98 (VirusTotal)
### Host Indicators

**File Paths (add if available from endpoint forensics):**
- C:/Windows/System32/regsvr32.exe
**Registry Keys (from VirusTotal behavior):**
- HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\
- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\
- \REGISTRY\A\
**Processes:**
- Excel.exe spawned regsvr32.exe (MITRE T1218.010)
- regsvr32.exe registered malicious DLLs
	- 14:20 (first URL) - regsvr32.exe -s ../iroto.dll
	- 14:21 (second URL) - regsvr32.exe -s ../iroto1.dll
### Email Indicators

**Email Headers (if accessible):**
- From: trenton@tritowncomputers.com
- To: lars@letsdefend.io
- Subject: RE: Meeting Notes
- Date: June 13, 2021 14:11
- Attachment: [11f44531fb088d31307d87b01e8eabff.zip.zip]
- SPF/DKIM/DMARC: [check results - likely FAIL]
### Account Indicators

**Compromised:**
- Username: Lars
- Email: lars@letsdefend.io
- System: LarsPRD
- **Status: Credentials COMPROMISED**
### Malware Family

**Identification:**
- Family: Trojan.Buzus (variant: Iba)
- Type: Trojan Dropper/Downloader
- Capabilities:
  - Credential theft (API hooking)
  - Data exfiltration (C2 comms)
  - Persistence (registry, DLL side-loading)
  - Process injection
  - Anti-VM detection

---

## MITRE ATT&CK Mapping

### Initial Access (TA0001)
- **T1566.001** - Phishing: Spearphishing Attachment
  - Evidence: Email from trenton@tritowncomputers.com with Zip file containing malicious excel file
  - Subject: "RE: Meeting Notes" (fake reply social engineering)
  - Attachment: 11f44531fb088d31307d87b01e8eabff.zip.zip
  - Delivered to: lars@letsdefend.io
- **T1566.001** - User Execution: Malicious File
  - Evidence: Requires user to open Excel file for macro execution
  - Social engineering: "RE:" implies continuing conversation
  - Excel 4.0 macros may auto-execute without explicit enable

### Execution (TA0002)
- **T1203** - Exploitation for Client Execution
  - Evidence: Malicious Excel document exploits Office vulnerability to execute macro code
- **T1218.010** - System Binary Proxy Execution: Regsvr32
  - Evidence: Detected regsvr32.exe execution to register malicious DLLs

### Persistence (TA0003)
- **T1574.002** - Hijack Execution Flow: DLL Side-Loading
  - Evidence: Drops iroto.dll and iroto1.dll for persistent execution
- **T1056.004** - Input Capture: Credential API Hooking
  - Evidence: Installs hooks into running processes to capture credentials

### Privilege Escalation (TA0004)
- **T1574.002** - Hijack Execution Flow: DLL Side-Loading
  - Evidence: Side-loads malicious DLLs to execute with elevated privileges
- **T1055** - Process Injection
  - Evidence: Writes data and allocates virtual memory in remote process space
- **T1056.004** - Input Capture: Credential API Hooking
  - Evidence: API hooks allow privilege escalation through credential theft

### Defense Evasion (TA0005)
- **T1218.010** - System Binary Proxy Execution: Regsvr32
  - Evidence: Abuses legitimate Windows binary to bypass application control
- **T1574.002** - Hijack Execution Flow: DLL Side-Loading
  - Evidence: Disguises malicious code as legitimate library loading
- **T1055** - Process Injection
  - Evidence: Hides malicious code by injecting into legitimate processes
- **T1036** - Masquerading
  - Evidence: Renames malicious files to appear legitimate

### Credential Access (TA0006)
- **T1056.004** - Input Capture: Credential API Hooking
  - Evidence: Hooks credential input APIs to steal passwords and authentication data

### Discovery (TA0007)
- **T1057** - Process Discovery
  - Evidence: Enumerates running processes on infected system
- **T1012** - Query Registry
  - Evidence: Queries registry keys for system configuration
- **T1082** - System Information Discovery
  - Evidence: Reads software policies and system information
- **T1033** - System Owner/User Discovery
  - Evidence: Executes 'whoami' to identify current user context
- **T1010** - Application Window Discovery
  - Evidence: Scans for specific window names/titles

### Collection (TA0008)
- **T1005** - Data from Local System
  - Evidence: Attempts to access and read document files on local system
- **T1056.004** - Input Capture: Credential API Hooking
  - Evidence: Collects credentials through API hooks

### Exfiltration (TA0010)
- **T1041** - Exfiltration Over C2 Channel
  - Evidence: POSTs stolen data to C2 servers (royalpalm.sparkblue[.]lk, nws.visionconsulting[.]ro) via HTTPS
- **T1030** - Data Transfer Size Limits
  - Evidence: Multiple POST requests with consistent size but different payloads (evasion of size-based detection)

### Command and Control (TA0011)
- **T1071.001** - Application Layer Protocol: Web Protocols
  - Evidence: Uses HTTPS for C2 communication (GET/POST requests)
- **T1573** - Encrypted Channel
  - Evidence: Uses TLS/SSL encryption for C2 communications
- **T1105** - Ingress Tool Transfer
  - Evidence: Downloads additional executables from web server via HTTPS, drops files to disk

---
## ATT&CK Summary
**Primary Kill Chain:**
1. **Initial Access** → Phishing email with malicious Zip file (T1566.001)
2. **Execution** → Excel macro exploitation (T1203, T1218.010)
3. **Persistence** → DLL side-loading (T1574.002)
4. **Defense Evasion** → Process injection, masquerading (T1055, T1036)
5. **Credential Access** → API hooking (T1056.004)
6. **Discovery** → System reconnaissance (T1057, T1012, T1082, T1033, T1010)
7. **Collection** → Local data access (T1005)
8. **C2** → HTTPS communication to C2 servers (T1071.001, T1573)
9. **Exfiltration** → Data exfil over C2 channel (T1041)

**Total Techniques:** 17 unique MITRE ATT&CK techniques across 9 tactics

**Sophistication Level:** Medium-High
- Multi-stage infection
- Process injection and API hooking
- Encrypted C2 communications
- Anti-analysis techniques (regsvr32 abuse, masquerading)

---
## Decision Points

**Is this malicious?**
- Evidence for: Yes, this .zip folder contains three files, one of which is an excel file, that begins to run malicious code against the machine and communicate with the C2 server.
- Evidence against: None
- **Decision:** Yes, this file is very obviously malicious

**Was attack successful?**
- Evidence it worked: User had accessed the attachment and the C2 server was communicated to.
- Evidence it failed: Did not spread to other machines.
- **Decision:** Sucess/Partial

**Severity assessment:**
- Impact if successful: High
- Actual impact: High
- Urgency: Immediate

---
## Containment Actions

**What needs to happen NOW:**
-  Block IP: [24.213.228.54]
-  Isolate endpoint: LarsPRD
-  Disable account: [username]
-  Reset credentials: [username]
-  Quarantine file: [11f44531fb088d31307d87b01e8eabff.zip.zip]
-  Kill process: [process name]

---
## Recommendations

#### Immediate (within 24 hours):
1. **Block all IOCs at perimeter:**
   - SMTP IP: 24.213.228.54
   - C2 domains: royalpalm.sparkblue[.]lk, nws.visionconsulting[.]ro
   - File hashes: [all 4 hashes documented]
   - Sender domain: tritowncomputers.com (if confirmed spoofed)
2. **Reset Lars's credentials across ALL systems:**
   - Domain password
   - Email password
   - VPN credentials
   - Any application-specific passwords
   - Force MFA enrollment if not already enabled
3. **Complete endpoint forensics on LarsPRD:**
   - Full malware scan with updated signatures
   - Memory dump analysis (DLLs may be in memory)
   - Check for additional persistence mechanisms
   - Review all recent file access/modifications
   - Check for lateral movement attempts
4. **Search all mailboxes for same campaign:**
```
   From: trenton@tritowncomputers.com OR
   Subject: "RE: Meeting Notes" OR
   Attachment: 11f44531fb088d31307d87b01e8eabff.zip.zip OR
   Attachment hash: 1df68d55968bb9d2db4d0d18155188a03a442850ff543c8595166ac6987df820
   Date: June 13, 2021 (±2 days)
```
   - Quarantine/delete from all mailboxes
   - Identify if any other users opened attachment
   - Check endpoints of anyone who received email
5. **Monitor Lars's account activity:**
   - Watch for unauthorized login attempts
   - Review recent account activity (past 7 days)
   - Check for unusual email rules or forwards
   - Verify no unauthorized access to sensitive systems

#### Short-term (within 1 week):
6. **Email security enhancements:**
   - Enable/enforce SPF, DKIM, DMARC
   - Implement email banner warnings for external emails
   - Deploy advanced threat protection (ATP) for attachments
   - Enable sandboxing for all attachments
   - Block/quarantine Excel 4.0 macro files by default
7. **Endpoint protection improvements:**
   - Deploy EDR if not present on all systems
   - Update AV signatures
   - Enable behavioral analysis/AMSI for Office macros
   - Block regsvr32.exe execution from Office processes
   - Implement application whitelisting
8. **User education:**
   - Security awareness training for Lars (targeted, not punitive)
   - Company-wide phishing awareness training
   - Focus on: fake "RE:" emails, unexpected attachments, verification procedures
   - Implement "report phishing" button in email client
9. **Incident response process review:**
   - Why did it take 7 minutes (14:13 alert → 14:20 C2 access)?
   - How can we respond faster?
   - Should Excel 4.0 macros trigger immediate isolation?

#### Long-term (ongoing):
10. **Proactive threat hunting:**
    - Search environment for other Excel 4.0 macro files
    - Hunt for DLL side-loading artifacts
    - Check for regsvr32.exe abuse patterns
    - Review historical connections to suspicious domains
11. **Email authentication enforcement:**
    - DMARC policy: reject (not quarantine)
    - Regular SPF/DKIM record audits
    - Monitor authentication failures
12. **Detection engineering:**
    - Create SIEM rules for:
      - Excel spawning regsvr32.exe
      - Multiple HTTP POSTs to same domain (data exfil)
      - DLL writes to unusual locations
      - Connections to newly registered domains
    - Alert on Excel 4.0 macro execution
13. **Regular testing:**
    - Monthly phishing simulations
    - Quarterly incident response tabletop exercises
    - Annual penetration testing
    - Red team exercises (test Excel 4.0 macro detection)
14. **Threat intelligence integration:**
    - Subscribe to threat feeds for Excel 4.0 macro campaigns
    - Monitor for similar IOCs (Trojan.Buzus family)
    - Share IOCs with industry ISACs

---
## Final Verdict

**Verdict:** Malicious - True Positive

**Confidence:** High (100%)

**Summary:**
Confirmed phishing attack delivering Trojan.Buzus.Iba malware via (potentially) spoofed business email. User Lars opened malicious Excel file containing Excel 4.0 macros, which executed multi-stage payload (iroto.dll, iroto1.dll). Malware established persistence via registry modifications and API hooking, then connected to two C2 servers (Sri Lanka and Romania) for command and control. Data exfiltration occurred. Endpoint isolated, credentials compromised and require reset. Email security controls failed to detect Excel 4.0 macros. Attack progression: 9 minutes from email delivery to C2 communication. No lateral movement detected.

**Attribution/Geography:**
- **Attack origin:** Likely international organized cybercrime
- **SMTP source:** US (Colorado - Charter ISP) - likely compromised residential/business connection OR VPN exit node
- **C2 Infrastructure:**
  - Primary C2: Sri Lanka (.lk domain)
  - Secondary C2: Romania (.ro domain)
- **File hosting:** AWS (52.219.178.226) - cloud infrastructure abuse
- **Assessment:** Not specifically US/Romania/Sri Lanka origin - attackers use global infrastructure to obfuscate location. C2 servers likely compromised legitimate websites in those countries.

**Impact Assessment:**
- **Severity:** HIGH
- **User compromise:** Confirmed (credentials, data)
- **System compromise:** Confirmed (persistence, C2 access)
- **Data exposure:** HIGH LIKELIHOOD (credential theft capabilities confirmed)
- **Spread:** None detected (isolated to LarsPRD)
- **Business impact:** Moderate (single user, no spread, quick containment)

**Response Quality:** Good
- Fast detection (2 min after delivery via SIEM)
- Endpoint isolated
- IOCs documented

---