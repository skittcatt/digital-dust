[15/12/2025]
## Using Threat Intelligence - XTI Framework

*Extended Threat Intelligence (XTI)* combines three key areas to provide comprehensive threat awareness:

1. **External Attack Surface Management (EASM)** → What attackers can see and target
2. **Digital Risk Protection (DRP)** → How the brand and people are at risk
3. **Cyber Threat Intelligence (CTI)** → What's happening in the global threat landscape

When all three areas are combined and integrated with security tools (SIEM, SOAR, EDR), they form a complete XTI structure that enables proactive defense.

---
## CTI Lifecycle

![[CTI_Lifecycle.png]]
#### Step One: Planning & Direction
- Foundational structure for CTI.
- It defines what intelligence is needed, who uses it, and how its used by asking certain questions:
	- *Does the organization have a SOC team?*
		- **If yes** - more technical and detailed intelligence would be needed for that SOC team.
		- **If no** - this indicates that managers would use the intelligence. High-level summaries with less technical jargon would be more appropriate.
	- ***Has the organization been attacked before? What's the success rate?***
		- How successful were those attacks?
		- Use past attacks to:
			- Improve future defenses
			- Decide how often intelligence should be updated
		- Organizations attacked often need:
			- Frequent intelligence updates
			- Fast response and consumption
	- ***Who is targeted in the attacks?***
		- **The organization:**
			- Ensure focus is on exposed/vulnerable systems and assets.
			- Use External Attack Surface Management (EASM), this is designed more for attacks targeting the system surface itself.
		- **The individuals/employees/users:**
			- Ensure focus is on the users and the user risks.
			- Use Digital Risk Protection (DRP), as this is designed more for defining the risks that companies may face through the surface.
	- ***Are there other companies exposed to the same attacks?***
		- If yes - use this information to learn from each other in the attacks.
		- Share and identify if any of the IOC's/threat actors are the same.

#### Step 2: Information Gathering
- We identify *where* we would gather the information/data from.
- Data can come from either internal or external sources.
- Here is a list from LetsDefend of some possible sources:
	- Hacker Forums
	- Ransomware Blogs
	- Deep/Dark Web Forums and Bot Markets
	- Public Sandboxes
	- Telegram/ICQ/IRC/Discord/Twitter/Instagram/Facebook/LinkedIn
	- Surface Web(Cybersecurity Blogs etc.)
	- Public Research Reports
	- File Download Sites
	- Github/Gitlab/Bitbucket etc.
	- Public Buckets (Amazon S3/Azure Blob etc.)
	- Shodan/Binary Edge/Zoomeye vb.
	- Sources that provide IOC (Alienvault, Abuse.ch, MalwareBazaar vb.)
	- Honeypots
	- SIEM, IDS/IPS, Firewalls
	- Public Leak Databases

#### Step 3: Processing
- This is where we have all of our data and need to filter it down to only the important information.
- Some ways to 'process' the information:
	- Clean from false positives.
	- Pass through rulesets.
	- Subject to correlations.

#### Step 4: Analysis & Production
- We interpret the information and analyze it.
- Reports are to be prepared for the respective personnel.

#### Step 5: Dissemination & Feedback
- This is where we share the information/report with the right person/people.
- The intelligence should be distributed through the appropriate channels depending on the user.
	- Technical teams should receive the technical and detailed versions.
	- Management or other teams should receive the summarized version or the lesser detailed reports.
- Feedback would be provided by the teams that were given the information to improve accuracy and usefulness.
 
---
## Types of CTI 
- The reason why it is split up is because the CTI varies by position in a company.
	- Technical staff would have different intelligence that managerial staff.

#### Technical CTI 
- Low-level, short-term use.
- Analysis based on IOCs.
- The output would be to create rulesets from a report containing hashes of malicious IP addresses, phishing domains and harmful files.
- Used primarily by SOC analysts and incident responders.

#### Tactical CTI
- Low-level, long-term use.
- Used to understand the TTP of attackers by trying to find the answers to certain questions. Simple questions like:
	- What vulnerabilities does this attacker exploit the most?
	- Where in the world does this attacker operate from?
	- What is the motivation of the attacker?
	- What are the primary methods that the attacker uses?
- The report for tactical CTI should be able to answer these questions, and is better suited for management personnel like the SOC manager who lead the technical teams.

#### Operational CTI
- High-level, short-term use.
- Similar to tactical CTI, but used mostly for threat hunting.
- Focuses more on a specific *type* of attack, or a single attacker rather than an entire group.
- Used by security managers or threat hunting personnel.

#### Strategic CTI
- High-level, long-term use.
- Used for long-term tasks, these can include:
	- Product purchasing.
	- Budgeting.
	- Planning.
- Weighs the tactical CTI outputs against the tasks that the organization has in the long-run.

---
## Using Threat Intelligence
- We gain consumable threat intelligence after the data has been interpreted and analyzed.
- There are three different areas where the intelligence can be used. When all three of these areas are combined, they form the XTI (Extended Threat Intelligence) structure.

### External Attack Surface Management (EASM)

**What EASM is**
- Manages everything the organization exposes to the internet
- Helps find unknown, forgotten, or misconfigured assets

**What EASM Monitors**
- Domains & subdomains
- IP addresses    
- Websites    
- Open ports    
- SSL certificates
    
**Why EASM Matters**
- Exposed assets = attack opportunities
- Vulnerabilities on public assets increase risk    
- Assets must be **continuously monitored**
    
**Common EASM Alerts**
- **New asset detected** → Check if it belongs to the organization    
- **Domain / DNS change** → Verify it was authorized    
- **DNS zone transfer** → Check for misconfiguration    
- **Internal IP exposed** → Fix DNS record    
- **Critical open port** → Close or secure it    
- **SMTP open relay** → Fix mail server configuration    
- **SPF / DMARC missing** → Configure email security records    
- **SSL expired/revoked** → Renew certificate    
- **Suspicious redirect** → Possible compromise    
- **Subdomain takeover** → Fix DNS immediately    
- **Website status changed** → Investigate outage or issue    
- **Vulnerability detected** → Patch immediately    

### Digital Risk Protection (DRP)

**What DRP is**
- Protects the organization’s brand, people, and reputation
- Focuses on threats outside the internal network

**What DRP Monitors**
- Phishing domains    
- Fake mobile apps    
- Social media impersonation    
- Dark & Deep Web activity    
- Leaked data and credentials    

**Common DRP Alerts**
- **Phishing domain** → Investigate & request takedown    
- **Fake mobile app** → Analyze & remove    
- **IP reputation loss** → Investigate possible abuse or breach    
- **Impersonating social account** → Report & request removal    
- **Botnet listing** → Isolate system & reset credentials    
- **Dark web mention** → Analyze threat early    
- **IM platform mention** → Investigate conversation    
- **Stolen credit card** → Inform fraud team    
- **Data leak in repo/bucket** → Remove data immediately    
- **Malware mentioning company** → Analyze file    
- **Employee/VIP credentials leaked** → Reset passwords    

### Cyber Threat Intelligence (CTI)

**What CTI is**
- Sub-branch of XTI focused on the broader cyber threat landscape.
- Monitors global threat activity and trends.
- Provides awareness of what's happening in the cyber world.
- Complements EASM and DRP with external threat context.

**What CTI Monitors**
- Current malicious campaigns (global threat activity)
- Ransomware group operations and targets
- Offensive IP addresses and infrastructure worldwide
- Emerging vulnerabilities and exploits
- Threat actor movements and tactics
- Zero-day discoveries
- Botnet activity

**How CTI Works**
- **Global perspective:** Monitors threats beyond just your organization
- **Intelligence feeds:** Aggregates data from multiple sources worldwide
- **Corporate integration:** Combines global CTI with your organization's internal data (corporate feeds)
- **Tool enhancement:** Integrates with SIEM, SOAR, and EDR platforms

