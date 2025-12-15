[15/12/2025]
## What is Cyber Threat Intelligence (CTI)?

- Cybersecurity discipline focused on producing actionable intelligence.
- Processes and interprets data from multiple sources.
- Helps organizations prevent, detect, and reduce impact of cyber attacks.
- The purpose is to understand attackers Techniques, Tactics and Procedures (TTPs) as well as turning this into meaningful data.

---
## CTI Lifecycle

![[CTI_Lifecycle.png.png]]

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
		- **The individuals/employees/users:
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
- Weighs the tatical CTI outputs against the tasks that the organization has in the long-run.

---

## Attack Surface

- 