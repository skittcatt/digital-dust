### Intrusion Detection System (IDS)

- Detects security breaches and attacks.
- Monitors a network or a host.
- Different types:
	- Network (NIDS)
		- Observes all traffic passing through the network. 
		- Once it finds abnormal behaviour, it generates an alert to the network administrator.
	- Host (HIDS)
		- Works on a specific host on the network.
		- Examines network packets going to and from the host device and generates an alert once it detects malicious activity.
	- Protocol-Based (PIDS)
		- Examines the traffic between a server and client in a protocol-specific way.
	- Application Protocol-Based (APIDS)
		- Detects breaches/attacks by examining traffic in application-specific protocols.
	- Hybrid
		- A type of IDS that uses two or more violation detection approaches together.
- IDS sends alerts to a SIEM for analysts to examine.
- Detects violations by established rules. Rules must be regularly checked and updated to ensure it is properly alerting breaches and attacks.

---
### Intrusion Prevention System (IPS)

- Detects violations and prevents them.
- Different Types:
	- Network-Based (NIPS)
		- Monitors and prevents violations from the incoming traffic to the network.
	- Host-Based (HIPS)
		- Monitors and prevents violations from incoming and outgoing traffic on a specific host.
	- Network Behaviour Analysis (NBA)
		- Detects and blocks unusual traffic flows and Denial of Service (DoS) attacks on the network.
	- Wireless (WIPS)
		- Monitors and prevents violations of wireless devices in the network.
- Needs to be monitored by an admin to ensure the correct functions are being performed by the IPS (not plug-and-play).

---

### Firewall

- Different types:
	- Application-Level Gateways (Proxy)
		- Blocks at the application layer between two end systems.
		- Captures and analyses packets.
	- Circuit-Level Gateways
		- Easy to configure, low resource consumption, simple structure.
		- Verifies TCP connections and sessions.
		- Operates in the session layer of the OSI model.
	- Cloud Firewalls (also know as FWaaS)
		- A firewall service over a cloud service.
		- No physical resources used.
		- Modular, can add/deplete capacity as required.
	- Endpoint Firewalls
		- Protects that specific device/host.
		- Runs locally on the computer.
		- You manage it per device.
		- Harder to manage across many devices.
	- Network Address Translation (NAT) Firewalls
		- Hides your internal network's real IP while on the internet.
		- Accesses internet traffic and blocks unwanted connections.
		- All internal devices share one public IP.
		- Translates internal IPs (192.168.x.x) to public IP when going online.
	- Next-Generation Firewalls (NGFW)
		- It is like a modern version of your typical firewall with additional features added into it.
		- Deep-packet inspection (DPI), reads inside packets.
		- Blocks malware, external threats, advanced attack methods.
	- Packet-Filtering Firewalls
		- Most basic firewall.
		- Quick solution, doesn't have any resource requirements
			- Has disadvantages - can't block web-based attacks
		- Scans source and destination IP, ports and protocol then matches it against its rules.
	- Stateful Multi-Layer Inspection (SMLI) Firewalls
		- Can do both packet inspection and validate TCP handshakes.
		- Can track the status of established connections.
	- Threat-Focused NGFW
		- All NGFW features plus new features.
		- Advanced threat detection, can react quickly to attacks.
		- Rules written with a threat focus.
		- Monitors all malicious activity from start to finish.
	- Unified Threat Management (UTM) Firewalls
		- Special type of stateful inspection firewall with added antivirus and intrusion prevention.
		- 'Everything in one box'
- Even though they all seem to have different functions, the basic principle is the same - it creates a safety barrier between two networks/departments/devices to block/allow traffic.

---

### Endpoint Detection and Response (EDR)

- Endpoint devices are anything like a mobile phone, laptop, server, POS system, etc.
- EDR works by:
	- Monitoring and collecting each process on the device that may identify a security threat
	- Analyzing the behavior of threat actors according to the data collected on the device
	- Informing the relevant analyst by taking the appropriate security action against the threat actor obtained from the collected data.
	- Allow forensic analysis on the device to conduct in-depth investigation of suspicious activities
- Security needs to be ensured on endpoint devices since attackers aim to use weak devices to access the network.

---

### Antivirus Software (AV)

- Detects malware on devices then attempted to block and remove it before it does harm to the system
- Different Types:
	- Signature-Based Scanning
		- Scans the system with a digital signature. If it comes up with a match, it will mark that file as 'malicious' and removes it from the system.
		- Needs to be updated constantly to keep with up-to-date known malware.
	- Heuristic Scanning
		- Monitors the accesses and behaviour of examined files.
		- If the file can read or modify system files that it shouldn't, this AV will mark it as 'malicious' (doesn't seem to remove it automatically).
		- Can mark as malicious even if it isn't in the database.
- Detect, Protect, Clean.

---
### Sandbox Solutions

- An isolated environment used to run/open and examine suspicious and potentially malicious files.

---
### Data Loss Prevention (DLP)

- Prevents sensitive and critical information from being extracted from the network.
- Different Types:
	- Network DLP
		- Monitors and controls data leaving the organization over the network.
		- Inspects packet flow and blocks risky transfers (e.g., FTP uploads).
		- Can audit actions or forward logs to security systems.
		- Reports suspicious network activity to administrators.
	- Endpoint DLP
		- Installed directly on user devices.
		- Monitors local activity involving sensitive data.
		- Key for securing data on remote-worker endpoints.
		- Can check if sensitive files are stored securely (e.g., encrypted).
	- Cloud DLP
		- Protects sensitive data in cloud environments.
		- Integrates with cloud apps to prevent data leaks or misuse.
		- Ensures safe and secure use of cloud services by employees.
- When the DLP detects data that is in the right format according to its rules, it will either block the action or attempt to ensure security by encrypting the data. 

---
### Asset Management Solutions

- Software that can implement all asset management operations.
	- Monitoring operating status of assets.
	- Maintain assets.
	- Remove unnecessary assets.
- Benefits include:
	- It facilitates the implementation of standards.
	- It helps with documentation.
	- It improves the working performance of assets.
	- Provides inventory control.
	- Provides strategic decision-making support.

--- 
### Web Application Firewall (WAF)

- Security software/hardware that monitors, filters, and blocks packets going to and from web applications.
- Different types:
	- Network-based WAF
		- Is hardware-based on the relevant network.
		- Needs rules to be written on it and maintained by staff/admin.
		- Expensive compared to other WAF products.
	- Host-based WAF
		- Software-based with lots more of customization options.
		- Consumes the resources of the server that it is on.
		- Difficult to maintain (hosts) and must be securely hardened.
	- Cloud-based WAF
		- Convenient and easy-to-apply security solution.
		- Service and maintenance is included.
		- In the cloud (duh).

---
### Load Balancer

- Hardware/Software used to distribute traffic to the servers in a balanced way.
- Benefits include:
	- Efficiency
	- Flexibility
	- Reduced Downtime
	- Redundancy
	- Scalable
- Detects the most suitable target by using mathematical algorithms while performing the load-balancing process and directs the network packets to the appropriate target.

---
### Proxy Server

- Hardware/Software used for many different purposes.
- Acts a gateway between client and server.
- Different types:
	- Forward Proxy Server
		- Most popular type.
		- Directs requests from a private network to the outside network with a firewall.
	- Transparent Proxy Server
		- Directs requests and responses without making changings to the incoming/outgoing requests and responses.
	- Anonymous Proxy Server
		- Enables anonymous browsing.
	- High Anonymity Proxy Server
		- Removes the proxy server type and client IP address information from the request to increase client anonymity.
	- Distorting Proxy Server
		- Attempts to hide its identity as a proxy server of a website.
		- Changes the real IP address.
	- Data Center Proxy Server
		- Used by proxy servers that are not connected to the ISP.
		- Insufficient to provide anonymity
		- Quick response feature.
	- Residential Proxy Server
		- Passes all requests made by the client.
		- Blocks certain advertisements.
	- Public Proxy Server
		- Available to everyone.
		- Cost effective, at the cost of security and speed.
	- Shared Proxy Server
		- Can be used by multiple people at once.
		- This feature can cause issues between users (if someone is blocked on a website, everyone is blocked).
	- SSL Proxy Server
		- Communication between client and server in provided in a bidirectional encrypted manner.
		- Encrypted communication against threats.
	- Rotating Proxy Server
		- Each client is given a different/separate IP address.
	- Reverse Proxy Server
		- Validates and processes transactions which allows the client to not have to communicate directly.
	- Split Proxy Server
		- Runs as two programs installed on two separate devices.
	- Non-Transparent Proxy Server
		- Sends all requests to the firewall.
	- Hostile Proxy Server
		- Used to 'eavesdrop' on traffic between client and target on the internet.
	- Intercepting Proxy Server
		- Allows to use proxy server and gateway features together.
	- Forced Proxy Server
		- Blocking and allowing policies are applied together.
	- Caching Proxy Server
		- Has a caching mechanism on it.
		- Returns a response in line with this in response to the requests sent by clients.
	- Web Proxy Server
		- Works on web traffic.
	- Socks Proxy Server
		- Prevents external network components from gaining info on the client.
	- HTTP Proxy Server
		- Has a caching mechanism for the HTTP protocol.
- Benefits:
	- Private browsing.
	- Increasing client/user security.
	- Hides the IP address of the client/user.
	- Allows management of network traffic.
	- Save bandwidth with the caching mechanism.
	- Provides access to areas with access restrictions.

---
### Email Security Solutions

- Ensures security against threats sent through email.
- Can be either hardware or software.
- Functions:
	- Security control of email attachments and URLS.
	- Detects and blocks spoofed emails/email domains.
	- Blocks harmful/malicious emails.
	- Transmits information about the above to the relevant product/manager as an alert/warning.
- Phishing is a popular attack method, and these solutions help to prevent them.

