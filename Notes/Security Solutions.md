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
- 
