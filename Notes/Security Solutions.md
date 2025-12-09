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

- 