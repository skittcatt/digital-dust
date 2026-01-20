**Phase 1: Foundation
1. Inventory my hardware - label each PC/laptop with what it'll be used for - **DONE**
	- 2 basic desktops
		- Very basic specs
		- Victims/may use one with Security Onion/Wazuh
	- 2 laptops
		- Need to evaluate if they will work for this purpose.
	- Main PC
		- AMD Ryzen 7 9800 series, 32GB RAM, most likely will VM on this device.
	- Huawei Router
	- TP-Link 5-port switch (unmanaged)
2. Pick a hypervisor (Hyper-V if Windows, Proxmox if you want dedicated)
3. Download Windows Server evaluation ISO (180-day trial)
4. Set up first VM: Windows Server as Domain Controller
5. Configure Active Directory Domain Services, DNS, DHCP
6. Join one laptop to the domain as test client
7. Create basic GPO (something simple like desktop wallpaper or password policy)
8. Test GPO applies to domain-joined laptop

**Phase 2: Deployment Infrastructure**
1. Set up MDT (Microsoft Deployment Toolkit) on second VM or same server
2. Create basic Windows 10/11 deployment image
3. Configure PXE boot on network
4. Practice imaging the test laptop

**Phase 3: Monitoring/Security Layer**
1. Set up Security Onion or Wazuh VM on old PC 1
2. Configure logging from domain controller
3. Configure logging from client machines
4. Generate some test events, verify they show up in SIEM
5. Set up basic alerts

**Phase 4: Attack/Defense Practice**
1. Kali Linux VM
2. Run basic attacks against infrastructure (port scans, brute force)
3. Detect attacks in SIEM
4. Practice incident response on compromised test machines
5. Document findings