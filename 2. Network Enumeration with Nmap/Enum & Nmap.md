Most ways to get access:
	- Functions and/or resources that allow us to interact with the target and/or provide additional information.`
	- Information that provides us with even more important information to access our target.

* Network Mapper (`Nmap`) is an open-source network analysis and security auditing tool written in C, C++, Python, and Lua.
	* identify which hosts are available on the network using raw packets, and services and applications, including the name and version, where possible.
	* identify the operating systems and versions of these hosts.
	* scanning capabilities that can determine if packet filters, firewalls, or intrusion detection systems (IDS) are configured as needed.

### Nmap Architecture

Nmap offers many different types of scans that can be used to obtain various results about our targets. Basically, Nmap can be divided into the following scanning techniques:
- Host discovery
- Port scanning
- Service enumeration and detection
- OS detection
- Scriptable interaction with the target service (Nmap Scripting Engine)

`nmap <scan types> <options> <target>`

TCP-SYN scan (`-sS`) is one of the default settings unless we have defined otherwise and is also one of the most popular scan methods.
* makes it possible to scan several thousand ports per second. The TCP-SYN scan sends one packet with the SYN flag and, therefore, never completes the three-way handshake, which results in not establishing a full TCP connection to the scanned port.

	- If our target sends an `SYN-ACK` flagged packet back to the scanned port, Nmap detects that the port is `open`.
	- If the packet receives an `RST` flag, it is an indicator that the port is `closed`.
	- If Nmap does not receive a packet back, it will display it as `filtered`. Depending on the firewall configuration, certain packets may be dropped or ignored by the firewall.