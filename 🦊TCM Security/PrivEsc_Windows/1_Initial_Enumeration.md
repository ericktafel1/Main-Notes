#Enum #meterpreter #wmic #whoami #net #ipconfig #arp #route #netstat #findstr #netsh #sc

- Complete HTB Machine: [[Devel]]

`msf6 post(multi/recon/local_exploit_suggester) > `

# System Enumeration

- When you get a meterpreter, enumerate with commands:
	- `meterpreter> shell`
	- `systeminfo`
```Or for just three systeminfo 
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
- `hostname`
- `wmic qfe` - windows management instrumentation quick fix engineering
	- shows patches
	- `wmic qfe get Caption,Description,HotFixID,InstalledOn`
	- `wmic logicaldisk get caption,description,providername`
	- `list drives`

# User Enumeration

- Use these commands to enumerate the user:
	- `whoami`
		- `whoami /priv`
		- `whoami /groups`
	- `net user`
		- `net user Administrator`
	- `net localgroup`
		- `net localgroup administrators`

# Network Enumeration

- Use these commands to enumerate the network:
	- `ipconfig /all`
	- `arp -a`
	- `route print`
	- `netstat -ano`

# Password Hunting

- Use these commands to hunt for passwords (automated later):
	- `findstr /si password *.txt *.ini *.config` 
		- _Note: runs in current directory_
	- `netsh wlan show profile`
	- `netsh wlan show profile <SSID> key=clear`

# AV Enumeration

- Use these commands to enumerate AV and Firewalls:
	- `sc query windefend`
		- `sc queryex type= service`
	- `netsh advfirewall firewall dump`
		- `netsh firewall show state`
		- `netsh firewall show config`