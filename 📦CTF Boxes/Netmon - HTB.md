---
date: 2024-10-08
title: Netmon HTB Write-Up
machine_ip: 10.10.10.152
os: Windows
difficulty: Easy
my_rating: 
tags:
  - Windows
  - PrivEsc
  - FTP
  - nmap
  - gobuster
  - searchsploit
  - webserver
references: "[[📚CTF Box Writeups]]"
---
# Enumeration

- Nmap
```
┌──(root㉿kali)-[~/Downloads]
└─# nmap -sVC -Pn  10.10.10.152 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-08 16:52 PDT
Nmap scan report for 10.10.10.152
Host is up (0.097s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
21/tcp  open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_11-10-23  10:20AM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-server-header: PRTG/18.1.37.13946
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-10-08T23:52:38
|_  start_date: 2024-10-08T23:05:28
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.19 seconds
```

- nmap shows port 80 is hosting a PRTG Network Monitor 18.1.37.13946 web server. Also, FTP allows anonymous login, we logged in
```
┌──(root㉿kali)-[~/Downloads]
└─# ftp 10.10.10.152         
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
```

- We grabbed the `PRTG Configuration.dat` to search for more information, no luck
- Digging deeper, within `C:\Windows\Program Files (x86)\` we find `PRTG Network Monitor` folder with 


# Foothold
- gain shell via exploit
- Searchsploit shows PRTG Network Monitor 18.2.38 is vulnerable to (Authenticated) Remote Code Execution - `windows/webapps/46527.sh`
	- exploit tells us to log into the app with default creds of `prtgadmin:prtgadmin`, grab the cookie once authenticated and use it in the script.
	- Default creds won't work. Back to enumerating the config file.
	- `ls -al` REMEMBER TO LOOK FOR HIDDEN FILES
==resume here==



# PrivEsc
- escalate from webshell to user to root

User flag
```

```