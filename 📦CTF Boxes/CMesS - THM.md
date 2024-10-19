---
date: 2024-10-18
title: CMesS THM Write-Up
machine_ip: varies
os: Linux
difficulty: Medium
my_rating: 
tags:
  - Linux
  - PrivEsc
  - Cron
  - "#Apache"
  - "#Gila"
  - "#CMS"
  - rustscan
  - feroxbuster
  - ffuf
  - whatweb
  - gobuster
references: "[[📚CTF Box Writeups]]"
---

# Enumeration


- Rustscan
```
└─# rustscan -a 10.10.179.92 -t 2000 -b 2000 -- -A -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
With RustScan, I scan ports so fast, even my firewall gets whiplash 💨

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.179.92:22
Open 10.10.179.92:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.179.92
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-18 16:28 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:28
Completed NSE at 16:28, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:28
Completed NSE at 16:28, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:28
Completed NSE at 16:28, 0.00s elapsed
Initiating SYN Stealth Scan at 16:28
Scanning cmess.thm (10.10.179.92) [2 ports]
Discovered open port 22/tcp on 10.10.179.92
Discovered open port 80/tcp on 10.10.179.92
Completed SYN Stealth Scan at 16:28, 0.18s elapsed (2 total ports)
Initiating Service scan at 16:28
Scanning 2 services on cmess.thm (10.10.179.92)
Completed Service scan at 16:29, 63.04s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against cmess.thm (10.10.179.92)
Retrying OS detection (try #2) against cmess.thm (10.10.179.92)
Initiating Traceroute at 16:29
Completed Traceroute at 16:29, 3.02s elapsed
Initiating Parallel DNS resolution of 1 host. at 16:29
Completed Parallel DNS resolution of 1 host. at 16:29, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
NSE: Script scanning 10.10.179.92.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:29
NSE Timing: About 97.54% done; ETC: 16:30 (0:00:01 remaining)
NSE Timing: About 99.65% done; ETC: 16:30 (0:00:00 remaining)
Completed NSE at 16:30, 70.55s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:30
Completed NSE at 16:30, 8.17s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:30
Completed NSE at 16:30, 0.00s elapsed
Nmap scan report for cmess.thm (10.10.179.92)
Host is up, received user-set (0.22s latency).
Scanned at 2024-10-18 16:28:19 PDT for 151s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d9:b6:52:d3:93:9a:38:50:b4:23:3b:fd:21:0c:05:1f (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCvfxduhH7oHBPaAYuN66Mf6eL6AJVYqiFAh6Z0gBpD08k+pzxZDtbA3cdniBw3+DHe/uKizsF0vcAqoy8jHEXOOdsOmJEqYXjLJSayzjnPwFcuaVaKOjrlmWIKv6zwurudO9kJjylYksl0F/mRT6ou1+UtE2K7lDDiy4H3CkBZALJvA0q1CNc53sokAUsf5eEh8/t8oL+QWyVhtcbIcRcqUDZ68UcsTd7K7Q1+GbxNa3wftE0xKZ+63nZCVz7AFEfYF++glFsHj5VH2vF+dJMTkV0jB9hpouKPGYmxJK3DjHbHk5jN9KERahvqQhVTYSy2noh9CBuCYv7fE2DsuDIF
|   256 21:c3:6e:31:8b:85:22:8a:6d:72:86:8f:ae:64:66:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGOVQ0bHJHx9Dpyf9yscggpEywarn6ZXqgKs1UidXeQqyC765WpF63FHmeFP10e8Vd3HTdT3d/T8Nk3Ojt8mbds=
|   256 5b:b9:75:78:05:d7:ec:43:30:96:17:ff:c6:a8:6c:ed (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFUGmaB6zNbqDfDaG52mR3Ku2wYe1jZX/x57d94nxxkC
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18
|_http-generator: Gila CMS
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.10 - 3.13 (96%), Linux 5.4 (96%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Android 5.1 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/18%OT=22%CT=%CU=43210%PV=Y%DS=4%DC=T%G=N%TM=6712EFAA%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)
SEQ(SP=104%GCD=4%ISR=10D%TI=Z%CI=I%II=I%TS=8)
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

Uptime guess: 207.992 days (since Sun Mar 24 16:41:56 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   87.19 ms  10.6.0.1
2   ... 3
4   354.92 ms cmess.thm (10.10.179.92)

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 16:30
Completed NSE at 16:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 16:30
Completed NSE at 16:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 16:30
Completed NSE at 16:30, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 150.49 seconds
           Raw packets sent: 61 (4.304KB) | Rcvd: 1536 (770.867KB)
```
- ports 22 and 80 are open

- Web enumeration
	- feroxbuster
```
┌──(root㉿kali)-[~/Transfer]
└─# feroxbuster -r -k --url http://10.10.179.92    
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.179.92
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
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
403      GET        9l       28w      277c http://10.10.179.92/src/?url=src
403      GET        9l       28w      277c http://10.10.179.92/themes/?url=themes
403      GET        9l       28w      277c http://10.10.179.92/lib/?url=lib
404      GET       86l      246w     3214c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      277c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       41l       99w     1583c http://10.10.179.92/admin
200      GET      107l      290w     3874c http://10.10.179.92/
200      GET       43l       98w     1366c http://10.10.179.92/login/password_reset
200      GET      109l      291w     3871c http://10.10.179.92/category
200      GET      109l      292w     3883c http://10.10.179.92/tag
200      GET      107l      290w     3860c http://10.10.179.92/blog
200      GET        0l        0w        0c http://10.10.179.92/api
404      GET        9l       31w      274c http://10.10.179.92/assets/icons/
404      GET        9l       31w      274c http://10.10.179.92/assets/icons/blank.gif
200      GET       14l       40w      566c http://10.10.179.92/assets/?url=assets
200      GET        4l       66w    31000c http://10.10.179.92/lib/font-awesome/css/font-awesome.min.css
200      GET        0l        0w    15763c http://10.10.179.92/lib/gila.min.css
200      GET      107l      290w     3860c http://10.10.179.92/search
200      GET       68l      422w    25046c http://10.10.179.92/assets/gila-logo.png
200      GET       41l       99w     1583c http://10.10.179.92/login
200      GET       41l       99w     1583c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      107l      290w     3860c http://10.10.179.92/index
200      GET      102l      308w     4090c http://10.10.179.92/1
200      GET        0l        0w        0c http://10.10.179.92/login/callback
200      GET        0l        0w        0c http://10.10.179.92/fm
500      GET        0l        0w        0c http://10.10.179.92/cm
200      GET       92l      266w     3345c http://10.10.179.92/About
200      GET        1l        4w       68c http://10.10.179.92/login/Register
200      GET      102l      308w     4090c http://10.10.179.92/01
200      GET      107l      290w     3860c http://10.10.179.92/Index
200      GET       21l       42w      735c http://10.10.179.92/Feed
200      GET      107l      290w     3860c http://10.10.179.92/SEARCH
200      GET       92l      266w     3345c http://10.10.179.92/ABOUT
200      GET      102l      308w     4090c http://10.10.179.92/1qaz2wsx
200      GET      109l      292w     3883c http://10.10.179.92/Tag
```
- Web server is #Apache and running #Gila CMS
- there is an `admin` login page
- gobuster for subdomain enumeration
```
┌──(root㉿kali)-[~/Transfer]
└─# gobuster dir -u  http://10.10.179.92/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.179.92/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index                (Status: 200) [Size: 3860]
/about                (Status: 200) [Size: 3359]
/search               (Status: 200) [Size: 3860]
/blog                 (Status: 200) [Size: 3860]
/login                (Status: 200) [Size: 1583]
/1                    (Status: 200) [Size: 4090]
/01                   (Status: 200) [Size: 4090]
/category             (Status: 200) [Size: 3871]
/themes               (Status: 301) [Size: 324] [--> http://10.10.179.92/themes/?url=themes]
/feed                 (Status: 200) [Size: 735]
/0                    (Status: 200) [Size: 3860]
/admin                (Status: 200) [Size: 1583]
/assets               (Status: 301) [Size: 324] [--> http://10.10.179.92/assets/?url=assets]
/tag                  (Status: 200) [Size: 3883]
/author               (Status: 200) [Size: 3599]
/sites                (Status: 301) [Size: 322] [--> http://10.10.179.92/sites/?url=sites]
/Search               (Status: 200) [Size: 3860]
/About                (Status: 200) [Size: 3345]
/log                  (Status: 301) [Size: 318] [--> http://10.10.179.92/log/?url=log]
/Index                (Status: 200) [Size: 3860]
/tags                 (Status: 200) [Size: 3145]
/1x1                  (Status: 200) [Size: 4090]
/lib                  (Status: 301) [Size: 318] [--> http://10.10.179.92/lib/?url=lib]
/src                  (Status: 301) [Size: 318] [--> http://10.10.179.92/src/?url=src]
/api                  (Status: 200) [Size: 0]
/001                  (Status: 200) [Size: 4090]
/cm                   (Status: 500) [Size: 0]
/1pix                 (Status: 200) [Size: 4090]
/fm                   (Status: 200) [Size: 0]
/tmp                  (Status: 301) [Size: 318] [--> http://10.10.179.92/tmp/?url=tmp]
/1a                   (Status: 200) [Size: 4090]
/0001                 (Status: 200) [Size: 4090]
/1x1transparent       (Status: 200) [Size: 4090]
/INDEX                (Status: 200) [Size: 3860]
/1px                  (Status: 200) [Size: 4090]
/1d                   (Status: 200) [Size: 4090]
/1_1                  (Status: 200) [Size: 4090]
/Author               (Status: 200) [Size: 3599]
```
- None of these pages appear to give me more information

- whatweb ouptput
```
┌──(root㉿kali)-[~/Transfer]
└─# whatweb 10.10.179.92     
http://10.10.179.92 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.179.92], MetaGenerator[Gila CMS], Script
```

- Looking more into the `http://cmess.thm/admin` login web portal
	- found [this](https://github.com/GilaCMS/gila/blob/master/config.default.php) github showing the `config.default.php` GilaCMS default admin email
		- `admin@mail.com`
- Need to enumerate further

---
# Foothold

- gain shell via exploit


---
# PrivEsc

- escalate to root