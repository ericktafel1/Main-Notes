#Windows #PrivEsc #Potato #TokenImpersonation #whoami #JuicyPotato #RottenPotato #mimikatz 

# Token Impersonation

- **Tokens** - temporary keys (basically cookies) that allow you access to a system/network. Two types:
	1. **Delegate** - created for logging into a machine or using RDP
	2. **Impersonate** - "non-interactive" such as attaching a network drive or a domain logon script

See [[3_Token Impersonation]]

- `whoami /priv` to see privileges of shell user
	- `SeImpersonatePrivilege` == `SeAssignPrimaryToken` (Potato attacks!) #Potato
		- ==Usually service accounts have this privilege==
	- `SeChangeNotifyPrivilege` (not Token attack but is sensitive)
- See EoP - Impersonate Privileges in Windows - Privilege Escalation Page from [PayloadAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/windows-privilege-escalation/#eop-living-off-the-land-binaries-and-scripts)

## EoP - Impersonation Privileges

Full privileges cheatsheet at https://github.com/gtworek/Priv2Admin, summary below will only list direct ways to exploit the privilege to obtain an admin session or read sensitive files.

| Privilege              | Impact      | Tool                    | Execution path                                                                                                                                                                                                                                                                                                                           | Remarks                                                                                                                                                                                                                                                            |
| ---------------------- | ----------- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `SeAssignPrimaryToken` | **_Admin_** | 3rd party tool          | _"It would allow a user to impersonate tokens and privesc to nt system using tools such as potato.exe, rottenpotato.exe and juicypotato.exe"_                                                                                                                                                                                            | Thank you [Aurélien Chalot](https://twitter.com/Defte_) for the update. I will try to re-phrase it to something more recipe-like soon.                                                                                                                             |
| `SeBackup`             | **Threat**  | **_Built-in commands_** | Read sensitve files with `robocopy /b`                                                                                                                                                                                                                                                                                                   | - May be more interesting if you can read %WINDIR%\MEMORY.DMP  <br>  <br>- `SeBackupPrivilege` (and robocopy) is not helpful when it comes to open files.  <br>  <br>- Robocopy requires both SeBackup and SeRestore to work with /b parameter.                    |
| `SeCreateToken`        | **_Admin_** | 3rd party tool          | Create arbitrary token including local admin rights with `NtCreateToken`.                                                                                                                                                                                                                                                                |                                                                                                                                                                                                                                                                    |
| `SeDebug`              | **_Admin_** | **PowerShell**          | Duplicate the `lsass.exe` token.                                                                                                                                                                                                                                                                                                         | Script to be found at [FuzzySecurity](https://github.com/FuzzySecurity/PowerShell-Suite/blob/master/Conjure-LSASS.ps1)                                                                                                                                             |
| `SeLoadDriver`         | **_Admin_** | 3rd party tool          | 1. Load buggy kernel driver such as `szkg64.sys` or `capcom.sys`  <br>2. Exploit the driver vulnerability  <br>  <br>Alternatively, the privilege may be used to unload security-related drivers with `ftlMC` builtin command. i.e.: `fltMC sysmondrv`                                                                                   | 1. The `szkg64` vulnerability is listed as [CVE-2018-15732](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-15732)  <br>2. The `szkg64` [exploit code](https://www.greyhathacker.net/?p=1025) was created by [Parvez Anwar](https://twitter.com/parvezghh) |
| `SeRestore`            | **_Admin_** | **PowerShell**          | 1. Launch PowerShell/ISE with the SeRestore privilege present.  <br>2. Enable the privilege with [Enable-SeRestorePrivilege](https://github.com/gtworek/PSBits/blob/master/Misc/EnableSeRestorePrivilege.ps1)).  <br>3. Rename utilman.exe to utilman.old  <br>4. Rename cmd.exe to utilman.exe  <br>5. Lock the console and press Win+U | Attack may be detected by some AV software.  <br>  <br>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.                                                                                                 |
| `SeTakeOwnership`      | **_Admin_** | **_Built-in commands_** | 1. `takeown.exe /f "%windir%\system32"`  <br>2. `icalcs.exe "%windir%\system32" /grant "%username%":F`  <br>3. Rename cmd.exe to utilman.exe  <br>4. Lock the console and press Win+U                                                                                                                                                    | Attack may be detected by some AV software.  <br>  <br>Alternative method relies on replacing service binaries stored in "Program Files" using the same privilege.                                                                                                 |
| `SeTcb`                | **_Admin_** | 3rd party tool          | Manipulate tokens to have local admin rights included. May require SeImpersonate.  <br>  <br>To be verified.                                                                                                                                                                                                                             |                                                                                                                                                                                                                                                                    |
| `SeRelabel`            | **_Admin_** | 3rd party too           | [decoder-it/RelabelAbuse](https://github.com/decoder-it/RelabelAbuse)                                                                                                                                                                                                                                                                    | Allows you to own resources that have an integrity level even higher than your own                                                                                                                                                                                 |

---

# Potato Attacks

1. Rotten Potato - [https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/](https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/)

- The idea behind this vulnerability is simple to describe at a high level:

	1. Trick the “NT AUTHORITY\SYSTEM” account into authenticating via NTLM to a TCP endpoint we control.
	2. Man-in-the-middle this authentication attempt (NTLM relay) to locally negotiate a security token for the “NT AUTHORITY\SYSTEM” account. This is done through a series of Windows API calls.
	3. Impersonate the token we have just negotiated. This can only be done if the attackers current account has the privilege to impersonate security tokens. This is usually true of most service accounts and not true of most user-level accounts.

2. Juicy Potato - [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)

- Leverages the privilege escalation chain based on `BITS` service having the `MiTM` listener on `127.0.0.1:6666` and when you have `SeImpersonate` or `SeAssignPrimaryToken` privileges. During a Windows build review we found a setup where `BITS` was intentionally disabled and port `6666` was taken.

---

HTB Jeeves