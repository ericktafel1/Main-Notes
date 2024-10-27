#Linux #PrivEsc 

1. [[LazyAdmin - THM]]
	- Web app revshell file upload
	- Sudo privesc perl + backup script
2. [[Anonymous - THM]]
	- anonymous ftp login, change `clean.sh` script to revshell bash
	- SUID env privesc
3. [[Tomghost - THM]]
	- Ghostcat - AJP exploit for Tomcat 9.0.30
	- Pivot - #GPG, #john , #gpg2john 
	- sudo -l /usr/bin/zip privesc
4. [[ConvertMyVideo - THM]]
	- Hint: `pspy` privesc enumeration tool on GitHub 
	- #BurpeSuite URL encoding payloads to bypass restrictions
	- #htapasswd file readable, crack hash with hashcat
	- #ps command with #pspy , #Cron change script to revshell
5. [[Brainpan1 - THM]]
	- Hint: BoF exe, utilize Windows machine for debugger or Linux using gdb tool
	- #ghidra Reverse engineer `.exe`
	- #BufferOverflow for reverseshell
	- #sudo GTFO Bins privesc