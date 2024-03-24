## Linux Structure
* Components
	* Bootloader
	* OS Kernel
	* Daemons
	* OS Shell
	* Graphics server
	* Window Manager
	* Utilities
* Architecture
	* Hardware
	* Kernel
	* Shell
	* System
	* System Utility
* File System Hierarchy
	![[Pasted image 20231019130029.png]]
	* / 
		* The top-level directory is the root filesystem and contains all of the files required to boot the operating system before other filesystems are mounted as well as the files required to boot the other filesystems. After boot, all of the other filesystems are mounted at standard mount points as subdirectories of the root.
	* /bin
		* Contains essential command binaries.
	* /boot
		* Consists of the static bootloader, kernel executable, and files required to boot the Linux OS.
	* /dev
		* Contains device files to facilitate access to every hardware device attached to the system.
	* /etc
			* Local system configuration files. Configuration files for installed applications may be saved here as well.
	* /home
		* Each user on the system has a subdirectory here for storage.
	* /lib
		* Shared library files that are required for system boot.
	* /media
		* External removable media devices such as USB drives are mounted here.
	* /mnt
		* Temporary mount point for regular filesystems.
	* /opt
		* Optional files such as third-party tools can be saved here.
	* /root
		* The home directory for the root user.
	* /sbin
		* This directory contains executables used for system administration (binary system files).
	* /tmp
		* The operating system and many programs use this directory to store temporary files. This directory is generally cleared upon system boot and may be deleted at other times without any warning.
	* /usr
		* Contains executables, libraries, man files, etc.
	* /var
		* This directory contains variable data files such as log files, email in-boxes, web application related files, cron files, and more.
		
* ## Distributions
	* Ubuntu
	* Fedora
	* CentOS
	* Debian
	* RHEL

* Distros for Cyber Security Specialists
	* ParrotOS
	* RaspberryPi OS
	* BlackArch
	* Ubuntu
	* CentOS
	* Pentoo
	* Debian
	* BackBox
	* Kali
	
* ## Shell
	* AKA terminal/command line
	* Terminal emulators and multiplexers allows for GUI CLI (tmux)
		* Terminal is an interface to the shell interpreter
	* Most common shell is the **Bourne-Again Shell (BASH)**, and is part of the GNU project.
		* Can do anything in CLI in BASH, also easily automate with scripts in BASH
		
* ## Prompt Description
	* can be customized in $PS1 environment variable and the shell's configuration file, `.bashrc` for the Bash shell.
	* home directory
		* ~
	* user signed in
		* $
	* root signed in
		* #``
	* useful for us during our penetration tests because we can use various tools and possibilities like `script` or the `.bash_history` to filter and print all the commands we used and sort them by date and time.
		* |**Special Character**|       |**Description**|
		* `\d`                                        Date (Mon Feb 6)
		* `\D{%Y-%m-%d}`                      Date (YYYY-MM-DD)
		* `\H`                                        Full hostname
		* `\j`                                        Number of jobs managed by the shell
		* `\n`                                        Newline
		* `\r`                                        Carriage return
		* `\s`                                        Name of the shell
		* `\t`                                        Current time 24-hour (HH:MM:SS)
		* `\T`                                        Current time 12-hour (HH:MM:SS)
		* `\@`                                        Current time
		* `\u`                                        Current username
		* `\w`                                        Full path of the current working directory
		
* ## Getting Help
	* manual pages
		* `man`
	* help tag
		* `--help`
		* `-h`
	* search manual pages for a given key word
		* `apropos`
	* Another useful resource to get help if we have issues to understand a long command is: [https://explainshell.com/](https://explainshell.com/)

* ## System Information
	* **whoami** - current user
	* **id** - returns user identity
		* 4(adm) means user can read files in /var/log where sensitive information could be hidden
		* 1337(hackthebox) group is non-standard is should be of interest to a penteser
		* 27(sudo) member of the sudo group is of interest too, can run commands as root
	* **hostname** - current host system (parrot)
	* **uname** - OS and system hardware (USE INSTEAD OF HOSTNAME)
		* uname -a prints all info, kernel is Linux, hostname is parrot, kernel release is 6.1.0-1parrot1-amd64 the kernel version is #1 SMP PREEMPT_DYNAMIC Parrot 6.1.15- 1parrot1 (2023-04-25) x86_64 GNU/Linux
			* ```Linux parrot 6.1.0-1parrot1-amd64 #1 SMP PREEMPT_DYNAMIC Parrot 6.1.15- 1parrot1 (2023-04-25) x86_64 GNU/Linux```
		* uname -r print kernel release
			* ```6.1.0-1parrot1-amd64```
	* **pwd** - directory
	* **ifconfig** - network interface
	* **ip** - manipulate routing, network devices, interfaces and tunnels
	* **netstat** - network status
	* **ss** - investigate sockets
	* **ps** - processes
	* **who** - who is logged in
	* **env** - environment or sets and executes command shows path to mail and user specified shell, etc.
	* **lsblk** - lists block devices
	* **lsusb** - lists USB devices
	* **lsof** - lists opened files
	* **lspci** - lists pci devices 
* **Secure Shell (SSH)** a protocol that allows clients to access and execute commands or actions on remote computers.
	* SSH is port 22
		* DO NOT USE TELNET ON PORT 23 
	* ```ssh [username]@[IP address]```
* **OpenVPN** for box 
	* 1.) Download the .ovpn file. (Should appear in your downloads folder as ‘htbacademy.ovpn’, or something similar)
	* 2.) Use the ‘mkdir’ command in your home directory to create a new home for your future VPNs. (‘mkdir VPN’)
	* 3.) Move the .ovpn file from the downloads folder to the new VPN folder. (mv ~/Downloads/name_of_ovpn.ovpn ~/VPN)
	* 4.) execute ‘openvpn’ on the .ovpn file using sudo permissions. (sudo openvpn name_of_file.ovpn)

* ## **Navigation**
	* **pwd**
	* **ls**
		* -l shows more info for directories and files
			* permissions, # of hard links, owner, group, size (512-byte), date, directory name
		* -i 
			* shows index number
		* -la shows all hidden files (list all)
			* (e.g. `.bashrc` and `.bash_history`)
		* can sepcify a path too
			* `ls -l /var/`
	* **cd**
		* `cd -` goes back and forth to directories
		* `cd ..` goes back continuously, one directory at a time
			* directories with a double `..` represents the parent directory
		* can auto fill to directories
		* **directories with a single `.` indicates the current directory we are in!**
	* **clear**
		* Ctrl + L
		* Ctrl + R

* ## Working with Files and Directories
	* **vim** -edit
	* **nano** -edit
	* **touch** - create empty file
	* **mkdir**
	* **mv**
	* **cp**
	* **tree** - shows directories in tree
	* `ls -1t` for last modified files
	* `ls -i` for inode number
		* reference number/index

* ## Editing Files
	* **nano**
		* ^ = CTRL
	* **vim**
		* i am less familiar with
		* In contrast to Nano, `Vim` is a modal editor that can distinguish between text and command input. Vim offers a total of six fundamental modes that make our work easier and make this editor so powerful:
			* Normal
			* Insert
			* Visual
			* Command
			* Replace
		* vimtutor to practice

* ## Find Files and Directories
	* **which**
		* path to file
	* **find** - e.g. ```$ find / -type f -name *.conf -user root -size +20k -newermt 2020-03-03 -exec ls -al {} \; 2>/dev/null```
		* `-type f` Hereby, we define the type of the searched object. In this case, '`f`' stands for '`file`'.
		* `-name *.conf`With '`-name`', we indicate the name of the file we are looking for. The asterisk (`*`) stands for 'all' files with the '`.conf`' extension.
		* `-user root`This option filters all files whose owner is the root user.
		* `-size +20k`We can then filter all the located files and specify that we only want to see the files that are larger than 20 KiB.
		* `-newermt 2020-03-03`With this option, we set the date. Only files newer than the specified date will be presented.
		* `-exec ls -al {} \;`This option executes the specified command, using the curly brackets as placeholders for each result. The backslash escapes the next character from being interpreted by the shell because otherwise, the semicolon would terminate the command and not reach the redirection.
		* `2>/dev/null`This is a `STDERR` redirection to the '`null device`', which we will come back to in the next section. This redirection ensures that no errors are displayed in the terminal. This redirection must `not` be an option of the 'find' command.
	* **locate** - in contrast to find, locate works with a local db that contains all info, thus much faster
		* `sudo updatedb`
		* `locate *.conf`
		* however, much less filters than find has

* ## File Descriptors and Redirections
	* `STDIN - 0` Data Stream for Input
	* `STDOUT - 1` Data Stream for Output
	* `STDERR - 2` Data Stream for Output that relates to an error occurring
		* using `2>/dev/null` will discard error messages so only STDOUT is output
	* `2> stderr.txt` outputs STDERR to txt file
	* `1> stdout.txt` outputs STDOUT to txt file
	* `<` serves as STDIN
		* ```cat < stdout.txt
		/etc/shadow```
	* `>` redirect STDOUT to a new file
	* `>>` append STDOUT to our existing file
	* `|` another way to redirect STDOUT
		* e.g. ```find /etc/ -name *.conf 2>/dev/null | grep systemd```
			* finds .conf files in /etc/ and greps from systemd, not showing STDERR
	* **wc** - wordcount

* ## Filter Contents
	* **more** - shows content in pages
	* **less**
	* **head** - first 10 lines in file
	* **tail** - last 10 lines in file
	* **sort** - alphabetically/numerically
	* **grep** - pattern within search
		* `cat /etc/passwd | grep "/bin/bash"`
		* -v excludes specific results
			* ```cat /etc/passwd | grep -v "false\|nologin"```
			* excludes all users who have disabled the standard shell with the name "/bin/bash" or "/usr/bin/nolgin"
	* **cut** - remove specific delimiters and show the words on a line in a specified position. Use the option "`-d`" and set the delimiter to the colon character (`:`) and define with the option "`-f`" the position in the line we want to output:
		* ```cat /etc/passwd | grep -v "false\|nologin" | cut -d":" -f1
		root
		sync
		mrb3n
		cry0l1t3
		htb-student```
	* **tr** - replace tool. We can replace "`:`" with "` `" spaces:
		* ```cat /etc/passwd | grep -v "false\|nologin" | tr ":" " "

		root x 0 0 root /root /bin/bash
		sync x 4 65534 sync /bin /bin/sync
		mrb3n x 1000 1000 mrb3n /home/mrb3n /bin/bash
		cry0l1t3 x 1001 1001  /home/cry0l1t3 /bin/bash
		htb-student x 1002 1002  /home/htb-student /bin/bash```
		
	* **column** - display results in tabular form using the "`-t`":
		* ```cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | column -t

		root         x  0     0      root               /root        /bin/bash
		sync         x  4     65534  sync               /bin         /bin/sync
		mrb3n        x  1000  1000   mrb3n              /home/mrb3n  /bin/bash
		cry0l1t3     x  1001  1001   /home/cry0l1t3     /bin/bash
		htb-student  x  1002  1002   /home/htb-student  /bin/bash```
	* **awk** - sort out results, can allow us to display the first (`$1`) and last (`$NF`) result of the line:
		* ```cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}'

		root /bin/bash
		sync /bin/sync
		mrb3n /bin/bash
		cry0l1t3 /bin/bash
		htb-student /bin/bash```
	* **sed** - change specific names in the whole file or standard output. It is a stream editor, substitutes text by looking for patterns defined in regex and replaces them with another pattern also defined. So from the last results, lets replace the word "bin" with "HTB". "`s`" flag stands for substitute and "`g`" stands for replacing all matches:
		* ```cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}' | sed 's/bin/HTB/g'

		root /HTB/bash
		sync /HTB/sync
		mrb3n /HTB/bash
		cry0l1t3 /HTB/bash
		htb-student /HTB/bash```
	* **wc** - word count. "`-l`" specifies only lines are counted:
		* ```cat /etc/passwd | grep -v "false\|nologin" | tr ":" " " | awk '{print $1, $NF}' | wc -l

		5```
	* **ss** - list services listening on target (not on localhost and IPv4 only)
		* ```ss -l -4 | grep -v "127\.0\.0" | grep "LISTEN" | wc -l```
			* **-l**: show only listening services
			* **-4**: show only ipv4
			* **-grep -v "127.0.0"**: exclude all localhost results
			* **-grep "LISTEN"**: better filtering only listening services
			* **wc -l**: count results
* ## Regular Expressions
	* an art of expression language to search for patterns in text and files. Find, replace, analyze, validate, search, and more. Filter criterion.
		* e.g. `grep -Po "https://www.inlanefreights/[^'\"]*" `
			* grabs unique paths from the website with all a-Z and 0-9 combinations, stops at the " or ' at the end of the href link
	* **Grouping** - allows for three different approaches:
		* **Operators**
			* `(a)` The round brackets are used to group parts of a regex. Within the brackets, you can define further patterns which should be processed together.
			* `[a-z]` The square brackets are used to define character classes. Inside the brackets, you can specify a list of characters to search for.
			* `{1,10}` The curly brackets are used to define quantifiers. Inside the brackets, you can specify a number or a range that indicates how often a previous pattern should be repeated.
			* `|` Also called the **OR** **operator** and shows results when one of the two expressions matches
			* `.*` Also called the **AND** **operator** and displayed results only if both expressions match
		* **OR operator** example
			* ```grep -E "(my|false)" /etc/passwd

				lxd:x:105:65534::/var/lib/lxd/:/bin/false
				pollinate:x:109:1::/var/cache/pollinate:/bin/false
				mysql:x:116:120:MySQL Server,,:/nonexistent:/bin/false```
			* the regex searches for one of the given search patterns. Searches for the word my or false. `-E` option in grep applies the extended regex
		* **AND operator** example
			* ```grep -E "(my.*false)" /etc/passwd

				mysql:x:116:120:MySQL Server,,:/nonexistent:/bin/false```
			* searches for both my and false. Simplified example is:
			* ```grep -E "my" /etc/passwd | grep -E "false"

				mysql:x:116:120:MySQL Server,,:/nonexistent:/bin/false```
* ## Permission Management
	* **rwx** - read, write, execute (111 binary representation = 421 binary notation = 7 octal value)
		* 111 = 421 = 7 = rwx
		* 101 = 41 = 5 = rx-
		* 100 = 4 = 4 = r--
	* **chmod** - change permissions for
		* ```chmod a+r shell && ls -l shell

		-rwxr-xr-x   1 cry0l1t3 htbteam 0 May  4 22:12 shell```
		* ```chmod 754 shell && ls -l shell

		-rwxr-xr--   1 cry0l1t3 htbteam 0 May  4 22:12 shell```
					* u - owner
					* g - group
					* o - others
					* a - all users
					* at the start, `-` means file `d` means directory
	* **chown** - change owner of a file or directory
		* ```chown root:root shell && ls -l shell

		-rwxr-xr--   1 root root 0 May  4 22:12 shell```
	* **SUID** & **SGID** - can configure special permissions for files. SUID/SGID bits allow, for example, users to run programs with the rights of another user. Administrators often use this to give their users special rights for certain applications or files. The letter "`s`" is used instead of an "`x`". When executing such a program, the SUID/SGID of the file owner is used.
		* ==Note security risk== - if set the SUID bit to "`journalctl`," any user with access to this application could execute a shell as `root`.
	* **Sticky Bit** - a type of file permission that can be set on directories (like inherited)
		* it is represented by the letter “`t`" in the execute permission of the directory's permissions. For example, if a directory has permissions “`rwxrwxrwt`", it means that the sticky bit is set, giving the extra level of security so that no one other than the owner or root user can delete or rename the files or folders in the directory.
			* If the sticky bit is capitalized (`T`), then this means that all other users do not have `execute` (`x`) permissions and, therefore, cannot see the contents of the folder nor run any programs from it. The lowercase sticky bit (`t`) is the sticky bit where the `execute` (`x`) permissions have been set.
* ## User Management
	* use **sudo** to execute as root

	* `sudo` Execute command as a different user.
	* `su` The `su` utility requests appropriate user credentials via PAM and switches to that user ID (the default user is the superuser). A shell is then executed.
		* bad practice
	* `useradd` Creates a new user or update default new user information.
	* `userdel` Deletes a user account and related files.
	* `usermod` Modifies a user account.
	* `addgroup` Adds a group to the system.
	* `delgroup` Removes a group from the system.
	* `passwd` Changes user password.
* ## Package Management
	* packages are archives that contain binaries of software, config files, info on dependencies, and keep track of updates and upgrades. Features are:
		* Package downloading
		- Dependency resolution
		- A standard binary package format
		- Common installation and configuration locations
		- Additional system-related configuration and functionality
		- Quality control
	* types:
		* `dpkg` The `dpkg` is a tool to install, build, remove, and manage Debian packages. The primary and more user-friendly front-end for `dpkg` is aptitude.
		* `apt` Apt provides a high-level command-line interface for the package management system.
		* `aptitude` Aptitude is an alternative to apt and is a high-level interface to the package manager.
		* `snap` Install, configure, refresh, and remove snap packages. Snaps enable the secure distribution of the latest apps and utilities for the cloud, servers, desktops, and the internet of things.
		* `gem` Gem is the front-end to RubyGems, the standard package manager for Ruby.
		* `pip` Pip is a Python package installer recommended for installing Python packages that are not available in the Debian archive. It can work with version control repositories (currently only Git, Mercurial, and Bazaar repositories), logs output extensively, and prevents partial installs by downloading all requirements before starting installation.
		* `git` Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals.
	* The repository list for Parrot OS is at `/etc/apt/sources.list.d/parrot.list`
	* **APT** uses a database called **APT** **cache**. We can  search if to find packages related to certain activities:
		* ```apt-cache search impacket

		impacket-scripts - Links to useful impacket scripts examples
		polenum - Extracts the password policy from a Windows system
		python-pcapy - Python interface to the libpcap packet capture library (Python 2)
		python3-impacket - Python3 module to easily build and dissect network protocols
		python3-pcapy - Python interface to the libpcap packet capture library (Python 3)```
		* we can view additional information about a package:
		* ```apt-cache show impacket-scripts

		Package: impacket-scripts
		Version: 1.4
		Architecture: all
		Maintainer: Kali Developers <devel@kali.org>
		Installed-Size: 13
		Depends: python3-impacket (>= 0.9.20), python3-ldap3 (>= 2.5.0), python3-ldapdomaindump
		Breaks: python-impacket (<< 0.9.18)
		Replaces: python-impacket (<< 0.9.18)
		Priority: optional
		Section: misc
		Filename: pool/main/i/impacket-scripts/impacket-scripts_1.4_all.deb
		Size: 2080
		<SNIP>```
	* List all installed packages:
		* ```apt list --installed

		Listing... Done
		accountsservice/rolling,now 0.6.55-2 amd64 [installed,automatic]
		adapta-gtk-theme/rolling,now 3.95.0.11-1 all [installed]
		adduser/rolling,now 3.118 all [installed]
		adwaita-icon-theme/rolling,now 3.36.1-2 all [installed,automatic]
		aircrack-ng/rolling,now 1:1.6-4 amd64 [installed,automatic]
		<SNIP>```
	* Lets install packages/scripts
		* `sudo apt install impacket-scripts -y`
		* ```mkdir ~/nishang/ && git clone https://github.com/samratashok/nishang.git ~/nishang```
		* ```wget http://archive.ubuntu.com/ubuntu/pool/main/s/strace/strace_4.21-1ubuntu1_amd64.deb```
* ## Service and Process Management
	* two types
		* internal, the relevant services that are required at system startup, which for example, perform hardware-related tasks
		* and services that are installed by the user, which usually include all server services.
			* run in background, also called **daemons**, identified with the letter **`d`** at the end of th program name(e.g. `sshd` or `systemd`)
		* Most Linux distros switched to `systemd`, this daemon is an Init process started first (PID 1). It monitors and orderly starts and stops other services
			* view PIDs in `/proc/` with the corresponding number
			* PPID (Parent Process ID)
		* Besides `systemctl` we can also use `update-rc.d` to manage SysV init script links. Let us have a look at some examples. We will use the `OpenSSH` server in these examples.
			* `systemctl start ssh`
			* `systemctl status ssh`
			* To add OpenSSH to the SysV script to tell the system to run this service after startup, we can link it with the following command:
				* `systemctl enable ssh`
			* Once we reboot the system, the OpenSSH server will automatically run. We can check this with a tool called `ps`.
				* `ps -aux | grep ssh`
			* We can also use `systemctl` to list all services.
				* `systemctl list-units --type=service`
			* To see the problem, we can use the tool `journalctl` to view the logs.
				* `journalctl -u ssh.service --no-pager`
	* **Kill a Process**
		* Running
		* Waiting (waiting for an event or system resource)
		* Stopped
		* Zombie (stopped but still has an entry in the process table)

		* **kill**, **pkill**, **pgrep**, and **killall**
		* To view all signals to send to a process:
			* `kill -l`
			* Most commonly used are (Signal, Description):
				* `1`,`SIGHUP` - This is sent to a process when the terminal that controls it is closed.
				* `2`, `SIGINT` - Sent when a user presses `[Ctrl] + C` in the controlling terminal to interrupt a process.
				* `3`, `SIGQUIT` - Sent when a user presses `[Ctrl] + D` to quit.
				* `9`, `SIGKILL` - Immediately kill a process with no clean-up operations. (MOST COMMON)
				* `15`, `SIGTERM` - Program termination.
				* `19`, `SIGSTOP` - Stop the program. It cannot be handled anymore.
				* `20`, `SIGTSTP` - Sent when a user presses `[Ctrl] + Z` to request for a service to suspend. The user can handle it afterward.
		* e.g. `kill 9 <PID>`
	* **Background a Process**
		* `jobs` - displays all background processes
		* The `[Ctrl] + Z` shortcut suspends the processes, and they will not be executed further. To keep it running in the background, we have to enter the command `bg` to put the process in the background.
			* `ping -c 10 www.hackthebox.com`
			* `vim tmpfile`
			* [Ctrl + Z]
			* `jobs`
			* `bg`
			`--- www.hackthebox.eu ping statistics ---`
			`10 packets transmitted, 0 received, 100% packet loss, time 113482ms`
			``[ENTER]`
			``[1]+  Exit 1                  ping -c 10 www.hackthebox.eu`
			* Another option is to automatically set the process with an AND sign (`&`) at the end of the command:
				* ```ping -c 10 www.hackthebox.eu &```
	* **Foreground a Process**
		* `fg <ID>` - sends the background process to foreground e.g. `fg 1`
	* **Execute Multiple Commands**
		* three possibilities to run several commands
			* Semicolon (`;`) - command separator, executes commands by ignoring previous commands' results and errors. Example shows echo and listing a nonexistent file
				* e.g. ```echo '1'; ls MISSING_FILE; echo '3'
					1
					ls: cannot access 'MISSING_FILE': No such file or directory
					3```
			* Double ampersand characters (`&&`) - If there is an error in one of the commands, the following ones will not be executed anymore, and the whole process will be stopped.
				* e.g. ```echo '1' && ls MISSING_FILE && echo '3'
					1
					ls: cannot access 'MISSING_FILE': No such file or directory```
			* Pipes (`|`) - depends not only on the correct and error-free operation of the previous processes but also on the previous processes' results.
* ## **Task Scheduling**
	* a feature in Linux systems that allows users to schedule and automate tasks. Examples include automatically updating software, running scripts, cleaning databases, and automating backups.
		* **systemd** - service to start processes and scripts at a specific time. Steps and precautions to take:
			* 1. **Create a timer** - create directory, create a script that configures the timer. The script must contain the following options: "Unit", "Timer" and "Install". The "Unit" option specifies a description for the timer. The "Timer" option specifies when to start the timer and when to activate it. Finally, the "Install" option specifies where to install the timer.
				* `sudo mkdir /etc/systemd/system/mytimer.timer.d`
				* `sudo vim /etc/systemd/system/mytimer.timer`
					* ```[Unit]
					Description=My Timer
		
					[Timer]
					OnBootSec=3min
					OnUnitActiveSec=1hour

					[Install]
					WantedBy=timers.target```
			* 2. **Create a service** - Set a description and specify the full path to the script we want to run. The "multi-user.target" is the unit system that is activated when starting a normal multi-user mode. It defines the services that should be started on a normal system startup. After that, we have to let `systemd` read the folders again to include the changes.
				* `sudo vim /etc/systemd/system/mytimer.service`
				* ```[Unit]
				Description=My Service

				[Service]
				ExecStart=/full/path/to/my/script.sh

				[Install]
				WantedBy=multi-user.target```
				* `sudo systemctl daemon-reload`
			* 3. **Activate the timer** - After that, we can use `systemctl` to `start` the service manually and `enable` the autostart.
				* `sudo systemctl start mytimer.service`
				* `sudo systemctl enable mytimer.service`
		* **Cron** - another tool that can be used to schedule and automate processes. To set up the cron daemon, we need to store the tasks in a file called `crontab` and then tell the daemon to run the tasks. Then we can schedule and automate the tasks by configuring the cron daemon accordingly. The structure of Cron consists of the following components:
			* Minutes (0-59) - This specifies in which minute the task should be executed.
			* Hours (0-23) - This specifies in which hour the task should be executed.
			* Days of month (1-31) - This specifies on which day of the month the task should be executed.
			* Months (1-12) - This specifies in which month the task should be executed.
			* Days of the week (0-7) - This specifies on which day of the week the task should be executed.

		* For example, such a crontab could look like this:
		* `# System Update`
		`* */6 * * /path/to/update_software.sh`
		
		`# Execute scripts`
		`0 0 1 * * /path/to/scripts/run_scripts.sh`

		`# Cleanup DB`
		`0 0 * * 0 /path/to/scripts/clean_database.sh`

		`# Backups`
		`0 0 * * 7 /path/to/scripts/backup.sh`
		* System Update, every 6th hour, executed by update_software.sh script
		* Execute scripts, every first day of the month at midnight, executed by run_scripts.sh script
		* Cleanup DB, every Sunday at midnight, executed by clean_database.sh script
		* Backups, every Sunday at midnight, executed by backup.sh script
	* **Systemd vs. Cron**
		* difference is how they are configured
		* With Systemd, you need to create a timer and services script that tells the operating system when to run the tasks. On the other hand, with Cron, you need to create a `crontab` file that tells the cron daemon when to run the tasks.
* ## Network Services
	* **SSH** - securely maange remote systems
		* `sudo apt install openssh-server -y`
		* `systemctl status ssh`
		* `ssh htb-student@10.129.17.122` (example)
		* OpenSSH can be configured and customized by editing the file `/etc/ssh/sshd_config` with a text editor. Can adjust:
			* max connections
			* use of passwords/keys
			* host key checking
			* etc.
	* **NFS** - Network File System is a network protocol that allows us to store and manage files on remote systems as if they were stored on the local system (NFS-UTILS (`Ubuntu`), NFS-Ganesha (`Solaris`), and OpenNFS (`Redhat Linux`).
		* `sudo apt install nfs-kernel-server -y`
		* `systemctl status nfs-kernel-server`
		* We can configure NFS via the configuration file `/etc/exports`. Important access rights that can be configured:
			* `rw` Gives users and systems read and write permissions to the shared directory.
			* `ro` Gives users and systems read-only access to the shared directory.
			* `no_root_squash` Prevents the root user on the client from being restricted to the rights of a normal user.
			* `root_squash` Restricts the rights of the root user on the client to the rights of a normal user.
			* `sync` Synchronizes the transfer of data to ensure that changes are only transferred after they have been saved on the file system.
			* `async` Transfers data asynchronously, which makes the transfer faster, but may cause inconsistencies in the file system if changes have not been fully committed.
		* Example, created a new folder and share it temporarily in NFS:
			* `mkdir nfs_sharing`
			* ``echo '/home/cry0l1t3/nfs_sharing hostname(rw,sync,no_root_squash)' >> /etc/exports```
			* ` cat /etc/exports | grep -v "#"`
			* If we have created an NFS share and want to work with it on the target system, we have to mount it first. We can do this with the following command:
			* `mkdir ~/target_nfs`
			* ```mount 10.129.12.17:/home/john/dev_scripts ~/target_nfs```
			* `tree ~/target_nfs`
			* mounted the NFS share (`dev_scripts`) from our target (`10.129.12.17`) locally to our system in the mount point `target_nfs`
	* **Web Server** - critical part of web applications and often targets to attack.
		* type of software that provides data and documents or other applications and functions over the internet.
			* **HTTP** - send/receive data
			* **HTML** - renders data requests
		* Most popular web servers for Linux
			* Apache
			* Nginx
			* Lighttpd
			* Caddy
		* `sudo apt install apache2 -y`
		* For Apache2, to specify which folders can be accessed, we can edit the file `/etc/apache2/apache2.conf` with a text editor.
		* ```<Directory /var/www/html>
			    Options Indexes FollowSymLinks
			    AllowOverride All
			    Require all granted
		</directory>```
		* This section specifies that the default `/var/www/html` folder is accessible, that users can use the `Indexes` and `FollowSymLinks` options, that changes to files in this directory can be overridden with `AllowOverride All`, and that `Require all granted` grants all users access to this directory.
		* For example, if we want to transfer files to one of our target systems using a web server, we can put the appropriate files in the `/var/www/html` folder and use `wget` or `curl` or other applications to download these files on the target system.
		* customize individual settings at the directory level by using the `.htaccess` file
			*  allows us to configure certain directory-level settings, such as access controls, without having to customize the Apache configuration file.
		* We can also add modules to get features like `mod_rewrite`, `mod_security`, and `mod_ssl` that help us improve the security of our web application.
		* **Python Web Server** - simple fast alternative to Apache. Can host a single folder with a single command to transfer files to another system.
			* `sudo apt install python3 -y`
			* `python3 -m http.server`
			* This will start a Python web server on the `TCP/8000` port, and we can access the `/home/cry0l1t3/target_files` folder from the browser, for example. When we access our Python web server, we can transfer files to the other system by typing the link in our browser and downloading the files. We can also host our Python web server on a port other than the default port by using the `-p` option:
			* `python3 -m http.server 443`
			* This will host our Python web server on port 443 instead of the default `TCP/8000` port. We can access this web server by typing the link in our browser.
		* **VPN** - allows secure connection to another network as if we were directly in it. Creates an encrypted tunnel connection between the client and the server. Provides encryption, tunneling, traffic shaping, network routing, and the ability to adapt to dynamically changing networks.
			* `sudo apt install openvpn -y`
			* customized and configured by editing the configuration file `/etc/openvpn/server.conf`. Configure encryption, tunneling, traffic shaping, etc.
			* to connect to an OpenVPN server, we can use the `.ovpn` file we received from the server and save it on our system. We can do this with the following command on the command line:
				* `sudo openvn --config internal.ovpn`
				* `sudo openvpn /file/location/`
			* Popular VPNs
				* OpenVPN
				* L2TP/IPsec
				* PPTP
				* SSTP
				* SoftEther
* ## Working with Web Services
	* For an Apache web server, we can use appropriate modules, which can encrypt the communication between browser and web server (mod_ssl), use as a proxy server (mod_proxy), or perform complex manipulations of HTTP header data (mod_headers) and URLs (mod_rewrite).
		* Apache offers the possibility to create web pages dynamically using server-side scripting languages (PHP, Perl, or Ruby; other languages are Python, JavaScript, Lua, and .NET which can be used for this).
		* `sudo apt install apache2 -y`
		* start apache web server
		* visit default home page at http://localhost
	* **cURL** - tool that allows us to transfer files from the shell over protocols like HTTP, HTTPS, FTP, SFTP, FTPS, or SCP. Control and test websites remotely.
		* Besides the remote servers' content, we can also view individual requests to look at the client's and server's communication.
		* `curl http://localhost`
	* **Wget** - an alternative to curl. Can download files from FTP or HTTP servers directly from the terminal.
		* `wget http://localhost`
	* **Python 3** - another web server option for data transfer. The web server's root directory is where the command is executed to start the server.
		* For this example, we are in a directory where WordPress is installed and contains a "readme.html." Now, let us start the Python 3 web server and see if we can access it using the browser.
			* `python3 -m http.server`
			* we can see requests made from the terminal (Python 3 web server's events
* ## Backup and Restore
	* software tools to protect data
		* **Rsync** - remote backup location, good for large file transfers, only transmits changed parts of file. Can create backups locally or on remote servers.
		* **Duplicity** - GUI backup tool for Ubuntu. It also uses Rsync as a backend and allows for encryption of backup copies
		* **Deja Dup** - GUI backup tool for Ubuntu that simplifies the backup process. User-friendly interface. Uses Rsync as a backend and also supports data encryption.
	* Alternatively, we can encrypt backups on Ubuntu systems by utilizing tools such as **GnuPG**, **eCryptfs**, and **LUKS**.
	* In order to install Rsync on Ubuntu, we can use the `apt` package manager:
		* `sudo apt install rsync -y`
		* backup a local directory to our backup-server 
			* ```rsync -av /path/to/mydirectory user@backup_server:/path/to/backup/directory```
			* This command will copy the entire directory (/path/to/mydirectory) to a remote host (backup_server), to the directory /path/to/backup/directory. The option archive (-a) is used to preserve the original file attributes, such as permissions, timestamps, etc., and using the verbose (-v) option provides a detailed output of the progress of the rsync operation.
		* Using compression and incremental backups:
			* ```rsync -avz --backup --backup-dir=/path/to/backup/folder --delete /path/to/mydirectory user@backup_server:/path/to/backup/directory```
			* With this, we back up the `mydirectory` to the remote `backup_server`, preserving the original file attributes, timestamps, and permissions, and enabled compression (`-z`) for faster transfers. The `--backup` option creates incremental backups in the directory `/path/to/backup/folder`, and the `--delete` option removes files from the remote host that is no longer present in the source directory.
		* To restore our directory from our backup server to our local directory:
			* ```rsync -av user@remote_host:/path/to/backup/directory /path/to/mydirectory```
	* **Encrypted Rsync** - To ensure the security of our `rsync` file transfer between our local host and our backup server, we can combine the use of **SSH** and other security measures. We can also use firewalls and other security protocols. To use **rsync** with **SSH**:
		* `rsync -avz -e ssh /path/to/mydirectory user@backup_server:/path/to/backup/directory`
	* **Auto-Synchronization** - to enable, use a combination of **cron** and **rsync** to automate the synchronization process. Schedule the **cron** job to run at regular internals to ensure contents are kept in sync.
		* create a new script called `RSYNC_Backup.sh`, which will trigger the `rsync` command to sync our local directory with the remote one.
			* ```#!/bin/bash

			rsync -avz -e ssh /path/to/mydirectory user@backup_server:/path/to/backup/directory````
		* to ensure that the script is able to execute properly, we must provide the necessary permissions:
			* `chmod +x RSYNC_Backup.sh`
			* also important to make sure that the script is owned by the correct user
	* **Auto-Sync - Crontab**
		* `0 * * * * /path/to/RSYNC_Backup.sh`
			* with this setup, **cron** will executed the script at the desired intervals.
* ## File System Management
	* Linux is a powerful operating system that supports a wide range of file systems, including ext2, ext3, ext4, XFS, Btrfs, NTFS, and more.
		* ext2 is suitable for basic file system management tasks,
		* Btrfs offers robust data integrity and snapshot capabilities
		* NTFS is useful when compatibility with Windows is required
	* Linux File system is based on the Unix file system
		* At the top of this structure is the inode table, the basis for the entire file system.
			* inode table is a table of information associated with each file and directory on a Linux system
			* Inodes contain metadata about the file or directory, such as its permissions, size, type, owner, and so on. The inode table is like a database of information about every file and directory on a Linux system, allowing the operating system to quickly access and manage files.
	* Files can be stored in Linux one of two ways:
		* Regular files
		* Directories
	* Linux also supports symbolic links, which are references to other files or directories.
	* `ls -il`
		* shows permissions for files/directories in a given directory
	* **Disks & Drives** - main tool for disk management on Linux is the **fdisk**, allowing us to create, delete, and manage partitions on a drive. Also display partition table information.
		* Partitioning involves dividing the physical storage space into separate, logical sections.
		* Each partition can then be formatted with a specific file system, such as ext4, NTFS, or FAT32, and can be mounted as a separate file system. The most common partitioning tool on Linux is also `fdisk`, `gpart`, and `GParted`.
	* **Fdisk**
		* `sudo fdisk -l`
	* **Mounting** - each logical partition or drive needs to be assigned to a specific directory on Linux. Makes it accessible to the file system hierarchy.
		* The `mount` tool is used to mount file systems on Linux, and the `/etc/fstab` file is used to define the default file systems that are mounted at boot time.
			* `cat /etc/fstab`
	* **List Mounted Drives**
		* `mount`
		* For example, to mount a USB drive with the device name `/dev/sdb1` to the directory `/mnt/usb`, we would use the following command:
			* `sudo mount /dev/sdb1 /mnt/usb`
			* `cd /mnt/usb && ls -l`
		* To unmount a file system in Linux, we can use the `umount` command followed by the mount point of the file system we want to unmount. T
		* For example, to unmount the USB drive that was previously mounted to the directory `/mnt/usb`, we would use the following command:
			* `sudo umount /mnt/usb`
			* We also cannot unmount a file system that is in use by a running process. To ensure that there are no running processes that are using the file system, we can use the `lsof` command to list the open files on the file system.
				* `lsof | grep cry0l1t3`
				*  If we find any processes that are using the file system, we need to stop them before we can unmount the file system. Additionally, we can also unmount a file system automatically when the system is shut down by adding an entry to the `/etc/fstab` file.
				* To unmount a file system automatically at shutdown, we need to add the `noauto` option to the entry in the `/etc/fstab` file for that file system. This would like, for example, like following:
					* ```/dev/sda1 / ext4 defaults 0 0
					/dev/sda2 /home ext4 defaults 0 0
					/dev/sdb1 /mnt/usb ext4 rw,noauto,user 0 0
					192.168.1.100:/nfs /mnt/nfs nfs defaults 0 0```
	* **SWAP** - a crucial; aspect of memory management in Linux, ensures system runs smoothly. The kernel transfers inactive pages of memory to the swap space when the system runs out of physical memory.
		* during install
		* after install
			* **mkswap** - sets a Linux swap area on a device or in a file
			* **swapon** - activates a swap area
		* When creating a swap space, it is important to ensure that it is placed on a **dedicated partition or file**, separate from the rest of the file system.
		* It is also important to ensure that the swap space is **encrypted**
		* Is used for one of two things:
			* extension of physical memory
			* hibernation - a power management feature that allows the system to save its state to disk and then power off instead of shutting down completely. When the system is later powered on, it can restore its state from the swap space, returning to the state it was in before it was powered off.
* ## Containerization 
	* a process of packaging and running applications in isolated environments, such as a container, virtual machine, or serverless environment. Create, deploy, and manage applications quickly, securely, and efficiently. Very lightweight. More secure than VMs. Docker, Docker Compose, and Linux Containers.
		* **Docker** - an open-source platform for automating the deployment of applications as self-contained units called containers. It uses a layered filesystem and resource isolation features to provide flexibility and portability.
			* **Install Docker-Engine**
				* ```#!/bin/bash
				
				# Preparation
				sudo apt update -y
				sudo apt install ca-certificates curl gnupg lsb-release -y
				sudo mkdir -m 0755 -p /etc/apt/keyrings
				curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
				echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
				
				# Install Docker Engine
				sudo apt update -y
				sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
				
				# Add user htb-student to the Docker group
				sudo usermod -aG docker htb-student
				echo '[!] You need to log out and log back in for the group changes to take effect.'
				
				# Test Docker installation
				docker run hello-world```
			* The Docker engine and specific Docker images are needed to run a container. These can be obtained from the [Docker Hub](https://hub.docker.com/), a repository of pre-made images, or created by the user.
				* public and private areas
			* creating a Docker image is done by creating a **Dockerfile**, which contains all the instructions the Docker engine needs to create the container.
				* we can use Docker containers as our "file hosting" server when transferring specific files to our target system.
				* Therefore, we must create a `Dockerfile` based on Ubuntu 22.04 with `Apache` and `SSH` server running. With this, we can use `scp` to transfer files to the docker image, and Apache allows us to host files and use tools like `curl`, `wget`, and others on the target system to download the required files. Such a `Dockerfile` could look like the following:
					* ```# Use the latest Ubuntu 22.04 LTS as the base image
					FROM ubuntu:22.04
					# Update the package repository and install the required packages
					RUN apt-get update && \
					    apt-get install -y \
					        apache2 \
					        openssh-server \
					        && \
					    rm -rf /var/lib/apt/lists/*
					
					# Create a new user called "student"
					RUN useradd -m docker-user && \
					    echo "docker-user:password" | chpasswd
					
					# Give the htb-student user full access to the Apache and SSH services
					RUN chown -R docker-user:docker-user /var/www/html && \
					    chown -R docker-user:docker-user /var/run/apache2 && \
					    chown -R docker-user:docker-user /var/log/apache2 && \
					    chown -R docker-user:docker-user /var/lock/apache2 && \
					    usermod -aG sudo docker-user && \
					    echo "docker-user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
					
					# Expose the required ports
					EXPOSE 22 80
					
					# Start the SSH and Apache services
					CMD service ssh start && /usr/sbin/apache2ctl -D FOREGROUND```
			* After we define our Dockerfile, we need to convert it into an image. With `build` command, we take the directory with the Dockerfile, execute the steps from the `Dockerfile`, and store the image in our local Docker Engine. If one of the steps fails due to an error, the container creation will be aborted. With the option `-t`, we give our container a tag, so it is easier to identify and work with later.
				* ```docker build -t FS_docker``` DOESNT WORK
				* use this -> `docker build - < Dockerfile`
			* once created, it can be executed through the Docker engine, efficient and easy way to run a container.
			* container can be considered a running process of an image, read-only templates.
			* When a container is to be started on a system, a package with the respective image is first loaded if unavailable locally. We can start the container by the following command [docker run](https://docs.docker.com/engine/reference/commandline/run/):
				* `docker run -p <host port>:<docker port> -d <docker container name>`
				* `docker run -p 8022:22 -p 8080:80 -d FS_docker`
					* we start a new container from the image `FS_docker` and map the host ports 8022 and 8080 to container ports 22 and 80, respectively.
					* The container runs in the background, allowing us to access the SSH and HTTP services inside the container using the specified host ports.
			* **Docker Management** - easily create, deploy, and manage containers. List, start, stop.
				* `docker ps` List all running containers
				* `docker stop` Stop a running container.
				* `docker start` Start a stopped container.
				* `docker restart` Restart a running container.
				* `docker rm` Remove a container.
				* `docker rmi` Remove a Docker image.
				* `docker logs` View the logs of a container.
			* When working with Docker images, it's important to note that **any changes made to an existing image are not permanent**. Instead, we need to create a new image that inherits from the original and includes the desired changes.
				* This is done by creating a new Dockerfile that starts with the `FROM` statement, which specifies the base image, and then adds the necessary commands to make the desired changes.
				* Once the Dockerfile is created, we can use the `docker build` command to build the new image, tagging it with a unique name to help identify it. This process ensures that the original image remains intact while allowing us to create a new image with the desired changes.
			* Docker containers are designed to be **immutable**.
				* Therefore, it is recommended to use container orchestration tools such as Docker Compose or Kubernetes to manage and scale containers in a production environment.
		* **Linux Containers** - (LXC) is a lightweight virtualization technology that uses resource isolation features of the Linux kernel to provide an isolated environment for applications.
			* images manually built using a root filesystem and installing necessary packages and configs.
			* those containers are tied to the host system, not easily portable.
			* Docker is application-centric platform, builds on top of LXC and is more user-friendly
			* **To install LXC:**
				* `sudo apt-get install lxc lxc-utils -y`
					* try without lxc-utils
				* now we can start creating and managing containers on the Linux host
			* **Creating an LXC Container**
				* `sudo lxc-create -n linuxcontainer -t ubuntu`
			* **Managing LXC Containers**
				* create new, configure settings, start, stop, monitor performance.
				* Use `sudo` for below:
					* `lxc-ls` List all existing containers
					* `lxc-stop -n <container>` Stop a running container.
					* `lxc-start -n <container>` Start a stopped container.
					* `lxc-restart -n <container>` Restart a running container.
					* `lxc-config -n <container name> -s storage` Manage container storage
					* `lxc-config -n <container name> -s network` Manage container network settings
					* `lxc-config -n <container name> -s security` Manage container security settings
					* `lxc-attach -n <container>` Connect to a container.
					* `lxc-attach -n <container> -f /path/to/share` Connect to a container and share a specific directory or file.
			* **Securing LXC**
			* It is important to configure LXC container security to prevent unauthorized access or malicious activities inside the container. This can be achieved by implementing several security measures, such as:
				- **Restricting access to the container** - disabling unnecessary services, using secure protocols, and enforcing strong authentication mechanisms.
					- For example, we can disable SSH access to the container by removing the `openssh-server` package or by configuring SSH only to allow access from trusted IP addresses.
				- **Limiting** **resources** - resource limits or quotas to prevent containers from consuming excessive resources.
					- For example, we can use `cgroups` to limit the amount of CPU, memory, or disk space that a container can use.
					- `sudo vim /usr/share/lxc/config/linuxcontainer.conf`
					- add these lines
					- ```lxc.cgroup.cpu.shares = 512
					lxc.cgroup.memory.limit_in_bytes = 512M
					- The `lxc.cgroup.cpu.shares` parameter determines the CPU time a container can use in relation to the other containers on the system. Default is 1024, we set it to 512.
					- The `lxc.cgroup.memory.limit_in_bytes` parameter allows you to set the maximum amount of memory a container can use.
					- `[Esc] :wq` to write quit (save & exit)
					- To apply these changes, we must restart the LXC service.
						- `sudo systemctl restart lxc.service`
				- **Isolating the container from the host** - LXC uses `namespaces`, feature of the Linux kernel, to provide an isolated environment for processes, networks, and file systems from the host system. 
					- Each container is allocated a unique process ID (`pid`) number space, isolated from the host system's process IDs.
					- Additionally, each container has its own network interfaces (`net`), routing tables, and firewall rules, which are completely separate from the host system's network interfaces.
					- Moreover, containers come with their own root file system (`mnt`), which is entirely different from the host system's root file system.
				- **Enforcing mandatory access control**
				- **Keeping the container up to date**

* ## Network Configuration 
	* key skill for pentesters
	* **Configure network interfaces**
		* assign IP addresses
		* configuring network devices (routers, switches, network protocols[TCP/IP, DNS, DHCP, and FTP])
		* wireless/wired connections
	* **Network Access Control** - know how to configure Linux network devices for NAC (setting up **SELinux** policies, configuring **AppArmor** profiles, and using **TCP** **wrappers** to control accesses)
		* Discretionary access control (**DAC**)
		- Mandatory access control (**MAC**)
		- Role-based access control (**RBAC**)
	- **Monitoring network traffic**
		- monitoring and logging
		- **syslog**, **rsyslog**, **ss**, **lsof**, and the **ELK stack**
	- **Network troubleshooting tools** - insight into network traffic, packet loss, latency, DNS resolution, etc.
		- **ping**, **nslookup**, and **nmap**
	- **Configuring Network Interfaces**
		- `ifconfig`
		- `ip addr`
		-  These commands allow users to modify and activate settings for a specific interface, such as `eth0`. We can adjust the network settings to suit our needs by using the appropriate syntax and specifying the interface name.
			- `sudo ifconfig eth0 up`
			- `sudo ip link set eth0 up`
	- **Assign IP Address to an Interface**
		- `sudo ifconfig eth0 192.168.1.2`
	- **Assign a Network to an Interface**
		- `sudo ifconfig eth0 netmask 255.255.255.0`
	- **Assign the Route to an Interface**
		- `sudo route add default gw 192.168.1.1 eth0`
		-  When we want to set the default gateway for a network interface, we can use the `route` command with the `add` option. This allows us to specify the gateway's IP address and the network interface to which it should be applied.
	- **Editing DNS Settings**
		- set Domain Name System (`DNS`) servers to ensure proper network functionality. DNS servers translate domain names into IP addresses, allowing devices to connect with each other on the internet.
		- update the `/etc/resolv.conf` file with the appropriate DNS server information:
			- `nameserver 8.8.8.8`
			- `nameserver 8.8.4.4`
	- **Editing Interfaces**
		-  ensure that these changes are saved to persist across reboots. This can be achieved by editing the `/etc/network/interfaces` file, which defines network interfaces for Linux-based operating systems.
			- `sudo vim /etc/network/interfaces`
			- ```auto eth0
			iface eth0 inet static
			  address 192.168.1.2
			  netmask 255.255.255.0
			  gateway 192.168.1.1
			  dns-nameservers 8.8.8.8 8.8.4.4```
			* ensures network connection is stable and reliable.
		* `sudo systemctl restart networking`
	* **Network Access Control** - a security system that ensures that only authorized and compliant devices are granted access to the network, preventing unauthorized access, data breaches, and other security threats.
		* **DAC** - enables users to manage access to their resources by granting resource owners the responsibility of controlling access permissions to their resources.
		* **MAC** - define rules that determine resource access based on the resource's security level and the user's security level or process requesting access (Clearances, TSC).
		* **RBAC** - assigns permissions to users based on their roles within an organization.
	* **Monitoring** - capture, analyze, and interpret network traffic to identify security threats and vulnerabilities.
		* **Wireshark**
		* **tshark**
		* **Tcpdump**
	* **Troubleshooting** - diagnose and resolve network issues:
		* **Ping** - test connectivity between devices
			* `ping 8.8.8.8`
		* **Traceroute** - trace the route of packets take to reach a remote host.
			* `traceroute  www.inlanefreight.com`
			* `* * *` - means no response
		* **Netstat** - display active network connections and their ports
			* `netstat -a`
		* **Tcpdump**
		* **Wireshark**
		* **Nmap**
	* The most common network issues we will encounter during our penetration tests include the following:
		- Network connectivity issues
		- DNS resolution issues (it's always DNS)
		- Packet loss
		- Network performance issues
	- **Hardening** - safeguard Linux systems against various security threats, from unauthorized access to malicious attacks, especially while conducting a penetration test.
		- **SELinux** - a MAC system that is built into the Linux kernel. enforces a policy that defines access controls for each process and file on the system. **OPTIONAL ACTIVITY**:
			1. **Install SELinux**: Ensure SELinux is installed and running by checking its status:
			    
			    `sestatus`
			    
			    If SELinux is not installed, install it with your package manager.
			    
			2. **Prevent User Access to a Specific File**: To prevent a user (e.g., "user1") from accessing a specific file (e.g., "secretfile.txt"):
			    
			    `sudo chcon -t user_home_t /path/to/secretfile.txt
			    `sudo chown user1:user1 /path/to/secretfile.txt
			    `sudo chmod 600 /path/to/secretfile.txt`
			    
			3. **Allow a Single User to Access a Specific Network Service**: To allow a single user (e.g., "user2") to access the SSH service, you can use SELinux booleans:
			    
			    `sudo semanage login -a -s targeted -r s0 -l s0 __default__ 
			    `sudo setsebool -P ssh_chroot on`
			    
			4. **Deny Access to a Specific User for a Network Service**: To deny access to a specific user (e.g., "user3") for a network service (e.g., FTP):
			    
			    `sudo cat <<EOF > /etc/selinux/custom_ftp.te
			    `module custom_ftp 1.0;
			    `require {  
					`type ftpd_t;  
					`type user_home_dir_t;
				``}
				`allow user_home_dir_t ftpd_t:tcp_socket name_bind;
				`EOF`
				
				`checkmodule -M -m -o custom_ftp.mod /etc/selinux/custom_ftp.te semodule_package -o custom_ftp.pp -m custom_ftp.mod semodule -i custom_ftp.pp`
			    
		- **AppArmor** - also a MAC system. Implemented as a **Linux Security Module (LSM)** and uses application profiles to define the resources that an application can access. **OPTIONAL ACTIVITY**:
			1. Prevent a user from accessing a specific file:**
				- Identify the user and the specific file you want to protect.
				- Create a custom AppArmor profile for the user if it doesn't already exist:
			    
			    `sudo nano /etc/apparmor.d/usr.bin.yourapp`
			    
				- In the profile, add the following line to deny access to the specific file:
			    
			    `/path/to/your/specific/file r,`
			    
				- Save the file and reload the AppArmor profiles:
			    
			    `sudo apparmor_parser -r /etc/apparmor.d/usr.bin.yourapp`
			    
			2. Allow a single user to access a specific network service but deny access to all others:
				- Create or edit the AppArmor profile for the network service you want to restrict:
			    
			    `sudo nano /etc/apparmor.d/usr.sbin.network-service`
			    
				- In the profile, add the following rules to allow the specific user and deny access to others:
			    
			    `/usr/sbin/network-service r, /usr/sbin/network-service ix, deny /usr/sbin/network-service rix,`
			    
				- Save the file and reload the AppArmor profiles:
			    
			    `sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.network-service`
			    
			
			3. Deny access to a specific user or group for a specific network service:**
				- Follow the same steps as Scenario 6 to create or edit the AppArmor profile for the network service.
				- Add a rule to deny access for the specific user or group. For example, to deny access to the user "denieduser," add:
			    
			    `deny /usr/sbin/network-service (target) (rule),`
			    
				Replace `(target)` with the appropriate rule you want to deny (e.g., `r`, `ix`, etc.).
			    
				- Save the file and reload the AppArmor profiles:
			    
			    `sudo apparmor_parser -r /etc/apparmor.d/usr.sbin.network-se`
			    
		- **TCP wrappers** - a host-based network access control mechanism that can be used to restrict access to network services based on the IP address of the client system. Intercepts incoming network requests and compares the IP address of the client system to the access control rules. **OPTIONAL ACTIVITY**:
			1. **Allow Access to a Specific Network Service from a Specific IP Address:**
			    To allow access to a service (like SSH) from a specific computer (e.g., 192.168.1.100), you can add this line to the `/etc/hosts.allow` file:
			    
			    `sshd : 192.168.1.100`
			    
			    This allows only the computer at IP address 192.168.1.100 to use SSH.
			    
			2. **Deny Access to a Specific Network Service from a Specific IP Address:**
			    
			    To deny access to a service (e.g., Telnet) from a particular computer (e.g., 10.0.0.2), you can add this line to the `/etc/hosts.deny` file:
			    
			    `in.telnetd : 10.0.0.2`
			    
			    This blocks the computer at IP address 10.0.0.2 from using Telnet.
			    
			3. **Allow Access to a Specific Network Service from a Range of IP Addresses:**
			    
			    To allow access to a service (e.g., FTP) from a range of computers (e.g., 192.168.1.0 to 192.168.1.255), you can add this line to the `/etc/hosts.allow` file:
			    
			    `vsftpd : 192.168.1.0/24`
			    
			    This allows any computer within the range of IP addresses from 192.168.1.0 to 192.168.1.255 to use FTP.
* ## Remote Desktop Protocols in Linux
	* GUI remote access
		* RDP (Windows)
		* VNC (Linux)
	* **XServer** - the user-side part of the `X Window System network protocol` (`X11` / `X`).
		* **X11** - a fixed system that consists of a collection of protocols and applications that allow us to call application windows on displays in a graphical user interface.
		* The ports that are utilized for X server are typically located in the range of `TCP/6001-6009`, allowing communication between the client and server.
	* **VNC** and **RDP** generate the graphical output on the remote computer and transport it over the network. Whereas with **X11**, it is rendered on the local computer. This saves traffic and a load on the remote computer. However, X11's significant disadvantage is the unencrypted data transmission. However, this can be overcome by tunneling the SSH protocol.
		* To allow X11 forwarding in the SSH config file (`/etc/ssh/sshd_config`) on the server that provides the application by changing this option to `yes`:
			* ```cat /etc/ssh/sshd_config | grep X11Forwarding
			X11Forwarding yes```
		* Now can start the application from our client:
			* `ssh -X htb-student@10.129.23.11 /usr/bin/firefox`
	* **X11 Security** - not a secure protocol on its own as communication is not encrypted.
		* Vulnerabilities known to **XServer** are CVE-2017-2624, CVE-2017-2625, and CVE-2017-2626.
	* **XDMCP** - `X Display Manager Control Protocol` (`XDMCP`) protocol is used by the `X Display Manager` for communication through UDP port 177 between X terminals and computers operating under Unix/Linux.
		* manage remote X Window sessions on other machines.
		* insecure protocol
			* exploited through man-in-the-middle
	* **VNC** - `Virtual Network Computing` (`VNC`) is a remote desktop sharing system based on the RFB protocol that allows users to control a computer remotely.
		* generally secure
		* There are two different concepts for VNC servers.
			1. The usual server offers the actual screen of the host computer for user support. Because the keyboard and mouse remain usable at the remote computer, an arrangement is recommended.
			2. The second group of server programs allows user login to virtual sessions, similar to the terminal server concept.
		*  the VNC server listens on TCP port 5900. So it offers its `display 0` there. Other displays can be offered via additional ports, mostly `590[x]`, where `x` is the display number. Adding multiple connections would be assigned to a higher TCP port like 5901, 5902, 5903, etc.
		* For these VNC connections, many different tools are used. Among them are for example:
			- [TigerVNC](https://tigervnc.org/)
			- [TightVNC](https://www.tightvnc.com/)
			- [RealVNC](https://www.realvnc.com/en/)most used
			- [UltraVNC](https://uvnc.com/)most used
		- In this example, we set up a `TigerVNC` server, and for this, we need, among other things, also the `XFCE4` desktop manager since VNC connections with GNOME are somewhat unstable. Therefore we need to install the necessary packages and create a password for the VNC connection.
			- `sudo apt install xfce4 xfce4-goodies tigervnc-standalone-server -y`
			- `vncpasswd`
			- During installation, a hidden folder is created in the home directory called `.vnc`. Then, we have to create two additional files, `xstartup` and `config`. The `xstartup` determines how the VNC session is created in connection with the display manager, and the `config` determines its settings.
				- `touch ~/.vnc/xstartup ~/.vnc/config`
				- `cat <<EOF >> ~/.vnc/xstartup`
				- ```#!/bin/bash
				unset SESSION_MANAGER
				unset DBUS_SESSION_BUS_ADDRESS
				/usr/bin/startxfce4
				[ -x /etc/vnc/xstartup ] && exec /etc/vnc/xstartup
				[ -r $HOME/.Xresources ] && xrdb $HOME/.Xresources
				x-window-manager &
				EOT
				* ```cat <<EOT >> ~/.vnc/config
				geometry=1920x1080
				dpi=96
				EOT```
			* Additionally, the `xstartup` executable needs rights to be started by the service.
				* chmod +x ~/.vnc/xstartup
			* Start VNC server
				* `vncserver`
			* List sessions
				* `vncserver -list`
			* Setting Up an SSH Tunnel
				* ```ssh -L 5901:127.0.0.1:5901 -N -f -l htb-student 10.129.14.130```
			* Finally, connecting to the VNC Server
				* `xtightvncviewer localhost:5901`
* ## Linux Security
	* Update and Upgrade
		* `apt update && apt dist-upgrade`
	* If SSH is open on the server, the configuration should be set up to disallow password login and disallow the root user from logging in via SSH.
	* `fail2ban` - a tool that counts the number of failed login attempts, and if a user has reached the maximum number, the host that tried to connect will be handled as configured.
	* Audit the system regularly
	* **SELinux** or **AppArmor**, other applications and services to help secure Linux are [Snort](https://www.snort.org/), [chkrootkit](http://www.chkrootkit.org/), [rkhunter](https://packages.debian.org/sid/rkhunter), [Lynis](https://cisofy.com/lynis/).
	* ==Security settings to make:
		* Removing or disabling all unnecessary services and software
		- Removing all services that rely on unencrypted authentication mechanisms
		- Ensure NTP is enabled and Syslog is running
		- Ensure that each user has its own account
		- Enforce the use of strong passwords
		- Set up password aging and restrict the use of previous passwords
		- Locking user accounts after login failures
		- Disable all unwanted SUID/SGID binaries
		- and more...
	- **TCP Wrappers** - a security mechanism used in Linux systems that allows the system administrator to control which services are allowed access to the system.
		- It works by restricting access to certain services based on the hostname or IP address of the user requesting access.
		- TCP wrappers use the following configuration files:
			- `/etc/hosts.allow`
				- ```cat /etc/hosts.allow
				
				#Allow access to SSH from the local network
				sshd : 10.129.14.0/24
				
				#Allow access to FTP from a specific host
				ftpd : 10.129.14.10
				
				#Allow access to Telnet from any host in the inlanefreight.local domain
				telnetd : .inlanefreight.local```
			- `/etc/hosts.deny`
				- ```cat /etc/hosts.deny

				#Deny access to all services from any host in the inlanefreight.com domain
				ALL : .inlanefreight.com
				
				#Deny access to SSH from a specific host
				sshd : 10.129.22.22
				
				#Deny access to FTP from hosts with IP addresses in the range of 10.129.22.0 to 10.129.22.255
				ftpd : 10.129.22.0/24```
			* Order of rules matters, first rule that matches is applied first
	* **Firewall Setup** - a security mechanism for controlling and monitoring network traffic between different network segments, such as internal and external networks or different network zones.
		* filter incoming and outgoing traffic based on pre-defined rules, protocols, ports, and other criteria to prevent unauthorized access and mitigate security threats.
		* **Iptables** - this utility provides a flexible set of rules for filtering network traffic based on various criteria such as source and destination IP addresses, port numbers, protocols, and more.
			* Tables in iptables are used to categorize and organize firewall rules based on the type of traffic that they are designed to handle. These tables are used to organize and categorize firewall rules. Each table is responsible for performing a specific set of tasks. Table names:
				* `filter` Used to filter network traffic based on IP addresses, ports, and protocols. INPUT, OUTPUT, FORWARD (these 3 are built-in chains)
				* `nat` Used to modify the source or destination IP addresses of network packets. PREROUTING, POSTROUTING (these 2 are built-in chains)
				* `mangle` Used to modify the header fields of network packets. PREROUTING, OUTPUT, INPUT, FORWARD, POSTROUTING (these 4 are built-in chains)
				* In addition to the built-in tables, iptables provides a fourth table called the raw table, which is used to configure special packet processing options. The raw table contains two built-in chains: PREROUTING and OUTPUT. (these 2 are built-in chains)
					* Built-in chains
					* User-defined chains
			* Iptables rules are used to define the criteria for filtering network traffic and the actions to take for packets that match the criteria. Rules are added to chains using the `-A` option followed by the chain name, and they can be modified or deleted using various other options.
			* Each rule consists of a set of criteria or matches and a target specifying the action for packets that match the criteria. Some of the common targets used in iptables rules include the following:
				* `ACCEPT` Allows the packet to pass through the firewall and continue to its destination
				* `DROP` Drops the packet, effectively blocking it from passing through the firewall
				* `REJECT` Drops the packet and sends an error message back to the source address, notifying them that the packet was blocked
				* `LOG` Logs the packet information to the system log
				* `SNAT` Modifies the source IP address of the packet, typically used for Network Address Translation (NAT) to translate private IP addresses to public IP addresses
				* `DNAT` Modifies the destination IP address of the packet, typically used for NAT to forward traffic from one IP address to another
				* `MASQUERADE` Similar to SNAT but used when the source IP address is not fixed, such as in a dynamic IP address scenario
				* `REDIRECT` Redirects packets to another port or IP address
				* `MARK` Adds or modifies the Netfilter mark value of the packet, which can be used for advanced routing or other purposes
			* `Matches` are used to specify the criteria that determine whether a firewall rule should be applied to a particular packet or connection.
				* `-p` or `--protocol` Specifies the protocol to match (e.g. tcp, udp, icmp)
				* `--dport` Specifies the destination port to match
				* `--sport` Specifies the source port to match
				* `-s` or `--source` Specifies the source IP address to match
				* `-d` or `--destination` Specifies the destination IP address to match
				* `-m state` Matches the state of a connection (e.g. NEW, ESTABLISHED, RELATED)
				* `-m multiport` Matches multiple ports or port ranges
				* `-m tcp` Matches TCP packets and includes additional TCP-specific options
				* `-m udp` Matches UDP packets and includes additional UDP-specific options
				* `-m string` Matches packets that contain a specific string
				* `-m limit` Matches packets at a specified rate limit
				* `-m conntrack` Matches packets based on their connection tracking information
				* `-m mark` Matches packets based on their Netfilter mark value
				* `-m mac` Matches packets based on their MAC address
				* `-m iprange` Matches packets based on a range of IP addresses
			*  For example, the following command adds a rule to the 'INPUT' chain in the 'filter' table that matches incoming TCP traffic on port 80:
				* `sudo iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT`
				* This rule matches incoming TCP traffic (`-p tcp`) on port 80 (`--dport 80`) and jumps to the accept target (`-j ACCEPT`) if the match is successful.
		* Other firewall solutions are:
			* **UFW** - uncomplicated firewall, simpler and user-friendly interface. Built on top of iptables framework
			* **firewalld** - dynamic and flexible firewall solution for complex configurations. It supports a rich set of rules for filtering network traffic and can be used to create custom firewall zones and services. It consists of several components that work together to provide a flexible and powerful firewall solution. The main components of iptables are:
				* `Tables` Tables are used to organize and categorize firewall rules.
				* `Chains` Chains are used to group a set of firewall rules applied to a specific type of network traffic.
				* `Rules` Rules define the criteria for filtering network traffic and the actions to take for packets that match the criteria.
				* `Matches` Matches are used to match specific criteria for filtering network traffic, such as source or destination IP addresses, ports, protocols, and more.
				* `Targets` Targets specify the action for packets that match a specific rule. For example, targets can be used to accept, drop, or reject packets or modify the packets in another way.
			* **nftables** - more modern syntax and improved performance from iptables, however, the syntax of nftables rules is not compatible with iptables, so migration to nftables requires some effort.
	* **Optional Firewall exercise**
		1. **Launch a web server on TCP/8080 port on your target:** You can start a web server (e.g., Apache) on port 8080 with a command like `sudo systemctl start apache2`.
			**Use iptables to block incoming traffic on port TCP/8080:** To block incoming traffic on port 8080, use the command `sudo iptables -A INPUT -p tcp --dport 8080 -j DROP`.
		2. **Change iptables rules to allow incoming traffic on TCP/8080 port:** To allow incoming traffic on port 8080, you can use the command `sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT`.
		3. **Block traffic from a specific IP address:** To block traffic from a specific IP (e.g., 192.168.1.100), use `sudo iptables -A INPUT -s 192.168.1.100 -j DROP`.
		4. **Allow traffic from a specific IP address:** To allow traffic from a specific IP (e.g., 192.168.1.101), use `sudo iptables -A INPUT -s 192.168.1.101 -j ACCEPT`.
		5. **Block traffic based on protocol:** For example, to block all incoming UDP traffic, use `sudo iptables -A INPUT -p udp -j DROP`.
		6. **Allow traffic based on protocol:** To allow, for instance, ICMP traffic (ping), use `sudo iptables -A INPUT -p icmp -j ACCEPT`.
		7. **Create a new chain:** You can create a custom chain like this: `sudo iptables -N mychain`.
		8. **Forward traffic to a specific chain:** To forward traffic to a custom chain, use `sudo iptables -A INPUT -j mychain`.
		9. **Delete a specific rule:** To delete a specific rule (e.g., rule number 3), use `sudo iptables -D INPUT 3`.
		10. **List all existing rules:** You can list all existing rules with `sudo iptables -L`.
* ## System Logs
	* a set of files that contain information about the system and the activities taking place on it.
	* onfigure system logs properly by setting the appropriate log levels, configuring log rotation to prevent log files from becoming too large, and ensuring that the logs are stored securely and protected from unauthorized access. 
		* In addition, it is important to regularly review and analyze the logs to identify potential security risks and respond to any security events in a timely manner. There are several different types of system logs on Linux, including:
			* **Kernel Logs** - These logs contain information about the system's kernel, including hardware drivers, system calls, and kernel events
				* `/var/log/kern.log`
			* **System Logs** - These logs contain information about system-level events, such as service starts and stops, login attempts, and system reboots.
				* `/var/log/syslog`
			* **Authentication Logs** - These logs contain information about user authentication attempts, including successful and failed attempts.
				* `/var/log/auth.log`
			* **Application Logs** - These logs contain information about the activities of specific applications running on the system.
				* They are often stored in their own files, such as `/var/log/apache2/error.log` for the Apache web server or `/var/log/mysql/error.log` for the MySQL database server.
				* On Linux systems, most common services have default locations for access logs:
					* `Apache` Access logs are stored in the /var/log/apache2/access.log file (or similar, depending on the distribution).
					* `Nginx` Access logs are stored in the /var/log/nginx/access.log file (or similar).
					* `OpenSSH` Access logs are stored in the /var/log/auth.log file on Ubuntu and in /var/log/secure on CentOS/RHEL.
					* `MySQL` Access logs are stored in the /var/log/mysql/mysql.log file.
					* `PostgreSQL` Access logs are stored in the /var/log/postgresql/postgresql-version-main.log file.
					* `Systemd` Access logs are stored in the /var/log/journal/ directory.
			* **Security Logs** - These security logs and their events are often recorded in a variety of log files, depending on the specific security application or tool in use.
				* These security logs and their events are often recorded in a variety of log files, depending on the specific security application or tool in use. For example, the Fail2ban application records failed login attempts in the `/var/log/fail2ban.log` file, while the UFW firewall records activity in the `/var/log/ufw.log` file.
* ## Solaris
	* a Unix-based operating system developed by Sun Microsystems (later acquired by Oracle Corporation) in the 1990s.
	* It is known for its robustness, scalability, and support for high-end hardware and software systems. Solaris is widely used in enterprise environments for mission-critical applications, such as database management, cloud computing, and virtualization. For example, it includes a built-in hypervisor called `Oracle VM Server for SPARC`, which allows multiple virtual machines to run on a single physical server. **Overall, it is designed to handle large amounts of data and provide reliable and secure services to users and is often used in enterprise environments where security, performance, and stability are key requirements.**
	* One of the main differences between Solaris and Linux distributions is that Solaris is a proprietary operating system.
	* Solaris uses the Image Packaging System (`IPS`) package manager, which provides a powerful and flexible way to manage packages and updates.
	*  Solaris also provides advanced security features, such as Role-Based Access Control (`RBAC`) and mandatory access controls, which are not available in all Linux distributions.
	* One of the most important differences is that the source code is not open source and is only known in closed circles. This means that unlike Ubuntu or many other distributions, the source code cannot be viewed and analyzed by the public. In summary, the main differences can be grouped into the following categories:
		- Filesystem
		- Process management
		- Package management
		- Kernel and Hardware support
		- System monitoring
		- Security
	- `uname -a` = `showrev -a`
	- `sudo apt-get install apache2` = `pkgadd -d SUNWapchr`
	- `truss` - a highly useful utility for developers and system administrators who need to debug complex software issues on the Solaris operating system.
		- trace system calls made by a process
			- `sudo strace -p 'pgrep apache2' = truss ls
		- The output is similar to `strace`, but the format is slightly different. One difference between `strace` and `truss` is that `truss` can also trace the signals sent to a process, while `strace` cannot. Another difference is that `truss` has the ability to trace the system calls made by child processes, while `strace` can only trace the system calls made by the process specified on the command line.
- ## Shortcuts
	* #### Auto-Complete
	
	`[TAB]` - Initiates auto-complete. This will suggest to us different options based on the `STDIN` we provide. These can be specific suggestions like directories in our current working environment, commands starting with the same number of characters we already typed, or options.
	
	---
	
	* #### Cursor Movement
	
	`[CTRL] + A` - Move the cursor to the `beginning` of the current line.
	
	`[CTRL] + E` - Move the cursor to the `end` of the current line.
	
	`[CTRL] + [←]` / `[→]` - Jump at the beginning of the current/previous word.
	
	`[ALT] + B` / `F` - Jump backward/forward one word.
	
	---
	
	* #### Erase The Current Line
	
	`[CTRL] + U` - Erase everything from the current position of the cursor to the `beginning` of the line.
	
	`[Ctrl] + K` - Erase everything from the current position of the cursor to the `end` of the line.
	
	`[Ctrl] + W` - Erase the word preceding the cursor position.
	
	---
	
	* #### Paste Erased Contents
	
	`[Ctrl] + Y` - Pastes the erased text or word.
	
	---
	
	* #### Ends Task
	
	`[CTRL] + C` - Ends the current task/process by sending the `SIGINT` signal. For example, this can be a scan that is running by a tool. If we are watching the scan, we can stop it / kill this process by using this shortcut. While not configured and developed by the tool we are using. The process will be killed without asking us for confirmation.
	
	---
	
	* #### End-of-File (EOF)
	
	`[CTRL] + D` - Close `STDIN` pipe that is also known as End-of-File (EOF) or End-of-Transmission.
	
	---
	
	* #### Clear Terminal
	
	`[CTRL] + L` - Clears the terminal. An alternative to this shortcut is the `clear` command you can type to clear our terminal.
	
	---
	
	* #### Background a Process
	
	`[CTRL] + Z` - Suspend the current process by sending the `SIGTSTP` signal.
	
	---
	
	* #### Search Through Command History
	
	`[CTRL] + R` - Search through command history for commands we typed previously that match our search patterns.
	
	`[↑]` / `[↓]` - Go to the previous/next command in the command history.
	
	---
	
	* #### Switch Between Applications
	
	`[ALT] + [TAB]` - Switch between opened applications.
	
	---
	
	* #### Zoom
	
	`[CTRL] + [+]` - Zoom in.
	
	`[CTRL] + [-]` - Zoom out.

















