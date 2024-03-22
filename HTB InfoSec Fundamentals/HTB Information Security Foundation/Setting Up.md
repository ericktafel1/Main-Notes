# **Scenario:**

Our company was commissioned by a new customer (Inlanefreight) to perform an external and internal penetration test. As already mentioned, proper Operating System preparation is required before conducting any penetration test. Our customer provides us with internal systems that we should prepare before the engagement so that the penetration testing activities commence without delays. For this, we have to prepare the necessary operating systems accordingly and efficiently.

## **Organization**

Corporate environments consist of heterogeneous networks (hosts/servers having different OS). Organize the host/server based on OS like:


```
G1GS@htb[/htb]$ tree .
.  
└── Penetration-Testing  
	│  
	├── Pre-Engagement  
	│       └── ...  
    ├── Linux  
    │   ├── Information-Gathering  
    │   │   └── ...  
    │   ├── Vulnerability-Assessment  
    │   │   └── ...  
    │   ├── Exploitation  
    │   │   └── ...  
    │   ├── Post-Exploitation  
    │   │   └── ...  
    │   └── Lateral-Movement  
    │       └── ...  
    ├── Windows  
    │   ├── Information-Gathering  
    │   │   └── ...  
    │   ├── Vulnerability-Assessment  
    │   │   └── ...  
    │   ├── Exploitation  
    │   │   └── ...  
    │   ├── Post-Exploitation  
    │   │   └── ...  
    │   └── Lateral-Movement  
    │       └── ...  
    ├── Reporting  
    │   └── ...  
	└── Results  
	    └── ...  
```

 
We can also reorganize the structure based on specialized penetration testing fields. Take this for example:

```
G1GS@htb[/htb]$ tree .    
.  
└── Penetration-Testing  
	│  
	├── Pre-Engagement  
	│       └── ...  
    ├── Network-Pentesting  
	│       ├── Linux  
	│       │   ├── Information-Gathering  
	│		│   │   └── ...  
	│       │   ├── Vulnerability-Assessment  
    │       │   │	└── ...  
    │       │	└── ...  
    │       │    	└── ...  
    │		├── Windows  
    │ 		│   ├── Information-Gathering  
    │		│   │   └── ...  
    │		│   └── ...  
    │       └── ...  
    ├── WebApp-Pentesting  
	│       └── ...  
    ├── Social-Engineering  
	│       └── ...  
    ├── .......  
	│       └── ...  
    ├── Reporting  
    │   └── ...  
	└── Results  
	    └── ...
```

As a new comer penetration tester, start with the OS structure for notes.

There are five different main types of information that need to be noted down:

1. Newly discovered information
2. Ideas for further tests and processing
3. Scan results
4. Logging
5. Screenshots

### Reporting
* Use Ghostwriter or Pwndoc
* Follow the wiki to install, will require containers to be ran on Docker

### Logging
* use **script** and **date**.
* To display the date and time, we can replace the **PS1** variable in our .bashrc file with the following content.
```
PS1="\[\033[1;32m\]\342\224\200\$([[ \$(/opt/vpnbash.sh) == *\"10.\"* ]] && echo \"[\[\033[1;34m\]\$(/opt/vpnserver.sh)\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\$(/opt/vpnbash.sh)\[\033[1;32m\]]\342\224\200\")[\[\033[1;37m\]\u\[\033[01;32m\]@\[\033[01;34m\]\h\[\033[1;32m\]]\342\224\200[\[\033[1;37m\]\w\[\033[1;32m\]]\n\[\033[1;32m\]\342\224\224\342\224\200\342\224\200\342\225\274 [\[\e[01;33m\]$(date +%D-%r)\[\e[01;32m\]]\\$ \[\e[0m\]"

```

* Date
```
─[eu-academy-1]─[10.10.14.2]─[Cry0l1t3@htb]─[~]
└──╼ [03/21/21-01:45:04 PM]$
```
* To start logging with script (for Linux) and Start-Transcript (for Windows), we can use the following command and rename it according to our needs. It is recommended to define a certain format in advance after saving the individual logs. One option is using the format `<date>-<start time>-<name>.log`.

* Script

```
[!bash!]$ script 03-21-2021-0200pm-exploitation.log

Script started, output log file is '03-21-2021-0200pm-exploitation.log'.

[!bash!]$ ...SNIP...
[!bash!]$ exit
```

* Start-Transcript

```
C:\> Start-Transcript -Path "C:\Pentesting\03-21-2021-0200pm-exploitation.log"

Transcript started, output file is C:\Pentesting\03-21-2021-0200pm-exploitation.log

C:\> ...SNIP...
C:\> Stop-Transcript
```

* Tmux & Terminator - Terminals

### Screenshots
* use Flameshot

### Virtualization
* VMware/Virtual box
	* upload iso files
### IF "Virtualized AMD-V/RVI is not supported on this platform" error messgae for Windows11 VM, then:
1. bcdedit /set hypervisorlaunchtype off
2. win + r > optionalfeatures
3. Remove "Windows Subsystem for Linux"
4. Reboot

### Containers
* A container cannot be defined as a virtual machine but as an isolated group of processes running on a single host that corresponds to a complete application, including its configuration and dependencies. 
* Has no operating system or kernel

|**Virtual Machine**|**Container**|
|---|---|
|Contain applications and the complete operating system|Contain applications and only the necessary operating system components such as libraries and binaries|
|A hypervisor such as VMware ESXi provides virtualization|The operating system with the container engine provides its own virtualization|
|Multiple VMs run in isolation from each other on a physical server|Several containers run isolated from each other on one operating system|

* The cooperation of various applications is also possible, and if the containers run on the same system, a container daemon is used, for example, the Linux Container Daemon (LXD).
	* LXD is similar to Linux Containers (LXC)
	* LXD is better for automating mass container management and is used in cloud computing and data centers
* Large container setups can be managed without any problems because of orchestration systems such as **Apache Mesos** or **Google Kubernetes**. 
* **Docker** is an open source software that can isolate applications in containers.
	* Docker Engine
	* Docker Compose
* **Vagrant** is a tool that can create, configure and manage virtual machines or virtual machine environments.
	* ![[Pasted image 20231017144135.png]]

### Linux
* I am already very familiar with Linux
* Use ParrotOS Security for HTB skill and job paths
* Store as a single file in VM
* Recommended to set the size larger than 20GB
* Encrypt data with LVM (LVM in Windows is Storage Spaces, LVM in MacOS is CoreStorage)
* Recommended to create a Swap (no hibernate) partition
* To do
	* The package manager is used for package management. This means that we can search, update, and install program packages. APT uses repositories (thus package sources), which are deposited in the directory `/etc/apt/sources.list` (in our case for ParrotOS: `/etc/apt.sources.list.d/parrot.list`).
	* Update ```sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y```
	* Tools List ```cat tools.list```
		* install all tools in list at once with ```sudo apt install $(cat tools.list | tr "\n" " ") -y```
		* Also install from github Privilege-Escalation-Awesome-Scripts-Suite ```git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git```
	* Install Additional Tools
		* $PS1, Date, Script (Linux)
		* Tmux, Terminator
		* bashrcgenerator
		* Obsidian/Cherrytree
		* Flameshot
		* VMware
		*  Docker, Ghostwriter/Pwndoc + Vagrant
	* Using Github
		* use ```git clone```
		# Take a **VM Snapshot!**
	* When I am on engagements or have a server myself, I can setup **Containers** with **Docker** to use images I created
		* I can also host a **bash script** to curl to from the clients workstation to get the **PS1** I need for clean logs.
		* Automation
			* Bash Prompt Customization Script - Prompt.sh```
			#!/bin/bash
			#### Make a backup of the .bashrc file
			cp ~/.bashrc ~/.bashrc.bak
			#### Customize bash prompt
			echo 'export PS1="-[\[$(tput sgr0)\]\[\033[38;5;10m\]\d\[$(tput sgr0)\]-\[$(tput sgr0)\]\[\033[38;5;10m\]\t\[$(tput sgr0)\]]-[\[$(tput sgr0)\]\[\033[38;5;214m\]\u\[$(tput sgr0)\]@\[$(tput sgr0)\]\[\033[38;5;196m\]\h\[$(tput sgr0)\]]-\n-[\[$(tput sgr0)\]\[\033[38;5;33m\]\w\[$(tput sgr0)\]]\\$ \[$(tput sgr0)\]"' >> ~/.bashrc
		
			* If we then host this script on our VPS, we can retrieve it from our customer's Linux workstation and apply it. ```
			#### Request Prompt.sh
			user@workstation:~$ curl -s http://myvps.vps-provider.net/Prompt.sh | bash
			#### Customized Bash Prompt
			-[Wed Mar 24-11:27:15]-[user@workstation]-
			* ### Applies to all customization scripts
	* Create another Snapshot
	* Encrypt the VM in settings
		* Access Control settings 

### Windows
* I know a lot of Windows too
* **Windows Subsystem for Linux (WSL)** - windows feature that allows Linux OS to run alongside Windows install.
	* Can run tools for Linux on Windows without a hypervisor
* Install
	* WSL
	* Visual Studio Code
	* Python
	* Git
	* Chocolatey Package Manager
* Disable Hyper-V in VMware and Memory Integrity in Windows

* To prepare our Windows host, we have to make a few changes before installing our fun tools:
	1. We will need to update our host to ensure it is working at the required level and keep our security posture as strong as possible.
	2. We will want to install the Windows Subsystem for Linux and the Chocolatey Package manager. Once these tasks are completed, we can make our exclusions to Windows Defender scanning policies to ensure they will not quarantine our newly installed tools and scripts ==**(did not do this, could not find solution)**==. From this point, it is now time to install our tools and scripts of choice.
	3. We will finish our buildout by taking a backup or snapshot of the host to have a fallback point if something happens to it.
	```
	Get-ExecutionPolicy List
	Set-ExecutionPolicy Bypass -Scope Process
	Set-ExecutionPolicy Unrestricted -Scope Process
	```
	* Bypass to install scripts Windows would overwise not allow
	* Now we want to set all to Undefined
	* Then ONLY change process policy to Unrestricted (only applies to current PowerShell process)
* Install PSWindowsUpdate
	* ```Install-Module PSWindowsUpdate
	* ```Import-Module PSWindowsUpdate
	* ```Install-WindowsUpdate -AcceptALL
	* ```Restart-Computer -Force

* To install chocolatey
	* ```Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	* To update chocolatey
	* ```choco upgrade chocolatey -y 
	* Using choco to install packages, first list info about a package. Can install packages separately or from a list in a XML file (packages.config)
		* ```choco info vscode
		* ```choco install python vscode git wsl2 openssh openvpn
		* ```RefreshEnv
	* RefreshEnv updates Powershell and any environment variables
	* install Terminal with Chocolatey
		* ```choco install microsoft-windows-terminal
	* install WSL2
		* ```choco install WSL2
		* **will not work without VM CPU settings enabling AMD-V, only works with Memory Integrity**

	* * Security Configurations and Defender Modifications
		* Windows Defender Exemptions for the Tools' Folders.
			* C:\Users\Erick\AppData\Local\Temp\chocolatey\
			* C:\Users\Erick\Documents\git-repos\
			* C:\Users\Erick\Documents\scripts\
	* Choco Build Scripts
	```powershell
	# Choco build script
	
write-host "*** Initial app install for core tools and packages. ***"
	
write-host "*** Configuring chocolatey ***"
choco feature enable -n allowGlobalConfirmation
	
write-host "*** Beginning install, go grab a coffee. ***"
choco upgrade wsl2 python git vscode openssh openvpn netcat nmap wireshark burp-suite-free-edition heidisql sysinternals putty golang neo4j-community openjdk
	
write-host "*** Build complete, restoring GlobalConfirmation policy. ***"
choco feature disable -n allowGlobalCOnfirmation```

	* always use **choco** or **choco.exe** as the command in your scripts. **cup** or **cinst** tends to misbehave when used in a script.
	* when utilizing options like **-n** it is recommended that we use the extended option like **--name**.
	* Do not use **--force** in scripts. It overrides Chocolatey's behavior.

	* Git Clone for packages Chocolatey doesn't have
		* ```C:\htb> git clone https://github.com/dafthack/DomainPasswordSpray.git```
	* Test VMs for client and install correct versions / updates to simulate their environments

### VPS Providers
* A **Virtual Private Server (VPS)** provider is an isolated environment created on a physical server using virtualization technology (VT). Also called a **Virtual Dedicated Server (VDS)**
* Basically an IaaS solution. Its uses can be for:
	* Webserver, LAMP/XAMPP stack, Mail server, DNS server, Development server, Proxy server, Test server, Code repository, Pentesting, VPN, Gaming server, C2 server
* I plan to use my MacMini and make it a server/container (==Project for the future==)
	* Other providers:
		* Vultr
		* Linode
		* DigitalOcean
		* OneHostCloud
* Use IPv6
* Generate SSH Keys to log into the VPS via SSH later:
	* ```ssh-keygen -t rsa -b 4096 -f vps-ssh
* With the command shown above, we generate two different keys.
	* The **vps-ssh** is the private key and must not be shared anywhere or with anyone.
	* The second **vps-ssh.pub** is the public key which we can now insert in the VPS control panel.
* ```ls -l vps*
* Access the VPS via SSH:
	* ```G1GS@htb[/htb]$ ssh root@<vps-ip-address>
		root@<vps-ip-address>'s password: 
		[root@VPS ~]# 
* Add new user to avoid running services on root:
	 ```
	[root@VPS ~]# adduser cry0l1t3
	[root@VPS ~]# usermod -aG sudo cry0l1t3
	[root@VPS ~]# su - cry0l1t3
	Password: 
	[cry0l1t3@VPS ~]$
	```
* Adding Public SSH Key to VPS
	```
	[cry0l1t3@VPS ~]$ mkdir ~/.ssh
	[cry0l1t3@VPS ~]$ echo '<vps-ssh.pub>' > ~/.ssh/authorized_keys
	[cry0l1t3@VPS ~]$ chmod 600 ~/.ssh/authorized_keys
	```
* Once we have added this to the authorized_keys file, we can use the private key to log in to the system via SSH:
	* ```G1GS@htb[/htb]$ ssh cry0l1t3@<vps-ip-address> -i vps-ssh
		[cry0l1t3@VPS ~]$ 
		
* **VPS Hardening**
	* Limit access to the VPS to SSH and disable all other services on the VPS
	* Reduce attack vectors
	* Ways to harden SSH to a VPS:
		* Install Fail2ban
		* Working only with SSH keys
		* Reduce Idle timeout interval
		* Disable passwords
		* Disable x11 forwarding
		* Use a different port
		* Limit users' SSH access
		* Disable root logins
		* Use SSH proto 2
		* Enable 2FA Authentication for SSH
	* First, make sure system is up-to-date:
		* ```sudo apt update -y && sudo apt full-upgrade -y && sudo apt autoremove -y && sudo apt autoclean -y
	* **SSH Hardening**
		* Change some of the settings in the **configuration file** /etc/ssh/sshd_config
		* Install **Fail2Ban**
			* ```sudo apt install fail2ban -y
			* Fail2Ban Config Backup
				* ```sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bak
				* Add to Fail2Ban config file:
					* ```# [sshd]
						enabled = true
						bantime = 4w
						maxretry = 3
			* Editing OpenSSH Config
				* ```sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
					sudo vim /etc/ssh/sshd_config```
				
				```sshd_config
				LogLevel VERBOSE
				PermitRootLogin no
				MaxAuthTries 3
				MaxSessions 5
				HostbasedAuthentication no
				PermitEmptyPasswords no
				ChallengeResponseAuthentication yes
				UsePAM yes
				X11Forwarding no
				PrintMotd no
				ClientAliveInterval 600
				ClientAliveCountMax 0
				AllowUsers <"username>" (**WITHOUT QUOTES**)
				Protocol 2
				AuthenticationMethods publickey,keyboard-interactive
				PasswordAuthentication no
				```
			* 2FA Google Authentication
				* Using Google Authenticator, generates a 6 digit OTP
				* To configure this on the VPS, we need the Google-Authenticator PAM Module
					* ```sudo apt install libpam-google-authenticator -y
						google-authenticator```
					* save backup codes and scan QR code or enter secret key into Google Authenticator app or webpage.
					* prompts to update /home/gigs/.google_autheticator file: 
						* yes, yes, no, yes
			* 2FA PAM Configuration
				* ```sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.bak```
				* ```sudo nano /etc/pam.d/sshd```
				* We comment out the "`@include common-auth`" line by putting a "`#`" in front of it. Besides, we add two new lines at the end of the file, as follows:
					* ```#@include common-auth
						...SNIP...
						auth required pam_google_authenticator.so
						auth required pam_permit.so```
			* Adjust settings in our SSH daemon to allow this authentication method, add two lines at bottom:
				* ```sshd_config
					...SNIP...
					AuthenticationMethods publickey,keyboard-interactive
					PasswordAuthentication no```
			* Restart SSH Server
				`sudo service ssh restart`
			* Connect with 2FA SSH
			
				* **Did not successfully complete the remaining VPS Hardening steps, moving on as having a VPS is not required.**
				
				```ssh gigs@VPS -i ~/.ssh/vps-ssh```
			
			* Transfer all resources, scripts, notes, and other components to the VPS using **SCP***
				* ```scp -i <ssh-private-key> -r <directory to transfer> <username>@<IP/FQDN>:<path>```
				* ```scp -i ~/.ssh/vps-ssh -r ~/Pentesting cry0l1t3@VPS:~/```

