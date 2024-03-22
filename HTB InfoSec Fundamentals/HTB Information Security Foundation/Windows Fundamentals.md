* ## Introduction to Windows
	* I used this OS all my life, simple notes
	* Majority of OS
	* 1985 - MS-DOS
	* OS name and Versions:
		* Windows NT 4 - 4.0
		* Windows 2000 - 5.0
		* Windows XP - 5.1
		* Windows Server 2003, 2003 R2 - 5.2
		* Windows Vista, Server 2008 - 6.0
		* Windows 7, Server 2008 R2 - 6.1
		* Windows 8, Server 2012 - 6.2
		* Windows 8.1, Server 2012 R2 - 6.3
		* Windows 10, Server 2016, Server 2019 - 10.0
	* We can use the [Get-WmiObject](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1) [cmdlet](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-overview?view=powershell-7) to find information about the operating system.
		* `Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber`
	* `Win32_Process` to get a process listing, `Win32_Service` to get a listing of services, and `Win32_Bios` to get [Basic Input/Output System](https://en.wikipedia.org/wiki/BIOS) (`BIOS`) information.
	* **Accessing Windows**
		* **Local access**
			* Local access is the most common way to access any computer, including computers running Windows
		* **Remote access**
			* Accessing a computer over a network. Local access to a computer is needed before one can access another computer remotely.
			* Some of the most common remote access technologies include but aren't limited to:
				- Virtual Private Networks (**VPN**)
				- Secure Shell (**SSH**)
				- File Transfer Protocol (**FTP**)
				- Virtual Network Computing (**VNC**)
				- Windows Remote Management (or PowerShell Remoting) (**WinRM**)
				- Remote Desktop Protocol (**RDP**) - uses a client/server architecture where a client-side application is used to specify a computer's target IP address or hostname over a network where RDP access is enabled. The target computer where RDP remote access is enabled is considered the server.
					- **port 3389**
					- ==consider a network subnet a street in a town (the corporate network), an IP address in that subnet assigned to a host as a house on that street, and logical ports as windows/doors that can be used to access the house.
					- If we are connecting to a Windows target from a Windows host, we can use the built-in RDP client application called `Remote Desktop Connection` ([mstsc.exe](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/mstsc)).
						- remote access must be allowed on the target Windows system.
					- Remote Desktop Connection also allows us to save connection profiles.
						- `.rdp` files 
					- **xfreerdp** - From a Linux-based attack host we can use a tool called [xfreerdp](https://linux.die.net/man/1/xfreerdp) to remotely access Windows targets.
						- `xfreerdp /v:<targetIp> /u:htb-student /p:Password`
					- Other RDP clients exist, such as [Remmina](https://remmina.org/) and [rdesktop](http://www.rdesktop.org/)
- ## Operating System Structure
	- root directory is C://
	- directory structure
		- **Perflogs** - Can hold Windows performance logs but is empty by default.
		- **Program Files** - On 32-bit systems, all 16-bit and 32-bit programs are installed here. On 64-bit systems, only 64-bit programs are installed here
		- **Program Files (x86)** - 32-bit and 16-bit programs are installed here on 64-bit editions of Windows
		- **ProgramData** - This is a hidden folder that contains data that is essential for certain installed programs to run. This data is accessible by the program no matter what user is running it
		- **Users** - This folder contains user profiles for each user that logs onto the system and contains the two folders Public and Default
		- **Default** - This is the default user profile template for all created users. Whenever a new user is added to the system, their profile is based on the Default profile
		- **Public** - This folder is intended for computer users to share files and is accessible to all users by default. This folder is shared over the network by default but requires a valid network account to access
		- **AppData** - Per user application data and settings are stored in a hidden user subfolder (i.e., cliff.moore\AppData). Each of these folders contains three subfolders. The Roaming folder contains machine-independent data that should follow the user's profile, such as custom dictionaries. The Local folder is specific to the computer itself and is never synchronized across the network. LocalLow is similar to the Local folder, but it has a lower data integrity level. Therefore it can be used, for example, by a web browser set to protected or safe mode
		- **Windows** - The majority of the files required for the Windows operating system are contained here
		- **System**, **System32**, **SysWOW64** - Contains all DLLs required for the core features of Windows and the Windows API. The operating system searches these folders any time a program asks to load a DLL without specifying an absolute path
		- **WinSxS** - The Windows Component Store contains a copy of all Windows components, updates, and service packs.
	- `dir` = `cd`
	- `tree`
		- ```tree c:\ /f | more```
		- use this to walk through tree output one page at a time
- ## File System
	- There are 5 types of Windows file systems:
		- **FAT12** - deprecated
		- **FAT16** - deprecated
		- **FAT32** - USB and SD cards (32 bits)
		- **NTFS** - default Windows file system
			- Permissions:
				- **Full Control** - Allows reading, writing, changing, deleting of files/folders.
				- **Modify** - Allows reading, writing, and deleting of files/folders.
				- **List** **Folder** **Contents** - Allows for viewing and listing folders and subfolders as well as executing files. Folders only inherit this permission.
				- **Read** **and** **Execute** - Allows for viewing and listing files and subfolders as well as executing files. Files and folders inherit this permission.
				- **Write** - Allows for adding files to folders and subfolders and writing to a file.
				- **Read** - Allows for viewing and listing of folders and subfolders and viewing a file's contents.
				- **Traverse** **Folder** - This allows or denies the ability to move through folders to reach other files or folders. For example, a user may not have permission to list the directory contents or view files in the documents or web apps directory in this example c:\users\bsmith\documents\webapps\backups\backup_02042020.zip but with Traverse Folder permissions applied, they can access the backup archive.
		- **exFAT** - default Linux file system
	- **Integrity Control Access Control List (icacls)** - gives fine level of granularity over NTFS file permissions in Windows from the command line.
		- `icacls c:\windows`
		- Possible inheritance:
			- `(CI)`: container inherit
			- `(OI)`: object inherit
			- `(IO)`: inherit only
			- `(NP)`: do not propagate inherit
			- `(I)`: permission inherited from parent container
		- Basic access permissions are as follows:
			- `F` : full access
			- `D` :  delete access
			- `N` :  no access
			- `M` :  modify access
			- `RX` :  read and execute access
			- `R` :  read-only access
			- `W` :  write-only access
		- We can add and remove permissions via the command line using `icacls`.
			- `icacls c:\users /grant joe:f`
				- grants joe full control over the directory
			* `icacls c:\users /remote joe`
				* revokes these permissions.
		* A full listing of `icacls` command-line arguments and detailed permission settings can be found [here](https://ss64.com/nt/icacls.html).
* ## NTFS vs. Share Permissions
	![[Pasted image 20231030111956.png]]
	* a virus, by definition, is software written with malicious intent and can be written for any OS.
		* infamous `EternalBlue` vulnerability still haunts unpatched Windows systems running `SMBv1` and often paves the way for ransomware to shut down organizations.
		* **Server Message Block protocol (SMB)** - used in Windows to connect shared resouces like files and printers. Used in all sizes of environments.
	* **NTFS permissions** and **share permissions** are often understood to be the same. They are not the same but often apply to the same shared resource. Let’s take a look at the individual permissions that can be set to secure/grant objects access to a network share hosted on a Windows OS running the NTFS file system.
		* **Share permissions**
			* `Full Control` - Users are permitted to perform all actions given by Change and Read permissions as well as change permissions for NTFS files and subfolders
			* `Change` - Users are permitted to read, edit, delete and add files and subfolders
			* `Read` - Users are allowed to view file & subfolder contents
		* **NTFS Basic permissions**
			* `Full Control` - Users are permitted to add, edit, move, delete files & folders as well as change NTFS permissions that apply to all allowed folders
			* `Modify` - Users are permitted or denied permissions to view and modify files and folders. This includes adding or deleting files
			* `Read & Execute` - Users are permitted or denied permissions to read the contents of files and execute programs
			* `List folder contents` - Users are permitted or denied permissions to view a listing of files and subfolders
			* `Read` - Users are permitted or denied permissions to read the contents of files
			* `Write` - Users are permitted or denied permissions to write changes to a file and add new files to a folder
			* `Special Permissions` - A variety of advanced permissions options:
				* `Full control` - Users are permitted or denied permissions to add, edit, move, delete files & folders as well as change NTFS permissions that apply to all permitted folders
				* `Traverse folder / execute file` - Users are permitted or denied permissions to access a subfolder within a directory structure even if the user is denied access to contents at the parent folder level. Users may also be permitted or denied permissions to execute programs
				* `List folder/read data` - Users are permitted or denied permissions to view files and folders contained in the parent folder. Users can also be permitted to open and view files
				* `Read attributes` - Users are permitted or denied permissions to view basic attributes of a file or folder. Examples of basic attributes: system, archive, read-only, and hidden
				* `Read extended attributes` - Users are permitted or denied permissions to view extended attributes of a file or folder. Attributes differ depending on the program
				* `Create files/write data` - Users are permitted or denied permissions to create files within a folder and make changes to a file
				* `Create folders/append data` - Users are permitted or denied permissions to create subfolders within a folder. Data can be added to files but pre-existing content cannot be overwritten
				* `Write attributes` -Users are permitted or denied to change file attributes. This permission does not grant access to creating files or folders
				* `Write extended attributes` - Users are permitted or denied permissions to change extended attributes on a file or folder. Attributes differ depending on the program
				* `Delete subfolders and files` - Users are permitted or denied permissions to delete subfolders and files. Parent folders will not be deleted
				* `Delete` - Users are permitted or denied permissions to delete parent folders, subfolders and files.
				* `Read permissions` - Users are permitted or denied permissions to read permissions of a folder
				* `Change permissions` - Users are permitted or denied permissions to change permissions of a file or folder
				* `Take ownership` - Users are permitted or denied permission to take ownership of a file or folder. The owner of a file has full permissions to change any permissions
		* Keep in mind that NTFS permissions apply to the system where the folder and files are hosted. Folders created in NTFS inherit permissions from parent folders by default.
	* **Creating the Folder**
		* Keep in mind that in most large enterprise environments, shares are created on a Storage Area Network (SAN), Network Attached Storage device (NAS), or a separate partition on drives accessed via a server operating system like Windows Server.
		* Advanced Sharing option
		* Similar to NTFS permissions, there is an `access control list` (`ACL`) for shared resources. We can consider this the SMB permissions list. Keep in mind that with shared resources, both the SMB and NTFS permissions lists apply to every resource that gets shared in Windows. The ACL contains `access control entries` (`ACEs`). Typically these ACEs are made up of `users` & `groups` (also called security principals) as they are a suitable mechanism for managing and tracking access to shared resources.
	*  A **server** is technically a software function used to service the requests of a client. In this case, the Pwnbox is our client, and the Windows 10 target box is our server.
	* **Using smbclient to Connect to the Share**
		* `smbclient -L IPaddressOfTarget -U htb-student`
		* the Windows Defender Firewall that could potentially be blocking access to the SMB share.
			*  The primary difference between a workgroup and a Windows Domain in terms of authentication, is with a workgroup the local SAM database is used and in a Windows Domain a centralized network-based database (Active Directory) is used.
			* In terms of the firewall blocking connections, this can be tested by completely deactivating each firewall profile in Windows or by enabling specific predefined inbound firewall rules in the `Windows Defender Firewall advanced security settings`.
			* Windows Defender Firewall Profiles:
				- `Public`
				- `Private`
				- `Domain`
			- It is a best practice to enable predefined rules or add custom exceptions rather than deactivating the firewall altogether.
			- Firewall rules on desktop systems can be centrally managed when joined to a Windows Domain environment through the use of **Group Policy**.
	- **Mounting to the Share**
		- `sudo mount -t cifs -o username=htb-student,password=Academy_WinFun! //ipaddoftarget/"Company Data" /home/user/Desktop/`
		- If the syntax is correct yet the command is still not working, `cifs-utils` may need to be installed. This can be done with the following command:
			- `sudo apt-get install cifs-utils`
		- Once we have successfully created the mount point on the Desktop on our Pwnbox, we should look at a couple of tools built-in to Windows that will allow us to track and monitor what we have done.
			- The `net share` command allows us to view all the shared folders on the system. Notice the share we created and also the C:\ drive.
				- `net share`
			- `Computer Management` is another tool we can use to identify and monitor shared resources on a Windows system.
			- `Event Viewer` is another good place to investigate actions completed on Windows.
- ## Windows Services & Processes
	- **Services**
		- Services allow for the creation and management of long-running processes.
		- Can be started automatically at system boot without user intervention.
		- Run in background after user logs out
		- Applications can be created to install as a service (e.g. network monitoring application installed on a server)
			- networking functions
			- system diagnostics
			- managing user credentials
			- controlling Windows updates
		- `services.msc` MMC add-in
			- Service Control Manager (SCM) system
			- It is also possible to query and manage services via the command line using `sc.exe` using PowerShell cmdlets such as `Get-Service`.
				- `Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl`
		- Service statuses can appear as **Running**, **Stopped**, or **Paused**, and they can be set to start **manually**, **automatically**, or on a **delay** at system boot. Also **Starting** or **Stopping** status
		- Three categories of services:
			- **Local Services**
			- **Network Services**
			- **System Services**
		- ==Misconfigurations around service permissions are a common privilege escalation vector on Windows systems.==
		- Some [critical system services](https://docs.microsoft.com/en-us/windows/win32/rstmgr/critical-system-services) cannot be stopped and restarted without a system restart. If we update any file or resource in use by one of these services, we must restart the system:
			- **smss.exe** - Session Manager SubSystem. Responsible for handling sessions on the system.
			- **csrss.exe** - Client Server Runtime Process. The user-mode portion of the Windows subsystem. 
			- **wininit.exe** - Starts the Wininit file .ini file that lists all of the changes to be made to Windows when the computer is restarted after installing a program.
			- **logonui.exe** - Used for facilitating user login into a PC
			- **lsass.exe** - The Local Security Authentication Server verifies the validity of user logons to a PC or server. It generates the process responsible for authenticating users for the Winlogon service.
			- **services.exe** - Manages the operation of starting and stopping services.
			- **winlogon.exe** - Responsible for handling the secure attention sequence, loading a user profile on logon, and locking the computer when a screensaver is running.
			- **System** - A background system process that runs the Windows kernel.
			- **svchost.exe with RPCSS** - Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." *Uses the Remote Procedure Call (RPC) Service (RPCSS).
			- **svchost.exe with Dcom/PnP** - Manages system services that run from dynamic-link libraries (files with the extension .dll) such as "Automatic Updates," "Windows Firewall," and "Plug and Play." *Uses the Distributed Component Object Model (DCOM) and Plug and Play (PnP) services.
			**- This [link](https://en.wikipedia.org/wiki/List_of_Microsoft_Windows_components#Services) has a list of Windows components, including key services.**
	* **Processes**
		* Run in the background on Windows systems
		* automatically or started by other installed applications
		* Processes associated with installed applications can often be terminated without causing a severe impact on the operating system.
			* Certain processes are critical and, if terminated, will stop certain components of the operating system from running properly:
				* Windows Logon Application,
				* System,
				* System Idle Process,
				* Windows Start-Up Application,
				* Client Server Runtime,
				* Windows Session Manager,
				* Service Host,
				* Local Security Authority Subsystem Service (LSASS) process.
					* `lsass.exe` is the process that is responsible for enforcing the security policies on Windows systems.
					* When a user attempts to log on to the system, this process verifies their log on attempt and creates access tokens based on the user's permission levels.
					* LSASS is also responsible for user account password changes.
					* All events associated with this process (logon/logoff attempts, etc.) are logged within the Windows Security Log.
					* ==LSASS is an extremely high-value target as several tools exist to extract both cleartext and hashed credentials stored in memory by this process.
		* **Sysinternals Tools** - a set of portable Windows applications that can be used to administer Windows systems. 
			* The tools can be either downloaded from the Microsoft website or by loading them directly from an internet-accessible file share by typing `\\live.sysinternals.com\tools` into a Windows Explorer window.
			* For example, we can run `procdump.exe` directly from this share without downloading it directly to disk.
				* `\\live.sysinternals.com\tools\procdump.exe -accepteula`
			* Includes **Process Explorer** (enchanced version of **Task Manager**) and **Process Monitor**, **TCPView** (monitor internet activity), **PSExec** (manage/connect to systems via the SMB protocol remotely)
			* **Task Manager**
				* ctrl + shift + Esc, pressing ctrl + alt + del and selecting `Task Manager`
			* **Process Explorer**
				* This tool can show which handles and DLL processes are loaded when a program runs. Process Explorer shows a list of currently running processes, and from there, we can see what handles the process has selected in one view or the DLLs and memory-swapped files that have been loaded in another view. We can also search within the tool to show which processes tie back to a specific handle or DLL. The tool can also be used to analyze parent-child process relationships to see what child processes are spawned by an application and help troubleshoot any issues such as orphaned processed that can be left behind when a process is terminated.
* ## Service Permissions
	* ==potential threat vectors that can be used to load malicious DLLs, execute applications without access to an admin account, escalate privileges and even maintain persistence.
		* service permissions misconfigurations
	* Install process includes assigning a specific service to run using the credentials and privileges of a designated user, which by default is set within the currently logged-on user context.
		* For example, if we are logged on as Bob on a server during DHCP install, then that service will be configured to run as Bob unless specified otherwise.
			* Well, what if Bob leaves the organization or gets fired? The typical business practice would be to disable Bob’s account as part of his exit process. In this case, what would happen to DHCP and other services running using Bob’s account? Those services would fail to start.
		* **It is highly recommended to create an individual user account to run critical network services. These are referred to as service accounts.**
	* **Examining Services using service.msc**
		* view and manage just about every detail regarding all services.
		* Most services run with LocalSystem privileges by default which is the highest level of access allowed on an individual Windows OS.
		* It is a good practice to identify applications that can run with the least privileges possible to align with the principle of least privilege. [Here is one breakdown of the principle of least privilege](https://www.cloudflare.com/learning/access-management/principle-of-least-privilege/)
		* Notable built-in service accounts in Windows:
			- **LocalService**
			- **NetworkService**  
			- **LocalSystem**
		- The recovery tab allows steps to be configured should a service fail. Notice how this service can be set to run a program after the first failure. ==This is yet another vector that an attacker could use to run malicious programs by utilizing a legitimate service.
	- **Examining services using sc**
		- `sc qc wuauserv`
			- query the service.
			- To query a service on a device over the network:
				- `sc //hostname or ip of box query ServiceName`
			- To start and stop services
				- `sc stop wuauserv`
				- To perform this action with elevated permissions:
					- `sc config wuauserv binPath=C"\Winbows\Perfectlylegitprogram.exe`
					- `sc qc wuauserv`
			- Another helpful way we can examine service permissions using `sc` is through the `sdshow` command.
				- `sc sdshow wuauserv`
				- Output
				- `D:(A;;CCLCSWRPLORC;;;AU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)`
					- Security descriptors identify the object’s owner and a primary group containing a `Discretionary Access Control List` (`DACL`) and a `System Access Control List` (`SACL`).
					- This amalgamation of characters crunched together and delimited by opened and closed parentheses is in a format known as the `Security Descriptor Definition Language` (`SDDL`).
					- This entire security descriptor associated with the `Windows Update` (`wuauserv`) service has three sets of access control entries because there are three different security principals. Each security principal has specific permissions applied.
					- We may be tempted to read from left to right because that is how the English language is typically written, but it can be much different when interacting with computers. Read the entire security descriptor for the `Windows Update` (`wuauserv`) service in this order starting with the first letter and set of parentheses:
						`D: (A;;CCLCSWRPLORC;;;AU)`
						1. D: - the proceeding characters are DACL permissions
						2. AU: - defines the security principal Authenticated Users
						3. A;; - access is allowed
						4. CC - SERVICE_QUERY_CONFIG is the full name, and it is a query to the service control manager (SCM) for the service configuration
						5. LC - SERVICE_QUERY_STATUS is the full name, and it is a query to the service control manager (SCM) for the current status of the service
						6. SW - SERVICE_ENUMERATE_DEPENDENTS is the full name, and it will enumerate a list of dependent services
						7. RP - SERVICE_START is the full name, and it will start the service
						8. LO - SERVICE_INTERROGATE is the full name, and it will query the service for its current status
						9. RC - READ_CONTROL is the full name, and it will query the security descriptor of the service
	* **Examine service permissions using PowerShell**
		* `Get-Acl -Path HKLM:\System\CurrentControlSet\Services\wuauserv | Format-List`
		* easier to read format than the `sc` command method.
* ## Windows Sessions
	* **Interactive**
		* local logon session, normal use case
		* An interactive logon can be initiated by logging directly into the system, by requesting a secondary logon session using the `runas` command via the command line, or through a Remote Desktop connection.
	* **Non-interactive**
		* do not require login credentials, generally used by the Windows operating system to automatically start services and applications without requiring user interaction.
		* These accounts have no password associated with them and are usually used to start services when the system boots or to run scheduled tasks.
		* 3 types:
			* **Local System Account** - Also known as the `NT AUTHORITY\SYSTEM` account, this is the **most powerful account** in Windows systems. It is used for a variety of OS-related tasks, such as starting Windows services. This account is more powerful than accounts in the local administrators group.
			* **Local Service Account** - Known as the `NT AUTHORITY\LocalService` account, this is a less privileged version of the SYSTEM account and has similar privileges to a local user account. It is granted limited functionality and can start some services.
			* **Network Service Account** - This is known as the `NT AUTHORITY\NetworkService` account and is similar to a standard domain user account. It has similar privileges to the Local Service Account on the local machine. It can establish authenticated sessions for certain network services.
* ## Interacting with the Windows Operating System
	* **GUI**
	* **RDP** (3389)
	* **Windows Command Line** ([Windows Command Reference](https://download.microsoft.com/download/5/8/9/58911986-D4AD-4695-BF63-F734CD4DF8F2/ws-commands.pdf) )
		* **CMD** (cmd.exe) - `/?` for help
		* **PowerShell** - built on top of .NET framework, similar to cmd
			*  [cmdlets](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/cmdlet-overview?view=powershell-7) - are small single-function tools built into the shell.
				* **Cmdlets** are in the form of `Verb-Noun`. For example, the command `Get-ChildItem` can be used to list our current directory.
				* `Get-ChildItem -Path C:\Users\Administrator\Downloads -Recurse.`
				* **alias**. For example, the aliases for the cmdlet `Set-Location`, to change directories, is either `cd` or `sl`.
					* `Get-Alias`
					* to create our own aliases
						* `New-Alias -Name "Show-Files" Get-ChildItem`
					* help
						* `Get-Help <cmdlet-name> -Online`
	* **Running Scripts**
		* **PowerShell ISE** (Integrated Scripting Environment) allows users to write PowerShell scripts
			* can autocomplete/lookup commands
			* to run
				* `.\PowerView.ps1;Get-LocalGroup | fl`
			* One common way to work with a script in PowerShell is to import it so that all functions are then available within our current PowerShell console session: `Import-Module .\PowerView.ps1`.
	* **Execution Policy**
		* a security feature that attempts to prevent the execution of malicious scripts. Possible policies are:
			* `AllSigned`|All scripts can run, but a trusted publisher must sign scripts and configuration files. This includes both remote and local scripts. We receive a prompt before running scripts signed by publishers that we have not yet listed as either trusted or untrusted.
			* `Bypass` - No scripts or configuration files are blocked, and the user receives no warnings or prompts.
			* `Default` - This sets the default execution policy, `Restricted` for Windows desktop machines and `RemoteSigned` for Windows servers.
			* `RemoteSigned` - Scripts can run but requires a digital signature on scripts that are downloaded from the internet. Digital signatures are not required for scripts that are written locally.
			* `Restricted` - This allows individual commands but does not allow scripts to be run. All script file types, including configuration files (`.ps1xml`), module script files (`.psm1`), and PowerShell profiles (`.ps1`) are blocked.
			* `Undefined` - No execution policy is set for the current scope. If the execution policy for ALL scopes is set to undefined, then the default execution policy of `Restricted` will be used.
			* `Unrestricted` - This is the default execution policy for non-Windows computers, and it cannot be changed. This policy allows for unsigned scripts to be run but warns the user before running scripts that are not from the local intranet zone.
		* to get the current execution policy for all scopes
			* `Get-ExecutionPolicy -List`
* ## Windows Management Instrumentation (WMI)
	* a subsystem of PowerShell that provides sys admins tools for monitoring.
	* Consolidates device and application management across corporate networks. 
	* It is made up of the following components:
		* **WMI service** - The Windows Management Instrumentation process, which runs automatically at boot and acts as an intermediary between WMI providers, the WMI repository, and managing applications.
		* **Managed objects** - Any logical or physical components that can be managed by WMI.
		* **WMI providers** - Objects that monitor events/data related to a specific object.
		* **Classes** -These are used by the WMI providers to pass data to the WMI service.
		* **Methods** - These are attached to classes and allow actions to be performed. For example, methods can be used to start/stop processes on remote machines.
		* **WMI repository** - A database that stores all static data related to WMI.
		* **CIM Object Manager** - The system that requests data from WMI providers and returns it to the application requesting it.
		* **WMI API** - Enables applications to access the WMI infrastructure.
		* **WMI Consumer** - Sends queries to objects via the CIM Object Manager.
	* Some of the uses for WMI are:
		- Status information for local/remote systems
		- Configuring security settings on remote machines/applications
		- Setting and changing user and group permissions
		- Setting/modifying system properties
		- Code execution
		- Scheduling processes
		- Setting up logging
	- These tasks can all be performed using a combination of **PowerShell** and the **WMI Command-Line Interface** (**WMIC**).
		- `wmic`
		- to list information about the OS
			- `wmic os list brief`
	- WMIC uses aliases and associated verbs, adverbs, and switches.
		-  An in-depth listing of verbs, switches, and adverbs is available [here](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmic)
	- WMI can be used with PowerShell by using the `Get-WmiObject` [module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-wmiobject?view=powershell-5.1). This module is used to get instances of WMI classes or information about available classes. This module can be used against local or remote machines.
		- `Get-WmiObject -Class Win32_OperatingSystem | select SystemDirectory,BuildNumber,SerialNumber,Version | ft`
	- `Invoke-WmiMethod` [module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/invoke-wmimethod?view=powershell-5.1), which is used to call the methods of WMI objects. For example, renaming a file:
		- `Invoke-WmiMethod -Path "CIM_DataFile.Name='C:\users\public\spns.csv'" -Name Rename -ArgumentList "C:\Users\Public\kerberoasted_users.csv"`
- ## Microsoft Management Console (MMC)
	- can be used to group snap-ins, or administrative tools, to manage hardware, software, and network components within a Windows host.
	- also can be used to create custom tools.
	- `mmc`
- ## Windows Subsystem for Linux (WSL)
	- a feature that allows Linux binaries to be run natively on Windows 10 and Windows Server 2019.
	- installed by running PowerShell command
		- `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux`
		- `wsl.exe --list --online
		- `wsl.exe --install <distro>`
- ## Desktop Experience vs. Server Core
	- [Windows Server Core](https://docs.microsoft.com/en-us/windows-server/administration/server-core/what-is-server-core)
	- a minimalistic Server environment only containing key Server functionality.
		- lower management requirements
		- smaller attack surface
		- less disk space and memory
	- choose one during install, neither can be rolled back
	- setup Server Core
		- `Sconfig`
- ## Windows Security
	- These are units in the system that can be authorized or authenticated for a particular action. These units include:
		- users,
		- computers on the network,
		- threads,
		- processes.
	* **Security Identifier (SID)**
		* each security principle on the system, has a unique SID.
		* automatically generated
		* view user SID
			* `whoami /user`
			* `S-1-5-21-674899381-4069889467-2080702030-1002`
		* pattern
			* `(SID)-(revision level)-(identifier-authority)-(subauthority1)-(subauthority2)-(etc)`
			* S, SID - Identifies the string as a SID.
			* 1, Revision Level - To date, this has never changed and has always been `1`.
			* 5, Identifier-authority - A 48-bit string that identifies the authority (the computer or network) that created the SID.
			* 21, Subauthority1 - This is a variable number that identifies the user's relation or group described by the SID to the authority that created it. It tells us in what order this authority created the user's account.
			* 674899381-4069889467-2080702030, Subauthority2 - Tells us which computer (or domain) created the number
			* 1002, Subauthority3 - The RID that distinguishes one account from another. Tells us whether this user is a normal user, a guest, an administrator, or part of some other group
	* **Security Accounts Manager (SAM) and Access Control Entries (ACE)**
		* **SAM** grants rights to a network to execute specific processes
		* **ACE** manages the access rights themselves in **Access Control Lists (ACL)**
			* ACL contains the ACEs that define which users, groups, or processes have access to a file or to execute a process, for example.
			* The permissions to access a securable object are given by the security descriptor, classified into two types of ACLs: 
				* `Discretionary Access Control List (DACL)` 
				* `System Access Control List (SACL)`
			* An integral part of this process is access tokens, validated by the **Local Security Authority (LSA)**. 
				* Access tokens contain other security-relevant information. 
	* **User Account Control (UAC)**
		* a security feature in Windows that prevents malware from running or manipulating processes that could damage the computer or its contents
			* Admin Approval Mode
				* designed to prevent unwanted software from being installed without admin's knowledge or to prevent system-wide changes from being made
				* consent prompt I see all the time when installing applications
		* ![[Pasted image 20231101103150.png]]
	* **Registry**
		* a hierarchical database in Windows critical for the OS.
		* stores low-level settings for the Windows OS and applications
		* `regedit`
		* The tree-structure consists of main folders (root keys) in which subfolders (subkeys) with their entries/files (values) are located. There are 11 different types of values that can be entered in a subkey:
			* **REG_BINARY** - Binary data in any form.
			* **REG_DWORD** - A 32-bit number.
			* **REG_DWORD_LITTLE_ENDIAN** - A 32-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_DWORD in the Windows header files.
			* **REG_DWORD_BIG_ENDIAN** - A 32-bit number in big-endian format. Some UNIX systems support big-endian architectures
			* **REG_EXPAND_SZ** - A null-terminated string that contains unexpanded references to environment variables (for example, "%PATH%"). It will be a Unicode or ANSI string depending on whether you use the Unicode or ANSI functions. To expand the environment variable references, use the [**ExpandEnvironmentStrings**](https://docs.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsa) function.
			* **REG_LINK** - A null-terminated Unicode string containing the target path of a symbolic link created by calling the [**RegCreateKeyEx**](https://docs.microsoft.com/en-us/windows/desktop/api/Winreg/nf-winreg-regcreatekeyexa) function with REG_OPTION_CREATE_LINK.
			* **REG_MULTI_SZ** - A sequence of null-terminated strings, terminated by an empty string (\0). The following is an example: _String1_\0_String2_\0_String3_\0_LastString_\0\0 The first \0 terminates the first string, the second to the last \0 terminates the last string, and the final \0 terminates the sequence. Note that the final terminator must be factored into the length of the string.
			* **REG_NONE** - No defined value type.
			* **REG_QWORD** - A 64-bit number.
			* **REG_QWORD_LITTLE_ENDIAN** - A 64-bit number in little-endian format. Windows is designed to run on little-endian computer architectures. Therefore, this value is defined as REG_QWORD in the Windows header files.
			* **REG_SZ** - A null-terminated string. This will be either a Unicode or an ANSI string, depending on whether you use the Unicode or ANSI functions.
			* Source: [https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types)
		* root keys all start with `HKEY`
		* `HKEY-LOCAL-MACHINE` is abbreviated to `HKLM`
			* contains all settings relevant to the local system
				* `SAM`
				* `SECURITY`
				* `SYSTEM`
				* `SOFTWARE`
				* `HARDWARE`
				* `BCD`
		* The entire system registry is stored in several files on the operating system. You can find these under `C:\Windows\System32\Config\`.
			* `ls C:\Windows\System32\Config\`
		* The user-specific registry hive (HKCU) is stored in the user folder (i.e., `C:\Users\<USERNAME>\Ntuser.dat`).
			* `gci -Hidden`
	* **Run and RunOnce Registry Keys**
		* There are also so-called registry hives, which contain a logical group of keys, subkeys, and values to support software and files loaded into memory when the operating system is started or a user logs in. These hives are useful for maintaining access to the system. These are called [Run and RunOnce registry keys](https://docs.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys).
		* The Windows registry includes the following four keys:
			* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
			* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
			* `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce`
			* `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
		* Example of the `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run` key while logged in to a system.
			* `reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run`
		* Example of the `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` showing applications running under the current user while logged in to a system.
			* `reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
	* **Application Whitelisting**
		* a list of approved software applications or executables allowed to be present and run on a system.
		* implement in audit mode initiallty
		* **Blacklisting**, in contrast, specifies a list of harmful or disallowed software/applications to block, and all others are allowed to run/be installed. 
		* **Whitelisting** is based on a "**zero trust**" principle in which all software/applications are deemed "bad" except for those specifically allowed.
		* Whitelisting is recommended by organizations such as [NIST](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-167.pdf), especially in high-security environments.
	* **AppLocker**
		* Microsoft's application whitelisting solution and was first introduced in Windows 7.
		* It allows for creating rules based on file attributes such as the publisher's name (which can be derived from the digital signature), product name, file name, and version.
		* Rules can also be set up based on file paths and hashes.
		* Rules can be applied to either security groups or individual users, based on the business need.
		* AppLocker can be deployed in audit mode first to test the impact before enforcing all of the rules.
	* **Local Group Policy**
		* allows administrators to set, configure, and adjust a variety of settings.
		* In a domain environment, group policies are pushed down from a **Domain Controller** onto all domain-joined machines that **Group Policy objects (GPOs)** are linked to. These settings can also be defined on individual machines using Local Group Policy.
		* Group Policy can be configured locally, in both domain environments and non-domain environments. 
			* Tweak certain graphical and network settings that are otherwise not accessible via the Control Panel
			* Lock down an individual computer policy with stringent security settings, such as only allowing certain programs to be installed/run or enforcing strict user account password requirements.
		* To open the Local Group Policy Editor
			* `gpedit.msc`
			* Two categories under Local Computer Policy:
				* `Computer Configuration`
				* `User Configuration`
		* To enable **Credential Guard** - a feature in Windows 10 that protects against credential theft attacks by isolating the operating system's LSA process.
			* enable `Turn On Virtualization Based Security` in `gpedit.msc`
		* Also, we can enable fine-tuned account auditing and configure **AppLocker** from the Local Group Policy Editor
	* **Windows Defender Antivirus**
		* aka Defender
		* free with Windows OS
			* Real-time protection, which protects the device from known threats in real-time
				* can be tweaked to add files, folders, and memory areas to controlled folder access to prevent unauthorized changes
				* can also add files or folders to an exclusion list, so they are not scanned. (e.g. excluding a folder of tools used for penetration testing from scanning as they will be flagged malicious and quarantined or removed from the system)
				* Controlled folder access is Defender's built-in Ransomware protection.
			* Cloud-delivered protection, which works in conjunction with automatic sample submission to upload suspicious files for analysis
			* Tamper Protection, which prevents security settings from being changed through the Registry, PowerShell cmdlets, or group policy.
		* Managed from the Security Center
* ## Skills Assessment
	* Inlanefreight recently had an incident where a disgruntled employee in marketing accessed an internally hosted HR share and deleted several confidential files & folders. Thankfully, the IT team had good backups and restored all of the deleted data. There are now concerns that this disgruntled employee was able to access the HR share in the first place. After performing a security assessment, you have found that the IT team may not fully understand how permissions work in Windows. You are conducting training and a demonstration to show the department good security practices with file sharing in a Windows environment as well as viewing services from the command line to check for any potential tampering.
	* Note: It is important that each step is completed in the order they are presented. Starting with step 1 and working your way through step 8, including all associated specifications with each step. Please know that each step is designed to give you the opportunity to apply the skills & concepts taught throughout this module. Take your time, have fun and feel free to reach out if you get stuck.
	* In this demonstration, you are:
		 1. Creating a shared folder called Company Data
			 - right click
		 2. Creating a subfolder called HR inside of the Company Data folder
			 - right click
		 3. Creating a user called Jim
			- `Uncheck: User must change password at logon`
			- Computer Management > Local Users and Groups
		 4. Creating a security group called HR
			 - Computer Management > Local Users and Groups
		 5. Adding Jim to the HR security group
			  - Computer Management > Local Users and Groups
		 6. Adding the HR security group to the shared Company Data folder and NTFS permissions list
			 - right click > Advanced Sharing/Security tab, advanced
			- `Remove the default group that is present`
			- `Share Permissions: Allow Change & Read`
			- `Disable Inheritance before issuing specific NTFS permissions`
			- `NTFS permissions: Modify, Read & Execute, List folder contents, Read, Write`
		 7. Adding the HR security group to the NTFS permissions list of the HR subfolder
			- `Remove the default group that is present`
			- `Disable Inheritance before issuing specific NTFS permissions`
			- `NTFS permissions: Modify, Read & Execute, List folder contents, Read, and Write`
		 8. Using PowerShell to list details about a service
	* **Questions/Answers:**
		* What is the name of the group that is present in the Company Data Share Permissions ACL by default?
			* Everyone
		* What is the name of the tab that allows you to configure NTFS permissions?
			* Security
		* What is the name of the service associated with Windows Update?
			* type cmd `Get-Service`
			* wuauserv
		* List the SID associated with the user account Jim you created.
			* type cmd `Get-WmiObject Win32_UserAccount | Select-Object Name, SID`
			*  S-1-5-21-2614195641-1726409526-3792725429-1006
		* List the SID associated with the HR security group you created.
			* type cmd `Get-WmiObject Win32_Group | Select-Object Name, SID`
			* S-1-5-21-2614195641-1726409526-3792725429-1007