#sudo #ps #uname #lscpu #whoami #arp #grep #locate #Find #ssh #/etc/passwd #/etc/shadow 

[linuxprivescarena](https://tryhackme.com/room/linuxprivescarena)

#ssh issue, add the following to `/etc/ssh/ssh_config`
	`HostKeyAlgorithms ssh-rsa`
	`PubkeyAcceptedKeyTypes ssh-rsa`

---
# System Enumeration

- What kernel & Linux distribution
	- `uname -a`
	- `cat /proc/version`
	- `cat /etc/issue`
- CPU information / Architecture (x64)
	- `lscpu`
- What services are running?
	- `ps aux`
	- `ps aux | grep root`

# User Enumeration

- About the user
	- `whoami`
	- `id`
- User permissions
	- `sudo -l`
- View files
	- `cat /etc/passwd`
	- `cat /etc/passwd | cut -d : -f 1`
	- `cat /etc/shadow`
	- `cat /etc/group`
- View commands typed
	- `history`
- Sudo switch users
	- `sudo su -`

# Network Enumeration

- `ifconfig`
- `ip a`
- `ip route`
- `arp -a`
- `ip neigh`
- `netstat -ano`

# Password Hunting

- Pull out the word "password" from files and color red
	- `grep --color=auto -rnw '/' -ie "PASSWORD=" --color=always 2> /dev/null`
	- `grep --color=auto -rnw '/' -ie "PASS=" --color=always 2> /dev/null`
	- `grep --color=auto -rnw '/' -ie "PWD=" --color=always 2> /dev/null`
- Look for phrase "password" as file name
	- `locate password | more`
	- `locate pass | more`
	- `locate pwd | more`
- Hunt SSH keys #ssh 
	- `find / -name authorized_keys 2> /dev/null`
	- `find / -name id_rsa 2> /dev/null`