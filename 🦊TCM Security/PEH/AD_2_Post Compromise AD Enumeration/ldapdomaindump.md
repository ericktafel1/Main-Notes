* seen in IPv6 attack (html report)
* Use this tool in network if no IPv6 and we have access to a user account

1st - Make a directory and cd to it in kali
	`mkdir marvel.local`
	`cd marvel.local`
2nd - run `ldapdomaindump` to DC user domain user and password (must be in directory)
		(wont work without python3)
	`sudo ldapdomaindump ldaps://192.168.95.132 -u 'MARVEL\fcastle' -p Password1 `
	
May need to update python
	`sudo apt-get update`
	`sudo apt-get install python3 python3-pip`
and ldap3
	`sudo pip3 install ldap3 ldapdomaindump`
Now must add python3 to command
	
```
┌─(~/Documents/PEH/marvel.local)──────────────────────────────────────────────────────────────────────(kali@kali:pts/4)─┐
└─(16:10:09)──> sudo python3 -m ldapdomaindump ldaps://192.168.95.132 -u 'MARVEL\fcastle' -p Password1

[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
┌─(~/Documents/PEH/marvel.local)──────────────────────────────────────────────────────────────────────(kali@kali:pts/4)─┐
└─(16:10:17)──> ll                                                                                        ──(Fri,Jun28)─┘
total 212K
-rw-r--r-- 1 root root 2.3K Jun 28 16:10 domain_computers_by_os.html
-rw-r--r-- 1 root root  772 Jun 28 16:10 domain_computers.grep
-rw-r--r-- 1 root root 1.9K Jun 28 16:10 domain_computers.html
-rw-r--r-- 1 root root  12K Jun 28 16:10 domain_computers.json
-rw-r--r-- 1 root root  10K Jun 28 16:10 domain_groups.grep
-rw-r--r-- 1 root root  17K Jun 28 16:10 domain_groups.html
-rw-r--r-- 1 root root  79K Jun 28 16:10 domain_groups.json
-rw-r--r-- 1 root root  258 Jun 28 16:10 domain_policy.grep
-rw-r--r-- 1 root root 1.2K Jun 28 16:10 domain_policy.html
-rw-r--r-- 1 root root 5.2K Jun 28 16:10 domain_policy.json
-rw-r--r-- 1 root root   71 Jun 28 16:10 domain_trusts.grep
-rw-r--r-- 1 root root  828 Jun 28 16:10 domain_trusts.html
-rw-r--r-- 1 root root    2 Jun 28 16:10 domain_trusts.json
-rw-r--r-- 1 root root  15K Jun 28 16:10 domain_users_by_group.html
-rw-r--r-- 1 root root 2.1K Jun 28 16:10 domain_users.grep
-rw-r--r-- 1 root root 6.4K Jun 28 16:10 domain_users.html
-rw-r--r-- 1 root root  19K Jun 28 16:10 domain_users.json
```

To view the dump:

`firefox domain_users_by_group.html`

**High Value Targets:**
- Domain Admins
- Enterprise Admins
- Domain Users (check description)
- Domain Computers
- Domain Trusts
- Domain Policy

