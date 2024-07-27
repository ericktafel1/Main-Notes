1. Start mitm6 OR Responder
2. Crack hash/pass attacks(crackmapexec) to gain a shell
	1. secretsdump
	2. Continuously enumerate user accounts for pivoting/lateral movement
3. PowerView OR BloodHound
4. Kerberoasting/Mimikatz/Token Impersonation
	1. Dump NTDS.dit
	2. Golden Tickets
5. RESPRAY hashes & passwords with CME
6. MIMIKATZ on compromised machines (must run as administrator)
7. Try RDP if thats open
8. Go back to step 2 and repeat
9. 