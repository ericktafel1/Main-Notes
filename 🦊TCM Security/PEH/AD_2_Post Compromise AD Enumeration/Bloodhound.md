install latest

`sudo pip install bloodhound`

Run `neo4j`. Required console to run Bloodhound
May require install... `sudo apt-get install neo4j`

`sudo neo4j console`
- shows server address via "Bolt enabled on localhost:7687."
- clickable link to neo4j browser shown also in output.. click it
	- login with neo4j:neo4j
	- changed password to neo4j1

Run Bloodhound.. may need to install `sudo apt-get install bloodhound` and do `sudo pip3 install bloodhound`
`sudo bloodhound`
- now go back to browser
- need to run ingestor, back to terminal
`mkdir bloodhound && cd bloodhound`
- now run ingestor
`sudo bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns 192.168.95.132 -c all`


```
┌─(~/Documents/PEH/bloodhound)────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(16:26:42)──> sudo bloodhound-python -d MARVEL.local -u fcastle -p Password1 -ns 192.168.95.132 -c all 
INFO: Found AD domain: marvel.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (hydra-dc.marvel.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: hydra-dc.marvel.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: hydra-dc.marvel.local
INFO: Found 9 users
INFO: Found 52 groups
INFO: Found 3 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: SPIDERMAN.MARVEL.local
INFO: Querying computer: THEPUNISHER.MARVEL.local
INFO: Querying computer: HYDRA-DC.MARVEL.local
INFO: Done in 00M 00S
```

saved to current dir

```
┌─(~/Documents/PEH/bloodhound)────────────────────────────────────────────────────────────────────────(kali@kali:pts/3)─┐
└─(16:26:45)──> ls                                                                                        ──(Fri,Jun28)─┘
20240628162644_computers.json   20240628162644_domains.json  20240628162644_groups.json  20240628162644_users.json
20240628162644_containers.json  20240628162644_gpos.json     20240628162644_ous.json
```

In Bloodhound app, upload data on right hand side
Shows graphical representation of environment, permissions, domains, etc. everything.
- **Kerberoastable users**
- Good for graphical, use ldapdomaindump for details, bloodhound for marking owned and determining paths to attack (roast)
