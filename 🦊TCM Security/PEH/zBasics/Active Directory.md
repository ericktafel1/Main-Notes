* 95% of Fortune 1000 companies
* Can be non-Windows
* Uses Kerberos to authenticate, non-Windows uses RADIUS or LDAP
* MANY VULNERABILITIES are features not bugs, known vulnerabilities
	* Know these for exam and their remediations


*Can also see HTB Fundamentals Active Directory notes for more detail*

# AD Components

* Physical AD Components
	* Data Store (DS)
		* Continas **Ntds.dit** file
	* Domain Controller (DC)
		* Head honcho
	* Global Catalog Server
	* Read-Only Domain Controller (RODC)
* Logical AD Components
	* Partitions
	* Schema
		* Rulebook/blueprint to define types of objects that can be stored within the Directory
		* Class vs. Attribute Objects (user/computer/printer vs. display name)
	* Domains
		* Boundary
		* lives within DC
		* Administrative boundary for applying policies to groups of objects.
	* Domain trees
		* More than one domain, hierarchy (parent and children)
	* Forests
		* Collection of trees ^
		* Share schema, config partition, etc.
		* Share Enterprise admins and schema admins
			* domain admin in forest is not necessarily an enterprise admin
	* Sites
	* Organization units (OUs)
		* Containers
			* Users, groups, computers, other OUs
		* Can apply policies/set permissions to OUs
	* Trusts
		* Directional
			* flows from trusting domain to a trusted domain
		* Transitive
			* extended beyond a two-domain trust to include other trusts, tree to tree/ forest to forest
		* all domains in a forest trust all other domains in the forest
	* Objects
		* live within an OU






	- AD Boxes to Pwn
		- [Active](https://youtu.be/jUc1J31DNdw)
		- [Resolute](https://www.youtube.com/watch?v=8KJebvmd1Fk)
		- [Forest](https://youtu.be/H9FcE_FMZio)
		- [Cascade](https://youtu.be/mr-fsVLoQGw)
	- AD Skill Paths
		- [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap)
		- [Active Directory PowerView](https://academy.hackthebox.com/course/preview/active-directory-powerview)
		- [Active Directory BloodHound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound)