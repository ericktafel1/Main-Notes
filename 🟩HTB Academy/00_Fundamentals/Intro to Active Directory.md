* ## Why Active Directory?
	* Active Directory (AD) is **a directory service for Windows** network environments.
	* It is a distributed, **hierarchical** **structure** that allows for centralized management of an organization's resources, including users, computers, groups, network devices, file shares, group policies, devices, and trusts.
	* AD provides **authentication** and **authorization** functions within a Windows domain environment.
	* It has come under increasing attack in recent years. It is designed to be **backward-compatible**, and many features are arguably not "secure by default," and it can be easily misconfigured. This weakness can be leveraged to move laterally and vertically within a network and gain unauthorized access
	* AD is essentially a sizeable read-only database accessible to all users within the domain, regardless of their privilege level. A basic AD user account with no added privileges can enumerate most objects within AD. This fact makes it extremely important to properly secure an AD implementation because ANY user account, regardless of their privilege level, can be used to enumerate the domain and hunt for misconfigurations and flaws thoroughly.
	* Also, multiple attacks can be performed with only a standard domain user account, showing the importance of a defense-in-depth strategy and careful planning focusing on security and hardening AD, network segmentation, and least privilege. One example is the [noPac](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware) attack that was first released in December of 2021.
	* Active Directory makes information easy to find and use for administrators and users. AD is highly scalable, supports millions of objects per domain, and allows the creation of additional domains as an organization grows.
	* ![[Pasted image 20231205111504.png]]
	*  The [Conti Ransomware](https://www.cisa.gov/sites/default/files/publications/AA21-265A-Conti_Ransomware_TLP_WHITE.pdf) which has been used in more than 400 attacks around the world has been shown to leverage recent critical Active Directory flaws such as [PrintNightmare (CVE-2021-34527)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [Zerologon (CVE-2020-1472)](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472) to escalate privileges and move laterally in a target network.
	* **History of Active Directory**
		* LDAP, the foundation of Active Directory, was first introduced in [RFCs](https://en.wikipedia.org/wiki/Request_for_Comments) as early as 1971. Active Directory was predated by the [X.500](https://en.wikipedia.org/wiki/X.500) organizational unit concept, which was the earliest version of all directory systems created by Novell and Lotus and released in 1993 as [Novell Directory Services](https://en.wikipedia.org/wiki/NetIQ_eDirectory).
		* Active Directory was first introduced in the mid-'90s but did not become part of the Windows operating system until the release of Windows Server 2000
			* Microsoft first attempted to provide directory services in 1990 with the release of Windows NT 3.0. This operating system combined features of the [LAN Manager](https://en.wikipedia.org/wiki/LAN_Manager) protocol and the [OS/2](https://en.wikipedia.org/wiki/OS/2) operating systems, which Microsoft created initially along with IBM lead by [Ed Iacobucci](https://en.wikipedia.org/wiki/Ed_Iacobucci) who also led the design of [IBM DOS](https://en.wikipedia.org/wiki/IBM_PC_DOS) and later co-founded Citrix Systems. The NT operating system evolved throughout the 90s, adapting protocols such as LDAP and Kerberos with Microsoft's proprietary elements. The first beta release of Active Directory was in 1997.
		* The release of Windows Server 2003 saw extended functionality and improved administration and added the `Forest` feature, which allows sysadmins to create "containers" of separate domains, users, computers, and other objects all under the same umbrella. [Active Directory Federation Services (ADFS)](https://en.wikipedia.org/wiki/Active_Directory_Federation_Services) was introduced in Server 2008 to provide Single Sign-On (SSO) to systems and applications for users on Windows Server operating systems. ADFS made it simpler and more streamlined for users to sign into applications and systems, not on their same LAN.
			* ADFS enables users to access applications across organizational boundaries using a single set of credentials. ADFS uses the [claims-based](https://en.wikipedia.org/wiki/Claims-based_identity) Access Control Authorization model, which attempts to ensure security across applications by identifying users by a set of claims related to their identity, which are packaged into a security token by the identity provider.
		* The release of Server 2016 brought even more changes to Active Directory, such as the ability to migrate AD environments to the cloud and additional security enhancements such as user access monitoring and [Group Managed Service Accounts (gMSA)](https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/service-accounts-group-managed). gMSA offers a more secure way to run specific automated tasks, applications, and services and is often a recommended mitigation against the infamous Kerberoasting attack.
			* 2016 saw a more significant push towards the cloud with the release of Azure AD Connect, which was designed as a single sign-on method for users being migrated to the Microsoft Office 365 environment.
		* Active Directory has suffered from various misconfigurations from 2000 to the present day. New vulnerabilities are discovered regularly that affect Active Directory and other technologies that interface with AD, such as Microsoft Exchange. As security researchers continue to uncover new flaws, organizations that run Active Directory need to remain on top of patching and implementing fixes. As penetration testers, we are tasked with finding these flaws for our clients before attackers.
* ## Active Directory Research Over the Years
	* As we can see from the timeline below, critical flaws are continuously being discovered. The noPac attack was discovered in December of 2021 and is the most recent critical AD attack that has been discovered as of January 2022.
		* **2013** - The [Responder](https://github.com/SpiderLabs/Responder/commits/master?after=c02c74853298ea52a2bfaa4d250c3898886a44ac+174&branch=master) tool was released by Laurent Gaffie. Responder is a tool used for poisoning LLMNR, NBT-NS, and MDNS on an Active Directory network. It can be used to obtain password hashes and also perform SMB Relay attacks (when combined with other tools) to move laterally and vertically in an AD environment. It has evolved considerably over the years and is still actively supported (with new features added) as of January 2022.
		* **2014** - Veil-PowerView first [released](https://github.com/darkoperator/Veil-PowerView/commit/fdfd47c0a1e06e529bf31c93da7caed3479d08e1#diff-1695122ff2b5844b625f6d05c9274ce0a8b75b9b7cde84386df07e24ae98181b). This project later became part of the [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) framework as the (no longer supported) [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) AD recon tool. The Kerberoasting attack was first presented at a conference by [Tim Medin](https://twitter.com/timmedin) at SANS Hackfest 2014.
		* **2015** - 2015 saw the release of some of the most impactful Active Directory tools of all time. The [PowerShell Empire framework](https://github.com/EmpireProject/Empire) was released. [PowerView 2.0](http://www.harmj0y.net/blog/redteaming/powerview-2-0/) released as part of the (now deprecated) [PowerTools](https://github.com/PowerShellEmpire/PowerTools/) repository, which was a part of the PowerShellEmpire GitHub account. The DCSync attack was first released by Benjamin Delpy and Vincent Le Toux as part of the [mimikatz](https://github.com/gentilkiwi/mimikatz/) tool. It has since been included in other tools. The first stable release of CrackMapExec ([(v1.0.0)](https://github.com/byt3bl33d3r/CrackMapExec/releases?page=3) was introduced. Sean Metcalf gave a talk at Black Hat USA about the dangers of Kerberos Unconstrained Delegation and released an excellent [blog post](https://adsecurity.org/?p=1667) on the topic. The [Impacket](https://github.com/SecureAuthCorp/impacket/releases?page=2) toolkit was also released in 2015. This is a collection of Python tools, many of which can be used to perform Active Directory attacks. It is still actively maintained as of January 2022 and is a key part of most every penetration tester's toolkit.
		* **2016** - [BloodHound](https://wald0.com/?p=68) was released as a game changing tool for visualizing attack paths in AD at [DEF CON 24](https://www.youtube.com/watch?v=wP8ZCczC1OU).
		* **2017** - The [ASREPRoast](http://www.harmj0y.net/blog/activedirectory/roasting-as-reps/) technique was introduced for attacking user accounts that don't require Kerberos preauthentication. _wald0 and harmj0y delivered the pivotal talk on Active Directory ACL attacks ["ACE Up the Sleeve"](https://www.slideshare.net/harmj0y/ace-up-the-sleeve) at Black Hat and DEF CON. harmj0y released his ["A Guide to Attacking Domain Trusts"](https://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/) blog post on enumerating and attacking domain trusts.
		* **2018** - The "Printer Bug" bug was discovered by Lee Christensen and the [SpoolSample](https://github.com/leechristensen/SpoolSample) PoC tool was released which leverages this bug to coerce Windows hosts to authenticate to other machines via the MS-RPRN RPC interface. harmj0y released the [Rubeus toolkit](http://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/) for attacking Kerberos. Late in 2018 harmj0y also released the blog ["Not A Security Boundary: Breaking Forest Trusts"](http://www.harmj0y.net/blog/redteaming/not-a-security-boundary-breaking-forest-trusts/) which presented key research on performing attacks across forest trusts. The [DCShadow](https://www.dcshadow.com/) attack technique was also released by Vincent LE TOUX and Benjamin Delpy at the Bluehat IL 2018 conference. The [Ping Castle](https://github.com/vletoux/pingcastle/commits/master?after=f128d84e86e675f1ad65c4b9b05bd529e1f9dc7c+34&branch=master) tool was released by Vincent LE TOUX for performing security audits of Active Directory by looking for misconfigurations and other flaws that can raise the risk level of a domain and producing a report that can be used to identify ways to further harden the environment.
		* **2019** - harmj0y delivered the talk ["Kerberoasting Revisited"](https://www.slideshare.net/harmj0y/derbycon-2019-kerberoasting-revisited) at DerbyCon which laid out new approaches to Kerberoasting. Elad Shamir released a [blog post](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html) outlining techniques for abusing resource-based constrained delegation (RBCD) in Active Directory. The company BC Security released [Empire 3.0](https://github.com/BC-SECURITY/Empire) (now version 4) which was a re-release of the PowerShell Empire framework written in Python3 with many additions and changes.
		* **2020** - The [ZeroLogon](https://blog.malwarebytes.com/exploits-and-vulnerabilities/2021/01/the-story-of-zerologon/) attack debuted late in 2020. This was a critical flaw that allowed an attacker to impersonate any unpatched domain controller in a network.
		* **2021** - The [PrintNightmare](https://en.wikipedia.org/wiki/PrintNightmare) vulnerability was released. This was a remote code execution flaw in the Windows Print Spooler that could be used to take over hosts in an AD environment. The [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) attack was released which allows for low privileged users to impersonate other user and computer accounts if conditions are right, and can be used to escalate privileges in a domain. The [noPac](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware) attack was released in mid-December of 2021 when much of the security world was focused on the Log4j vulnerabilities. This attack allows an attacker to gain full control over a domain from a standard domain user account if the right conditions exist.
* ## Active Directory Structure
	*  Hierarchical structure that allows for centralized management of an organization's resources (users, computers, groups, network devices and file shares, group policies, servers and workstations, and trusts).
	* Authentication and authorization functions
	* A basic AD user account with no added privileges can be used to enumerate the majority of objects contained within AD, including but not limited to:
		* Domain Computers
		* Domain Users
		* Domain Group Information
		* Organizational Units (OUs)
		* Default Domain Policy
		* Functional Domain Levels
		* Password Policy
		* Group Policy Objects (GPOs)
		* Domain Trusts
		* Access Control Lists (ACLs)
	* Active Directory is arranged in a hierarchical tree structure, with a forest at the top containing one or more domains, which can themselves have nested subdomains.
		* A forest is the security boundary within which all objects are under administrative control.
		* A forest may contain multiple domains, and a domain may include further child or sub-domains.
		* A domain is a structure within which contained objects (users, computers, and groups) are accessible. It has many built-in Organizational Units (OUs), such as Domain Controllers, Users, Computers, and new OUs can be created as required. OUs may contain objects and sub-OUs, allowing for the assignment of different group policies.
	* two forests, bidirectional trust between the two forests.
* ## Active Directory Terminology
	* **Object** - defined as ANY resource present within an AD environment (OUs, printers, users, domain controllers, etc.)
	* **Attributes** - every object in AD has an associated set of attributes used to define characteristics of the given object (a computer object obtains attributes such as hostname and DNS name)
		* all attributes in AD have an associated LDAPname that can be used when performing LDAP queries, such as `displayName` for `Full Name` and `given name` for `First Name`.
	* **Schema** - The AD schema is essentially the blueprint of any enterprise environment.
		* Defines what types of objects can exist in the AD database and their associated attributes.
		* Lists definitions corresponding to AD objects and holds information about each object (e.g. users in AD belong to the class "user," and computer objects to "computer," and so on. Each object has its own information (some required to be set and others optional) that are stored in Attributes. When an object is created from a class, this is called **instantiation**, and an object created from a specific class is called an **instance of that class**. For example, if we take the computer RDS01. This computer object is an instance of the "computer" class in Active Directory.)
	* **Domain** - a logical group of objects such as computers, users, OUs, groups, etc.
		* basically each domain is a different city in the same state.
		* can operate independently of one another or be connected via trust relationships
	* **Forest** - a collection of AD domains/trees, top most container
		* the state and all cities within are domains
	* **Tree** - a collection of AD domains that begins at a single root domain.
	* **Container** - container objects hold other objects and have a defined place in the directory sub tree hierarchy.
	* **Leaf** - leaf objects do not contain other objects and are found at the end of the sub tree hierarchy
	* **Global Unique Identifier (GUID)** - a unique 128-bit value assigned when a domain user or group is created. Unique across the enterprise, similar to a MAC address.
		* Every single object created by Active Directory is assigned a GUID, not only user and group objects.
		* The GUID is stored in the `ObjectGUID` attribute. When querying for an AD object (such as a user, group, computer, domain, domain controller, etc.), we can query for its `objectGUID` value using PowerShell or search for it by specifying its distinguished name, GUID, SID, or SAM account name.
		* Searching in Active Directory by GUID value is probably the most accurate and reliable way to find the exact object you are looking for, especially if the global catalog may contain similar matches for an object name. Specifying the `ObjectGUID` value when performing AD enumeration will ensure that we get the most accurate results pertaining to the object we are searching for information about.
		* The `ObjectGUID` property `never` changes and is associated with the object for as long as that object exists in the domain.
	* **Security principals** - Anything that the operating system can authenticate, including users, computer accounts, or even threads/processes that run in the context of a user or computer account (i.e., an application such as Tomcat running in the context of a service account within the domain).
		* In AD, security principles are domain objects that can manage access to other resources within the domain. We can also have local user accounts and security groups used to control access to resources on only that specific computer. These are not managed by AD but rather by the [Security Accounts Manager (SAM)]([https://en.wikipedia.org/wiki/Security_Account_Manager](https://en.wikipedia.org/wiki/Security_Account_Manager)).
	* **Security Identifier (SID)** - Used as a unique identifier for a security principal or security group.
		* Every account, group, or process has its own unique SID, which, in an AD environment, is issued by the domain controller and stored in a secure database.
		* A SID can only be used once. Even if the security principle is deleted, it can never be used again in that environment to identify another user or group.
		* When a user logs in, the system creates an access token for them which contains the user's SID, the rights they have been granted, and the SIDs for any groups that the user is a member of. This token is used to check rights whenever the user performs an action on the computer.
		* There are also [well-known SIDs]([https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers](https://ldapwiki.com/wiki/Wiki.jsp?page=Well-known%20Security%20Identifiers)) that are used to identify generic users and groups. These are the same across all operating systems. An example is the `Everyone` group.
	* **Distinguished Name (DN)** - describes the full path to an object in AD (such as `cn=bjones, ou=IT, ou=Employees, dc=inlanefreight, dc=local`).
		* In this example, the user `bjones` works in the IT department of the company Inlanefreight, and his account is created in an Organizational Unit (OU) that holds accounts for company employees. The Common Name (CN) `bjones` is just one way the user object could be searched for or accessed within the domain.
	* **Relative Distinguished Name (RDN)** - a single component of the Distinguished Name that identifies the object as unique from other objects at the current level in the naming hierarchy.
		* In our example, `bjones` is the Relative Distinguished Name of the object. AD does not allow two objects with the same name under the same parent container, but there can be two objects with the same RDNs that are still unique in the domain because they have different DNs. For example, the object `cn=bjones,dc=dev,dc=inlanefreight,dc=local` would be recognized as different from `cn=bjones,dc=inlanefreight,dc=local`.
		* DN must be unique in the directory
		* RDN must be unique in an OU
	* **sAMAccountName** - user's logon name.
		* `bjones`
		* must be a unique value and 20 or fewer characters
	* **userPrincipleName** - this attribute is another way to identify users in AD.
		* not mandatory
	* **FSMO Roles** - In the early days of AD, if you had multiple DCs in an environment, they would fight over which DC gets to make changes, and sometimes changes would not be made properly.
		* Microsoft then implemented "last writer wins," which could introduce its own problems if the last change breaks things.
		* They then introduced a model in which a single "master" DC could apply changes to the domain while the others merely fulfilled authentication requests. This was a flawed design because if the master DC went down, no changes could be made to the environment until it was restored.
		* To resolve this single point of failure model, Microsoft separated the various responsibilities that a DC can have into [Flexible Single Master Operation (FSMO)]([https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/fsmo-roles)) roles. These give Domain Controllers (DC) the ability to continue authenticating users and granting permissions without interruption (authorization and authentication).
		* There are five FMSO roles:
			* `Schema Master` and `Domain Naming Master` (one of each per forest),
			* `Relative ID (RID) Master` (one per domain),
			* `Primary Domain Controller (PDC) Emulator` (one per domain), and
			* `Infrastructure Master` (one per domain).
		* All five roles are assigned to the first DC in the forest root domain in a new AD forest. Each time a new domain is added to a forest, only the RID Master, PDC Emulator, and Infrastructure Master roles are assigned to the new domain. FSMO roles are typically set when domain controllers are created, but sysadmins can transfer these roles if needed.
		* These roles help replication in AD to run smoothly and ensure that critical services are operating correctly. We will walk through each of these roles in detail later in this section.
	* **Global Catalog** - a domain controller that stores copies of ALL objects in an Active Directory forest.
		* Stores a full copy of all objects in the current domain and a partial copy of objects that belong to other domains in the forest.
		* Standard domain controllers hold a complete replica of objects belonging to its domain but not those of different domains in the forest.
		* The GC allows both users and applications to find information about any objects in ANY domain in the forest.
		* GC is a feature that is enabled on a domain controller and performs the following functions:
			- Authentication (provided authorization for all groups that a user account belongs to, which is included when an access token is generated)
			- Object search (making the directory structure within a forest transparent, allowing a search to be carried out across all domains in a forest by providing just one attribute about an object.)
	- **Read-Only Domain Controller (RODC)** - a read-only Active Directory database.
		- No AD account passwords are cached on an RODC (other than the RODC computer account & RODC KRBTGT passwords.)
		- No changes are pushed out via an RODC's AD database, SYSVOL, or DNS.
		- RODCs also include a read-only DNS server, allow for administrator role separation, reduce replication traffic in the environment, and prevent SYSVOL modifications from being replicated to other DCs.
	- **Replication** - happens in AD when AD objects are updated and transferred from one Domain Controller to another.
		- Whenever a DC is added, connection objects are created to manage replication between them. These connections are made by the Knowledge Consistency Checker (KCC) service, which is present on all DCs. Replication ensures that changes are synchronized with all other DCs in a forest, helping to create a backup in case one domain controller fails.
	- **Service Principal Name (SPN)** - uniquely identifies a service instance.
		- They are used by Kerberos authentication to associate an instance of a service with a logon account, allowing a client application to request the service to authenticate an account without needing to know the account name.
	- **Group Policy Object (GPO)** - virtual collections of policy settings.
		- Each GPO has a unique GUID.
		- A GPO can contain local file system settings or Active Directory settings.
		- GPO settings can be applied to both user and computer objects. They can be applied to all users and computers within the domain or defined more granularly at the OU level.
	- **Access Control List (ACL)** - the ordered collection of Access Control Entries (ACEs) that apply to an object.
	- **Access Control Entries (ACEs)** - Each [Access Control Entry (ACE)]([https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-entries)) in an ACL identifies a trustee (user account, group account, or logon session) and lists the access rights that are allowed, denied, or audited for the given trustee.
	- **Disrectionary Access Control List (DACL)** - DACLs define which security principles are granted or denied access to an object; it contains a list of ACEs.
		- When a process tries to access a securable object, the system checks the ACEs in the object's DACL to determine whether or not to grant access. If an object does NOT have a DACL, then the system will grant full access to everyone, but if the DACL has no ACE entries, the system will deny all access attempts. ACEs in the DACL are checked in sequence until a match is found that allows the requested rights or until access is denied.
	- **System Access Control Lists (SACL)** - Allows for administrators to log access attempts that are made to secured objects.
		- ACEs specify the types of access attempts that cause the system to generate a record in the security event log.
	- **Fully Qualified Domain Name (FQDN)** - the complete name for a specific computer or host. It is written with the hostname and domain name in the format [host name].[domain name].[tld]. This is used to specify an object's location in the tree hierarchy of DNS.
		- The FQDN can be used to locate hosts in an Active Directory without knowing the IP address, much like when browsing to a website such as [google.com](http://google.com/) instead of typing in the associated IP address.
		- An example would be the host `DC01` in the domain `INLANEFREIGHT.LOCAL`. The FQDN here would be `DC01.INLANEFREIGHT.LOCAL`.
	- **Tombstone** - a container object in AD that holds deleted AD objects.
		- When an object is deleted from AD, the object remains for a set period of time known as the `Tombstone Lifetime,` and the `isDeleted` attribute is set to `TRUE`.
		- Once an object exceeds the `Tombstone Lifetime`, it will be entirely removed.
		- Microsoft recommends a tombstone lifetime of 180 days to increase the usefulness of backups, but this value may differ across environments. Depending on the DC operating system version, this value will default to 60 or 180 days.
		- If an object is deleted in a domain that does not have an AD Recycle Bin, it will become a tombstone object. When this happens, the object is stripped of most of its attributes and placed in the `Deleted Objects` container for the duration of the `tombstoneLifetime`. It can be recovered, but any attributes that were lost can no longer be recovered.
	- **AD Recycle Bin** - first introduced in Windows Server 2008 R2 to facilitate the recovery of deleted AD objects.
		- This made it easier for sysadmins to restore objects, avoiding the need to restore from backups, restarting Active Directory Domain Services (AD DS), or rebooting a Domain Controller.
		- When the AD Recycle Bin is enabled, any deleted objects are preserved for a period of time, facilitating restoration if needed.
		- Sysadmins can set how long an object remains in a deleted, recoverable state. If this is not specified, the object will be restorable for a default value of 60 days.
		- The biggest advantage of using the AD Recycle Bin is that most of a deleted object's attributes are preserved, which makes it far easier to fully restore a deleted object to its previous state.
	- **SYSVOL** - folder or share that stores copies of public files in the domain such as system policies, Group Policy settings, logon/logoff scripts, and often contains other types of scripts that are executed to perform various tasks in the AD environment.
		- The contents of the SYSVOL folder are replicated to all DCs within the environment using File Replication Services (FRS). You can read more about the SYSVOL structure [here]([http://www.techiebird.com/Sysvol_structure.html](http://www.techiebird.com/Sysvol_structure.html)).
	- **AdminSDHolder** - object used to manage ACLs for members of built-in groups in AD marked as privileged.
		- It acts as a container that holds the Security Descriptor applied to members of protected groups.
		- The SDProp (SD Propagator) process runs on a schedule on the PDC Emulator Domain Controller. When this process runs, it checks members of protected groups to ensure that the correct ACL is applied to them. It runs every hour by default.
		- For example, suppose an attacker is able to create a malicious ACL entry to grant a user certain rights over a member of the Domain Admins group. In that case, unless they modify other settings in AD, these rights will be removed (and they will lose any persistence they were hoping to achieve) when the SDProp process runs on the set interval.
	- **deHeuristics** - an attribute that is a string value set on the Directory Service object used to define multiple forest-wide configuration settings.
		- One of these settings is to exclude built-in groups from the [Protected Groups]([https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)) list. Groups in this list are protected from modification via the `AdminSDHolder` object. If a group is excluded via the `dsHeuristics` attribute, then any changes that affect it will not be reverted when the SDProp process runs.
	- **adminCount** - this attribute determines whether or not the SDProp process protects a user.
		- If the value is set to `0` or not specified, the user is not protected. If the attribute value is set to `value`, the user is protected. ==Attackers will often look for accounts with the `adminCount` attribute set to `1` to target in an internal environment. These are often privileged accounts and may lead to further access or full domain compromise.==
	- **Active Directory Users and Computers (ADUC)** - ADUC is a GUI console commonly used for managing users, groups, computers, and contacts in AD. Changes made in ADUC can be done via PowerShell as well.
	- **ADSI Edit** - a GUI tool used to manage objects in AD.
		- It provides access to far more than is available in ADUC and can be used to set or delete any attribute available on an object, add, remove, and move objects as well.
		- It is a powerful tool that allows a user to access AD at a much deeper level. Great care should be taken when using this tool, as changes here could cause major problems in AD.
	- **sIDHistory** - [This]([https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute](https://docs.microsoft.com/en-us/defender-for-identity/cas-isp-unsecure-sid-history-attribute)) attribute holds any SIDs that an object was assigned previously.
		- It is usually used in migrations so a user can maintain the same level of access when migrated from one domain to another.
		- This attribute can potentially be abused if set insecurely, allowing an attacker to gain prior elevated access that an account had before a migration if SID Filtering (or removing SIDs from another domain from a user's access token that could be used for elevated access) is not enabled.
	* **NTDS.DIT** - The NTDS.DIT file can be considered the heart of Active Directory.
		* It is stored on a Domain Controller at `C:\Windows\NTDS\` and is a database that stores AD data such as information about user and group objects, group membership, and, most important to attackers and penetration testers, the ==password hashes for all users in the domain==.
		* Once full domain compromise is reached, an attacker can retrieve this file, extract the hashes, and either use them to perform a pass-the-hash attack or crack them offline using a tool such as Hashcat to access additional resources in the domain.
		* If the setting [Store password with reversible encryption]([https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption)) is enabled, then the NTDS.DIT will also store the cleartext passwords for all users created or who changed their password after this policy was set. While rare, some organizations may enable this setting if they use applications or protocols that need to use a user's existing password (and not Kerberos) for authentication.
	* **MSBROWSE** - a Microsoft networking protocol that was used in early versions of Windows-based local area networks (LANs) to provide browsing services. It was used to maintain a list of resources, such as shared printers and files, that were available on the network, and to allow users to easily browse and access these resources.
		* In older version of Windows we could use `nbtstat -A ip-address` to search for the Master Browser. If we see MSBROWSE it means that's the Master Browser. Aditionally we could use `nltest` utility to query a Windows Master Browser for the names of the Domain Controllers.
		* Today, MSBROWSE is largely obsolete and is no longer in widespread use. Modern Windows-based LANs use the Server Message Block (**SMB**) protocol for file and printer sharing, and the Common Internet File System (**CIFS**) protocol for browsing services.
* ## Active Directory Objects
	* Object is ANY resource present within an AD environment
		* **Domain** - structure of an AD network.contains objects.each domain has its own policies and database.
		* **Computer** - leaf object, security principal
		* **Groups** - container object, security principal
			* nested group - group added as a member of another group
			* ==leverage nested groups in pen test,use BloodHound to discover attack paths==
		* **User** - leaf objects (cannot contain any other objects within them). a security principal
		* **Printers** - leaf object, not a security principal
		* **OU** - a container that sys admins use to store similar objects for ease of administration.
		* **Contact** - leaf objects, contacts represent an external user and contains informational attributes. not a security principal
		* **Shared Folders** - NOT security principals
		* **Domain Controllers** - brains of an AD network. authentication and verification of users, control access to resources in the domain. enforces security policies and stores info about every other object in the domain
		* **Sites** - a set of computers across one or more subnets connected using high-speed links.
			* used to make replication across domain controllers run efficiently
		* **Built-in** - a container that holds default groups in an AD domain.
		* **Foreign Security Principals** - (FSP) an object created in AD to represent a security principal that belongs to a trusted external forest.
			* created when an object such as a user, group, or computer from an external forest is added to a group in the current domain
			* Placeholder object that holds the SID of the foreign object
			* FSPs are created in a specific container named ForeignSecurityPrincipals with a distinguished name like `cn=ForeignSecurityPrincipals,dc=inlanefreight,dc=local`.
* ## Active Directory Functionality
	* There are five Flexible Single Master Operation (FSMO) roles:
		* `Schema Master` - This role manages the read/write copy of the AD schema, which defines all attributes that can apply to an object in AD.
		* `Domain Naming Master` - Manages domain names and ensures that two domains of the same name are not created in the same forest.
		* `Relative ID (RID) Master` - The RID Master assigns blocks of RIDs to other DCs within the domain that can be used for new objects. The RID Master helps ensure that multiple objects are not assigned the same SID. Domain object SIDs are the domain SID combined with the RID number assigned to the object to make the unique SID.
		* `PDC Emulator` - The host with this role would be the authoritative DC in the domain and respond to authentication requests, password changes, and manage Group Policy Objects (GPOs). The PDC Emulator also maintains time within the domain.
		* `Infrastructure Master` - This role translates GUIDs, SIDs, and DNs between domains. This role is used in organizations with multiple domains in a single forest. The Infrastructure Master helps them to communicate. If this role is not functioning properly, Access Control Lists (ACLs) will show SIDs instead of fully resolved names.
	* These roles may be assigned to specific DCs or as defaults each time a new DC is added.
	* Issues with FSMO roles will lead to authentication and authorization difficulties within a domain.
	* **Domain and Forest Functional Levels**
		* Microsoft introduced functional levels to determine the various features and capabilities available in Active Directory Domain Services (AD DS) at the domain and forest level.
		* They are also used to specify which Windows Server operating systems can run a Domain Controller in a domain or forest.
		* [This]([https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918(v=ws.10)?redirectedfrom=MSDN](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc754918(v=ws.10)?redirectedfrom=MSDN)) and [this]([https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/active-directory-functional-levels)) article describe both the domain and forest functional levels from Windows 2000 native to Windows Server 2012 R2.
		* A new functional level was not added with the release of Windows Server 2019. However, Windows Server 2008 functional level is the minimum requirement for adding Server 2019 Domain Controllers to an environment. Also, the target domain has to use [DFS-R]([https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview](https://docs.microsoft.com/en-us/windows-server/storage/dfs-replication/dfsr-overview)) for SYSVOL replication.
	* Forest functional levels have introduced a few key capabilities over the years:
	* **Trusts**
		* A trust is used to establish `forest-forest` or `domain-domain` authentication, allowing users to access resources in (or administer) another domain outside of the domain their account resides in.
		* A trust creates a link between the authentication systems of two domains.
		* Types of trusts:
			* `Parent-child` - Domains within the same forest. The child domain has a two-way transitive trust with the parent domain.
			* `Cross-link` - a trust between child domains to speed up authentication.
			* `External` - A non-transitive trust between two separate domains in separate forests which are not already joined by a forest trust. This type of trust utilizes SID filtering.
			* `Tree-root` - a two-way transitive trust between a forest root domain and a new tree root domain. They are created by design when you set up a new tree root domain within a forest.
			* `Forest` - a transitive trust between two forest root domains.
		* Example:
		* ![[Pasted image 20231214113721.png]]
	* Trusts can be transitive or non-transitive.
		- A transitive trust means that trust is extended to objects that the child domain trusts.
		- In a non-transitive trust, only the child domain itself is trusted.
	* Trusts can be set up to be one-way or two-way (bidirectional).
		- In bidirectional trusts, users from both trusting domains can access resources.
		- In a one-way trust, only users in a trusted domain can access resources in a trusting domain, not vice-versa. The direction of trust is opposite to the direction of access.
	* Often, domain trusts are set up improperly and provide unintended attack paths.
		* Also, trusts set up for ease of use may not be reviewed later for potential security implications.
		* Mergers and acquisitions can result in bidirectional trusts with acquired companies, unknowingly introducing risk into the acquiring company’s environment.
		* It is not uncommon to be able to ==perform an attack such as Kerberoasting against a domain outside the principal domain and obtain a user that has administrative access within the principal domain.==
* ## Kerberos, DNS, LDAP, MSRPC
	* Active Directory specifically requires Lightweight Directory Access Protocol (**LDAP**), Microsoft's version of **Kerberos**, **DNS** for authentication and communication, and **MSRPC** which is the Microsoft implementation of Remote Procedure Call (RPC), an interprocess communication technique used for client-server model-based applications.
	* **Kerberos** - the default authentication protocol for domain accounts since Windows 2000.
		* Kerberos is an open standard and allows for interoperability with other systems using the same standard.
			* When a user logs into their PC, Kerberos is used to authenticate them via mutual authentication, or both the user and the server verify their identity.
		* Kerberos is a stateless authentication protocol based on tickets instead of transmitting user passwords over the network.
		* As part of Active Directory Domain Services (AD DS), Domain Controllers have a Kerberos Key Distribution Center (**KDC**) that issues tickets.
			* When a user initiates a login request to a system, the client they are using to authenticate requests a ticket from the KDC, encrypting the request with the user's password. If the KDC can decrypt the request (AS-REQ) using their password, it will create a Ticket Granting Ticket (**TGT**) and transmit it to the user. The user then presents its TGT to a Domain Controller to request a Ticket Granting Service (**TGS**) ticket, encrypted with the associated service's NTLM password hash. Finally, the client requests access to the required service by presenting the TGS to the application or service, which decrypts it with its password hash. If the entire process completes appropriately, the user will be permitted to access the requested service or application.
		* Kerberos authentication effectively decouples users' credentials from their requests to consumable resources, ensuring that their password isn't transmitted over the network (i.e., accessing an internal SharePoint intranet site).
		* The Kerberos Key Distribution Centre (KDC) does not record previous transactions. Instead, the Kerberos Ticket Granting Service ticket (TGS) relies on a valid Ticket Granting Ticket (TGT). It assumes that if the user has a valid TGT, they must have proven their identity. The following diagram walks through this process at a high level.
			1. The user logs on, and their password is converted to an NTLM hash, which is used to encrypt the TGT ticket. This decouples the user's credentials from requests to resources.
			2. The KDC service on the DC checks the authentication service request (AS-REQ), verifies the user information, and creates a Ticket Granting Ticket (TGT), which is delivered to the user.
			3. The user presents the TGT to the DC, requesting a Ticket Granting Service (TGS) ticket for a specific service. This is the TGS-REQ. If the TGT is successfully validated, its data is copied to create a TGS ticket.
			4. The TGS is encrypted with the NTLM password hash of the service or computer account in whose context the service instance is running and is delivered to the user in the TGS_REP.
			5. The user presents the TGS to the service, and if it is valid, the user is permitted to connect to the resource (AP_REQ).
			* ![[Pasted image 20231214113923.png]]
		* Kerberos protocol uses port 88 tcp and udp.
	* **DNS**
		* Active Directory Domain Services (AD DS) uses DNS to allow clients (workstations, servers, and other systems that communicate with the domain) to locate Domain Controllers and for Domain Controllers that host the directory service to communicate amongst themselves.
		* DNS is used to resolve hostnames to IP addresses and is broadly used across internal networks and the internet.
		* Private internal networks use Active Directory DNS namespaces to facilitate communications between servers, clients, and peers.
		* AD maintains a database of services running on the network in the form of service records (**SRV**). These service records allow clients in an AD environment to locate services that they need, such as a file server, printer, or Domain Controller.
		* Dynamic DNS is used to make changes in the DNS database automatically should a system's IP address change.
		* When a client joins the network, it locates the Domain Controller by sending a query to the DNS service, retrieving an SRV record from the DNS database, and transmitting the Domain Controller's hostname to the client. The client then uses this hostname to obtain the IP address of the Domain Controller.
		* DNS uses TCP and UDP port 53. UDP port 53 is the default, but it falls back to TCP when no longer able to communicate and DNS messages are larger than 512 bytes.
		* ![[Pasted image 20231214114054.png]]
		* **Forward DNS Lookup**
			* `nslookup INLANEFREIGHT.LOCAL`
		* **Reverse DNS Lookup**
			* `nslookup 172.16.6.5`
		* **Finding IP Address of a Host**
			* `nslookp ACADEMY-EA-DC01`
	* **LDAP**
		* Active Directory supports [Lightweight Directory Access Protocol (LDAP)]([https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)) for directory lookups. LDAP is an open-source and cross-platform protocol used for authentication against various directory services (such as AD).
		* The latest LDAP specification is [Version 3]([https://tools.ietf.org/html/rfc4511](https://tools.ietf.org/html/rfc4511)), published as RFC 4511. A firm understanding of how LDAP works in an AD environment is crucial for attackers and defenders.
		* LDAP uses port 389, and LDAP over SSL (LDAPS) communicates over port 636.
		* AD stores user account information and security information such as passwords and facilitates sharing this information with other devices on the network
		* LDAP is the language that applications use to communicate with other servers that provide directory services. In other words, LDAP is how systems in the network environment can "speak" to AD.
		* An LDAP session begins by first connecting to an LDAP server, also known as a Directory System Agent. The Domain Controller in AD actively listens for LDAP requests, such as security authentication requests.
		* ![[Pasted image 20231214114024.png]]
		* The relationship between AD and LDAP can be compared to Apache and HTTP. The same way Apache is a web server that uses the HTTP protocol, Active Directory is a directory server that uses the LDAP protocol.
		* While uncommon, you may come across organization while performing an assessment that do not have AD but are using LDAP, meaning that they most likely use another type of LDAP server such as [OpenLDAP]([https://en.wikipedia.org/wiki/OpenLDAP](https://en.wikipedia.org/wiki/OpenLDAP)).
	* **AD LDAP Authentication**
		* LDAP is set up to authenticate credentials against AD using a "BIND" operation to set the authentication state for an LDAP session. There are two types of LDAP authentication.
			1. `Simple Authentication`: This includes anonymous authentication, unauthenticated authentication, and username/password authentication. Simple authentication means that a `username` and `password` create a BIND request to authenticate to the LDAP server.
			2. `SASL Authentication`: [The Simple Authentication and Security Layer (SASL)]([https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer](https://en.wikipedia.org/wiki/Simple_Authentication_and_Security_Layer)) framework uses other authentication services, such as Kerberos, to bind to the LDAP server and then uses this authentication service (Kerberos in this example) to authenticate to LDAP. The LDAP server uses the LDAP protocol to send an LDAP message to the authorization service, which initiates a series of challenge/response messages resulting in either successful or unsuccessful authentication. SASL can provide additional security due to the separation of authentication methods from application protocols.
	* **MSRPC**
		* MSRPC is Microsoft's implementation of Remote Procedure Call (**RPC**), an interprocess communication technique used for client-server model-based applications. Windows systems use MSRPC to access systems in Active Directory using four key RPC interfaces.
			* `lsarpc` - A set of RPC calls to the [Local Security Authority (LSA)]([https://networkencyclopedia.com/local-security-authority-lsa/](https://networkencyclopedia.com/local-security-authority-lsa/)) system which manages the local security policy on a computer, controls the audit policy, and provides interactive authentication services. LSARPC is used to perform management on domain security policies.
			* `netlogon` - Netlogon is a Windows process used to authenticate users and other services in the domain environment. It is a service that continuously runs in the background.
			* `samr` - Remote SAM (samr) provides management functionality for the domain account database, storing information about users and groups. IT administrators use the protocol to manage users, groups, and computers by enabling admins to create, read, update, and delete information about security principles. ==Attackers (and pentesters) can use the samr protocol to perform reconnaissance about the internal domain using tools such as [BloodHound]([https://github.com/BloodHoundAD/](https://github.com/BloodHoundAD/)) to visually map out the AD network and create "attack paths" to illustrate visually how administrative access or full domain compromise could be achieved.== Organizations can [protect]([https://stealthbits.com/blog/making-internal-reconnaissance-harder-using-netcease-and-samri1o/](https://stealthbits.com/blog/making-internal-reconnaissance-harder-using-netcease-and-samri1o/)) against this type of reconnaissance by changing a Windows registry key to only allow administrators to perform remote SAM queries since, by default, all authenticated domain users can make these queries to gather a considerable amount of information about the AD domain.
			* `drsuapi` - drsuapi is the Microsoft API that implements the Directory Replication Service (DRS) Remote Protocol which is used to perform replication-related tasks across Domain Controllers in a multi-DC environment. ==Attackers can utilize drsuapi to [create a copy of the Active Directory domain database]([https://attack.mitre.org/techniques/T1003/003/](https://attack.mitre.org/techniques/T1003/003/)) (NTDS.dit) file to retrieve password hashes for all accounts in the domain, which can then be used to perform Pass-the-Hash attacks to access more systems or cracked offline using a tool such as Hashcat to obtain the cleartext password to log in to systems using remote management protocols such as Remote Desktop (RDP) and WinRM.==
* ## NTLM Authentication
	* Aside from Kerberos and LDAP, Active Directory uses several other authentication methods which can be used (and abused) by applications and services in AD.
	* These include LM, NTLM, NTLMv1, and NTLMv2.
	* LM and NTLM here are the hash names, and NTLMv1 and NTLMv2 are authentication protocols that utilize the LM or NT hash.
	* Below is a quick comparison between these hashes and protocols, which shows us that, while not perfect by any means, Kerberos is often the authentication protocol of choice wherever possible. It is essential to understand the difference between the hash types and the protocols that use them.
	* ![[Pasted image 20231214114220.png]]
	* **LM**
		* `LAN Manager` (LM or LANMAN) hashes are the oldest password storage mechanism used by the Windows operating system. LM debuted in 1987 on the OS/2 operating system. If in use, they are stored in the SAM database on a Windows host and the NTDS.DIT database on a Domain Controller. Due to significant security weaknesses in the hashing algorithm used for LM hashes, it has been turned off by default since Windows Vista/Server 2008. However, it is still common to encounter, especially in large environments where older systems are still used. Passwords using LM are limited to a maximum of `14` characters. Passwords are not case sensitive and are converted to uppercase before generating the hashed value, limiting the keyspace to a total of 69 characters making it relatively easy to crack these hashes using a tool such as Hashcat.
		* Before hashing, a 14 character password is first split into two seven-character chunks. If the password is less than fourteen characters, it will be padded with NULL characters to reach the correct value. Two DES keys are created from each chunk. These chunks are then encrypted using the string `KGS!@#$%`, creating two 8-byte ciphertext values. These two values are then concatenated together, resulting in an LM hash. ==This hashing algorithm means that an attacker only needs to brute force seven characters twice instead of the entire fourteen characters, making it fast to crack LM hashes on a system with one or more GPUs. If a password is seven characters or less, the second half of the LM hash will always be the same value and could even be determined visually without even needed tools such as Hashcat. ==The use of LM hashes can be disallowed using [Group Policy]([https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change)). An LM hash takes the form of `299bd128c1101fd6`.
	* **NTHash (NTLM)**
		* `NT LAN Manager` (NTLM) hashes are used on modern Windows systems. It is a challenge-response authentication protocol and uses three messages to authenticate: a client first sends a `NEGOTIATE_MESSAGE` to the server, whose response is a `CHALLENGE_MESSAGE` to verify the client's identity. Lastly, the client responds with an `AUTHENTICATE_MESSAGE`. These hashes are stored locally in the SAM database or the NTDS.DIT database file on a Domain Controller. The protocol has two hashed password values to choose from to perform authentication: the LM hash (as discussed above) and the NT hash, which is the MD4 hash of the little-endian UTF-16 value of the password. The algorithm can be visualized as: `MD4(UTF-16-LE(password))`.
		* ![[Pasted image 20231214114251.png]]
		* Even though they are considerably stronger than LM hashes (supporting the entire Unicode character set of 65,536 characters), they can still be brute-forced offline relatively quickly using a tool such as Hashcat. ==GPU attacks have shown that the entire NTLM 8 character keyspace can be brute-forced in under `3 hours`. Longer NTLM hashes can be more challenging to crack depending on the password chosen, and even long passwords (15+ characters) can be cracked using an offline dictionary attack combined with rules.== NTLM is also vulnerable to the pass-the-hash attack, which means ==an attacker can use just the NTLM hash (after obtaining via another successful attack) to authenticate to target systems where the user is a local admin without needing to know the cleartext value of the password.==
		* An NT hash takes the form of `b4b9b02e6f09a9bd760f388b67351e2b`, which is the second half of the full NTLM hash. An NTLM hash looks like this:
			* `Rachel:500:aad3c435b514a4eeaad3b935b51304fe:e46b9e548fa0d122de7f59fb6d48eaa2:::`
				* `Rachel` is the username
				- `500` is the Relative Identifier (RID). 500 is the known RID for the `administrator` account
				- `aad3c435b514a4eeaad3b935b51304fe` is the LM hash and, if LM hashes are disabled on the system, can not be used for anything
				- `e46b9e548fa0d122de7f59fb6d48eaa2` is the NT hash. This hash can either be cracked offline to reveal the cleartext value (depending on the length/strength of the password) or used for a pass-the-hash attack.
		- **Note:** Neither LANMAN (LM) nor NTLM uses a salt.
	- **NTLMv1 (Net-NTLMv1)**
		- The NTLM protocol performs a challenge/response between a server and client using the NT hash. NTLMv1 uses both the NT and the LM hash, which can make it easier to "crack" offline after capturing a hash using a tool such as [Responder]([https://github.com/lgandx/Responder](https://github.com/lgandx/Responder)) or via an [NTLM relay attack]([https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)) (both of which are out of scope for this module and will be covered in later modules on Lateral Movement). The protocol is used for network authentication, and the Net-NTLMv1 hash itself is created from a challenge/response algorithm. The server sends the client an 8-byte random number (challenge), and the client returns a 24-byte response. These hashes can NOT be used for pass-the-hash attacks. The algorithm looks as follows:
			- ```C = 8-byte server challenge, random K1 | K2 | K3 = LM/NT-hash | 5-bytes-0 response = DES(K1,C) | DES(K2,C) | DES(K3,C)```
		* An example of a full NTLMv1 hash:
			* `u4-netntlm::kNS:338d08f8e26de93300000000000000000000000000000000:9526fb8c23a90751cdd619b6cea564742e1e4bf33006ba41:cb8086049ec4736c`
		* NTLMv1 was the building block for modern NTLM authentication. Like any protocol, it has flaws and is susceptible to cracking and other attacks. Now let us move on and take a look at NTLMv2 and see how it improves on the foundation that version one set.
	* **NTLMv2 (Net-NTLMv2)**
		* The NTLMv2 protocol was first introduced in Windows NT 4.0 SP4 and was created as a stronger alternative to NTLMv1. It has been the default in Windows since Server 2000. It is hardened against certain spoofing attacks that NTLMv1 is susceptible to. NTLMv2 sends two responses to the 8-byte challenge received by the server. These responses contain a 16-byte HMAC-MD5 hash of the challenge, a randomly generated challenge from the client, and an HMAC-MD5 hash of the user's credentials. A second response is sent, using a variable-length client challenge including the current time, an 8-byte random value, and the domain name. The algorithm is as follows:
			* ```SC = 8-byte server challenge, random CC = 8-byte client challenge, random CC* = (X, time, CC2, domain name) v2-Hash = HMAC-MD5(NT-Hash, user name, domain name) LMv2 = HMAC-MD5(v2-Hash, SC, CC) NTv2 = HMAC-MD5(v2-Hash, SC, CC*) response = LMv2 | CC | NTv2 | CC*```
		* An example of an NTLMv2 hash:
		* `admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c7830310000000000000b45c67103d07d7b95acd12ffa11230e0000000052920b85f78d013c31cdb3b92f5d765c783030`
		* We can see that developers improved upon v1 by making NTLMv2 harder to crack and giving it a more robust algorithm made up of multiple stages. We have one more authentication mechanism to discuss before moving on. This method is of note to us because it does not require a persistent network connection to work.
	* **Domain Cached Credentials (MSCache2)**
		* In an AD environment, the authentication methods mentioned in this section and the previous require the host we are trying to access to communicate with the "brains" of the network, the Domain Controller.
		* Microsoft developed the [MS Cache v1 and v2]([https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/](https://webstersprodigy.net/2014/02/03/mscash-hash-primer-for-pentesters/)) algorithm (also known as `Domain Cached Credentials` (DCC) to solve the potential issue of a domain-joined host being unable to communicate with a domain controller (i.e., due to a network outage or other technical issue) and, hence, NTLM/Kerberos authentication not working to access the host in question.
		* Hosts save the last `ten` hashes for any domain users that successfully log into the machine in the `HKEY_LOCAL_MACHINE\SECURITY\Cache` registry key.
		* These hashes cannot be used in pass-the-hash attacks. Furthermore, the hash is very slow to crack with a tool such as Hashcat, even when using an extremely powerful GPU cracking rig, so attempts to crack these hashes typically need to be extremely targeted or rely on a very weak password in use.
		* These hashes can be obtained by an attacker or pentester after gaining local admin access to a host and have the following format: `$DCC2$10240#bjones#e4e938d12fe5974dc42a90120bd9c90f`. It is vital as penetration testers that we understand the varying types of hashes that we may encounter while assessing an AD environment, their strengths, weaknesses, how they can be abused (cracking to cleartext, pass-the-hash, or relayed), and when an attack may be futile (i.e., spending days attempting to crack a set of Domain Cached Credentials).
* ## User and Machine Accounts
	* User accounts are created on both local systems (not joined to AD) and in Active Directory to give a person or a program (such as a system service) the ability to log on to a computer and access resources based on their rights.
	* When a user logs in, the system verifies their password and creates an access token.
		* This token describes the security content of a process or thread and includes the user's security identity and group membership.
		* Whenever a user interacts with a process, this token is presented.
	* User accounts are used to allow employees/contractors to log in to a computer and access resources, to run programs or services under a specific security context (i.e., running as a highly privileged user instead of a network service account), and to manage access to objects and their properties such as network file shares, files, applications, etc.
	* Users can be assigned to groups that can contain one or more members. These groups can also be used to control access to resources.
	* It can be easier for an administrator to assign privileges once to a group (which all group members inherit) instead of many times to each individual user. This helps simplify administration and makes it easier to grant and revoke user rights.
	* The ability to provision and manage user accounts is one of the core elements of Active Directory.
		* Typically, every company we encounter will have at least one AD user account provisioned per user.
		* Some users may have two or more accounts provisioned based on their job role (i.e., an IT admin or Help Desk member).
		* Aside from standard user and admin accounts tied back to a specific user, we will often see many service accounts used to run a particular application or service in the background or perform other vital functions within the domain environment.
		* An organization with 1,000 employees could have 1,200 active user accounts or more! We may also see organizations with hundreds of disabled accounts from former employees, temporary/seasonal employees, interns, etc.
			* Some companies must retain records of these accounts for audit purposes, so they will deactivate them (and hopefully remove all privileges) once the employee is terminated, but they will not delete them. It is common to see an OU such as `FORMER EMPLOYEES` that will contain many deactivated accounts.
	* User accounts can be provisioned many rights in Active Directory. They can be configured as basically read-only users who have read access to most of the environment (which are the permissions a standard Domain User receives) up to Enterprise Admin (with complete control of every object in the domain) and countless combinations in between.
		* Because users can have so many rights assigned to them, they can also be misconfigured relatively easily and granted unintended rights that an attacker or a penetration tester can leverage.
		* User accounts present an immense attack surface and are usually a ==key focus for gaining a foothold during a penetration test.==
		* Users are often the weakest link in any organization. It is difficult to manage human behavior and account for every user choosing weak or shared passwords, installing unauthorized software, or admins making careless mistakes or being overly permissive with account management.
		* To combat this, an organization needs to have policies and procedures to combat issues that can arise around user accounts and must have defense in depth to mitigate the inherent risk that users bring to the domain.
	* **Local Accounts**
		* Local accounts are stored locally on a particular server or workstation. These accounts can be assigned rights on that host either individually or via group membership. Any rights assigned can only be granted to that specific host and will not work across the domain. Local user accounts are considered security principals but can only manage access to and secure resources on a standalone host. There are several default local user accounts that are created on a Windows system:
			* `Administrator`: this account has the SID `S-1-5-domain-500` and is the first account created with a new Windows installation. It has full control over almost every resource on the system. It cannot be deleted or locked, but it can be disabled or renamed. Windows 10 and Server 2016 hosts disable the built-in administrator account by default and create another local account in the local administrator's group during setup.
			- `Guest`: this account is disabled by default. The purpose of this account is to allow users without an account on the computer to log in temporarily with limited access rights. By default, it has a blank password and is generally recommended to be left disabled because of the security risk of allowing anonymous access to a host.
			- `SYSTEM`: The SYSTEM (or `NT AUTHORITY\SYSTEM`) account on a Windows host is the default account installed and used by the operating system to perform many of its internal functions. Unlike the Root account on Linux, `SYSTEM` is a service account and does not run entirely in the same context as a regular user. Many of the processes and services running on a host are run under the SYSTEM context. One thing to note with this account is that a profile for it does not exist, but it will have permissions over almost everything on the host. It does not appear in User Manager and cannot be added to any groups. ==A `SYSTEM` account is the highest permission level one can achieve on a Windows host and, by default, is granted Full Control permissions to all files on a Windows system.==
			- `Network Service`: This is a predefined local account used by the Service Control Manager (SCM) for running Windows services. When a service runs in the context of this particular account, it will present credentials to remote services.
			- `Local Service`: This is another predefined local account used by the Service Control Manager (SCM) for running Windows services. It is configured with minimal privileges on the computer and presents anonymous credentials to the network.
		- Microsoft's documentation on [local default accounts]([https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts))
	- **Domain Users**
		- Domain users differ from local users in that they are granted rights from the domain to access resources such as file servers, printers, intranet hosts, and other objects based on the permissions granted to their user account or the group that account is a member of.
		- Domain user accounts can log in to any host in the domain, unlike local users.
		- For more information on the many different Active Directory account types, check out this [link]([https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts)).
			- One account to keep in mind is the `KRBTGT` account, however. This is a type of local account built into the AD infrastructure. This account acts as a service account for the Key Distribution service providing authentication and access for domain resources. ==This account is a common target of many attackers since gaining control or access will enable an attacker to have unconstrained access to the domain. It can be leveraged for privilege escalation and persistence in a domain through attacks such as the [Golden Ticket]([https://attack.mitre.org/techniques/T1558/001/](https://attack.mitre.org/techniques/T1558/001/)) attack.==
	- **User Naming Attributes**
		- Security in Active Directory can be improved using a set of user naming attributes to help identify user objects like logon name or ID. The following are a few important Naming Attributes in AD:
			- `UserPrincipalName` (UPN) - This is the primary logon name for the user. By convention, the UPN uses the email address of the user.
			- `ObjectGUID` - This is a unique identifier of the user. In AD, the ObjectGUID attribute name never changes and remains unique even if the user is removed.
			- `SAMAccountName` - This is a logon name that supports the previous version of Windows clients and servers.
			- `objectSID` - The user's Security Identifier (SID). This attribute identifies a user and its group memberships during security interactions with the server.
			- `sIDHistory` - This contains previous SIDs for the user object if moved from another domain and is typically seen in migration scenarios from domain to domain. After a migration occurs, the last SID will be added to the `sIDHistory` property, and the new SID will become its `objectSID`.
		- For a deeper look at user object attributes, check out this [page]([https://docs.microsoft.com/en-us/windows/win32/ad/user-object-attributes](https://docs.microsoft.com/en-us/windows/win32/ad/user-object-attributes)).
	- **Domain-Joined vs. Non-Domain-Joined Machines**
		- Several ways to manage computer resources:
			- `Domain joined`
				- Hosts joined to a domain have greater ease of information sharing within the enterprise and a central management point (the DC) to gather resources, policies, and updates from. A host joined to a domain will acquire any configurations or changes necessary through the domain's Group Policy. The benefit here is that a user in the domain can log in and access resources from any host joined to the domain, not just the one they work on. This is the typical setup you will see in enterprise environments.
			- `Non-domain joined`
				- Non-domain joined computers or computers in a `workgroup` are not managed by domain policy. With that in mind, sharing resources outside your local network is much more complicated than it would be on a domain. This is fine for computers meant for home use or small business clusters on the same LAN. The advantage of this setup is that the individual users are in charge of any changes they wish to make to their host. Any user accounts on a workgroup computer only exist on that host, and profiles are not migrated to other hosts within the workgroup.
				- It is important to note that a machine account (`NT AUTHORITY\SYSTEM` level access) in an AD environment will have most of the same rights as a standard domain user account. This is important because we do not always need to obtain a set of valid credentials for an individual user's account to begin enumerating and attacking a domain (as we will see in later modules). ==We may obtain `SYSTEM` level access to a domain-joined Windows host through a successful remote code execution exploit or by escalating privileges on a host. This access is often overlooked as only useful for pillaging sensitive data (i.e., passwords, SSH keys, sensitive files, etc.) on a particular host. In reality, access in the context of the `SYSTEM` account will allow us read access to much of the data within the domain and is a great launching point for gathering as much information about the domain as possible before proceeding with applicable AD-related attacks.==
- ## Active Directory Groups
	- Groups are the next significant object in AD
	- ==key target for attackers and penetration testers, as the rights that they confer on their members may not be readily apparent but may grant excessive privileges that can be abused if not set up correctly==
	- Many [built-in groups]([https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#about-active-directory-groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#about-active-directory-groups)) in Active Directory
	- It is essential to understand the impact of using different group types and for any organization to periodically `audit` which groups exist within their domain, the privileges that these groups grant their members, and check for excessive group membership beyond what is required for a user to perform their day-to-day work.
	- What is the difference between **Groups** and **Organizational Units**?
		- **OUs** are useful for grouping users, groups, and computers to ease management and deploying Group Policy settings to specific objects in the domain.
		- **Groups** are primarily used to assign permissions to access resources.
		- **OUs** can also be used to delegate administrative tasks to a user, such as resetting passwords or unlocking user accounts without giving them additional admin rights that they may inherit through group memberships.
	- **Types of Groups**
		- Groups are used to place users, computers, and contact objects into management units that provide ease of administration over permissions and facilitate the assignment of resources such as printers and file share access.
		- Groups in AD have two fundamental characteristics: **type** and **scope**
			- **Group Type** defines the group's purpose
				- **Security** group - primarily for ease of assigning permissions and rights to a collection of users instead of one at a time. Simplify management and reduce overhead when assigning permissions and rights for a given resource. All users added to a security group will inherit any permissions assigned to the group, making it easier to move users in and out of groups while leaving the group's permissions unchanged
				- **Distribution** group - used by email applications such as Microsoft Exchange to distribute messages to group members. They function much like mailing lists and allow for auto-adding emails in the "To" field when creating an email in Microsoft Outlook. This type of group cannot be used to assign permissions to resources in a domain environment.
			- **Group Scope** shows how the group can be used within the domain or forest.
				- **Domain local** - can only be used to manage permissions to domain resources in the domain where it was created. Local groups cannot be used in other domains but `CAN` contain users from `OTHER` domains. Local groups can be nested into (contained within) other local groups but `NOT` within global groups.
				- **Global** - can be used to grant access to resources in `another domain`. A global group can only contain accounts from the domain where it was created. Global groups can be added to both other global groups and local groups.
				- **Universal** - can be used to manage resources distributed across multiple domains and can be given permissions to any object within the same `forest`. They are available to all domains within an organization and can contain users from any domain.
					- Unlike domain local and global groups, universal groups are stored in the Global Catalog (GC), and adding or removing objects from a universal group triggers forest-wide replication. It is recommended that administrators maintain other groups (such as global groups) as members of universal groups because global group membership within universal groups is less likely to change than individual user membership in global groups. Replication is only triggered at the individual domain level when a user is removed from a global group. If individual users and computers (instead of global groups) are maintained within universal groups, it will trigger forest-wide replication each time a change is made. This can create a lot of network overhead and potential for issues.
		- Group scopes can be changed, but there are a few caveats:
			- A Global Group can only be converted to a Universal Group if it is NOT part of another Global Group.
			- A Domain Local Group can only be converted to a Universal Group if the Domain Local Group does NOT contain any other Domain Local Groups as members.
			- A Universal Group can be converted to a Domain Local Group without any restrictions.
			- A Universal Group can only be converted to a Global Group if it does NOT contain any other Universal Groups as members.
	- **Built-in** **vs. Custom Groups**
		-  Several built-in security groups are created with a Domain Local Group scope when a domain is created.
		- These groups are used for specific administrative purposes and are discussed more in the next section.
		- It is important to note that **only user accounts** can be added to these built-in groups as they **do not allow for group nesting** (groups within groups).
			- Some examples of built-in groups included `Domain Admins`, which is a `Global` security group and can only contain accounts from its own domain. If an organization wants to allow an account from domain B to perform administrative functions on a domain controller in domain A, the account would have to be added to the built-in Administrators group, which is a `Domain Local` group.
		- Though Active Directory comes prepopulated with many groups, it is common for most organizations to create additional groups (both security and distribution) for their own purposes. Changes/additions to an AD environment can also trigger the creation of additional groups.
			- For example, when Microsoft Exchange is added to a domain, it adds various different security groups to the domain, some of which are highly privileged and, if not managed properly, can be used to gain privileged access within the domain.
	- **Nested Group Membership**
		- Nested group membership is an important concept in AD. As mentioned previously, a Domain Local Group can be a member of another Domain Local Group in the same domain.
		- Through this membership, a user may inherit privileges not assigned directly to their account or even the group they are directly a member of, but rather the group that their group is a member of.
			- This can sometimes lead to unintended privileges granted to a user that are difficult to uncover without an in-depth assessment of the domain. ==Tools such as [BloodHound]([https://github.com/BloodHoundAD/BloodHound](https://github.com/BloodHoundAD/BloodHound)) are particularly useful in uncovering privileges that a user may inherit through one or more nestings of groups. This is a key tool for penetration testers for uncovering nuanced misconfigurations and is also extremely powerful for sysadmins and the like to gain deep insights (visually) into the security posture of their domain(s).==
			- An example of privileges inherited through nested group membership: Though `DCorner` is not a direct member of `Helpdesk Level 1`, their membership in `Help Desk` grants them the same privileges that any member of `Helpdesk Level 1` has. In this case, the privilege would allow them to add a member to the `Tier 1 Admins` group (`GenericWrite`). If this group confers any elevated privileges in the domain, it would likely be a key target for a penetration tester. Here, we could add our user to the group and obtain privileges that members of the `Tier 1 Admins` group are granted, such as local administrator access to one or more hosts that could be used to further access.
	- **Important Group Attributes**
		- `cn`: The `cn` or Common-Name is the name of the group in Active Directory Domain Services.
		- `member`: Which user, group, and contact objects are members of the group.
		- `groupType`: An integer that specifies the group type and scope.
		- `memberOf`: A listing of any groups that contain the group as a member (nested group membership).
		- `objectSid`: This is the security identifier or SID of the group, which is the unique value used to identify the group as a security principal.
- ## Active Directory Rights and Privileges
	- Rights and privileges are the cornerstones of AD management and, if mismanaged, can easily lead to abuse by attackers or penetration testers.
	- Access rights and privileges are two important topics in AD (and infosec in general), and we must understand the difference.
		- `Rights` are typically assigned to users or groups and deal with permissions to `access` an object such as a file, while
		- `privileges` grant a user permission to `perform an action` such as run a program, shut down a system, reset passwords, etc.
			- Privileges can be assigned individually to users or conferred upon them via built-in or custom group membership.
			* Windows computers have a concept called `User Rights Assignment`, which, while referred to as rights, are actually types of privileges granted to a user. 
	* **Built-in AD Group**
		* AD contains many [default or built-in security groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups), some of which grant their members powerful rights and privileges which can be abused to escalate privileges within a domain and ultimately gain Domain Admin or SYSTEM privileges on a Domain Controller (DC).
			* |`Account Operators`|Members can create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers. They cannot manage the Administrator account, administrative user accounts, or members of the Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators groups.
			* |`Administrators`|Members have full and unrestricted access to a computer or an entire domain if they are in this group on a Domain Controller.
			* |`Backup Operators`|Members can back up and restore all files on a computer, regardless of the permissions set on the files. Backup Operators can also log on to and shut down the computer. Members can log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, which, if taken, can be used to extract credentials and other juicy info.
			* |`DnsAdmins`|Members have access to network DNS information. The group will only be created if the DNS server role is or was at one time installed on a domain controller in the domain.
			* |`Domain Admins`|Members have full access to administer the domain and are members of the local administrator's group on all domain-joined machines.
			* |`Domain Computers`|Any computers created in the domain (aside from domain controllers) are added to this group.
			* |`Domain Controllers`|Contains all DCs within a domain. New DCs are added to this group automatically.
			* |`Domain Guests`|This group includes the domain's built-in Guest account. Members of this group have a domain profile created when signing onto a domain-joined computer as a local guest.
			* |`Domain Users`|This group contains all user accounts in a domain. A new user account created in the domain is automatically added to this group.
			* |`Enterprise Admins`|Membership in this group provides complete configuration access within the domain. The group only exists in the root domain of an AD forest. Members in this group are granted the ability to make forest-wide changes such as adding a child domain or creating a trust. The Administrator account for the forest root domain is the only member of this group by default.
			* |`Event Log Readers`|Members can read event logs on local computers. The group is only created when a host is promoted to a domain controller.
			* |`Group Policy Creator Owners`|Members create, edit, or delete Group Policy Objects in the domain.
			* |`Hyper-V Administrators`|Members have complete and unrestricted access to all the features in Hyper-V. If there are virtual DCs in the domain, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.
			* |`IIS_IUSRS`|This is a built-in group used by Internet Information Services (IIS), beginning with IIS 7.0.
			* |`Pre–Windows 2000 Compatible Access`|This group exists for backward compatibility for computers running Windows NT 4.0 and earlier. Membership in this group is often a leftover legacy configuration. It can lead to flaws where anyone on the network can read information from AD without requiring a valid AD username and password.
			* |`Print Operators`|Members can manage, create, share, and delete printers that are connected to domain controllers in the domain along with any printer objects in AD. Members are allowed to log on to DCs locally and may be used to load a malicious printer driver and escalate privileges within the domain.
			* |`Protected Users`|Members of this [group](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#protected-users) are provided additional protections against credential theft and tactics such as Kerberos abuse.
			* |`Read-only Domain Controllers`|Contains all Read-only domain controllers in the domain.
			* |`Remote Desktop Users`|This group is used to grant users and groups permission to connect to a host via Remote Desktop (RDP). This group cannot be renamed, deleted, or moved.
			* |`Remote Management Users`|This group can be used to grant users remote access to computers via [Windows Remote Management (WinRM)](https://docs.microsoft.com/en-us/windows/win32/winrm/portal)
			* |`Schema Admins`|Members can modify the Active Directory schema, which is the way all objects with AD are defined. This group only exists in the root domain of an AD forest. The Administrator account for the forest root domain is the only member of this group by default.
			* |`Server Operators`|This group only exists on domain controllers. Members can modify services, access SMB shares, and backup files on domain controllers. By default, this group has no members.
	* **Server Operators Group Details**
		* `Get-ADGroup -Identity "Server Operators" -Properties *`
	* **Domain Admins Group Membership**
		* Domain Admins are also Global groups instead of domain local. More on group membership can be found later in this module. Be wary of who, if anyone, you give access to these groups. ==An attacker could easily gain the keys to the enterprise if they gain access to a user assigned to these groups.==
		* `Get-ADGroup -Identity "Domain Admins" -Properties * | select DistinguishedName,GroupCategory,GroupScope,Name,Members`
	* **User Rights Assignment**
		* Not every right listed here is important to us from a security standpoint as penetration testers or defenders, but ==some rights granted to an account can lead to unintended consequences such as privilege escalation or access to sensitive files.==
			* For example, let's say we can gain write access over a Group Policy Object (GPO) applied to an OU containing one or more users that we control. In this example, we could potentially leverage a tool such as [SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse) to assign targeted rights to a user. We may perform many actions in the domain to further our access with these new rights. A few examples include:
				* |`SeRemoteInteractiveLogonRight`|This privilege could give our target user the right to log onto a host via Remote Desktop (RDP), which could potentially be used to obtain sensitive data or escalate privileges.
				* |`SeBackupPrivilege`|This grants a user the ability to create system backups and could be used to obtain copies of sensitive system files that can be used to retrieve passwords such as the SAM and SYSTEM Registry hives and the NTDS.dit Active Directory database file.
				* |`SeDebugPrivilege`|This allows a user to debug and adjust the memory of a process. With this privilege, attackers could utilize a tool such as [Mimikatz](https://github.com/ParrotSec/mimikatz) to read the memory space of the Local System Authority (LSASS) process and obtain any credentials stored in memory.
				* |`SeImpersonatePrivilege`|This privilege allows us to impersonate a token of a privileged account such as `NT AUTHORITY\SYSTEM`. This could be leveraged with a tool such as JuicyPotato, RogueWinRM, PrintSpoofer, etc., to escalate privileges on a target system.
				* |`SeLoadDriverPrivilege`|A user with this privilege can load and unload device drivers that could potentially be used to escalate privileges or compromise a system.
			* |`SeTakeOwnershipPrivilege`|This allows a process to take ownership of an object. At its most basic level, we could use this privilege to gain access to a file share or a file on a share that was otherwise not accessible to us.
	* **Viewing a User's Privileges**
		* After logging into a host, typing the command `whoami /priv` will give us a listing of all user rights assigned to the current user. Some rights are only available to administrative users and can only be listed/leveraged when running an elevated CMD or PowerShell session.
		* These concepts of elevated rights and [User Account Control (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) are security features introduced with Windows Vista that default to restricting applications from running with full permissions unless absolutely necessary.
		* `whoami /priv`
* ## Security in Active Directory
	* When we think about cybersecurity, one of the first things that come up is the balance between **Confidentiality, Integrity, and Availability**, also known as the **CIA Triad**. Finding this balance is hard, and AD leans heavily toward Availability and Confidentiality at its core.
	* ![[Pasted image 20231215103143.png]]
	* Many other general security hardening principles must be in place within an organization to ensure a proper `defense-in-depth` approach (having an accurate asset inventory, vulnerability patches, configuration management, endpoint protection, security awareness training, network segmentation, etc.).
	* **General Active Directory Hardening Measures**
		* **LAPS** - [Microsoft Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.
			* free tool
		* **Audit Policy Settings (Logging and Monitoring)**
			* logging and monitoring setup to detect and react to unexpected changes or activities that may indicate an attack.
		* **Group Policy Security Settings**
			* Group Policy Objects (GPOs) are virtual collections of policy settings that can be applied to specific users, groups, and computers at the OU level. These can be used to apply a wide variety of [security policies](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/security-policy-settings) to help harden Active Directory. The following is a non-exhaustive list of the types of security policies that can be applied:
				* **Account Policies**
				* **Local Policies**
				* **Software Restriction Policies**
				* **Application Control Policies** (e.g. AppLocker)
				* **Advanced Audit Policy Configuration**
		* **Update Management (SCCM/WSUS)**
			* Proper patch management is critical for any organization, especially those running Windows/Active Directory systems.
			* The [Windows Server Update Service (WSUS)](https://docs.microsoft.com/en-us/windows-server/administration/windows-server-update-services/get-started/windows-server-update-services-wsus) can be installed as a role on a Windows Server and can be used to minimize the manual task of patching Windows systems.
			* `System Center Configuration Manager` (SCCM) is a paid solution that relies on the WSUS Windows Server role being installed and offers more features than WSUS on its own.
			* A patch management solution can help ensure timely deployment of patches and maximize coverage, making sure that no hosts miss critical security patches. If an organization relies on a manual method for applying patches, it could take a very long time depending on the size of the environment and also could result in systems being missed and left vulnerable.
		* **Group Managed Service Accounts (gMSA)**
			* an account managed by the domain that offers a higher level of security than other types of service accounts for use with non-interactive applications, services, processes, and tasks that are run automatically but require credentials to run.
			* They provide automatic password management with a 120 character password generated by the domain controller. The password is changed at a regular interval and does not need to be known by any user. It allows for credentials to be used across multiple hosts.
		* **Security Groups**
			* Security groups offer an easy way to assign access to network resources. They can be used to assign specific rights to the group (instead of directly to the user) to determine what members of the group can do within the AD environment.
			* Active Directory automatically creates some [default security groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#active-directory-default-security-groups-by-operating-system-version) during installation.
				* Some examples are Account Operators, Administrators, Backup Operators, Domain Admins, and Domain Users. These groups can also be used to assign permission to access resources (i.e., a file share, folder, printer, or a document).
			* Security groups help ensure you can assign granular permissions to users en masse instead of individually managing each user.
		* **Account Separation**
			* Administrators must have two separate accounts. One for their day-to-day work and a second for any administrative tasks they must perform.
				* For example, a user could log into their machine using their `sjones` account to send/receive an email, create documents, etc. They should have a separate account, such as `sjones_adm`, to access a [secure administrative host](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-secure-administrative-hosts) used to perform administrative tasks.
			* This can help ensure that if a user's host is compromised (through a phishing attack, for example), the attacker would be limited to that host and would not obtain credentials for a highly privileged user with considerable access within the domain.
			* It is also essential for the individual to use different passwords for each account to mitigate the risk of password reuse attacks if their non-admin account is compromised.
		* **Password Complexity Policies + Passphrases + 2FA**
			* Ideally, an organization should be using passphrases or large randomly generated passwords using an enterprise password manager.
			* The standard 7-8 character passwords can be ==cracked offline using a tool such as Hashcat very quickly with a GPU password cracking rig==. Shorter, less complex passwords may also be guessed through a password spraying attack, giving an attacker a foothold in the domain. Password complexity rules alone in AD are not enough to ensure strong passwords.
				* For example, the password `Welcome1` would meet the standard complexity rules (3 out of 4 of uppercase, lowercase, number, and special character) but would be one of the first passwords I would try in a password spraying attack.
			* An organization should also consider implementing a password filter to disallow passwords containing the months or seasons of the year, the company name, and common words such as `password` and `welcome`.
			* The minimum password length for standard users should be at least 12 characters and ideally longer for administrators/service accounts.
			* Another important security measure is the implementation of multi-factor authentication (MFA) for Remote Desktop Access to any host. This can help to limit lateral movement attempts that may rely on GUI access to a host.
		* **Limiting Domain Admin Account Usage**
			* All-powerful Domain Admin accounts should only be used to log in to Domain Controllers, not personal workstations, jump hosts, web servers, etc.
		* **Periodically Auditing and Removing Stale Users and Objects**
			* It is important for an organization to periodically audit Active Directory and remove or disable any unused accounts.
				* For example, there may be a privileged service account that was created eight years ago with a very weak password that was never changed, and the account is no longer in use. Even if the password policy had since been changed to be more resistant to attacks such as password spraying, an account such as this may be a quick and easy foothold or method for lateral movement or privilege escalation within the domain.
		* **Auditing Permissions and Access**
			* Organizations should also periodically perform access control audits to ensure that users only have the level of access required for their day-to-day work.
			* It is important to audit local admin rights, the number of Domain Admins (do we really need 30 of them?), and Enterprise Admins to limit the attack surface, file share access, user rights (i.e., membership in certain privileged security groups), and more.
		* **Audit Policies & Logging**
			* An organization can achieve this through robust logging and then using rules to detect anomalous activity (such as many failed login attempts that could be indicative of a password spraying attack) or indicators that a Kerberoasting attack is being attempted. These can also be used to detect Active Directory enumeration. It is worth familiarizing ourselves with Microsoft's [Audit Policy Recommendations](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations) to help detect compromise.
		* **Using Restricted Groups**
			* [Restricted Groups](https://social.technet.microsoft.com/wiki/contents/articles/20402.active-directory-group-policy-restricted-groups.aspx) allow for administrators to configure group membership via Group Policy.
			* They can be used for a number of reasons, such as controlling membership in the local administrator's group on all hosts in the domain by restricting it to just the local Administrator account and Domain Admins and controlling membership in the highly privileged Enterprise Admins and Schema Admins groups and other key administrative groups.
		* **Limiting Server Roles**
			* It is important not to install additional roles on sensitive hosts, such as installing the `Internet Information Server` (IIS) role on a Domain Controller.
			* This would increase the attack surface of the Domain Controller, and this type of role should be installed on a separate standalone web server.
				* Some other examples would be not hosting web applications on an Exchange mail server and separating web servers and database servers out to different hosts. This type of role separation can help to reduce the impact of a successful attack.
		* **Limiting Local Admin and RDP Rights**
			* Organizations should tightly control which users have local admin rights on which computers. As stated above, this can be achieved using Restricted Groups.
			* The same goes for Remote Desktop (RDP) rights. If many users can RDP to one or many machines, this increases the risk of sensitive data exposure or potential privilege escalation attacks, leading to further compromise.
* ## Examining Group Policy
	* Group Policy is a Windows feature that provides administrators with a wide array of advanced settings that can apply to both user and computer accounts in a Windows environment.
	* Every Windows host has a Local Group Policy editor to manage local settings.
	* Gaining rights over a Group Policy Object could lead to lateral movement, privilege escalation, and even full domain compromise if the attacker can leverage them in a way to take over a high-value user or computer. They can also be ==used as a way for an attacker to maintain persistence within a network.== Understanding how Group Policy works will give us a leg up against attackers and can help us greatly on penetration tests, sometimes finding nuanced misconfigurations that other penetration testers may miss.
	* **Group Policy Objects (GPO)**
		* A [Group Policy Object (GPO)](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects) is a virtual collection of policy settings that can be applied to `user(s)` or `computer(s)`.
		* GPOs include policies such as screen lock timeout, disabling USB ports, enforcing a custom domain password policy, installing software, managing applications, customizing remote access settings, and much more.
		* Every GPO has a unique name and is assigned a unique identifier (a GUID).
		* They can be linked to a specific OU, domain, or site. A single GPO can be linked to multiple containers, and any container can have multiple GPOs applied to it.
		* Examples:
			* Establishing different password policies for service accounts, admin accounts, and standard user accounts using separate GPOs
				* - Passwords must be at least 7 characters long.
				- Passwords must contain characters from at least three of the following four categories:
				    - Uppercase characters (A-Z)
				    - Lowercase characters (a-z)
				    - Numbers (0-9)
				    - Special characters (e.g. !@#$%^&*()_+|~-=`{}[]:";'<>?,./)
			- Preventing the use of removable media devices (such as USB devices)
			- Enforcing a screensaver with a password
			- Restricting access to applications that a standard user may not need, such as cmd.exe and PowerShell
			- Enforcing audit and logging policies
			- Blocking users from running certain types of programs and scripts
			- Deploying software across a domain
			- Blocking users from installing unapproved software
			- Displaying a logon banner whenever a user logs into a system
			- Disallowing LM hash usage in the domain
			- Running scripts when computers start/shutdown or when a user logs in/out of their machine
		- GPO settings are processed using the hierarchical structure of AD and are applied using the `Order of Precedence` rule as seen in the table below:
			- |`Local Group Policy`|The policies are defined directly to the host locally outside the domain. Any setting here will be overwritten if a similar setting is defined at a higher level.
			- |`Site Policy`|Any policies specific to the Enterprise Site that the host resides in. Remember that enterprise environments can span large campuses and even across countries. So it stands to reason that a site might have its own policies to follow that could differentiate it from the rest of the organization. Access Control policies are a great example of this. Say a specific building or `site` performs secret or restricted research and requires a higher level of authentication for access to resources. You could specify those settings at the site level and ensure they are linked so as not to be overwritten by domain policy. This is also a great way to perform actions like printer and share mapping for users in specific sites.
			- |`Domain-wide Policy`|Any settings you wish to have applied across the domain as a whole. For example, setting the password policy complexity level, configuring a Desktop background for all users, and setting a Notice of Use and Consent to Monitor banner at the login screen.
			- |`Organizational Unit` (OU)|These settings would affect users and computers who belong to specific OUs. You would want to place any unique settings here that are role-specific. For example, the mapping of a particular share drive that can only be accessed by HR, access to specific resources like printers, or the ability for IT admins to utilize PowerShell and command-prompt.
			- |`Any OU Policies nested within other OU's`|Settings at this level would reflect special permissions for objects within nested OUs. For example, providing Security Analysts a specific set of Applocker policy settings that differ from the standard IT Applocker settings.
			- ![[Pasted image 20231216085726.png]]
		- When more than one GPO is linked to an OU, they are processed based on the `Link Order`. The GPO with the lowest Link Order is processed last, or the GPO with link order 1 has the highest precedence, then 2, and 3, and so on.
		- It is possible to specify the `Enforced` option to enforce settings in a specific GPO. If this option is set, policy settings in GPOs linked to lower OUs `CANNOT` override the settings.
		- Regardless of which GPO is set to enforced, if the `Default Domain Policy` GPO is enforced, it will take precedence over all GPOs at all levels.
		* It is also possible to set the `Block inheritance` option on an OU. If this is specified for a particular OU, then policies higher up (such as at the domain level) will NOT be applied to this OU. If both options are set, the `No Override` option has precedence over the `Block inheritance` option.
	- **Group Policy Refresh Frequency**
		- When a new GPO is created, the settings are not automatically applied right away.
		- Windows performs periodic Group Policy updates, which by default is done every 90 minutes with a randomized offset of +/- 30 minutes for users and computers. The period is only 5 minutes for domain controllers to update by default.
		- When a new GPO is created and linked, it could take up to 2 hours (120 minutes) until the settings take effect. This random offset of +/- 30 minutes is set to avoid overwhelming domain controllers by having all clients request Group Policy from the domain controller simultaneously.
		- It is possible to change the default refresh interval within Group Policy itself. Furthermore, we can issue the command `gpupdate /force` to kick off the update process. This command will compare the GPOs currently applied on the machine against the domain controller and either modify or skip them depending on if they have changed since the last automatic update.
		- We can modify the refresh interval via Group Policy by clicking on `Computer Configuration --> Policies --> Administrative Templates --> System --> Group Policy` and selecting `Set Group Policy refresh interval for computers`. While it can be changed, it should not be set to occur too often, or it could cause network congestion leading to replication issues.
	- **Security Considerations of GPOs**
		- As mentioned earlier, GPOs can be used to carry out attacks. ==These attacks may include adding additional rights to a user account that we control, adding a local administrator to a host, or creating an immediate scheduled task to run a malicious command such as modifying group membership, adding a new admin account, establishing a reverse shell connection, or even installing targeted malware throughout a domain. ==
		- These attacks typically happen when a user has the rights required to modify a GPO that applies to an OU that contains either a user account that we control or a computer.
		- Below is an example of a ==GPO attack path identified using the [BloodHound](https://github.com/BloodHoundAD/BloodHound) tool. ==This example shows that the `Domain Users` group can modify the `Disconnect Idle RDP` GPO due to nested group membership. In this case, we would next look to see which OUs this GPO applies to and if we can leverage these rights to gain control over a high-value user (administrator or Domain Admin) or computer (server, DC, or critical host) and move laterally to escalate privileges within the domain.
		- ![[Pasted image 20231216090352.png]]
- ## AD Administration: Guided Lab Part I & II
	- Completed
	- Boxes to Pwn
		- [Active](https://youtu.be/jUc1J31DNdw)
		- [Resolute](https://www.youtube.com/watch?v=8KJebvmd1Fk)
		- [Forest](https://youtu.be/H9FcE_FMZio)
		- [Cascade](https://youtu.be/mr-fsVLoQGw)
	- Skill Paths
		- [Active Directory LDAP](https://academy.hackthebox.com/course/preview/active-directory-ldap)
		- [Active Directory PowerView](https://academy.hackthebox.com/course/preview/active-directory-powerview)
		- [Active Directory BloodHound](https://academy.hackthebox.com/course/preview/active-directory-bloodhound)
	- Pro Labs
		- [Dante](https://app.hackthebox.com/prolabs/overview/dante) Pro Lab
		- [Offshore](https://app.hackthebox.com/prolabs/overview/offshore) Pro Lab