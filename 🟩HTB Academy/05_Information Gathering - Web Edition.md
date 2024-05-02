___

The [information gathering](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/README) phase is the first step in every penetration test where we need to simulate external attackers without internal information from the target organization. This phase is crucial as poor and rushed information gathering could result in missing flaws that otherwise thorough enumeration would have uncovered.

![](https://academy.hackthebox.com/storage/modules/144/PT-process.png)

This phase helps us understand the attack surface, technologies used, and, in some cases, discover development environments or even forgotten and unmaintained infrastructure that can lead us to internal network access as they are usually less protected and monitored. Information gathering is typically an iterative process. As we discover assets (say, a subdomain or virtual host), we will need to fingerprint the technologies in use, look for hidden pages/directories, etc., which may lead us to discover another subdomain and start the process over again.

For example, we can think of it as stumbling across new subdomains during one of our penetration tests based on the SSL certificate. However, if we take a closer look at these subdomains, we will often see different technologies in use than the main company website. Subdomains and vhosts are used to present other information and perform other tasks that have been separated from the homepage. Therefore, it is essential to find out which technologies are used, what purpose they serve, and how they work. During this process, our objective is to identify as much information as we can from the following areas:

| Area | Description |
| --- | --- |
| Domains and Subdomains | Often, we are given a single domain or perhaps a list of domains and subdomains that belong to an organization. Many organizations do not have an accurate asset inventory and may have forgotten both domains and subdomains exposed externally. This is an essential part of the reconnaissance phase. We may come across various subdomains that map back to in-scope IP addresses, increasing the overall attack surface of our engagement (or bug bounty program). Hidden and forgotten subdomains may have old/vulnerable versions of applications or dev versions with additional functionality (a Python debugging console, for example). Bug bounty programs will often set the scope as something such as `*.inlanefreight.com`, meaning that all subdomains of `inlanefreight.com`, in this example, are in-scope (i.e., `acme.inlanefreight.com`, `admin.inlanefreight.com`, and so forth and so on). We may also discover subdomains of subdomains. For example, let's assume we discover something along the lines of `admin.inlanefreight.com`. We could then run further subdomain enumeration against this subdomain and perhaps find `dev.admin.inlanefreight.com` as a very enticing target. There are many ways to find subdomains (both passively and actively) which we will cover later in this module. |
| IP ranges | Unless we are constrained to a very specific scope, we want to find out as much about our target as possible. Finding additional IP ranges owned by our target may lead to discovering other domains and subdomains and open up our possible attack surface even wider. |
| Infrastructure | We want to learn as much about our target as possible. We need to know what technology stacks our target is using. Are their applications all ASP.NET? Do they use Django, PHP, Flask, etc.? What type(s) of APIs/web services are in use? Are they using Content Management Systems (CMS) such as WordPress, Joomla, Drupal, or DotNetNuke, which have their own types of vulnerabilities and misconfigurations that we may encounter? We also care about the web servers in use, such as IIS, Nginx, Apache, and the version numbers. If our target is running outdated frameworks or web servers, we want to dig deeper into the associated web applications. We are also interested in the types of back-end databases in use (MSSQL, MySQL, PostgreSQL, SQLite, Oracle, etc.) as this will give us an indication of the types of attacks we may be able to perform. |
| Virtual Hosts | Lastly, we want to enumerate virtual hosts (vhosts), which are similar to subdomains but indicate that an organization is hosting multiple applications on the same web server. We will cover vhost enumeration later in the module as well. |

We can break the information gathering process into two main categories:

| Category | Description |
| --- | --- |
| Passive information gathering | We do not interact directly with the target at this stage. Instead, we collect publicly available information using search engines, whois, certificate information, etc. The goal is to obtain as much information as possible to use as inputs to the active information gathering phase. |
| Active information gathering | We directly interact with the target at this stage. Before performing active information gathering, we need to ensure we have the required authorization to test. Otherwise, we will likely be engaging in illegal activities. Some of the techniques used in the active information gathering stage include port scanning, DNS enumeration, directory brute-forcing, virtual host enumeration, and web application crawling/spidering. |

It is crucial to keep the information that we collect well-organized as we will need various pieces of data as inputs for later phasing of the testing process. Depending on the type of assessment we are performing, we may need to include some of this enumeration data in our final report deliverable (such as an External Penetration Test). When writing up a bug bounty report, we will only need to include details relevant specifically to the bug we are reporting (i.e., a hidden subdomain that we discovered led to the disclosure of another subdomain that we leveraged to obtain remote code execution (RCE) against our target).

It is worth signing up for an account at [Hackerone](https://hackerone.com/bug-bounty-programs), perusing the program list, and choosing a few targets to reproduce all of the examples in this module. Practice makes perfect. Continuously practicing these techniques will help us hone our craft and make many of these information gathering steps second nature. As we become more comfortable with the tools and techniques shown throughout this module, we should develop our own, repeatable methodology. We may find that we like specific tools and command-line techniques for some phases of information gathering and discover different tools that we prefer for other phases. We may want to write out our own scripts to automate some of these phases as well.

___

## Moving On

Let's move on and discuss passive information gathering. For the module section examples and exercises, we will focus on Facebook, which has its own [bug bounty program](https://www.facebook.com/whitehat), [PayPal](https://hackerone.com/paypal?type=team), [Tesla](https://bugcrowd.com/tesla), and internal lab hosts. While performing the information gathering examples, we must be sure not to stray from the program scope, which lists in-scope and out-of-scope websites and applications and out-of-scope attacks such as physical security attacks, social engineering, the use of automated vulnerability scanners, man-in-the-middle attacks, etc.

---
## WHOIS #WHOIS

___

We can consider [WHOIS](https://en.wikipedia.org/wiki/WHOIS) as the "white pages" for domain names. It is a TCP-based transaction-oriented query/response protocol listening on TCP port 43 by default. We can use it for querying databases containing domain names, IP addresses, or autonomous systems and provide information services to Internet users. The protocol is defined in [RFC 3912](https://datatracker.ietf.org/doc/html/rfc3912). The first WHOIS directory was created in the early 1970s by [Elizabeth Feinler](https://en.wikipedia.org/wiki/Elizabeth_J._Feinler) and her team working out of Stanford University's Network Information Center (NIC). Together with her team, they created domains divided into categories based upon a computer's physical address. We can read more about the fascinating history of WHOIS [here](https://en.wikipedia.org/wiki/WHOIS#History).

The WHOIS domain lookups allow us to retrieve information about the domain name of an already registered domain. The [Internet Corporation of Assigned Names and Numbers](https://www.icann.org/get-started) (`ICANN`) requires that accredited registrars enter the holder's contact information, the domain's creation, and expiration dates, and other information in the Whois database immediately after registering a domain. In simple terms, the Whois database is a searchable list of all domains currently registered worldwide.

WHOIS lookups were initially performed using command-line tools. Nowadays, many web-based tools exist, but command-line options often give us the most control over our queries and help filter and sort the resultant output. [Sysinternals WHOIS](https://docs.microsoft.com/en-gb/sysinternals/downloads/whois) for Windows or Linux [WHOIS](https://linux.die.net/man/1/whois) command-line utility are our preferred tools for gathering information. However, there are some online versions like [whois.domaintools.com](https://whois.domaintools.com/) we can also use.

We would get the following response from the previous command to run a `whois` lookup against the `facebook.com` domain. An example of this `whois` command is:

WHOIS

```shell
6165@htb[/htb]$ export TARGET="facebook.com" # Assign our target to an environment variable
6165@htb[/htb]$ whois $TARGET

Domain Name: FACEBOOK.COM
Registry Domain ID: 2320948_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.registrarsafe.com
Registrar URL: https://www.registrarsafe.com
Updated Date: 2021-09-22T19:33:41Z
Creation Date: 1997-03-29T05:00:00Z
Registrar Registration Expiration Date: 2030-03-30T04:00:00Z
Registrar: RegistrarSafe, LLC
Registrar IANA ID: 3237
Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
Registrar Abuse Contact Phone: +1.6503087004
Domain Status: clientDeleteProhibited https://www.icann.org/epp#clientDeleteProhibited
Domain Status: clientTransferProhibited https://www.icann.org/epp#clientTransferProhibited
Domain Status: clientUpdateProhibited https://www.icann.org/epp#clientUpdateProhibited
Domain Status: serverDeleteProhibited https://www.icann.org/epp#serverDeleteProhibited
Domain Status: serverTransferProhibited https://www.icann.org/epp#serverTransferProhibited
Domain Status: serverUpdateProhibited https://www.icann.org/epp#serverUpdateProhibited
Registry Registrant ID:
Registrant Name: Domain Admin
Registrant Organization: Facebook, Inc.
Registrant Street: 1601 Willow Rd
Registrant City: Menlo Park
Registrant State/Province: CA
Registrant Postal Code: 94025
Registrant Country: US
Registrant Phone: +1.6505434800
Registrant Phone Ext:
Registrant Fax: +1.6505434800
Registrant Fax Ext:
Registrant Email: domain@fb.com
Registry Admin ID:
Admin Name: Domain Admin
Admin Organization: Facebook, Inc.
Admin Street: 1601 Willow Rd
Admin City: Menlo Park
Admin State/Province: CA
Admin Postal Code: 94025
Admin Country: US
Admin Phone: +1.6505434800
Admin Phone Ext:
Admin Fax: +1.6505434800
Admin Fax Ext:
Admin Email: domain@fb.com
Registry Tech ID:
Tech Name: Domain Admin
Tech Organization: Facebook, Inc.
Tech Street: 1601 Willow Rd
Tech City: Menlo Park
Tech State/Province: CA
Tech Postal Code: 94025
Tech Country: US
Tech Phone: +1.6505434800
Tech Phone Ext:
Tech Fax: +1.6505434800
Tech Fax Ext:
Tech Email: domain@fb.com
Name Server: C.NS.FACEBOOK.COM
Name Server: B.NS.FACEBOOK.COM
Name Server: A.NS.FACEBOOK.COM
Name Server: D.NS.FACEBOOK.COM
DNSSEC: unsigned

<SNIP>
```

We can gather the same data using `whois.exe` from Windows Sysinternals:

WHOIS

```cmd
C:\htb> whois.exe facebook.com

Whois v1.21 - Domain information lookup
Copyright (C) 2005-2019 Mark Russinovich
Sysinternals - www.sysinternals.com

Connecting to COM.whois-servers.net...

WHOIS Server: whois.registrarsafe.com
   Registrar URL: http://www.registrarsafe.com
   Updated Date: 2021-09-22T19:33:41Z
   Creation Date: 1997-03-29T05:00:00Z
   Registry Expiry Date: 2030-03-30T04:00:00Z
   Registrar: RegistrarSafe, LLC
   Registrar IANA ID: 3237
   Registrar Abuse Contact Email: abusecomplaints@registrarsafe.com
   Registrar Abuse Contact Phone: +1-650-308-7004
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited
   Domain Status: serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited
   Domain Status: serverTransferProhibited https://icann.org/epp#serverTransferProhibited
   Domain Status: serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited
   Name Server: A.NS.FACEBOOK.COM
   Name Server: B.NS.FACEBOOK.COM
   Name Server: C.NS.FACEBOOK.COM
   Name Server: D.NS.FACEBOOK.COM
   DNSSEC: unsigned
   URL of the ICANN Whois Inaccuracy Complaint Form: https://www.icann.org/wicf/
>>> Last update of whois database: 2021-10-11T06:03:10Z <<<

<SNIP>
```

From this output, we have gathered the following information:

|  |  |
| --- | --- |
| Organisation | Facebook, Inc. |
| Locations | US, 94025 Menlo Park, CA, 1601 Willo Rd |
| Domain Email address | domain@fb.com |
| Registrar Email address | abusecomplaints@registrarsafe.com |
| Phone number | +1.6505434800 |
| Language | English (US) |
| Registrar | RegistrarSafe, LLC |
| New Domain | fb.com |
| [DNSSEC](https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions) | [unsigned](https://aws.amazon.com/blogs/networking-and-content-delivery/configuring-dnssec-signing-and-validation-with-amazon-route-53) |
| Name servers | A.NS.FACEBOOK.COM |
|  | B.NS.FACEBOOK.COM |
|  | C.NS.FACEBOOK.COM |
|  | D.NS.FACEBOOK.COM |

Though none of this information on its own is enough for us to mount an attack, it is essential data that we want to note down for later.

---

