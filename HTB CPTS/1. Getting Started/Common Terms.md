* Some redundant information but noted for reference later if needed.
---
### What is a Shell

* `Shell` has a few meanings. On a Linux system, the shell is a program that takes input from the user via the keyboard and passes these commands to the operating system to perform a specific function. 
* More operating system types and versions have emerged along with the graphic user interface (GUI) to complement command-line interfaces (shell), such as the Linux terminal, Windows command-line (cmd.exe), and Windows PowerShell.
* Most Linux systems use a program called [Bash (Bourne Again Shell)](https://www.gnu.org/savannah-checkouts/gnu/bash/manual/bash.html) as a shell program to interact with the operating system. Bash is an enhanced version of [sh](https://man7.org/linux/man-pages/man1/sh.1p.html), the Unix systems' original shell program. Aside from `bash` there are also other shells, including but not limited to [Zsh](https://en.wikipedia.org/wiki/Z_shell), [Tcsh](https://en.wikipedia.org/wiki/Tcsh), [Ksh](https://en.wikipedia.org/wiki/KornShell), [Fish shell](https://en.wikipedia.org/wiki/Fish_(Unix_shell)), etc.
* We will often read about or hear others talking about "getting a shell" on a box (system). This means that the target host has been exploited, and we have obtained shell-level access (typically `bash` or `sh`) and can run commands interactively as if we are sitting logged in to the host. A shell may be obtained by exploiting a web application or network/service vulnerability or obtaining credentials and logging into the target host remotely. There are three main types of shell connections:

|**Shell Type**|**Description**|
|---|---|
|`Reverse shell`|Initiates a connection back to a "listener" on our attack box.|
|`Bind shell`|"Binds" to a specific port on the target host and waits for a connection from our attack box.|
|`Web shell`|Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a `PHP` script to run a single command.|

* Each type of shell has its use case, and the same way there are many ways to obtain a shell, the helper program that we use to get a shell can be written in many languages (`Python`, `Perl`, `Go`, `Bash`, `Java`, `awk`, `PHP`, etc.). 

---
### What is a Port?

* Ports are virtual points where network connections begin and end. They are software-based and managed by the host operating system. Ports are associated with a specific process or service and allow computers to differentiate between different traffic types (SSH traffic flows to a different port than web requests to access a website even though the access requests are sent over the same network connection).
* There are two categories of ports, [Transmission Control Protocol (TCP)](https://en.wikipedia.org/wiki/Transmission_Control_Protocol), and [User Datagram Protocol (UDP)](https://en.wikipedia.org/wiki/User_Datagram_Protocol).  
	* `TCP` is connection-oriented, meaning that a connection between a client and a server must be established before data can be sent. The server must be in a listening state awaiting connection requests from clients.  
	* `UDP` utilizes a connectionless communication model. There is no "handshake" and therefore introduces a certain amount of unreliability since there is no guarantee of data delivery. `UDP` is useful when error correction/checking is either not needed or is handled by the application itself. `UDP` is suitable for applications that run time-sensitive tasks since dropping packets is faster than waiting for delayed packets due to retransmission, as is the case with `TCP` and can significantly affect a real-time system. There are `65,535` `TCP` ports and `65,535` different `UDP` ports, each denoted by a number. Some of the most well-known `TCP` and `UDP` ports are listed below:

|Port(s)|Protocol|
|---|---|
|`20`/`21` (TCP)|`FTP`|
|`22` (TCP)|`SSH`|
|`23` (TCP)|`Telnet`|
|`25` (TCP)|`SMTP`|
|`80` (TCP)|`HTTP`|
|`161` (TCP/UDP)|`SNMP`|
|`389` (TCP/UDP)|`LDAP`|
|`443` (TCP)|`SSL`/`TLS` (`HTTPS`)|
|`445` (TCP)|`SMB`|
|`3389` (TCP)|`RDP`|

* Guides such as [this](https://www.stationx.net/common-ports-cheat-sheet/) and [this](https://packetlife.net/media/library/23/common-ports.pdf) are great resources for learning standard and less common TCP and UDP ports.

---
### What is a Web Server

* A web server is an application that runs on the back-end server, which handles all of the `HTTP` traffic from the client-side browser, routes it to the requests destination pages, and finally responds to the client-side browser.
* Many types of vulnerabilities can affect web applications. We will often hear about/see references to the [OWASP Top 10](https://owasp.org/www-project-top-ten/). This is a standardized list of the top 10 web application vulnerabilities maintained by the Open Web Application Security Project (OWASP). The current OWASP Top 10 list is:

|Number|Category|Description|
|---|---|---|
|1.|[Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)|Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc.|
|2.|[Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)|Failures related to cryptography which often leads to sensitive data exposure or system compromise.|
|3.|[Injection](https://owasp.org/Top10/A03_2021-Injection/)|User-supplied data is not validated, filtered, or sanitized by the application. Some examples of injections are SQL injection, command injection, LDAP injection, etc.|
|4.|[Insecure Design](https://owasp.org/Top10/A04_2021-Insecure_Design/)|These issues happen when the application is not designed with security in mind.|
|5.|[Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)|Missing appropriate security hardening across any part of the application stack, insecure default configurations, open cloud storage, verbose error messages which disclose too much information.|
|6.|[Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)|Using components (both client-side and server-side) that are vulnerable, unsupported, or out of date.|
|7.|[Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)|Authentication-related attacks that target user's identity, authentication, and session management.|
|8.|[Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)|Software and data integrity failures relate to code and infrastructure that does not protect against integrity violations. An example of this is where an application relies upon plugins, libraries, or modules from untrusted sources, repositories, and content delivery networks (CDNs).|
|9.|[Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)|This category is to help detect, escalate, and respond to active breaches. Without logging and monitoring, breaches cannot be detected..|
|10.|[Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)|SSRF flaws occur whenever a web application is fetching a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send a crafted request to an unexpected destination, even when protected by a firewall, VPN, or another type of network access control list (ACL).|
