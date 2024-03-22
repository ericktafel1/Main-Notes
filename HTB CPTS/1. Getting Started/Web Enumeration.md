* When performing service scanning, we will often run into web servers running on ports 80 and 443. Webservers host web applications (sometimes more than 1) which often provide a considerable attack surface and a very high-value target during a penetration test.

---
### Gobuster

* After discovering a web application, it is always worth checking to see if we can uncover any hidden files or directories on the webserver that are not intended for public access.
* We can use a tool such as [ffuf](https://github.com/ffuf/ffuf) or [GoBuster](https://github.com/OJ/gobuster) to perform this directory enumeration. Sometimes we will find hidden functionality or pages/directories exposing sensitive data that can be leveraged to access the web application or even remote code execution on the web server itself.

#### Directory/File Enumeration

* GoBuster is a versatile tool that allows for performing DNS, vhost, and directory brute-forcing. The tool has additional functionality, such as enumeration of public AWS S3 buckets. 
* The directory (and file) brute-forcing modes specified with the switch `dir`. Let us run a simple scan using the `dirb` `common.txt` wordlist.

`gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt`

* An HTTP status code of `200` reveals that the resource's request was successful, while a 403 HTTP status code indicates that we are forbidden to access the resource.
* A 301 status code indicates that we are being redirected, which is not a failure case.
* It is worth familiarizing ourselves with the various HTTP status codes, which can be found [here](https://en.wikipedia.org/wiki/List_of_HTTP_status_codes).
* The scan was completed successfully, and it identifies a WordPress installation at `/wordpress`. WordPress is the most commonly used CMS (Content Management System) and has an enormous potential attack surface. In this case, visiting `http://10.10.10.121/wordpress` in a browser reveals that WordPress is still in setup mode, which will allow us to gain remote code execution (RCE) on the server.

#### DNS Subdomain Enumeration

* There also may be essential resources hosted on subdomains, such as admin panels or applications with additional functionality that could be exploited.
* We can use `GoBuster` to enumerate available subdomains of a given domain using the `dns` flag to specify DNS mode. First, let us clone the SecLists GitHub [repo](https://github.com/danielmiessler/SecLists), which contains many useful lists for fuzzing and exploitation:

##### Install SecLists

`git clone https://github.com/danielmiessler/SecLists`

`sudo apt install seclists -y`

* Next, add a DNS Server such as 1.1.1.1 to the `/etc/resolv.conf` file. We will target the domain `inlanefreight.com`, the website for a fictional freight and logistics company.

`gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt`

* This scan reveals several interesting subdomains that we could examine further.

---
### Web Enumeration Tips

#### Banner Grabbing / Web Server Headers

* Web server headers provide a good picture of what is hosted on a web server. They can reveal the specific application framework in use, the authentication options, and whether the server is missing essential security options or has been misconfigured. We can use `cURL` to retrieve server header information from the command line. `cURL` is another essential addition to our penetration testing toolkit, and familiarity with its many options is encouraged.

`curl -IL https://www.inlanefreight.com`

* Another handy tool is [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness), which can be used to take screenshots of target web applications, fingerprint them, and identify possible default credentials.
#### Whatweb

* We can extract the version of web servers, supporting frameworks, and applications using the command-line tool `whatweb`. This information can help us pinpoint the technologies in use and begin to search for potential vulnerabilities.

`whatweb 10.10.10.121`

* `Whatweb` is a handy tool and contains much functionality to automate web application enumeration across a network.

`whatweb --no-errors 10.10.10.0/24`

#### Certificates

* SSL/TLS certificates are another potentially valuable source of information if HTTPS is in use. Browsing to `https://10.10.10.121/` and viewing the certificate reveals details, including the email address and company name. These could potentially be used to conduct a phishing attack if this is within the scope of an assessment.

#### Robots.txt

* It is common for websites to contain a `robots.txt` file, whose purpose is to instruct search engine web crawlers such as Googlebot which resources can and cannot be accessed for indexing.
* The `robots.txt` file can provide valuable information such as the location of private files and admin pages. In this case, we see that the `robots.txt` file contains two disallowed entries.
	* Navigating to `http://10.10.10.121/private` in a browser reveals a HTB admin login page.

#### Source Code

* It is also worth checking the source code for any web pages we come across. We can hit `[CTRL + U]` to bring up the source code window in a browser. This example reveals a developer comment containing credentials for a test account, which could be used to log in to the website.