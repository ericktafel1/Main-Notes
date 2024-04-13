## Enumeration Principles

___

Enumeration is a widely used term in cyber security. It stands for information gathering using active (scans) and passive (use of third-party providers) methods. It is important to note that OSINT is an independent procedure and should be performed separately from enumeration because `OSINT is based exclusively on passive information gathering` and does not involve active enumeration of the given target. Enumeration is a loop in which we repeatedly gather information based on what data we have or have already discovered.

Information can be gathered from domains, IP addresses, accessible services, and many other sources.

Once we have identified targets in our client's infrastructure, we need to examine the individual services and protocols. In most cases, these are services that enable communication between customers, the infrastructure, the administration, and the employees.

If we imagine that we have been hired to investigate the IT security of a company, we will start to develop a general understanding of the company's functionality. For example, we need to understand how the company is structured, what services and third-party vendors it uses, what security measures may be in place, and more. This is where this stage can be a bit misunderstood because most people focus on the obvious and try to force their way into the company's systems instead of understanding how the infrastructure is set up and what technical aspects and services are necessary to be able to offer a specific service.

An example of such a wrong approach could be that after finding authentication services like SSH, RDP, WinRM, and the like, we try to brute-force with common/weak passwords and usernames. Unfortunately, brute-forcing is a noisy method and can easily lead to blacklisting, making further testing impossible. Primarily, this can happen if we do not know about the company's defensive security measures and its infrastructure. Some may smile at this approach, but experience has shown that far too many testers take this type of approach.

`Our goal is not to get at the systems but to find all the ways to get there.`

We can think of this as an analogy of a treasure hunter preparing for his expedition. He would not just grab a shovel and start digging in some random spot, but he would plan and gather his gear and study maps and learn about the terrain he has to cover and where the treasure may be so he can bring the proper tools. If he goes around digging holes everywhere, he will cause damage, waste time and energy, and likely never achieve his goal. The same can be said for understanding a company's internal and external infrastructure, mapping it out, and carefully formulating our plan of attack.

The enumeration principles are based on some questions that will facilitate all our investigations in any conceivable situation. In most cases, the main focus of many penetration testers is on what they can see and not on what they cannot see. However, even what we cannot see is relevant to us and may well be of great importance. The difference here is that we start to see the components and aspects that are not visible at first glance with our experience.

-   What can we see?
-   What reasons can we have for seeing it?
-   What image does what we see create for us?
-   What do we gain from it?
-   How can we use it?
-   What can we not see?
-   What reasons can there be that we do not see?
-   What image results for us from what we do not see?

An important aspect that must not be confused here is that there are always exceptions to the rules. The principles, however, do not change. Another advantage of these principles is that we can see from the practical tasks that we do not lack penetration testing abilities but technical understanding when we suddenly do not know how to proceed because our core task is not to exploit the machines but to find how they can be exploited.

| **`No.`** | **`Principle`** |
| --- | --- |
| 1. | There is more than meets the eye. Consider all points of view. |
| 2. | Distinguish between what we see and what we do not see. |
| 3. | There are always ways to gain more information. Understand the target. |

To familiarize ourselves with these principles, we should write down these questions and principles where we can always see them and refer back to them with ease.

---
## Enumeration Methodology

___

Complex processes must have a standardized methodology that helps us keep our bearings and avoid omitting any aspects by mistake. Especially with the variety of cases that the target systems can offer us, it is almost unpredictable how our approach should be designed. Therefore, most penetration testers follow their habits and the steps they feel most comfortable and familiar with. However, this is not a standardized methodology but rather an experience-based approach.

We know that penetration testing, and therefore enumeration, is a dynamic process. Consequently, we have developed a static enumeration methodology for external and internal penetration tests that includes free dynamics and allows for a wide range of changes and adaptations to the given environment. This methodology is nested in 6 layers and represents, metaphorically speaking, boundaries that we try to pass with the enumeration process. The whole enumeration process is divided into three different levels:

| `Infrastructure-based enumeration` | `Host-based enumeration` | `OS-based enumeration` |
| --- | --- | --- |

![image](https://academy.hackthebox.com/storage/modules/112/enum-method3.png)

Note: The components of each layer shown represent the main categories and not a full list of all the components to search for. Additionally, it must be mentioned here that the first and second layer (Internet Presence, Gateway) does not quite apply to the intranet, such as an Active Directory infrastructure. The layers for internal infrastructure will be covered in other modules.

Consider these lines as some kind of obstacle, like a wall, for example. What we do here is look around to find out where the entrance is, or the gap we can fit through, or climb over to get closer to our goal. Theoretically, it is also possible to go through the wall headfirst, but very often, it happens that the spot we have smashed the gap with a lot of effort and time with force does not bring us much because there is no entry at this point of the wall to pass on to the next wall.

These layers are designed as follows:

| **Layer** | **Description** | **Information Categories** |
| --- | --- | --- |
| `1. Internet Presence` | Identification of internet presence and externally accessible infrastructure. | Domains, Subdomains, vHosts, ASN, Netblocks, IP Addresses, Cloud Instances, Security Measures |
| `2. Gateway` | Identify the possible security measures to protect the company's external and internal infrastructure. | Firewalls, DMZ, IPS/IDS, EDR, Proxies, NAC, Network Segmentation, VPN, Cloudflare |
| `3. Accessible Services` | Identify accessible interfaces and services that are hosted externally or internally. | Service Type, Functionality, Configuration, Port, Version, Interface |
| `4. Processes` | Identify the internal processes, sources, and destinations associated with the services. | PID, Processed Data, Tasks, Source, Destination |
| `5. Privileges` | Identification of the internal permissions and privileges to the accessible services. | Groups, Users, Permissions, Restrictions, Environment |
| `6. OS Setup` | Identification of the internal components and systems setup. | OS Type, Patch Level, Network config, OS Environment, Configuration files, sensitive private files |

Important note: The human aspect and the information that can be obtained by employees using OSINT have been removed from the "Internet Presence" layer for simplicity.

We can finally imagine the entire penetration test in the form of a labyrinth where we have to identify the gaps and find the way to get us inside as quickly and effectively as possible. This type of labyrinth may look something like this:

![image](https://academy.hackthebox.com/storage/modules/112/pentest-labyrinth.png)

The squares represent the gaps/vulnerabilities.

As we have probably already noticed, we can see that we will encounter one gap and very likely several. The interesting and very common fact is that not all the gaps we find can lead us inside. All penetration tests are limited in time, but we should always keep in mind that one belief that there is nearly always a way in. Even after a four-week penetration test, we cannot say 100% that there are no more vulnerabilities. Someone who has been studying the company for months and analyzing them will most likely have a much greater understanding of the applications and structure than we were able to gain within the few weeks we spent on the asessment. An excellent and recent example of this is the [cyber attack on SolarWinds](https://www.rpc.senate.gov/policy-papers/the-solarwinds-cyberattack), which happened not too long ago. This is another excellent reason for a methodology that must exclude such cases.

Let us assume that we have been asked to perform an external "black box" penetration test. Once all the necessary contract items have been completely fulfilled, our penetration test will begin at the specified time.

___

## Layer No.1: Internet Presence

The first layer we have to pass is the "Internet Presence" layer, where we focus on finding the targets we can investigate. If the scope in the contract allows us to look for additional hosts, this layer is even more critical than for fixed targets only. In this layer, we use different techniques to find domains, subdomains, netblocks, and many other components and information that present the presence of the company and its infrastructure on the Internet.

`The goal of this layer is to identify all possible target systems and interfaces that can be tested.`

___

## Layer No.2: Gateway

Here we try to understand the interface of the reachable target, how it is protected, and where it is located in the network. Due to the diversity, different functionalities, and some particular procedures, we will go into more detail about this layer in other modules.

`The goal is to understand what we are dealing with and what we have to watch out for.`

___

## Layer No.3: Accessible Services

In the case of accessible services, we examine each destination for all the services it offers. Each of these services has a specific purpose that has been installed for a particular reason by the administrator. Each service has certain functions, which therefore also lead to specific results. To work effectively with them, we need to know how they work. Otherwise, we need to learn to understand them.

`This layer aims to understand the reason and functionality of the target system and gain the necessary knowledge to communicate with it and exploit it for our purposes effectively.`

This is the part of enumeration we will mainly deal with in this module.

___

## Layer No.4: Processes

Every time a command or function is executed, data is processed, whether entered by the user or generated by the system. This starts a process that has to perform specific tasks, and such tasks have at least one source and one target.

`The goal here is to understand these factors and identify the dependencies between them.`

___

## Layer No.5: Privileges

Each service runs through a specific user in a particular group with permissions and privileges defined by the administrator or the system. These privileges often provide us with functions that administrators overlook. This often happens in Active Directory infrastructures and many other case-specific administration environments and servers where users are responsible for multiple administration areas.

`It is crucial to identify these and understand what is and is not possible with these privileges.`

___

## Layer No.6: OS Setup

Here we collect information about the actual operating system and its setup using internal access. This gives us a good overview of the internal security of the systems and reflects the skills and capabilities of the company's administrative teams.

`The goal here is to see how the administrators manage the systems and what sensitive internal information we can glean from them.`

___

## Enumeration Methodology in Practice

A methodology summarizes all systematic procedures in obtaining knowledge within the bounds of a given objective. It is important to note that a methodology is not a step-by-step guide but, as the definition implies, a summary of systematic procedures. In our case, the enumeration methodology is the systematic approach to explore a given target.

How the individual components are identified and information obtained in this methodology is a dynamic and growing aspect that is constantly changing and can therefore differ. An excellent example of this is using information-gathering tools from web servers. There are countless different tools for this, and each of them has a specific focus and therefore delivers individual results that differ from other applications. The goal, however, is the same. Thus, the collection of tools and commands is not part of the actual methodology but rather a cheat sheet that we can refer to using the commands and tools listed in given cases.

---
## Domain Information

___

Domain information is a core component of any penetration test, and it is not just about the subdomains but about the entire presence on the Internet. Therefore, we gather information and try to understand the company's functionality and which technologies and structures are necessary for services to be offered successfully and efficiently.

This type of information is gathered passively without direct and active scans. In other words, we remain hidden and navigate as "customers" or "visitors" to avoid direct connections to the company that could expose us. The OSINT relevant sections are only a tiny part of how in-depth OSINT goes and describe only a few of the many ways to obtain information in this way. More approaches and strategies for this can be found in the module [OSINT: Corporate Recon](https://academy.hackthebox.com/course/preview/osint-corporate-recon).

However, when `passively` gathering information, we can use third-party services to understand the company better. However, the first thing we should do is scrutinize the company's `main website`. Then, we should read through the texts, keeping in mind what technologies and structures are needed for these services.

For example, many IT companies offer app development, IoT, hosting, data science, and IT security services, depending on their industry. If we encounter a service that we have had little to do with before, it makes sense and is necessary to get to grips with it and find out what activities it consists of and what opportunities are available. Those services also give us a good overview of how the company can be structured.

For example, this part is the combination between the `first principle` and the `second principle` of enumeration. We pay attention to what `we see` and `we do not see`. We see the services but not their functionality. However, services are bound to certain technical aspects necessary to provide a service. Therefore, we take the developer's view and look at the whole thing from their point of view. This point of view allows us to gain many technical insights into the functionality.

___

## Online Presence

Once we have a basic understanding of the company and its services, we can get a first impression of its presence on the Internet. Let us assume that a medium-sized company has hired us to test their entire infrastructure from a black-box perspective. This means we have only received a scope of targets and must obtain all further information ourselves.

Note: Please remember that the examples below will differ from the practical exercises and will not give the same results. However, the examples are based on real penetration tests and illustrate how and what information can be obtained.

The first point of presence on the Internet may be the `SSL certificate` from the company's main website that we can examine. Often, such a certificate includes more than just a subdomain, and this means that the certificate is used for several domains, and these are most likely still active.

![](https://academy.hackthebox.com/storage/modules/112/DomInfo-1.png)

Another source to find more subdomains is [crt.sh](https://crt.sh/). This source is [Certificate Transparency](https://en.wikipedia.org/wiki/Certificate_Transparency) logs. Certificate Transparency is a process that is intended to enable the verification of issued digital certificates for encrypted Internet connections. The standard ([RFC 6962](https://tools.ietf.org/html/rfc6962)) provides for the logging of all digital certificates issued by a certificate authority in audit-proof logs. This is intended to enable the detection of false or maliciously issued certificates for a domain. SSL certificate providers like [Let's Encrypt](https://letsencrypt.org/) share this with the web interface [crt.sh](https://crt.sh/), which stores the new entries in the database to be accessed later.

![](https://academy.hackthebox.com/storage/modules/112/DomInfo-2.png)

We can also output the results in JSON format.

#### Certificate Transparency

Domain Information

```shell
6165@htb[/htb]$ curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq .

[
  {
    "issuer_ca_id": 23451835427,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "matomo.inlanefreight.com",
    "name_value": "matomo.inlanefreight.com",
    "id": 50815783237226155,
    "entry_timestamp": "2021-08-21T06:00:17.173",
    "not_before": "2021-08-21T05:00:16",
    "not_after": "2021-11-19T05:00:15",
    "serial_number": "03abe9017d6de5eda90"
  },
  {
    "issuer_ca_id": 6864563267,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "matomo.inlanefreight.com",
    "name_value": "matomo.inlanefreight.com",
    "id": 5081529377,
    "entry_timestamp": "2021-08-21T06:00:16.932",
    "not_before": "2021-08-21T05:00:16",
    "not_after": "2021-11-19T05:00:15",
    "serial_number": "03abe90104e271c98a90"
  },
  {
    "issuer_ca_id": 113123452,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
    "common_name": "smartfactory.inlanefreight.com",
    "name_value": "smartfactory.inlanefreight.com",
    "id": 4941235512141012357,
    "entry_timestamp": "2021-07-27T00:32:48.071",
    "not_before": "2021-07-26T23:32:47",
    "not_after": "2021-10-24T23:32:45",
    "serial_number": "044bac5fcc4d59329ecbbe9043dd9d5d0878"
  },
  { ... SNIP ...
```

If needed, we can also have them filtered by the unique subdomains.

Domain Information

```shell
6165@htb[/htb]$ curl -s https://crt.sh/\?q\=inlanefreight.com\&output\=json | jq . | grep name | cut -d":" -f2 | grep -v "CN=" | cut -d'"' -f2 | awk '{gsub(/\\n/,"\n");}1;' | sort -u

account.ttn.inlanefreight.com
blog.inlanefreight.com
bots.inlanefreight.com
console.ttn.inlanefreight.com
ct.inlanefreight.com
data.ttn.inlanefreight.com
*.inlanefreight.com
inlanefreight.com
integrations.ttn.inlanefreight.com
iot.inlanefreight.com
mails.inlanefreight.com
marina.inlanefreight.com
marina-live.inlanefreight.com
matomo.inlanefreight.com
next.inlanefreight.com
noc.ttn.inlanefreight.com
preview.inlanefreight.com
shop.inlanefreight.com
smartfactory.inlanefreight.com
ttn.inlanefreight.com
vx.inlanefreight.com
www.inlanefreight.com
```

Next, we can identify the hosts directly accessible from the Internet and not hosted by third-party providers. This is because we are not allowed to test the hosts without the permission of third-party providers.

#### Company Hosted Servers

Domain Information

```shell
6165@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done

blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```

Once we see which hosts can be investigated further, we can generate a list of IP addresses with a minor adjustment to the `cut` command and run them through `Shodan`.

[Shodan](https://www.shodan.io/) can be used to find devices and systems permanently connected to the Internet like `Internet of Things` (`IoT`). It searches the Internet for open TCP/IP ports and filters the systems according to specific terms and criteria. For example, open HTTP or HTTPS ports and other server ports for `FTP`, `SSH`, `SNMP`, `Telnet`, `RTSP`, or `SIP` are searched. As a result, we can find devices and systems, such as `surveillance cameras`, `servers`, `smart home systems`, `industrial controllers`, `traffic lights` and `traffic controllers`, and various network components.

#### Shodan - IP List

Domain Information

```shell
6165@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f4 >> ip-addresses.txt;done
6165@htb[/htb]$ for i in $(cat ip-addresses.txt);do shodan host $i;done

10.129.24.93
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-09-01T09:02:11.370085
Number of open ports:    2

Ports:
     80/tcp nginx 
    443/tcp nginx 
	
10.129.27.33
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-08-30T22:25:31.572717
Number of open ports:    3

Ports:
     22/tcp OpenSSH (7.6p1 Ubuntu-4ubuntu0.3)
     80/tcp nginx 
    443/tcp nginx 
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, -TLSv1.3, TLSv1.2
        |-- Diffie-Hellman Parameters:
                Bits:          2048
                Generator:     2
				
10.129.27.22
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-09-01T15:39:55.446281
Number of open ports:    8

Ports:
     25/tcp  
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
     53/tcp  
     53/udp  
     80/tcp Apache httpd 
     81/tcp Apache httpd 
    110/tcp  
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2
    111/tcp  
    443/tcp Apache httpd 
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, TLSv1.2, TLSv1.3
        |-- Diffie-Hellman Parameters:
                Bits:          2048
                Generator:     2
                Fingerprint:   RFC3526/Oakley Group 14
    444/tcp  
		
10.129.27.33
City:                    Berlin
Country:                 Germany
Organization:            InlaneFreight
Updated:                 2021-08-30T22:25:31.572717
Number of open ports:    3

Ports:
     22/tcp OpenSSH (7.6p1 Ubuntu-4ubuntu0.3)
     80/tcp nginx 
    443/tcp nginx 
        |-- SSL Versions: -SSLv2, -SSLv3, -TLSv1, -TLSv1.1, -TLSv1.3, TLSv1.2
        |-- Diffie-Hellman Parameters:
                Bits:          2048
                Generator:     2
```

We remember the IP `10.129.27.22` (`matomo.inlanefreight.com`) for later active investigations we want to perform. Now, we can display all the available DNS records where we might find more hosts.

#### DNS Records

Domain Information

```shell
6165@htb[/htb]$ dig any inlanefreight.com

; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 52058
;; flags: qr rd ra; QUERY: 1, ANSWER: 17, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 65494
;; QUESTION SECTION:
;inlanefreight.com.             IN      ANY

;; ANSWER SECTION:
inlanefreight.com.      300     IN      A       10.129.27.33
inlanefreight.com.      300     IN      A       10.129.95.250
inlanefreight.com.      3600    IN      MX      1 aspmx.l.google.com.
inlanefreight.com.      3600    IN      MX      10 aspmx2.googlemail.com.
inlanefreight.com.      3600    IN      MX      10 aspmx3.googlemail.com.
inlanefreight.com.      3600    IN      MX      5 alt1.aspmx.l.google.com.
inlanefreight.com.      3600    IN      MX      5 alt2.aspmx.l.google.com.
inlanefreight.com.      21600   IN      NS      ns.inwx.net.
inlanefreight.com.      21600   IN      NS      ns2.inwx.net.
inlanefreight.com.      21600   IN      NS      ns3.inwx.eu.
inlanefreight.com.      3600    IN      TXT     "MS=ms92346782372"
inlanefreight.com.      21600   IN      TXT     "atlassian-domain-verification=IJdXMt1rKCy68JFszSdCKVpwPN"
inlanefreight.com.      3600    IN      TXT     "google-site-verification=O7zV5-xFh_jn7JQ31"
inlanefreight.com.      300     IN      TXT     "google-site-verification=bow47-er9LdgoUeah"
inlanefreight.com.      3600    IN      TXT     "google-site-verification=gZsCG-BINLopf4hr2"
inlanefreight.com.      3600    IN      TXT     "logmein-verification-code=87123gff5a479e-61d4325gddkbvc1-b2bnfghfsed1-3c789427sdjirew63fc"
inlanefreight.com.      300     IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.24.8 ip4:10.129.27.2 ip4:10.72.82.106 ~all"
inlanefreight.com.      21600   IN      SOA     ns.inwx.net. hostmaster.inwx.net. 2021072600 10800 3600 604800 3600

;; Query time: 332 msec
;; SERVER: 127.0.0.53#53(127.0.0.53)
;; WHEN: Mi Sep 01 18:27:22 CEST 2021
;; MSG SIZE  rcvd: 940
```

Let us look at what we have learned here and come back to our principles. We see an IP record, some mail servers, some DNS servers, TXT records, and an SOA record.

-   `A` records: We recognize the IP addresses that point to a specific (sub)domain through the A record. Here we only see one that we already know.
    
-   `MX` records: The mail server records show us which mail server is responsible for managing the emails for the company. Since this is handled by google in our case, we should note this and skip it for now.
    
-   `NS` records: These kinds of records show which name servers are used to resolve the FQDN to IP addresses. Most hosting providers use their own name servers, making it easier to identify the hosting provider.
    
-   `TXT` records: this type of record often contains verification keys for different third-party providers and other security aspects of DNS, such as [SPF](https://datatracker.ietf.org/doc/html/rfc7208), [DMARC](https://datatracker.ietf.org/doc/html/rfc7489), and [DKIM](https://datatracker.ietf.org/doc/html/rfc6376), which are responsible for verifying and confirming the origin of the emails sent. Here we can already see some valuable information if we look closer at the results.
    

Domain Information

```shell
...SNIP... TXT     "MS=ms92346782372"
...SNIP... TXT     "atlassian-domain-verification=IJdXMt1rKCy68JFszSdCKVpwPN"
...SNIP... TXT     "google-site-verification=O7zV5-xFh_jn7JQ31"
...SNIP... TXT     "google-site-verification=bow47-er9LdgoUeah"
...SNIP... TXT     "google-site-verification=gZsCG-BINLopf4hr2"
...SNIP... TXT     "logmein-verification-code=87123gff5a479e-61d4325gddkbvc1-b2bnfghfsed1-3c789427sdjirew63fc"
...SNIP... TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.24.8 ip4:10.129.27.2 ip4:10.72.82.106 ~all"
```

What we could see so far were entries on the DNS server, which at first glance did not look very interesting (except for the additional IP addresses). However, we could not see the third-party providers behind the entries shown at first glance. The core information we can see now:

For example, [Atlassian](https://www.atlassian.com/) states that the company uses this solution for software development and collaboration. If we are not familiar with this platform, we can try it for free to get acquainted with it.

[Google Gmail](https://www.google.com/gmail/) indicates that Google is used for email management. Therefore, it can also suggest that we could access open GDrive folders or files with a link.

[LogMeIn](https://www.logmein.com/) is a central place that regulates and manages remote access on many different levels. However, the centralization of such operations is a double-edged sword. If access as an administrator to this platform is obtained (e.g., through password reuse), one also has complete access to all systems and information.

[Mailgun](https://www.mailgun.com/) offers several email APIs, SMTP relays, and webhooks with which emails can be managed. This tells us to keep our eyes open for API interfaces that we can then test for various vulnerabilities such as IDOR, SSRF, POST, PUT requests, and many other attacks.

[Outlook](https://outlook.live.com/owa/) is another indicator for document management. Companies often use Office 365 with OneDrive and cloud resources such as Azure blob and file storage. Azure file storage can be very interesting because it works with the SMB protocol.

The last thing we see is [INWX](https://www.inwx.com/en). This company seems to be a hosting provider where domains can be purchased and registered. The TXT record with the "MS" value is often used to confirm the domain. In most cases, it is similar to the username or ID used to log in to the management platform.

---
## Cloud Resources

___

The use of cloud, such as [AWS](https://aws.amazon.com/), [GCP](https://cloud.google.com/), [Azure](https://azure.microsoft.com/en-us/), and others, is now one of the essential components for many companies nowadays. After all, all companies want to be able to do their work from anywhere, so they need a central point for all management. This is why services from `Amazon` (`AWS`), `Google` (`GCP`), and `Microsoft` (`Azure`) are ideal for this purpose.

Even though cloud providers secure their infrastructure centrally, this does not mean that companies are free from vulnerabilities. The configurations made by the administrators may nevertheless make the company's cloud resources vulnerable. This often starts with the `S3 buckets` (AWS), `blobs` (Azure), `cloud storage` (GCP), which can be accessed without authentication if configured incorrectly.

#### Company Hosted Servers

Cloud Resources

```shell
6165@htb[/htb]$ for i in $(cat subdomainlist);do host $i | grep "has address" | grep inlanefreight.com | cut -d" " -f1,4;done

blog.inlanefreight.com 10.129.24.93
inlanefreight.com 10.129.27.33
matomo.inlanefreight.com 10.129.127.22
www.inlanefreight.com 10.129.127.33
s3-website-us-west-2.amazonaws.com 10.129.95.250
```

Often cloud storage is added to the DNS list when used for administrative purposes by other employees. This step makes it much easier for the employees to reach and manage them. Let us stay with the case that a company has contracted us, and during the IP lookup, we have already seen that one IP address belongs to the `s3-website-us-west-2.amazonaws.com` server.

However, there are many different ways to find such cloud storage. One of the easiest and most used is Google search combined with Google Dorks. For example, we can use the Google Dorks `inurl:` and `intext:` to narrow our search to specific terms. In the following example, we see red censored areas containing the company name.

#### Google Search for AWS

![](https://academy.hackthebox.com/storage/modules/112/gsearch1.png)

#### Google Search for Azure

![](https://academy.hackthebox.com/storage/modules/112/gsearch2.png)

Here we can already see that the links presented by Google contain PDFs. When we search for a company that we may already know or want to know, we will also come across other files such as text documents, presentations, codes, and many others.

Such content is also often included in the source code of the web pages, from where the images, JavaScript codes, or CSS are loaded. This procedure often relieves the web server and does not store unnecessary content.

#### Target Website - Source Code

![](https://academy.hackthebox.com/storage/modules/112/cloud3.png)

Third-party providers such as [domain.glass](https://domain.glass/) can also tell us a lot about the company's infrastructure. As a positive side effect, we can also see that Cloudflare's security assessment status has been classified as "Safe". This means we have already found a security measure that can be noted for the second layer (gateway).

#### Domain.Glass Results

![](https://academy.hackthebox.com/storage/modules/112/cloud1.png)

Another very useful provider is [GrayHatWarfare](https://buckets.grayhatwarfare.com/). We can do many different searches, discover AWS, Azure, and GCP cloud storage, and even sort and filter by file format. Therefore, once we have found them through Google, we can also search for them on GrayHatWarefare and passively discover what files are stored on the given cloud storage.

#### GrayHatWarfare Results

![](https://academy.hackthebox.com/storage/modules/112/cloud2.png)

Many companies also use abbreviations of the company name, which are then used accordingly within the IT infrastructure. Such terms are also part of an excellent approach to discovering new cloud storage from the company. We can also search for files simultaneously to see the files that can be accessed at the same time.

#### Private and Public SSH Keys Leaked

![](https://academy.hackthebox.com/storage/modules/112/ghw1.png)

Sometimes when employees are overworked or under high pressure, mistakes can be fatal for the entire company. These errors can even lead to SSH private keys being leaked, which anyone can download and log onto one or even more machines in the company without using a password.

#### SSH Private Key

![](https://academy.hackthebox.com/storage/modules/112/ghw2.png)

---
## Staff

___

Searching for and identifying employees on social media platforms can also reveal a lot about the teams' infrastructure and makeup. This, in turn, can lead to us identifying which technologies, programming languages, and even software applications are being used. To a large extent, we will also be able to assess each person's focus based on their skills. The posts and material shared with others are also a great indicator of what the person is currently engaged in and what that person currently feels is important to share with others.

Employees can be identified on various business networks such as [LinkedIn](https://www.linkedin.com/) or [Xing](https://www.xing.de/). Job postings from companies can also tell us a lot about their infrastructure and give us clues about what we should be looking for.

#### LinkedIn - Job Post

Code: txt

```txt
Required Skills/Knowledge/Experience:

* 3-10+ years of experience on professional software development projects.

« An active US Government TS/SCI Security Clearance (current SSBI) or eligibility to obtain TS/SCI within nine months.
« Bachelor's degree in computer science/computer engineering with an engineering/math focus or another equivalent field of discipline.
« Experience with one or more object-oriented languages (e.g., Java, C#, C++).
« Experience with one or more scripting languages (e.g., Python, Ruby, PHP, Perl).
« Experience using SQL databases (e.g., PostgreSQL, MySQL, SQL Server, Oracle).
« Experience using ORM frameworks (e.g., SQLAIchemy, Hibernate, Entity Framework).
« Experience using Web frameworks (e.g., Flask, Django, Spring, ASP.NET MVC).
« Proficient with unit testing and test frameworks (e.g., pytest, JUnit, NUnit, xUnit).
« Service-Oriented Architecture (SOA)/microservices & RESTful API design/implementation.
« Familiar and comfortable with Agile Development Processes.
« Familiar and comfortable with Continuous Integration environments.
« Experience with version control systems (e.g., Git, SVN, Mercurial, Perforce).

Desired Skills/Knowledge/ Experience:

« CompTIA Security+ certification (or equivalent).
« Experience with Atlassian suite (Confluence, Jira, Bitbucket).
« Algorithm Development (e.g., Image Processing algorithms).
« Software security.
« Containerization and container orchestration (Docker, Kubernetes, etc.)
« Redis.
« NumPy.
```

From a job post like this, we can see, for example, which programming languages are preferred: `Java, C#, C++, Python, Ruby, PHP, Perl`. It also required that the applicant be familiar with different databases, such as: `PostgreSQL, Mysql, and Oracle`. In addition, we know that different frameworks are used for web application development, such as: `Flask, Django, ASP.NET, Spring`.

Furthermore, we use `REST APIs, Github, SVN, and Perforce`. The job offer also results that the company works with Atlassian Suite, and therefore there may be resources that we could potentially access. We can see some skills and projects from the career history that give us a reasonable estimate of the employee's knowledge.

#### LinkedIn - Employee #1 About

![](https://academy.hackthebox.com/storage/modules/112/linkedin-pers2.png)

We try to make business contacts on social media sites and prove to visitors what skills we bring to the table, which inevitably leads to us sharing with the public what we know and what we have learned so far. Companies always hire employees whose skills they can use and apply to the business. For example, we know that Flask and Django are web frameworks for the Python programming language.

If we do a little search for Django security misconfigurations, we will eventually come across the following [Github repository](https://github.com/boomcamp/django-security) that describes OWASP Top10 for Django. We can use this to understand the inner structure of Django and how it works. The best practices also often tell us what to look for. Because many blindly trust them and even name many of the files as shown in the instructions.

#### Github

![](https://academy.hackthebox.com/storage/modules/112/github.png)

![](https://academy.hackthebox.com/storage/modules/112/github2.png)

Showing our projects can, of course, be of great advantage to make new business contacts and possibly even get a new job, but on the other hand, it can lead to mistakes that will be very difficult to fix. For example, in one of the files, we can discover the employee's personal email address, and upon deeper investigation, the web application has a hardcoded [JWT token](https://jwt.io/).

#### LinkedIn - Employee #2 Career

![](https://academy.hackthebox.com/storage/modules/112/linkedin-pers1.png)

[LinkedIn](https://www.linkedin.com/) offers a comprehensive search for employed, sorted by connections, locations, companies, school, industry, profile language, services, names, titles, and more. Understandably, the more detailed information we provide there, the fewer results we get. Therefore, we should think carefully about the purpose of performing the search.

Suppose we are trying to find the infrastructure and technology the company is most likely to use. We should look for technical employees who work both in development and security. Because based on the security area and the employees who work in that area, we will also be able to determine what security measures the company has put in place to secure itself.

---
## FTP

___

The `File Transfer Protocol` #FTP is one of the oldest protocols on the Internet. The FTP runs within the application layer of the TCP/IP protocol stack. Thus, it is on the same layer as `HTTP` or `POP`. These protocols also work with the support of browsers or email clients to perform their services. There are also special FTP programs for the File Transfer Protocol.

Let us imagine that we want to upload local files to a server and download other files using the [FTP](https://datatracker.ietf.org/doc/html/rfc959) protocol. In an FTP connection, two channels are opened. First, the client and server establish a control channel through `TCP port 21`. The client sends commands to the server, and the server returns status codes. Then both communication participants can establish the data channel via `TCP port 20`. This channel is used exclusively for data transmission, and the protocol watches for errors during this process. If a connection is broken off during transmission, the transport can be resumed after re-established contact.

A distinction is made between `active` and `passive` FTP. In the active variant, the client establishes the connection as described via TCP port 21 and thus informs the server via which client-side port the server can transmit its responses. However, if a firewall protects the client, the server cannot reply because all external connections are blocked. For this purpose, the `passive mode` has been developed. Here, the server announces a port through which the client can establish the data channel. Since the client initiates the connection in this method, the firewall does not block the transfer.

The FTP knows different [commands](https://www.smartfile.com/blog/the-ultimate-ftp-commands-list/) and status codes. Not all of these commands are consistently implemented on the server. For example, the client-side instructs the server-side to upload or download files, organize directories or delete files. The server responds in each case with a status code that indicates whether the command was successfully implemented. A list of possible status codes can be found [here](https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes).

Usually, we need credentials to use FTP on a server. We also need to know that FTP is a `clear-text` protocol that can sometimes be sniffed if conditions on the network are right. However, there is also the possibility that a server offers `anonymous FTP`. The server operator then allows any user to upload or download files via FTP without using a password. Since there are security risks associated with such a public FTP server, the options for users are usually limited.

___

## TFTP

`Trivial File Transfer Protocol` (`TFTP`) is simpler than FTP and performs file transfers between client and server processes. However, it `does not` provide user authentication and other valuable features supported by FTP. In addition, while FTP uses TCP, TFTP uses `UDP`, making it an unreliable protocol and causing it to use UDP-assisted application layer recovery.

This is reflected, for example, in the fact that TFTP, unlike FTP, does not require the user's authentication. It does not support protected login via passwords and sets limits on access based solely on the read and write permissions of a file in the operating system. Practically, this leads to TFTP operating exclusively in directories and with files that have been shared with all users and can be read and written globally. Because of the lack of security, TFTP, unlike FTP, may only be used in local and protected networks.

Let us take a look at a few commands of `TFTP`:

| **Commands** | **Description** |
| --- | --- |
| `connect` | Sets the remote host, and optionally the port, for file transfers. |
| `get` | Transfers a file or set of files from the remote host to the local host. |
| `put` | Transfers a file or set of files from the local host onto the remote host. |
| `quit` | Exits tftp. |
| `status` | Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on. |
| `verbose` | Turns verbose mode, which displays additional information during file transfer, on or off. |

Unlike the FTP client, `TFTP` does not have directory listing functionality.

___

## Default Configuration

One of the most used FTP servers on Linux-based distributions is [vsFTPd](https://security.appspot.com/vsftpd.html). The default configuration of vsFTPd can be found in `/etc/vsftpd.conf`, and some settings are already predefined by default. It is highly recommended to install the vsFTPd server on a VM and have a closer look at this configuration.

#### Install vsFTPd

FTP

```shell
6165@htb[/htb]$ sudo apt install vsftpd 
```

The vsFTPd server is only one of a few FTP servers available to us. There are many different alternatives to it, which also bring, among other things, many more functions and configuration options with them. We will use the vsFTPd server because it is an excellent way to show the configuration possibilities of an FTP server in a simple and easy-to-understand way without going into the details of the man pages. If we look at the configuration file of vsFTPd, we will see many options and settings that are either commented or commented out. However, the configuration file does not contain all possible settings that can be made. The existing and missing ones can be found on the [man page](http://vsftpd.beasts.org/vsftpd_conf.html).

#### vsFTPd Config File

FTP

```shell
6165@htb[/htb]$ cat /etc/vsftpd.conf | grep -v "#"
```

| **Setting** | **Description** |
| --- | --- |
| `listen=NO` | Run from inetd or as a standalone daemon? |
| `listen_ipv6=YES` | Listen on IPv6 ? |
| `anonymous_enable=NO` | Enable Anonymous access? |
| `local_enable=YES` | Allow local users to login? |
| `dirmessage_enable=YES` | Display active directory messages when users go into certain directories? |
| `use_localtime=YES` | Use local time? |
| `xferlog_enable=YES` | Activate logging of uploads/downloads? |
| `connect_from_port_20=YES` | Connect from port 20? |
| `secure_chroot_dir=/var/run/vsftpd/empty` | Name of an empty directory |
| `pam_service_name=vsftpd` | This string is the name of the PAM service vsftpd will use. |
| `rsa_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem` | The last three options specify the location of the RSA certificate to use for SSL encrypted connections. |
| `rsa_private_key_file=/etc/ssl/private/ssl-cert-snakeoil.key` |  |
| `ssl_enable=NO` |  |

In addition, there is a file called `/etc/ftpusers` that we also need to pay attention to, as this file is used to deny certain users access to the FTP service. In the following example, the users `guest`, `john`, and `kevin` are not permitted to log in to the FTP service, even if they exist on the Linux system.

#### FTPUSERS

FTP

```shell
6165@htb[/htb]$ cat /etc/ftpusers

guest
john
kevin
```

___

## Dangerous Settings

There are many different security-related settings we can make on each FTP server. These can have various purposes, such as testing connections through the firewalls, testing routes, and authentication mechanisms. One of these authentication mechanisms is the `anonymous` user. This is often used to allow everyone on the internal network to share files and data without accessing each other's computers. With vsFTPd, the [optional settings](http://vsftpd.beasts.org/vsftpd_conf.html) that can be added to the configuration file for the anonymous login look like this:

| **Setting** | **Description** |
| --- | --- |
| `anonymous_enable=YES` | Allowing anonymous login? |
| `anon_upload_enable=YES` | Allowing anonymous to upload files? |
| `anon_mkdir_write_enable=YES` | Allowing anonymous to create new directories? |
| `no_anon_password=YES` | Do not ask anonymous for password? |
| `anon_root=/home/username/ftp` | Directory for anonymous. |
| `write_enable=YES` | Allow the usage of FTP commands: STOR, DELE, RNFR, RNTO, MKD, RMD, APPE, and SITE? |

With the standard FTP client (`ftp`), we can access the FTP server accordingly and log in with the anonymous user if the settings shown above have been used. The use of the anonymous account can occur in internal environments and infrastructures where the participants are all known. Access to this type of service can be set temporarily or with the setting to accelerate the exchange of files.

As soon as we connect to the vsFTPd server, the `response code 220` is displayed with the banner of the FTP server. Often this banner contains the description of the `service` and even the `version` of it. It also tells us what type of system the FTP server is. One of the most common configurations of FTP servers is to allow `anonymous` access, which does not require legitimate credentials but provides access to some files. Even if we cannot download them, sometimes just listing the contents is enough to generate further ideas and note down information that will help us in another approach.

#### Anonymous Login

FTP

```shell
6165@htb[/htb]$ ftp 10.129.14.136

Connected to 10.129.14.136.
220 "Welcome to the HTB Academy vsFTP service."
Name (10.129.14.136:cry0l1t3): anonymous

230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.


ftp> ls

200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Clients
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 1002     1002           41 Sep 14 16:45 Important Notes.txt
226 Directory send OK.
```

However, to get the first overview of the server's settings, we can use the following command:

#### vsFTPd Status

FTP

```shell
ftp> status

Connected to 10.129.14.136.
No proxy connection.
Connecting using address family: any.
Mode: stream; Type: binary; Form: non-print; Structure: file
Verbose: on; Bell: off; Prompting: on; Globbing: on
Store unique: off; Receive unique: off
Case: off; CR stripping: on
Quote control characters: on
Ntrans: off
Nmap: off
Hash mark printing: off; Use of PORT cmds: on
Tick counter printing: off
```

Some commands should be used occasionally, as these will make the server show us more information that we can use for our purposes. These commands include `debug` and `trace`.

#### vsFTPd Detailed Output

FTP

```shell
ftp> debug

Debugging on (debug=1).


ftp> trace

Packet tracing on.


ftp> ls

---> PORT 10,10,14,4,188,195
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 1002     1002         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 1002     1002           41 Sep 14 16:45 Important Notes.txt
226 Directory send OK.
```

| **Setting** | **Description** |
| --- | --- |
| `dirmessage_enable=YES` | Show a message when they first enter a new directory? |
| `chown_uploads=YES` | Change ownership of anonymously uploaded files? |
| `chown_username=username` | User who is given ownership of anonymously uploaded files. |
| `local_enable=YES` | Enable local users to login? |
| `chroot_local_user=YES` | Place local users into their home directory? |
| `chroot_list_enable=YES` | Use a list of local users that will be placed in their home directory? |

| **Setting** | **Description** |
| --- | --- |
| `hide_ids=YES` | All user and group information in directory listings will be displayed as "ftp". |
| `ls_recurse_enable=YES` | Allows the use of recurse listings. |

In the following example, we can see that if the `hide_ids=YES` setting is present, the UID and GUID representation of the service will be overwritten, making it more difficult for us to identify with which rights these files are written and uploaded.

#### Hiding IDs - YES

FTP

```shell
ftp> ls

---> TYPE A
200 Switching to ASCII mode.
ftp: setsockopt (ignored): Permission denied
---> PORT 10,10,14,4,223,101
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
-rw-rw-r--    1 ftp     ftp      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 ftp     ftp         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 ftp     ftp         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 ftp     ftp         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 ftp     ftp           41 Sep 14 16:45 Important Notes.txt
-rw-------    1 ftp     ftp            0 Sep 15 14:57 testupload.txt
226 Directory send OK.
```

This setting is a security feature to prevent local usernames from being revealed. With the usernames, we could attack the services like FTP and SSH and many others with a brute-force attack in theory. However, in reality, [fail2ban](https://en.wikipedia.org/wiki/Fail2ban) solutions are now a standard implementation of any infrastructure that logs the IP address and blocks all access to the infrastructure after a certain number of failed login attempts.

Another helpful setting we can use for our purposes is the `ls_recurse_enable=YES`. This is often set on the vsFTPd server to have a better overview of the FTP directory structure, as it allows us to see all the visible content at once.

#### Recursive Listing

FTP

```shell
ftp> ls -R

---> PORT 10,10,14,4,222,149
200 PORT command successful. Consider using PASV.
---> LIST -R
150 Here comes the directory listing.
.:
-rw-rw-r--    1 ftp      ftp      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 ftp      ftp         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 ftp      ftp           41 Sep 14 16:45 Important Notes.txt
-rw-------    1 ftp      ftp            0 Sep 15 14:57 testupload.txt

./Clients:
drwx------    2 ftp      ftp          4096 Sep 16 18:04 HackTheBox
drwxrwxrwx    2 ftp      ftp          4096 Sep 16 18:00 Inlanefreight

./Clients/HackTheBox:
-rw-r--r--    1 ftp      ftp         34872 Sep 16 18:04 appointments.xlsx
-rw-r--r--    1 ftp      ftp        498123 Sep 16 18:04 contract.docx
-rw-r--r--    1 ftp      ftp        478237 Sep 16 18:04 contract.pdf
-rw-r--r--    1 ftp      ftp           348 Sep 16 18:04 meetings.txt

./Clients/Inlanefreight:
-rw-r--r--    1 ftp      ftp         14211 Sep 16 18:00 appointments.xlsx
-rw-r--r--    1 ftp      ftp         37882 Sep 16 17:58 contract.docx
-rw-r--r--    1 ftp      ftp            89 Sep 16 17:58 meetings.txt
-rw-r--r--    1 ftp      ftp        483293 Sep 16 17:59 proposal.pptx

./Documents:
-rw-r--r--    1 ftp      ftp         23211 Sep 16 18:05 appointments-template.xlsx
-rw-r--r--    1 ftp      ftp         32521 Sep 16 18:05 contract-template.docx
-rw-r--r--    1 ftp      ftp        453312 Sep 16 18:05 contract-template.pdf

./Employees:
226 Directory send OK.
```

`Downloading` files from such an FTP server is one of the main features, as well as `uploading` files created by us. This allows us, for example, to use LFI vulnerabilities to make the host execute system commands. Apart from the files, we can view, download and inspect. Attacks are also possible with the FTP logs, leading to `Remote Command Execution` (`RCE`). This applies to the FTP services and all those we can detect during our enumeration phase.

#### Download a File

FTP

```shell
ftp> ls

200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rwxrwxrwx    1 ftp      ftp             0 Sep 16 17:24 Calendar.pptx
drwxrwxrwx    4 ftp      ftp          4096 Sep 16 17:57 Clients
drwxrwxrwx    2 ftp      ftp          4096 Sep 16 18:05 Documents
drwxrwxrwx    2 ftp      ftp          4096 Sep 16 17:24 Employees
-rwxrwxrwx    1 ftp      ftp            41 Sep 18 15:58 Important Notes.txt
226 Directory send OK.


ftp> get Important\ Notes.txt

local: Important Notes.txt remote: Important Notes.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for Important Notes.txt (41 bytes).
226 Transfer complete.
41 bytes received in 0.00 secs (606.6525 kB/s)


ftp> exit

221 Goodbye.
```

FTP

```shell
6165@htb[/htb]$ ls | grep Notes.txt

'Important Notes.txt'
```

We also can download all the files and folders we have access to at once. This is especially useful if the FTP server has many different files in a larger folder structure. However, this can cause alarms because no one from the company usually wants to download all files and content all at once.

#### Download All Available Files

FTP

```shell
6165@htb[/htb]$ wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

--2021-09-19 14:45:58--  ftp://anonymous:*password*@10.129.14.136/                                         
           => ‘10.129.14.136/.listing’                                                                     
Connecting to 10.129.14.136:21... connected.                                                               
Logging in as anonymous ... Logged in!
==> SYST ... done.    ==> PWD ... done.
==> TYPE I ... done.  ==> CWD not needed.
==> PORT ... done.    ==> LIST ... done.                                                                 
12.12.1.136/.listing           [ <=>                                  ]     466  --.-KB/s    in 0s       
                                                                                                         
2021-09-19 14:45:58 (65,8 MB/s) - ‘10.129.14.136/.listing’ saved [466]                                     
--2021-09-19 14:45:58--  ftp://anonymous:*password*@10.129.14.136/Calendar.pptx   
           => ‘10.129.14.136/Calendar.pptx’                                       
==> CWD not required.                                                           
==> SIZE Calendar.pptx ... done.                                                                                                                            
==> PORT ... done.    ==> RETR Calendar.pptx ... done.       

...SNIP...

2021-09-19 14:45:58 (48,3 MB/s) - ‘10.129.14.136/Employees/.listing’ saved [119]

FINISHED --2021-09-19 14:45:58--
Total wall clock time: 0,03s
Downloaded: 15 files, 1,7K in 0,001s (3,02 MB/s)
```

Once we have downloaded all the files, `wget` will create a directory with the name of the IP address of our target. All downloaded files are stored there, which we can then inspect locally.

FTP

```shell
6165@htb[/htb]$ tree .

.
└── 10.129.14.136
    ├── Calendar.pptx
    ├── Clients
    │   └── Inlanefreight
    │       ├── appointments.xlsx
    │       ├── contract.docx
    │       ├── meetings.txt
    │       └── proposal.pptx
    ├── Documents
    │   ├── appointments-template.xlsx
    │   ├── contract-template.docx
    │   └── contract-template.pdf
    ├── Employees
    └── Important Notes.txt

5 directories, 9 files
```

Next, we can check if we have the permissions to upload files to the FTP server. Especially with web servers, it is common that files are synchronized, and the developers have quick access to the files. FTP is often used for this purpose, and most of the time, configuration errors are found on servers that the administrators think are not discoverable. The attitude that internal network components cannot be accessed from the outside means that the hardening of internal systems is often neglected and leads to misconfigurations.

The ability to upload files to the FTP server connected to a web server increases the likelihood of gaining direct access to the webserver and even a reverse shell that allows us to execute internal system commands and perhaps even escalate our privileges.

#### Upload a File

FTP

```shell
6165@htb[/htb]$ touch testupload.txt
```

With the `PUT` command, we can upload files in the current folder to the FTP server.

FTP

```shell
ftp> put testupload.txt 

local: testupload.txt remote: testupload.txt
---> PORT 10,10,14,4,184,33
200 PORT command successful. Consider using PASV.
---> STOR testupload.txt
150 Ok to send data.
226 Transfer complete.


ftp> ls

---> TYPE A
200 Switching to ASCII mode.
---> PORT 10,10,14,4,223,101
200 PORT command successful. Consider using PASV.
---> LIST
150 Here comes the directory listing.
-rw-rw-r--    1 1002     1002      8138592 Sep 14 16:54 Calender.pptx
drwxrwxr-x    2 1002     1002         4096 Sep 14 17:03 Clients
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Documents
drwxrwxr-x    2 1002     1002         4096 Sep 14 16:50 Employees
-rw-rw-r--    1 1002     1002           41 Sep 14 16:45 Important Notes.txt
-rw-------    1 1002     133             0 Sep 15 14:57 testupload.txt
226 Directory send OK.
```

___

## Footprinting the Service

Footprinting using various network scanners is also a handy and widespread approach. These tools make it easier for us to identify different services, even if they are not accessible on standard ports. One of the most widely used tools for this purpose is Nmap. Nmap also brings the [Nmap Scripting Engine](https://nmap.org/book/nse.html) (`NSE`), a set of many different scripts written for specific services. More information on the capabilities of Nmap and NSE can be found in the [Network Enumeration with Nmap](https://academy.hackthebox.com/course/preview/network-enumeration-with-nmap) module. We can update this database of NSE scripts with the command shown.

#### Nmap FTP Scripts

FTP

```shell
6165@htb[/htb]$ sudo nmap --script-updatedb

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 13:49 CEST
NSE: Updating rule database.
NSE: Script Database updated successfully.
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.28 seconds
```

All the NSE scripts are located on the Pwnbox in `/usr/share/nmap/scripts/`, but on our systems, we can find them using a simple command on our system.

FTP

```shell
6165@htb[/htb]$ find / -type f -name ftp* 2>/dev/null | grep scripts

/usr/share/nmap/scripts/ftp-syst.nse
/usr/share/nmap/scripts/ftp-vsftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-vuln-cve2010-4221.nse
/usr/share/nmap/scripts/ftp-proftpd-backdoor.nse
/usr/share/nmap/scripts/ftp-bounce.nse
/usr/share/nmap/scripts/ftp-libopie.nse
/usr/share/nmap/scripts/ftp-anon.nse
/usr/share/nmap/scripts/ftp-brute.nse
```

As we already know, the FTP server usually runs on the standard TCP port 21, which we can scan using Nmap. We also use the version scan (`-sV`), aggressive scan (`-A`), and the default script scan (`-sC`) against our target `10.129.14.136`.

#### Nmap

FTP

```shell
6165@htb[/htb]$ sudo nmap -sV -p21 -sC -A 10.129.14.136

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-16 18:12 CEST
Nmap scan report for 10.129.14.136
Host is up (0.00013s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rwxrwxrwx    1 ftp      ftp       8138592 Sep 16 17:24 Calendar.pptx [NSE: writeable]
| drwxrwxrwx    4 ftp      ftp          4096 Sep 16 17:57 Clients [NSE: writeable]
| drwxrwxrwx    2 ftp      ftp          4096 Sep 16 18:05 Documents [NSE: writeable]
| drwxrwxrwx    2 ftp      ftp          4096 Sep 16 17:24 Employees [NSE: writeable]
| -rwxrwxrwx    1 ftp      ftp            41 Sep 16 17:24 Important Notes.txt [NSE: writeable]
|_-rwxrwxrwx    1 ftp      ftp             0 Sep 15 14:57 testupload.txt [NSE: writeable]
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.4
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
```

The default script scan is based on the services' fingerprints, responses, and standard ports. Once Nmap has detected the service, it executes the marked scripts one after the other, providing different information. For example, the [ftp-anon](https://nmap.org/nsedoc/scripts/ftp-anon.html) NSE script checks whether the FTP server allows anonymous access. If so, the contents of the FTP root directory are rendered for the anonymous user.

The `ftp-syst`, for example, executes the `STAT` command, which displays information about the FTP server status. This includes configurations as well as the version of the FTP server. Nmap also provides the ability to trace the progress of NSE scripts at the network level if we use the `--script-trace` option in our scans. This lets us see what commands Nmap sends, what ports are used, and what responses we receive from the scanned server.

#### Nmap Script Trace

FTP

```shell
6165@htb[/htb]$ sudo nmap -sV -p21 -sC -A 10.129.14.136 --script-trace

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 13:54 CEST                                                                                                                                                   
NSOCK INFO [11.4640s] nsock_trace_handler_callback(): Callback: CONNECT SUCCESS for EID 8 [10.129.14.136:21]                                   
NSOCK INFO [11.4640s] nsock_trace_handler_callback(): Callback: CONNECT SUCCESS for EID 16 [10.129.14.136:21]             
NSOCK INFO [11.4640s] nsock_trace_handler_callback(): Callback: CONNECT SUCCESS for EID 24 [10.129.14.136:21]
NSOCK INFO [11.4640s] nsock_trace_handler_callback(): Callback: CONNECT SUCCESS for EID 32 [10.129.14.136:21]
NSOCK INFO [11.4640s] nsock_read(): Read request from IOD #1 [10.129.14.136:21] (timeout: 7000ms) EID 42
NSOCK INFO [11.4640s] nsock_read(): Read request from IOD #2 [10.129.14.136:21] (timeout: 9000ms) EID 50
NSOCK INFO [11.4640s] nsock_read(): Read request from IOD #3 [10.129.14.136:21] (timeout: 7000ms) EID 58
NSOCK INFO [11.4640s] nsock_read(): Read request from IOD #4 [10.129.14.136:21] (timeout: 11000ms) EID 66
NSE: TCP 10.10.14.4:54226 > 10.129.14.136:21 | CONNECT
NSE: TCP 10.10.14.4:54228 > 10.129.14.136:21 | CONNECT
NSE: TCP 10.10.14.4:54230 > 10.129.14.136:21 | CONNECT
NSE: TCP 10.10.14.4:54232 > 10.129.14.136:21 | CONNECT
NSOCK INFO [11.4660s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 50 [10.129.14.136:21] (41 bytes): 220 Welcome to HTB-Academy FTP service...
NSOCK INFO [11.4660s] nsock_trace_handler_callback(): Callback: READ SUCCESS for EID 58 [10.129.14.136:21] (41 bytes): 220 Welcome to HTB-Academy FTP service...
NSE: TCP 10.10.14.4:54228 < 10.129.14.136:21 | 220 Welcome to HTB-Academy FTP service.
```

The scan history shows that four different parallel scans are running against the service, with various timeouts. For the NSE scripts, we see that our local machine uses other output ports (`54226`, `54228`, `54230`, `54232`) and first initiates the connection with the `CONNECT` command. From the first response from the server, we can see that we are receiving the banner from the server to our second NSE script (`54228`) from the target FTP server. If necessary, we can, of course, use other applications such as `netcat` or `telnet` to interact with the FTP server.

#### Service Interaction

FTP

```shell
6165@htb[/htb]$ nc -nv 10.129.14.136 21
```

FTP

```shell
6165@htb[/htb]$ telnet 10.129.14.136 21
```

It looks slightly different if the FTP server runs with TLS/SSL encryption. Because then we need a client that can handle TLS/SSL. For this, we can use the client `openssl` and communicate with the FTP server. The good thing about using `openssl` is that we can see the SSL certificate, which can also be helpful.

FTP

```shell
6165@htb[/htb]$ openssl s_client -connect 10.129.14.136:21 -starttls ftp

CONNECTED(00000003)                                                                                      
Can't use SSL_get_servername                        
depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
verify error:num=18:self signed certificate
verify return:1

depth=0 C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
verify return:1
---                                                 
Certificate chain
 0 s:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
 
 i:C = US, ST = California, L = Sacramento, O = Inlanefreight, OU = Dev, CN = master.inlanefreight.htb, emailAddress = admin@inlanefreight.htb
---
 
Server certificate

-----BEGIN CERTIFICATE-----

MIIENTCCAx2gAwIBAgIUD+SlFZAWzX5yLs2q3ZcfdsRQqMYwDQYJKoZIhvcNAQEL
...SNIP...
```

This is because the SSL certificate allows us to recognize the `hostname`, for example, and in most cases also an `email address` for the organization or company. In addition, if the company has several locations worldwide, certificates can also be created for specific locations, which can also be identified using the SSL certificate.

---
## SMB #SMB 

___

`Server Message Block` (`SMB`) is a client-server protocol that regulates access to files and entire directories and other network resources such as printers, routers, or interfaces released for the network. Information exchange between different system processes can also be handled based on the SMB protocol. [SMB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/f210069c-7086-4dc2-885e-861d837df688) first became available to a broader public, for example, as part of the OS/2 network operating system LAN Manager and LAN Server. Since then, the main application area of the protocol has been the Windows operating system series in particular, whose network services support SMB in a downward-compatible manner - which means that devices with newer editions can easily communicate with devices that have an older Microsoft operating system installed. With the free software project Samba, there is also a solution that enables the use of SMB in Linux and Unix distributions and thus cross-platform communication via SMB.

The SMB protocol enables the client to communicate with other participants in the same network to access files or services shared with it on the network. The other system must also have implemented the network protocol and received and processed the client request using an SMB server application. Before that, however, both parties must establish a connection, which is why they first exchange corresponding messages.

In IP networks, SMB uses TCP protocol for this purpose, which provides for a three-way handshake between client and server before a connection is finally established. The specifications of the TCP protocol also govern the subsequent transport of data. We can take a look at some examples [here](https://winprotocoldoc.blob.core.windows.net/productionwindowsarchives/MS-SMB2/%5bMS-SMB2%5d.pdf#%5B%7B%22num%22%3A920%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C738%2C0%5D).

An SMB server can provide arbitrary parts of its local file system as shares. Therefore the hierarchy visible to a client is partially independent of the structure on the server. Access rights are defined by `Access Control Lists` (`ACL`). They can be controlled in a fine-grained manner based on attributes such as `execute`, `read`, and `full access` for individual users or user groups. The ACLs are defined based on the shares and therefore do not correspond to the rights assigned locally on the server.

___

## Samba

As mentioned earlier, there is an alternative variant to the SMB server, called Samba, developed for Unix-based operating system. Samba implements the `Common Internet File System` (`CIFS`) network protocol. [CIFS](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/934c2faa-54af-4526-ac74-6a24d126724e) is a "dialect" of SMB. In other words, CIFS is a very specific implementation of the SMB protocol, which in turn was created by Microsoft. This allows Samba to communicate with newer Windows systems. Therefore, it usually is referred to as `SMB / CIFS`. However, CIFS is the extension of the SMB protocol. So when we pass SMB commands over Samba to an older NetBIOS service, it usually connects to the Samba server over TCP ports `137`, `138`, `139`, but CIFS uses TCP port `445` only. There are several versions of SMB, including outdated versions that are still used in specific infrastructures.

| **SMB Version** | **Supported**                       | **Features**                                                           |
| --------------- | ----------------------------------- | ---------------------------------------------------------------------- |
| CIFS            | Windows NT 4.0                      | Communication via NetBIOS interface                                    |
| SMB 1.0         | Windows 2000                        | Direct connection via TCP                                              |
| SMB 2.0         | Windows Vista, Windows Server 2008  | Performance upgrades, improved message signing, caching feature        |
| SMB 2.1         | Windows 7, Windows Server 2008 R2   | Locking mechanisms                                                     |
| SMB 3.0         | Windows 8, Windows Server 2012      | Multichannel connections, end-to-end encryption, remote storage access |
| SMB 3.0.2       | Windows 8.1, Windows Server 2012 R2 |                                                                        |
| SMB 3.1.1       | Windows 10, Windows Server 2016     | Integrity checking, AES-128 encryption                                 |
|                 |                                     |                                                                        |

With version 3, the Samba server gained the ability to be a full member of an Active Directory domain. With version 4, Samba even provides an Active Directory domain controller. It contains several so-called daemons for this purpose - which are Unix background programs. The SMB server daemon (`smbd`) belonging to Samba provides the first two functionalities, while the NetBIOS message block daemon (`nmbd`) implements the last two functionalities. The SMB service controls these two background programs.

We know that Samba is suitable for both Linux and Windows systems. In a network, each host participates in the same `workgroup`. A workgroup is a group name that identifies an arbitrary collection of computers and their resources on an SMB network. There can be multiple workgroups on the network at any given time. IBM developed an `application programming interface` (`API`) for networking computers called the `Network Basic Input/Output System` (`NetBIOS`). The NetBIOS API provided a blueprint for an application to connect and share data with other computers. In a NetBIOS environment, when a machine goes online, it needs a name, which is done through the so-called `name registration` procedure. Either each host reserves its hostname on the network, or the [NetBIOS Name Server](https://networkencyclopedia.com/netbios-name-server-nbns/) (`NBNS`) is used for this purpose. It also has been enhanced to [Windows Internet Name Service](https://networkencyclopedia.com/windows-internet-name-service-wins/) (`WINS`).

___

## Default Configuration

As we can imagine, Samba offers a wide range of [settings](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) that we can configure. Again, we define the settings via a text file where we can get an overview of some of the settings. These settings look like the following when filtered out:

#### Default Configuration

SMB

```shell
6165@htb[/htb]$ cat /etc/samba/smb.conf | grep -v "#\|\;" 

[global]
   workgroup = DEV.INFREIGHT.HTB
   server string = DEVSMB
   log file = /var/log/samba/log.%m
   max log size = 1000
   logging = file
   panic action = /usr/share/samba/panic-action %d

   server role = standalone server
   obey pam restrictions = yes
   unix password sync = yes

   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .

   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes

[printers]
   comment = All Printers
   browseable = no
   path = /var/spool/samba
   printable = yes
   guest ok = no
   read only = yes
   create mask = 0700

[print$]
   comment = Printer Drivers
   path = /var/lib/samba/printers
   browseable = yes
   read only = yes
   guest ok = no
```

We see global settings and two shares that are intended for printers. The global settings are the configuration of the available SMB server that is used for all shares. In the individual shares, however, the global settings can be overwritten, which can be configured with high probability even incorrectly. Let us look at some of the settings to understand how the shares are configured in Samba.

| **Setting** | **Description** |
| --- | --- |
| `[sharename]` | The name of the network share. |
| `workgroup = WORKGROUP/DOMAIN` | Workgroup that will appear when clients query. |
| `path = /path/here/` | The directory to which user is to be given access. |
| `server string = STRING` | The string that will show up when a connection is initiated. |
| `unix password sync = yes` | Synchronize the UNIX password with the SMB password? |
| `usershare allow guests = yes` | Allow non-authenticated users to access defined share? |
| `map to guest = bad user` | What to do when a user login request doesn't match a valid UNIX user? |
| `browseable = yes` | Should this share be shown in the list of available shares? |
| `guest ok = yes` | Allow connecting to the service without using a password? |
| `read only = yes` | Allow users to read files only? |
| `create mask = 0700` | What permissions need to be set for newly created files? |

___

## Dangerous Settings

Some of the above settings already bring some sensitive options. However, suppose we question the settings listed below and ask ourselves what the employees could gain from them, as well as attackers. In that case, we will see what advantages and disadvantages the settings bring with them. Let us take the setting `browseable = yes` as an example. If we as administrators adopt this setting, the company's employees will have the comfort of being able to look at the individual folders with the contents. Many folders are eventually used for better organization and structure. If the employee can browse through the shares, the attacker will also be able to do so after successful access.

| **Setting**                 | **Description**                                                     |
| --------------------------- | ------------------------------------------------------------------- |
| `browseable = yes`          | Allow listing available shares in the current share?                |
| `read only = no`            | Forbid the creation and modification of files?                      |
| `writable = yes`            | Allow users to create and modify files?                             |
| `guest ok = yes`            | Allow connecting to the service without using a password?           |
| `enable privileges = yes`   | Honor privileges assigned to specific SID?                          |
| `create mask = 0777`        | What permissions must be assigned to the newly created files?       |
| `directory mask = 0777`     | What permissions must be assigned to the newly created directories? |
| `logon script = script.sh`  | What script needs to be executed on the user's login?               |
| `magic script = script.sh`  | Which script should be executed when the script gets closed?        |
| `magic output = script.out` | Where the output of the magic script needs to be stored?            |

Let us create a share called `[notes]` and a few others and see how the settings affect our enumeration process. We will use all of the above settings and apply them to this share. For example, this setting is often applied, if only for testing purposes. If it is then an internal subnet of a small team in a large department, this setting is often retained or forgotten to be reset. This leads to the fact that we can browse through all the shares and, with high probability, even download and inspect them.

#### Example Share

SMB

```shell
...SNIP...

[notes]
	comment = CheckIT
	path = /mnt/notes/

	browseable = yes
	read only = no
	writable = yes
	guest ok = yes

	enable privileges = yes
	create mask = 0777
	directory mask = 0777
```

It is highly recommended to look at the man pages for Samba and configure it ourselves and experiment with the settings. We will then discover potential aspects that will be interesting for us as a penetration tester. In addition, the more familiar we become with the Samba server and SMB, the easier it will be to find our way around the environment and use it for our purposes. Once we have adjusted `/etc/samba/smb.conf` to our needs, we have to restart the service on the server.

#### Restart Samba

SMB

```shell
root@samba:~# sudo systemctl restart smbd
```

Now we can display a list (`-L`) of the server's shares with the `smbclient` command from our host. We use the so-called `null session` (`-N`), which is `anonymous` access without the input of existing users or valid passwords.

#### SMBclient - Connecting to the Share

SMB

```shell
6165@htb[/htb]$ smbclient -N -L //10.129.14.128

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        home            Disk      INFREIGHT Samba
        dev             Disk      DEVenv
        notes           Disk      CheckIT
        IPC$            IPC       IPC Service (DEVSM)
SMB1 disabled -- no workgroup available
```

We can see that we now have five different shares on the Samba server from the result. Thereby `print$` and an `IPC$` are already included by default in the basic setting, as we have already seen. Since we deal with the `[notes]` share, let us log in and inspect it using the same client program. If we are not familiar with the client program, we can use the `help` command on successful login, listing all the possible commands we can execute.

SMB

```shell
6165@htb[/htb]$ smbclient //10.129.14.128/notes

Enter WORKGROUP\<username>'s password: 
Anonymous login successful
Try "help" to get a list of possible commands.


smb: \> help

?              allinfo        altname        archive        backup         
blocksize      cancel         case_sensitive cd             chmod          
chown          close          del            deltree        dir            
du             echo           exit           get            getfacl        
geteas         hardlink       help           history        iosize         
lcd            link           lock           lowercase      ls             
l              mask           md             mget           mkdir          
more           mput           newer          notify         open           
posix          posix_encrypt  posix_open     posix_mkdir    posix_rmdir    
posix_unlink   posix_whoami   print          prompt         put            
pwd            q              queue          quit           readlink       
rd             recurse        reget          rename         reput          
rm             rmdir          showacls       setea          setmode        
scopy          stat           symlink        tar            tarmode        
timeout        translate      unlock         volume         vuid           
wdel           logon          listconnect    showconnect    tcon           
tdis           tid            utimes         logoff         ..             
!            


smb: \> ls

  .                                   D        0  Wed Sep 22 18:17:51 2021
  ..                                  D        0  Wed Sep 22 12:03:59 2021
  prep-prod.txt                       N       71  Sun Sep 19 15:45:21 2021

                30313412 blocks of size 1024. 16480084 blocks available
```

Once we have discovered interesting files or folders, we can download them using the `get` command. Smbclient also allows us to execute local system commands using an exclamation mark at the beginning (`!<cmd>`) without interrupting the connection.

#### Download Files from SMB

SMB

```shell
smb: \> get prep-prod.txt 

getting file \prep-prod.txt of size 71 as prep-prod.txt (8,7 KiloBytes/sec) 
(average 8,7 KiloBytes/sec)


smb: \> !ls

prep-prod.txt


smb: \> !cat prep-prod.txt

[] check your code with the templates
[] run code-assessment.py
[] …
```

From the administrative point of view, we can check these connections using `smbstatus`. Apart from the Samba version, we can also see who, from which host, and which share the client is connected. This is especially important once we have entered a subnet (perhaps even an isolated one) that the others can still access.

For example, with domain-level security, the samba server acts as a member of a Windows domain. Each domain has at least one domain controller, usually a Windows NT server providing password authentication. This domain controller provides the workgroup with a definitive password server. The domain controllers keep track of users and passwords in their own `Security Authentication Module` (`SAM`) and authenticate each user when they log in for the first time and wish to access another machine's share.

#### Samba Status

SMB

```shell
root@samba:~# smbstatus

Samba version 4.11.6-Ubuntu
PID     Username     Group        Machine                                   Protocol Version  Encryption           Signing              
----------------------------------------------------------------------------------------------------------------------------------------
75691   sambauser    samba        10.10.14.4 (ipv4:10.10.14.4:45564)      SMB3_11           -                    -                    

Service      pid     Machine       Connected at                     Encryption   Signing     
---------------------------------------------------------------------------------------------
notes        75691   10.10.14.4   Do Sep 23 00:12:06 2021 CEST     -            -           

No locked files
```

___

## Footprinting the Service

Let us go back to one of our enumeration tools. Nmap also has many options and NSE scripts that can help us examine the target's SMB service more closely and get more information. The downside, however, is that these scans can take a long time. Therefore, it is also recommended to look at the service manually, mainly because we can find much more details than Nmap could show us. First, however, let us see what Nmap can find on our target Samba server, where we created the `[notes]` share for testing purposes.

#### Nmap

SMB

```shell
6165@htb[/htb]$ sudo nmap 10.129.14.128 -sV -sC -p139,445

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 15:15 CEST
Nmap scan report for sharing.inlanefreight.htb (10.129.14.128)
Host is up (0.00024s latency).

PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 4.6.2
445/tcp open  netbios-ssn Samba smbd 4.6.2
MAC Address: 00:00:00:00:00:00 (VMware)

Host script results:
|_nbstat: NetBIOS name: HTB, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-09-19T13:16:04
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.35 seconds
```

We can see from the results that it is not very much that Nmap provided us with here. Therefore, we should resort to other tools that allow us to interact manually with the SMB and send specific requests for the information. One of the handy tools for this is `rpcclient`. This is a tool to perform MS-RPC functions.

The [Remote Procedure Call](https://www.geeksforgeeks.org/remote-procedure-call-rpc-in-operating-system/) (`RPC`) is a concept and, therefore, also a central tool to realize operational and work-sharing structures in networks and client-server architectures. The communication process via RPC includes passing parameters and the return of a function value.

#### RPCclient

SMB

```shell
6165@htb[/htb]$ rpcclient -U "" 10.129.14.128

Enter WORKGROUP\'s password:
rpcclient $> 
```

The `rpcclient` offers us many different requests with which we can execute specific functions on the SMB server to get information. A complete list of all these functions can be found on the [man page](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) of the rpcclient.

| **Query** | **Description** |
| --- | --- |
| `srvinfo` | Server information. |
| `enumdomains` | Enumerate all domains that are deployed in the network. |
| `querydominfo` | Provides domain, server, and user information of deployed domains. |
| `netshareenumall` | Enumerates all available shares. |
| `netsharegetinfo <share>` | Provides information about a specific share. |
| `enumdomusers` | Enumerates all domain users. |
| `queryuser <RID>` | Provides information about a specific user. |

#### RPCclient - Enumeration

SMB

```shell
rpcclient $> srvinfo

        DEVSMB         Wk Sv PrQ Unx NT SNT DEVSM
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03
		
		
rpcclient $> enumdomains

name:[DEVSMB] idx:[0x0]
name:[Builtin] idx:[0x1]


rpcclient $> querydominfo

Domain:         DEVOPS
Server:         DEVSMB
Comment:        DEVSM
Total Users:    2
Total Groups:   0
Total Aliases:  0
Sequence No:    1632361158
Force Logoff:   -1
Domain Server State:    0x1
Server Role:    ROLE_DOMAIN_PDC
Unknown 3:      0x1


rpcclient $> netshareenumall

netname: print$
        remark: Printer Drivers
        path:   C:\var\lib\samba\printers
        password:
netname: home
        remark: INFREIGHT Samba
        path:   C:\home\
        password:
netname: dev
        remark: DEVenv
        path:   C:\home\sambauser\dev\
        password:
netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
netname: IPC$
        remark: IPC Service (DEVSM)
        path:   C:\tmp
        password:
		
		
rpcclient $> netsharegetinfo notes

netname: notes
        remark: CheckIT
        path:   C:\mnt\notes\
        password:
        type:   0x0
        perms:  0
        max_uses:       -1
        num_uses:       1
revision: 1
type: 0x8004: SEC_DESC_DACL_PRESENT SEC_DESC_SELF_RELATIVE 
DACL
        ACL     Num ACEs:       1       revision:       2
        ---
        ACE
                type: ACCESS ALLOWED (0) flags: 0x00 
                Specific bits: 0x1ff
                Permissions: 0x101f01ff: Generic all access SYNCHRONIZE_ACCESS WRITE_OWNER_ACCESS WRITE_DAC_ACCESS READ_CONTROL_ACCESS DELETE_ACCESS 
                SID: S-1-1-0
```

These examples show us what information can be leaked to anonymous users. Once an `anonymous` user has access to a network service, it only takes one mistake to give them too many permissions or too much visibility to put the entire network at significant risk.

Most importantly, anonymous access to such services can also lead to the discovery of other users, who can be attacked with brute-forcing in the most aggressive case. Humans are more error-prone than properly configured computer processes, and the lack of security awareness and laziness often leads to weak passwords that can be easily cracked. Let us see how we can enumerate users using the `rpcclient`.

#### Rpcclient - User Enumeration

SMB

```shell
rpcclient $> enumdomusers

user:[mrb3n] rid:[0x3e8]
user:[cry0l1t3] rid:[0x3e9]


rpcclient $> queryuser 0x3e9

        User Name   :   cry0l1t3
        Full Name   :   cry0l1t3
        Home Drive  :   \\devsmb\cry0l1t3
        Dir Drive   :
        Profile Path:   \\devsmb\cry0l1t3\profile
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Do, 01 Jan 1970 01:00:00 CET
        Logoff Time              :      Mi, 06 Feb 2036 16:06:39 CET
        Kickoff Time             :      Mi, 06 Feb 2036 16:06:39 CET
        Password last set Time   :      Mi, 22 Sep 2021 17:50:56 CEST
        Password can change Time :      Mi, 22 Sep 2021 17:50:56 CEST
        Password must change Time:      Do, 14 Sep 30828 04:48:05 CEST
        unknown_2[0..31]...
        user_rid :      0x3e9
        group_rid:      0x201
        acb_info :      0x00000014
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...


rpcclient $> queryuser 0x3e8

        User Name   :   mrb3n
        Full Name   :
        Home Drive  :   \\devsmb\mrb3n
        Dir Drive   :
        Profile Path:   \\devsmb\mrb3n\profile
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Do, 01 Jan 1970 01:00:00 CET
        Logoff Time              :      Mi, 06 Feb 2036 16:06:39 CET
        Kickoff Time             :      Mi, 06 Feb 2036 16:06:39 CET
        Password last set Time   :      Mi, 22 Sep 2021 17:47:59 CEST
        Password can change Time :      Mi, 22 Sep 2021 17:47:59 CEST
        Password must change Time:      Do, 14 Sep 30828 04:48:05 CEST
        unknown_2[0..31]...
        user_rid :      0x3e8
        group_rid:      0x201
        acb_info :      0x00000010
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000000
        padding1[0..7]...
        logon_hrs[0..21]...
```

We can then use the results to identify the group's RID, which we can then use to retrieve information from the entire group.

#### Rpcclient - Group Information

SMB

```shell
rpcclient $> querygroup 0x201

        Group Name:     None
        Description:    Ordinary Users
        Group Attribute:7
        Num Members:2
```

However, it can also happen that not all commands are available to us, and we have certain restrictions based on the user. However, the query `queryuser <RID>` is mostly allowed based on the RID. So we can use the rpcclient to brute force the RIDs to get information. Because we may not know who has been assigned which RID, we know that we will get information about it as soon as we query an assigned RID. There are several ways and tools we can use for this. To stay with the tool, we can create a `For-loop` using `Bash` where we send a command to the service using rpcclient and filter out the results.

#### Brute Forcing User RIDs

SMB

```shell
6165@htb[/htb]$ for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

        User Name   :   sambauser
        user_rid :      0x1f5
        group_rid:      0x201
		
        User Name   :   mrb3n
        user_rid :      0x3e8
        group_rid:      0x201
		
        User Name   :   cry0l1t3
        user_rid :      0x3e9
        group_rid:      0x201
```

An alternative to this would be a Python script from [Impacket](https://github.com/SecureAuthCorp/impacket) called [samrdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/samrdump.py).

#### Impacket - Samrdump.py

SMB

```shell
6165@htb[/htb]$ samrdump.py 10.129.14.128

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Retrieving endpoint list from 10.129.14.128
Found domain(s):
 . DEVSMB
 . Builtin
[*] Looking up users in domain DEVSMB
Found user: mrb3n, uid = 1000
Found user: cry0l1t3, uid = 1001
mrb3n (1000)/FullName: 
mrb3n (1000)/UserComment: 
mrb3n (1000)/PrimaryGroupId: 513
mrb3n (1000)/BadPasswordCount: 0
mrb3n (1000)/LogonCount: 0
mrb3n (1000)/PasswordLastSet: 2021-09-22 17:47:59
mrb3n (1000)/PasswordDoesNotExpire: False
mrb3n (1000)/AccountIsDisabled: False
mrb3n (1000)/ScriptPath: 
cry0l1t3 (1001)/FullName: cry0l1t3
cry0l1t3 (1001)/UserComment: 
cry0l1t3 (1001)/PrimaryGroupId: 513
cry0l1t3 (1001)/BadPasswordCount: 0
cry0l1t3 (1001)/LogonCount: 0
cry0l1t3 (1001)/PasswordLastSet: 2021-09-22 17:50:56
cry0l1t3 (1001)/PasswordDoesNotExpire: False
cry0l1t3 (1001)/AccountIsDisabled: False
cry0l1t3 (1001)/ScriptPath: 
[*] Received 2 entries.
```

The information we have already obtained with `rpcclient` can also be obtained using other tools. For example, the [SMBMap](https://github.com/ShawnDEvans/smbmap) and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) tools are also widely used and helpful for the enumeration of SMB services.

#### SMBmap

SMB

```shell
6165@htb[/htb]$ smbmap -H 10.129.14.128

[+] Finding open SMB ports....
[+] User SMB session established on 10.129.14.128...
[+] IP: 10.129.14.128:445       Name: 10.129.14.128                                     
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        print$                                                  NO ACCESS       Printer Drivers
        home                                                    NO ACCESS       INFREIGHT Samba
        dev                                                     NO ACCESS       DEVenv
        notes                                                   NO ACCESS       CheckIT
        IPC$                                                    NO ACCESS       IPC Service (DEVSM)
```

#### CrackMapExec

SMB

```shell
6165@htb[/htb]$ crackmapexec smb 10.129.14.128 --shares -u '' -p ''

SMB         10.129.14.128   445    DEVSMB           [*] Windows 6.1 Build 0 (name:DEVSMB) (domain:) (signing:False) (SMBv1:False)
SMB         10.129.14.128   445    DEVSMB           [+] \: 
SMB         10.129.14.128   445    DEVSMB           [+] Enumerated shares
SMB         10.129.14.128   445    DEVSMB           Share           Permissions     Remark
SMB         10.129.14.128   445    DEVSMB           -----           -----------     ------
SMB         10.129.14.128   445    DEVSMB           print$                          Printer Drivers
SMB         10.129.14.128   445    DEVSMB           home                            INFREIGHT Samba
SMB         10.129.14.128   445    DEVSMB           dev                             DEVenv
SMB         10.129.14.128   445    DEVSMB           notes           READ,WRITE      CheckIT
SMB         10.129.14.128   445    DEVSMB           IPC$                            IPC Service (DEVSM)
```

Another tool worth mentioning is the so-called [enum4linux-ng](https://github.com/cddmp/enum4linux-ng), which is based on an older tool, enum4linux. This tool automates many of the queries, but not all, and can return a large amount of information.

#### Enum4Linux-ng - Installation

SMB

```shell
6165@htb[/htb]$ git clone https://github.com/cddmp/enum4linux-ng.git
6165@htb[/htb]$ cd enum4linux-ng
6165@htb[/htb]$ pip3 install -r requirements.txt
```

#### Enum4Linux-ng - Enumeration

SMB

```shell
6165@htb[/htb]$ ./enum4linux-ng.py 10.129.14.128 -A

ENUM4LINUX - next generation

 ==========================
|    Target Information    |
 ==========================
[*] Target ........... 10.129.14.128
[*] Username ......... ''
[*] Random Username .. 'juzgtcsu'
[*] Password ......... ''
[*] Timeout .......... 5 second(s)

 =====================================
|    Service Scan on 10.129.14.128    |
 =====================================
[*] Checking LDAP
[-] Could not connect to LDAP on 389/tcp: connection refused
[*] Checking LDAPS
[-] Could not connect to LDAPS on 636/tcp: connection refused
[*] Checking SMB
[+] SMB is accessible on 445/tcp
[*] Checking SMB over NetBIOS
[+] SMB over NetBIOS is accessible on 139/tcp

 =====================================================
|    NetBIOS Names and Workgroup for 10.129.14.128    |
 =====================================================
[+] Got domain/workgroup name: DEVOPS
[+] Full NetBIOS names information:
- DEVSMB          <00> -         H <ACTIVE>  Workstation Service
- DEVSMB          <03> -         H <ACTIVE>  Messenger Service
- DEVSMB          <20> -         H <ACTIVE>  File Server Service
- ..__MSBROWSE__. <01> - <GROUP> H <ACTIVE>  Master Browser
- DEVOPS          <00> - <GROUP> H <ACTIVE>  Domain/Workgroup Name
- DEVOPS          <1d> -         H <ACTIVE>  Master Browser
- DEVOPS          <1e> - <GROUP> H <ACTIVE>  Browser Service Elections
- MAC Address = 00-00-00-00-00-00

 ==========================================
|    SMB Dialect Check on 10.129.14.128    |
 ==========================================
[*] Trying on 445/tcp
[+] Supported dialects and settings:
SMB 1.0: false
SMB 2.02: true
SMB 2.1: true
SMB 3.0: true
SMB1 only: false
Preferred dialect: SMB 3.0
SMB signing required: false

 ==========================================
|    RPC Session Check on 10.129.14.128    |
 ==========================================
[*] Check for null session
[+] Server allows session using username '', password ''
[*] Check for random user session
[+] Server allows session using username 'juzgtcsu', password ''
[H] Rerunning enumeration with user 'juzgtcsu' might give more results

 ====================================================
|    Domain Information via RPC for 10.129.14.128    |
 ====================================================
[+] Domain: DEVOPS
[+] SID: NULL SID
[+] Host is part of a workgroup (not a domain)

 ============================================================
|    Domain Information via SMB session for 10.129.14.128    |
 ============================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found domain information via SMB
NetBIOS computer name: DEVSMB
NetBIOS domain name: ''
DNS domain: ''
FQDN: htb

 ================================================
|    OS Information via RPC for 10.129.14.128    |
 ================================================
[*] Enumerating via unauthenticated SMB session on 445/tcp
[+] Found OS information via SMB
[*] Enumerating via 'srvinfo'
[+] Found OS information via 'srvinfo'
[+] After merging OS information we have the following result:
OS: Windows 7, Windows Server 2008 R2
OS version: '6.1'
OS release: ''
OS build: '0'
Native OS: not supported
Native LAN manager: not supported
Platform id: '500'
Server type: '0x809a03'
Server type string: Wk Sv PrQ Unx NT SNT DEVSM

 ======================================
|    Users via RPC on 10.129.14.128    |
 ======================================
[*] Enumerating users via 'querydispinfo'
[+] Found 2 users via 'querydispinfo'
[*] Enumerating users via 'enumdomusers'
[+] Found 2 users via 'enumdomusers'
[+] After merging user results we have 2 users total:
'1000':
  username: mrb3n
  name: ''
  acb: '0x00000010'
  description: ''
'1001':
  username: cry0l1t3
  name: cry0l1t3
  acb: '0x00000014'
  description: ''

 =======================================
|    Groups via RPC on 10.129.14.128    |
 =======================================
[*] Enumerating local groups
[+] Found 0 group(s) via 'enumalsgroups domain'
[*] Enumerating builtin groups
[+] Found 0 group(s) via 'enumalsgroups builtin'
[*] Enumerating domain groups
[+] Found 0 group(s) via 'enumdomgroups'

 =======================================
|    Shares via RPC on 10.129.14.128    |
 =======================================
[*] Enumerating shares
[+] Found 5 share(s):
IPC$:
  comment: IPC Service (DEVSM)
  type: IPC
dev:
  comment: DEVenv
  type: Disk
home:
  comment: INFREIGHT Samba
  type: Disk
notes:
  comment: CheckIT
  type: Disk
print$:
  comment: Printer Drivers
  type: Disk
[*] Testing share IPC$
[-] Could not check share: STATUS_OBJECT_NAME_NOT_FOUND
[*] Testing share dev
[-] Share doesn't exist
[*] Testing share home
[+] Mapping: OK, Listing: OK
[*] Testing share notes
[+] Mapping: OK, Listing: OK
[*] Testing share print$
[+] Mapping: DENIED, Listing: N/A

 ==========================================
|    Policies via RPC for 10.129.14.128    |
 ==========================================
[*] Trying port 445/tcp
[+] Found policy:
domain_password_information:
  pw_history_length: None
  min_pw_length: 5
  min_pw_age: none
  max_pw_age: 49710 days 6 hours 21 minutes
  pw_properties:
  - DOMAIN_PASSWORD_COMPLEX: false
  - DOMAIN_PASSWORD_NO_ANON_CHANGE: false
  - DOMAIN_PASSWORD_NO_CLEAR_CHANGE: false
  - DOMAIN_PASSWORD_LOCKOUT_ADMINS: false
  - DOMAIN_PASSWORD_PASSWORD_STORE_CLEARTEXT: false
  - DOMAIN_PASSWORD_REFUSE_PASSWORD_CHANGE: false
domain_lockout_information:
  lockout_observation_window: 30 minutes
  lockout_duration: 30 minutes
  lockout_threshold: None
domain_logoff_information:
  force_logoff_time: 49710 days 6 hours 21 minutes

 ==========================================
|    Printers via RPC for 10.129.14.128    |
 ==========================================
[+] No printers returned (this is not an error)

Completed after 0.61 seconds
```

We need to use more than two tools for enumeration. Because it can happen that due to the programming of the tools, we get different information that we have to check manually. Therefore, we should never rely only on automated tools where we do not know precisely how they were written.

---
## NFS #NFS

___

`Network File System` (`NFS`) is a network file system developed by Sun Microsystems and has the same purpose as SMB. Its purpose is to access file systems over a network as if they were local. However, it uses an entirely different protocol. [NFS](https://en.wikipedia.org/wiki/Network_File_System) is used between Linux and Unix systems. This means that NFS clients cannot communicate directly with SMB servers. NFS is an Internet standard that governs the procedures in a distributed file system. While NFS protocol version 3.0 (`NFSv3`), which has been in use for many years, authenticates the client computer, this changes with `NFSv4`. Here, as with the Windows SMB protocol, the user must authenticate.

| **Version** | **Features** |
| --- | --- |
| `NFSv2` | It is older but is supported by many systems and was initially operated entirely over UDP. |
| `NFSv3` | It has more features, including variable file size and better error reporting, but is not fully compatible with NFSv2 clients. |
| `NFSv4` | It includes Kerberos, works through firewalls and on the Internet, no longer requires portmappers, supports ACLs, applies state-based operations, and provides performance improvements and high security. It is also the first version to have a stateful protocol. |

NFS version 4.1 ([RFC 8881](https://datatracker.ietf.org/doc/html/rfc8881)) aims to provide protocol support to leverage cluster server deployments, including the ability to provide scalable parallel access to files distributed across multiple servers (pNFS extension). In addition, NFSv4.1 includes a session trunking mechanism, also known as NFS multipathing. A significant advantage of NFSv4 over its predecessors is that only one UDP or TCP port `2049` is used to run the service, which simplifies the use of the protocol across firewalls.

NFS is based on the [Open Network Computing Remote Procedure Call](https://en.wikipedia.org/wiki/Sun_RPC) (`ONC-RPC`/`SUN-RPC`) protocol exposed on `TCP` and `UDP` ports `111`, which uses [External Data Representation](https://en.wikipedia.org/wiki/External_Data_Representation) (`XDR`) for the system-independent exchange of data. The NFS protocol has `no` mechanism for `authentication` or `authorization`. Instead, authentication is completely shifted to the RPC protocol's options. The authorization is derived from the available file system information. In this process, the server is responsible for translating the client's user information into the file system's format and converting the corresponding authorization details into the required UNIX syntax as accurately as possible.

The most common authentication is via UNIX `UID`/`GID` and `group memberships`, which is why this syntax is most likely to be applied to the NFS protocol. One problem is that the client and server do not necessarily have to have the same mappings of UID/GID to users and groups, and the server does not need to do anything further. No further checks can be made on the part of the server. This is why NFS should only be used with this authentication method in trusted networks.

___

## Default Configuration

NFS is not difficult to configure because there are not as many options as FTP or SMB have. The `/etc/exports` file contains a table of physical filesystems on an NFS server accessible by the clients. The [NFS Exports Table](http://manpages.ubuntu.com/manpages/trusty/man5/exports.5.html) shows which options it accepts and thus indicates which options are available to us.

#### Exports File

NFS

```shell
6165@htb[/htb]$ cat /etc/exports 

# /etc/exports: the access control list for filesystems which may be exported
#               to NFS clients.  See exports(5).
#
# Example for NFSv2 and NFSv3:
# /srv/homes       hostname1(rw,sync,no_subtree_check) hostname2(ro,sync,no_subtree_check)
#
# Example for NFSv4:
# /srv/nfs4        gss/krb5i(rw,sync,fsid=0,crossmnt,no_subtree_check)
# /srv/nfs4/homes  gss/krb5i(rw,sync,no_subtree_check)
```

The default `exports` file also contains some examples of configuring NFS shares. First, the folder is specified and made available to others, and then the rights they will have on this NFS share are connected to a host or a subnet. Finally, additional options can be added to the hosts or subnets.

| **Option**         | **Description**                                                                                                                             |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `rw`               | Read and write permissions.                                                                                                                 |
| `ro`               | Read only permissions.                                                                                                                      |
| `sync`             | Synchronous data transfer. (A bit slower)                                                                                                   |
| `async`            | Asynchronous data transfer. (A bit faster)                                                                                                  |
| `secure`           | Ports above 1024 will not be used.                                                                                                          |
| `insecure`         | Ports above 1024 will be used.                                                                                                              |
| `no_subtree_check` | This option disables the checking of subdirectory trees.                                                                                    |
| `root_squash`      | Assigns all permissions to files of root UID/GID 0 to the UID/GID of anonymous, which prevents `root` from accessing files on an NFS mount. |

Let us create such an entry for test purposes and play around with the settings.

#### ExportFS

NFS

```shell
root@nfs:~# echo '/mnt/nfs  10.129.14.0/24(sync,no_subtree_check)' >> /etc/exports
root@nfs:~# systemctl restart nfs-kernel-server 
root@nfs:~# exportfs

/mnt/nfs      	10.129.14.0/24
```

We have shared the folder `/mnt/nfs` to the subnet `10.129.14.0/24` with the setting shown above. This means that all hosts on the network will be able to mount this NFS share and inspect the contents of this folder.

___

## Dangerous Settings

However, even with NFS, some settings can be dangerous for the company and its infrastructure. Here are some of them listed:

| **Option** | **Description** |
| --- | --- |
| `rw` | Read and write permissions. |
| `insecure` | Ports above 1024 will be used. |
| `nohide` | If another file system was mounted below an exported directory, this directory is exported by its own exports entry. |
| `no_root_squash` | All files created by root are kept with the UID/GID 0. |

It is highly recommended to create a local VM and experiment with the settings. We will discover methods that will show us how the NFS server is configured. For this, we can create several folders and assign different options to each one. Then we can inspect them and see what settings can have what effect on the NFS share and its permissions and the enumeration process.

We can take a look at the `insecure` option. This is dangerous because users can use ports above 1024. The first 1024 ports can only be used by root. This prevents the fact that no users can use sockets above port 1024 for the NFS service and interact with it.

___

## Footprinting the Service

When footprinting NFS, the TCP ports `111` and `2049` are essential. We can also get information about the NFS service and the host via RPC, as shown below in the example.

#### Nmap

NFS

```shell
6165@htb[/htb]$ sudo nmap 10.129.14.128 -p111,2049 -sV -sC

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:12 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00018s latency).

PORT    STATE SERVICE VERSION
111/tcp open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41982/udp6  mountd
|   100005  1,2,3      45837/tcp   mountd
|   100005  1,2,3      47217/tcp6  mountd
|   100005  1,2,3      58830/udp   mountd
|   100021  1,3,4      39542/udp   nlockmgr
|   100021  1,3,4      44629/tcp   nlockmgr
|   100021  1,3,4      45273/tcp6  nlockmgr
|   100021  1,3,4      47524/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.58 seconds
```

The `rpcinfo` NSE script retrieves a list of all currently running RPC services, their names and descriptions, and the ports they use. This lets us check whether the target share is connected to the network on all required ports. Also, for NFS, Nmap has some NSE scripts that can be used for the scans. These can then show us, for example, the `contents` of the share and its `stats`.

NFS

```shell
6165@htb[/htb]$ sudo nmap --script nfs* 10.129.14.128 -sV -p111,2049

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-19 17:37 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00021s latency).

PORT     STATE SERVICE VERSION
111/tcp  open  rpcbind 2-4 (RPC #100000)
| nfs-ls: Volume /mnt/nfs
|   access: Read Lookup NoModify NoExtend NoDelete NoExecute
| PERMISSION  UID    GID    SIZE  TIME                 FILENAME
| rwxrwxrwx   65534  65534  4096  2021-09-19T15:28:17  .
| ??????????  ?      ?      ?     ?                    ..
| rw-r--r--   0      0      1872  2021-09-19T15:27:42  id_rsa
| rw-r--r--   0      0      348   2021-09-19T15:28:17  id_rsa.pub
| rw-r--r--   0      0      0     2021-09-19T15:22:30  nfs.share
|_
| nfs-showmount: 
|_  /mnt/nfs 10.129.14.0/24
| nfs-statfs: 
|   Filesystem  1K-blocks   Used       Available   Use%  Maxfilesize  Maxlink
|_  /mnt/nfs    30313412.0  8074868.0  20675664.0  29%   16.0T        32000
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      41982/udp6  mountd
|   100005  1,2,3      45837/tcp   mountd
|   100005  1,2,3      47217/tcp6  mountd
|   100005  1,2,3      58830/udp   mountd
|   100021  1,3,4      39542/udp   nlockmgr
|   100021  1,3,4      44629/tcp   nlockmgr
|   100021  1,3,4      45273/tcp6  nlockmgr
|   100021  1,3,4      47524/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp open  nfs_acl 3 (RPC #100227)
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.45 seconds
```

Once we have discovered such an NFS service, we can mount it on our local machine. For this, we can create a new empty folder to which the NFS share will be mounted. Once mounted, we can navigate it and view the contents just like our local system.

#### Show Available NFS Shares

NFS

```shell
6165@htb[/htb]$ showmount -e 10.129.14.128

Export list for 10.129.14.128:
/mnt/nfs 10.129.14.0/24
```

#### Mounting NFS Share

NFS

```shell
6165@htb[/htb]$ mkdir target-NFS
6165@htb[/htb]$ sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock
6165@htb[/htb]$ cd target-NFS
6165@htb[/htb]$ tree .

.
└── mnt
    └── nfs
        ├── id_rsa
        ├── id_rsa.pub
        └── nfs.share

2 directories, 3 files
```

There we will have the opportunity to access the rights and the usernames and groups to whom the shown and viewable files belong. Because once we have the usernames, group names, UIDs, and GUIDs, we can create them on our system and adapt them to the NFS share to view and modify the files.

#### List Contents with Usernames & Group Names

NFS

```shell
6165@htb[/htb]$ ls -l mnt/nfs/

total 16
-rw-r--r-- 1 cry0l1t3 cry0l1t3 1872 Sep 25 00:55 cry0l1t3.priv
-rw-r--r-- 1 cry0l1t3 cry0l1t3  348 Sep 25 00:55 cry0l1t3.pub
-rw-r--r-- 1 root     root     1872 Sep 19 17:27 id_rsa
-rw-r--r-- 1 root     root      348 Sep 19 17:28 id_rsa.pub
-rw-r--r-- 1 root     root        0 Sep 19 17:22 nfs.share
```

#### List Contents with UIDs & GUIDs

NFS

```shell
6165@htb[/htb]$ ls -n mnt/nfs/

total 16
-rw-r--r-- 1 1000 1000 1872 Sep 25 00:55 cry0l1t3.priv
-rw-r--r-- 1 1000 1000  348 Sep 25 00:55 cry0l1t3.pub
-rw-r--r-- 1    0 1000 1221 Sep 19 18:21 backup.sh
-rw-r--r-- 1    0    0 1872 Sep 19 17:27 id_rsa
-rw-r--r-- 1    0    0  348 Sep 19 17:28 id_rsa.pub
-rw-r--r-- 1    0    0    0 Sep 19 17:22 nfs.share
```

It is important to note that if the `root_squash` option is set, we cannot edit the `backup.sh` file even as `root`.

We can also use NFS for further escalation. For example, if we have access to the system via SSH and want to read files from another folder that a specific user can read, we would need to upload a shell to the NFS share that has the `SUID` of that user and then run the shell via the SSH user.

After we have done all the necessary steps and obtained the information we need, we can unmount the NFS share.

#### Unmounting

NFS

```shell
6165@htb[/htb]$ cd ..
6165@htb[/htb]$ sudo umount ./target-NFS
```

---
## DNS #DNS

___

`Domain Name System` (`DNS`) is an integral part of the Internet. For example, through domain names, such as [academy.hackthebox.com](https://academy.hackthebox.com/) or [www.hackthebox.com](https://www.hackthebox.eu/), we can reach the web servers that the hosting provider has assigned one or more specific IP addresses. DNS is a system for resolving computer names into IP addresses, and it does not have a central database. Simplified, we can imagine it like a library with many different phone books. The information is distributed over many thousands of name servers. Globally distributed DNS servers translate domain names into IP addresses and thus control which server a user can reach via a particular domain. There are several types of DNS servers that are used worldwide:

-   DNS root server
-   Authoritative name server
-   Non-authoritative name server
-   Caching server
-   Forwarding server
-   Resolver

| **Server Type** | **Description** |
| --- | --- |
| `DNS Root Server` | The root servers of the DNS are responsible for the top-level domains (`TLD`). As the last instance, they are only requested if the name server does not respond. Thus, a root server is a central interface between users and content on the Internet, as it links domain and IP address. The [Internet Corporation for Assigned Names and Numbers](https://www.icann.org/) (`ICANN`) coordinates the work of the root name servers. There are `13` such root servers around the globe. |
| `Authoritative Nameserver` | Authoritative name servers hold authority for a particular zone. They only answer queries from their area of responsibility, and their information is binding. If an authoritative name server cannot answer a client's query, the root name server takes over at that point. |
| `Non-authoritative Nameserver` | Non-authoritative name servers are not responsible for a particular DNS zone. Instead, they collect information on specific DNS zones themselves, which is done using recursive or iterative DNS querying. |
| `Caching DNS Server` | Caching DNS servers cache information from other name servers for a specified period. The authoritative name server determines the duration of this storage. |
| `Forwarding Server` | Forwarding servers perform only one function: they forward DNS queries to another DNS server. |
| `Resolver` | Resolvers are not authoritative DNS servers but perform name resolution locally in the computer or router. |

DNS is mainly unencrypted. Devices on the local WLAN and Internet providers can therefore hack in and spy on DNS queries. Since this poses a privacy risk, there are now some solutions for DNS encryption. By default, IT security professionals apply `DNS over TLS` (`DoT`) or `DNS over HTTPS` (`DoH`) here. In addition, the network protocol `DNSCrypt` also encrypts the traffic between the computer and the name server.

However, the DNS does not only link computer names and IP addresses. It also stores and outputs additional information about the services associated with a domain. A DNS query can therefore also be used, for example, to determine which computer serves as the e-mail server for the domain in question or what the domain's name servers are called.

![](https://academy.hackthebox.com/storage/modules/27/tooldev-dns.png)

Different `DNS records` are used for the DNS queries, which all have various tasks. Moreover, separate entries exist for different functions since we can set up mail servers and other servers for a domain.

| **DNS Record** | **Description**                                                                                                                                                                                                                                   |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `A`            | Returns an IPv4 address of the requested domain as a result.                                                                                                                                                                                      |
| `AAAA`         | Returns an IPv6 address of the requested domain.                                                                                                                                                                                                  |
| `MX`           | Returns the responsible mail servers as a result.                                                                                                                                                                                                 |
| `NS`           | Returns the DNS servers (nameservers) of the domain.                                                                                                                                                                                              |
| `TXT`          | This record can contain various information. The all-rounder can be used, e.g., to validate the Google Search Console or validate SSL certificates. In addition, SPF and DMARC entries are set to validate mail traffic and protect it from spam. |
| `CNAME`        | This record serves as an alias. If the domain www.hackthebox.eu should point to the same IP, and we create an A record for one and a CNAME record for the other.                                                                                  |
| `PTR`          | The PTR record works the other way around (reverse lookup). It converts IP addresses into valid domain names.                                                                                                                                     |
| `SOA`          | Provides information about the corresponding DNS zone and email address of the administrative contact.                                                                                                                                            |

The `SOA` record is located in a domain's zone file and specifies who is responsible for the operation of the domain and how DNS information for the domain is managed.

DNS

```shell
6165@htb[/htb]$ dig soa www.inlanefreight.com

; <<>> DiG 9.16.27-Debian <<>> soa www.inlanefreight.com
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15876
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 1, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;www.inlanefreight.com.         IN      SOA

;; AUTHORITY SECTION:
inlanefreight.com.      900     IN      SOA     ns-161.awsdns-20.com. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Thu Jan 05 12:56:10 GMT 2023
;; MSG SIZE  rcvd: 128
```

The dot (.) is replaced by an at sign (@) in the email address. In this example, the email address of the administrator is `awsdns-hostmaster@amazon.com`.

___

## Default Configuration

There are many different configuration types for DNS. Therefore, we will only discuss the most important ones to illustrate better the functional principle from an administrative point of view. All DNS servers work with three different types of configuration files:

1.  local DNS configuration files
2.  zone files
3.  reverse name resolution files

The DNS server [Bind9](https://www.isc.org/bind/) is very often used on Linux-based distributions. Its local configuration file (`named.conf`) is roughly divided into two sections, firstly the options section for general settings and secondly the zone entries for the individual domains. The local configuration files are usually:

-   `named.conf.local`
-   `named.conf.options`
-   `named.conf.log`

It contains the associated RFC where we can customize the server to our needs and our domain structure with the individual zones for different domains. The configuration file `named.conf` is divided into several options that control the behavior of the name server. A distinction is made between `global options` and `zone options`.

Global options are general and affect all zones. A zone option only affects the zone to which it is assigned. Options not listed in named.conf have default values. If an option is both global and zone-specific, then the zone option takes precedence.

#### Local DNS Configuration

DNS

```shell
root@bind9:~# cat /etc/bind/named.conf.local

//
// Do any local configuration here
//

// Consider adding the 1918 zones here, if they are not used in your
// organization
//include "/etc/bind/zones.rfc1918";
zone "domain.com" {
    type master;
    file "/etc/bind/db.domain.com";
    allow-update { key rndc-key; };
};
```

In this file, we can define the different zones. These zones are divided into individual files, which in most cases are mainly intended for one domain only. Exceptions are ISP and public DNS servers. In addition, many different options extend or reduce the functionality. We can look these up on the [documentation](https://wiki.debian.org/Bind9) of Bind9.

A `zone file` is a text file that describes a DNS zone with the BIND file format. In other words it is a point of delegation in the DNS tree. The BIND file format is the industry-preferred zone file format and is now well established in DNS server software. A zone file describes a zone completely. There must be precisely one `SOA` record and at least one `NS` record. The SOA resource record is usually located at the beginning of a zone file. The main goal of these global rules is to improve the readability of zone files. A syntax error usually results in the entire zone file being considered unusable. The name server behaves similarly as if this zone did not exist. It responds to DNS queries with a `SERVFAIL` error message.

In short, here, all `forward records` are entered according to the BIND format. This allows the DNS server to identify which domain, hostname, and role the IP addresses belong to. In simple terms, this is the phone book where the DNS server looks up the addresses for the domains it is searching for.

#### Zone Files

DNS

```shell
root@bind9:~# cat /etc/bind/db.domain.com

;
; BIND reverse data file for local loopback interface
;
$ORIGIN domain.com
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

      IN     MX     10     mx.domain.com.
      IN     MX     20     mx2.domain.com.

             IN     A       10.129.14.5

server1      IN     A       10.129.14.5
server2      IN     A       10.129.14.7
ns1          IN     A       10.129.14.2
ns2          IN     A       10.129.14.3

ftp          IN     CNAME   server1
mx           IN     CNAME   server1
mx2          IN     CNAME   server2
www          IN     CNAME   server2
```

For the IP address to be resolved from the `Fully Qualified Domain Name` (`FQDN`), the DNS server must have a reverse lookup file. In this file, the computer name (FQDN) is assigned to the last octet of an IP address, which corresponds to the respective host, using a `PTR` record. The PTR records are responsible for the reverse translation of IP addresses into names, as we have already seen in the above table.

#### Reverse Name Resolution Zone Files

DNS

```shell
root@bind9:~# cat /etc/bind/db.10.129.14

;
; BIND reverse data file for local loopback interface
;
$ORIGIN 14.129.10.in-addr.arpa
$TTL 86400
@     IN     SOA    dns1.domain.com.     hostmaster.domain.com. (
                    2001062501 ; serial
                    21600      ; refresh after 6 hours
                    3600       ; retry after 1 hour
                    604800     ; expire after 1 week
                    86400 )    ; minimum TTL of 1 day

      IN     NS     ns1.domain.com.
      IN     NS     ns2.domain.com.

5    IN     PTR    server1.domain.com.
7    IN     MX     mx.domain.com.
...SNIP...
```

___

## Dangerous Settings

There are many ways in which a DNS server can be attacked. For example, a list of vulnerabilities targeting the BIND9 server can be found at [CVEdetails](https://www.cvedetails.com/product/144/ISC-Bind.html?vendor_id=64). In addition, SecurityTrails provides a short [list](https://securitytrails.com/blog/most-popular-types-dns-attacks) of the most popular attacks on DNS servers.

Some of the settings we can see below lead to these vulnerabilities, among others. Because DNS can get very complicated and it is very easy for errors to creep into this service, forcing an administrator to work around the problem until they find an exact solution. This often leads to elements being released so that parts of the infrastructure function as planned and desired. In such cases, functionality has a higher priority than security, which leads to misconfigurations and vulnerabilities.

| **Option** | **Description** |
| --- | --- |
| `allow-query` | Defines which hosts are allowed to send requests to the DNS server. |
| `allow-recursion` | Defines which hosts are allowed to send recursive requests to the DNS server. |
| `allow-transfer` | Defines which hosts are allowed to receive zone transfers from the DNS server. |
| `zone-statistics` | Collects statistical data of zones. |

___

## Footprinting the Service

The footprinting at DNS servers is done as a result of the requests we send. So, first of all, the DNS server can be queried as to which other name servers are known. We do this using the NS record and the specification of the DNS server we want to query using the `@` character. This is because if there are other DNS servers, we can also use them and query the records. However, other DNS servers may be configured differently and, in addition, may be permanent for other zones.

#### DIG - NS Query

DNS

```shell
6165@htb[/htb]$ dig ns inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> ns inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45010
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: ce4d8681b32abaea0100000061475f73842c401c391690c7 (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      NS

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:04:03 CEST 2021
;; MSG SIZE  rcvd: 107
```

Sometimes it is also possible to query a DNS server's version using a class CHAOS query and type TXT. However, this entry must exist on the DNS server. For this, we could use the following command:

#### DIG - Version Query

DNS

```shell
6165@htb[/htb]$ dig CH TXT version.bind 10.129.120.85

; <<>> DiG 9.10.6 <<>> CH TXT version.bind
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47786
;; flags: qr aa rd; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; ANSWER SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1"

;; ADDITIONAL SECTION:
version.bind.       0       CH      TXT     "9.10.6-P1-Debian"

;; Query time: 2 msec
;; SERVER: 10.129.120.85#53(10.129.120.85)
;; WHEN: Wed Jan 05 20:23:14 UTC 2023
;; MSG SIZE  rcvd: 101
```

We can use the option `ANY` to view all available records. This will cause the server to show us all available entries that it is willing to disclose. It is important to note that not all entries from the zones will be shown.

#### DIG - ANY Query

DNS

```shell
6165@htb[/htb]$ dig any inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> any inlanefreight.htb @10.129.14.128
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 7649
;; flags: qr aa rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 2

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 4096
; COOKIE: 064b7e1f091b95120100000061476865a6026d01f87d10ca (good)
;; QUESTION SECTION:
;inlanefreight.htb.             IN      ANY

;; ANSWER SECTION:
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.

;; ADDITIONAL SECTION:
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136

;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:42:13 CEST 2021
;; MSG SIZE  rcvd: 437
```

`Zone transfer` refers to the transfer of zones to another server in DNS, which generally happens over TCP port 53. This procedure is abbreviated `Asynchronous Full Transfer Zone` (`AXFR`). Since a DNS failure usually has severe consequences for a company, the zone file is almost invariably kept identical on several name servers. When changes are made, it must be ensured that all servers have the same data. Synchronization between the servers involved is realized by zone transfer. Using a secret key `rndc-key`, which we have seen initially in the default configuration, the servers make sure that they communicate with their own master or slave. Zone transfer involves the mere transfer of files or records and the detection of discrepancies in the data sets of the servers involved.

The original data of a zone is located on a DNS server, which is called the `primary` name server for this zone. However, to increase the reliability, realize a simple load distribution, or protect the primary from attacks, one or more additional servers are installed in practice in almost all cases, which are called `secondary` name servers for this zone. For some `Top-Level Domains` (`TLDs`), making zone files for the `Second Level Domains` accessible on at least two servers is mandatory.

DNS entries are generally only created, modified, or deleted on the primary. This can be done by manually editing the relevant zone file or automatically by a dynamic update from a database. A DNS server that serves as a direct source for synchronizing a zone file is called a master. A DNS server that obtains zone data from a master is called a slave. A primary is always a master, while a secondary can be both a slave and a master.

The slave fetches the `SOA` record of the relevant zone from the master at certain intervals, the so-called refresh time, usually one hour, and compares the serial numbers. If the serial number of the SOA record of the master is greater than that of the slave, the data sets no longer match.

#### DIG - AXFR Zone Transfer

DNS

```shell
6165@htb[/htb]$ dig axfr inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr inlanefreight.htb @10.129.14.128
;; global options: +cmd
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
inlanefreight.htb.      604800  IN      TXT     "MS=ms97310371"
inlanefreight.htb.      604800  IN      TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
inlanefreight.htb.      604800  IN      TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
inlanefreight.htb.      604800  IN      NS      ns.inlanefreight.htb.
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
internal.inlanefreight.htb. 604800 IN   A       10.129.1.6
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
inlanefreight.htb.      604800  IN      SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 4 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:51:19 CEST 2021
;; XFR size: 9 records (messages 1, bytes 520)
```

If the administrator used a subnet for the `allow-transfer` option for testing purposes or as a workaround solution or set it to `any`, everyone would query the entire zone file at the DNS server. In addition, other zones can be queried, which may even show internal IP addresses and hostnames.

#### DIG - AXFR Zone Transfer - Internal

DNS

```shell
6165@htb[/htb]$ dig axfr internal.inlanefreight.htb @10.129.14.128

; <<>> DiG 9.16.1-Ubuntu <<>> axfr internal.inlanefreight.htb @10.129.14.128
;; global options: +cmd
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
internal.inlanefreight.htb. 604800 IN   TXT     "MS=ms97310371"
internal.inlanefreight.htb. 604800 IN   TXT     "atlassian-domain-verification=t1rKCy68JFszSdCKVpw64A1QksWdXuYFUeSXKU"
internal.inlanefreight.htb. 604800 IN   TXT     "v=spf1 include:mailgun.org include:_spf.google.com include:spf.protection.outlook.com include:_spf.atlassian.net ip4:10.129.124.8 ip4:10.129.127.2 ip4:10.129.42.106 ~all"
internal.inlanefreight.htb. 604800 IN   NS      ns.inlanefreight.htb.
dc1.internal.inlanefreight.htb. 604800 IN A     10.129.34.16
dc2.internal.inlanefreight.htb. 604800 IN A     10.129.34.11
mail1.internal.inlanefreight.htb. 604800 IN A   10.129.18.200
ns.internal.inlanefreight.htb. 604800 IN A      10.129.34.136
vpn.internal.inlanefreight.htb. 604800 IN A     10.129.1.6
ws1.internal.inlanefreight.htb. 604800 IN A     10.129.1.34
ws2.internal.inlanefreight.htb. 604800 IN A     10.129.1.35
wsus.internal.inlanefreight.htb. 604800 IN A    10.129.18.2
internal.inlanefreight.htb. 604800 IN   SOA     inlanefreight.htb. root.inlanefreight.htb. 2 604800 86400 2419200 604800
;; Query time: 0 msec
;; SERVER: 10.129.14.128#53(10.129.14.128)
;; WHEN: So Sep 19 18:53:11 CEST 2021
;; XFR size: 15 records (messages 1, bytes 664)
```

The individual `A` records with the hostnames can also be found out with the help of a brute-force attack. To do this, we need a list of possible hostnames, which we use to send the requests in order. Such lists are provided, for example, by [SecLists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/DNS/subdomains-top1million-5000.txt).

An option would be to execute a `for-loop` in Bash that lists these entries and sends the corresponding query to the desired DNS server.

#### Subdomain Brute Forcing

DNS

```shell
6165@htb[/htb]$ for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done

ns.inlanefreight.htb.   604800  IN      A       10.129.34.136
mail1.inlanefreight.htb. 604800 IN      A       10.129.18.201
app.inlanefreight.htb.  604800  IN      A       10.129.18.15
```

Many different tools can be used for this, and most of them work in the same way. One of these tools is, for example [DNSenum](https://github.com/fwaeytens/dnsenum).

DNS

```shell
6165@htb[/htb]$ dnsenum --dnsserver 10.129.14.128 --enum -p 0 -s 0 -o subdomains.txt -f /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt inlanefreight.htb

dnsenum VERSION:1.2.6

-----   inlanefreight.htb   -----


Host's addresses:
__________________



Name Servers:
______________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136


Mail (MX) Servers:
___________________



Trying Zone Transfers and getting Bind Versions:
_________________________________________________

unresolvable name: ns.inlanefreight.htb at /usr/bin/dnsenum line 900 thread 1.

Trying Zone Transfer for inlanefreight.htb on ns.inlanefreight.htb ...
AXFR record query failed: no nameservers


Brute forcing with /home/cry0l1t3/Pentesting/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:
_______________________________________________________________________________________________________

ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136
mail1.inlanefreight.htb.                 604800   IN    A        10.129.18.201
app.inlanefreight.htb.                   604800   IN    A        10.129.18.15
ns.inlanefreight.htb.                    604800   IN    A        10.129.34.136

...SNIP...
done.
```

---
## SMTP #SMTP

___

The `Simple Mail Transfer Protocol` (`SMTP`) is a protocol for sending emails in an IP network. It can be used between an email client and an outgoing mail server or between two SMTP servers. SMTP is often combined with the IMAP or POP3 protocols, which can fetch emails and send emails. In principle, it is a client-server-based protocol, although SMTP can be used between a client and a server and between two SMTP servers. In this case, a server effectively acts as a client.

By default, SMTP servers accept connection requests on port `25`. However, newer SMTP servers also use other ports such as TCP port `587`. This port is used to receive mail from authenticated users/servers, usually using the STARTTLS command to switch the existing plaintext connection to an encrypted connection. The authentication data is protected and no longer visible in plaintext over the network. At the beginning of the connection, authentication occurs when the client confirms its identity with a user name and password. The emails can then be transmitted. For this purpose, the client sends the server sender and recipient addresses, the email's content, and other information and parameters. After the email has been transmitted, the connection is terminated again. The email server then starts sending the email to another SMTP server.

SMTP works unencrypted without further measures and transmits all commands, data, or authentication information in plain text. To prevent unauthorized reading of data, the SMTP is used in conjunction with SSL/TLS encryption. Under certain circumstances, a server uses a port other than the standard TCP port `25` for the encrypted connection, for example, TCP port `465`.

An essential function of an SMTP server is preventing spam using authentication mechanisms that allow only authorized users to send e-mails. For this purpose, most modern SMTP servers support the protocol extension ESMTP with SMTP-Auth. After sending his e-mail, the SMTP client, also known as `Mail User Agent` (`MUA`), converts it into a header and a body and uploads both to the SMTP server. This has a so-called `Mail Transfer Agent` (`MTA`), the software basis for sending and receiving e-mails. The MTA checks the e-mail for size and spam and then stores it. To relieve the MTA, it is occasionally preceded by a `Mail Submission Agent` (`MSA`), which checks the validity, i.e., the origin of the e-mail. This `MSA` is also called `Relay` server. These are very important later on, as the so-called `Open Relay Attack` can be carried out on many SMTP servers due to incorrect configuration. We will discuss this attack and how to identify the weak point for it a little later. The MTA then searches the DNS for the IP address of the recipient mail server.

On arrival at the destination SMTP server, the data packets are reassembled to form a complete e-mail. From there, the `Mail delivery agent` (`MDA`) transfers it to the recipient's mailbox.

| Client (`MUA`) | `➞` | Submission Agent (`MSA`) | `➞` | Open Relay (`MTA`) | `➞` | Mail Delivery Agent (`MDA`) | `➞` | Mailbox (`POP3`/`IMAP`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |

But SMTP has two disadvantages inherent to the network protocol.

1.  The first is that sending an email using SMTP does not return a usable delivery confirmation. Although the specifications of the protocol provide for this type of notification, its formatting is not specified by default, so that usually only an English-language error message, including the header of the undelivered message, is returned.
    
2.  Users are not authenticated when a connection is established, and the sender of an email is therefore unreliable. As a result, open SMTP relays are often misused to send spam en masse. The originators use arbitrary fake sender addresses for this purpose to not be traced (mail spoofing). Today, many different security techniques are used to prevent the misuse of SMTP servers. For example, suspicious emails are rejected or moved to quarantine (spam folder). For example, responsible for this are the identification protocol [DomainKeys](http://dkim.org/) (`DKIM`), the [Sender Policy Framework](https://dmarcian.com/what-is-spf/) (`SPF`).
    

For this purpose, an extension for SMTP has been developed called `Extended SMTP` (`ESMTP`). When people talk about SMTP in general, they usually mean ESMTP. ESMTP uses TLS, which is done after the `EHLO` command by sending `STARTTLS`. This initializes the SSL-protected SMTP connection, and from this moment on, the entire connection is encrypted, and therefore more or less secure. Now [AUTH PLAIN](https://www.samlogic.net/articles/smtp-commands-reference-auth.htm) extension for authentication can also be used safely.

___

## Default Configuration

Each SMTP server can be configured in many ways, as can all other services. However, there are differences because the SMTP server is only responsible for sending and forwarding emails.

#### Default Configuration

SMTP

```shell
6165@htb[/htb]$ cat /etc/postfix/main.cf | grep -v "#" | sed -r "/^\s*$/d"

smtpd_banner = ESMTP Server 
biff = no
append_dot_mydomain = no
readme_directory = no
compatibility_level = 2
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
myhostname = mail1.inlanefreight.htb
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
smtp_generic_maps = hash:/etc/postfix/generic
mydestination = $myhostname, localhost 
masquerade_domains = $myhostname
mynetworks = 127.0.0.0/8 10.129.0.0/16
mailbox_size_limit = 0
recipient_delimiter = +
smtp_bind_address = 0.0.0.0
inet_protocols = ipv4
smtpd_helo_restrictions = reject_invalid_hostname
home_mailbox = /home/postfix
```

The sending and communication are also done by special commands that cause the SMTP server to do what the user requires.

| **Command** | **Description** |
| --- | --- |
| `AUTH PLAIN` | AUTH is a service extension used to authenticate the client. |
| `HELO` | The client logs in with its computer name and thus starts the session. |
| `MAIL FROM` | The client names the email sender. |
| `RCPT TO` | The client names the email recipient. |
| `DATA` | The client initiates the transmission of the email. |
| `RSET` | The client aborts the initiated transmission but keeps the connection between client and server. |
| `VRFY` | The client checks if a mailbox is available for message transfer. |
| `EXPN` | The client also checks if a mailbox is available for messaging with this command. |
| `NOOP` | The client requests a response from the server to prevent disconnection due to time-out. |
| `QUIT` | The client terminates the session. |

To interact with the SMTP server, we can use the `telnet` tool to initialize a TCP connection with the SMTP server. The actual initialization of the session is done with the command mentioned above, `HELO` or `EHLO`.

#### Telnet - HELO/EHLO

SMTP

```shell
6165@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 


HELO mail1.inlanefreight.htb

250 mail1.inlanefreight.htb


EHLO mail1

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING
```

The command `VRFY` can be used to enumerate existing users on the system. However, this does not always work. Depending on how the SMTP server is configured, the SMTP server may issue `code 252` and confirm the existence of a user that does not exist on the system. A list of all SMTP response codes can be found [here](https://serversmtp.com/smtp-error/).

#### Telnet - VRFY

SMTP

```shell
6165@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server 

VRFY root

252 2.0.0 root


VRFY cry0l1t3

252 2.0.0 cry0l1t3


VRFY testuser

252 2.0.0 testuser


VRFY aaaaaaaaaaaaaaaaaaaaaaaaaaaa

252 2.0.0 aaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

Therefore, one should never entirely rely on the results of automatic tools. After all, they execute pre-configured commands, but none of the functions explicitly state how the administrator configures the tested server.

Sometimes we may have to work through a web proxy. We can also make this web proxy connect to the SMTP server. The command that we would send would then look something like this: `CONNECT 10.129.14.128:25 HTTP/1.0`

All the commands we enter in the command line to send an email we know from every email client program like Thunderbird, Gmail, Outlook, and many others. We specify the `subject`, to whom the email should go, CC, BCC, and the information we want to share with others. Of course, the same works from the command line.

#### Send an Email

SMTP

```shell
6165@htb[/htb]$ telnet 10.129.14.128 25

Trying 10.129.14.128...
Connected to 10.129.14.128.
Escape character is '^]'.
220 ESMTP Server


EHLO inlanefreight.htb

250-mail1.inlanefreight.htb
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250-DSN
250-SMTPUTF8
250 CHUNKING


MAIL FROM: <cry0l1t3@inlanefreight.htb>

250 2.1.0 Ok


RCPT TO: <mrb3n@inlanefreight.htb> NOTIFY=success,failure

250 2.1.5 Ok


DATA

354 End data with <CR><LF>.<CR><LF>

From: <cry0l1t3@inlanefreight.htb>
To: <mrb3n@inlanefreight.htb>
Subject: DB
Date: Tue, 28 Sept 2021 16:32:51 +0200
Hey man, I am trying to access our XY-DB but the creds don't work. 
Did you make any changes there?
.

250 2.0.0 Ok: queued as 6E1CF1681AB


QUIT

221 2.0.0 Bye
Connection closed by foreign host.
```

The mail header is the carrier of a large amount of interesting information in an email. Among other things, it provides information about the sender and recipient, the time of sending and arrival, the stations the email passed on its way, the content and format of the message, and the sender and recipient.

Some of this information is mandatory, such as sender information and when the email was created. Other information is optional. However, the email header does not contain any information necessary for technical delivery. It is transmitted as part of the transmission protocol. Both sender and recipient can access the header of an email, although it is not visible at first glance. The structure of an email header is defined by [RFC5322](https://datatracker.ietf.org/doc/html/rfc5322).

___

## Dangerous Settings

To prevent the sent emails from being filtered by spam filters and not reaching the recipient, the sender can use a relay server that the recipient trusts. It is an SMTP server that is known and verified by all others. As a rule, the sender must authenticate himself to the relay server before using it.

Often, administrators have no overview of which IP ranges they have to allow. This results in a misconfiguration of the SMTP server that we will still often find in external and internal penetration tests. Therefore, they allow all IP addresses not to cause errors in the email traffic and thus not to disturb or unintentionally interrupt the communication with potential and current customers.

#### Open Relay Configuration

SMTP

```shell
mynetworks = 0.0.0.0/0
```

With this setting, this SMTP server can send fake emails and thus initialize communication between multiple parties. Another attack possibility would be to spoof the email and read it.

___

## Footprinting the Service

The default Nmap scripts include `smtp-commands`, which uses the `EHLO` command to list all possible commands that can be executed on the target SMTP server.

#### Nmap

SMTP

```shell
6165@htb[/htb]$ sudo nmap 10.129.14.128 -sC -sV -p25

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-27 17:56 CEST
Nmap scan report for 10.129.14.128
Host is up (0.00025s latency).

PORT   STATE SERVICE VERSION
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: mail1.inlanefreight.htb, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING, 
MAC Address: 00:00:00:00:00:00 (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.09 seconds
```

However, we can also use the [smtp-open-relay](https://nmap.org/nsedoc/scripts/smtp-open-relay.html) NSE script to identify the target SMTP server as an open relay using 16 different tests. If we also print out the output of the scan in detail, we will also be able to see which tests the script is running.

#### Nmap - Open Relay

SMTP

```shell
6165@htb[/htb]$ sudo nmap 10.129.14.128 -p25 --script smtp-open-relay -v

Starting Nmap 7.80 ( https://nmap.org ) at 2021-09-30 02:29 CEST
NSE: Loaded 1 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Initiating ARP Ping Scan at 02:29
Scanning 10.129.14.128 [1 port]
Completed ARP Ping Scan at 02:29, 0.06s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:29
Completed Parallel DNS resolution of 1 host. at 02:29, 0.03s elapsed
Initiating SYN Stealth Scan at 02:29
Scanning 10.129.14.128 [1 port]
Discovered open port 25/tcp on 10.129.14.128
Completed SYN Stealth Scan at 02:29, 0.06s elapsed (1 total ports)
NSE: Script scanning 10.129.14.128.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.07s elapsed
Nmap scan report for 10.129.14.128
Host is up (0.00020s latency).

PORT   STATE SERVICE
25/tcp open  smtp
| smtp-open-relay: Server is an open relay (16/16 tests)
|  MAIL FROM:<> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@nmap.scanme.org> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@ESMTP> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest%nmap.scanme.org@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest%nmap.scanme.org@ESMTP>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest@nmap.scanme.org">
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest%nmap.scanme.org">
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<"relaytest@nmap.scanme.org"@[10.129.14.128]>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<relaytest@nmap.scanme.org@ESMTP>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@[10.129.14.128]:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<@ESMTP:relaytest@nmap.scanme.org>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest>
|  MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest@[10.129.14.128]>
|_ MAIL FROM:<antispam@[10.129.14.128]> -> RCPT TO:<nmap.scanme.org!relaytest@ESMTP>
MAC Address: 00:00:00:00:00:00 (VMware)

NSE: Script Post-scanning.
Initiating NSE at 02:29
Completed NSE at 02:29, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.48 seconds
           Raw packets sent: 2 (72B) | Rcvd: 2 (72B)
```

---
