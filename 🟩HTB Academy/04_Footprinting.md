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
