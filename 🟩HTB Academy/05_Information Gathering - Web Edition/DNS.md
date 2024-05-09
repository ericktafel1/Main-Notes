#DNS 

___

We can start looking further into the data to identify particular targets now that we have some information about our target. The [Domain Name System](https://en.wikipedia.org/wiki/Domain_Name_System) (`DNS`) is an excellent place to look for this kind of information. But first, let us take a look at what DNS is.

___

## What is DNS?

The DNS is the Internet's phone book. Domain names such as `hackthebox.com` and `inlanefreight.com` allow people to access content on the Internet. Internet Protocol (`IP`) addresses are used to communicate between web browsers. DNS converts domain names to IP addresses, allowing browsers to access resources on the Internet.

Each Internet-connected device has a unique IP address that other machines use to locate it. DNS servers minimize the need for people to learn IP addresses like `104.17.42.72` in `IPv4` or more sophisticated modern alphanumeric IP addresses like `2606:4700::6811:2b48` in `IPv6`. When a user types `www.facebook.com` into their web browser, a translation must occur between what the user types and the IP address required to reach the `www.facebook.com` webpage.

Some of the advantages of using DNS are:

-   It allows names to be used instead of numbers to identify hosts.
-   It is a lot easier to remember a name than it is to recall a number.
-   By merely retargeting a name to the new numeric address, a server can change numeric addresses without having to notify everyone on the Internet.
-   A single name might refer to several hosts splitting the workload between different servers.

There is a hierarchy of names in the DNS structure. The system's root, or highest level, is unnamed.

TLDs nameservers, the Top-Level Domains, might be compared to a single shelf of books in a library. The last portion of a hostname is hosted by this nameserver, which is the following stage in the search for a specific IP address (in `www.facebook.com`, the TLD server is `com`). Most TLDs have been delegated to individual country managers, who are issued codes from the [ISO-3166-1 table](https://en.wikipedia.org/wiki/List_of_ISO_3166_country_codes). These are known as country-code Top-Level Domains or ccTLDs managed by a United Nations agency.

There are also a small number of "generic" Top Level Domains (gTLDs) that are not associated with a specific country or region. TLD managers have been granted responsibility for procedures and policies for the assignment of Second Level Domain Names (SLDs) and lower level hierarchies of names, according to the policy advice specified in ISO-3166-1.

A manager for each nation organizes country code domains. These managers provide a public service on behalf of the Internet community. Resource Records are the results of DNS queries and have the following structure:

|  |  |
| --- | --- |
| `Resource Record` | A domain name, usually a fully qualified domain name, is the first part of a Resource Record. If you don't use a fully qualified domain name, the zone's name where the record is located will be appended to the end of the name. |
| `TTL` | In seconds, the Time-To-Live (`TTL`) defaults to the minimum value specified in the SOA record. |
| `Record Class` | Internet, Hesiod, or Chaos |
| `Start Of Authority` (`SOA`) | It should be first in a zone file because it indicates the start of a zone. Each zone can only have one `SOA` record, and additionally, it contains the zone's values, such as a serial number and multiple expiration timeouts. |
| `Name Servers` (`NS`) | The distributed database is bound together by `NS` Records. They are in charge of a zone's authoritative name server and the authority for a child zone to a name server. |
| `IPv4 Addresses` (`A`) | The A record is only a mapping between a hostname and an IP address. 'Forward' zones are those with `A` records. |
| `Pointer` (`PTR`) | The PTR record is a mapping between an IP address and a hostname. 'Reverse' zones are those that have `PTR` records. |
| `Canonical Name` (`CNAME`) | An alias hostname is mapped to an `A` record hostname using the `CNAME` record. |
| `Mail Exchange` (`MX`) | The `MX` record identifies a host that will accept emails for a specific host. A priority value has been assigned to the specified host. Multiple MX records can exist on the same host, and a prioritized list is made consisting of the records for a specific host. |

___
## Nslookup & DIG #nslookup #dig


Now that we have a clear understanding of what DNS is, let us take a look at the `Nslookup` command-line utility. Let us assume that a customer requested us to perform an external penetration test. Therefore, we first need to familiarize ourselves with their infrastructure and identify which hosts are publicly accessible. We can find this out using different types of DNS requests. With `Nslookup`, we can search for domain name servers on the Internet and ask them for information about hosts and domains. Although the tool has two modes, interactive and non-interactive, we will mainly focus on the non-interactive module.

We can query `A` records by just submitting a domain name. But we can also use the `-query` parameter to search specific resource records. Some examples are:

#### Querying: A Records

DNS

```shell
6165@htb[/htb]$ export TARGET="facebook.com"
6165@htb[/htb]$ nslookup $TARGET

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	facebook.com
Address: 31.13.92.36
Name:	facebook.com
Address: 2a03:2880:f11c:8083:face:b00c:0:25de
```

We can also specify a nameserver if needed by adding `@<nameserver/IP>` to the command. Unlike nslookup, `DIG` shows us some more information that can be of importance.

DNS

```shell
6165@htb[/htb]$ dig facebook.com @1.1.1.1

; <<>> DiG 9.16.1-Ubuntu <<>> facebook.com @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 58899
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;facebook.com.                  IN      A

;; ANSWER SECTION:
facebook.com.           169     IN      A       31.13.92.36

;; Query time: 20 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Mo Okt 18 16:03:17 CEST 2021
;; MSG SIZE  rcvd: 57
```

The entry starts with the complete domain name, including the final dot. The entry may be held in the cache for `169` seconds before the information must be requested again. The class is understandably the Internet (`IN`).

#### Querying: A Records for a Subdomain

DNS

```shell
6165@htb[/htb]$ export TARGET=www.facebook.com
6165@htb[/htb]$ nslookup -query=A $TARGET

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
www.facebook.com	canonical name = star-mini.c10r.facebook.com.
Name:	star-mini.c10r.facebook.com
Address: 31.13.92.36
```

DNS

```shell
6165@htb[/htb]$ dig a www.facebook.com @1.1.1.1

; <<>> DiG 9.16.1-Ubuntu <<>> a www.facebook.com @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 15596
;; flags: qr rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;www.facebook.com.              IN      A

;; ANSWER SECTION:
www.facebook.com.       3585    IN      CNAME   star-mini.c10r.facebook.com.
star-mini.c10r.facebook.com. 45 IN      A       31.13.92.36

;; Query time: 16 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Mo Okt 18 16:11:48 CEST 2021
;; MSG SIZE  rcvd: 90
```

#### Querying: PTR Records for an IP Address #PTR

DNS

```shell
6165@htb[/htb]$ nslookup -query=PTR 31.13.92.36

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
36.92.13.31.in-addr.arpa	name = edge-star-mini-shv-01-frt3.facebook.com.

Authoritative answers can be found from:
```

DNS

```shell
6165@htb[/htb]$ dig -x 31.13.92.36 @1.1.1.1

; <<>> DiG 9.16.1-Ubuntu <<>> -x 31.13.92.36 @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51730
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;36.92.13.31.in-addr.arpa.      IN      PTR

;; ANSWER SECTION:
36.92.13.31.in-addr.arpa. 1028  IN      PTR     edge-star-mini-shv-01-frt3.facebook.com.

;; Query time: 16 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Mo Okt 18 16:14:20 CEST 2021
;; MSG SIZE  rcvd: 106
```

#### Querying: ANY Existing Records #ANY

In this example, we are using Google as an example instead of Facebook as the last one did not respond to our query.

DNS

```shell
6165@htb[/htb]$ export TARGET="google.com"
6165@htb[/htb]$ nslookup -query=ANY $TARGET

Server:		10.100.0.1
Address:	10.100.0.1#53

Non-authoritative answer:
Name:	google.com
Address: 172.217.16.142
Name:	google.com
Address: 2a00:1450:4001:808::200e
google.com	text = "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
google.com	text = "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
google.com	text = "v=spf1 include:_spf.google.com ~all"
google.com	text = "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
google.com	text = "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
google.com	text = "apple-domain-verification=30afIBcvSuDV2PLX"
google.com	text = "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
google.com	text = "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
google.com	text = "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
google.com	nameserver = ns3.google.com.
google.com	nameserver = ns2.google.com.
google.com	nameserver = ns1.google.com.
google.com	nameserver = ns4.google.com.
google.com	mail exchanger = 10 aspmx.l.google.com.
google.com	mail exchanger = 40 alt3.aspmx.l.google.com.
google.com	mail exchanger = 20 alt1.aspmx.l.google.com.
google.com	mail exchanger = 30 alt2.aspmx.l.google.com.
google.com	mail exchanger = 50 alt4.aspmx.l.google.com.
google.com
	origin = ns1.google.com
	mail addr = dns-admin.google.com
	serial = 398195569
	refresh = 900
	retry = 900
	expire = 1800
	minimum = 60
google.com	rdata_257 = 0 issue "pki.goog"

Authoritative answers can be found from:
```

DNS

```shell
6165@htb[/htb]$ dig any google.com @8.8.8.8

; <<>> DiG 9.16.1-Ubuntu <<>> any google.com @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 49154
;; flags: qr rd ra; QUERY: 1, ANSWER: 22, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;google.com.                    IN      ANY

;; ANSWER SECTION:
google.com.             249     IN      A       142.250.184.206
google.com.             249     IN      AAAA    2a00:1450:4001:830::200e
google.com.             549     IN      MX      10 aspmx.l.google.com.
google.com.             3549    IN      TXT     "apple-domain-verification=30afIBcvSuDV2PLX"
google.com.             3549    IN      TXT     "facebook-domain-verification=22rm551cu4k0ab0bxsw536tlds4h95"
google.com.             549     IN      MX      20 alt1.aspmx.l.google.com.
google.com.             3549    IN      TXT     "docusign=1b0a6754-49b1-4db5-8540-d2c12664b289"
google.com.             3549    IN      TXT     "v=spf1 include:_spf.google.com ~all"
google.com.             3549    IN      TXT     "globalsign-smime-dv=CDYX+XFHUw2wml6/Gb8+59BsH31KzUr6c1l2BPvqKX8="
google.com.             3549    IN      TXT     "google-site-verification=wD8N7i1JTNTkezJ49swvWW48f8_9xveREV4oB-0Hf5o"
google.com.             9       IN      SOA     ns1.google.com. dns-admin.google.com. 403730046 900 900 1800 60
google.com.             21549   IN      NS      ns1.google.com.
google.com.             21549   IN      NS      ns3.google.com.
google.com.             549     IN      MX      50 alt4.aspmx.l.google.com.
google.com.             3549    IN      TXT     "docusign=05958488-4752-4ef2-95eb-aa7ba8a3bd0e"
google.com.             549     IN      MX      30 alt2.aspmx.l.google.com.
google.com.             21549   IN      NS      ns2.google.com.
google.com.             21549   IN      NS      ns4.google.com.
google.com.             549     IN      MX      40 alt3.aspmx.l.google.com.
google.com.             3549    IN      TXT     "MS=E4A68B9AB2BB9670BCE15412F62916164C0B20BB"
google.com.             3549    IN      TXT     "google-site-verification=TV9-DBe4R80X4v0M4U_bd_J9cpOJM0nikft0jAgjmsQ"
google.com.             21549   IN      CAA     0 issue "pki.goog"

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mo Okt 18 16:15:22 CEST 2021
;; MSG SIZE  rcvd: 922
```

The more recent [RFC8482](https://tools.ietf.org/html/rfc8482) specified that `ANY` DNS requests be abolished. Therefore, we may not receive a response to our `ANY` request from the DNS server or get a reference to the said RFC8482.

DNS

```shell
6165@htb[/htb]$ dig any cloudflare.com @8.8.8.8

; <<>> DiG 9.16.1-Ubuntu <<>> any cloudflare.com @8.8.8.8
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 22509
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 512
;; QUESTION SECTION:
;cloudflare.com.                        IN      ANY

;; ANSWER SECTION:
cloudflare.com.         2747    IN      HINFO   "RFC8482" ""
cloudflare.com.         2747    IN      RRSIG   HINFO 13 2 3789 20211019145905 20211017125905 34505 cloudflare.com. 4/Bq8xUN96SrOhuH0bj2W6s2pXRdv5L5NWsgyTAGLAjEwwEF4y4TQuXo yGtvD3B13jr5KhdXo1VtrLLMy4OR8Q==

;; Query time: 16 msec
;; SERVER: 8.8.8.8#53(8.8.8.8)
;; WHEN: Mo Okt 18 16:16:27 CEST 2021
;; MSG SIZE  rcvd: 174
```

#### Querying: TXT Records #TXT

DNS

```shell
6165@htb[/htb]$ export TARGET="facebook.com"
6165@htb[/htb]$ nslookup -query=TXT $TARGET

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
facebook.com	text = "v=spf1 redirect=_spf.facebook.com"
facebook.com	text = "google-site-verification=A2WZWCNQHrGV_TWwKh6KHY90tY0SHZo_RnyMJoDaG0s"
facebook.com	text = "google-site-verification=wdH5DTJTc9AYNwVunSVFeK0hYDGUIEOGb-RReU6pJlY"

Authoritative answers can be found from:
```

DNS

```shell
6165@htb[/htb]$ dig txt facebook.com @1.1.1.1

; <<>> DiG 9.16.1-Ubuntu <<>> txt facebook.com @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 63771
;; flags: qr rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;facebook.com.                  IN      TXT

;; ANSWER SECTION:
facebook.com.           86400   IN      TXT     "v=spf1 redirect=_spf.facebook.com"
facebook.com.           7200    IN      TXT     "google-site-verification=A2WZWCNQHrGV_TWwKh6KHY90tY0SHZo_RnyMJoDaG0s"
facebook.com.           7200    IN      TXT     "google-site-verification=wdH5DTJTc9AYNwVunSVFeK0hYDGUIEOGb-RReU6pJlY"

;; Query time: 24 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Mo Okt 18 16:17:46 CEST 2021
;; MSG SIZE  rcvd: 249
```

#### Querying: MX Records #MX

DNS

```shell
6165@htb[/htb]$ export TARGET="facebook.com"
6165@htb[/htb]$ nslookup -query=MX $TARGET

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
facebook.com	mail exchanger = 10 smtpin.vvv.facebook.com.

Authoritative answers can be found from:
```

DNS

```shell
6165@htb[/htb]$ dig mx facebook.com @1.1.1.1

; <<>> DiG 9.16.1-Ubuntu <<>> mx facebook.com @1.1.1.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 9392
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags:; udp: 1232
;; QUESTION SECTION:
;facebook.com.                  IN      MX

;; ANSWER SECTION:
facebook.com.           3600    IN      MX      10 smtpin.vvv.facebook.com.

;; Query time: 40 msec
;; SERVER: 1.1.1.1#53(1.1.1.1)
;; WHEN: Mo Okt 18 16:18:22 CEST 2021
;; MSG SIZE  rcvd: 68
```

So far, we have gathered `A`, `NS`, `MX`, and `CNAME` records with the `nslookup` and `dig` commands. Organizations are given IP addresses on the Internet, but they aren't always their owners. They might rely on `ISP`s and hosting providers that lease smaller netblocks to them.

We can combine some of the results gathered via nslookup with the whois database to determine if our target organization uses hosting providers. This combination looks like the following example:

#### Nslookup #nslookup 

DNS

```shell
6165@htb[/htb]$ export TARGET="facebook.com"
6165@htb[/htb]$ nslookup $TARGET

Server:		1.1.1.1
Address:	1.1.1.1#53

Non-authoritative answer:
Name:	facebook.com
Address: 157.240.199.35
Name:	facebook.com
Address: 2a03:2880:f15e:83:face:b00c:0:25de
```

#### WHOIS #whois

DNS

```shell
6165@htb[/htb]$ whois 157.240.199.35

NetRange:       157.240.0.0 - 157.240.255.255
CIDR:           157.240.0.0/16
NetName:        THEFA-3
NetHandle:      NET-157-240-0-0-1
Parent:         NET157 (NET-157-0-0-0-0)
NetType:        Direct Assignment
OriginAS:
Organization:   Facebook, Inc. (THEFA-3)
RegDate:        2015-05-14
Updated:        2015-05-14
Ref:            https://rdap.arin.net/registry/ip/157.240.0.0



OrgName:        Facebook, Inc.
OrgId:          THEFA-3
Address:        1601 Willow Rd.
City:           Menlo Park
StateProv:      CA
PostalCode:     94025
Country:        US
RegDate:        2004-08-11
Updated:        2012-04-17
Ref:            https://rdap.arin.net/registry/entity/THEFA-3


OrgAbuseHandle: OPERA82-ARIN
OrgAbuseName:   Operations
OrgAbusePhone:  +1-650-543-4800
OrgAbuseEmail:  domain@facebook.com
OrgAbuseRef:    https://rdap.arin.net/registry/entity/OPERA82-ARIN

OrgTechHandle: OPERA82-ARIN
OrgTechName:   Operations
OrgTechPhone:  +1-650-543-4800
OrgTechEmail:  domain@facebook.com
OrgTechRef:    https://rdap.arin.net/registry/entity/OPERA82-ARIN
```
