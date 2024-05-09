
___

Subdomain enumeration refers to mapping all available subdomains within a domain name. It increases our attack surface and may uncover hidden management backend panels or intranet web applications that network administrators expected to keep hidden using the "security by obscurity" strategy. At this point, we will only perform passive subdomain enumeration using third-party services or publicly available information. Still, we will expand the information we gather in future active subdomain enumeration activities.

___

## VirusTotal

VirusTotal maintains its DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them. To receive information about a domain, type the domain name into the search bar and click on the "Relations" tab.

![image](https://academy.hackthebox.com/storage/modules/144/virustotal.png)

___

## Certificates

Another interesting source of information we can use to extract subdomains is SSL/TLS certificates. The main reason is Certificate Transparency (CT), a project that requires every SSL/TLS certificate issued by a Certificate Authority (CA) to be published in a publicly accessible log.

We will learn how to examine CT logs to discover additional domain names and subdomains for a target organization using two primary resources:

-   [https://censys.io](https://censys.io/)
    
-   [https://crt.sh](https://crt.sh/)
    

We can navigate to https://search.censys.io/certificates or https://crt.sh and introduce the domain name of our target organization to start discovering new subdomains.

![image](https://academy.hackthebox.com/storage/modules/144/censys_facebook.png)

![](https://academy.hackthebox.com/storage/modules/144/crt_facebook.png)

Although the website is excellent, we would like to have this information organized and be able to combine it with other sources found throughout the information-gathering process. Let us perform a curl request to the target website asking for a JSON output as this is more manageable for us to process. We can do this via the following commands:

#### Certificate Transparency

Passive Subdomain Enumeration

```shell
6165@htb[/htb]$ export TARGET="facebook.com"
6165@htb[/htb]$ curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
```

Passive Subdomain Enumeration

```shell
6165@htb[/htb]$ head -n20 facebook.com_crt.sh.txt

*.adtools.facebook.com
*.ak.facebook.com
*.ak.fbcdn.net
*.alpha.facebook.com
*.assistant.facebook.com
*.beta.facebook.com
*.channel.facebook.com
*.cinyour.facebook.com
*.cinyourrc.facebook.com
*.connect.facebook.com
*.cstools.facebook.com
*.ctscan.facebook.com
*.dev.facebook.com
*.dns.facebook.com
*.extern.facebook.com
*.extools.facebook.com
*.f--facebook.com
*.facebook.com
*.facebookcorewwwi.onion
*.facebookmail.com
```

|  |  |
| --- | --- |
| `curl -s` | Issue the request with minimal output. |
| `https://crt.sh/?q=<DOMAIN>&output=json` | Ask for the json output. |
| `jq -r '.[]' "\(.name_value)\n\(.common_name)"'` | Process the json output and print certificate's name value and common name one per line. |
| `sort -u` | Sort alphabetically the output provided and removes duplicates. |

We also can manually perform this operation against a target using OpenSSL via:

Passive Subdomain Enumeration

```shell
6165@htb[/htb]$ export TARGET="facebook.com"
6165@htb[/htb]$ export PORT="443"
6165@htb[/htb]$ openssl s_client -ign_eof 2>/dev/null <<<$'HEAD / HTTP/1.0\r\n\r' -connect "${TARGET}:${PORT}" | openssl x509 -noout -text -in - | grep 'DNS' | sed -e 's|DNS:|\n|g' -e 's|^\*.*||g' | tr -d ',' | sort -u

*.facebook.com
*.facebook.net
*.fbcdn.net
*.fbsbx.com
*.m.facebook.com
*.messenger.com
*.xx.fbcdn.net
*.xy.fbcdn.net
*.xz.fbcdn.net
facebook.com
messenger.com
```

___

## Automating Passive Subdomain Enumeration

We have learned how to acquire helpful information from our target organization, like subdomains, naming patterns, alternate TLDs, IP ranges, etc., using third-party services without interacting directly with their infrastructure or relying on automated tools. Now, we will learn how to enumerate subdomains using tools and previously obtained information.

___

#### TheHarvester #TheHarvester

[TheHarvester](https://github.com/laramies/theHarvester) is a simple-to-use yet powerful and effective tool for early-stage penetration testing and red team engagements. We can use it to gather information to help identify a company's attack surface. The tool collects `emails`, `names`, `subdomains`, `IP addresses`, and `URLs` from various public data sources for passive information gathering. For now, we will use the following modules:

|  |  |
| --- | --- |
| [Baidu](http://www.baidu.com/) | Baidu search engine. |
| `Bufferoverun` | Uses data from Rapid7's Project Sonar - [www.rapid7.com/research/project-sonar/](http://www.rapid7.com/research/project-sonar/) |
| [Crtsh](https://crt.sh/) | Comodo Certificate search. |
| [Hackertarget](https://hackertarget.com/) | Online vulnerability scanners and network intelligence to help organizations. |
| `Otx` | AlienVault Open Threat Exchange - [https://otx.alienvault.com](https://otx.alienvault.com/) |
| [Rapiddns](https://rapiddns.io/) | DNS query tool, which makes querying subdomains or sites using the same IP easy. |
| [Sublist3r](https://github.com/aboul3la/Sublist3r) | Fast subdomains enumeration tool for penetration testers |
| [Threatcrowd](http://www.threatcrowd.org/) | Open source threat intelligence. |
| [Threatminer](https://www.threatminer.org/) | Data mining for threat intelligence. |
| `Trello` | Search Trello boards (Uses Google search) |
| [Urlscan](https://urlscan.io/) | A sandbox for the web that is a URL and website scanner. |
| `Vhost` | Bing virtual hosts search. |
| [Virustotal](https://www.virustotal.com/gui/home/search) | Domain search. |
| [Zoomeye](https://www.zoomeye.org/) | A Chinese version of Shodan. |

To automate this, we will create a file called sources.txt with the following contents.

Passive Subdomain Enumeration

```shell
6165@htb[/htb]$ cat sources.txt

baidu
bufferoverun
crtsh
hackertarget
otx
projectdiscovery
rapiddns
sublist3r
threatcrowd
trello
urlscan
vhost
virustotal
zoomeye
```

Once the file is created, we will execute the following commands to gather information from these sources.

Passive Subdomain Enumeration

```shell
6165@htb[/htb]$ export TARGET="facebook.com"
6165@htb[/htb]$ cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done

<SNIP>
*******************************************************************
*  _   _                                            _             *
* | |_| |__   ___    /\  /\__ _ _ ____   _____  ___| |_ ___ _ __  *
* | __|  _ \ / _ \  / /_/ / _` | '__\ \ / / _ \/ __| __/ _ \ '__| *
* | |_| | | |  __/ / __  / (_| | |   \ V /  __/\__ \ ||  __/ |    *
*  \__|_| |_|\___| \/ /_/ \__,_|_|    \_/ \___||___/\__\___|_|    *
*                                                                 *
* theHarvester 4.0.0                                              *
* Coded by Christian Martorella                                   *
* Edge-Security Research                                          *
* cmartorella@edge-security.com                                   *
*                                                                 *
*******************************************************************


[*] Target: facebook.com

[*] Searching Urlscan.

[*] ASNS found: 29
--------------------
AS12578
AS13335
AS13535
AS136023
AS14061
AS14618
AS15169
AS15817

<SNIP>
```

When the process finishes, we can extract all the subdomains found and sort them via the following command:

Passive Subdomain Enumeration

```shell
6165@htb[/htb]$ cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
```

Now we can merge all the passive reconnaissance files via:

Passive Subdomain Enumeration

```shell
6165@htb[/htb]$ cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
6165@htb[/htb]$ cat facebook.com_subdomains_passive.txt | wc -l

11947
```

So far, we have managed to find 11947 subdomains merging the passive reconnaissance result files. It is important to note here that there are many more methods to find subdomains passively. More possibilities are shown, for example, in the [OSINT: Corporate Recon](https://academy.hackthebox.com/course/preview/osint-corporate-recon) module.
