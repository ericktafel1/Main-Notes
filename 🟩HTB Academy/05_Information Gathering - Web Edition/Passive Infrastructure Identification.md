
___

[Netcraft](https://www.netcraft.com/) can offer us information about the servers without even interacting with them, and this is something valuable from a passive information gathering point of view. We can use the service by visiting `https://sitereport.netcraft.com` and entering the target domain.

![](https://academy.hackthebox.com/storage/modules/144/netcraft_facebook.png)

Some interesting details we can observe from the report are:

|  |  |
| --- | --- |
| `Background` | General information about the domain, including the date it was first seen by Netcraft crawlers. |
| `Network` | Information about the netblock owner, hosting company, nameservers, etc. |
| `Hosting history` | Latest IPs used, webserver, and target OS. |

We need to pay special attention to the latest IPs used. Sometimes we can spot the actual IP address from the webserver before it was placed behind a load balancer, web application firewall, or IDS, allowing us to connect directly to it if the configuration allows it. This kind of technology could interfere with or alter our future testing activities.

___

## Wayback Machine

The [Internet Archive](https://en.wikipedia.org/wiki/Internet_Archive) is an American digital library that provides free public access to digitalized materials, including websites, collected automatically via its web crawlers.

We can access several versions of these websites using the [Wayback Machine](http://web.archive.org/) to find old versions that may have interesting comments in the source code or files that should not be there. This tool can be used to find older versions of a website at a point in time. Let's take a website running WordPress, for example. We may not find anything interesting while assessing it using manual methods and automated tools, so we search for it using Wayback Machine and find a version that utilizes a specific (now vulnerable) plugin. Heading back to the current version of the site, we find that the plugin was not removed properly and can still be accessed via the `wp-content` directory. We can then utilize it to gain remote code execution on the host and a nice bounty.

![image](https://academy.hackthebox.com/storage/modules/144/wayback1.png)

We can check one of the first versions of `facebook.com` captured on December 1, 2005, which is interesting, perhaps gives us a sense of nostalgia but is also extremely useful for us as security researchers.

![](https://academy.hackthebox.com/storage/modules/144/wayback2.png)

We can also use the tool [waybackurls](https://github.com/tomnomnom/waybackurls) to inspect URLs saved by Wayback Machine and look for specific keywords. Provided we have `Go` set up correctly on our host, we can install the tool as follows:

Passive Infrastructure Identification

```shell
6165@htb[/htb]$ go install github.com/tomnomnom/waybackurls@latest
```

To get a list of crawled URLs from a domain with the date it was obtained, we can add the `-dates` switch to our command as follows:

Passive Infrastructure Identification #waybackurls

```shell
6165@htb[/htb]$ waybackurls -dates https://facebook.com > waybackurls.txt
6165@htb[/htb]$ cat waybackurls.txt

2018-05-20T09:46:07Z http://www.facebook.com./
2018-05-20T10:07:12Z https://www.facebook.com/
2018-05-20T10:18:51Z http://www.facebook.com/#!/pages/Welcome-Baby/143392015698061?ref=tsrobots.txt
2018-05-20T10:19:19Z http://www.facebook.com/
2018-05-20T16:00:13Z http://facebook.com
2018-05-21T22:12:55Z https://www.facebook.com
2018-05-22T15:14:09Z http://www.facebook.com
2018-05-22T17:34:48Z http://www.facebook.com/#!/Syerah?v=info&ref=profile/robots.txt
2018-05-23T11:03:47Z http://www.facebook.com/#!/Bin595

<SNIP>
```

If we want to access a specific resource, we need to place the URL in the search menu and navigate to the date when the snapshot was created. As stated previously, Wayback Machine can be a handy tool and should not be overlooked. It can very likely lead to us discovering forgotten assets, pages, etc., which can lead to discovering a flaw.
