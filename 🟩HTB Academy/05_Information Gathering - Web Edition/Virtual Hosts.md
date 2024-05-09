
___

A virtual host (`vHost`) is a feature that allows several websites to be hosted on a single server. This is an excellent solution if you have many websites and don't want to go through the time-consuming (and expensive) process of setting up a new web server for each one. Imagine having to set up a different webserver for a mobile and desktop version of the same page. There are two ways to configure virtual hosts:

-   `IP`\-based virtual hosting
-   `Name`\-based virtual hosting

#### IP-based Virtual Hosting

For this type, a host can have multiple network interfaces. Multiple IP addresses, or interface aliases, can be configured on each network interface of a host. The servers or virtual servers running on the host can bind to one or more IP addresses. This means that different servers can be addressed under different IP addresses on this host. From the client's point of view, the servers are independent of each other.

#### Name-based Virtual Hosting

The distinction for which domain the service was requested is made at the application level. For example, several domain names, such as `admin.inlanefreight.htb` and `backup.inlanefreight.htb`, can refer to the same IP. Internally on the server, these are separated and distinguished using different folders. Using this example, on a Linux server, the vHost `admin.inlanefreight.htb` could point to the folder `/var/www/admin`. For `backup.inlanefreight.htb` the folder name would then be adapted and could look something like `/var/www/backup`.

During our subdomain discovering activities, we have seen some subdomains having the same IP address that can either be virtual hosts or, in some cases, different servers sitting behind a proxy.

Imagine we have identified a web server at `192.168.10.10` during an internal pentest, and it shows a default website using the following command. Are there any virtual hosts present?

Virtual Hosts

```shell
6165@htb[/htb]$ curl -s http://192.168.10.10

<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
```

Let's make a `cURL` request sending a domain previously identified during the information gathering in the `HOST` header. We can do that like so:

Virtual Hosts

```shell
6165@htb[/htb]$ curl -s http://192.168.10.10 -H "Host: randomtarget.com"

<html>
    <head>
        <title>Welcome to randomtarget.com!</title>
    </head>
    <body>
        <h1>Success! The randomtarget.com server block is working!</h1>
    </body>
</html>
```

Now we can automate this by using a dictionary file of possible vhost names (such as `/opt/useful/SecLists/Discovery/DNS/namelist.txt` on the Pwnbox) and examining the Content-Length header to look for any differences.

#### vHosts List

Virtual Hosts

```shell
app
blog
dev-admin
forum
help
m
my
shop
some
store
support
www
```

#### vHost Fuzzing

Virtual Hosts

```shell
6165@htb[/htb]$ cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done


********
FUZZING: app
********
Content-Length: 612

********
FUZZING: blog
********
Content-Length: 612

********
FUZZING: dev-admin
********
Content-Length: 120

********
FUZZING: forum
********
Content-Length: 612

********
FUZZING: help
********
Content-Length: 612

********
FUZZING: m
********
Content-Length: 612

********
FUZZING: my
********
Content-Length: 612

********
FUZZING: shop
********
Content-Length: 612

********
FUZZING: some
********
Content-Length: 195

********
FUZZING: store
********
Content-Length: 612

********
FUZZING: support
********
Content-Length: 612

********
FUZZING: www
********
Content-Length: 185
```

We have successfully identified a virtual host called `dev-admin`, which we can access using a `cURL` request.

Virtual Hosts

```shell
6165@htb[/htb]$ curl -s http://192.168.10.10 -H "Host: dev-admin.randomtarget.com"

<!DOCTYPE html>
<html>
<body>

<h1>Randomtarget.com Admin Website</h1>

<p>You shouldn't be here!</p>

</body>
</html>
```

___

## Automating Virtual Hosts Discovery #ffuf

We can use this manual approach for a small list of virtual hosts, but it will not be feasible if we have an extensive list. Using [ffuf](https://github.com/ffuf/ffuf), we can speed up the process and filter based on parameters present in the response. Let's replicate the same process we did with ffuf, but first, let's look at some of its options.

Virtual Hosts

```shell
MATCHER OPTIONS:
  -mc                 Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403,405)
  -ml                 Match amount of lines in response
  -mr                 Match regexp
  -ms                 Match HTTP response size
  -mw                 Match amount of words in response

FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges
```

We can match or filter responses based on different options. The web server responds with a default and static website every time we issue an invalid virtual host in the `HOST` header. We can use the filter by size `-fs` option to discard the default response as it will always have the same size.

Virtual Hosts

```shell
6165@htb[/htb]$ ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.1.0-git
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.10.10
 :: Wordlist         : FUZZ: ./vhosts
 :: Header           : Host: FUZZ.randomtarget.com
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 612
________________________________________________

dev-admin               [Status: 200, Size: 120, Words: 7, Lines: 12]
www                     [Status: 200, Size: 185, Words: 41, Lines: 9]
some                    [Status: 200, Size: 195, Words: 41, Lines: 9]
:: Progress: [12/12] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
```

where:

-   `-w`: Path to our wordlist (`/usr/share/dirb/wordlists/common.txt`, `/usr/share/seclists/Discovery/DNS/namelist.txt`)
-   `-u`: URL we want to fuzz
-   `-H "HOST: FUZZ.randomtarget.com"`: This is the `HOST` Header, and the word `FUZZ` will be used as the fuzzing point.
-   `-fs 612`: Filter responses with a size of 612, default response size in this case.