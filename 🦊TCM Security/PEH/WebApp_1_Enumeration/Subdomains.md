#go #assetfinder 

Installing with `go`
```
go get -u github.com/tomnomnom/assetfinder
```

# Assetfinder

```
assetfinder tesla.com >> tesla-subs.txt
```

To find only subs for domain:
```
assetfinder --subs-only tesla.com
```

Create a script to automate subdomain enumeration:
```
gedit subs.sh
```

run.sh:
```
#!/bin/bash

url=$1

if [ ! -d "$url" ];then
	mkdir $url
fi

if [ ! -d "$url/recon" ];then
	mkdir $url/recon
fi


echo "[+] Harvesting subdomains with assetfinder for Overlord Erick..."
assetfinder $url >> $url/recon/raw.txt
cat $url/recon/raw.txt | grep $1 >> $url/recon/assets.txt
rm $url/recon/raw.txt
```

Output of script:
```
┌──(root㉿kali)-[/home/kali/Documents/PEH]
└─# ./subs.sh tesla.com
[+] Harvesting subdomains with assetfinder for Overlord Erick...

┌──(root㉿kali)-[/home/kali/Documents/PEH]
└─# cd tesla.com/recon 

┌──(root㉿kali)-[/home/…/Documents/PEH/tesla.com/recon]
└─# ls
assets.txt

┌──(root㉿kali)-[/home/…/Documents/PEH/tesla.com/recon]
└─# head assets.txt                                                 
tesla.com
ams13-gpgw1.tesla.com
comparison.tesla.com
dal11-gpgw1.tesla.com
mta.email.tesla.com
mta2.email.tesla.com
emails.tesla.com
click.emails.tesla.com
mta.emails.tesla.com
mta2.emails.tesla.com
```