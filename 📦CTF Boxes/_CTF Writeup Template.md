---
date: 
title: "[BOX] HTB Write-Up"
machine_ip: 10.10.10.4
os: Windows
difficulty: Medium
my_rating: 
tags: 
references: "[[📚CTF Box Writeups]]"
---
dataview properties:
dataview properties:

---
date:
title: HTB Write-Up
machine_ip: 
os: 
difficulty: 
my_rating
tags:
references: HTB Writeups

---


*must be on first line



# Enumeration


- Rustscan
	- `rustscan -a 10.10.10.10 -t 2000 -b 2000 -- -A -sVC -p- -Pn` 
	- `-- -` then nmap tacks
		- Misses some open ports so also use **nmap**
	- Also, may need do manage the container
		- `docker ps -a`
		- `docker rm -f <name>`
		- `alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:alpine'`
		- Then run scan...
	- may need to re-download `.deb` package from [here](https://github.com/RustScan/RustScan/releases/download/2.3.0/rustscan_2.3.0_amd64.deb), and run:
		- `dpkg -i <rustscan.deb>`
		- `rustscan` should work now

- Nmap
	- `nmap <ip> -A -sVC -p- -Pn --script 'default,vuln'`

- Web enumeration
	- feroxbuster
		- `feroxbuster -u http://<ip>:<port> -k -r -v --filter-status 403,400,404`
	- gobuster
		- `gobuster dir -u  http://<ip>:<port> --wordlist /path/to/wordlist.txt`
	- dirsearch
		- `gobuster dir -u  http://<ip>:<port> -w /path/to/wordlist.txt`
	- Dirbuster, whatweb, etc.

---
# Foothold

- gain shell via exploit


---
# PrivEsc

- escalate to root