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
	- `rustscan -a 10.10.10.10 -t 500 -b 1500 -- -sVC` 
	- `-- -` then nmap tacks
		- Misses some open ports so also use **nmap**
	- Also, may need do manage the container
		- `docker ps -a`
		- `docker rm -f <name>`
		- `alias rustscan='docker run -it --rm --name rustscan rustscan/rustscan:alpine'`
		- Then run scan...
- Nmap
	- `nmap -sVC -A -Pn <ip>`

- Web enumeration
	- feroxbuster
		- `feroxbuster -u http://<ip> -k -r -v --filter-status 403 400 500 503 404`
	- gobuster
		- `gobuster dir -u  http://<ip> --wordlist /path/to/wordlist.txt`
	- Dirbuster, dirsearch, whatweb, etc.

# Foothold
- gain shell via exploit


# PrivEsc
[[Privilege Escalation]], [[1_Initial_Enumeration]]
- escalate to root