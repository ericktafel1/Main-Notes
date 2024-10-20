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
	- feroxbuster - directories/files
		- `feroxbuster -u http://<ip>:<port> -k -r -v --filter-status 403,400,404`
	- gobuster
		- `gobuster dir -u  http://<ip>:<port> --wordlist /path/to/wordlist.txt`
	- dirsearch
		- `gobuster dir -u  http://<ip>:<port> -w /path/to/wordlist.txt`
	- Dirbuster, whatweb, etc.
	- ffuf - vhosts
		- `ffuf -w /usr/share/seclists/SecLists-master/Discovery/DNS/shubs-subdomains.txt -u http://<IP> -H "HOST: FUZZ.website.com". -fs <Size1>,<Size2>`

---
# Foothold

- gain shell via exploit
- Stablize shell
	- Step 1: `python3 -c 'import pty;pty.spawn("/bin/bash")'`  
	- Step 2: `CTRL + Z`  
	- Step 3: `stty raw -echo; fg` 
	- Step 4: `export TERM=xterm`

## Pivot to user
- enumerate!

---
# PrivEsc

- escalate to root