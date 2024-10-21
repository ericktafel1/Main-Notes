---
date: 2024-10-21
title: Lazy Admin THM Write-Up
machine_ip: varies
os: Linux
difficulty: Medium
my_rating: 
tags: 
references: "[[📚CTF Box Writeups]]"
---

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
		- `dirsearch dir -u  http://<ip>:<port> -w /path/to/wordlist.txt`
	- Dirbuster, whatweb, etc.
	- ffuf - vhosts, then add to `/etc/hosts`
		- `ffuf -w /usr/share/seclists/SecLists-master/Discovery/DNS/shubs-subdomains.txt -u http://<IP> -H "HOST: FUZZ.website.com". -fs <Size1>,<Size2> -fw <wordcount>`
	- wfuzz - vhosts, then add to `/etc/hosts`
		- `wfuzz -c -f sub-fighter -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u 'http://website.com' -H "HOST: FUZZ.website.com" -fs <Size1>,<Size2> --hw <wordcount>`
- ftp
	- `anonymous`
- smb
	- list shares with no login
	- 

---
# Foothold

- gain shell via exploit
- `Search-That-Hash`
- Stablize shell
	- Step 1: `python3 -c 'import pty;pty.spawn("/bin/bash")'`  
	- Step 2: `CTRL + Z`  
	- Step 3: `stty raw -echo; fg` 
	- Step 4: `export TERM=xterm`

## Pivot to user
- enumerate!
- 

---
# PrivEsc

- escalate to root
- PrivEsc_Linux
- PrivEsc_Windows
- HackTricks
- GTFOBins
- PayloadAllThings