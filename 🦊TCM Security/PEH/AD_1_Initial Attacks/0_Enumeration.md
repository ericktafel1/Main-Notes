If applicable, use these notes...

`netdiscover -r 192.168.95.0/24`

- See HTB nmap notes

- Use dirbuster GUI

- msf to enumerate SMB and other services

- `ssh 192.168.95.131 -oKexAlgorithms=+diffie-hellman-group1-sha1 -c aes128-cbc`
	- grabs banner

Nessus
- Download it for .deb
- `/bin/systemctl start nessusd.server `
- navigate to `https://kali:8834/`
- See HTB Notes (Vuln Assessment)