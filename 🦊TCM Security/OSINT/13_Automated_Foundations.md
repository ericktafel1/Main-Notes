#OSINT #subfinder #assetfinder #Httprobe #amass #gowitness 

- Subfinder - [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)

- Assetfinder - [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder)

- httprobe - [https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe)

- Amass - [https://github.com/OWASP/Amass](https://github.com/OWASP/Amass)

- GoWitness - [https://github.com/sensepost/gowitness/wiki/Installation](https://github.com/sensepost/gowitness/wiki/Installation)

# Tool OSINT Chain
- `whois tcm-sec.com`
- `subfinder -d tcm-sec.com`
- `assetfinder tcm-sec.com`
- `amass enum -d tcm-sec.com`
- `cat tesla.txt | sort -u | httprobe -s -p https:443`
- `gowitness file -f ./alive.txt -P ./pics --no-http`

Automate these into a #bash script
```
#!/bin/bash

# Use the first argument as the domain name
domain=$1
# Define colors
RED="\033[1;31m"
RESET="\033[0m"

# Define directories
base_dir="$domain"
info_path="$base_dir/info"
subdomain_path="$base_dir/subdomains" screenshot_path="$base_dir/screenshots"

# Create directories if they don't exist
for path in "$info_path" "$subdomain_path" "$screenshot_path"; do
	if [ ! -d "$path" ]; then
		mkdir -p "$path"
		echo "Created directory: $path"
	fi
done

echo -e "${RED} [+] Checking who it is ... ${RESET}"
whois "$domain" > "$info_path/whois.txt"

echo -e "${RED} [+] Launching subfinder ... ${RESET}"
subfinder -d "$domain" > "$subdomain_path/found.txt"

echo -e "${RED} [+] Running assetfinder ... ${RESET}"
assetfinder "$domain" | grep "$domain" >> "$subdomain_path/found.txt"

echo -e "${RED} [+] Checking what's alive ... ${RESET}"
cat "$subdomain_path/found.txt" | grep "$domain" | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a "$subdomain_path/alive.txt"

echo -e "${RED} [+] Taking screenshots ... ${RESET}"
gowitness file -f "$subdomain_path/alive.txt" -P "$screenshot_path/" --no-http
```