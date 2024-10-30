#OSINT #exiftool #sherlock #phoneinfoga #InstagramOSINT #recon-ng #maltego 
*Use browser OSINT from previous notes with these tools*
# Image and Location
#exiftool 
- Basic usage: `exiftool <img>`
- To save to a file: `exiftool <img> > file.txt`

# Emails and Breached Data

- Dehashed API Tool: [https://github.com/hmaverickadams/DeHashed-API-Tool](https://github.com/hmaverickadams/DeHashed-API-Tool)
	- Requires paid access to dehashed and API

# Username and Account
#sherlock 
- `sudo apt install sherlock`
- `sherlock thecybermentor`

# Phone Number
#phoneinfoga 
- `bash <( curl -sSL https://raw.githubusercontent.com/sundowndev/phoneinfoga/master/support/scripts/install )`
- `phoneinfoga scan -n 12148675309`
- `phoneinfoga serve -p 8080`

# Social Media
#InstagramOSINT 
- Install [tool](https://github.com/sc1341/InstagramOSINT) to `/opt/InstagramOSINT`
- `pip install -r requirements.txt`
- `python3 main.py --username USERNAME`

# OSINT Frameworks
#recon-ng #maltego
- `recon-ng`
	- `marketplace search`
	- `marketplace install hackertarget`
		- `modules load hackertarget`
		- `info`
		- `options set SOURCE website.com`
		- `run`
		- `show hosts`
	- `marketplace install profiler`
		- `modules load profiler`
		- `info`
		- `options set SOURCE username`
		- `run`
		- `show profiles`
- `maltego`
	- Maltego CE (Free) > Accept > Register Account

# Other Tools

- Hunchly - [https://hunch.ly](https://hunch.ly/)
