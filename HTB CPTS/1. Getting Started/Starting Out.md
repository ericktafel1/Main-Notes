* HTB Academy follows a `guided` learning approach where students work through a module on a given subject, reading the material, and reproducing the examples to reinforce the topics presented.
* The main HTB platform follows an `exploratory` learning approach to put users in a wide variety of real-world scenarios in which they have to use their technical skills and processes such as enumeration to achieve an, often unknown, goal.

---
## Resources

* There are many resources available to practice common web and network vulnerabilities in a safe, controlled setting. The following are some examples of purposefully vulnerable web applications and vulnerable machines that we can set up in a lab environment for extra practice:
	* [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) - Is a modern vulnerable web application written in Node.js, Express, and Angular which showcases the entire [OWASP Top Ten](https://owasp.org/www-project-top-ten) along with many other real-world application security flaws.
	* [Metasploitable 2](https://docs.rapid7.com/metasploit/metasploitable-2-exploitability-guide/) - Is a purposefully vulnerable Ubuntu Linux VM that can be used to practice enumeration, automated, and manual exploitation.
	* [Metasploitable 3](https://github.com/rapid7/metasploitable3) - Is a template for building a vulnerable Windows VM configured with a wide range of [vulnerabilities](https://github.com/rapid7/metasploitable3/wiki/Vulnerabilities).
	* [DVWA](https://github.com/digininja/DVWA) - This is a vulnerable PHP/MySQL web application showcasing many common web application vulnerabilities with varying degrees of difficulty.
* There are many YouTube channels out there that showcase penetration testing/hacking techniques. A few worth bookmarking are:
	* [IppSec](https://www.youtube.com/channel/UCa6eh7gCkpPo5XXUDfygQQA) - Provides an extremely in-depth walkthrough of every retired HTB box packed full of insight from his own experience, as well as videos on various techniques.
	* [VbScrub](https://www.youtube.com/channel/UCpoyhjwNIWZmsiKNKpsMAQQ) - Provides HTB videos as well as videos on techniques, primarily focusing on Active Directory exploitation.
	* [STÖK](https://www.youtube.com/channel/UCQN2DsjnYH60SFBIA6IkNwg) - Provides videos on various infosec related topics, mainly focusing on bug bounties and web application penetration testing.
	* [LiveOverflow](https://www.youtube.com/channel/UClcE-kVhqyiHCcjYwcpfj9w) - Provides videos on a wide variety of technical infosec topics.
* One great blog worth checking out is [0xdf hacks stuff](https://0xdf.gitlab.io/).
* There are many tutorial websites out there for practicing fundamental IT skills, such as scripting. 
* Two great tutorial websites are [Under The Wire](https://underthewire.tech/wargames) and [Over The Wire](https://overthewire.org/wargames/). These websites are set up to help train users on using both Windows `PowerShell` and the Linux command line, respectively, through various scenarios in a "war games" format.
* [Starting Point](https://app.hackthebox.com/starting-point) is an introduction to HTB labs and basic machines/challenges. After completing a tutorial covering connecting to VPN, enumeration, gaining a foothold, and privilege escalation against a single target, we are presented with several easy-rated machines that can be attacked before accessing the rest of the HTB platform.
* On the main HTB platform [Tracks](https://app.hackthebox.com/tracks), "selections of machines and challenges tied together for users to progress through, mastering a particular subject." Tracks cover a variety of topics and are continually being added to the platform. Their goal is to help students stay focused on a specific goal in a structured way while following an exploratory learning approach.
* There are many beginner-friendly machines on the main HTB platform. Some recommended ones are:

|[Lame](https://app.hackthebox.com/machines/1)|[Blue](https://app.hackthebox.com/machines/51)|[Nibbles](https://app.hackthebox.com/machines/121)|[Shocker](https://app.hackthebox.com/machines/108)|[Jerry](https://app.hackthebox.com/machines/144)|
|---|---|---|---|---|
*  The HTB platform contains one-off challenges in a variety of categories. Some beginner-friendly challenges include:

|[Find The Easy Pass](https://app.hackthebox.com/challenges/5)|[Weak RSA](https://app.hackthebox.com/challenges/6)|[You know 0xDiablos](https://app.hackthebox.com/challenges/106)|
|---|---|---|
* The [Dante Pro Lab](https://app.hackthebox.com/prolabs/overview/dante) is the most beginner-friendly prolab offered to date. This lab is geared towards players with some experience performing network and web application attacks and an understanding of networking concepts and the basics of penetration methodologies such as scanning/enumeration, lateral movement, privilege escalation, post-exploitation, etc.
* `Pro Labs` are the ultimate lab experience, as they are designed to simulate a real-world enterprise infrastructure, which is an excellent chance for testing out your pentesting skills.
	* `Pro Labs` are large and can take a while to finish and learn all of their attack paths and security challenges. Each Pro Lab has a specific scenario and level of difficulty:

|Lab|Scenario|
|---|---|
|`Dante`|Beginner-friendly to learn common pentesting techniques and methodologies, common pentesting tools, and common vulnerabilities.|
|`Offshore`|Active Directory lab that simulates a real-world corporate network.|
|`Cybernetics`|Simulates a fully-upgraded and up-to-date Active Directory network environment, which is hardened against attacks. It is aimed at experienced penetration testers and Red Teamers.|
|`RastaLabs`|Red Team simulation environment, featuring a combination of attacking misconfigurations and simulated users.|
|`APTLabs`|This lab simulates a targeted attack by an external threat agent against an MSP (Managed Service Provider) and is the most advanced Pro Lab offered at this time.|
* `Fortresses` are vulnerable labs created by external companies and hosted on `HackTheBox`.
* `Endgames` are virtual labs that contain several machines connected to a single network. The scenarios strive to reflect a real-world situation you may encounter when performing a pentest for an actual company.
* `HTB Battlegrounds` is a real-time game of strategy and hacking. You can play in a team of 4 or a team of 2.
	* `Cyber Mayhem` battles are based on the attack/defense style, in which each team is assigned several machines that they have to defend against attacks while attacking the other team's machines.
	* `Server Siege` mode is an attack-only style, in which the team who can hack the other team faster wins.