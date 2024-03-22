
* Whether we are performing client assessments, playing CTFs, taking a course in Academy or elsewhere, or playing HTB boxes/labs, organization is always crucial. It is essential to prioritize clear and accurate documentation from the very beginning.

---
### Folder Structure

* When attacking a single box, lab, or client environment, we should have a clear folder structure on our attack machine to save data such as: scoping information, enumeration data, evidence of exploitation attempts, sensitive data such as credentials, and other data obtained during recon, exploitation, and post-exploitation. A sample folder structure may look like follows:

```shell-session
6165@htb[/htb]$ tree Projects/

Projects/
└── Acme Company
    ├── EPT
    │   ├── evidence
    │   │   ├── credentials
    │   │   ├── data
    │   │   └── screenshots
    │   ├── logs
    │   ├── scans
    │   ├── scope
    │   └── tools
    └── IPT
        ├── evidence
        │   ├── credentials
        │   ├── data
        │   └── screenshots
        ├── logs
        ├── scans
        ├── scope
        └── tools
```

* Here we have a folder for the client `Acme Company` with two assessments, Internal Penetration Test (IPT) and External Penetration Test (EPT). Under each folder, we have subfolders for saving scan data, any relevant tools, logging output, scoping information (i.e., lists of IPs/networks to feed to our scanning tools), and an evidence folder that may contain any credentials retrieved during the assessment, any relevant data retrieved as well as screenshots.

---
### Note Taking Tools

* Some great options to explore include:
	* [Cherrytree](https://www.giuspen.com/cherrytree)
	* [Visual Studio Code](https://code.visualstudio.com/)
	* [Evernote](https://evernote.com/)
	* [Notion](https://www.notion.so/)
	* [GitBook](https://www.gitbook.com/) **(Use my GitBook for boxes/ctfs because it syncs to my GitHub!)**
	* [Sublime Text](https://www.sublimetext.com/)
	* [Notepad++](https://notepad-plus-plus.org/downloads)
	* [Obsidian](https://obsidian.md/) **(Use for these notes)**