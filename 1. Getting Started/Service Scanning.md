* The first thing we need to do is identify the operating system and any available services that might be running.
	* A service is an application running on a computer that performs some useful function for other users or computers. We call these specialized machines that host these useful services "servers" instead of workstations, allowing users to interact with and consume these various services.
* What we're interested in are services that have either been misconfigured or have a vulnerability. 
* Computers are assigned an IP address, which allows them to be uniquely identified and accessible on a network. The services running on these computers may be assigned a port number to make the service accessible.
* Port 0 is a reserved port in TCP/IP networking and is not used in TCP or UDP messages. If anything attempts to bind to port 0 (such as a service), it will bind to the next available port above port 1,024 because port 0 is treated as a "wild card" port.
* One of the most commonly used scanning tools is Nmap(Network Mapper).

---
### Nmap

* Suppose that we want to perform a basic scan against a target residing at 10.129.42.253. To do this we should type `nmap 10.129.42.253` and hit return. We see that the `Nmap` scan was completed very quickly. This is because if we don't specify any additional options, Nmap will only scan the 1,000 most common ports by default. The scan output reveals that ports 21, 22, 80, 139, and 445 are available.

`nmap 10.129.42.253`

* Under the `PORT` heading, it also tells us that these are TCP ports. By default, `Nmap` will conduct a TCP scan unless specifically requested to perform a UDP scan.  
* The `STATE` heading confirms that these ports are open. Sometimes we will see other ports listed that have a different state, such as `filtered`. This can happen if a firewall is only allowing access to the ports from specific addresses.  
* The `SERVICE` heading tells us the service's name is typically mapped to the specific port number. However, the default scan will not tell us what is listening on that port. Until we instruct `Nmap` to interact with the service and attempt to tease out identifying information, it could be another service altogether.
* Let us run a more advanced `Nmap` scan and gather more information about the target device.
* We can use the `-sC` parameter to specify that `Nmap` scripts should be used to try and obtain more detailed information. The `-sV` parameter instructs `Nmap` to perform a version scan. In this scan, Nmap will fingerprint services on the target system and identify the service protocol, application name, and version. The version scan is underpinned by a comprehensive database of over 1,000 service signatures. Finally, `-p-` tells Nmap that we want to scan all 65,535 TCP ports.

`nmap -sV -sC -p- 10.129.42.253`

* This returns a lot more information. We see that it took a lot longer to scan 65,535 ports than 1,000 ports. The `-sC` and `-sV` options also increase the duration of a scan, as instead of performing a simple TCP handshake, they perform a lot more checks. We notice that this time there is a VERSION heading, which reports the service version and the operating system if this is possible to identify.
* So far, we know that the operating system is Ubuntu Linux. Application versions can also help reveal the target OS version. Take OpenSSH, for example. We see the reported version is `OpenSSH 8.2p1 Ubuntu 4ubuntu0.1`. From inspection of other Ubuntu SSH package [changelogs](https://launchpad.net/ubuntu/yakkety/+source/openssh/+changelog), we see the release version takes the format `1:7.3p1-1ubuntu0.1`. Updating our version to fit this format, we get `1:8.2p1-4ubuntu0.1`.
	* A quick search for this version online reveals that it is included in Ubuntu Linux Focal Fossa 20.04.
	* Another quick search reveals that the release date of this OS is April 23rd, 2020.
	* However, it is worth noting that this cross-referencing technique is not entirely reliable, as it is possible to install more recent application packages on an older OS version.
* The script scan `-sC` flag causes `Nmap` to report the server headers `http-server-header` page and the page title `http-title` for any web page hosted on the webserver. The web page title `PHP 7.4.3 - phpinfo()` indicates that this is a PHPInfo file, which is often manually created to confirm that PHP has been successfully installed. The title (and PHPInfo page) also reveals the PHP version, which is worth noting if it is vulnerable.

---
### Nmap Scripts

* Specifying `-sC` will run many useful default scripts against a target, but there are cases when running a specific script is required. For example, in an assessment scope, we may be asked to audit a large Citrix installation. We could use [this](https://raw.githubusercontent.com/cyberstruggle/DeltaGroup/master/CVE-2019-19781/CVE-2019-19781.nse) `Nmap` script to audit for the severe Citrix NetScaler vulnerability ([CVE-2019–19781](https://blog.rapid7.com/2020/01/17/active-exploitation-of-citrix-netscaler-cve-2019-19781-what-you-need-to-know/)), while `Nmap` also has other scripts to audit a Citrix installation.

`locate scripts/citrix`

`nmap --script <script name> -p<port> <host>`

---
### Attacking Network Services

#### Banner Grabbing

* Often a service will look to identify itself by displaying a banner once a connection is initiated. Nmap will attempt to grab the banners if the syntax `nmap -sV --script=banner <target>` is specified. We can also attempt this manually using `Netcat`. Let us take another example, using the `nc` version of `Netcat`:

`nc -nv 10.129.42.253 21`
`(UNKNOWN) [10.129.42.253] 21 (ftp) open`
`220 (vsFTPd 3.0.3)`

* This reveals that the version of `vsFTPd` on the server is `3.0.3`. We can also automate this process using `Nmap's` powerful scripting engine: `nmap -sV --script=banner -p21 10.10.10.0/24`.

#### FTP

* It is worth gaining familiarity with FTP, as it is a standard protocol, and this service can often contain interesting data. A `Nmap` scan of the default port for FTP (21) reveals the vsftpd 3.0.3 installation that we identified previously. Further, it also reports that anonymous authentication is enabled and that a `pub` directory is available.

`nmap -sC -sV -p21 10.129.42.253`

* To connect to the service using the `ftp` command-line utility.

`ftp -p 10.129.42.253`

* Supports common commands such as `cd` and `ls` and allows us to download files using the `get` command.

---

### SMB

* SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as [EternalBlue](https://www.avast.com/c-eternalblue).
* It is crucial to enumerate this sizeable potential attack surface carefully. `Nmap` has many scripts for enumerating SMB, such as [smb-os-discovery.nse](https://nmap.org/nsedoc/scripts/smb-os-discovery.html), which will interact with the SMB service to extract the reported operating system version.

`nmap --script smb-os-discovery.nse -p445 10.10.10.40`

* In this case, the host runs a legacy Windows 7 OS, and we could conduct further enumeration to confirm if it is vulnerable to EternalBlue. The Metasploit Framework has several [modules](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/) for EternalBlue that can be used to validate the vulnerability and exploit it.
* We can run a scan against our target for this module section to gather information from the SMB service. We can ascertain that the host runs a Linux kernel, Samba version 4.6.2, and the hostname is GS-SVCSCAN.

`nmap -A -p445 10.129.42.253`

---
### Shares

* SMB allows users and administrators to share folders and make them accessible remotely by other users. Often these shares have files in them that contain sensitive information such as passwords. A tool that can enumerate and interact with SMB shares is [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html). The `-L` flag specifies that we want to retrieve a list of available shares on the remote host, while `-N` suppresses the password prompt.

`smbclient -N -L \\\\10.129.42.253`

* This reveals the non-default share `users`. Let us attempt to connect as the guest user.

`smbclient \\\\10.129.42.253\\users`

* The `ls` command resulted in an access denied message, indicating that guest access is not permitted. Let us try again using credentials for the user bob (`bob:Welcome1`).

`smbclient -U bob \\\\10.129.42.253\\users`
`Enter WORKGROUP\bob's password: `

---
### SNMP

* SNMP Community strings provide information and statistics about a router or device, helping us gain access to it. The manufacturer default community strings of `public` and `private` are often unchanged.
* In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3.
* Much information can be gained from SNMP. Examination of process parameters might reveal credentials passed on the command line, which might be possible to reuse for other externally accessible services given the prevalence of password reuse in enterprise environments. Routing information, services bound to additional interfaces, and the version of installed software can also be revealed.

`snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0`

`snmpwalk -v 2c -c private  10.129.42.253 `

* A tool such as [onesixtyone](https://github.com/trailofbits/onesixtyone) can be used to brute force the community string names using a dictionary file of common community strings such as the `dict.txt` file included in the GitHub repo for the tool.

`onesixtyone -c dict.txt 10.129.42.254`

