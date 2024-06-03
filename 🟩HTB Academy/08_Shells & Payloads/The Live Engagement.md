
___

Here we are. It’s the big day and time to start our engagement. We need to put our new skills with crafting and delivering payloads, acquiring and interacting with a shell on Windows and Linux, and how to take over a Web application to the test. Complete the objectives below to finish the engagement.

___

## Scenario:

CAT5's team has secured a foothold into Inlanefrieght's network for us. Our responsibility is to examine the results from the recon that was run, validate any info we deem necessary, research what can be seen, and choose which exploit, payloads, and shells will be used to control the targets. Once on the VPN or from your `Pwnbox`, we will need to `RDP` into the foothold host and perform any required actions from there. Below you will find any credentials, IP addresses, and other info that may be required.

___

## Objectives:

-   Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Windows host or server`.
-   Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Linux host or server`.
-   Demonstrate your knowledge of exploiting and receiving an interactive shell from a `Web application`.
-   Demonstrate your ability to identify the `shell environment` you have access to as a user on the victim host.

Complete the objectives by answering the challenge questions `below`.

___

## Credentials and Other Needed Info:

Foothold:

-   IP:
-   Credentials: `htb-student` / HTB\_@cademy\_stdnt! Can be used by RDP.

___

## Connectivity To The Foothold

`Connection Instructions`:  
Accessing the Skills Assessment lab environment will require the use of [XfreeRDP](https://manpages.ubuntu.com/manpages/trusty/man1/xfreerdp.1.html) to provide GUI access to the virtual machine. We will be connecting to the Academy lab like normal utilizing your own VM with a HTB Academy `VPN key` or the `Pwnbox` built into the module section. You can start the `FreeRDP` client on the Pwnbox by typing the following into your shell once the target spawns:

Code: bash

```bash
xfreerdp /v:<target IP> /u:htb-student /p:HTB_@cademy_stdnt!
```

You can find the `target IP`, `Username`, and `Password` needed below:

-   Click below in the Questions section to spawn the target host and obtain an IP address.
    -   `IP` ==
    -   `Username` == htb-student
    -   `Password` == HTB\_@cademy\_stdnt!

Once you initiate the connection, you will be required to enter the provided credentials again in the window you see below:

#### XFreeRDP Login

![image](https://academy.hackthebox.com/storage/modules/115/xfree-login.png)

Enter your credentials again and click `OK` and you will be connected to the provided Parrot Linux desktop instance.

#### Target Hosts

![image](https://academy.hackthebox.com/storage/modules/115/challenge-map.png)

Hosts 1-3 will be your targets for this skills challenge. Each host has a unique vector to attack and may even have more than one route built-in. The challenge questions below can be answered by exploiting these three hosts. Gain access and enumerate these targets. You will need to utilize the Foothold PC provided. The IP will appear when you spawn the targets. Attempting to interact with the targets from anywhere other than the foothold will not work. Keep in mind that the Foothold host has access to the Internal inlanefreight network (`172.16.1.0/23` network) so you may want to pay careful attention to the IP address you pick when starting your listeners.

___

## Hints

Attempt to complete the challenges on your own. If you get stuck then view the helpful hints below and next to each challenge question:

`Host-1 hint`:

**Click to show hint** This host has two upload vulnerabilities. If you look at status.inlanefreight.local or browse to the IP on port 8080, you will see the vector. When messing with one of them, the creds " tomcat | Tomcatadm " may come in handy.

`Host-2 hint`:

**Click to show hint** Have you taken the time to validate the scan results? Did you browse to the webpage being hosted? blog.inlanefreight.local looks like a nice space for team members to chat. If you need the credentials for the blog, " admin:admin123!@# " have been given out to all members to edit their posts. At least, that's what our recon showed.

`Host-3 hint`:

**Click to show hint** This host is vulnerable to a very common exploit released in 2017. It has been known to make many a sysadmin feel Blue.

Note: Please allow 1-2 minutes for the hosts in the assessment environment to spawn, then connect to the foothold machine using xfreerdp and begin. This would be a good time to review any notes and prepare for the challenge.

Host 1
#tomcat
#FileUpload .war

Host 2
#FileUpload php

Host 3
#SMB 
#EternalBlue 