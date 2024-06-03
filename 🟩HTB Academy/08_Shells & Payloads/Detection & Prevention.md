#Evasion 
___

We are on the downslope now! Let's take a break from our super-spy business of infiltrating hosts and take a look at the defensive side. This section explores ways to detect active shells, look for payloads on a host and over network traffic, and how these attacks can be obfuscated to bypass our defenses.

___

## Monitoring

When it comes to looking for and identifying active shells, payload delivery and execution, and potential attempts to subvert our defenses, we have many different options to utilize to detect and respond to these events. Before talking about data sources and tools we can use, let's take a second to talk about the [MITRE ATT&CK Framework](https://attack.mitre.org/) and define the techniques and tactics being utilized by attackers. The `ATT&CK Framework` as defined by MITRE, is "`a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations`."

#### ATT&CK Framework

![image](https://academy.hackthebox.com/storage/modules/115/attack-framework.png)

Keeping the framework in mind, three of the most notable techniques we can tie to Shells & Payloads are listed below in the table with descriptions.

___

#### Notable MITRE ATT&CK Tactics and Techniques:

| **Tactic / Technique**                                       | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Initial Access](https://attack.mitre.org/techniques/T1190/) | Attackers will attempt to gain initial access by compromising a public-facing host or service such as web Applications, misconfigured services such as SMB or authentication protocols, and/or bugs in a public-facing host that introduce a vulnerability. This is often done on some form of bastion host and provides the attacker with a foothold in the network but not yet full access. For more information on initial access, especially via Web Applications, check out the [OWASP Top Ten](https://owasp.org/www-project-top-ten/) or read further in the Mitre Att&ck framework.                                                                                                                                                                                                                                                                                                                                                       |
| [Execution](https://attack.mitre.org/tactics/TA0002)         | This technique depends on code supplied and planted by an attacker running on the victim host. `The Shells & Payloads` module focuses mainly on this tactic. We utilize many different payloads, delivery methods, and shell scripting solutions to access a host. This can be anything from the execution of commands within our web browser to get execution and access on a Web Application, issuing a PowerShell one-liner via PsExec, taking advantage of a publicly released exploit or zero-day in conjunction with a framework such as Metasploit, or uploading a file to a host via many different protocols and calling it remotely to receive a callback.                                                                                                                                                                                                                                                                              |
| [Command & Control](https://attack.mitre.org/tactics/TA0011) | Command and Control (`C2`) can be looked at as the culmination of our efforts within this module. We gain access to a host and establish some mechanism for continued and/or interactive access via code execution, then utilize that access to perform follow on actions on objectives within the victim network. The use of standard ports and protocols within the victim network to issue commands and receive output from the victim is common. This can appear as anything from normal web traffic over HTTP/S, commands issued via other common external protocols such as DNS and NTP, and even the use of common allowed applications such as Slack, Discord, or MS Teams to issue commands and receive check-ins. C2 can have various levels of sophistication varying from basic clear text channels like Netcat to utilizing encrypted and obfuscated protocols along with complex traffic routes via proxies, redirectors, and VPNs. |

___

## Events To Watch For:

-   `File uploads`: Especially with Web Applications, file uploads are a common method of acquiring a shell on a host besides direct command execution in the browser. Pay attention to application logs to determine if anyone has uploaded anything potentially malicious. The use of firewalls and anti-virus can add more layers to your security posture around the site. Any host exposed to the internet from your network should be sufficiently hardened and monitored.
    
-   `Suspicious non-admin user actions`: Looking for simple things like normal users issuing commands via Bash or cmd can be a significant indicator of compromise. When was the last time an average user, much less an admin, had to issue the command `whoami` on a host? Users connecting to a share on another host in the network over SMB that is not a normal infrastructure share can also be suspicious. This type of interaction usually is end host to infrastructure server, not end host to end host. Enabling security measures such as logging all user interactions, PowerShell logging, and other features that take note when a shell interface is used will provide you with more insight.
    
-   `Anomalous network sessions`: Users tend to have a pattern they follow for network interaction. They visit the same websites, use the same applications, and often perform those actions multiple times a day like clockwork. Logging and parsing NetFlow data can be a great way to spot anomalous network traffic. Looking at things such as top talkers, or unique site visits, watching for a heartbeat on a nonstandard port (like 4444, the default port used by Meterpreter), and monitoring any remote login attempts or bulk GET / POST requests in short amounts of time can all be indicators of compromise or attempted exploitation. Using tools like network monitors, firewall logs, and SIEMS can help bring a bit of order to the chaos that is network traffic.
    

___

## Establish Network Visibility

Much like identifying and then using various shells & payloads, `detection` & `prevention` requires a detailed understanding of the systems and overall network environment you are trying to protect. It's always essential to have good documentation practices so individuals responsible for keeping the environment secure can have consistent visibility of the devices, data, and traffic flow in the environments they administer. Developing & maintaining visual network topology diagrams can help visualize network traffic flow. Newer tools like [netbrain](https://www.netbraintech.com/) may be good to research as they combine visual diagraming that can be achieved with tools like [Draw.io](https://draw.io/), documentation and remote management. Interactive visual network topologies allow you to interact with the routers, network firewalls, IDS/IPS appliances, switches, and hosts (clients). Tools like this are becoming more common to use as it can be challenging to keep the visibility of the network updated, especially in larger environments that are constantly growing.

Some network device vendors like Cisco Meraki, Ubiquiti, Check Point, and Palo Alto Networks are building layer 7 visibility (like layer 7 of the OSI model) into their network devices and moving the management capabilities to cloud-based network controllers. This means admins log in to a web portal to manage all the network devices in the environment. A visual dashboard is often provided with these cloud-based network controllers making it easier to have a `baseline` of the traffic usage, network protocols, applications, and inbound & outbound traffic. Having and understanding the baseline of your network will make any deviation from the norm extremely visible. The faster you can react and triage any potential issue, the less time for possible leaks, destruction of data, or worse.

Keep in mind that if a payload is successfully executed, it will need to communicate over the network, so this is why network visibility is essential within the context of shells & payloads. Having a network security appliance capable of [deep packet inspection](https://en.wikipedia.org/wiki/Deep_packet_inspection) can often act as an anti-virus for the network. Some of the payloads we discussed could get detected & blocked at the network level if successfully executed on the hosts. This is especially easy to detect if traffic is not encrypted. When we used Netcat in the bind & reverse shell sections, the traffic passing between the source and destination (target) was `not encrypted`. Someone could capture that traffic and see every command we sent between our attack box and the target, as seen in the examples below.

This image shows NetFlow between two hosts frequently and on a suspicious port (`4444`). We can tell it is basic TCP traffic, so if we take action and inspect it a bit, we can see what's going on.

___

#### Suspicious Traffic.. In Clear Text

![image](https://academy.hackthebox.com/storage/modules/115/pcap-4444.png)

Notice now that that same traffic has been expanded, and we can see that someone is using `net` commands to create a new user on this host.

___

#### Following the Traffic

![image](https://academy.hackthebox.com/storage/modules/115/follow-sus.png)

This is an excellent example of basic access and command execution to gain persistence via the addition of a user to the host. Regardless of the name `hacker` being used, if command-line logging is in place paired with the NetFlow data, we can quickly tell that the user is performing potentially malicious actions and triage this event to determine if an incident has occurred or if this is just some admin playing around. A modern security appliance may detect, alert and prevent further network communications from that host using deep packet inspection.

Speaking of anti-virus, let's discuss end device detection & protection a bit.

___

## Protecting End Devices

`End devices` are the devices that connect at the "end" of a network. This means they are either the source or destination of data transmission. Some examples of end devices would be:

-   Workstations (employees computers)
-   Servers (providing various services on the network)
-   Printers
-   Network Attached Storage (NAS)
-   Cameras
-   Smart TVs
-   Smart Speakers

We should prioritize the protection of these kinds of devices, especially those that run an operating system with a `CLI` that can be remotely accessed. The same interface that makes it easy to administer and automate tasks on a device can make it a good target for attackers. As simple as this seems, having anti-virus installed & enabled is a great start. The most common successful attack vector besides misconfiguration is the human element. All it takes is for a user to click a link or open a file, and they can be compromised. Having monitoring and alerting on your end devices can help detect and potentially prevent issues before they happen.

On `Windows` systems, `Windows Defender` (also known as Windows Security or Microsoft Defender) is present at install and should be left enabled. Also, ensuring the Defender Firewall is left enabled with all profiles (Domain, Private and Public) left on. Only make exceptions for approved applications based on a [change management process](https://www.atlassian.com/itsm/change-management). Establish a [patch management](https://www.rapid7.com/fundamentals/patch-management/) strategy (if not already established) to ensure that all hosts are receiving updates shortly after Microsoft releases them. All of this applies to servers hosting shared resources and websites as well. Though it can slow performance, AV on a server can prevent the execution of a payload and the establishment of a shell session with a malicious attacker's system.

___

## Potential Mitigations:

Consider the list below when considering what implementations you can put in place to mitigate many of these vectors or exploits.

-   `Application Sandboxing`: By sandboxing your applications that are exposed to the world, you can limit the scope of access and damage an attacker can perform if they find a vulnerability or misconfiguration in the application.
    
-   `Least Privilege Permission Policies`: Limiting the permissions users have can go a long way to help stop unauthorized access or compromise. Does an ordinary user need administrative access to perform their daily duties? What about domain admin? Not really, right? Ensuring proper security policies and permissions are in place will often hinder if not outright stop an attack.
    
-   `Host Segmentation & Hardening`: Properly hardening hosts and segregating any hosts that require exposure to the internet can help ensure an attacker cannot easily hop in and move laterally into your network if they gain access to a boundary host. Following STIG hardening guides and placing hosts such as web servers, VPN servers, etc., in a DMZ or 'quarantine' network segment will stop that type of access and lateral movement.
    
-   `Physical and Application Layer Firewalls`: Firewalls can be powerful tools if appropriately implemented. Proper inbound and outbound rules that only allow traffic first established from within your network, on ports approved for your applications, and denying inbound traffic from your network addresses or other prohibited IP space can cripple many bind and reverse shells. It adds a hop in the network chain, and network implementations such as Network Address Translation (NAT) can break the functionality of a shell payload if it is not taken into account.
    

___

## Sum It All Up

These protections and mitigations are not the ends all be all for stopping attacks. A strong security posture and defense strategy are required in today's age. Adapting a defense-in-depth approach to your security posture will help hinder attackers and ensure the low-hanging fruit cannot be easily taken advantage of.