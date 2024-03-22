* ## Network Traffic Analysis
	* `Network Traffic Analysis (NTA)` can be described as the act of examining network traffic to characterize common ports and protocols utilized, establish a baseline for our environment, monitor and respond to threats, and ensure the greatest possible insight into our organization's network.
		* Collecting
		* Setting
		* Identifying
		* Detecting
		* Investigating
	* **Common Traffic Analysis Tools**
		* tcpdump
		* Tshark
		* Wireshark
		* NGrep
		* tcpick
		* Network Taps
		* Networking Span Ports
		* Elastic Stack
		* SIEMS
	* Many of the tools mentioned above have their syntax and commands to utilize, but one that is shared among them is [Berkeley Packet Filter (BPF)](https://en.wikipedia.org/wiki/Berkeley_Packet_Filter) syntax. This syntax is the primary method. For more information on BPF syntax, check out this [reference](https://www.ibm.com/docs/en/qsip/7.4?topic=queries-berkeley-packet-filters).
		1. **Ingest Traffic**
			* Once we have decided on our placement, begin capturing traffic. Utilize capture filters if we already have an idea of what we are looking for.
		2. **Reduce Noise by Filtering**
			* Capturing traffic of a link, especially one in a production environment, can be extremely noisy. Once we complete the initial capture, an attempt to filter out unnecessary traffic from our view can make analysis easier. (Broadcast and Multicast traffic, for example.)
		3. **Analyze and Explore**
			* Now is the time to start carving out data pertinent to the issue we are chasing down. Look at specific hosts, protocols, even things as specific as flags set in the TCP header. The following questions will help us:
				1. Is the traffic encrypted or plain text? Should it be?
				2. Can we see users attempting to access resources to which they should not have access?
				3. Are different hosts talking to each other that typically do not?
		4. **Detect the Root Issue**
			1. Are we seeing any errors? Is a device not responding that should be?
			2. Use our analysis to decide if what we see is benign or potentially malicious.
			3. Other tools like IDS and IPS can come in handy at this point. They can run heuristics and signatures against the traffic to determine if anything within is potentially malicious.
		5. **Fix and Monitor**
			* Fix and monitor is not a part of the loop but should be included in any workflow we perform. If we make a change or fix an issue, we should continue to monitor the source for a time to determine if the issue has been resolved.
* ## Networking Primer - Layers 1-4
	* This section serves as a quick refresher on networking and how some standard protocols we can see while performing traffic captures work. 
	* **TCP 3-way Handshake**
		* One of the ways TCP ensures the delivery of data from server to client is the utilization of sessions. These sessions are established through what is called a three-way handshake. To make this happen, TCP utilizes an option in the TCP header called flags. We will not deep dive into TCP flags now; know that the common flags we will see in a three-way handshake are Synchronization (`SYN`) and acknowledgment (`ACK`). When a host requests to have a conversation with a server over TCP;
			1. The `client` sends a packet with the SYN flag set to on along with other negotiable options in the TCP header.
			    1. This is a synchronization packet. It will only be set in the first packet from host and server and enables establishing a session by allowing both ends to agree on a sequence number to start communicating with.
			    2. This is crucial for the tracking of packets. Along with the sequence number sync, many other options are negotiated in this phase to include window size, maximum segment size, and selective acknowledgments.
			2. The `server` will respond with a TCP packet that includes a SYN flag set for the sequence number negotiation and an ACK flag set to acknowledge the previous SYN packet sent by the host.
			    1. The server will also include any changes to the TCP options it requires set in the options fields of the TCP header.
			3. The `client` will respond with a TCP packet with an ACK flag set agreeing to the negotiation.
			    1. This packet is the end of the three-way handshake and established the connection between client and server.
		* Another flag we will see with TCP is the `FIN` flag. It is used for signaling that the data transfer is finished and the sender is requesting termination of the connection. The client acknowledges the receipt of the data and then sends a `FIN` and `ACK` to begin session termination. The server responds with an acknowledgment of the FIN and sends back its own FIN. Finally, the client acknowledges the session is complete and closes the connection. Before session termination, we should see a packet pattern of:
			1. `FIN, ACK`
			2. `FIN, ACK`,
			3. `ACK`
* ## Networking Primer - Layers 5-7
	* It takes many different applications and services to maintain a network connection and ensure that data can be transferred between hosts.
		* **HTTP**
			* enables the transfer of data in clear text between a client and server over TCP.
			* The client would send an HTTP request to the server, asking for a resource. A session is established, and the server responds with the requested media (HTML, images, hyperlinks, video).
				* HTTP utilizes ports 80 or 8000 over TCP during normal operations. In exceptional circumstances, it can be modified to use alternate ports, or even at times, UDP.
			* To perform operations such as fetching webpages, requesting items for download, or posting your most recent tweet all require the use of specific methods. These methods define the actions taken when requesting a URI. Methods:
				* `HEAD` - `required` is a safe method that requests a response from the server similar to a Get request except that the message body is not included. It is a great way to acquire more information about the server and its operational status.
				* `GET` - `required` Get is the most common method used. It requests information and content from the server. For example, `GET http://10.1.1.1/Webserver/index.html` requests the index.html page from the server based on our supplied URI.
				* `POST` - `optional` Post is a way to submit information to a server based on the fields in the request. For example, submitting a message to a Facebook post or website forum is a POST action. The actual action taken can vary based on the server, and we should pay attention to the response codes sent back to validate the action.
				* `PUT` - `optional` Put will take the data appended to the message and place it under the requested URI. If an item does not exist there already, it will create one with the supplied data. If an object already exists, the new PUT will be considered the most up-to-date, and the object will be modified to match. The easiest way to visualize the differences between PUT and POST is to think of it like this; PUT will create or update an object at the URI supplied, while POST will create child entities at the provided URI. The action taken can be compared with the difference between creating a new file vs. writing comments about that file on the same page.
				* `DELETE` - `optional` Delete does as the name implies. It will remove the object at the given URI.
				* `TRACE` - `optional` Allows for remote server diagnosis. The remote server will echo the same request that was sent in its response if the TRACE method is enabled.
				* `OPTIONS` - `optional` The Options method can gather information on the supported HTTP methods the server recognizes. This way, we can determine the requirements for interacting with a specific resource or server without actually requesting data or objects from it.
				* `CONNECT` - `optional` Connect is reserved for use with Proxies or other security devices like firewalls. Connect allows for tunneling over HTTP. (`SSL tunnels`)
		* **HTTPS**
			* a modification of the HTTP protocol designed to utilize Transport Layer Security (`TLS`) or Secure Sockets Layer (`SSL`) with older applications for data security.
			* HTTPS utilizes ports 443 and 8443 instead of the standard port 80.
			* **TLS Handshake Via HTTPS**
				* To summarize the handshake:
					1. Client and server exchange hello messages to agree on connection parameters.
					2. Client and server exchange necessary cryptographic parameters to establish a premaster secret.
					3. Client and server will exchange x.509 certificates and cryptographic information allowing for authentication within the session.
					4. Generate a master secret from the premaster secret and exchanged random values.
					5. Client and server issue negotiated security parameters to the record layer portion of the TLS protocol.
					6. Client and server verify that their peer has calculated the same security parameters and that the handshake occurred without tampering by an attacker.
		* **FTP**
			* an Application Layer protocol that enables quick data transfer between computing devices. Port 20 and 21 over TCP.
			* FTP is capable of running in two different modes, `active` or `passive`.
				* Active is the default operational method utilized by FTP, meaning that the server listens for a control command `PORT` from the client, stating what port to use for data transfer.
				* Passive mode enables us to access FTP servers located behind firewalls or a NAT-enabled link that makes direct TCP connections impossible. In this instance, the client would send the `PASV` command and wait for a response from the server informing the client what IP and port to utilize for the data transfer channel connection.
			* FTP Commands:
				* `USER` - specifies the user to log in as.
				* `PASS` - sends the password for the user attempting to log in.
				* `PORT` - when in active mode, this will change the data port used.
				* `PASV` - switches the connection to the server from active mode to passive.
				* `LIST` - displays a list of the files in the current directory.
				* `CWD` - will change the current working directory to one specified.
				* `PWD` - prints out the directory you are currently working in.
				* `SIZE` - will return the size of a file specified.
				* `RETR` - retrieves the file from the FTP server.
				* `QUIT` - ends the session.
		* **SMB**
			* a protocol most widely seen in Windows enterprise environments that enables sharing resources between hosts over common networking architectures. Port 137 and 138 over UDP. Also port 445 over TCP, NetBIOS over TCP port 139.
			* SMB provides us easy and convenient access to resources like printers, shared drives, authentication servers, and more.
* ## The Analysis Process
	* Traffic Analysis is a `detailed examination of an event or process`, determining its origin and impact, which can be used to trigger specific precautions and/or actions to support or prevent future occurrences.
	* Traffic capturing and analysis can be performed in two different ways, `active` or `passive`. Each has its dependencies:
		* ![[Pasted image 20231130172829.png]]
* ## Analysis in Practice
	* **Descriptive Analysis**
		1. `What is the issue?`
		    - Suspected breach? Networking issue?
		2. `Define our scope and the goal. (what are we looking for? which time period?)`
		    - Target: multiple hosts potentially downloading a malicious file from bad.example.com
		    - When: within the last 48 hours + 2 hours from now.
		    - Supporting info: filenames/types 'superbad.exe' 'new-crypto-miner.exe'
		3. `Define our target(s) (net / host(s) / protocol)`
		    - Scope: 192.168.100.0/24 network, protocols used were HTTP and FTP.
	- **Diagnostic Analysis**
		4. `Capture network traffic`
		    - Plug into a link with access to the 192.168.100.0/24 network to capture live traffic to try and grab one of the executables in transfer. See if an admin can pull PCAP and/or netflow data from our SIEM for the historical data.
		5. `Identification of required network traffic components (filtering)`
		    - Once we have traffic, filter out any packets not needed for this investigation to include; any traffic that matches our common baseline and keep anything relevant to the scope of the investigation. For example, HTTP and FTP from the subnet, anything transferring or containing a GET request for the suspected executable files.
		6. `An understanding of captured network traffic`
		    - Once we have filtered out the noise, it is time to dig for our targets—filter on things like `ftp-data` to find any files transferred and reconstruct them. For HTTP, we can filter on `http.request.method == "GET"` to see any GET requests that match the filenames we are searching for. This can show us who has acquired the files and potentially other transfers internal to the network on the same protocols.
	- **Predictive Analysis**
		7. `Note-taking and mind mapping of the found results`
		    - Annotating everything we do, see, or find throughout the investigation is crucial. Ensure we are taking ample notes, including:
		    - Timeframes we captured traffic during.
		    - Suspicious hosts within the network.
		    - Conversations containing the files in question. ( to include timestamps and packet numbers)
		8. `Summary of the analysis (what did we find?)`
		    - Finally, summarize what we have found explaining the relevant details so that superiors can decide to quarantine the affected hosts or perform more significant incident response.
		    - Our analysis will affect decisions made, so it is essential to be as clear and concise as possible.
	- **Prescriptive Analysis** (Same as above but condensed)
		1. `What is the issue?`
		    - Suspected breach? Networking issue?
		2. `Define our scope and the goal (what are we looking for? which time period?)`
		    - target: multiple hosts potentially downloading a malicious file from bad.example.com
		    - when: within the last 48 hours + 2 hours from now.
		    - supporting info: filenames/types 'superbad.exe' 'new-crypto-miner.exe'
		3. `Define our target(s) (net / host(s) / protocol)`
		    - scope: 192.168.100.0/24 network protocols used were HTTP and FTP.
		4. `Capture network traffic`
		    - plug into a link with access to the 192.168.100.0/24 network to capture live traffic to try and grab one of the executables in transfer. See if an admin can pull PCAP and/or netflow data from our SIEM for the historical data.
		5. `Identification of required network traffic components (filtering)`
		    - once we have traffic, filter out any traffic not needed for this investigation to include; any traffic that matches our common baseline and keep anything relevant to the scope. `HTTP and FTP from the subnet, anything transferring or containing a GET request for the suspected executable files.
		6. `An understanding of captured network traffic`
		    - Once we have filtered out the noise, it's time to dig for our targets—filter on things like `ftp-data` to find any files transferred and reconstruct them. For HTTP, we can filter on `http.request.method == "GET"` to see any GET requests that match the filenames we are searching for. This can show us who has acquired the files and potential other transfers internal to the network on the same protocols.
		7. `Note-taking and mind mapping of the found results.`
		    - Annotating everything we do, see, or find throughout the investigation is crucial. Ensure we are taking ample notes, including:
		    - Timeframes we captured traffic during.
		    - Suspicious hosts within the network.
		    - Conversations containing the files in question. ( to include timestamps and packet numbers)
		8. `Summary of the analysis (what did we find?)`
		    - Finally, summarize what has been found, explaining the relevant details so that superiors can make an informed decision to quarantine the affected hosts or perform more significant incident response.
		    - Our analysis will affect decisions made, so it is essential to be as clear and concise as possible.
	- Some easy wins when looking at traffic and finding problems:
		- Start with `standard protocols first` and work our way into the `austere and specific` only to the organization.
			- Most attacks will come from the internet, so it has to access the internal net somehow. This means there will be traffic generated and logs written about it. HTTP/S, FTP, E-mail, and basic TCP and UDP traffic will be the most common things seen coming from the world. Start at these and clear out anything that is not necessary to the investigation.
			- After these, check standard protocols that allow for communications between networks, such as SSH, RDP, or Telnet. When looking for these types of anomalies, be mindful of the security policy of the network. Does our organization's security plan and implementations allow for RDP sessions that are initiated outside the enterprise? What about the use of Telnet?
		* Look for `patterns`. Is a specific host or set of hosts checking in with something on the internet at the same time daily? This is a typical Command and Control profile setup that can easily be spotted by looking for patterns in our traffic data.
		* Check anything `host to host` within our network. In a standard setup, the user's hosts will rarely talk to each other. So be suspicious of any traffic that appears like this. Typically hosts will talk to infrastructure for IP address leases, DNS requests, enterprise services and to find its route out. We will also see hosts talking with local webservers, file shares, and other critical infrastructure for the environment to function like Domain controllers and authentication apps.
		* Look for `unique` events. Things like a host who usually visits a specific site ten times a day changing its pattern and only doing so once is curious. Seeing a different User-Agent string not matching our applications or hosts talking to a server out on the internet is also something to be concerned with. A random port only being bound once or twice on a host is also of note. This could be an opening for things like C2 callbacks, someone opening a port to do something non-standard, or an application showing abnormal behavior. In large environments, patterns are expected, so anything sticking out warrants a look.
* ## Tcpdump Fundamentals
	* learned this in Google cert, notes may be brief here as well
	* locate `tcpdump`
		* `which tcpdump`
		* can be found in `/usr/sbin/tcpdump`
	* Install
		* `sudo apt install tcpdump`
	* Version validation
		* `sudo tcpdump --version`
	* Basic Capture Options
		* D	Will display any interfaces available to capture from
		* i	Selects an interface to capture from. ex. -i eth
		* n	Do not resolve hostnames
		* nn	Do not resolve hostnames or well-known ports
		* e	Will grab the ethernet header along with upper-layer data
		* X	Show Contents of packets in hex and ASCII
		* XX	Same as X, but will also specify ethernet headers. (like using Xe)
		* v, vv, vvv	Increase the verbosity of output shown and saved
		* c	Grab a specific number of packets, then quit the program
		* s	Defines how much of a packet to grab
		* S	change relative sequence numbers in the capture display to absolute sequence numbers. (13248765839 instead of 101
		* q	Print less protocol information
		* r file.pcap	Read from a file
		* w file.pcap	Write into a file
	* Man Pages
		* `man tcpdump`
	* Listing Available Interfaces
		* `sudo tcpdump -D`
	* Choosing an Interface to Capture from
		* `sudo tcpdump -i eth0`
	* Disable Name Resolution
		* `sudo tcpdump -i eth0 -nn`
	* Display the Ethernet Header
		* `sudo tcpdump -i eth0 -e`
	* Include ASCII and Hex Output
		* `sudo tcpdump -i eth0 -X`
	* Tcpdump Switch Combinations
		* `sudo tcpdump -i eth0 -nnvXX`
	* **File Input/Output with Tcpdump**
		* Save PCAP Output to a File
			* `sudo tcpdump -i eth0 -w ~/output.pcap`
		* Read Output from a File
			* `sudo tcpdump -r ~/output.pcap`
* ## Fundamentals Lab
	* `Validate Tcpdump is installed on our machine.`
		* Before we can get started, ensure we have tcpdump installed. What command do we use to determine if tcpdump is installed on Linux?
		* `which tcpdump`
	* `Start a capture.`
		* Once we know tcpdump is installed, we are ready to start our first capture. If we are unsure of what interfaces we have to listen from, we can utilize a built-in switch to list them all for us.
		* Which tcpdump switch is used to show us all possible interfaces we can listen to?
		* `tcpdump -D`
		* `tcpdump -i eth0`
	* `Utilize Basic Capture Filters.`
		* Now that we can capture traffic, let us modify how that information is presented to us. We will accomplish this by adding verbosity to our output and displaying contents in ASCII and Hex. Once we complete this task, attempt it again using other switches.
		* Disable name resolution and display relative sequence numbers for another challenge.
		* `tcpdump -i eth0 -vX`
	* `Save a Capture to a .PCAP file.`
		* Now it is up to us how we wish to capture and see the output. Remember, when utilizing capture filters, it will modify what we get. Grab our first full capture from the wire, and save it to a PCAP file. This will be a sample to baseline the enterprise network.
		* `tcpdump -i eth0 -nvw /path/to/filename.pcap`
	* `Read the Capture from a .PCAP file.`
		* Our team members have given us a PCAP they captured while surveying another section of the enterprise, read the PCAP file into tcpdump, and modify our view of the PCAP to help us determine what is happening. We can disable hostname and port resolution for simplicity and ensure we see any TCP sequence and acknowledgment numbers in absolute values. For the sake of the lab, utilize the PCAP file we created in the previous step for this task.
		* `tcpdump -nnSXr /path/to/filename.pcap`
* ## Tcpdump Packet Filtering
	* host	host will filter visible traffic to show anything involving the designated host. Bi-directional
	* src / dest	src and dest are modifiers. We can use them to designate a source or destination host or port.
	* net	net will show us any traffic sourcing from or destined to the network designated. It uses / notation.
	* proto	will filter for a specific protocol type. (ether, TCP, UDP, and ICMP as examples)
	* port	port is bi-directional. It will show any traffic with the specified port as the source or destination.
	* portrange	portrange allows us to specify a range of ports. (0-1024)
	* less / greater "< >"	less and greater can be used to look for a packet or protocol option of a specific size.
	* and / &&	and && can be used to concatenate two different filters together. for example, src host AND port.
	* or	or allows for a match on either of two conditions. It does not have to meet both. It can be tricky.
	* not	not is a modifier saying anything but x. For example, not UDP.
	* **Host Filter**
		* `sudo tcpdump -i eth0 host 172.16.146.2`
	* **Source/Destination Filter**
		* `sudo tcpdump -i eth0 src host 172.16.146.2`
	* **Utilizing Source With Port as a Filter**
		* `sudo tcpdump -i eth0 tcp src port 80`
	* **Using Destination in Combination with the Net Filter**
		* `sudo tcpdump -i eth0 dest net 172.16.146.0/24`
	* **Protocol Filter**
		* `sudo tcpdump -i eth0 udp`
	* **Protocol Number Filter**
		* `sudo tcpdump -i eth0 proto 17`
	* **Port Filter**
		* `sudo tcpdump -i eth0 tcp port 443`
	* **Port Range Filter**
		* `sudo tcpdump -i eth0 portrange 0-1024`
	* **Less/Greater Filter**
		* `sudo tcpdump -i eth0 less 64`
	* **Utilizing Greater**
		* `sudo tcpdump -i eth0 greater 500`
	* **AND Filter**
		* `sudo tcpdump -i eth0 host 192.168.0.1 and port 23`
	* **Basic Capture With No Filter**
		* `sudo tcpdump -i eth0`
	* **OR Filter**
		* `sudo tcpdump -r sus.pcap icmp or host 172.16.146.1`
	* **NOT Filter**
		* `sudo tcpdump -r sus.pcap not icmp`
	* **Pinging a Capture to a Grep**
		* `sudo tcpdump -Ar http.cap -l | grep 'mailto:*'`
	* **Looking for TCP Protocol Flags**
		* `tcpdump -i eth0 'tcp[13] &2 != 0'`
		* This is counting to the 13th byte in the structure and looking at the 2nd bit. If it is set to 1 or ON, the SYN flag is set.
	* **Protocol RFC Links**
		* [IP Protocol](https://tools.ietf.org/html/rfc791) - `RFC 791` describes IP and its functionality.
		* [ICMP Protocol](https://tools.ietf.org/html/rfc792) - `RFC 792` describes ICMP and its functionality.
		* [TCP Protocol](https://tools.ietf.org/html/rfc793) - `RFC 793` describes the TCP protocol and how it functions.
		* [UDP Protocol](https://tools.ietf.org/html/rfc768) - `RFC 768` describes UDP and how it operates.
		* [RFC Quick Links](https://en.wikipedia.org/wiki/List_of_RFCs#Topical_list) - This Wikipedia article contains a large list of protocols tied to the RFC that explains their implementation.
* ## Interrogating Network Traffic With Capture and Display Filters
	* `Read a capture from a file without filters implemented.`
		* To start, let's examine this pcap with no filters applied.
	* `Identify the type of traffic seen.`
		* Take note of what types of traffic can be seen. (Ports utilized, protocols, any other information you deem relevant.) What filters can we use to make this task easier?
		* What type of traffic do we see?
		* Common protocols:
		* Ports utilized:
	* `Identify conversations.`
		* We have examined the basics of this traffic, now determine if you notice any patterns with the traffic.  
		* Are you noticing any common connections between a server and host? If so, who?
		* What are the client and server port numbers used in the first full TCP three-way handshake?
		* Who are the servers in these conversations? How do we know?
		* Who are the receiving hosts?
	* `Interpret the capture in depth.`
		* Now that we have some familiarity with the pcap file, let's do some analysis. Utilize whatever syntax necessary to accomplish answering the questions below.
		* What is the timestamp of the first established conversation in the pcap file?
		* What is the IP address/s of apache.org from the DNS server responses?
		* What protocol is being utilized in that first conversation? (name/#)
	* `Filter out traffic.`
		* It's time to clear some of this data out now. Reload the pcap file and filter out all traffic that is not DNS. What can you see?
		* Who is the DNS server for this segment?
		* What domain name/s were requested in the pcap file?
		* What type of DNS Records could be seen?
		* Now that we are only seeing DNS traffic and have a better grasp on how the packet appears, try to answer the following questions regarding name resolution in the enterprise: Who requests an A record for apache.org? (hostname or IP)
		* What information does an A record provide?
		* Who is the responding DNS server in the pcap? (hostname or IP)
	* `Filter for TCP traffic.`
		* Now that we have a clear idea of our DNS server let's look for any webservers present. Filter out the view so that we only see the traffic pertaining to HTTP or HTTPS. What web pages were requested?
		* What are the most common HTTP request methods from this PCAP?
		* What is the most common HTTP response from this PCAP?
	* `What can you determine about the server in the first conversation.`
		* Let's take a closer look. What can be determined about the webserver in the first conversation? Does anything stick out? For some clarity, make sure our view includes the Hex and ASCII output for the pcap.
		* Can we determine what application is running the webserver?
	* **Tips For Analysis**
		* what type of traffic do you see? (protocol, port, etc.)
		* Is there more than one conversation? (how many?)
		* How many unique hosts?
		* What is the timestamp of the first conversation in the pcap (tcp traffic)
		* What traffic can I filter out to clean up my view?
		* Who are the servers in the PCAP? (answering on well-known ports, 53, 80, etc.)
		* What records were requested or methods used? (GET, POST, DNS A records, etc.)
* ## Analysis with Wireshark
	* Locating Wireshark
		* `which wireshark`
	* Installing Wireshark On Linux
		* `sudo apt install wireshark`
	* TShark VS. Wireshark (Terminal vs. GUI)
		* TShark is a purpose-built terminal tool based on Wireshark. TShark is perfect for use on machines with little or no desktop environment and can easily pass the capture information it receives to another tool via the command line.
		* Wireshark is the feature-rich GUI option for traffic capture and analysis. If you wish to have the full-featured experience and work from a machine with a desktop environment, the Wireshark GUI is the way to go.
	* **Basic TShark Switches**
		* D	Will display any interfaces available to capture from and then exit out.
		* L	Will list the Link-layer mediums you can capture from and then exit out. (ethernet as an example)
		* i	choose an interface to capture from. (-i eth0)
		* f	packet filter in libpcap syntax. Used during capture.
		* c	Grab a specific number of packets, then quit the program. Defines a stop condition.
		* a	Defines an autostop condition. Can be after a duration, specific file size, or after a certain number of packets.
		* r (pcap-file)	Read from a file.
		* W (pcap-file)	Write into a file using the pcapng format.
		* P	Will print the packet summary while writing into a file (-W)
		* x	will add Hex and ASCII output into the capture.
		* h	See the help menu
	* TShark help
		* `tshark -h`
	* Locating TShark
		* `which tshark`
	* Selecting an Interface & Writing to a File
		* `sudo tshark -i eth0 -w /tmp/test.pcap`
	* Applying Filters
		* `sudo tshark -i eth0 -f "host 172.16.146.2"`
	* **Termshark**
		* a text-based user interface (TUI) application that is like Wireshark GUI but inside your terminal
	* **Performing our first capture in Wireshark**
		* Capture > Options > Select interface (Wi-Fi/Ethernet) > Start
		* Save
	* **Capture Filters**
		* host x.x.x.x	Capture only traffic pertaining to a certain host
		* net x.x.x.x/24	Capture traffic to or from a specific network (using slash notation to specify the mask)
		* src/dst net x.x.x.x/24	Using src or dst net will only capture traffic sourcing from the specified network or destined to the target network
		* port #	will filter out all traffic except the port you specify
		* not port #	will capture everything except the port specified
		* port # and #	AND will concatenate your specified ports
		* portrange x-x	portrange will grab traffic from all ports within the range only
		* ip / ether / tcp	These filters will only grab traffic from specified protocol headers.
		* broadcast / multicast / unicast	Grabs a specific type of traffic. one to one, one to many, or one to all.
	* **Display Filters**
		* ip.addr == x.x.x.x	Capture only traffic pertaining to a certain host. This is an OR statement.
		* ip.addr == x.x.x.x/24	Capture traffic pertaining to a specific network. This is an OR statement.
		* ip.src/dst == x.x.x.x	Capture traffic to or from a specific host
		* dns / tcp / ftp / arp / ip	filter traffic by a specific protocol. There are many more options.
		* tcp.port == x	filter by a specific tcp port.
		* tcp.port / udp.port != x	will capture everything except the port specified
		* and / or / not	AND will concatenate, OR will find either of two options, NOT will exclude your input option.
* ## Familiarity with Wireshark
	* `Validate Wireshark is installed, then open Wireshark and familiarize yourself with the GUI windows and toolbars.`
		* Take a minute and explore the Wireshark GUI. Ensure we know what options reside under which tabs in the command menus. Please pay special attention to the Capture tab and what resides within it.
	* `Select an interface to run a capture on and create a capture filter to show only traffic to and from your host IP.`
		* Choose your active interface (eth0, or your Wifi card) to capture from.
	* `Create a capture filter.`
		* Next, we want to create a capture filter to only show us traffic sourcing from or destined to our IP address and apply it.
	* `Navigate to a webpage to generate some traffic.`
		* Open a web browser and navigate to pepsi.com. Repeat this step for http://apache.org. While the page is loading, switch back to the Wireshark window. We should see traffic flowing through our capture window. Once the page has loaded, stop the capture by clicking on the red square labeled Stop in the action bar.
	* `Use the capture results to answer the following questions.`
		* Are multiple sessions being established between the machine and the webserver? How can you tell?
		* What application-level protocols are displayed in the results?
		* Can we discern anything in clear text? What was it?
* ## Wireshark Advanced Usage
	* Statistics Tab
	* Analyze Tab
	* **Following TCP Streams**
		* right-click on a packet from the stream we wish to recreate.
		- select follow → TCP
		- this will open a new window with the stream stitched back together. From here, we can see the entire conversation.
	- **Extracting Data and Files From a Capture**
		- stop your capture.
		- Select the File radial → Export → , then select the protocol format to extract from.
		- (DICOM, HTTP, SMB, etc.)
	- Since FTP utilizes TCP as its transport mechanism, we can utilize the `follow tcp stream` function we utilized earlier in the section to group any conversation we wish to explore. The basic steps to dissect FTP data from a pcap are as follows:
		1. Identify any FTP traffic using the `ftp` display filter.
		2. Look at the command controls sent between the server and hosts to determine if anything was transferred and who did so with the `ftp.request.command` filter.
		3. Choose a file, then filter for `ftp-data`. Select a packet that corresponds with our file of interest and follow the TCP stream that correlates to it.
		4. Once done, Change "`Show and save data as`" to "`Raw`" and save the content as the original file name.
		5. Validate the extraction by checking the file type.
* ## Packet Inspection, Dissecting Network Traffic With Wireshark
	* `Open a pre-captured file (HTTP extraction)`
		* In Wireshark, Select File → Open → , then browse to Wireshark-lab-2.pcap. Open the file.
	* `Filter the results.`
		* Now that we have the pcap file open in Wireshark, we can see quite a lot of traffic within this capture file. It has around 1171 packets total, and of those, less than 20 are HTTP packets specifically. Take a minute to examine the pcap file, become familiar with the conversations being had while thinking of the task to accomplish. Our goal is to extract potential images embedded for evidence. Based on what has been asked of us, let's clear our view by filtering for HTTP traffic only.
		* Apply a filter to include only HTTP (80/TCP) requests.
		* Please note how this removes any additional TCP or IP datagrams from the window and allows us to focus on communication solely with HTTP. From here, we can see several basic HTTP datagrams containing the GET method and 200 OK responses. These are interesting because we can now see that a client requested several files, and the server responded with an OK. If we select one of the OK responses, we can follow that stream and see the data transfer over TCP. Let's give this a shot.
	* `Follow the stream and extract the item(s) found.`
		* So now that we have established there is HTTP traffic in this capture file, let's try to grab some of the items inside as requested. The first thing we need to do is follow the stream for one of the file transfers. With our `http` filter still applied, look for one of the lines in which the Web Server responds with a “200 OK” message which acts as an acknowledgment/receipt to a users’ GET request. Now let's select that packet and follow the TCP stream.
		* Now that we validated the transfer happened, Wireshark can make it extremely easy to extract files from HTTP traffic. We can check to see if an image file was pulled down by looking for the `JFIF` format in the packets. The JPEG File Interchange Format `JFIF` will alert us to the presence of any JPEG image files. We are looking for this format because it is the most common file type for images alongside the png format. With that in mind, we will likely see an image in this format for our investigation.
		* Check for the presence of JFIF files in the HTTP traffic.
	* **Connectivity to Lab**
		* `xfreerdp /v:<target IP> /u:htb-student /p:HTB_@cademy_stdnt!`
		* Start a Wireshark Capture
			* We will be sniffing traffic from the host we logged into from our own VM or Pwnbox. Utilizing interface `ENS224` in Wireshark, let the capture run for a few minutes before stopping it. Our goal is to determine if anything is happening with the user's host and another machine on the corporate or external networks.
		* Self Analysis
			* Before following these tasks below, take the time to step through our pcap traffic unguided. Use the skills we have previously tested, such as following streams, analysis of conversations, and other skills to determine what is going on. Keep these questions in mind while performing analysis:
				- How many conversations can be seen?
				- Can we determine who the clients and servers are?
				- What protocols are being utilized?
				- Is anything of note happening? ( ports being misused, clear text traffic or credentials, etc.)
			* In this lab, we are concerned with the hosts 172.16.10.2 and 172.16.10.20 while performing the following steps. In our analysis, we should have noticed some web traffic between these hosts and some FTP traffic. Let's dig a bit deeper.
		* FTP Analysis
			* When examining the traffic, we captured, was any traffic pertaining to FTP noticed? Who was the server for that traffic?
			* Were we able to determine if an authenticated user was performing these actions, or were they anonymous?
		* Filter the results
			* Now that we have seen some interesting traffic, let's try and grab the file off the wire.
			* Examine the FTP commands to determine what you need to inspect, and then extract the files from ftp-data and reassemble it
				1. Identify any FTP traffic using the `ftp` display filter.
				2. Look at the command controls sent between the server and hosts to determine if anything was transferred and who did so with the `ftp.request.command` filter.
				3. Choose a file, then filter for `ftp-data`. Select a packet that corresponds with our file of interest and follow the TCP stream that correlates to it.
				4. Once done, Change "Show and save data as" to "Raw" and save the content as the original file name.
				5. Validate the extraction by checking the file type.
		* HTTP Analysis
			* We should have seen a bit of HTTP traffic as well. Was this the case for you?
			* If so, could we determine who the webserver is?
			* What application is running the webserver?
			* What were the most common method requests you saw?
		* Follow the stream and extract the item(s) found
			* Now attempt to follow the HTTP stream and determine if there is anything to extract.
				* Apply the filter “http && image-jfif” to include only HTTP (80/TCP) packets along with a filter to include only JPEG File Interchange Formats (JPEG files).
				* Look for the line in which the Web Server responds with a “200 OK” message which acts as an acknowledgment/receipt to a users’ GET request.
				* Select “File > Export Objects > HTTP > `file.JPG`
* ## Guided Lab: Traffic Analysis Workflow
	* One of our fellow admins noticed a weird connection from Bob's host `IP = 172.16.10.90` when analyzing the baseline captures we have been gathering. He asked us to check it out and see what we think is happening.
	* Attempt to utilize the concepts from the Analysis Process sections to complete an analysis of the guided-analysis.zip provided in the optional resources and live traffic from the academy network. Once done, a guided answer key is included with the PCAP in the zip to check your work.
	* `Connect to the live host for capture.`
		* `Connection Instructions`: Access to the lab environment to complete the following tasks will require the use of [XfreeRDP](https://manpages.ubuntu.com/manpages/trusty/man1/xfreerdp.1.html) to provide GUI access to the virtual machine so we can utilize Wireshark from within the environment.
		* We will be connecting to the Academy lab like normal utilizing your own VM with a HTB Academy VPN key or the Pwnbox built into the module section. You can start the FreeRDP client on the Pwnbox by typing the following into your shell once the target spawns:
		* `xfreerdp /v:<target IP> /u:htb-student /p:HTB_@cademy_stdnt!`
		* You can find the `target IP`, `Username`, and `Password` needed below:
			- Click below in the Questions section to spawn the target host and obtain an IP address.
			    - `IP` == 10.129.43.4
			    - `Username` == htb-student
			    - `Password` == HTB_@cademy_stdnt!
			    * Once connected, open Wireshark and begin capturing on interface ENS224.
	* Follow this workflow template and examine the suspicious traffic. The goal is to determine what is happening with the host in question.
		1. what is the issue?
		    1. a brief summary of the issue.
			    Suspicious traffic coming from within the network.
		2. define our scope and the goal (what are we looking for? which time period?)
		    1. Scope: traffic is originating from 10.129.43.4
		    2. when the issue started: within the last 48 hours. Capture traffic to determine if it is still happening.
		    3. supporting info: NTA-guided.pcap
		3. define our target(s) (net / host(s) / protocol)
		    1. Target hosts: 10.129.43.4 and anyone with a connection to it. Unknown protocol over port 4444.
		4. capture network traffic / read from previously captured PCAP.	
			1. plug into a link with access to the 10.129.43.0/24 network to capture live traffic attempting to see if anything is happening.
			2. We have been given a PCAP with historical data that contains some of the suspect traffic. We will examine this to analyze the issue.
		6. identification of required network traffic components (filtering)
		    1. Statistics > protocol hierarchy
		    2. !tcp .... normal traffic
		    3. !udp && !arp > follow TCP stream
		7. An understanding of captured network traffic
		    1. it appears that someone is performing basic recon of the host. They are issuing commands like `whoami`, `ipconfig`, `dir`. It would appear they are trying to get a lay of the land and figure out what user they landed as on the host.
		8. note taking / mind mapping of the found results.
		    1. Annotating everything we do, see, or find throughout the investigation is crucial. Ensure you are taking ample notes, including:
		    - Timeframes we captured traffic during.
		    - Suspicious hosts/ports within the network.
		    - Conversations containing anything suspicious. ( to include timestamps, and packet numbers, files, etc.)
		    2. we can now see someone made the account `hacker` and assigned it to the `administrators group` on this host. Either this is a joke by a poor administrator. Or someone has infiltrated the corporate infrastructure.
		1. summary of the analysis (what did we find?)
		    1. Based on our analysis, we determined that a malicious actor has infiltrated at least one host on the network. Host 10.129.43.29 shows signs of someone executing commands to include user creation and assigning local administrator permissions via the `net` commands. It would look like the actor was using Bob's host to perform said actions. Since Bob was previously under investigation for the exfil of corporate secrets and disguising it as web traffic, I think it is safe to say the issue has spread further. The screenshots included with this document show the flow of traffic and commands utilized.
		    2. It is our opinion that a complete Incident Response `IR` procedure be enacted to ensure the threat is stopped from spreading further. We can dedicate resources to clearing the malicious presence and cleaning the affected hosts.
    * `Complete an attempt on your own first to examine and follow the workflow, then look below for a guided walkthrough of the lab.`
* ## Decrypting RDP connections
	* When performing IR and analysis on Bob's machine, the IR team captured some PCAP of the RDP traffic they noticed from Bob's host to another host in the network. We have been asked to investigate the occurrence by our team lead. While combing his host for further evidence, you found an RDP-key hidden in a folder hive on Bob's host. After some research, we realize that we can utilize that key to decrypt the RDP traffic to inspect it.
	* Attempt to utilize the concepts from the Analysis Process sections to complete an analysis of the RDP-analysis.zip provided.
	* `Open the rdp.pcapng file in Wireshark.`
		* Unzip the zip file included in the optional resources and open it in Wireshark.
	* `Analyze the traffic included.`
		* Take a minute to look at the traffic. Notice there is a lot of information here. We know our focus is on RDP, so let's take a second to filter on `rdp` and see what it returns.
	* `Filter on port 3389 to determine if any RDP traffic encrypted or otherwise exists.`
		* We can at least verify that a session was established between the two hosts over TCP port 3389.
	* `Provide the RDP-key to Wireshark so it can decrypt the traffic.`
		* Now, let's take this a step further and use the key we found to try and decrypt the traffic.
		* To apply the key in Wireshark:
			1. go to Edit → Preferences → Protocols → TLS
			2. On the TLS page, select Edit by RSA keys list → a new window will open.
			3. Follow the steps below to import the RSA server key.
				* Click the + to add a new key
				* Type in the IP address of the RDP server 10.129.43.29
				* Type in the port used 3389
				* Protocol filed equals tpkt or blank.
				* Browse to the server.key file and add it in the key file section.
				* Save and refresh your pcap file.
	* From here, we can perform an analysis of the RDP traffic. We can now follow TCP streams, export any potential objects found, and anything else we feel necessary for our investigation. This works because we acquired the RSA key used for encrypting the RDP session. The steps for acquiring the key were a bit lengthy, but the short of it is that if the RDP certificate is acquired from the server, `OpenSSL` can pull the private key out of it.
	* What host initiated the RDP session with our server?
	* Which user account was used to initiate the RDP connection?