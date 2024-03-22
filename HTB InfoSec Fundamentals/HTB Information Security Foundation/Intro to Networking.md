I have completed many Networking courses and obtained Network+
Will treat this module as review and write minimal notes.
* ## Networking Overview
	* Most networks use a `/24` subnet, so much so that many Penetration Testers will set this subnet mask (255.255.255.0) without checking. The /24 network allows computers to talk to each other as long as the first three octets of an IP Address are the same (ex: 192.168.1.xxx). Setting the subnet mask to `/25` divides this range in half, and the computer will be able to talk to only the computers on "its half." We have seen Penetration Test reports where the assessor claimed a Domain Controller was offline when it was just on a different network in reality. The network structure was something like this:
		- Server Gateway: 10.20.0.1/25
		- Domain Controller: 10.20.0.10/25
		- Client Gateway: 10.20.0.129/25
		- Client Workstation: 10.20.0.200/25
		- Pentester IP: 10.20.0.252/24 (Set Gateway to 10.20.0.1)
	- The Pentester communicated with the Client Workstations and thought they did an excellent job because they managed to steal a workstation password via Impacket. However, due to a failure to understand the network, they never managed to get off the Client Network and reach more "high value" targets such as database servers.
	- ![[Pasted image 20231122153014.png]]
	- The difference between `URL`s and `FQDN`s is that:
		- an `FQDN` (`www.hackthebox.eu`) only specifies the address of the "building" and
		- an `URL` (`https://www.hackthebox.eu/example?floor=2&office=dev&employee=17`) also specifies the "`floor`," "`office`," "`mailbox`" and the corresponding "`employee`" for whom the package is intended.
- ## Network Types
	- Types
		- **WAN**
		- **LAN**
		- **WLAN**
		- **VPN**
			- **Site-To-Site VPN**
				- Both the client and server are Network Devices, typically either `Routers` or `Firewalls`, and share entire network ranges. This is most commonly **used to join company networks together over the Internet, allowing multiple locations to communicate over the Internet as if they were local**.
			- **Remote Access VPN**
				- This involves the client's computer creating a virtual interface that behaves as if it is on a client's network. Hack The Box utilizes `OpenVPN`, which makes a TUN Adapter letting us access the labs. When analyzing these VPNs, an important piece to consider is the routing table that is created when joining the VPN. If the VPN only creates routes for specific networks (ex: 10.10.10.0/24), this is called a `Split-Tunnel VPN`, meaning the Internet connection is not going out of the VPN. This is great for Hack The Box because it **provides access to the Lab without the privacy concern of monitoring your internet connection. However, for a company, `split-tunnel` VPN's are typically not ideal because if the machine is infected with malware, network-based detection methods will most likely not work as that traffic goes out the Internet**.
			- **SSL VPN**
				- This is essentially a VPN that is done within our web browser and is becoming increasingly common as web browsers are becoming capable of doing anything. Typically these will stream applications or entire desktop sessions to your web browser. A great **example of this would be the HackTheBox Pwnbox**.
		- **GAN**
		- **MAN**
		- **WPAN**
- ## Networking Topologies
	- The `transmission medium layout` used to connect devices is the physical topology of the network. For conductive or glass fiber media, this refers to the cabling plan, the positions of the `nodes`, and the connections between the nodes and the cabling. In contrast, the `logical topology` is how the signals act on the network media or how the data will be transmitted across the network from one device to the devices' physical connection.
		- Connections
			- Wired
				- Coaxial
				- glass fiber
				- twisted-pair
			- Wireless
				- Wi-Fi
				- Cellular
				- Satellite
		- Nodes
			- Repeaters
			- Hub
			- Bridges
			- Switches
			- Router/Modem
			- Gateways
			- Firewalls
		- Classifications
			- Point-to-Point
			- Bus
			- Star
			- Ring
			- Mesh (WAN and MAN)
			- Tree (extended star topology, large companies)
			- Hybrid
			- Daisy Chain (often in automation technology, CAN)
- ## Proxies
	* Many people have different opinions on what a proxy is:
		- Security Professionals jump to `HTTP Proxies` (BurpSuite) or pivoting with a `SOCKS/SSH Proxy` (`Chisel`, `ptunnel`, `sshuttle`).
		- Web Developers use proxies like Cloudflare or ModSecurity to block malicious traffic.    
		- Average people may think a proxy is used to obfuscate your location and access another country's Netflix catalog.
		- Law Enforcement often attributes proxies to illegal activity.
	- Not all the above examples are correct. **A proxy is when a device or service sits in the middle of a connection and acts as a mediator.**
		- The `mediator` is the critical piece of information because it means the device in the middle must be able to inspect the contents of the traffic. Without the ability to be a `mediator`, the device is technically a `gateway`, not a proxy.
	- Proxies will almost always operate at Layer 7 of the OSI Model (All People Seem To Need Data Processing {Application, Presentation, Session, Transport, Network, Data, Physical (Layer 7 - 1)}). There are many types of proxy services, but the key ones are:
		- **Dedicated Proxy/Forward Proxy**
			- The `Forward Proxy`, is what most people imagine a proxy to be. **A Forward Proxy is when a client makes a request to a computer, and that computer carries out the request.**
				- For example, in a corporate network (or school computers), sensitive computers may not have direct access to the Internet. To access a website, they must go through a proxy (or web filter). This can be an incredibly powerful line of defense against malware, as not only does it need to bypass the web filter (easy), but it would also need to be `proxy aware` or use a non-traditional C2 (a way for malware to receive tasking information). If the organization only utilizes `FireFox`, the likelihood of getting proxy-aware malware is improbable.
			- Web Browsers like Internet Explorer, Edge, or Chrome all obey the **"System Proxy"** settings by default. If the malware utilizes WinSock (Native Windows API), it will likely be proxy aware without any additional code. Firefox does not use `WinSock` and instead uses `libcurl`, which enables it to use the same code on any operating system. This means that the malware would need to look for Firefox and pull the proxy settings, which malware is highly unlikely to do.
			- Alternatively, malware could use DNS as a c2 mechanism, but if an organization is monitoring DNS (which is easily done using [Sysmon]([https://medium.com/falconforce/sysmon-11-dns-improvements-and-filedelete-events-7a74f17ca842](https://medium.com/falconforce/sysmon-11-dns-improvements-and-filedelete-events-7a74f17ca842)) ), this type of traffic should get caught quickly.
			- Another example of a Forward Proxy is Burp Suite, as most people utilize it to forward HTTP Requests. However, this application is the swiss army knife of HTTP Proxies and can be configured to be a reverse proxy or transparent!
			- ![[Pasted image 20231126113909.png]]
		- **Reverse Proxy**
			- A `reverse proxy`, is the reverse of a `Forward Proxy`. **Instead of being designed to filter outgoing requests, it filters incoming ones.** The most common goal with a `Reverse Proxy`, is to listen on an address and forward it to a closed-off network.
			- Many organizations use CloudFlare as they have a robust network that can withstand most DDOS Attacks. By using Cloudflare, organizations have a way to filter the amount (and type) of traffic that gets sent to their webservers.
			- Penetration Testers will configure reverse proxies on infected endpoints. The infected endpoint will listen on a port and send any client that connects to the port back to the attacker through the infected endpoint. This is useful to bypass firewalls or evade logging. Organizations may have `IDS` (`Intrusion Detection Systems`), watching external web requests. If the attacker gains access to the organization over SSH, a reverse proxy can send web requests through the SSH Tunnel and evade the IDS.
			- Another common Reverse Proxy is `ModSecurity`, a `Web Application Firewall` (`WAF`). Web Application Firewalls inspect web requests for malicious content and block the request if it is malicious. [ModSecurity Core Rule Set]([https://owasp.org/www-project-modsecurity-core-rule-set/](https://owasp.org/www-project-modsecurity-core-rule-set/)). Cloudflare, also can act as a WAF but doing so requires letting them decrypt HTTPS Traffic, which some organizations may not want.
			- ![[Pasted image 20231126113958.png]]
		- **Transparent Proxy**
			- All the above proxy services act either `transparently` or `non-transparently`.
			- With a `transparent proxy`, the client doesn't know about its existence. The transparent proxy intercepts the client's communication requests to the Internet and acts as a substitute instance. To the outside, the transparent proxy, like the non-transparent proxy, acts as a communication partner.
			- If it is a `non-transparent proxy`, we must be informed about its existence. For this purpose, we and the software we want to use are given a special proxy configuration that ensures that traffic to the Internet is first addressed to the proxy. If this configuration does not exist, we cannot communicate via the proxy. However, since the proxy usually provides the only communication path to other networks, communication to the Internet is generally cut off without a corresponding proxy configuration.
- ## Networking Models
	* Two models describing the communication and transfer of data from one host to another:
		* **ISO/OSI model** - All People Seem To Need Data Processing (Layer 7 -> Layer 1)
		* **TCP/IP model** - ATIL (Layer 4 -> Layer 1)
			* The protocols are responsible for switching and transport of data packets on the Internet. Internet is based on the TCP/IP protocol family (e.g. ICMP,UDP)
		* ![[Pasted image 20231126114127.png]]
	* **ISO/OSI s TCP/IP**
		* `TCP/IP` is a communication protocol that allows hosts to connect to the Internet. It refers to the `Transmission Control Protocol` used in and by applications on the Internet. In contrast to `OSI`, it allows a lightening of the rules that must be followed, provided that general guidelines are followed.
		* `OSI`, on the other hand, is a communication gateway between the network and end-users. The OSI model is usually referred to as the reference model because it is newer and more widely used. It is also known for its strict protocol and limitations.
	* **Packet Transfers**
		* In a layered system, devices in a layer exchange data in a different format called a `protocol data unit` (`PDU`).
			* For example, when we want to browse a website on the computer, the remote server software first passes the requested data to the application layer. It is processed layer by layer, each layer performing its assigned functions. The data is then transferred through the network's physical layer until the destination server or another device receives it. The data is routed through the layers again, with each layer performing its assigned operations until the receiving software uses the data.
		* ![[Pasted image 20231126114229.png]]
		* During the transmission, each layer adds a `header` to the `PDU` from the upper layer, which controls and identifies the packet. **This process is called** `encapsulation`. The header and the data together form the PDU for the next layer. The process continues to the `Physical Layer` or `Network Layer`, where the data is transmitted to the receiver. The receiver reverses the process and unpacks the data on each layer with the header information. After that, the application finally uses the data. This process continues until all data has been sent and received.
		* ![[Pasted image 20231126114250.png]]
		* For us, as penetration testers, both reference models are useful.
			* With `TCP/IP`, we can quickly understand how the entire connection is established, and with `ISO`, we can take it apart piece by piece and analyze it in detail. This often happens when we can listen to and intercept specific network traffic. We then have to analyze this traffic accordingly, going into more detail in the `Network Traffic Analysis` module.
* ## The OSI Model
	* The goal in defining the `ISO/OSI` standard was to create a reference model that enables the communication of different technical systems via various devices and technologies and provides compatibility.
	* The `OSI` model uses `seven` different layers, which are hierarchically based on each other to achieve this goal. These layers represent phases in the establishment of each connection through which the sent packets pass. In this way, the standard was created to trace how a connection is structured and established visually:
		* `7.Application` - Among other things, this layer controls the input and output of data and provides the application functions.
		* `6.Presentation` - The presentation layer's task is to transfer the system-dependent presentation of data into a form independent of the application.
		* `5.Session` - The session layer controls the logical connection between two systems and prevents, for example, connection breakdowns or other problems.
		* `4.Transport` - Layer 4 is used for end-to-end control of the transferred data. The Transport Layer can detect and avoid congestion situations and segment data streams.
		* `3.Network` - On the networking layer, connections are established in circuit-switched networks, and data packets are forwarded in packet-switched networks. Data is transmitted over the entire network from the sender to the receiver.
		* `2.Data Link` - The central task of layer 2 is to enable reliable and error-free transmissions on the respective medium. For this purpose, the bitstreams from layer 1 are divided into blocks or frames.
		* `1.Physical` - The transmission techniques used are, for example, electrical signals, optical signals, or electromagnetic waves. Through layer 1, the transmission takes place on wired or wireless transmission lines.
		* **A**ll **P**eople **S**eem **T**o **N**eed **D**ata **P**rocessing
	* **The layers `2-4` are `transport oriented`, and the layers `5-7` are `application oriented` layers.**
		* Each layer offers services for use to the layer directly above it. To make these services available, the layer uses the services of the layer below it and performs the tasks of its layer.
	* If two systems communicate, all seven layers of the `OSI` model are run through at least `twice`, since both the sender and the receiver must take the layer model into account. Therefore, a large number of different tasks must be performed in the individual layers to ensure the communication's security, reliability, and performance.
	* When an application sends a packet to the other system, the system works the layers shown above from layer `7` down to layer `1`, and the receiving system unpacks the received packet from layer `1` up to layer `7`.
* ## The TCP/IP Model
	* The `TCP/IP` model is also a layered reference model, often referred to as the `Internet Protocol Suite`. The term `TCP/IP` stands for the two protocols `Transmission Control Protocol` (`TCP`) and `Internet Protocol` (`IP`). `IP` is located within the `network layer` (`Layer 3`) and `TCP` is located within the `transport layer` (`Layer 4`) of the `OSI` layer model.
		* `4.Application` - The Application Layer allows applications to access the other layers' services and defines the protocols applications use to exchange data.
		* `3.Transport` - The Transport Layer is responsible for providing (TCP) session and (UDP) datagram services for the Application Layer.
		* `2.Internet` - The Internet Layer is responsible for host addressing, packaging, and routing functions.
		* `1.Link` - The Link layer is responsible for placing the TCP/IP packets on the network medium and receiving corresponding packets from the network medium. TCP/IP is designed to work independently of the network access method, frame format, and medium.'
	* The most important tasks of `TCP/IP` are:
		* `Logical Addressing` (`IP`) - Due to many hosts in different networks, there is a need to structure the network topology and logical addressing. Within TCP/IP, IP takes over the logical addressing of networks and nodes. Data packets only reach the network where they are supposed to be. The methods to do so are `network classes`, `subnetting`, and `CIDR`.
		* `Routing` (`IP`) - For each data packet, the next node is determined in each node on the way from the sender to the receiver. This way, a data packet is routed to its receiver, even if its location is unknown to the sender.
		* `Error & Control Flow` (`TCP`) - The sender and receiver are frequently in touch with each other via a virtual connection. Therefore control messages are sent continuously to check if the connection is still established.
		* `Application Support` (`TCP`) - TCP and UDP ports form a software abstraction to distinguish specific applications and their communication links.
		* `Name Resolution` (`DNS`) - DNS provides name resolution through Fully Qualified Domain Names (FQDN) in IP addresses, enabling us to reach the desired host with the specified name on the internet.
* ## Network Layer
	* The `network layer` (`Layer 3`) of `OSI` controls the exchange of data packets, as these cannot be directly routed to the receiver and therefore have to be provided with routing nodes.
	* The data packets are then transferred from node to node until they reach their target. To implement this, the `network layer` identifies the individual network nodes, sets up and clears connection channels, and takes care of routing and data flow control.
	* When sending the packets, addresses are evaluated, and the data is routed through the network from node to node. There is usually no processing of the data in the layers above the `L3` in the nodes. Based on the addresses, the routing and the construction of routing tables are done.
	* In short, it is responsible for the following functions
		* `Logical Addressing
		* `Routing`
	* Protocols are defined in each layer of `OSI`, and these protocols represent a collection of rules for communication in the respective layer. They are transparent to the protocols of the layers above or below. Some protocols fulfill tasks of several layers and extend over two or more layers. The most used protocols on this layer are:
		* `IPv4` / `IPv6`
		- `IPsec`
		- `ICMP`
		- `IGMP`
		- `RIP`
		- `OSPF`
* ## IP Addresses
	* Each host in the network located can be identified by the so-called `Media Access Control` address (`MAC`). Addressing on the Internet is done via the `IPv4` and/or `IPv6` address, which is made up of the `network address` and the `host address`.
		- `IPv4` / `IPv6` - describes the unique postal address and district of the receiver's building.
		- `MAC` - describes the exact floor and apartment of the receiver.
	* It is possible for a single IP address to address multiple receivers (broadcasting) or for a device to respond to multiple IP addresses. However, it must be ensured that each IP address is assigned only once within the network.
	* **IPv4 Structure**
		* The most common method of assigning IP addresses is `IPv4`, which consists of a `32`-bit binary number combined into `4 bytes` consisting of `8`-bit groups (`octets`) ranging from `0-255`. These are converted into more easily readable decimal numbers, separated by dots and represented as dotted-decimal notation.
		* The IP address is divided into a `host part` and a `network part`. The `router` assigns the `host part` of the IP address at home or by an administrator. The respective `network administrator` assigns the `network part`. On the Internet, this is `IANA`, which allocates and manages the unique IPs.
		* In the past, further classification took place here. The IP network blocks were divided into `classes A - E`. The different classes differed in the host and network shares' respective lengths.
		* A further separation of these classes into small networks is done with the help of `subnetting`. This separation is done using the `netmasks`, which is as long as an IPv4 address. As with classes, it describes which bit positions within the IP address act as `network part` or `host part`.
		* The `two` additional `IPs` added in the `IPs column` are reserved for the so-called `network address` and the `broadcast address`. Another important role plays the `default gateway`, which is the name for the IPv4 address of the `router` that couples networks and systems with different protocols and manages addresses and transmission methods. It is common for the `default gateway` to be assigned the first or last assignable IPv4 address in a subnet. This is not a technical requirement, but has become a de-facto standard in network environments of all sizes.
		* The `broadcast` IP address's task is to connect all devices in a network with each other. `Broadcast` in a network is a message that is transmitted to all participants of a network and does not require any response. In this way, a host sends a data packet to all other participants of the network simultaneously and, in doing so, communicates its `IP address`, which the receivers can use to contact it. This is the `last IPv4` address that is used for the `broadcast`.
		* ![[Pasted image 20231127124004.png]]
	* **Binary System**
		* The binary system is a number system that uses only two different states that are represented into two numbers (`0` and `1`) opposite to the decimal-system (0 to 9).
		* An IPv4 address is divided into 4 octets, as we have already seen. Each `octet` consists of `8 bits`. Each position of a bit in an octet has a specific decimal value. Let's take the following IPv4 address as an example:
			- IPv4 Address: `192.168.10.39`
				- ```Values:         128  64  32  16  8  4  2  1
				Binary:           1   1   0   0  0  0  0  0```
				* 1st: 128 + 64 + 0 + 0 + 0 + 0 + 0 + 0 = `192`
				* 2nd: 128 + 0 + 32 + 0 + 8 + 0 + 0 + 0 = `168`
				* 3rd: 0 + 0 + 0 + 0 + 8 + 0 + 2 + 0 = `10`
				* 4th: 0 + 0 + 32 + 0 + 0 + 4 + 2 + 1 = `39`
			* 255 = 128 + 64 + 32 + 16 + 8 + 4 + 2 + 1
	* **CIDR**
		* `Classless Inter-Domain Routing` (`CIDR`) is a method of representation and replaces the fixed assignment between IPv4 address and network classes (A, B, C, D, E). The division is based on the subnet mask or the so-called `CIDR suffix`, which allows the bitwise division of the IPv4 address space and thus into `subnets` of any size. The `CIDR suffix` indicates how many bits from the beginning of the IPv4 address belong to the network. It is a notation that represents the `subnet mask` by specifying the number of `1`-bits in the subnet mask.
		* Let us stick to the following IPv4 address and subnet mask as an example:
			- IPv4 Address: `192.168.10.39`
			- Subnet mask: `255.255.255.0`
		* Now the whole representation of the IPv4 address and the subnet mask would look like this:
			- CIDR: `192.168.10.39/24`
			- ```Octet:             1st         2nd         3rd         4th
			Binary:         1111 1111 . 1111 1111 . 1111 1111 . 0000 0000 (/24)
			Decimal:           255    .    255    .    255    .     0```
* ## Subnetting
	* The division of an address range of IPv4 addresses into several smaller address ranges is called `subnetting`
		* A logical segment of a network that uses IP addresses with the same network address.
		* We can think of a subnet as a labeled entrance on a large building corridor. For example, this could be a glass door that separates various departments of a company building. With the help of subnetting, we can create a specific subnet by ourselves or find out the following outline of the respective network:
			* Network Address
			* Broadcast Address
			* First host
			* Last host
			* Number of host
				* Example:
					* IPv4 Address: `192.168.12.160`
					- Subnet Mask: `255.255.255.192`
					- CIDR: `192.168.12.160/26`
				- Network Address - `192.168.12.128`
				- First Host - `192.168.12.129`
				- Other Hosts - `...`
				- Last Host - `192.168.12.190`
				- Broadcast Address - `192.168.12.191`
	- **Subnetting Into Smaller Networks**
		- 2^0...2^8=1...256
		- The following parameters:
			- Subnet: `192.168.12.128/26`
			- Required Subnets: `4`
		- Now we increase/expand our subnet mask by `2 bits` from `/26` to `/28`.
		* Next, we can divide the `64` IPv4 addresses that are available to us into `4 parts`.
		* So we know how big each subnet will be. From now on, we start from the network address given to us (192.168.12.128) and add the `16` hosts `4` times.
	* **Mental Subnetting**
		* /8   /16   /24   /32
		* It is possible to identify what octet of the IP Address may change by remembering those four numbers. Given the Network Address: `192.168.1.1/25`, it is immediately apparent that 192.168.2.4 would not be in the same network because the `/25` subnet means only the fourth octet may change.
		* The next part identifies how big each subnet can be but by dividing eight by the network and looking at the `remainder`. This is also called `Modulo Operation (%)` and is heavily utilized in cryptology. Given our previous example of `/25`, `(25 % 8)` would be 1. This is because eight goes into 25 three times (8 * 3 = 24). There is a 1 leftover, which is the network bit reserved for the network mask. There is a total of eight bits in each octet of an IP Address. If one is used for the network mask, the equation becomes 2^(8-1) or 2^7, 128.
* ## MAC Addresses
	* Each host in a network has its own `48`-bit (`6 octets`) `Media Access Control` (`MAC`) address, represented in hexadecimal format. `MAC` is the `physical address` for our network interfaces. There are several different standards for the MAC address:
		- Ethernet (IEEE 802.3)
		- Bluetooth (IEEE 802.15)
		- WLAN (IEEE 802.11)
	- MAC address:
		- `DE:AD:BE:EF:13:37`
		- `DE-AD-BE-EF-13-37`
		- `DEAD.BEEF.1337`
	- First 3 from manufacturer, Last 3 from NIC/individual address
		- `DE:AD:BE` 
		- `:EF:13:37`
	- If a host with the IP target address is located in the same subnet, the delivery is made directly to the target computer's physical address. However, if this host belongs to a different subnet, the Ethernet frame is addressed to the `MAC address` of the responsible router (`default gateway`). If the Ethernet frame's destination address matches its own `layer 2 address`, the router will forward the frame to the higher layers. `Address Resolution Protocol` (`ARP`) is used in IPv4 to determine the MAC addresses associated with the IP addresses.
	- The last two bits in the first octet can play another essential role. The last bit can have two states, 0 and 1, as we already know. The last bit identifies the MAC address as `Unicast` (`0`) or `Multicast` (`1`).
		- With `unicast`, it means that the packet sent will reach only one specific host.
		- With `multicast`, the packet is sent only once to all hosts on the local network, which then decides whether or not to accept the packet based on their configuration.
	- **MAC Multicast**
		- `01:00:5E` first 3 octets
	- **MAC Broadcast**
		- `FF:FF:FF:FF:FF:FF` all octets
	- **Address Resolution Protocol**
		- **MAC addresses can be changed/manipulated or spoofed, and as such, they should not be relied upon as a sole means of security or identification.** Network administrators should implement additional security measures, such as **network segmentation** and **strong authentication protocols**, to protect against potential attacks.
		- There exist several attack vectors that can potentially be exploited through the use of MAC addresses:
			- `MAC spoofing`: This involves altering the MAC address of a device to match that of another device, typically to gain unauthorized access to a network.
			- `MAC flooding`: This involves sending many packets with different MAC addresses to a network switch, causing it to reach its MAC address table capacity and effectively preventing it from functioning correctly.
			- `MAC address filtering`: Some networks may be configured only to allow access to devices with specific MAC addresses that we could potentially exploit by attempting to gain access to the network using a spoofed MAC address.
		- [Address Resolution Protocol](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) (`ARP`) is a network protocol. It is an important part of the network communication used to resolve a network layer (layer 3) IP address to a link layer (layer 2) MAC address. It maps a host's IP address to its corresponding MAC address to facilitate communication between devices on a [Local Area Network](https://en.wikipedia.org/wiki/Local_area_network) (`LAN`). When a device on a LAN wants to communicate with another device, it sends a broadcast message containing the destination IP address and its own MAC address. The device with the matching IP address responds with its own MAC address, and the two devices can then communicate directly using their MAC addresses. This process is known as ARP resolution.
		- ARP is an important part of the network communication process because it allows devices to send and receive data using MAC addresses rather than IP addresses, which can be more efficient. Two types of request messages can be used:
			- **ARP Request**
				- When a device wants to communicate with another device on a LAN, it sends an ARP request to resolve the destination device's IP address to its MAC address. The request is broadcast to all devices on the LAN and contains the IP address of the destination device. The device with the matching IP address responds with its MAC address.
			- **ARP Relay**
				- When a device receives an ARP request, it sends an ARP reply to the requesting device with its MAC address. The reply message contains the IP and MAC addresses of both the requesting and the responding devices.
		- `ARP spoofing`, also known as `ARP cache poisoning` or `ARP poison routing`, is an attack that can be done using tools like [Ettercap](https://github.com/Ettercap/ettercap) or [Cain & Abel](https://github.com/xchwarze/Cain) in which we send falsified ARP messages over a LAN. The goal is to associate our MAC address with the IP address of a legitimate device on the company's network, effectively allowing us to intercept traffic intended for the legitimate device. For example, this could look like the following:
			- ```1   0.000000 10.129.12.100 -> 10.129.12.101 ARP 60  10.129.12.100 is at AA:AA:AA:AA:AA:AA
			2   0.000015 10.129.12.100 -> 10.129.12.255 ARP 60  Who has 10.129.12.101?  Tell 10.129.12.100
			3   0.000030 10.129.12.101 -> 10.129.12.100 ARP 60  10.129.12.101 is at BB:BB:BB:BB:BB:BB
			4   0.000045 10.129.12.100 -> 10.129.12.101 ARP 60  10.129.12.100 is at AA:AA:AA:AA:AA:AA```
		* The first and fourth lines show us (`10.129.12.100`) sending falsified ARP messages to the target, associating its MAC address with its IP address (`10.129.12.101`). The second and third lines show the target sending an ARP request and replying to our MAC address. This indicates that we have poisoned the target's ARP cache and that all traffic intended for the target will now be sent to our MAC address.
		* **We can use ARP poisoning to perform various activities, such as stealing sensitive information, redirecting traffic, or launching MITM attacks. However, to protect against ARP spoofing, it is important to use secure network protocols, such as IPSec or SSL, and to implement security measures, such as firewalls and intrusion detection systems.**
* ## IPv6 Addresses
	* `IPv6` is the successor of IPv4. In contrast to IPv4, the `IPv6` address is `128` bit long. The `prefix` identifies the host and network parts. The Internet Assigned Numbers Authority (`IANA`) is responsible for assigning IPv4 and IPv6 addresses and their associated network portions. In the long term, `IPv6` is expected to completely replace IPv4, which is still predominantly used on the Internet. In principle, however, IPv4 and IPv6 can be made available simultaneously (`Dual Stack`).
	* IPv6 consistently follows the `end-to-end` principle and provides publicly accessible IP addresses for any end devices without the need for NAT. Consequently, an interface can have multiple IPv6 addresses, and there are special IPv6 addresses to which multiple interfaces are assigned.
	* `IPv6` is a protocol with many new features, which also has many other advantages over IPv4:
		- Larger address space
		- Address self-configuration (SLAAC)
		- Multiple IPv6 addresses per interface
		- Faster routing
		- End-to-end encryption (IPsec)
		- Data packages up to 4 GByte
	- Four types of IPv6 addresses:
		- `Unicast` - Addresses for a single interface.
		- `Anycast` - Addresses for multiple interfaces, where only one of them receives the packet.
		- `Multicast` - Addresses for multiple interfaces, where all receive the same packet.
		- `Broadcast` - Do not exist and is realized with multicast addresses.
	- Example:
		- `192.168.12.160`
		- Full IPv6: `fe80:0000:0000:0000:dd80:b1a9:6687:2d3b/64`
			- Short IPv6: `fe80::dd80:b1a9:6687:2d3b/64`
	- Consists of two parts:
		- `Network Prefix` (network part)
			- identifies the network, subnet, or address range.
		- `Interface Identifier` also called `Suffix` (host part)
	- In RFC 5952, the aforementioned IPv6 address notation was defined:
		- All alphabetical characters are always written in lower case.
		- All leading zeros of a block are always omitted.
		- One or more consecutive blocks of `4 zeros` (hex) are shortened by two colons (`::`).
		- The shortening to two colons (`::`) may only be performed `once` starting from the left.
- ## Networking Key Terminology
	- ![[Pasted image 20231128105431.png]]
	- ![[Pasted image 20231128105515.png]]
	- ![[Pasted image 20231128105543.png]]
- ## Common Protocols
	- Internet protocols are standardized rules and guidelines defined in RFCs that specify how devices on a network should communicate with each other.
	- They ensure that devices on a network can exchange information consistently and reliably, regardless of the hardware and software used. For devices to communicate on a network, they need to be connected through a communication channel, such as a wired or wireless connection. The devices then exchange information using a set of standardized protocols that define the format and structure of the data being transmitted.
	- The two main types of connections used on networks are [Transmission Control Protocol](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) (`TCP`) and [User Datagram Protocol](https://en.wikipedia.org/wiki/User_Datagram_Protocol) (`UDP`):
		- `TCP` is a `connection-oriented` protocol that establishes a virtual connection between two devices before transmitting data by using a [Three-Way-Handshake](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment). This connection is maintained until the data transfer is complete, and the devices can continue to send data back and forth as long as the connection is active.
			- ![[Pasted image 20231128111206.png]]
			- ![[Pasted image 20231128111226.png]]
		- `UDP` is a `connectionless` protocol, which means it does not establish a virtual connection before transmitting data. Instead, it sends the data packets to the destination without checking to see if they were received.
			- ![[Pasted image 20231128111649.png]]
		- [Internet Control Message Protocol](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol) (`ICMP`) is a protocol used by devices to communicate with each other on the Internet for various purposes, including error reporting and status information. It sends requests and messages between devices, which can be used to report errors or provide status information.
			- ![[Pasted image 20231128111953.png]]
			-  [Time-To-Live](https://en.wikipedia.org/wiki/Time_to_live) (`TTL`) field in the ICMP packet header limits the packet's lifetime as it travels through the network. It prevents packets from circulating indefinitely on the network in the event of routing loops.
				- Each time a packet passes through a router, the router decrements the `TTL value by 1`. When the TTL value reaches `0`, the router discards the packet and sends an ICMP `Time Exceeded` message back to the sender.
				- For example, if we see a ping with the `TTL` value of `122`, it could mean that we are dealing with a Windows system (`TTL 128` by default) that is 6 hops away.
				- However, it is also possible to guess the operating system based on the default `TTL` value used by the device. **Each operating system typically has a default `TTL` value when sending packets.** This value is set in the packet's header and is decremented by 1 each time the packet passes through a router. Therefore, examining a device's default `TTL` value makes it possible to infer which operating system the device is using.
					- For example: **Windows systems** (`2000/XP/2003/Vista/10`) typically have a default `TTL` value of 128, while **macOS and Linux** systems typically have a default `TTL` value of 64 and **Solaris**' default `TTL` value of 255. However, it is important to note that the **user can change these values**, so they should be independent of a definitive way to determine a device's operating system.
		- [Voice over Internet Protocol](https://www.fcc.gov/general/voice-over-internet-protocol-voip) (`VoIP`) is a method of transmitting voice and multimedia communications. For example, it allows us to make phone calls using a broadband internet connection instead of a traditional phone line, like Skype, Whatsapp, Google Hangouts, Slack, Zoom, and others.
			- The most common VoIP ports are `TCP/5060` and `TCP/5061`, which are used for the [Session Initiation Protocol](https://en.wikipedia.org/wiki/Session_Initiation_Protocol) (SIP). However, the port `TCP/1720` may also be used by some VoIP systems for the [H.323 protocol](https://en.wikipedia.org/wiki/H.323), a set of standards for multimedia communication over packet-based networks. Still, SIP is more widely used than H.323 in VoIP systems.
			- ![[Pasted image 20231128113631.png]]
			- However, SIP allows us to enumerate existing users for potential attacks. This can be done for various purposes, such as determining a user's availability, finding out information about the user's capabilities or services, or performing brute-force attacks on user accounts later on.
				* One of the possible ways to enumerate users is the SIP `OPTIONS` request. It is a method used to request information about the capabilities of a SIP server or user agents, such as the types of media it supports, the codecs it can decode, and other details. The `OPTIONS` request can probe a SIP server or user agent for information or test its connectivity and availability.
				* During our analysis, it is possible to discover a `SEPxxxx.cnf` file, where `xxxx` is a unique identifier, is a configuration file used by Cisco Unified Communications Manager, formerly known as Cisco CallManager, to define the settings and parameters for a Cisco Unified IP Phone. The file specifies the phone model, firmware version, network settings, and other details.
* ## Wireless Networks
	* Wireless networks use radio frequency (`RF`) technology to transmit data between devices. Each device on a wireless network has a wireless adapter that converts data into RF signals and sends them over the air. O
		* For example, a local area network (LAN) that covers a small area, such as a home or small office, might use a wireless technology called `WiFi`, which has a range of a few hundred feet. On the other hand, a wireless wide area network (`WWAN`) might use mobile telecommunication technology such as cellular data (`3G`, `4G LTE`, `5G`), which can cover a much larger area, such as an entire city or region.
	* Communication between devices occurs over RF in the `2.4 GHz` or `5 GHz` bands in a WiFi network. 
		* The WAP is a central device, like a router, that connects the wireless network to a wired network and controls access to the network.
	* The strength of the RF signal and the distance it can travel are influenced by factors such as the transmitter's power, the presence of obstacles, and the density of RF noise in the environment. 
	* The device must also be configured with the correct network settings, such as the network name / [Service Set Identifier](https://www.geeksforgeeks.org/service-set-identifier-ssid-in-computer-network/) (`SSID`) and `password`. So, to connect to the router, the laptop uses a wireless networking protocol called [IEEE 802.11](https://en.wikipedia.org/wiki/IEEE_802.11).
	* The connection request frame contains various fields of information, including the following but not limited to:
		* `MAC address` - A unique identifier for the device's wireless adapter.
		* `SSID` - The network name, also known as the `Service Set Identifier` of the WiFi network.
		* `Supported data rates` - A list of the data rates the device can communicate.
		* `Supported channels` - A list of the `channels` (frequencies) on which the device can communicate.
		* `Supported security protocols` - A list of the security protocols that the device is capable of using, such as `WPA2`/`WPA3`.
	* In addition to the `IEEE 802.11` protocol, other networking protocols and technologies may also be used, like TCP/IP, DHCP, and WPA2, in a WiFi network to perform tasks such as assigning IP addresses to devices, routing traffic between devices, and providing security.
	* **WEP Challenge-Response Handshake**
		* The challenge-response handshake is a process to establish a secure connection between a WAP and a client device in a wireless network that uses the WEP security protocol. This involves exchanging packets between the WAP and the client device to authenticate the device and establish a secure connection.
		*  [Cyclic Redundancy Check](https://en.wikipedia.org/wiki/Cyclic_redundancy_check) (`CRC`) is an error-detection mechanism used in the WEP protocol to protect against data corruption in wireless communications.
	* **Security Features**
		* WiFi networks have several security features to protect against unauthorized access and ensure the privacy and integrity of data transmitted over the network. Some of the leading security features include but are not limited to:
			- Encryption - WEP, WPA2, WPA3
			- Access Control
			- Firewall
		- **WEP**
			- `WEP` uses a `40-bit` or `104-bit` key to encrypt data
			- `WEP` uses the `RC4 cipher` encryption algorithm, which makes it vulnerable to attacks
			- WEP uses a `shared key` for authentication, which means the same key is used for encryption and authentication. There are two versions of the WEP protocol:
				- `WEP-40`/`WEP-64` - 40-bit (secret) key
				- `WEP-104` - 104-bit key
			- The key is divided into an [Initialization Vector](https://en.wikipedia.org/wiki/Initialization_vector) (`IV`) and a `secret key`.
		- **WPA**
			- `WPA` provides the highest level of security and is not susceptible to the same types of attacks as WEP.
			- WPA uses more secure authentication methods, such as a [Pre-Shared Key](https://en.wikipedia.org/wiki/Pre-shared_key) (`PSK`) or an 802.1X authentication server, which provide stronger protection against unauthorized access.
		- **Authentication Protocols**
			- [Lightweight Extensible Authentication Protocol](https://en.wikipedia.org/wiki/Lightweight_Extensible_Authentication_Protocol) (`LEAP`) and [Protected Extensible Authentication Protocol](https://en.wikipedia.org/wiki/Protected_Extensible_Authentication_Protocol) (`PEAP`) are authentication protocols used to secure wireless networks to provide a secure method for authenticating devices on a wireless network and are often used in conjunction with WEP or WPA to provide an additional layer of security. Both based on the [Extensible Authentication Protocol](https://en.wikipedia.org/wiki/Extensible_Authentication_Protocol) (`EAP`), a framework for authentication used in various networking contexts.
				- However, one key difference between `LEAP` and `PEAP` is how they secure the authentication process.
				- `LEAP` uses a `shared key` for authentication, which means that the `same key` is used for `encryption and authentication`.
				- `PEAP` uses a more secure authentication method called tunneled [Transport Layer Security](https://en.wikipedia.org/wiki/Transport_Layer_Security) (`TLS`). This method establishes a secure connection between the device and the WAP using a `digital certificate`, and an encrypted tunnel protects the authentication process. This provides more robust protection against unauthorized access and is more resistant to attacks.
		- **TACACS+**
			- In a wireless network, when a wireless access point (WAP) sends an authentication request to a [Terminal Access Controller Access-Control System Plus](https://www.ciscopress.com/articles/article.asp?p=422947&seqNum=4) (`TACACS+`) server, it is likely that the `entire request packet` will be encrypted to protect the confidentiality and integrity of the request.
			- `TACACS+` is a protocol used to authenticate and authorize users accessing network devices, such as routers and switches. When a WAP sends an authentication request to a `TACACS+` server, the request typically includes the user's credentials and other information about the session.
			- Several encryption methods may be used to encrypt the authentication request, such as `SSL`/`TLS` or `IPSec`. The specific encryption method used may depend on the configuration of the `TACACS+` server and the capabilities of the WAP.
	- **Disassociation Attack**
		- A [Disassociation Attack](https://www.makeuseof.com/what-are-disassociation-attacks/) is a type of `all` wireless network attack that aims to disrupt the communication between a WAP and its clients by sending disassociation frames to one or more clients.
		- The WAP uses disassociation frames to disconnect a client from the network. When a WAP sends a disassociation frame to a client, the client will disconnect from the network and have to reconnect to continue using the network.
		- We can launch the attack from `within` or `outside` the network depending on our location and network security measures. The purpose of this attack is to disrupt the communication between the WAP and its clients, causing the clients to disconnect and possibly causing inconvenience or disruption to the users. We can also use it as a precursor to other attacks, such as a MITM attack, by forcing the clients to reconnect to the network and potentially exposing them to further attacks.
	- **Wireless Hardening**
		- There are many different ways to protect wireless networks. However, some examples should be considered to increase wireless networks' security dramatically. These are the following, but not limited to:
			- Disabling broadcasting
			- WiFi Protected Access
			- MAC filtering
			- Deploying EAP-TLS
- ## Virtual Private Networks
	- A `Virtual Private Network` (`VPN`) is a technology that allows a secure and encrypted connection between a private network and a remote device. This allows the remote machine to access the private network directly, providing secure and confidential access to the network's resources and services.
		- VPN typically uses the ports `TCP/1723` for [Point-to-Point Tunneling Protocol](https://www.lifewire.com/pptp-point-to-point-tunneling-protocol-818182) `PPTP` VPN connections and `UDP/500` for [IKEv1](https://www.cisco.com/c/en/us/support/docs/security-vpn/ipsec-negotiation-ike-protocols/217432-understand-ipsec-ikev1-protocol.html) and [IKEv2](https://nordvpn.com/blog/ikev2ipsec/) VPN connections.
	- We can use VPNs to connect multiple remote locations, such as branch offices, into a single private network, making it easier to manage and access network resources. However, several components and requirements are necessary for a VPN to work:
		- `VPN Client` - This is installed on the remote device and is used to establish and maintain a VPN connection with the VPN server. For example, this could be an OpenVPN client.
		- `VPN Server` - This is a computer or network device responsible for accepting VPN connections from VPN clients and routing traffic between the VPN clients and the private network.
		- `Encryption` - VPN connections are encrypted using a variety of encryption algorithms and protocols, such as AES and IPsec, to secure the connection and protect the transmitted data.
		- `Authentication` - The VPN server and client must authenticate each other using a shared secret, certificate, or another authentication method to establish a secure connection.
	- The VPN client and server use these ports to establish and maintain the VPN connection. At the TCP/IP layer, a VPN connection typically uses the [Encapsulating Security Payload](https://www.ibm.com/docs/en/i/7.4?topic=protocols-encapsulating-security-payload) (`ESP`) protocol to encrypt and authenticate the VPN traffic. This allows the VPN client and server to exchange data over the public internet securely.
	- **IPsec**
		- [Internet Protocol Security](https://www.cloudflare.com/learning/network-layer/what-is-ipsec/) (`IPsec`) is a network security protocol that provides encryption and authentication for internet communications. It is a powerful and widely-used security protocol that provides encryption and authentication for internet communications and works by encrypting the data payload of each IP packet and adding an `authentication header` (`AH`), which is used to verify the integrity and authenticity of the packet. IPsec uses a combination of two protocols to provide encryption and authentication:
			1. [Authentication Header](https://www.ibm.com/docs/en/i/7.1?topic=protocols-authentication-header) (`AH`): This protocol provides integrity and authenticity for IP packets but does not provide encryption. It adds an authentication header to each IP packet, which contains a cryptographic checksum that can be used to verify that the packet has not been tampered with.
			2. [Encapsulating Security Payload](https://www.ibm.com/docs/en/i/7.4?topic=protocols-encapsulating-security-payload) (`ESP`): This protocol provides encryption and optional authentication for IP packets. It encrypts the data payload of each IP packet and optionally adds an authentication header, similar to AH.
		* IPsec can be used in two modes.
			* Transport Mode
			* Tunnel Mode
	* **PPTP**
		* [Point-to-Point Tunneling Protocol](https://www.vpnranks.com/blog/pptp-vs-l2tp/) (`PPTP`) is also a network protocol that allows the creation of VPNs and works by establishing a secure tunnel between the VPN client and server and then encapsulating the data being transmitted within this tunnel.
		* It is an extension of the PPTP and is implemented in many operating systems. **Due to known vulnerabilities, PPTP is no longer considered secure today**. PPTP can be used to tunnel protocols such as IP, IPX, or NetBEUI via IP. 
		* It is largely **replaced by other VPN protocols** such as `L2TP/IPsec`, `IPsec/IKEv2`, or `OpenVPN`. 
* ## Vendor Specific Information
	* [Cisco IOS](https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-technologies/index.html) is the operating system of Cisco network devices such as routers and switches. It provides features and services required to manage and operate network devices. This operating system comes in different versions and releases that vary in features, support, and performance. It offers several features required for the operation of modern networks, such as, but not limited to:
		- Support for IPv6
		- Quality of Service (QoS)
		- Security features such as encryption and authentication
		- Virtualization features such as Virtual Private LAN Service (VPLS)
		- Virtual Routing and Forwarding (VRF)
	- The Cisco IOS devices can be configured for SSH or Telnet. So it can be accessed remotely. We can determine from the response we receive that it is indeed a Cisco IOS, as it responds with the `User Access Verification` message.
	- **VLANs**
		- A `VLAN` is a logical grouping of network endpoints connected to defined ports on a switch, allowing the segmentation of networks by creating logical broadcast domains that can span multiple physical LAN segments.
		- With `VLANs`, network administrators can segment networks based on factors such as team, function, department, or application, without worrying about the physical location of endpoints and users. A broadcast packet sent over one `VLAN` does not reach any other endpoint that is a member of another `VLAN`. Because each `VLAN` is regarded as a broadcast domain, it needs to have its own `subnet`
		- A myriad of benefits is attained when using `VLANs`, including:
			- `Better Organization`: Network administrators can group endpoints based on any common attribute they share.
			- `Increased Security`: Network segmentation disallows unauthorized members from sniffing network packets in other `VLANs`.
			- `Simplified Administration`: Network administrators do not have to worry about the physical locations of an endpoint.
			- `Increased Performance`: With reduced broadcast traffic for all endpoints, more bandwidth is made available for use by the network.
		- Network administrators can assign the ports of a switch to `VLANs` either statically or dynamically.
			- Static `VLAN` assignment, which is the simplest and most common method, involves assigning each port to a `VLAN` manually using the switch's `network operating system`; this must be done for all switches separately (it is essential to keep in mind that endpoints connecting to these ports are unaware of the existence of `VLANs`).
			- Dynamic `VLAN` assignment automatically determines an endpoint's `VLAN` membership based on `MAC` addresses or protocols. The system administrator can register the `MAC` addresses in a centralized `VLAN` management service/database, such as the `VLAN Membership Policy Server` (`VMPS`) service, and then the switch queries the database of `VMPS` to determine the `VLAN` of the endpoint with that specific `MAC` address. Regardless of their flexibility and mobility, dynamic `VLANs` increase administrative overhead.
			- Security-wise, static `VLANs` are the more secure option because a port will forever be tied to a specific `VLAN` ID, unless changed manually afterward.
				- For dynamic `VLANs`, an attacker could potentially utilize tools such as [macchanger](https://github.com/alobbs/macchanger) to spoof the MAC address of legitimate endpoints and attain membership of their `VLANs`, therefore sniffing all network traffic sent through them.
		- Any port on a `VLAN`-enabled switch must be either an `access port` or a `trunk port`.
			- `Access ports` belong to and can carry the traffic of only one `VLAN` (or in some cases two, with the second being for `voice traffic`); any traffic arriving on an `access port` is assumed to belong to the `VLAN` the port was assigned.
			- On the other hand, `trunk ports` can carry multiple `VLANs` at the same time; `trunk links` connect two `trunk ports` on two switches (or a switch and router) to allow information from multiple `VLANs` to be carried out across switches.
		- Two main `trunking methods` are utilized to achieve this, `ISL` and `IEEE 802.1Q`.
			- `Inter-Switch Link` (`ISL`) is a Cisco-proprietary protocol used for trunking between `VLAN`-enabled devices. 
			- To ensure interoperability of `VLAN` technologies from the various network-equipments vendors, the `Institute of Electrical and Electronics Engineers` (`IEEE`) developed the [802.1Q](https://ieeexplore.ieee.org/document/10004498) specification in 1998.
		- ![[Pasted image 20231129092403.png]]
			- `Tag protocol identifier` (`TPID`) is a 16-bit field always set to `0x8100` to identify the `Ethernet` frame as an `802.1Q`-tagged frame.
			- `Tag Control Information` (`TCI`) is a 16-bit field containing `Priority code point` (`PCP`), `Drop eligible indicator` (`DEI`) (previously known as `Canonical format indicator` (`CFI`)), and `VLAN identifier` (`VID`). 
		- Some `network interface cards` (`NICs`) attached to computers/servers support `VLAN tagging`. Let us see how we can assign a `VLAN` ID to a `NIC` using Linux and Windows.
			- **Assigning NICs a VLAN in Linux**
				- To assign a network adapter a `VLAN` in Linux, many tools can be used, such as [ip](https://man7.org/linux/man-pages/man8/ip.8.html), [nmcli](https://linux.die.net/man/1/nmcli), and [vconfig](https://linux.die.net/man/8/vconfig) (deprecated). However, first, we need to ensure that the Kernel has the [802.1Q](https://elixir.bootlin.com/linux/v6.4.7/source/net/8021q/vlan.c) module loaded:
					- `sudo modprobe 8021q`
					- OR
					- `lsmod | grep 8021`
				- Find the name of the physical `Ethernet` interface that we will create the `VLAN` interface on top of, which is `eth0`:
					- `ip a`
				- Use `ip` to create a new interface that is a member of the desired `VLAN`, `20`, for example, on top of `eth0`:
					- `sudo ip link add link eth0 name eth0.20 type vlan id 20`
				- Assign the interface an IP address and then start it:
					- `sudo ip addr add 192.168.1.1/24 dev eth0.20`
					- `sudo ip link set up eth0.20`
				- Check whether the interface has changed states to up:
					- `ip a | grep eth0.20`
			- **Assigning NICs a VLAN in Windows**
				- Device Manager > Network Adapter Properties > Advanced tab: VLAN ID - 10 Value.
				- Check it:
					- `Get-NetAdapter | Format-Table -AutoSize`
					- `Get-NetAdapterAdvancedProperty -DisplayName "vlan id"`
				* Or from CLI:
					`Set-NetAdapter -Name "Ethernet 2" -VlanID 10`
		* **Analyzing VLAN Tagged Traffic**
			* We can identify and analyze `VLAN` tagged traffic on a network with `Wireshark` using the [vlan](https://www.wireshark.org/docs/dfref/v/vlan.html) filter. For example, when analyzing a network packet dump, we can inspect packets with `802.1Q` tagging using the filter `vlan`.
			* Moreover, we can search for packets with a specific `VLAN` ID; for example, to search for packets having `VLAN 10`, we can use the filter `vlan.id == 10`.
			* Additionally, to enumerate the used `VLAN` IDs from a packet dump, we can utilize [tshark](https://www.wireshark.org/docs/man-pages/tshark.html):
				* `tshark -r "The Ultimate PCAP v20221220.pcapng" -T fields -e vlan.id | sort -`
	* **Security Implications and VLAN Attacks**
		* Regardless of improving a network's security posture, adversaries can still circumvent the defensive mechanisms put forth by `VLANs`. 
		* `VLAN hopping` attacks enable traffic from one `VLAN` to be seen by another `VLAN` without the aid of a router. It exploits Cisco's `Dynamic Trunking Protocol` (`DTP`), a protocol used to automatically negotiate the formation of a `trunk link` between two Cisco devices.
			* An adversary needs to configure a host to mimic/act like a switch to take advantage of the automatic trunking port feature enabled by default on most switch ports.
			* To exploit `VLAN hopping`, an adversary must be able to physically connect with a switch port that has `DTP` enabled. The adversary can abuse this connection by configuring a host connected to the switch on that specific port to spoof `802.1Q` signaling and the `DTP` packets. If successful, the switch will eventually establish a `trunk link` with the adversary's host, exposing the network packets, not only for a specific `VLAN`.
			* We can use tools such as [Yersinia](https://linux.die.net/man/8/yersinia) to perform `VLAN hopping` attacks
		* `Double-tagging VLAN hopping attack` is an increasingly more sophisticated attack against `VLANs`. Although `VLAN double-tagging` is a legitimate practice that entities such as `Internet Service Providers` (`ISPs`) utilize (they can use their `VLANs` internally while carrying traffic from clients that are already `VLAN tagged`), adversaries can also attempt to abuse it.
			* In a `double-tagging VLAN hopping attack`, an adversary embeds a hidden `802.1Q` tag inside an `Ethernet` frame that already has an `802.1Q` tag, allowing the frame to go to a different `VLAN`, which the original `802.1Q` tag did not specify.
			* An adversary can carry out this attack following three steps. Bare in mind that this attack only works if the adversary is connected to a port residing in the same `VLAN` as the `native VLAN` of the trunk port:
				1. The adversary sends a `double-tagged 802.1Q` `Ethernet` frame to the switch with the outer header having the `VLAN` ID of the adversary, which is the same as the native `VLAN` of the trunk port. Assume that the native `VLAN` is `VLAN 10` and that `VLAN 30` is the `VLAN` the adversary wants to reach, where the victim resides.
				2. The outer 4-byte `802.1Q` tag arrives on the switch, and it is seen to be destined for `VLAN 10`, the native `VLAN`. After removing the `VLAN 10` tag, the frame is forwarded on all `VLAN 10` ports. On the trunk port, the `VLAN 10` tag is stripped (removed), and the packet is not re-tagged because it is part of the native `VLAN`. However, the `VLAN 30` tag is still intact (not stripped), and the first switch has not inspected it.
				3. Subsequently, the switch will look only at the inner `802.1Q` tag that the adversary sent, and it decides that the frame must be forwarded for `VLAN 30`, which is the adversary's chosen `VLAN`. Now, the second switch will either send the frame to the victim port directly or flood it, depending on whether there is an existing MAC address table entry for the victim host.
			* [Scapy](https://scapy.readthedocs.io/en/latest/usage.html#vlan-hopping) allows carrying out the `double-tagging VLAN hopping attack`, in addition to `Yersinia`.
	* **VXLAN**
		* `Virtual eXtensible Local Area Network` (`VXLAN`), is essentially a 'Layer 2 overlay scheme on a Layer 3 network.' `VXLAN` is specifically designed to address the limitations of traditional Layer 2 networks and cater to the requirements of Layer 2 and Layer 3 data center network infrastructures in a multi-tenant environment with virtual machines (VMs).
		* Operating over the existing networking infrastructure, `VXLAN` provides an innovative way to seamlessly extend a Layer 2 network. Its primary objective is to facilitate the scaling of Layer 2 networks across expansive data center landscapes, even spanning multiple physical data locations. Each `VXLAN` overlay is termed a `VXLAN segment`, ensuring that only VMs within the same VXLAN segment can communicate with each other, thus maintaining network isolation and security. A 24-bit segment ID, known as the `VXLAN Network Identifier` (`VNI`), uniquely identifies each VXLAN segment.
	* **Cisco Discovery Protocol**
		* Cisco Discovery Protocol (CDP) is a layer-2 network protocol from Cisco that is used by Cisco devices such as routers, switches, and bridges to gather information about other directly connected Cisco devices. This information can be used to discover and track the network's topology and help manage and troubleshoot the network. This protocol is usually enabled in Cisco devices, but it can be disabled if it is not needed or if it should be disabled for security reasons.
* ## Key Exchange Mechanisms
	* Key exchange methods are used to exchange [cryptographic keys](https://www.cloudflare.com/learning/ssl/what-is-a-cryptographic-key/) between two parties securely. This is an essential part of many cryptographic protocols, as the security of the encryption used to protect communication relies on the secrecy of the keys.
		* `Diffie-Hellman` (`DH`) Relatively secure and computationally efficient. Vulnerable to `MITM` attacks
		* `Rivest–Shamir–Adleman` (`RSA`) Widely used and considered secure, but computationally intensive
		* `Elliptic Curve Diffie-Hellman` (`ECDH`) Provides enhanced security compared to traditional Diffie-Hellman
		* `Elliptic Curve Digital Signature Algorithm` (`ECDSA`) Provides enhanced security and efficiency for digital signature generation
	* [Internet Key Exchange](https://www.hypr.com/security-encyclopedia/internet-key-exchange) (`IKE`) is a protocol used to establish and maintain secure communication sessions, such as those used in VPNs. It uses a combination of the `Diffie-Hellman` key exchange algorithm and `other cryptographic techniques` to securely exchange keys and negotiate security parameters.
		* It is typically used in conjunction with other protocols and algorithms, such as the RSA algorithm for key exchange and digital signatures, and the [Advanced Encryption Standard](https://www.geeksforgeeks.org/advanced-encryption-standard-aes/) (`AES`) for data encryption.
		* IKE operates either in `main mode` or `aggressive mode`. These modes determine the sequence and parameters of the key exchange process and can affect the security and performance of the IKE session.
			* **Main Mode**
				* The default mode for `IKE` and is generally considered `more secure` than the aggressive mode. The key exchange process is performed in `three phases` in the main mode, each exchanging a different set of security parameters and keys. This allows for greater flexibility and security but can also result in slower performance compared to aggressive mode.
			* **Aggressive Mode**
				* An alternative mode for `IKE` that provides `faster performance` by reducing the number of round trips and message exchanges required for key exchange. In this mode, the key exchange process is performed in `two phases`, with all security parameters and keys being exchanged in the first phase. However, this can provide faster performance but may also reduce the security of the IKE session compared to the main mode since the `aggressive mode` does not provide identity protection.
	* **Pre-Shared Keys**
		* In IKE, a `Pre-Shared Key` (`PSK`) is a secret value shared between the two parties involved in the key exchange. This key is used to authenticate the parties and establish a shared secret that encrypts subsequent communication.
		* The main advantage of using a PSK is that it provides an additional layer of security by allowing the parties to authenticate with each other. However, using a PSK also has some limitations and drawbacks. For example, it can be difficult to exchange the key securely, and if the key is compromised through a MITM attack, the security of the IKE session may be compromised.
* ## Authentication Protocols
	* ![[Pasted image 20231129102445.png]]
* ## TCP/UDP Connections
	* [Transmission Control Protocol](https://en.wikipedia.org/wiki/Transmission_Control_Protocol) (`TCP`) and [User Datagram Protocol](https://en.wikipedia.org/wiki/User_Datagram_Protocol) (`UDP`) are both protocols used in information and data transmission on the Internet. Typically, TCP connections transmit important data, such as web pages and emails. In contrast, UDP connections transmit real-time data such as streaming video or online gaming.
		* `TCP` is a connection-oriented protocol that ensures that all data sent from one computer to another is received. 
		* `UDP`, on the other hand, is a connectionless protocol.
	* An [Internet Protocol](https://en.wikipedia.org/wiki/Internet_Protocol) (`IP`) packet is the data area used by the network layer of the [Open Systems Interconnection](https://en.wikipedia.org/wiki/OSI_model) (`OSI`) model to transmit data from one computer to another. It consists of a header and the payload, the actual payload data.
		* The header of an IP packet contains several fields that have important information.
		* We may see a computer with multiple IP addresses in different networks. Here we should pay attention to the `IP ID` field. It is used to identify fragments of an IP packet when fragmented into smaller parts. It is a `16-bit` field with a unique number ranging from `0-65535`.
		* If a computer has multiple IP addresses, the `IP ID` field will be different for each packet sent from the computer but very similar.
	* The `Record-Route field` in the IP header also records the route to a destination device. When the destination device sends back the `ICMP Echo Reply` packet, the IP addresses of all devices that pass through the packet are listed in the `Record-Route field` of the IP header. This happens when we use the following command, for example:
		* `ping -c 1 -R 10.129.143.158`
		* The output indicates that a `ping` request was sent and a response was received from the destination device and also shows the `Record-Route field` in the IP header of the `ICMP Echo Request` packet. The Record Route field contains the IP addresses of all devices that passed through the `ICMP Echo Request` packet on the way to the destination device.
	* The `traceroute` tool can also be used to trace the route to a destination more accurately, which uses the TCP timeout method to determine when the route has been fully traced.
	* The payload (also referred to as `IP Data`) is the actual payload of the packet. It contains the data from various protocols, such as TCP or UDP, that are being transmitted, just like the contents of the letter in the envelope.
	* TCP packets, also known as `segments`, are divided into several sections called headers and payloads. The TCP segments are wrapped in the sent IP packet.
	* UDP transfers `datagrams` (small data packets) between two hosts.
	* `Blind spoofing`, is a method of data manipulation attack in which an attacker sends false information on a network without seeing the actual responses sent back by the target devices. It involves manipulating the IP header field to indicate false source and destination addresses.
		* For example, we send a TCP packet to the target host with false source and destination port numbers and a false `Initial Sequence Number` (`ISN`). The `ISN` is a field in the TCP header that is used to specify the sequence number of the first TCP packet in a connection. The ISN is set by the sender of a TCP packet and sent to the receiver in the TCP header of the first packet. This can cause the target host to establish a connection with us without receiving the connection.
		* This attack is commonly used to disrupt the integrity of network connections or to break connections between network devices. It can also be used to monitor network traffic or to intercept information sent by network devices.
* ## Cryptography
	* Digital keys in `symmetric` or `asymmetric` encryption processes are used for encryption.
		* Symmetric encryption, also known as secret key encryption, is a method that uses the same key to encrypt and decrypt the data. This means the sender and the receiver must have the same key to decrypt the data correctly.
			* [Advanced Encryption Standard](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) (`AES`) and [Data Encryption Standard](https://en.wikipedia.org/wiki/Data_Encryption_Standard) (`DES`) are examples of symmetric encryption algorithms.
				* DES is a symmetric-key block cipher, and its encryption works as a combination of the one-time pad, permutation, and substitution ciphers applied to bit sequences. It uses the `same key` in both `encrypting and decrypting` data.
					* An extension of DES is the so-called [Triple DES / 3DES](https://en.wikipedia.org/wiki/Triple_DES), which encrypts data more securely.
				* Compared to DES, AES uses 128-bit (`AES-128`), 192-bit (`AES-192`), or 256-bit (`AES-256`) keys to encrypt and decrypt data.
					*  This means that AES encryption and decryption can be performed faster than DES, which is especially important when large amounts of data need to be encrypted.
					* Used in:
						* WLAN IEEE 802.11i, IPsec, SSH, VoIP, PGP, OpenSSL
		* Asymmetric encryption, also known as `public-key encryption`, is a method of encryption that uses two different keys:
			- a `public key`
			- a `private key`
			- Examples of asymmetric encryption methods include [Rivest–Shamir–Adleman](https://en.wikipedia.org/wiki/RSA_(cryptosystem)) (`RSA`), [Pretty Good Privacy](https://en.wikipedia.org/wiki/Pretty_Good_Privacy) (`PGP`), and [Elliptic Curve Cryptography](https://en.wikipedia.org/wiki/Elliptic-curve_cryptography) (`ECC`).
			- Used in:
				- SSH, E-Signatures, SSL/TLS, VPNs, PKI, Cloud
		- **Cipher Modes**
			- A cipher mode refers to how a block cipher algorithm encrypts a plaintext message. A block cipher algorithm encrypts data, each using fixed-size blocks of data (usually 64 or 128 bits). A cipher mode defines how these blocks are processed and combined to encrypt a message of any length. There are several common cipher modes, including:
				- [Electronic Code Book](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation) (`ECB`) mode - ECB mode is generally not recommended for use due to its susceptibility to certain types of attacks. Furthermore, it does not hide data patterns efficiently. As a result, statistical analysis can reveal elements of clear-text messages, for example, in web applications.
				- [Cipher Block Chaining](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CBC) (`CBC`) mode - CBC mode is generally used to encrypt messages like disk encryption and e-mail communication. This is the default mode for AES and is also used in software like TrueCrypt, VeraCrypt, TLS, and SSL.
				- [Cipher Feedback](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_feedback_(CFB)) (`CFB`) mode - CFB mode is well suited for real-time encryption of a data stream, e.g., network communication encryption or encryption/decryption of files in transit like Public-Key Cryptography Standards (PKCS) and Microsoft's BitLocker.
				- [Output Feedback](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#OFB) (`OFB`) mode - OFB mode is also used to encrypt a data stream, e.g., to encrypt real-time communication. However, this mode is considered better for the data stream because of how the key stream is generated. We can find this mode in PKCS but also in the SSH protocol.
				- [Counter](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#CTR) (`CTR`) mode - CTR mode encrypts real-time data streams AES uses, e.g., network communication, disk encryption, and other real-time scenarios where data is processed. An example of this would be IPsec or Microsoft's BitLocker.
				- [Galois/Counter](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (`GCM`) mode - GCM is used in cases where confidentiality and integrity need to be protected together, such as wireless communications, VPNs, and other secure communication protocols.