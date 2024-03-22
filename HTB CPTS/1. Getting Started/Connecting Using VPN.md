* A [virtual private network (VPN)](https://en.wikipedia.org/wiki/Virtual_private_network) allows us to connect to a private (internal) network and access hosts and resources as if we were directly connected to the target private network.

---
### Why Use a VPN?

* We can use a VPN service such as `NordVPN` or `Private Internet Access` and connect to a VPN server in another part of our country or another region of the world to obscure our browsing traffic or disguise our public IP address.
* This can provide us with some level of security and privacy.
	* Usage of a VPN service **does not** guarantee anonymity or privacy but is useful for bypassing certain network/firewall restrictions or when connected to a possible hostile network (i.e., a public airport wireless network).

---
### Connecting to HTB VPN

* HTB and other services offering purposefully vulnerable VMs/networks require players to connect to the target network via a VPN to access the private lab network. Hosts within HTB networks cannot connect directly out to the internet.
 
	`sudo openvpn user.ovpn`

* The last line `Initialization Sequence Completed` tells us that we successfully connected to the VPN.
* If we type `ifconfig` in another terminal window, we will see a `tun` adapter if we successfully connected to the VPN.

	`ifconfig`

* Typing `netstat -rn` will show us the networks accessible via the VPN.

	`netstat -rn`

* Here can see that the 10.129.0.0/16 network used for HTB Academy machines is accessible via the tun0 adapter via the 10.10.14.0/23 network.