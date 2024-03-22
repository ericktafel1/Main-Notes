* Tools such as `SSH`, `Netcat`, `Tmux`, and `Vim` are essential and are used daily by most information security professionals.

---
### Using SSH

* [Secure Shell (SSH)](https://en.wikipedia.org/wiki/SSH_(Secure_Shell)) is a network protocol that runs on port `22` by default and provides users such as system administrators a secure way to access a computer remotely. SSH can be configured with password authentication or passwordless using [public-key authentication](https://serverpilot.io/docs/how-to-use-ssh-public-key-authentication/) using an SSH public/private key pair.

`ssh Bob@10.10.10.10`
`Bob@remotehost's password: *********`

---
### Using Netcat/Socat

* [Netcat](https://linux.die.net/man/1/nc), `ncat`, or `nc`, is an excellent network utility for interacting with TCP/UDP ports. It can be used for many things during a pentest. Its primary usage is for connecting to shells.
* In addition to that, `netcat` can be used to connect to any listening port and interact with the service running on that port. For example, `SSH` is programmed to handle connections over port 22 to send all data and keys. We can connect to TCP port 22 with `netcat`:

`netcat 10.10.10.10 22`
`SSH-2.0-OpenSSH_8.4p1 Debian-3`

* As we can see, port 22 sent us its banner, stating that `SSH` is running on it. This technique is called `Banner Grabbing`, and can help identify what service is running on a particular port.
* There's another Windows alternative to `netcat` coded in PowerShell called [PowerCat](https://github.com/besimorhino/powercat). `Netcat` can also be used to transfer files between machines, as we'll discuss later.
* Another similar network utility is [socat](https://linux.die.net/man/1/socat), which has a few features that `netcat` does not support, like forwarding ports and connecting to serial devices. `Socat` can also be used to [upgrade a shell to a fully interactive TTY](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/#method-2-using-socat).
* `Socat` is a very handy utility that should be a part of every penetration tester's toolkit. A [standalone binary](https://github.com/andrew-d/static-binaries) of `Socat` can be transferred to a system after obtaining remote code execution to get a more stable reverse shell connection.

---
### Using Tmux

* Terminal multiplexers, like `tmux` or `Screen`, are great utilities for expanding a standard Linux terminal's features, like having multiple windows within one terminal and jumping between them.

`sudo apt install tmux -y`

`tmux` or `tmux new -s namedsession`

* The default key to input `tmux` commands prefix is `[CTRL + B]`. In order to open a new window in `tmux`, we can hit the prefix 'i.e. `[CTRL + B]`' and then hit `C`.
* We see the numbered windows at the bottom. We can switch to each window by hitting the prefix and then inputting the window number, like `0` or `1`. We can also split a window vertically into panes by hitting the prefix and then `[SHIFT + %]`.
* We can also split into horizontal panes by hitting the prefix and then `[SHIFT + "]`.
* We can switch between panes by hitting the prefix and then the `left` or `right` arrows for horizontal switching or the `up` or `down` arrows for vertical switching.
	* `[CTRL + B]` + `SPACE` to auto format the windows
* This [cheatsheet](https://tmuxcheatsheet.com/) is a very handy reference. Also, this [Introduction to tmux](https://www.youtube.com/watch?v=Lqehvpe_djs) video by `ippsec` is worth your time.

---
### Using Vim

* [Vim](https://linuxcommand.org/lc3_man_pages/vim1.html) is a great text editor that can be used for writing code or editing text files on Linux systems. One of the great benefits of using `Vim` is that it relies entirely on the keyboard.

`vim /etc/hosts`

* If we want to create a new file, input the new file name, and `Vim` will open a new window with that file. Once we open a file, we are in read-only `normal mode`, which allows us to navigate and read the file. To edit the file, we hit `i` to enter `insert mode`, shown by the "`-- INSERT --`" at the bottom of `Vim`. Afterward, we can move the text cursor and edit the file.
* Once we are finished editing a file, we can hit the escape key `esc` to get out of `insert mode`, back into `normal mode`. When we are in `normal mode`, we can use the following keys to perform some useful shortcuts:

|Command|Description|
|---|---|
|`x`|Cut character|
|`dw`|Cut word|
|`dd`|Cut full line|
|`yw`|Copy word|
|`yy`|Copy full line|
|`p`|Paste|
* If we want to save a file or quit `Vim`, we have to press`:` to go into `command mode`. Once we do, we will see any commands we type at the bottom of the vim window. The following are some of them:

|Command|Description|
|---|---|
|`:1`|Go to line number 1.|
|`:w`|Write the file, save|
|`:q`|Quit|
|`:q!`|Quit without saving|
|`:wq`|Write and quit|
* This [cheatsheet](https://vimsheet.com/) is an excellent resource for further unlocking the power of `Vim`.