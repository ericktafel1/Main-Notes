#Windows #PrivEsc #ConfigFiles #base64 #xml 

## **Exploitation**

Windows VM

1. Open command prompt and type: `notepad C:\Windows\Panther\Unattend.xml`
2. Scroll down to the “`<Password>`” property and copy the base64 string that is confined between the “`<Value>`” tags underneath it.

Kali VM

1. In a terminal, type: `echo [copied base64] | base64 -d`
2. Notice the cleartext password