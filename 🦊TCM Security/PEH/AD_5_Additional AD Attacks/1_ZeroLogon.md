#ZeroLogon  

What is ZeroLogon? - [https://www.trendmicro.com/en_us/what-is/zerologon.html](https://www.trendmicro.com/en_us/what-is/zerologon.html)
dirkjanm CVE-2020-1472 - [https://github.com/dirkjanm/CVE-2020-1472](https://github.com/dirkjanm/CVE-2020-1472)
SecuraBV ZeroLogon Checker - [https://github.com/SecuraBV/CVE-2020-1472](https://github.com/SecuraBV/CVE-2020-1472)

- attacks domain controller, sets password to null, take over domain controller. (restore password otherwise DC will break)
- can run `ZeroLogon_Check.py`​ to confirm DC is vulnerable.`RestorePassword.py` can revert the exploit, need the plain_password_text from `secretsdump.py`​ results using the Administrator's hash.