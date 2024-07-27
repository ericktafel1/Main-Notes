#msfconsole #cPassword #gpp-decrypt
Older attack, wont be doing in home lab... so I assume not needed for exam but good to know in older AD environments

Overview:
- Group Policy Preference (GPP) allowed Admins to create policies using embedded credentials.
- These credentials were encrypted and placed in a "cPassword"
- The key for cPassword was accidently released
- Patched in MS14-025, but it doesn't prevent previous users
- STILL RELEVENT ON PENTESTS

Kali Tool to decrypt a cPassword hash
`gpp-decrypt <hash>`

MSFConsole to gain a shell
`auxiliary/scanner/smb/smb_enum_gpp`


Mitigation Strategies
- PATCH! Fixed in KB2962486
- In reality: delete the old GPP xml files stored in the SYSVOL
