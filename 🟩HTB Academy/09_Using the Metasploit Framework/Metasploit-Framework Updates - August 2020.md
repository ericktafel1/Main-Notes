#msfconsole 
___

Updating to MSF6 will render all previous payload sessions unusable if they were established using MSF5. Moreover, payloads generated using MSF5 will not work with MSF6 communication mechanisms. We have summarized the changes and additions that the August 2020 MSFconsole updates brought below.

___

## Generation Features

-   End to end encryption across Meterpreter sessions for all five implementations (Windows, Python, Java, Mettle, and PHP)
    
-   SMBv3 client support to further enable modern exploitation workflows
    
-   New polymorphic payload generation routine for Windows shellcode that improves evasive capabilities against common antivirus and intrusion detection system (IDS) products
    

___

## Expanded Encryption

-   Increased complexity for creation of signature-based detections for certain network operations and Metasploit’s main payload binaries
    
-   All Meterpreter payloads will use AES encryption during communication between the attacker and the target system
    
-   SMBv3 encryption integration will increase complexity for signature-based detections used to identify key operations performed over SMB
    

___

## Cleaner Payload Artifacts

-   DLLs used by the Windows Meterpreter now resolve necessary functions by ordinal instead of name
    
-   The standard export ReflectiveLoader used by reflectively loadable DLLs is no longer present in the payload binaries as text data
    
-   Commands that Meterpreter exposes to the Framework are now encoded as integers instead of strings
    

___

## Plugins

The old Mimikatz Meterpreter extension was removed in favor of its successor, Kiwi. Therefore, attempts to load Mimikatz will load Kiwi for the foreseeable future.

___

## Payloads

Replaced the shellcode static generation routine with a randomization routine that adds polymorphic properties to this critical stub by shuffling instructions around each time. To read more about these changes and see the full changelog, please [follow this link](https://blog.rapid7.com/2020/08/06/metasploit-6-now-under-active-development/).

___

## Closing Thoughts

As we have seen in this module, Metasploit is a powerful framework. Though often misused and mislabeled, it can be an important part of our penetration testing arsenal when used correctly. It is highly extensible great for tracking data during an assessment, and excellent for post-exploitation and facilitating pivoting. It is worth experimenting with all of the features Metasploit has to offer; you may find a way that it fits nicely into your workflow. If you prefer to avoid it, that's fine too! There are plenty of tools out there, and we should work with what we are most comfortable with. To get more practice with this tool, check out the HTB boxes tagged at the end of this module, or attempt any box or Academy module target using Metasploit. You can also practice with it (especially its power for pivoting) in the Dante Pro Lab.