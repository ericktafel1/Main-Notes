#printer #MFP #LDAP #SMTP





May not be necessary for exam since cant replicate in the lab...

Basically in printer login web GUI, change the LDAP IP to your attacker IP address and setup a listener (nc / responder/ msf). The password will get sent in clear text.






A Pen Tester’s Guide to Printer Hacking - [https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack/](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack/)

## A Pen Tester's Guide to Printer Hacking

### What is an MFP and MFP Hacking anyway?

**Multi-Function Peripherals (MFPs)** are an underutilized target in the realm of pen testing. When compared against other high-value targets, MFP hacking appears to be the low man on the totem pole. Penetration testers frequently attack other targets like web applications, file servers, and domain controllers. Too often, the thought is: Why waste your time on printers when you can attack things like systems potentially resulting in:

-   Credential Disclosure
-   File System Access
-   Memory Access

However, as illustrated [by a recent and surprisingly interesting printer penetration test engagement](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856), it turns out that a successful MFP breach can result in discovering all of the above findings, plus more. The best part is that MFP security and maintenance is often forgotten, potentially resulting in a quick win for someone looking to gain entry or escalate their privileges in a compromised network.

MFPs are the clunky pile of plastic typically located in your corporate closet. They’re equipped with network ports, USB drives, and an iPad looking control panel with its own set of specialized applications. These intelligent devices are capable of much more than the standard copy, print, and fax. Don’t forget the occasional paper jam too.

These industrial ink bleeders are loaded with plenty of functionality, like the ability to integrate with the corporate network to allow for convenient scan/email. This functionality necessitates:

-   Lightweight Directory Access Protocols (LDAP) integration
-   Simple Mail Transfer Protocol (SMTP) integration
-   Network Shares

What kind of information is at risk with an MFP? How can you, as a penetration tester, successfully hack into an MFP? 

### **Did You Say LDAP?**

MFP-LDAP integration can be a control mechanism to prevent unauthorized users from printing, copying, scanning, etc. It can also be used for email address lookups when leveraging the scan/copy to email functionality, as well as giving authenticated users access to their home folder located on the network. 

Most MFP vendors (HP, Xerox, Ricoh, Canon, etc.) have their version of an LDAP implementation for their specific MFP, but they are generally the same concept. If you input a few attributes here, an IP address there, add a username/password, then you sit back and watch the “magic” happen.

### **Why MFP Hacking Matters**

For the MFP to conduct queries on the LDAP server, the MFP must be configured with the appropriate credentials to access the LDAP server, or set with the ability to pass user credentials to the LDAP server. These credentials should be stored somewhere on the MFP and, if we can capture these credentials, then we may have an entryway into the network, and possibly more. 

### **Introducing the Pass-Back Attack**

The stored LDAP credentials are usually located on the network settings tab in the online configuration of the MFP and can typically be accessed via the Embedded Web Service (EWS). If you can reach the EWS and modify the LDAP server field by replacing the legitimate LDAP server with your malicious LDAP server, then the next time an LDAP query is conducted from the MFP, it will attempt to authenticate to your LDAP server using the configured credentials or the user-supplied credentials. 

### **Accessing the EWS**

Most MFPs ship with a set of default administrative credentials to access the EWS. These credentials are usually located in the Administrator Guide of the MFP in question and are a good place to start for initial access:

VendorUsernamePasswordRicohadminblankHPadminadmin or blankCanonADMINcanonEpsonEPSONWEBadmin

Another way to potentially access the EWS is through the Printer Exploitation Toolkit (PRET) and Praeda. Both tools are capable of Information Disclosure and Code Execution. If you are looking to utilize the tools for the first time, here are a few resources to help you get started:

-   • [https://github.com/RUB-NDS/PRET](https://github.com/RUB-NDS/PRET) 
-   • [https://github.com/percx/Praeda](https://github.com/percx/Praeda) 
-   • [http://www.hacking-printers.net/wiki/index.php/Printer\_Security\_Testing\_Cheat\_Sheet](https://www.hacking-printers.net/wiki/index.php/Printer_Security_Testing_Cheat_Sheet) 

### **Replace LDAP Attributes**

Once you are authenticated to the EWS, locate the LDAP settings. During our test on an HP Color LaserJet MFP M477fdn, these settings were in the access control portion of the networking tab.

![HP Color LaserJet MFP ScreenCap](https://cdn.prod.website-files.com/601959b8cde20c101809c86a/63702b148fa46855262734d6_HP-Color-LaserJet-MFP-Screencap.webp)

Next, we removed the existing LDAP Server Address, 192.168.1.100, and replaced it with our IP Address. Next, we saved the settings. Then, we created a Netcat listener on port 389, which was the existing port in the LDAP settings of the MFP. 

### **Capture Credentials**

The configuration of this MFP requires users to authenticate before using the available resources like the scan-to-email ability. The next time an unsuspecting user inputs their credentials at the control panel, the MFP will send their information to the LDAP server under our control. 

![](https://cdn.prod.website-files.com/601959b8cde20c101809c86a/63702b8ba81428188b9600ad_Command-line-LDAP-server-under-our-control.webp)

If the MFP supports and is configured to store LDAP credentials for email lookup (the model we tested did not), then these credentials can also be passed back to the LDAP server under our control.

### **Attacking SMTP and Windows Sign-in**

This attack can also be conducted against other settings on the MFP that support authentication. Like LDAP, the Windows sign-in can be an alternative method to control access to the MFP resources. We substitute the existing domain with our own domain, and the next time a domain user signs in at the control panel, the credentials are sent to our domain controller.

![HP Color Laser Login Hacked](https://cdn.prod.website-files.com/601959b8cde20c101809c86a/63702be62c89f77c67a24c44_HP-Color-LaserJet-MFP-M477fdn-signin.webp)

Conducting attacks on the SMTP configuration can also produce fruitful results. The existing SMTP configuration for this MFP has stored credentials for SMTP authentication that can be passed back to us, after replacing the existing SMTP server with our own SMTP server.

![replacing the existing SMTP server with our own SMTP server](https://cdn.prod.website-files.com/601959b8cde20c101809c86a/63702c4c0ce0bd335333b3d5_replacing-existing-SMTP-server-with-our-own-SMTP-server.webp)

### **Big Payout with Low Risk**

MFPs do not get the attention they deserve when it comes to security. They are usually physically accessible, poorly managed, and shipped with default credentials. All of this, coupled with their payout potential, should make them a prime target for your next engagement.

