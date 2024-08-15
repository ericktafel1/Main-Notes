Based on my experience:
1. ENUMERATE (e.g. nmap, navigate to any webapps, OSINT, BloodHound, PowerView, etc...)
2. Start mitm6 OR Responder
3. Crack hash/pass attacks(crackmapexec) to gain a shell. **RESPRAY hashes & passwords with CME**
	1. secretsdump
	2. Continuously enumerate user accounts for pivoting/lateral movement
4. Kerberoasting / Mimikatz (must run as admin) / Token Impersonation
	1. Dump NTDS.dit
	2. Golden Tickets
7. Try RDP if thats open
8. Go back to step 1 and repeat













from ChatGPT

### 1. Initial Access and Reconnaissance

#### LLMNR/NBT-NS Poisoning

- **Tools**: Responder, Inveigh
- **Description**: Poison LLMNR and NBT-NS requests to capture NTLMv2 hashes.
- **Execution**:
    - Run Responder to capture hashes.
    - Crack hashes offline using tools like Hashcat or John the Ripper.

#### Network Scanning

- **Tools**: Nmap, Netdiscover
- **Description**: Identify live hosts and open ports.
- **Execution**:
    - Use Nmap to scan the network (`nmap -sP <network_range>`).
    - Identify services running on live hosts (`nmap -sV <ip_address>`).

### 2. Credential Theft and Lateral Movement

#### SMB Relay

- **Tools**: Responder, NTLMRelayX
- **Description**: Relay captured SMB authentication attempts to other network services.
- **Execution**:
    - Set up Responder to capture NTLM hashes.
    - Use NTLMRelayX to relay the captured hashes (`ntlmrelayx.py -tf targets.txt -smb2support`).

#### IPv6 Attacks

- **Tools**: MITMf, Responder
- **Description**: Exploit IPv6 to capture credentials.
- **Execution**:
    - Enable IPv6 poisoning in Responder.
    - Capture and relay hashes using MITMf (`mitmf --arp --spoof --gateway <gateway_ip> --targets <target_ip>`).

#### Kerberoasting

- **Tools**: Rubeus, GetUserSPNs.py
- **Description**: Extract service account hashes from Kerberos tickets.
- **Execution**:
    - Use GetUserSPNs.py to list SPNs and extract TGS tickets (`GetUserSPNs.py -request`).
    - Crack the tickets offline using Hashcat (`hashcat -m 13100 <hash_file>`).

### 3. Persistence and Privilege Escalation

#### Pass-the-Hash

- **Tools**: Mimikatz, CrackMapExec
- **Description**: Use captured NTLM hashes to authenticate.
- **Execution**:
    - Extract hashes using Mimikatz (`mimikatz # sekurlsa::logonpasswords`).
    - Authenticate with CrackMapExec (`cme smb <ip> -u <user> -H <hash>`).

#### Pass-the-Pass

- **Tools**: Mimikatz
- **Description**: Use plaintext passwords to authenticate.
- **Execution**:
    - Use Mimikatz to pass plaintext passwords (`mimikatz # sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>`).

#### Token Impersonation

- **Tools**: Mimikatz
- **Description**: Impersonate tokens to escalate privileges.
- **Execution**:
    - Extract tokens using Mimikatz (`mimikatz # token::elevate`).

#### LNK File Attacks

- **Tools**: Social Engineering Toolkit (SET)
- **Description**: Create malicious LNK files to execute code.
- **Execution**:
    - Use SET to generate LNK payloads and distribute them.

### 4. Domain Dominance

#### GPP Attacks

- **Tools**: gpp-decrypt, PowerSploit
- **Description**: Decrypt passwords stored in Group Policy Preferences (GPP).
- **Execution**:
    - Extract and decrypt passwords using gpp-decrypt (`gpp-decrypt <cpassword>`).
    - Use PowerSploit to automate GPP password extraction.

#### Mimikatz for Credential Dumping

- **Tools**: Mimikatz
- **Description**: Extract plaintext passwords, hashes, and Kerberos tickets.
- **Execution**:
    - Run Mimikatz to dump credentials (`mimikatz # sekurlsa::logonpasswords`).

#### Pivoting

- **Tools**: ProxyChains, SSH Tunneling
- **Description**: Use compromised machines as a pivot to reach other network segments.
- **Execution**:
    - Set up SSH tunneling (`ssh -L <local_port>:<remote_ip>:<remote_port> <user>@<gateway_ip>`).
    - Configure ProxyChains to use the tunnel (`proxychains nmap -sT <target_ip>`).

### 5. Gaining Domain Controller Access

#### DCSync Attack

- **Tools**: Mimikatz
- **Description**: Simulate the behavior of a domain controller to extract credentials.
- **Execution**:
    - Use Mimikatz to perform a DCSync attack (`mimikatz # lsadump::dcsync /user:<username>`).

#### Golden Ticket Attack

- **Tools**: Mimikatz
- **Description**: Create a forged Kerberos ticket to gain persistent access.
- **Execution**:
    - Extract the KRBTGT hash using Mimikatz (`mimikatz # lsadump::lsa /inject /name:krbtgt`).
    - Create a Golden Ticket (`mimikatz # kerberos::golden /user:<user> /domain:<domain> /sid:<domain_sid> /krbtgt:<krbtgt_hash>`).

### Summary

1. **Initial Access**: LLMNR/NBT-NS Poisoning, Network Scanning
2. **Credential Theft and Lateral Movement**: SMB Relay, IPv6 Attacks, Kerberoasting
3. **Persistence and Privilege Escalation**: Pass-the-Hash, Pass-the-Pass, Token Impersonation, LNK File Attacks
4. **Domain Dominance**: GPP Attacks, Mimikatz for Credential Dumping, Pivoting
5. **Gaining Domain Controller Access**: DCSync Attack, Golden Ticket Attack

### Important Considerations

- **Stealth**: Use tools and techniques that minimize detection.
- **Logs and Forensics**: Be aware of logging and forensics to cover your tracks.
- **Rules of Engagement**: Always operate within the agreed-upon scope and rules of engagement for the penetration test.
