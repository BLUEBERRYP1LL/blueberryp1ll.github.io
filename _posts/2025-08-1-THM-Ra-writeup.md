---
title: "THM Ra Writeup"
date: 2025-08-1
tags:
  - THM
  - Ra
---
# My Walkthrough for 'Ra' Machine
In this writeup, I've tried to document almost every step I took including my dead ends and thought process, to give a full picture of how I approach the process. Towards the end, I became more focused on solving the machine itself, so the documentation for the final stages might be more direct

# Enumeration

The initial scan revealed a huge number of open ports, immediately suggesting this was a Domain Controller, which was confirmed by the Kerberos service on port 88.

I noted several non-standard ports, including a SOCKS5 proxy on 7777 and an Apache web server on 9090. There were also a few Jetty and Apache Hadoop ports, so I knew I had a lot to investigate.
<img width="1722" height="1442" alt="2025-08-01 151704" src="https://github.com/user-attachments/assets/65f8375a-201f-47e3-b76a-a1004c190030" />


My first step was to add the domains found in the Nmap scan, windcorp.thm and fire.windcorp.thm, to my /etc/hosts file. I checked for anonymous SMB access but the guest account was disabled.
<img width="704" height="78" alt="2025-08-01 152038" src="https://github.com/user-attachments/assets/3ceca742-ddec-420e-976d-fc1bb76915d6" />


On the website I found a page listing IT employees, hovering over the images revealed their usernames in the URL. I used a quick curl and grep command to automatically extract all the usernames and save them to a file.
<img width="1124" height="1249" alt="2025-08-01 152434" src="https://github.com/user-attachments/assets/df1fe0b7-0629-4246-a96a-960524336efc" />
<img width="1536" height="669" alt="2025-08-01 152720" src="https://github.com/user-attachments/assets/5f4f693f-ec87-478b-8689-483dc197e8ea" />


I run kerbrute to confirm which usernames were valid. 13 of the 15 were real accounts. I tried a password spray, but I quickly realized that brute-force protection was active and locking accounts, so I needed a different approach.


## Initial Foothold: The Password Reset Bypass

The website had an interesting password reset function. 
<img width="1605" height="531" alt="2025-08-01 153935" src="https://github.com/user-attachments/assets/fcfcae8d-0407-4383-a1c4-45ae8b2a2431" />

I sent the request to Burp Suite to see how it worked in the background. It used security questions, and my first thought was to bruteforce the answers.
<img width="945" height="516" alt="2025-08-01 154117" src="https://github.com/user-attachments/assets/e884ba1b-e77e-4e2d-9f50-db484754162c" />

I created wordlists for common "first car" brands and other questions and tried to use Hydra to bruteforce the secret, but this didn't work.

After getting stuck for a while, I went back to the employee page and took a closer look.
<img width="2181" height="719" alt="2025-08-01 163710" src="https://github.com/user-attachments/assets/4dc64bf5-64f4-4067-9689-abb32fdbabbc" />

opening the image of Lily Levesque i could see her username as well as her dog name, i was pretty confindent this is how i can reset password.
<img width="2127" height="1437" alt="Снимок экрана 2025-08-01 163755" src="https://github.com/user-attachments/assets/e500b99b-a440-4df0-839e-16f5276bf25f" />


so I tried it, and it worked! I successfully reset the password for the user lilyle.
<img width="1599" height="475" alt="2025-08-01 163947" src="https://github.com/user-attachments/assets/8a54c2ec-abe7-4615-b6a2-a96ab43d8c60" />


With lilyle's new credentials, I could now enumerate SMB shares. I found two non-standard shares, "shared" and "Users". The "shared" directory had the first flag and an installer for the Spark chat client.
<img width="1203" height="318" alt="2025-08-01 184353" src="https://github.com/user-attachments/assets/5ef26605-443a-45cc-a8c9-a4112e6491b1" />

## Pivoting to User buse: The Spark Exploit

I grabbed the first flag and started searching for exploits of the Spark version 2.8.3. I found a known remote code execution vulnerability, CVE-2020-12772, which basically says that an attacker can send a chat message containing immage and if that image points to an external server, spark may try to load it and after it sends the user's Windows NTLM hash.
There is a POC at https://github.com/theart42/cves/tree/master, so all i did was reproduces the steps and got an NTLM hash for user buse which i successfully cracked using hashcat.

I took the hash over to hashcat and cracked it with the rockyou.txt wordlist.

<img width="3771" height="1287" alt="2025-08-01 200428" src="https://github.com/user-attachments/assets/d2596df5-455f-4f6c-a99c-c5415027cbe8" />

With these new credentials, I could log in as buse using evil-winrm and grab the second flag.

<img width="2276" height="151" alt="2025-08-01 200628" src="https://github.com/user-attachments/assets/24b8dbb0-ac49-4ddd-a94a-d6f4fcdf9d1a" />
<img width="840" height="48" alt="2025-08-01 200949" src="https://github.com/user-attachments/assets/12417087-d6cb-4296-9a9e-d8438eb79e06" />


## Privilege Escalation to Root

Now inside as buse, I started enumerating my privileges. Running whoami /groups showed that I was a member of the Account Operators group. This is a highly privileged group which allows us manage other users and reset passwords for non protected users, this is useful, but not for now, i will note it.
<img width="2246" height="1140" alt="2025-08-01 201840" src="https://github.com/user-attachments/assets/8c02978d-666b-41ab-9056-17783f40494c" />

In C:\scripts, I found a PowerShell script, this script basically sends email alert to britannycr if the host is down, since it reads a hosts file from brittany and runs as administrator, i can replace that hosts file with a malicious one.
<img width="1587" height="1422" alt="2025-08-01 202604" src="https://github.com/user-attachments/assets/9a45f026-b053-4d70-a3f1-0959df42d23b" />


So my plan was:

    Use my "Account Operators" permissions to reset brittanycr password.

    Access brittanycr home directory and replace the hosts.txt file with a malicious payload.

    Wait for the scheduled script to run as Administrator and execute my payload.

First, I reseted brittanycr's password with net user, which im allowed to since im in the earlier mentionted Account Operators group.
<img width="920" height="96" alt="2025-08-01 202747" src="https://github.com/user-attachments/assets/e33c7967-976f-4d25-9346-72f2fc69aec5" />


I tried logging in as brittanycr with evil-winrm, but it did not work, probably because she isn't in the "Remote Management Users" group. But this is not a problem, since i can still access her files over SMB.
<img width="2238" height="255" alt="2025-08-01 202953" src="https://github.com/user-attachments/assets/b5273ee1-83dd-456a-8155-77af18b0dcff" />


I created a malicious hosts.txt file. My first few attempts to change the main Administrator's password or add my owned user "buse" to the administrators group didn't work, for unknown to me reasons. So, I changed my payload to create a new user ("blueberryp1ll") and add that new user to the "Administrators" group.

<img width="1301" height="31" alt="2025-08-01 212542" src="https://github.com/user-attachments/assets/14695df1-a98f-45dd-a0ca-c1734b4b1521" />

I used smbclient to connect to brittanycr's user share and replace the original hosts.txt with my malicious version.
<img width="1113" height="48" alt="2025-08-01 203456" src="https://github.com/user-attachments/assets/da1a76ae-39dd-49b3-acc5-d7c78da36009" />


After waiting a little, my new user was created. I logged in with evil-winrm as my new created account and had full administrator access to the machine. Grabbed the root flag and had fully compromised the Domain Controller.
<img width="2276" height="133" alt="2025-08-01 205358" src="https://github.com/user-attachments/assets/e4fb7689-742e-4584-bb09-b2e8834e6aa2" />

<img width="1406" height="339" alt="2025-08-01 205455" src="https://github.com/user-attachments/assets/11096880-d6ea-41b4-924d-ac2107e2da8a" />

<img width="957" height="58" alt="2025-08-01 205603" src="https://github.com/user-attachments/assets/6468fd19-a27f-46d6-bca9-a8176b8886f6" />

