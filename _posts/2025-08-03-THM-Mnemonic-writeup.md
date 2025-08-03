# Enumeration

I started with an Nmap scan and found three open ports: FTP (21), HTTP (80), and a non-standard SSH port on 1337. The Nmap results suggested it was an Ubuntu machine.
```bash
└─$ sudo nmap -sCV 10.10.240.19 -p- --min-rate=1000 -oN nmap_long
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-03 06:28 EDT
Nmap scan report for 10.10.240.19
Host is up (0.050s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/webmasters/*
|_http-title: Site doesn't have a title (text/html).
1337/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e0:42:c0:a5:7d:42:6f:00:22:f8:c7:54:aa:35:b9:dc (RSA)
|   256 23:eb:a9:9b:45:26:9c:a2:13:ab:c1:ce:07:2b:98:e0 (ECDSA)
|_  256 35:8f:cb:e2:0d:11:2c:0b:63:f2:bc:a0:34:f3:dc:49 (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

I checked FTP first, but anonymous login was disabled, so I moved on to the web server. The main page just had the word "test" on it.
<img width="1197" height="254" alt="2025-08-03 123230" src="https://github.com/user-attachments/assets/337833ab-2377-4e69-8a46-c35cdee52d9a" />

The robots.txt file had a disallowed entry for /webmasters/, so I started fuzzing that directory with ffuf. This revealed two subdirectories: /admin and /backups.

```bash
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.240.19/webmasters/FUZZ -c    

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.240.19/webmasters/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# Copyright 2007 James Fisher [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 53ms]
#    [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 54ms]
admin                   [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 49ms]
backups                 [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 59ms]

```

The /admin path led to a static login page where none of the functions worked. I turned my attention to the /backups directory. Running ffuf again on this directory with a different wordlist and found a backup.zip file.

## Getting a Foothold

1. Cracking the Backup

The backup.zip file was password protected. I used zip2john to extract the hash and then crack the hash with the rockyou.txt wordlist. After a few seconds I had the password.

<img width="3684" height="231" alt="2025-08-03 131136" src="https://github.com/user-attachments/assets/4f7e1596-25bb-4d55-8a4d-4d5626c1bf4c" />
<img width="2949" height="838" alt="2025-08-03 131305" src="https://github.com/user-attachments/assets/04ccafaa-a277-4fc0-8c1b-a9f644c41cfb" />

Inside the unzipped archive, a note.txt file mentioned a new FTP username: ftpuser.

```bash
┌──(kali㉿kali)-[~/…/thm/mnemonic/files/backups]
└─$ cat note.txt 
@vill

James new ftp username: ftpuser
we have to work hard
```

2. From Backup to FTP Access

The note didn't include a password, so I figured I had to brute-force it. I used Hydra with the rockyou.txt wordlist against the ftpuser account, and after a few minutes, it successfully found the password.
<img width="3009" height="362" alt="2025-08-03 132545" src="https://github.com/user-attachments/assets/2893815c-a890-4b29-9224-4cdb84139baf" />


3. From FTP to a Protected SSH Key

I logged into the FTP server as ftpuser and found two files: another not.txt file and an SSH private key (id_rsa).
<img width="969" height="180" alt="2025-08-03 133153" src="https://github.com/user-attachments/assets/13a97c0c-f024-440c-b0ea-b503070e145f" />

The note was a reminder for a user named "james" to change the FTP password. This gave me my next target username. I changed the permissions on the id_rsa file and tried to log in as james, but the key was protected with a passphrase.
```bash
└─$ cat not.txt 
james change ftp user password
```
<img width="1038" height="174" alt="2025-08-03 133611" src="https://github.com/user-attachments/assets/23c3b0ad-a75b-4ca5-9aa5-60619f8c030b" />

4. Cracking the SSH Key & Getting a Shell

Just like with the zip file, I used ssh2john to get the keys hash and john to crack the passphrase. It cracked almost instantly.
```bash
└─$ john ssh.john -w=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
<CRACKED_PASSWORD>        (id_rsa)     
1g 0:00:00:00 DONE (2025-08-03 07:39) 50.00g/s 1396Kp/s 1396Kc/s 1396KC/s canary..baller15
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
I tried to log in again with the key and the newly found passphrase, but I was still asked for a password. Luckily I tried using the passphrase as the password itself and it worked!
<img width="1550" height="1271" alt="2025-08-03 134319" src="https://github.com/user-attachments/assets/8bee2ebf-cfe7-4d76-b4df-0f78454ef131" />

As soon as I logged in, a warning message popped up saying an IPS had detected me and my shell would be closed in about two minutes. I also quickly realized I was in a restricted bash shell (rbash), which meant many commands like cd were disabled.
<img width="1127" height="723" alt="2025-08-03 134450" src="https://github.com/user-attachments/assets/57e7aa15-3b0a-4a17-886b-557da1e5176d" />

I had to act fast. In my short sessions, I managed to grab two files: 6450.txt (which contained a long list of numbers) and noteforjames.txt. The second note was important—it mentioned a new "Mnemonic" encryption.
```
james@mnemonic:~$ cat 6450.txt
5140656
354528
842004
1617534
465318
1617534
509634
1152216
753372
265896
265896
15355494
24617538
3567438
15355494
james@mnemonic:~$ cat noteforjames.txt
noteforjames.txt

@vill

james i found a new encryption İmage based name is Mnemonic  

I created the condor password. don't forget the beers on saturday

```
I was stuck at this point for a while. Since I couldn't cd, I used ls -la /home to see what I could access. I found I could read the /home/condor directory. Listing its contents revealed two files, it was obvious they were base64 encoded.


```bash
james@mnemonic:~$ ls -la /home/condor/
...
'/home/condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==': Permission denied
total 0
d????????? ? ? ? ?            ?  .
d????????? ? ? ? ?            ?  ..
d????????? ? ? ? ?            ? 'aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw=='
l????????? ? ? ? ?            ?  .bash_history
-????????? ? ? ? ?            ?  .bash_logout
-????????? ? ? ? ?            ?  .bashrc
d????????? ? ? ? ?            ?  .cache
d????????? ? ? ? ?            ?  .gnupg
-????????? ? ? ? ?            ?  .profile
d????????? ? ? ? ?            ? ''\''VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='\'''
```

I decoded them with base64 on my local machine. One was a URL to an image, and the other was the user flag!

## Pivoting to condor
Opening the URL i see a picture.
<img width="2730" height="1592" alt="2025-08-03 143707" src="https://github.com/user-attachments/assets/deee4c7d-aae1-40d9-b6fe-645a651604e4" />

I downloaded the image from the URL, but steghide and exiftool found nothing hidden in it. I remembered the note mentioning "Mnemonic encryption" and the 6450.txt file full of numbers. I searched online and found a GitHub repository for a Mnemonic-based encryption tool that uses an image and a list of numbers.
<img width="1366" height="1164" alt="2025-08-03 144055" src="https://github.com/user-attachments/assets/8f4cb8e1-daaf-46bd-86d8-7718ff6d3c4d" />

This looked promising. I used the script from the repository, providing the numbers from 6450.txt and the image as inputs. The script successfully decrypted the password for the user condor.
<img width="3746" height="1375" alt="2025-08-03 151916" src="https://github.com/user-attachments/assets/6093e924-06db-467c-8cdd-5c4b54d21928" />

## Privilege Escalation to Root

I logged in as condor and checked my privileges with sudo -l. It showed that I could run /bin/examplecode.py as root.

<img width="1995" height="231" alt="2025-08-03 152214" src="https://github.com/user-attachments/assets/53937984-6358-43cb-8c6b-1afb8e329211" />

I inspected the Python script and found a obvious vulnerability.
<img width="1238" height="261" alt="2025-08-03 153248" src="https://github.com/user-attachments/assets/d704fb53-e723-4f42-b168-149574136dd5" />
by entering a single period (.) instead of an expected confirmation input like yes or y, it is possible to execute arbitrary commands with root privileges.
So i will just type bash after . and get root shell.
<img width="797" height="362" alt="2025-08-03 153747" src="https://github.com/user-attachments/assets/ef4ddf7b-f99a-4bd5-8a53-7f6fb0be47c5" />

From there, I had a root shell. I grabbed the final flag, which needed to be MD5-hashed to be accepted and the machine was done.
