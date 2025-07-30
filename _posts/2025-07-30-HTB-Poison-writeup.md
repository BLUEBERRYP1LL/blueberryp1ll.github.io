---
title: "HTB Poison"
date: 2025-07-30
tags:
  - HTB
  - Poison
---
About Poison

Poison is a fairly easy machine which focuses mainly on log poisoning and port forwarding/tunneling. The machine is running FreeBSD which presents a few challenges for novice users as many common binaries from other distros are not available.

**Initial Enumeration**

The scan revealed two open ports:
<img width="1494" height="711" alt="Снимок экрана 2025-07-30 160447" src="https://github.com/user-attachments/assets/2194d4d8-e46d-4538-80b3-37ed5bec3363" />

### 1. Finding Command Injection
   On the website, I found a "Script Tester" page.
<img width="1486" height="383" alt="Снимок экрана 2025-07-30 161001" src="https://github.com/user-attachments/assets/09c5bd58-f289-42d6-a0d0-89a429acf52c" />

I entered listfiles.php, the output looked like it was running the ls command in the background. The listfiles.php script found something interesting: pwdbackup.txt.
<img width="2135" height="400" alt="Снимок экрана 2025-07-30 161205" src="https://github.com/user-attachments/assets/583b78c6-b530-46bc-b300-0a77495f55c8" />

### 2. Using LFI to Read Files
Looking at the page's URL, I noticed it used a **file** parameter to show the output. I figured this might be vulnerable to (LFI). I tried using the LFI to read the pwdbackup.txt file I had just found, and it worked!
I could see the contents of the file, which was a long Base64 string and a message saying it had been encoded 13 times.
<img width="3225" height="552" alt="Снимок экрана 2025-07-30 161314" src="https://github.com/user-attachments/assets/0722d08b-24ad-4588-ada3-06785efc3a50" />

### 3. Decoding the Password
I needed to decode that string 13 times, so I wrote a quick Python script to handle it automatically.
<img width="1881" height="1556" alt="Снимок экрана 2025-07-30 161835" src="https://github.com/user-attachments/assets/cc440a34-5a2d-4eac-bafa-cd7ed7f70fa8" />
<img width="677" height="30" alt="Снимок экрана 2025-07-30 162139" src="https://github.com/user-attachments/assets/004bf5a7-3209-49b0-b602-317f480d036d" />

### 4. Getting a Shell

Now I had a password but no username. I used the LFI vulnerability again, this time to read /etc/passwd. In the file, I found the user charix.
<img width="1485" height="189" alt="Снимок экрана 2025-07-30 162332" src="https://github.com/user-attachments/assets/0ef30994-ee79-4db6-b290-5b338329223b" />

I tried to SSH with the username charix and the password I just decoded, and I was in! I immediately grabbed the user.txt flag.

<img width="510" height="87" alt="Снимок экрана 2025-07-30 162543" src="https://github.com/user-attachments/assets/ece58ae5-7edc-4681-bfc4-49a690d24acb" />

## Privilege Escalation
### 1. Finding the secret.zip
Once I had a shell, I started looking around in charix's home directory and found a file named secret.zip. This seemed important. To analyze it safely, I transferred the file over to my Kali machine using netcat.
When I tried to unzip the file, it asked for a password. On a hunch, I tried charix's SSH password, and it worked! Inside was a file just named secret. It wasn't clear what it was for yet, so I kept it in mind.
<img width="939" height="171" alt="Снимок экрана 2025-07-30 163456" src="https://github.com/user-attachments/assets/d70f0bf6-b8c9-43ef-b7d5-ece78525a361" />

### 2. Finding the VNC Service
To find my next step, I started enumerating the machine from the inside. I ran ps aux to check all the running processes and netstat -an to look for network connections.

I found a process called vmsvc running as root. The netstat output showed that this process was listening on VNC ports (5801, 5901), but only locally on the machine.
<img width="1137" height="345" alt="Снимок экрана 2025-07-30 164203" src="https://github.com/user-attachments/assets/4743ec9f-b394-49d5-9d72-84417c45de2e" />
### 3. Port Forwarding with SSH
Since the VNC port was only open locally on the target, I needed to forward it to my own machine to access it. I used SSH local port forwarding to do this.

<img width="672" height="23" alt="Снимок экрана 2025-07-30 164736" src="https://github.com/user-attachments/assets/4893070f-67c8-4fa7-ace8-9a1b2870992f" />

This command forwards any connection I make to port 5901 on my machine over to port 5901 on the target's localhost.

### 4. Getting Root!

With the tunnel set up, I tried to connect with vncviewer. I remembered the secret file from the zip archive and thought it might be a password. I checked the help menu for vncviewer -h and saw a -passwd flag that lets you use a file for the password.

I put two and two together and ran vncviewer with the secret file and It worked perfectly! I got a VNC session running as root, and from there, I grabbed the final flag.

<img width="2031" height="468" alt="Снимок экрана 2025-07-30 165212" src="https://github.com/user-attachments/assets/f777742c-8286-47e4-b1ae-48d2fe16bc1c" />


