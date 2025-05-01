## init
```bash
<>
arp-scan -I wlo1 --localnet
ping -c 1 192.168.1.15

nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 192.168.1.15 -oG allPorts
nmap -sCV -p80 192.168.1.15 -oN targeted

nmap --script http-enum -p80 192.168.1.15 -oN webScan
whatweb http://192.168.1.15 

# ans
http://192.168.1.15 [200 OK] Apache[2.4.29], Bootstrap, Country[RESERVED][ZZ], Email[ex@abc.xyz], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[192.168.1.15], JQuery[3.2.1], Script, Title[Coming Soon 2]

gobuster dir -u http://192.168.1.15/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt

curl -s -X GET "http://192.168.1.15/users/" -I -L
# ans
HTTP/1.1 302 Found
Date: Fri, 25 Apr 2025 06:24:03 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=54upv3is81kcg5a6ulujnmdrk4; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: ../login/login.php
Content-Length: 767
Content-Type: text/html; charset=UTF-8

HTTP/1.1 200 OK
Date: Fri, 25 Apr 2025 06:24:03 GMT
Server: Apache/2.4.29 (Ubuntu)
Set-Cookie: PHPSESSID=rrbjpkntboiohmvlrrvu2uu3av; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 2323
Content-Type: text/html; charset=UTF-8

# WEn eed to do another scan to search files, not only dirs
gobuster dir -u http://192.168.1.14/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20 -x back,php.bak,zip,backup

7z l source_code.zip # list file content
drwxr-xr-x 1 root     root          44 Feb  1  2021 asset
-rw-r--r-- 1 root     root        2250 Feb  2  2021 db.sql
drwxr-xr-x 1 root     root          86 Feb  1  2021 include
-rw-r--r-- 1 root     root        3650 Feb  1  2021 index.php
drwxr-xr-x 1 root     root         170 Feb  1  2021 item
drwxr-xr-x 1 root     root         196 Feb  1  2021 login
drwxr-xr-x 1 root     root          54 Feb  1  2021 profile
-rw-r--r-- 1 root     root          33 Feb  2  2021 robots.txt
-rw-r--r-- 1 edibauer edibauer 5275298 Apr 25 16:09 source_code.zip
drwxr-xr-x 1 root     root         108 Feb  1  2021 users




```