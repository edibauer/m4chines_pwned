# FUZZ
wfuzz -c -L -t 30 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.65.187.137/FUZZ
## vhost
wfuzz -c -t 30 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.dominio.com" http://IP_OBJETIVO

# GOBUSTER
gobuster dir -u http://************* -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://************* -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
gobuster dir -u http://10.65.187.137 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -s 200
gobuster dir -u http://10.65.187.137 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x txt,html,php

## vhost
gobuster vhost -u http://IP_OBJETIVO -w subdomains.txt

# Transfer files
python3 -m http.server 80
nc -lp 4444 > archivo_recibido.txt # victims machine
nc -w 3 [IP_VICTIMA] 4444 < archivo_a_enviar.txt # attackers machine


# Term treatment
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
bash
/bin/sh -i

script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash

# Compress Files
tar -czvf archivo.tar.gz archivo
tar -xzvf archivo.tar.gz




