### Hack The Box Writeup: Support

## Overview

- **Machine Name**: Support
- **Difficulty**:Easy
- **Platform**: Hack The Box
- **Operating System**: Windows
- **Key Objectives**: 
- **Date Solved**: JUne 2025

## Tools Used

- **Enumeration**: \[e.g., Nmap, Gobuster\]
- **Exploitation**: \[e.g., Metasploit, Custom Python scripts\]
- **Privilege Escalation**: \[e.g., LinPEAS, Windows Exploit Suggester\]
- **Other**: \[e.g., Burp Suite, Wireshark\]

## Methodology

### Initial Enumeration

```bash
# ping machine
ping -c 1 10.10.11.174

# nmap
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.11.174 -oG allPorts
nmap -sCV -p53,139,135,445,464,49741,49664,636,49686,49667,3268,3269,593,49699,9389,389,88,49674,5985 10.10.11.174 -oN targeted

# 445 port is to SMB client
smbclient -L 10.10.11.174 -N

# ans
	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	support-tools   Disk      support staff tools
	SYSVOL          Disk      Logon server share 

# WE need to view file privileges
smbmap -H 10.10.11.174 -u none

# ans
[+] Guest session   	IP: 10.10.11.174:445	Name: 10.10.11.174                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	support-tools                                     	READ ONLY	support staff tools
	SYSVOL 


```

\[Explain findings, e.g., open ports, services, versions.\]

### Exploitation

\[Detail the exploitation process, including vulnerabilities targeted and how you exploited them.\]

```bash
# Example: Exploiting Samba with Metasploit
msfconsole
use exploit/multi/samba/usermap_script
set RHOSTS [machine_ip]
run
```

\[Describe the outcome, e.g., initial shell access, user-level credentials.\]

### Privilege Escalation

\[Explain how you escalated privileges to root/admin. Include any misconfigurations or exploits used.\]

```bash
# Example: Checking for SUID binaries
find / -perm -4000 2>/dev/null
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