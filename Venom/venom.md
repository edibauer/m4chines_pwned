### Hack The Box Writeup: Venom

## Overview

- **Machine Name**: Venom
- **Difficulty**: Easy
- **Platform**: Vulnhub
- **Operating System**: Linux
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
ping -c 1 192.168.1.10
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 192.168.1.10 -oG allPorts
nmap -sCV -p21,80,139,443,445

openssl s_client -connect 192.168.1.10 # vire certificats to check if vhost exists
```
```html
      </div>
    </div>
    <div class="validator">
    </div>
  </body>
</html>
<!...<5f2a66f947fa5690c26506f66bde5c23> follow this to get access on somewhere.....-->
```
```bash
hash-identifier
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 5f2a66f947fa5690c26506f66bde5c23

Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

crackstation.net

smbmap -H 192.168.1.10

rpcclient -U "" 192.168.1.10 -N

# ans
rpcclient $> srvinfo
	VENOM          Wk Sv PrQ Unx NT SNT venom server (Samba, Ubuntu)
	platform_id     :	500
	os version      :	6.1
	server type     :	0x809a03


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