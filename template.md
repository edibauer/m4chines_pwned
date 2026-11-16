# 🖥️ Walkthrough Template - VulnHub Machine

## 📋 Información de la Máquina

| Campo | Detalle |
|-------|---------|
| **Nombre** | `Nombre de la máquina` |
| **Plataforma** | VulnHub |
| **Dificultad** | `Fácil / Media / Difícil` |
| **Sistema Operativo** | `Linux / Windows` |
| **Fecha de resolución** | `YYYY-MM-DD` |
| **Autor** | `Tu nombre / handle` |

---

## 🎯 Objetivo

> Breve descripción del objetivo de la máquina: obtener flags, root, usuario, etc.

**Flags objetivo:**
- [ ] `user.txt`
- [ ] `root.txt`

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
```

**IP objetivo:** `192.168.X.X`

---

### 2. Escaneo de puertos

```bash
# Escaneo rápido de todos los puertos
nmap -p- --min-rate 5000 -T4 192.168.X.X -oN allPorts

# Escaneo detallado de puertos abiertos
nmap -sC -sV -p<puertos_abiertos> 192.168.X.X -oN targeted
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
# Tecnologías
whatweb http://192.168.X.X

# Directorios
gobuster dir -u http://192.168.X.X -w /usr/share/wordlists/dirb/common.txt -t 50

# Nikto
nikto -h http://192.168.X.X
```

**Hallazgos:**
- 
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

> Descripción del vector identificado (CVE, credenciales débiles, LFI, etc.)

```bash
# Comando / script de explotación
```

**Resultado:**
- 

---

## 🔑 Acceso inicial (User)

### Obtención de shell

```bash
# Comando utilizado
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

> **Flag:** `XXXXXXXXXXXXXXXXXXXX`

---

## ⬆️ Escalada de Privilegios

### Enumeración

```bash
# Info del sistema
uname -a
cat /etc/os-release
id
sudo -l

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
- 
- 

---

### Escalada

> Descripción del vector de escalada (SUID, sudo, cron, kernel, etc.)

```bash
# Comandos utilizados
```

**Root obtenido:** ✅

### Flag de root

```bash
cat /root/root.txt
```

> **Flag:** `XXXXXXXXXXXXXXXXXXXX`

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

> ✍️ *Walkthrough realizado por [Tu Nombre] - [Fecha]*