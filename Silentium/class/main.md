### vhost fuzzing and web enumeration
- We create a local lab
```bash
# docker-compose.yml

services:
  web:
    image: nginx:latest
    ports:
      - "1337:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf
      - ./public_html:/usr/share/nginx/html
      - ./secret_html:/usr/share/nginx/secret

# nginx.conf
# Sitio público (por defecto)
server {
    listen 80;
    server_name empresa.local;
    root /usr/share/nginx/html;
    index index.html;
}

# Sitio oculto (VHost secreto realista)
server {
    listen 80;
    server_name staging.empresa.local;
    root /usr/share/nginx/secret;
    index index.html;
}

# public_html/index.html
<h1>Bienvenido al sitio público de Empresa Local</h1>

# secret_html/index.html
<h1>🚩 FLAG{VHost_Discovery_Success}</h1><p>Panel de Administración Interno</p>

# secret_html/config.php.bak
DB_PASSWORD=SuperSecret123

docker-compose up -d # create contanier

```

### Manual enum
```bash
curl http://127.0.0.1:8080 # normal access
curl -H "Host: admin-secreto.empresa.local" http://127.0.0.1:8080 # host injection


```

### Fuzzing
- ffuf: Tú controlas exactamente dónde va la palabra FUZZ en la cabecera Host. Puedes usar una IP directamente.
- gobuster vhost: Toma el dominio de la URL que le pasas con -u y automáticamente le antepone cada palabra del diccionario. No funciona con IPs, necesita un nombre de dominio.

```bash
### vhost
# ffuf
ffuf -u http://127.0.0.1:1337 \
-H "Host: FUZZ.empresa.local" \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
-mc 200,301,302,403 \
-c \
-fs 55

# gobuster
gobuster vhost \
-u http://empresa.local:1337 \
-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
--append-domain \
-t 50

### file searching
# ffuf
ffuf -u http://staging.empresa.local:1337/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403 -e .php,.bak,.txt

# gobuster
gobuster dir \
-u http://staging.empresa.local:1337 \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-x txt,bak,php,conf,old \
-t 50

```