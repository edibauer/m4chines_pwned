# scripts
## portScan.sh
```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo...\n"
	tput cnorm; exit 1
}

trap ctrl_c INT

tput civis # ocultar cursor
for port in $(seq 1 65535);do

	timeout 1 bash -c "echo '' > /dev/tcp/10.10.0.11/${port}" 2>/dev/null && echo "[+] PORT ${port} - OPEN" &
done; wait

tput cnorm

```
# hostDiscovery.sh
```bash
#!/bin/bash

for i in $(seq 1 254); do
	timeout 1 bash -c "ping -c 1 10.10.0.${i}" &>/dev/null && echo "[+] HOST 10.10.0.${i} - ACTIVE" &	

done; wait

```