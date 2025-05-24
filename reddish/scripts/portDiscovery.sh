#!/bin/bash

function ctrl_c() {
    echo -e "\n[+] Saliendo...\n"
    exit 1
}

# ctrl + c
trap ctrl_c INT

hosts=("172.18.0.1" "172.19.0.1" "172.19.0.2" "172.19.0.3")

tput civis
for host in ${hosts[@]}; do
    echo -e "\n[+] Scanning ports on $host\n"
    for port in $(seq 1 10000); do
        timeout 1 bash -c "echo '' > /dev/tcp/$host/$port" 2> /dev/null && echo -e "\t[+] Port $port - OPEN" &
    done; wait
done
tput cnorm