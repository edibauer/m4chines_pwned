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
main_url = "http://nocturnal.htb/view.php?username=test&file=test.pdf"
cookie_value = sys.argv[1]

def makeRequest():
    
    cookies = {
        'PHPSESSID': cookie_value
    }

    r = requests.get(main_url, cookies=cookies)
    print(r.headers)
    print(r.status_code)
    print(r.text)



if __name__ == '__main__':
    makeRequest()