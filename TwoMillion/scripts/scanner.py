from pwn import *
from termcolor import colored
from scapy.all import *

import signal
import sys
import time
import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
# logging.getLogger("cryptography").setLevel(logging.ERROR)

def def_handler(sig, frame):
    print(colored("\n\n[!] Aborting...\n", 'red'))
    p1.failure("Aborted scan (ctrl + s has been pressed)")
    sys.exit(1)

# ctrl_c
signal.signal(signal.SIGINT, def_handler)

# Bar Progress
p1 = log.progress("TCP Scan")
p1.status("Scanning ports...")

# methods
def scan_port(ip, port):
    src_port = RandShort() # default port in threeway handshake

    try:
        response = sr1(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0)
        if response is None:
            return False
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            send(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R"), verbose=0)
            return True
        else:
            return False
    except Exception as e:
        log.failure(f"Error scanning {ip} on port: {e}")
        sys.exit(1)

def main(ip, ports, end_port):
    time.sleep(3) # to view bar progress msg
    for port in ports:
        p1.status(f"Scan Progress [{port}/{end_port}]")
        # print(port)
        response = scan_port(ip, port)
        if response:
            log.info(f"Port {port} - OPEN")
            
    p1.success("Finished Scan")

if __name__ == '__main__':
    # time.sleep(10) - testing
    if len(sys.argv) != 3:
        print(colored(f"\n[!] Uso: {colored('python3', 'blue')} {colored(sys.argv[0], 'green')} {colored('<ip> <ports-range>', 'yellow')}\n", 'red'))
        sys.exit(1)

    target_ip = sys.argv[1]
    port_range = sys.argv[2].split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])

    ports = range(start_port, end_port + 1)

    # function
    main(target_ip, ports, end_port)

