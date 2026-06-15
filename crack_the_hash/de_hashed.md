# Crack a pass
```
hashid 48bb6e862e54f2a795ffc4e541caed4d
hash-identifier 48bb6e862e54f2a795ffc4e541caed4d

# USING HASHCAT
1. We save the file (ex. hash.txt)
2. Execute the following command:
$ hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# ans
Dictionary cache building /usr/share/wordlists/rockyou.txt: 33553434 Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

48bb6e862e54f2a795ffc4e541caed4d:easy  

# USING JONH
$ john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
$ john --show --format=Raw-MD5 hash.txt

# ans
?:easy

## EXAMPLE 2
CBFDAC6008F9CAB4083784CBD1874F76618D2A97 = sha-1

hashcat -m 100 hash_2.txt /usr/share/wordlists/rockyou.txt
# ans
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

cbfdac6008f9cab4083784cbd1874f76618d2a97:password123

john --format=raw-sha1 hash_2.txt --wordlist=/usr/share/wordlists/rockyou.txt

# ans
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA1 [SHA1 256/256 AVX2 8x])
Warning: no OpenMP support for this hash type, consider --fork=8
Press 'q' or Ctrl-C to abort, almost any other key for status
password123      (?)     
1g 0:00:00:00 DONE (2026-06-01 22:38) 100.0g/s 138400p/s 138400c/s 138400C/s jesse..password123
Use the "--show --format=Raw-SHA1" options to display all of the cracked passwords reliably
Session completed

## EXAMPLE 3
1C8BFE8F801D79745C4631D09FFF36C82AA37FC4CCE4FC946683D7B336B63032 = sha-256

$ john --format=raw-sha256 hash_3.txt --wordlist=/usr/share/wordlists/rockyou.txt

# ans
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA256 [SHA256 256/256 AVX2 8x])
Warning: poor OpenMP scalability for this hash type, consider --fork=8
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
letmein          (?)     
1g 0:00:00:00 DONE (2026-06-01 22:41) 50.00g/s 6553Kp/s 6553Kc/s 6553KC/s 123456..kovacs
Use the "--show --format=Raw-SHA256" options to display all of the cracked passwords reliably
Session completed.

## EXAMPLE 4
$2y$12$Dwt1BZj6pcyc3Dy1FWZ5ieeUznr71EeNkJkUlypTsgbX1H68wsRom

Este hash tiene un formato muy diferente al anterior. El prefijo $2y$ indica que se trata de un hash bcrypt (específicamente la variante estándar actual en PHP).

$ hashcat -m 3200 hash_bcrypt.txt /usr/share/wordlists/rockyou.txt
$ john --format=bcrypt hash_bcrypt.txt --wordlist=/usr/share/wordlists/rockyou.txt

## EXAMPLE 5





```