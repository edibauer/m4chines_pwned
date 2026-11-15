### Endpoint fuzzing
```bash
ffuf -u http://staging.silentium.htb/api/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -mc 200,201,301,302,401,403,405

```
