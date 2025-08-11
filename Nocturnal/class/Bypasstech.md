The Vulnerable PHP Code:

```php
<?php
// ping.php - A very simple, but vulnerable, ping tool

// Simulate a very basic, flawed "cleanEntry" function
function cleanEntry($input) {
    // This hypothetical blacklist only removes basic command separators
    $input = str_replace(['&', '|', ';', ' '], '', $input); // Note: it removes spaces!
    return $input;
}

$target_ip = cleanEntry($_GET['ip']); // User input from URL parameter

// This is the vulnerable line: directly embedding user input into a shell command
// We'll assume the system shell is used to execute this string
$command = "ping -c 1 " . $target_ip;

// For demonstration, we'll just echo the command that WOULD be executed
// In a real scenario, this would be exec(), shell_exec(), system(), or proc_open()
echo "Simulating command execution:\n";
echo "Command to be executed: " . escapeshellarg($command) . "\n"; // escapeshellarg to show raw string
echo "-------------------------------------\n";

// In a real app:
// $output = shell_exec($command);
// echo "<pre>$output</pre>";

?>
```
The Attacker's Goal:

The attacker wants to run ls -la (list directory contents in long format) on the server, but the ping.php script only seems to let them ping. Plus, their cleanEntry function removes spaces!

### Bypass Technique 1: Using \n (Newline) for Command Splitting
#### The Concept:
A newline character (\n or \r\n) tells the shell that one command has ended and a new one is beginning. If the blacklist doesn't filter newlines, you can "inject" a new command right after the first one.

#### Attacker's Payload (URL-encoded for a GET request):

The attacker would visit a URL like this:
http://example.com/ping.php?ip=127.0.0.1%0als%20-la

127.0.0.1: The legitimate part of the ping command.

%0a: This is the URL-encoded form of \n (newline).

ls%20-la: This is ls -la (with %20 for the space, assuming it's not filtered by cleanEntry in this specific example for now).

How it "Looks" to the PHP Script (after cleanEntry is run):

Let's assume cleanEntry doesn't filter newlines, but does filter spaces. So, ls -la would become ls-la if it went through cleanEntry.

If cleanEntry only filters &, |, ; and not \n, the $target_ip variable would become:
127.0.0.1\nls -la (the \n is preserved)

How the $command string is built:
```php
$command = "ping -c 1 127.0.0.1\nls -la";
```
How the Shell Interprets It:

When this string is passed to the shell, it sees:

ping -c 1 127.0.0.1 (The original command, which executes)

ls -la (A new, entirely separate command, which also executes!)

The shell processes each command separated by the newline independently. The output of ls -la would then be returned by shell_exec() or logged, revealing the directory contents to the attacker.


### Bypass Technique 2: Using \t (Tab) as a Substitute for Space
The Concept:
Many shell commands require spaces between arguments (e.g., ls  -la). If the application's blacklist explicitly filters out standard space characters (     ) but not tab characters (\t), an attacker can use tabs as an alternative.

Attacker's Payload (URL-encoded for a GET request):

Let's use our ping.php example, but now assuming cleanEntry does filter standard spaces, but not tabs or newlines.

The attacker would visit a URL like this:
http://example.com/ping.php?ip=127.0.0.1%0als%09-la

127.0.0.1: The legitimate part.

%0a: Newline (as above, for command separation).

ls%09-la: This is ls\t-la (with %09 for the tab).

How it "Looks" to the PHP Script (after cleanEntry is run):

If cleanEntry filters spaces (     ) but not tabs (\t) or newlines (\n), the $target_ip variable would become:
127.0.0.1\nls\t-la

How the $command string is built:

$command = "ping -c 1 127.0.0.1\nls\t-la";
How the Shell Interprets It:

When this string is passed to the shell, it sees:

ping -c 1 127.0.0.1

ls -la (The shell treats the \t just like a space, effectively executing ls with the -la argument).

Why Both are Often Combined:

Attackers often combine these techniques. The newline (\n) is essential for truly splitting the command string into two separate, independently executable commands. The tab (\t) is then used within the injected command to separate its arguments, bypassing any blacklist that specifically targets spaces but not tabs.

This example illustrates how inadequate input sanitization, even with seemingly "minimal blacklists," can lead to severe security vulnerabilities. The fix is to use secure coding practices like prepared statements for database queries or, for shell commands, passing arguments as a proper array to functions like proc_open to prevent the shell from interpreting attacker-controlled input as code.