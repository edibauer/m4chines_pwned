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