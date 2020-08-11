# LiteWAF

**LiteWAF** is a simple in-app Web Application Firewall. It is a single `php` script that must be included at the beginning of each page you want to protect.
For each request, the script parses the parameters looking for well known attacks.

Actually the script supports the following attack types:
*  XSS
*  SQL Injection
*  Path Traversal
*  Remote Command Execution

When an attack attempt is detected the script logs the event into `attacklogs.php` file and then redirects the user to a default page.

The `attacklogs.php` script contains the logs, but it is authenticated. Thus means that you need to provide the right password to access the logs (url: `attacklogs.php?pwd=your_password`).
Even `attacklogs.php` is protected by LiteWAF.

At the moment the logs are stored in plain text. Each row contains several information about the event (datetime, ip, user-agent, url requested, attack type, etc.).

This tool is based on signature matching, this means that bypass techniques can exist. However it should block and log the major part of the attacks.

## Configuration

You can configure the tool editing the beginning of `litewaf.php`.
You can set where to redirect the user when an attack is detected (index is the default location). You can set the log file path (it **must be** a php file).
You *must set* the directory containing `litewaf.php`.
Finally, you can set the password to access the log file (random by default) and if redirect a user that provides the wrong credentials.
