# Key Findings  
## Web Application and Linux System Compromise

---

# 1. Initial Reconnaissance: Network and Web Application Discovery

### 1.1. Port Scanning with Nmap

Network reconnaissance is a critical initial phase in any penetration test, providing a foundational understanding of the target's exposed services. Nmap, a widely utilized tool for network discovery and security auditing, was employed for this purpose. Its primary function is to identify active hosts, open ports, and the services running on those ports.

The initial Nmap scan of the target IP address revealed two open ports: 22, typically associated with Secure Shell (SSH), and 80, indicating a Hypertext Transfer Protocol (HTTP) web service.

While the specific Nmap command used was a basic invocation with only the target IP address, more advanced scans often incorporate options such as `-sS` for a stealthy TCP SYN scan or `-sT` for a full TCP Connect scan, each with distinct implications for network traffic and logging on the target system.

The presence of port 80 immediately suggested the existence of a web server, which became the primary focus for subsequent enumeration activities.

The decision to concentrate on port 80, despite port 22 also being open, represents a strategic prioritization in penetration testing. Exploiting SSH typically requires valid credentials, which might necessitate brute-force attacks or credential stuffing, often time-consuming and prone to detection. Conversely, web applications frequently present a broader attack surface, offering more avenues for initial compromise through common vulnerabilities like file uploads, SQL injection, or cross-site scripting, which can often be discovered and exploited without prior authentication. This approach reflects a common methodology in penetration testing, where attackers seek paths of least resistance to gain initial access.

The identified open ports and their associated services are summarized in **Table 1** below:

| Port Number | Service | Status |
|-------------|---------|--------|
| 22          | SSH     | Open   |
| 80          | HTTP    | Open   |

**Table 1: Identified Open Ports and Services**

---

### 1.2. Web Application Enumeration with Gobuster

Following the identification of an open HTTP port, the focus shifted to web application enumeration to discover hidden or unlinked content. Gobuster, a fast and powerful command-line tool, is well-suited for brute-forcing various web application elements, including Uniform Resource Identifiers (URIs) for directories and files, DNS subdomains, and virtual host names.

This tool is instrumental in uncovering content that might contain sensitive information or expose vulnerabilities.

The command executed for this phase was:

```bash
gobuster dir -u http://10.10.138.176 -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt
```

In this command, `gobuster` initiates the tool, `dir` specifies the directory/file enumeration mode, `-u http://10.10.138.176` defines the target URL, and `-w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-small.txt` points to the wordlist used for brute-forcing directory and file names.

Gobuster systematically attempts to append each entry from this wordlist to the target URL, checking for valid responses.

The Gobuster scan successfully identified four key directories: `uploads`, `css`, `js`, and `panel`. While `css` and `js` directories are standard for web assets and typically do not pose immediate security risks, the `panel` directory immediately suggested the presence of an administrative interface or control panel. Such interfaces frequently contain functionalities like file uploads, user management, or configuration settings that are often susceptible to misconfigurations or vulnerabilities. The discovery of the `uploads` directory was particularly significant, as it directly implied user-controlled file submission, a common vector for deploying web shells or other malicious files.

The process of exploring the discovered directories demonstrated an iterative and intelligent approach to enumeration. After identifying `css` and `panel` from the Gobuster output, checking the contents of `/css` likely revealed files such as `panel.css`. This observation, even if seemingly minor, could lead to an educated guess about the existence of a `/panel` directory. This highlights how an attacker can correlate information and move beyond automated tool output to perform more targeted searches. Effective penetration testing relies not only on running tools but also on critical thinking, pattern recognition, and using subtle clues to uncover more significant attack surfaces.

The directories identified and their typical implications are summarized in **Table 2**:

| Path      | HTTP Status Code (Implied) | Description                          |
|-----------|----------------------------|------------------------------------|
| /uploads  | 200 OK                     | User-controlled file submission point |
| /css      | 200 OK                     | Standard web assets (stylesheets)  |
| /js       | 200 OK                     | Standard web assets (JavaScript files) |
| /panel    | 200 OK                     | Potential administrative or control interface |

**Table 2: Discovered Web Directories and Status Codes**

The discovery of both `uploads` and `panel` directories marked a crucial shift from general reconnaissance to identifying specific, high-value attack surfaces. In web application security, uploads directories are inherently risky as they permit external content to be placed on the server, often within the web root, making them prime targets for web shell deployment. `panel` directories, on the other hand, typically denote administrative or user control interfaces, which are often less rigorously secured or contain privileged functionalities. The presence of these directories immediately raises a security concern and directs further investigation, frequently leading to initial access. This underscores the importance of proper directory naming conventions and stringent access controls on such sensitive paths.

---

# 2. Gaining Initial Access: Web Shell Upload and Reverse Shell

### 2.1. Identifying and Exploiting Upload Functionality

The enumeration phase revealed that the `/panel` directory contained an upload functionality. File upload forms are a common vulnerability point in web applications, as inadequate validation of uploaded files can lead to severe consequences, including remote code execution.

To understand the behavior of this functionality and determine the storage location for uploaded files, a preliminary test was conducted by uploading a random JPG image. This benign upload successfully confirmed that files were being stored in the `/uploads` directory. This initial test is a best practice in reconnaissance. By uploading a harmless file before a malicious one, an attacker can gather vital information about the server's file handling, storage location, and basic validation mechanisms without immediately triggering security alerts. This systematic approach to exploiting file upload vulnerabilities increases the likelihood of success and reduces the risk of detection by mapping the process first.

---

### 2.2. PHP Reverse Shell Deployment and Extension Bypass

With the upload functionality confirmed and the storage location identified, the next step involved deploying a PHP reverse shell. A PHP reverse shell operates by leveraging PHP's socket functions, such as `open` and `exec`, to initiate an outbound connection from the compromised server back to an attacker's listening machine.

The pentestmonkey PHP reverse shell script, a widely recognized tool for this purpose, was chosen for deployment.

The initial attempt to upload the `php-reverse-shell.php` file failed. This failure indicated the presence of server-side validation mechanisms designed to prevent the direct upload of executable PHP files. To circumvent this, a methodical approach was adopted, systematically attempting to upload the reverse shell with various alternative PHP-related file extensions: `.php2`, `.php3`, `.php4`, and finally `.php5`.

The `.php5` extension proved successful for both upload and execution, triggering the reverse shell when accessed. This bypass is a common occurrence due to web server misconfigurations. For instance, Apache web servers can be configured using `AddHandler` or `FilesMatch` directives to treat multiple PHP extensions (e.g., `.php`, `.php4`, `.php5`) as executable PHP scripts.

The success with `.php5` indicates that the web server's validation was not strictly enforcing `.php` as the sole executable PHP extension, likely relying on a blacklist approach rather than a more secure whitelist.

The success of the `.php5` bypass reveals a common security misconfiguration: a reliance on blacklisting for file extension validation rather than a strict whitelist. If the server had implemented a robust whitelist (e.g., only allowing `.jpg`, `.png`, `.gif`), all PHP extensions would have been blocked. The fact that `.php` was blocked but `.php5` was permitted strongly suggests that the server's validation explicitly denied `.php` but failed to account for other valid PHP executable extensions. This is often caused by an incomplete `AddHandler` or `FilesMatch` directive in Apache, where the administrator may have only blacklisted `.php` to prevent direct shell uploads, overlooking other common PHP extensions that Apache is configured to parse.

This scenario exemplifies a "security through obscurity" failure, as attackers routinely test alternative extensions when initial attempts fail, exploiting incomplete or poorly implemented validation rules. This highlights the critical importance of robust input validation, ideally employing a whitelist approach for all file uploads.

A notable observation during this phase was that "clicking on the `.php` file in `/uploads` nothing happened" initially, but a shell was obtained after a listener was started. This implicitly demonstrates the fundamental client-server nature of reverse shells and the absolute necessity of a pre-configured listening component on the attacker's machine. A reverse shell functions by having the compromised server initiate an outbound connection back to the attacker's system. If the attacker's machine is not actively listening, the outbound connection from the victim has no destination, resulting in no apparent activity. The listener acts as the "server" waiting for this incoming connection. This reinforces a core concept of reverse shells: they are attacker-initiated inbound connections from the victim's perspective, a design that often bypasses egress filtering that might block direct inbound connections to the victim.

The attempts to upload the PHP reverse shell with various extensions are documented in **Table 3**:

| Attempted Extension | Result                  |
|--------------------|-------------------------|
| .php               | Failed Upload           |
| .php2              | Successful Upload, No Shell |
| .php3              | Successful Upload, No Shell |
| .php4              | Successful Upload, No Shell |
| .php5              | Successful Upload, Shell Obtained |

**Table 3: PHP Reverse Shell Extension Attempts**

---

### 2.3. Establishing a Netcat Listener

To receive the incoming reverse shell connection from the compromised web server, a Netcat listener was established on the attacking machine. Netcat, often abbreviated as `nc`, is a highly versatile networking utility frequently referred to as the "Swiss Army Knife of Networking" due to its broad capabilities.

The command used to set up the listener was:

```bash
nc -lvnp 1234
```

Each flag in this command serves a specific purpose:

- `nc`: Invokes the Netcat utility.
- `-l`: Specifies listen mode, instructing Netcat to wait for an incoming connection rather than initiating one.
- `-v`: Enables verbose output, providing more detailed information about the connection status, such as "Listening on..." when the listener starts and "Connection received..." upon a successful connection.
- `-n`: Instructs Netcat to use numeric IP addresses only, preventing DNS lookups. This can expedite the process and avoid potential issues related to DNS resolution.
- `-p 1234`: Specifies the local port number (1234) on which Netcat should listen for incoming connections. This port number must precisely match the port configured within the PHP reverse shell script that was uploaded to the target server.

The consistent use of Netcat throughout various stages of penetration testing, from establishing simple listeners to facilitating file transfers and even performing basic port scanning, underscores its fundamental importance in an attacker's toolkit.

Its simplicity, combined with its widespread availability on many systems (or ease of installation), makes it an indispensable tool for quick network interactions, particularly in scenarios where more specialized tools might be unavailable or overly complex.

Understanding Netcat's diverse flags and functionalities is therefore crucial for both offensive and defensive cybersecurity practitioners. For defenders, recognizing Netcat activity can serve as a strong indicator of compromise.

---

# 3. Post-Exploitation: Shell Upgrade and User Flag

### 3.1. Upgrading to an Interactive TTY Shell

The initial reverse shell obtained was a "dumb" shell. This type of shell lacks the interactive capabilities commonly found in a full terminal environment. Limitations include the absence of command history (preventing the use of up/down arrow keys), tab autocompletion, proper handling of Ctrl+C (which might terminate the entire shell instead of just the running process), and formatted output.

Such restrictions severely hinder effective post-exploitation activities, making it difficult to navigate the file system, interact with applications, or execute complex commands.

To overcome these limitations and achieve an interactive TTY (teletypewriter) shell, the command:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

was executed on the compromised system. This command leverages Python's `pty` (pseudo-terminal) module to spawn a new `/bin/bash` shell within a pseudo-terminal. This clever technique deceives the system into believing it is interacting with a full terminal, thereby granting interactive features. To fully stabilize the TTY and ensure correct handling of control characters, additional steps, often involving `stty raw -echo` and `fg` commands on the attacker's machine, are typically necessary.

The reliance on Python for shell stabilization highlights the significant role that scripting languages, commonly found on Linux systems, play as powerful post-exploitation tools. The presence of a Python interpreter on the target system is often a given in most Linux environments. Python's `os` and `pty` modules provide direct interfaces to system calls and pseudo-terminal functionalities, making it an ideal choice for manipulating shell behavior and enhancing interactivity. Attackers frequently "live off the land" by utilizing pre-installed tools and scripting languages on compromised systems. This strategy reduces the need to upload additional tools, which in turn lowers the chances of detection. Python, along with other languages like Perl and Ruby, and even utilities like `script`, are common choices for shell stabilization and various other post-exploitation tasks.

---

### 3.2. Initial Foothold and User Flag Discovery

Upon successfully establishing the reverse shell, the `whoami` command was executed to identify the current user context. The output revealed that the shell was running as `www-data`. This is a common low-privileged user account typically associated with web servers (such as Apache or Nginx) on Debian/Ubuntu-based systems, confirming that initial access was achieved through the web application.

Following user identification, directory enumeration was performed using `ls` commands in the current directory. To locate user-specific files, the current directory was changed to the home directory using `cd ~`, followed by another `ls` command. This systematic exploration led to the successful discovery of the first user flag within the home directory of the current user (likely `www-data` or a related user in `/home/`). This marked a significant milestone in the penetration test, confirming initial user-level compromise of the target system.

The `www-data` user being the initial shell user is a classic indicator of a successful web application compromise. This confirms that the initial access vector was indeed the web application, and the privileges gained are those of the web server process itself. This is a common scenario in web application penetration tests, where attackers typically start with low-privileged web server users and then focus on privilege escalation techniques to gain higher access, such as root. It also implies that the web server process itself might be operating with unnecessary permissions or have access to sensitive files, which could be further exploited.

---

# 4. Privilege Escalation to Root

### 4.1. Understanding SUID Bit Vulnerabilities

Privilege escalation is a critical phase in a penetration test, aiming to gain elevated access beyond the initial foothold. A key mechanism for this in Linux is the SUID (Set User ID) bit. SUID is a special file permission that, when set on an executable file, allows any user executing that file to run it with the permissions of the file's owner, rather than their own.

This is legitimately used for programs like `passwd`, which requires root privileges to modify sensitive system files such as `/etc/shadow`.

However, the SUID bit also represents a significant privilege escalation vector. If a binary owned by the root user has the SUID bit set and contains a vulnerability, or if it can be manipulated to execute arbitrary commands, a low-privileged user (like `www-data`) can execute it to gain root privileges.

This makes SUID binaries a prime target for attackers seeking to elevate their access.

The dual nature of SUID, serving both legitimate system functions and acting as a potential attack surface, highlights its role as a double-edged sword. While necessary for certain functionalities, any SUID binary, particularly those owned by root, inherently becomes a potential pathway for privilege escalation if not meticulously secured. This underscores the importance of robust security practices, including regular auditing of SUID binaries, ensuring they are only set on absolutely necessary files, and keeping all system software updated to patch known SUID-related vulnerabilities.

Custom SUID binaries, in particular, pose a heightened risk if not developed with stringent security considerations.

---

### 4.2. Identifying SUID Binaries

To identify potential privilege escalation paths, the system was scanned for SUID binaries owned by the root user. The command used for this discovery was:

```bash
find / -user root -perm /4000 2>/dev/null
```

Let's break down the parameters of this command:

- **`find /`**: This instructs the `find` utility to search the entire file system, starting from the root directory.  
- **`-user root`**: This filter restricts the search results to include only files that are owned by the root user.  
- **`-perm /4000`**: This is the crucial part for identifying SUID binaries. The `/4000` in octal represents the SUID bit (Set User ID on execution). The `/` prefix indicates that the command should match files where *any* of the specified permission bits are set.  
- **`2>/dev/null`**: This redirects stderr (standard error) output to `/dev/null`.

This is a practical operational detail that significantly enhances the efficiency of reconnaissance. When `find /` traverses the file system as a low-privileged user (like `www-data`), it will inevitably encounter numerous directories and files for which it does not have read permissions. Without this redirection, the output would be flooded with "Permission denied" errors, making it extremely difficult to identify legitimate SUID binaries amidst the noise.

This practice highlights the importance of making commands efficient and their output digestible in offensive security, maximizing information gain while minimizing irrelevant data.

The scan results indicated `/usr/bin/python` as a suspicious SUID binary. While Python is a legitimate and widely used programming language interpreter, having it SUID-enabled and owned by root represents a significant security misconfiguration. This is because Python, as an interpreter, can execute arbitrary code. If Python runs with root privileges due to the SUID bit, any Python code it executes will also run with root privileges. This provides a straightforward method for an attacker to simply pass a Python script or inline command that spawns a root shell.

This finding is a severe misconfiguration; SUID should generally **not** be set on interpreters, compilers, or editors because they offer a readily available means to "escape" to a privileged shell or perform privileged file operations. This situation exemplifies a common error in system administration where flexible tools are granted excessive privileges.

The identified SUID binaries owned by root are presented in **Table 4**:

| Binary Path      | Owner | Permissions  | Description/Purpose          |
|------------------|-------|--------------|-----------------------------|
| /usr/bin/python  | root  | -rwsr-xr-x   | Exploitable SUID (Interpreter) |
| (Other binaries)  | root  | -rwsr-xr-x   | Legitimate SUID (e.g., passwd) |

**Table 4: Identified SUID Binaries Owned by Root**

---

### 4.3. Exploiting SUID-enabled Python for Root Access

With `/usr/bin/python` identified as an exploitable SUID binary, the next step was to find a specific command to leverage this misconfiguration for root access. The necessary command was discovered by consulting **GTFOBins**. GTFOBins is an invaluable curated list of Unix binaries that can be abused to bypass local security restrictions, including privilege escalation, by leveraging their legitimate functionalities. It provides specific commands for various scenarios, making it an essential reference for "living off the land" techniques.

The exploitation command executed was:

```bash
python -c 'import os; os.execl("/bin/sh", "sh", "-p")'
```

Let's analyze this command in detail:

- **`python -c '...'`**: This instructs the Python interpreter to execute the code provided as a string argument.  
- **`import os;`**: This line imports Python's `os` module, which provides functions for interacting with the operating system, including process management.  
- **`os.execl("/bin/sh", "sh", "-p")`**: This is the core of the exploit. The `os.execl()` function is a wrapper around the exec family of system calls in Unix-like operating systems. Its purpose is to replace the current running process (in this case, the SUID-enabled Python interpreter) with a new program, without creating a new process.

  - `"/bin/sh"`: This specifies the path to the new program to be executed, which is the Bourne shell.  
  - `"sh"`: This is the first argument passed to the new program, conventionally the name of the program itself.  
  - `"-p"`: This is the critical flag for privilege escalation in this context. When `sh` (or other shells) is executed with the `-p` flag, it is instructed to run in "privileged" mode. This means that if the shell is executed from a SUID binary, it will attempt to retain the effective user ID (EUID) of the SUID binary's owner (which is root in this scenario), rather than dropping it to the real user ID (RUID) of the user who invoked the SUID binary (`www-data`). Without the `-p` flag, the shell would typically revert to the real user ID for security reasons, negating the benefit of the SUID bit.

The behavior of the exec family of functions, such as `os.execl()`, in replacing the current process while potentially retaining privileges, is a key mechanism in SUID exploitation. When Python, already running with SUID root privileges, calls `os.execl()` to execute `/bin/sh`, the shell process inherits those root privileges. This is not a new process being spawned by Python, but rather Python transforming itself into the shell, carrying its current privileges with it.

Understanding how exec calls interact with SUID is fundamental to Linux privilege escalation. It clarifies why simply running a shell from a SUID binary is often insufficient; the shell itself needs to be explicitly instructed to retain those privileges, which is precisely the role of the `-p` flag.

Execution of this command successfully granted root privileges on the target system. This allowed the final objective of the penetration test to be met: the retrieval of the root flag.

The use of GTFOBins in this scenario demonstrates its critical role as a resource for finding specific, "living off the land" privilege escalation techniques. GTFOBins is designed to document how common Unix binaries (like `python`, `find`, `gimp`, `view`) can be misused in misconfigured systems to achieve various post-exploitation goals, including SUID privilege escalation. It provides the exact commands needed for such purposes.

This highlights the importance of open-source security knowledge bases. Attackers do not always rely on zero-day exploits; they frequently leverage known misconfigurations and the legitimate functionalities of already installed binaries. For defenders, GTFOBins serves as an equally valuable resource for understanding common attack patterns and effectively hardening systems against them.

---

# 5. Conclusion and Root Flag

This penetration test successfully demonstrated a complete compromise of the target system, escalating privileges from an initial low-privileged `www-data` user to the root user. The compromise path involved exploiting a web application's unauthenticated file upload vulnerability, bypassing file extension validation, establishing a reverse shell, and finally leveraging a misconfigured SUID-enabled Python binary. The successful capture of the root flag signifies complete control over the target.
