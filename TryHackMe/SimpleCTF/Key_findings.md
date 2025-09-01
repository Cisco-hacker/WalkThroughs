
# Executive Summary

This report provides a comprehensive analysis of a simulated penetration test conducted on a target system. The objective of the engagement was to assess the system's security posture by identifying and exploiting vulnerabilities in a manner consistent with a real-world malicious actor. The analysis documents a complete attack chain, beginning with initial network reconnaissance and culminating in a full system compromise, achieving root-level administrative access.

# Key Findings

The investigation revealed a series of critical vulnerabilities, demonstrating systemic weaknesses in the system's security architecture and operational practices. The most significant findings include:

1. **Insecure Network Service Configuration:** The File Transfer Protocol (FTP) service was configured to allow anonymous, unauthenticated access. This misconfiguration, a well-documented vulnerability (CVE-1999-0497), led to a critical information disclosure that directly enabled subsequent stages of the attack.

2. **Vulnerable Web Application:** The system hosted an outdated version of the "CMS Made Simple" web application, which contained a high-severity, unauthenticated SQL Injection vulnerability (CVE-2019-9053). This flaw allowed for the remote extraction and cracking of administrative credentials.

3. **Weak Credential and Password Policies:** The user account mitch was protected by a weak, easily guessable password (secret). The presence of this password in common dictionaries like rockyou.txt, combined with the lack of multi-factor authentication (MFA), rendered the Secure Shell (SSH) service vulnerable to a targeted brute-force attack.

4. **Critical Privilege Escalation Flaw:** A misconfiguration in the sudo policy granted the compromised user account the ability to execute the vim text editor with root privileges. This flaw was exploited to gain an interactive root shell, resulting in a complete takeover of the system.

# Business Impact

The combination of these vulnerabilities exposes the organization to severe risks. A successful compromise could result in the exfiltration of all sensitive data stored on the system, deployment of ransomware, complete service disruption, and the use of the compromised server as a pivot point to attack other internal network assets. The reputational damage and potential regulatory fines resulting from such a breach would be substantial. The existence of two independent paths to initial compromise indicates a pattern of security neglect rather than an isolated oversight, suggesting that other systems within the environment may be similarly vulnerable.

# Strategic Recommendations

Immediate and decisive action is required to remediate these vulnerabilities. The highest priority is to correct the privilege escalation flaw and secure all remote access vectors. Long-term remediation must focus on implementing foundational security principles, including a robust patch management program, adherence to the principle of least privilege, enforcement of modern password policies and MFA, and comprehensive security training for system administrators and developers.

The following table provides a high-level summary of the critical vulnerabilities identified during this assessment.

| ID | Vulnerability Description           | Associated CVE/Issue       | Exploitation Vector                                  | Business Impact                                                                                   |
|----|-----------------------------------|---------------------------|-----------------------------------------------------|-------------------------------------------------------------------------------------------------|
| 1  | Anonymous FTP Access              | CVE-1999-0497             | Unauthenticated access to the FTP server, leading to sensitive information disclosure. | Direct exposure of internal files and intelligence, enabling targeted attacks on user accounts and other services. |
| 2  | CMS Made Simple SQL Injection     | CVE-2019-9053             | Unauthenticated, remote SQL injection via the web application, leading to credential theft. | Compromise of application and system user credentials, providing a direct path to initial shell access. |
| 3  | Sudo Privilege Escalation via vim | Sudoers Misconfiguration  | A local user with sudo rights to vim can execute shell commands to become root.         | Complete and total system compromise (root access) from a low-privilege user account, leading to data loss, backdoors, and further attacks. |

---

# Section 1: Reconnaissance and Attack Surface Analysis

The initial phase of any penetration test involves reconnaissance, where an attacker gathers intelligence about the target to identify potential weaknesses and map the attack surface. This process is foundational, as the quality of the intelligence gathered directly influences the success of subsequent exploitation attempts.

## 1.1 Network Discovery and Port Scanning with Nmap

The engagement began with a network scan using Nmap (Network Mapper), a powerful open-source utility for network discovery and security auditing. The primary goal of an Nmap scan is to identify live hosts on a network and discover the services they offer by probing for open Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) ports. The scan against the target IP address provided the first blueprint of its externally visible services.

The analysis revealed three open TCP ports, each representing a potential entry point into the system:

- Port 21: Hosting the File Transfer Protocol (FTP), a standard but often insecure protocol used for transferring files.
- Port 80: Hosting the Hypertext Transfer Protocol (HTTP), indicating the presence of a web server.
- Port 2222: Hosting the Secure Shell (SSH) protocol, used for secure remote command-line administration.

The use of an external scanning tool is critical as it provides the perspective of an attacker from the public internet, showing exactly what services are exposed and available for interaction.

## 1.2 Service and Version Enumeration

A simple list of open ports is only the first step. To formulate a viable attack strategy, it is crucial to identify the specific software and version running on each port. Nmap's version detection feature (-sV) interrogates open ports to determine the application name, version number, and often the underlying operating system. This detailed enumeration transforms a general port scan into a list of specific, researchable targets.

The scan successfully identified the following services:

- FTP: vsftpd (Very Secure FTP Daemon)
- HTTP: Apache httpd
- SSH: OpenSSH

The underlying operating system was identified as a UNIX-based system (e.g., Linux). This information is highly valuable, as it allows an attacker to search for known vulnerabilities and public exploits associated with these specific software versions. The discovery that SSH was running on the non-standard port 2222 instead of the default port 22 is particularly noteworthy. While administrators sometimes change default ports in an attempt to hide services from automated scanners, this practice, known as "security through obscurity," is not a robust security control. To a skilled attacker, it often signals a less mature security posture, suggesting that the administrator may be relying on hiding services rather than properly securing them. This can imply a higher likelihood of other misconfigurations, such as weak passwords or a lack of intrusion detection, making the target more attractive for further investigation.

The combination of services also suggests a potential lack of a unified security policy. The presence of FTP, a legacy protocol that transmits credentials in plaintext, alongside the modern and secure SSH protocol, may indicate that services have been added over time without a consistent security standard or a process for decommissioning old, insecure services. This "configuration drift" often leads to forgotten accounts, outdated software, and other security gaps.

| Port | Protocol | State | Service | Version | Notes and Immediate Inferences                                                                                  |
|-------|----------|-------|---------|---------|---------------------------------------------------------------------------------------------------------------|
| 21    | TCP      | OPEN  | ftp     | vsftpd  | A legacy protocol known for security weaknesses. The primary immediate concern is the potential for anonymous access, which is a critical vulnerability. |
| 80    | TCP      | OPEN  | http    | Apache  | A standard web server. The attack surface is the web application hosted on it, which must be enumerated for vulnerabilities. |
| 2222  | TCP      | OPEN  | ssh     | OpenSSH | A non-standard port for SSH. This is a form of security through obscurity and suggests that other fundamental security controls may be weak or absent. |

## 1.3 Web Reconnaissance: The robots.txt File

During the Nmap scan, an automated script also retrieved the robots.txt file from the web server on port 80. This file is intended to provide instructions to legitimate web crawlers, like Google's, on which directories they should not index. However, for an attacker, this file serves as a roadmap to potentially interesting or sensitive areas of a website that the administrator wishes to hide.

The scan revealed the following disallowed entry:

```
Disallow: /openemr-5_0_1_3
```

This finding was a significant piece of intelligence. By explicitly disallowing this directory, the administrator inadvertently confirmed two critical facts: the existence of the directory and the exact name and version of the application running within it (OpenEMR 5.0.1_3). This information provides a direct path for an attacker to search for known exploits targeting this specific version of OpenEMR, bypassing the need for further application fingerprinting.

---

# Section 2: Initial Access Vector I - Exploitation of Insecure FTP Services

The first successful path to gaining a foothold on the system exploited a classic and severe misconfiguration of the FTP service. This vector highlights the dangers of running legacy services without proper hardening and demonstrates how a seemingly low-risk vulnerability can provide the critical intelligence needed for a full compromise.

## 2.1 Anonymous FTP Login: An Open Door

Based on the reconnaissance finding that port 21 was open, the attacker attempted to connect using an FTP client. A common first step when assessing an FTP server is to test for anonymous login, where the username is anonymous and the password can be any value (often an email address or, simply, anonymous). In this case, the login attempt was successful.

Allowing anonymous FTP access is a well-known and high-risk vulnerability, cataloged as CVE-1999-0497. This configuration permits any user on the internet to establish a connection and, depending on the file system permissions, browse, download, or even upload files without any authentication. Unless there is a deliberate and controlled business requirement for public file distribution, anonymous FTP should always be disabled. Its presence on this server provided the attacker with their first interactive access to the target's file system, opening a direct channel for further enumeration.

## 2.2 Enumeration and Intelligence Gathering within FTP

Once connected, the attacker employed a methodical enumeration process using basic FTP commands. The `help` command revealed the available functions, and the `ls` command listed the contents of the current directory. This led to the discovery of a directory named `pub` (a common name for public-facing files). After navigating into this directory with `cd pub`, the attacker found a single file: `ForMitch.txt`.

The filename itself was a strong indicator that it was a message intended for a user named "Mitch." Before downloading the file, the attacker prudently switched the transfer mode to binary. This is a subtle but important step that ensures the integrity of the downloaded file, preventing any potential corruption that might occur if the file were not plain text. The file was then downloaded to the attacker's local machine using the `get` command.

## 2.3 Deconstructing the ForMitch.txt Message

The contents of the downloaded file provided a treasure trove of actionable intelligence:

> "Dammit man... you'te the worst dev i've seen. You set the same pass for the system user, and the password is so weak... i cracked it in seconds. Gosh... what a mess!”

A careful analysis of this message reveals several critical clues:

- **Username Identification:** The message is addressed to "Mitch," making it highly probable that a system user account named mitch exists.
- **Password Reuse:** The message explicitly states that the same password was used for the "system user," implying poor password hygiene and the reuse of credentials across different accounts.
- **Extreme Password Weakness:** The password is described as not just weak, but so trivial that it was "cracked in seconds." This strongly suggests the password is a very common word or pattern that would be found at the top of any standard password-cracking dictionary.

This information leak is not just a technical failure but also a human one. The act of leaving such a revealing and unprofessional note in a publicly accessible directory points to a profoundly weak security culture within the development team. It suggests that security is not integrated into their workflow and that other careless mistakes are likely present elsewhere in the system. For an attacker, this is a strong signal that the path of least resistance will involve exploiting simple, human-driven errors.

## 2.4 FTP Protocol Mechanics: Active vs. Passive Mode

A subtle but revealing technical detail was observed during the FTP connection: the client first attempted to use extended passive mode, which failed, before successfully falling back to active mode. This provides valuable insight into the server's network and firewall configuration.

- **Passive Mode (PASV):** In this mode, the client initiates both the command connection (to port 21) and the data connection. After the command channel is established, the client sends a PASV command, and the server responds with an IP address and a random high-numbered port that it has opened for the data transfer. The client then initiates the connection to this port. The failure of this mode suggests that the server's firewall is blocking incoming connections on these high-numbered ports, a common default security posture.

- **Active Mode (PORT):** In this mode, the client initiates the command connection, but the server initiates the data connection. The client tells the server which port it is listening on, and the server connects back to the client from its own data port (port 20). The success of this mode implies that the server's firewall permits outbound connections from port 20, which is a more permissive rule.

This seemingly minor detail reinforces the picture of a system with an inconsistent and likely not fully understood security configuration. The successful connection via this older, less firewall-friendly mode further supports the hypothesis of a legacy service that has not been properly maintained or secured. This entire vector demonstrates a critical principle in security assessment: no information leak is harmless. The "low-severity" finding of a readable anonymous FTP server acted as a powerful attack multiplier, providing the exact intelligence required to turn the subsequent SSH attack from a speculative gamble into a highly targeted and successful operation.

---

# Section 3: Initial Access Vector II - Web Application Compromise

As an alternative path to initial access, a sophisticated attack was executed against the web server on port 80. This vector demonstrates that even when one lead proves fruitless (the initial OpenEMR finding), persistent and systematic enumeration of the web attack surface can uncover entirely different, and equally critical, vulnerabilities.

## 3.1 Directory Enumeration with Dirbuster

After determining that the `/openemr-5_0_1_3` directory was not the intended path, the attacker pivoted to a broader web reconnaissance strategy. They employed DirBuster, a tool designed to discover hidden files and directories on a web server by launching a dictionary-based brute-force attack. By iterating through a list of common directory and file names, tools like DirBuster can uncover content that is not linked from the main website, such as administrative panels, old backup files, or entirely separate applications.

The DirBuster scan was configured to use a medium-sized wordlist against the web server's root. This process successfully identified a previously unknown directory: `/simple`. Navigating to this directory revealed a website powered by the "CMS Made Simple" content management system. This discovery was pivotal, as it shifted the attack surface from a generic Apache server to a specific, versionable software product with its own set of known vulnerabilities.

## 3.2 Vulnerability Identification with Searchsploit

With the application identified as "CMS Made Simple," the next logical step was to search for publicly disclosed vulnerabilities. The attacker utilized searchsploit, the command-line interface for Exploit-DB, which provides a fast, offline database of exploits and vulnerability information. This is a more efficient and discreet method than general web searches.

The search for "CMS Made Simple" would have returned numerous results. The attacker's task was to identify an exploit that matched the likely version of the target application and, most importantly, could lead to remote code execution (RCE) or, in this case, credential theft. The attacker correctly identified a Python script, `46635.py`, as the most promising candidate.

## 3.3 Exploitation of CVE-2019-9053: Time-Based Blind SQL Injection

The selected exploit, `46635.py`, targets a critical vulnerability known as CVE-2019-9053. This vulnerability is a time-based blind SQL injection in CMS Made Simple version 2.2.8 and earlier.

- **SQL Injection (SQLi):** This is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve, and in many cases, modify or delete this data, causing persistent changes to the application's content or behavior.

- **Blind and Time-Based Nature:** This is a particularly advanced form of SQLi. In a blind SQLi, the application does not return data or database errors directly in its HTTP responses. The exploit script overcomes this by injecting SQL queries that instruct the database to pause for a specific duration (e.g., 5 seconds) only if a certain condition is true. For example, the script might ask, "Is the first letter of the administrator's password hash 'a'?" If the server takes 5 seconds longer to respond, the script knows the answer is yes. By iterating through all possible characters for each position in the hash, the script can slowly but accurately exfiltrate sensitive data.

The attacker executed the exploit with the following command:

```bash
python 46635.py -u http://<IP_address>/simple --crack -w /usr/share/wordlists/rockyou.txt
```

This command instructs the script to perform a series of automated actions:

1. Target the URL (-u) of the CMS Made Simple installation.
2. Use the time-based SQLi vulnerability to extract the username, password salt, and password hash of the administrative user from the database.
3. Initiate the cracking process (--crack) on the extracted hash.
4. Use the provided wordlist (-w), rockyou.txt, as the source of password guesses.

The exploit ran successfully and returned the compromised credentials: **mitch** and **secret**. This result is highly significant for two reasons. First, it provided a completely independent path to obtaining the same credentials discovered through the FTP vector. Second, it highlights a systemic failure in security practices. The existence of two distinct, high-severity vulnerabilities leading to the same point of compromise indicates that security was not an isolated oversight but a pattern of neglect. This suggests a lack of fundamental security processes, such as a secure software development lifecycle, vulnerability scanning, and regular patch management. The presence of outdated, vulnerable software is a critical failure of operational security, making the system an easy target for any attacker with knowledge of public exploits.

# Section 4: Securing the Foothold - SSH Brute-Force and Access

After obtaining the username **mitch** and critical intelligence about his weak password from either the FTP information leak or the web application exploit, the next phase of the attack was to leverage this information to gain interactive shell access. The SSH service, running on the non-standard port 2222, was the logical target for this attempt.

## 4.1 Targeted Brute-Force with Hydra

The attacker employed Hydra, a powerful and flexible online password cracking tool, to perform a dictionary attack against the SSH service. A brute-force attack involves systematically attempting numerous passwords in the hope of guessing correctly. However, this was not a blind attack; it was a highly targeted operation informed by the previously gathered intelligence.

The command used was:

```bash
hydra -l mitch -P /usr/share/wordlists/rockyou.txt ssh://<IP_ADDRESS> -s 2222
```

This command is a textbook example of an efficient, intelligence-led brute-force attempt:

- `-l mitch`: This flag specifies a single login name to target. By focusing on a known valid username, the attacker drastically reduces the number of attempts required and avoids the noise of guessing both usernames and passwords.
- `-P /usr/share/wordlists/rockyou.txt`: This flag provides a path to a password dictionary. The choice of rockyou.txt was strategic, given the hint that the password was "so weak... i cracked it in seconds."
- `ssh://<IP_ADDRESS>`: This specifies the target protocol (SSH) and the IP address.
- `-s 2222`: This crucial option tells Hydra to connect to the non-standard port 2222, where the SSH service was discovered during the initial Nmap scan.

The success of this phase was predicated on the symbiotic relationship between the preceding information disclosure vulnerabilities and this brute-force attempt. Without the username **mitch**, the attack would have been exponentially more difficult and likely to fail or be detected. The information leak provided the context that made the brute-force attack not just possible, but highly efficient and probable.

## 4.2 The Power of the rockyou.txt Wordlist

The hydra attack successfully identified the password as **secret**. The fact that this password was found in rockyou.txt is not surprising. The rockyou.txt wordlist is a foundational tool in any penetration tester's arsenal and is included by default in security-focused operating systems like Kali Linux.

The list's origin is a 2009 data breach of the social networking site RockYou, during which the passwords of over 32 million users were exposed. Critically, these passwords were stored in plaintext, without any encryption or hashing. This raw data was compiled into the rockyou.txt file, which contains over 14 million unique, real-world passwords. Its effectiveness stems from the fact that it reflects actual human behavior in password creation, containing vast numbers of common patterns, simple words, keyboard sequences, and popular phrases. The password **secret** is a classic example of a low-entropy, dictionary-word password that is trivial to crack using such a list.

## 4.3 Gaining Initial Shell Access

With the valid credentials **mitch:secret** in hand, the attacker successfully authenticated to the SSH service using the command:

```bash
ssh -p 2222 mitch@<IP_ADDRESS>
```

This action marked the successful transition from external exploitation to internal access. The attacker was presented with a bash shell prompt (`$`), confirming they had established an interactive command-line session on the target machine as the user mitch. This "foothold" is a critical milestone in a penetration test. From this point, the attacker is no longer an outsider but an insider, able to execute commands, explore the internal file system, and, most importantly, begin the process of identifying and exploiting local vulnerabilities to escalate their privileges to the root user.

---

# Section 5: Privilege Escalation via Sudo Misconfiguration

Upon gaining initial shell access as the user **mitch**, the attacker's objective immediately shifted from gaining entry to gaining control. The final and most critical phase of the attack was privilege escalation: the process of elevating access from that of a standard user to the root user, who has complete and unrestricted control over the Linux system.

## 5.1 Post-Exploitation Enumeration: `sudo -l`

A skilled attacker's first actions upon landing in a new shell are to perform enumeration to understand the environment and identify pathways to greater privilege. After confirming their user identity (**mitch**) and location (`/home/mitch`), the attacker ran the command:

```bash
sudo -l
```

This command is one of the most important tools for Linux privilege escalation. It queries the `/etc/sudoers` configuration file and lists the commands that the current user is permitted to run with elevated privileges (typically as the root user). This provides a direct, system-sanctioned map of potential escalation paths.

## 5.2 Dissecting the Sudoers Misconfiguration

The output of `sudo -l` revealed that the user **mitch** was permitted to execute the following command as root:

```bash
/usr/bin/vim
```

This is a critical and classic misconfiguration of the sudoers file. The sudo utility is designed to grant granular administrative permissions according to the principle of least privilege. However, granting a user the ability to run an application as powerful and feature-rich as the vim text editor is functionally equivalent to granting them a full root shell. The administrator who wrote this rule likely intended to allow mitch to edit a specific configuration file as root. However, by granting permission to the vim binary itself, they inadvertently provided an unrestricted path to privilege escalation. Many common Linux utilities, including text editors (vim, nano), file pagers (less, more), and scripting tools (awk, perl), have features that allow for "shelling out" or executing arbitrary system commands from within the application.

An attacker who discovers such a rule in a sudoers file recognizes it immediately as a direct key to obtaining root access. This type of misconfiguration often stems from an administrator's lack of understanding of the full capabilities of the tools they are granting access to, highlighting a significant gap in security knowledge.

| User  | Host(s) | (Run As User) | Command       | Analysis of Flaw                                                                                                  |
|-------|---------|---------------|---------------|------------------------------------------------------------------------------------------------------------------|
| mitch | ALL     | (root)        | /usr/bin/vim  | This rule is critically flawed. vim is a powerful editor that allows users to execute external shell commands (e.g., via `:!/bin/sh`). By allowing mitch to run vim as root, the system is effectively giving mitch the ability to open a root shell at will, completely bypassing all security controls and violating the principle of least privilege. |

## 5.3 Exploiting vim for a Root Shell

The attacker exploited this misconfiguration using a well-documented technique, often found in resources like GTFOBins which catalog how legitimate system binaries can be used for malicious purposes.

The process was simple and effective:

1. **Execute vim as root:** The attacker ran the command:

    ```bash
    sudo /usr/bin/vim
    ```

    This launched the vim text editor, but the process itself was running with the effective user ID of root.

2. **Escape to a Shell:** Once inside vim, the attacker entered command mode by typing `:`. They then used the `!` character, which is vim's command to execute an external shell command. By providing `/bin/sh` as the command, they instructed vim to spawn a new shell.

Because the parent process (vim) was running as root, the new child process (the `/bin/sh` shell) inherited these elevated privileges. The attacker's command prompt immediately changed from the standard user prompt (`$`) to the root user prompt (`#`), signifying a successful privilege escalation.

## 5.4 Capturing the Final Flag

With full root privileges, the attacker had achieved complete control of the system. They were able to navigate to any directory, including the highly restricted `/root` home directory, which is inaccessible to all other users. A final `ls` command revealed the presence of the `root.txt` file, and a `cat` command displayed its contents, successfully capturing the final flag and completing the objectives of the penetration test.

This final step demonstrates the ultimate impact of the chained vulnerabilities. As the root user, the attacker could now read, modify, or delete any file on the system; install persistent backdoors or rootkits; sniff network traffic; erase logs to cover their tracks; and use the compromised machine as a trusted host to launch further attacks against other systems in the network.
