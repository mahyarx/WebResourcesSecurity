# Module 3: Server-Side Vulnerabilities and Risk Profiling

This module explores how attackers exploit server-side components such as input processors, file systems, and backend services. It also covers techniques to assess and prioritize risks during testing.

---

## 🛠️ Server-Side Vulnerabilities Overview

### 🔄 Server-Side vs. Client-Side
- **Client-side**: Code executed in the browser (e.g., XSS)
- **Server-side**: Code executed on the server (e.g., PHP, ASP.NET, Python apps)

---

## 💉 Common Server-Side Vulnerabilities

### 1. **File Inclusion (LFI/RFI)**
- LFI (Local File Inclusion): Includes local files like `/etc/passwd`
- RFI (Remote File Inclusion): Loads remote malicious files
- Vulnerable example:
  ```
  page=../../../../etc/passwd
  ```

### 2. **Command Injection**
- Executes system commands via unsanitized inputs
- Example:
  ```
  ; cat /etc/passwd
  ```

### 3. **File Upload Vulnerabilities**
- Allows uploading scripts (e.g., `.php`) that can be executed
- Check:
  - File type restrictions
  - MIME type spoofing
  - Client-side validations

### 4. **Deserialization Attacks**
- Injecting malicious serialized objects to execute arbitrary code
- Common in Java, PHP, .NET apps

---

## 🔍 Risk Profiling and Prioritization

### 🧠 Threat Modeling Recap
- Identify high-value assets
- Map likely attack paths
- Rank vulnerabilities based on impact and exploitability

---

## 🧪 Tools and Techniques

- **Burp Suite / ZAP**: Manual and active scanning
- **FFUF / Dirbuster**: Directory enumeration
- **Nikto / Nmap**: Web server misconfigurations
- **wfuzz / sqlmap**: Payload fuzzing and exploitation

---

## 📈 Vulnerability Classification

- Use CVSS (Common Vulnerability Scoring System)
- Refer to OWASP Top 10 and CWE (Common Weakness Enumeration)
- Categorize issues as:
  - High: RCE, SQLi, deserialization
  - Medium: LFI, XSS, file upload
  - Low: Info disclosure, verbose error messages

---

## 🛡️ Server Hardening Tips

- Disable unnecessary services and features
- Sanitize all inputs on the server
- Restrict file permissions and script execution
- Implement logging and monitoring
- Use secure frameworks and update them frequently

---

## 🧪 Exercises

1. **Identify LFI/RFI vulnerabilities using payloads**
2. **Attempt basic command injection**
3. **Test file upload restrictions and bypasses**
4. **Use risk profiling to prioritize findings from a test report**

---

## 📋 Summary

- Server-side flaws can give full control to attackers.
- Risk profiling helps prioritize and manage remediation.
- Always validate and sanitize user input on the server side.
- Automated and manual tools complement each other for better results.