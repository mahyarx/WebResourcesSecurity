# 📘 Module 1: Introduction and Information Gathering (Extended Version)

Welcome to the first lecture in the Web Resource Security course. This session introduces the foundational elements of web application penetration testing, emphasizing the importance of securing web technologies in modern infrastructures. You'll learn the reasons why web applications are often insecure, explore several web security testing methodologies, and gain hands-on experience with reconnaissance and information gathering techniques essential for later testing stages.

---

## 🎯 Learning Objectives

After this session, students will be able to:

- Explain the critical role of web applications in modern computing
- Describe common reasons for the lack of security in web applications
- Identify and compare various web security assessment methodologies
- Understand the toolkit required for effective penetration testing
- Configure and use interception proxies like Burp Suite and ZAP
- Perform passive and active reconnaissance (OSINT, HTTP analysis, HTTPS scanning)
- Discover hidden virtual hosts and gather key target intelligence

---

## 🌐 Why the Web?

Web applications have become central to nearly every business and government operation:

- **Ubiquity**: Nearly every organization—from social media companies to universities—relies on web applications for internal operations, client interactions, and service delivery.
- **Accessibility**: Web applications are typically publicly accessible, making them natural targets for attackers.
- **Data Sensitivity**: Many web apps process financial records, PII, medical data, credentials, and more.
- **Rapid Development**: Development cycles prioritize functionality and user experience over security.

### 🔓 Why Are Web Apps Insecure?

- Lack of formal security training for developers
- Pressure to deliver features quickly (short sprint cycles)
- Poor understanding of client-server communication flows
- Misconfiguration or improper implementation of authentication mechanisms
- Complex dependencies (frameworks, 3rd-party scripts, libraries)

---

## 🛠️ Web Application Security Testing Methodologies

Security assessments vary based on context and application. Some widely accepted methodologies include:

### 🔍 OWASP Web Security Testing Guide (WSTG)
A structured guide used globally to perform comprehensive app assessments:
- Offers step-by-step checklists for manual and automated tests
- Covers areas like input validation, authentication, session management, business logic, etc.

### 🔐 Penetration Testing Execution Standard (PTES)
PTES provides a broad, high-level methodology for penetration testing that can be adapted for web apps:
- **Pre-Engagement**: Define scope, rules, goals
- **Intelligence Gathering**: Passive OSINT and active scanning
- **Threat Modeling**: Identifying assets and potential attack vectors
- **Vulnerability Analysis & Exploitation**
- **Post Exploitation**: Establishing persistence or lateral movement (less applicable to web)
- **Reporting**: Documenting findings and mitigation

> SEC542 follows OWASP WSTG for most in-depth, actionable techniques but adapts based on context.

---

## 🧰 Building Your Pen Tester’s Toolkit

Penetration testing is both an art and a science. Tools are essential, but understanding how and when to use them is even more important.

### 🧱 Attack Platforms
- **Kali Linux**: The de facto standard, includes all major tools. Use `apt install kali-linux-web`.
- **Parrot OS**: Lightweight alternative to Kali.
- **Security542 Linux VM**: Preconfigured by the course authors, including Burp Suite, ZAP, vulnerable web apps, etc.

### 🌐 Browsers
Browsers are more than viewers—they’re analysis tools:
- **Firefox** and **Chromium** are preferred due to support for extensions and developer tools.
- Configure your browser to disable features like XSS protection when testing.
- Extensions: HTTP Header Live, Cookie Manager, User-Agent Switcher, etc.

### 🤖 Scanners (DAST)
Used to identify surface-level issues quickly:
- **ZAP**: Free and open-source, great for learning.
- **Burp Suite Pro**: Industry standard, especially with Intruder and Repeater.
- **Nikto, Arachni, Invicti (Netsparker)**: More specialized use cases.

---

## 🔄 Interception Proxies: MITM for the Web

These proxies intercept HTTP/S requests between the browser and the server:
- Enable viewing and modifying every request/response
- Core to manual testing and fuzzing
- Examples: **Burp Suite**, **OWASP ZAP**

### 📌 Configuration Steps:
1. Launch Burp or ZAP
2. Configure your browser to send traffic through `127.0.0.1:8080`
3. Install Burp/ZAP’s certificate to avoid HTTPS errors
4. Visit a website and observe traffic in real time
5. Modify requests (headers, parameters) and replay them

> Interception proxies are indispensable for identifying subtle vulnerabilities like logic flaws, privilege escalation, and input validation issues.

---

## 🌐 Open Source Intelligence (OSINT)

OSINT is passive reconnaissance—gathering intelligence without touching the target system directly.

### 🔍 What You Can Discover:
- Domain registrants (WHOIS)
- Subdomains (crt.sh, DNS Dumpster)
- Code leaks (GitHub, Pastebin)
- Public misconfigurations (e.g., `.git/`, `.env`)

### 🛠️ Tools for OSINT:
- `theHarvester`: Collects emails, subdomains, IPs
- `Amass`: Powerful subdomain enumeration
- `Shodan`: Finds internet-connected devices with banners
- Google Dorking:
  ```
  site:example.com inurl:admin
  filetype:env
  ```

---

## 🏠 Virtual Host Discovery

Modern web servers often use virtual hosting to serve multiple domains from one IP:
- These domains may not be advertised
- Discovering them reveals hidden apps, staging areas, admin portals

### 🔧 Discovery Techniques
- Brute-force subdomains using `ffuf`, `dnsenum`, `dnsrecon`
- Certificate analysis via `crt.sh` or `censys.io`
- Header inspection via tools like `whatweb` or `curl -I`

---

## 📨 HTTP Syntax and Semantics

Understanding HTTP is essential for:
- Crafting payloads
- Interpreting application behavior
- Debugging and exploiting

### Request Anatomy:
```
POST /login HTTP/1.1
Host: vulnerable.site
Content-Type: application/x-www-form-urlencoded
Cookie: sessionid=abcd
```

### Response Anatomy:
```
HTTP/1.1 200 OK
Set-Cookie: sessionid=abcd; HttpOnly
```

Key concepts:
- Methods: GET, POST, PUT, DELETE
- Headers: Authorization, Cookie, User-Agent
- Status codes: 200 (OK), 302 (Redirect), 403 (Forbidden), 500 (Server Error)

---

## 🔐 HTTPS and Cipher Testing

### Why Test HTTPS?
- TLS/SSL protects sensitive traffic—unless misconfigured
- Insecure ciphers can be exploited by man-in-the-middle attacks

### 🧪 Tools:
- `testssl.sh`: CLI scanner for supported ciphers, protocols
- `nmap` with `ssl-*` scripts
- SSL Labs (online scan)

### 📌 Exercise: Cipher Analysis
```bash
testssl.sh https://example.com
```

Look for:
- Deprecated protocols (SSLv3, TLS 1.0)
- Weak ciphers (RC4, NULL)
- Certificate errors (expired, self-signed)

---

## 🧭 Target Profiling

This step combines all previous efforts:
- Identify web server software (Apache, nginx, IIS)
- Frameworks used (Laravel, Django, React, etc.)
- Detect APIs, endpoints, hidden directories

### Tools:
- `whatweb`, `wappalyzer`: Fingerprint tech stack
- `dirbuster`, `ffuf`: Brute-force directory discovery
- `burp sitemap`, browser dev tools

---

## 🧪 Bonus: Heartbleed Exploitation

Heartbleed (CVE-2014-0160) was a critical OpenSSL flaw that allowed attackers to extract memory from servers:
- Affects services using OpenSSL with heartbeat enabled
- Use only in labs or with explicit permission

### 🔧 Example:
```bash
nmap -sV --script ssl-heartbleed -p 443 vulnerable.host
```

---

## 🧠 Summary

This module covered:
- Why web application security matters
- Different assessment methodologies (OWASP WSTG, PTES)
- How to build your testing toolkit
- Passive and active information gathering
- HTTPS and HTTP analysis
- Practical exercises on proxies, discovery, and cipher analysis

You are now equipped to begin enumerating and analyzing web applications from a penetration tester’s perspective.

👉 Up next: **XSS and Client-Side Attacks**