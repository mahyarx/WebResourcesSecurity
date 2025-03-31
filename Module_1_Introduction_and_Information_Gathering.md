# Module 1: Introduction and Information Gathering

This module introduces the fundamentals of web application penetration testing and covers the initial steps necessary to start an effective security assessment.

---

## 🎯 Why the Web?

Web applications are:

- Ubiquitous: used by organizations of all sizes.
- Critical: store and handle sensitive data.
- Vulnerable: often overlooked in terms of security.

**Key points:**
- Web app attacks can lead to data breaches, ransomware, or complete system compromise.
- Many developers and security professionals lack web security training.
- Understanding offensive techniques (hacking) helps improve defense strategies.

---

## 🔍 Application Assessment Methodologies

Web application penetration testing is one method among many to assess and improve the security posture of an application.

### 🧱 Security Testing Approaches
- **Threat Modeling**: Understand the app’s architecture, identify threats, and plan mitigations.
  - Key questions: What are we building? What can go wrong?
- **Code Review**: Examine source code to find logic errors and hidden vulnerabilities.
- **SAST (Static Application Security Testing)**: Automated source code analysis.
- **DAST (Dynamic Application Security Testing)**: Black-box testing on running apps.
- **Manual Review**: Interviews, architecture reviews, and documentation analysis.
- **Best Practice**: Combine automated + manual testing for deep, wide, and accurate assessments.

---

## 🧰 Web Application Pen Tester’s Toolkit

A penetration tester needs a solid toolkit:

### 🔧 Core Components
1. **Attack Platform**
   - Kali Linux with `kali-linux-web` metapackage
   - Custom Security542 Linux VM
   - macOS, Windows, or any OS you are comfortable with

2. **Browsers**
   - Prefer Chromium or Firefox for better extensions and debugging tools
   - Configure to reduce interference (e.g., disable security features temporarily for XSS testing)

3. **Dynamic Scanners**
   - Examples: Burp Suite Pro, ZAP, Nikto, Acunetix, Arachni
   - Used to quickly identify surface-level vulnerabilities

4. **Interception Proxies**
   - Bridge between browser and server to inspect/edit HTTP requests/responses
   - Tools: Burp Suite, OWASP ZAP

---

## 🌐 Interception Proxies

### 🛠️ Role in Pen Testing
- Interception proxies act as a "man-in-the-middle"
- Monitor, modify, and replay requests
- Interact manually or with scripts

### 🧪 Exercise: Configuring Proxies
- Configure browser to use proxy at `127.0.0.1:8080`
- Use Burp/ZAP to capture and analyze HTTP traffic

---

## 🛰️ Open Source Intelligence (OSINT)

Using public sources to gather intel:
- WHOIS records
- Google Dorking (advanced search queries)
- Shodan (IoT search engine)
- GitHub or Pastebin leaks

---

## 🏠 Virtual Host Discovery

Many web servers host multiple domains:
- Use DNS brute-forcing, certificate inspection, or reverse IP lookups
- Tools: `dnsmap`, `crt.sh`, `amass`

### 🧪 Exercise: Virtual Host Discovery
- Identify hidden domains served from the same IP

---

## 📨 HTTP Syntax and Semantics

Understand HTTP request and response structure:
- Methods: GET, POST, PUT, DELETE
- Headers: Host, Cookie, User-Agent, etc.
- Status Codes: 200, 301, 403, 500

---

## 🔐 HTTPS and Weak Cipher Testing

Learn to verify TLS security:
- Use tools like `testssl.sh`, `SSL Labs`, or `nmap --script ssl-*`
- Detect weak protocols (SSLv2, TLS 1.0) and cipher suites

### 🧪 Exercise: Testing HTTPS
- Scan for expired or self-signed certs
- Identify weak encryption algorithms

---

## 🧭 Target Profiling

Map out the target application:
- Identify technology stack (PHP, ASP.NET, etc.)
- Map directories and parameters
- Determine authentication methods
- Tool examples: `whatweb`, `wappalyzer`, `dirbuster`

---

## 📋 Summary

This module laid the foundation for:
- Understanding the importance of web app security
- Building your pen testing environment
- Performing reconnaissance using tools and methodologies
- Preparing for more advanced vulnerability exploitation

---

## 🧪 Bonus Exercise: Heartbleed

Optional challenge:
- Use test tools to identify Heartbleed (CVE-2014-0160) on a vulnerable server
- Practice extracting memory data via TLS heartbeat extension