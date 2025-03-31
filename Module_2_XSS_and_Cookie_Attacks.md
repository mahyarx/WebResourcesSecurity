# Module 2: XSS and Cookie Attacks

This module focuses on client-side web vulnerabilities, particularly Cross-Site Scripting (XSS) attacks and how cookies can be manipulated or stolen to hijack sessions.

---

## 🔥 Cross-Site Scripting (XSS) Overview

### ❓ What is XSS?
XSS is a vulnerability that allows attackers to inject malicious scripts into content from otherwise trusted websites.

### 🧨 Types of XSS
1. **Reflected XSS**  
   - Script is reflected off the web server (usually via query parameters)
   - Triggered immediately by a user clicking a malicious link

2. **Stored XSS**  
   - Script is stored on the server (e.g., in a database or forum)
   - Triggered when a user visits the infected page

3. **DOM-Based XSS**  
   - Occurs on the client side
   - Exploits the way JavaScript in the browser processes the DOM

### 🎯 Impact
- Session hijacking
- Credential theft
- Redirection to malicious sites
- Defacement

---

## 🔍 Detecting XSS

### 🧪 Manual Testing
- Insert payloads like:
  ```html
  <script>alert('XSS')</script>
  ```
- Try in different input fields (search bars, comment boxes, etc.)

### 🧰 Tools
- Burp Suite
- OWASP ZAP
- XSS Hunter
- DOM Invader

---

## 🛡️ Preventing XSS

### ✅ Best Practices
- Encode output (HTML, JavaScript, URL, etc.)
- Use Content Security Policy (CSP)
- Validate and sanitize user input
- Escape dynamic content in HTML templates

---

## 🍪 Cookie Attacks Overview

Cookies are used to store session data and authentication tokens. Improper handling can lead to serious security issues.

---

## 🍪 Common Cookie Vulnerabilities

1. **Cookie Theft (via XSS)**
   - Stealing session cookies with `document.cookie`

2. **Session Fixation**
   - Attacker sets a known session ID before login

3. **Insecure Cookie Attributes**
   - `HttpOnly`: Should be set to prevent JavaScript access
   - `Secure`: Ensures cookie is sent over HTTPS
   - `SameSite`: Prevents CSRF and some XSS

---

## 🧪 Testing Cookies

### 🔧 Manual Checks
- Use browser dev tools to inspect cookies
- Verify attributes (`HttpOnly`, `Secure`, `SameSite`)

### 🛠️ Automated Tools
- Burp Suite (Proxy > HTTP history > Cookies tab)
- OWASP ZAP cookie scanner

---

## 🛡️ Protecting Cookies

- Set `HttpOnly`, `Secure`, and `SameSite` attributes
- Use short expiration time for sensitive cookies
- Avoid storing sensitive data directly in cookies

---

## 🧪 Exercises

1. **Detect and exploit reflected and stored XSS**
2. **Use Burp or ZAP to monitor cookie behavior**
3. **Test a sample app with insecure cookie settings**
4. **Implement XSS mitigation using output encoding**

---

## 📋 Summary

- XSS is a powerful and common web vulnerability.
- Cookies, when mishandled, can be used to hijack sessions.
- Tools like Burp and ZAP help identify these issues.
- Applying proper encoding and cookie security flags helps mitigate these threats.