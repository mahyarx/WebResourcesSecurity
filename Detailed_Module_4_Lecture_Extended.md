# 💉 Module 4: SQL Injection (SQLi) and Cross-Site Request Forgery (XSRF/CSRF) – Extended Lecture

This module explores two of the most impactful vulnerabilities in web application security: **SQL Injection (SQLi)**, a direct attack on databases, and **Cross-Site Request Forgery (XSRF or CSRF)**, which abuses browser trust to execute unauthorized actions.

---

## 🎯 Learning Objectives

By the end of this module, students will be able to:

- Understand the mechanics and types of SQL Injection attacks
- Test for and exploit SQLi vulnerabilities using manual techniques and automated tools
- Understand and exploit Cross-Site Request Forgery (CSRF) vulnerabilities
- Identify CSRF weaknesses and implement effective prevention techniques
- Apply critical thinking to analyze attack vectors and defense strategies for both SQLi and CSRF

---

## 📚 Part 1: SQL Injection (SQLi)

### ❓ What is SQLi?
**SQL Injection** is a technique where an attacker manipulates SQL queries by injecting malicious SQL code via input fields, URLs, or HTTP headers.

> It exploits improper input sanitization, allowing attackers to read or alter sensitive data, bypass authentication, or even gain system access.

---

## 🔎 Types of SQL Injection

### 1. **Error-Based SQLi**
- Injected query causes a database error that reveals details.
- Example:
  ```
  ' OR 1=1 --
  ```

### 2. **Union-Based SQLi**
- Combines two SELECT queries to extract data from other tables.
- Example:
  ```
  ' UNION SELECT username, password FROM users --
  ```

### 3. **Blind SQLi**
- Server doesn’t return error messages, but changes in behavior can be observed.
- **Boolean-Based**:
  ```
  ' AND 1=1 --
  ' AND 1=2 --
  ```
- **Time-Based**:
  ```
  ' OR IF(1=1, SLEEP(5), 0) --
  ```

### 4. **Out-of-Band SQLi**
- Data is sent via alternative channels (DNS, HTTP callbacks)
- Rare but useful in restrictive environments

---

## 🧪 SQLi Testing and Exploitation

### 🔧 Manual Testing
- Test all inputs: forms, URLs, cookies, headers
- Use payloads like:
  ```
  ' OR 'a'='a
  ' UNION SELECT NULL, NULL --
  ```

### 🛠️ Tools
- **Burp Suite** (Repeater, Intruder)
- **sqlmap**: Powerful automated SQLi tool
- `curl` + crafted payloads for manual testing

### ⚙️ sqlmap Usage Example
```bash
sqlmap -u "https://target.com/page?id=1" --dbs
```

---

## 🛡️ SQLi Prevention Techniques

- **Use Prepared Statements / Parameterized Queries**:
  ```python
  cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
  ```
- **Sanitize and Validate Input**: Ensure input conforms to expected type and format.
- **Use ORM Safely**: Prevent unsafe dynamic query generation.
- **Minimal Privilege**: Application users should have limited database access.

---

## 🧪 SQLi Exercises

1. Test login forms for `' OR 1=1 --`
2. Use `sqlmap` to extract database names and user tables
3. Perform UNION-based SQLi to extract user emails
4. Craft time-based payloads and observe server delays

---

## 🔁 Part 2: Cross-Site Request Forgery (XSRF/CSRF)

### ❓ What is CSRF?

**CSRF** is an attack that tricks an authenticated user into performing unintended actions on a web application.

> “The attacker doesn’t need your password — just your session cookie.”

---

## 🔐 CSRF Attack Flow

1. Victim logs into a trusted website (e.g., banking site)
2. Victim visits attacker-controlled site while logged in
3. Attacker’s site submits a malicious request on behalf of the user
4. Server processes request using the existing session cookie

### Example:
```html
<img src="https://bank.com/transfer?amount=1000&to=attacker" />
```

---

## 💥 CSRF Attack Scenarios

- Change victim's email/password
- Make money transfers
- Delete resources
- Modify user roles or permissions

---

## 🧪 Detecting CSRF Vulnerabilities

- Look for state-changing operations (POST, PUT, DELETE) without CSRF tokens
- Check for lack of SameSite attribute on cookies
- Validate presence and randomness of anti-CSRF tokens

---

## 🛡️ Preventing CSRF

### ✅ Best Practices

1. **CSRF Tokens**
   - Include a unique, unpredictable token in each state-changing request
   - Token should be stored in session and checked on server

2. **SameSite Cookies**
   - `SameSite=Lax` or `SameSite=Strict` prevents cookies from being sent on cross-site requests

3. **Double Submit Cookies**
   - Send CSRF token both in a cookie and as a request parameter; verify both match

4. **Check Origin/Referer Headers**
   - Only allow requests from your own domain

---

## 🧪 CSRF Exercises

1. Create a CSRF proof-of-concept (POC) to change password/email
   ```html
   <form action="https://victim.com/change_email" method="POST">
     <input type="hidden" name="email" value="attacker@evil.com" />
     <input type="submit" value="Submit Request">
   </form>
   ```
2. Bypass CSRF protection using missing token or lack of referer checking
3. Implement CSRF protection and validate it in a test environment

---

## 📚 Summary

- **SQL Injection** targets backend databases and remains one of the most severe vulnerabilities.
- **CSRF** abuses session trust to execute unauthorized actions without needing credentials.
- Manual and automated tools help identify and exploit both flaws.
- Defense requires input validation, secure session management, and token-based verification.

Next module: **Authentication Breaking Techniques**