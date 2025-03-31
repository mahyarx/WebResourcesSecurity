# 🔐 Module 5: Authentication Breaking Techniques – Extended Lecture

This module focuses on breaking authentication systems — a critical component of web application security. Authentication ensures that users are who they claim to be. When this process is flawed, attackers can bypass logins, hijack sessions, and gain unauthorized access to sensitive systems.

---

## 🎯 Learning Objectives

By the end of this module, students will be able to:

- Understand how authentication mechanisms work and where they fail
- Identify common authentication vulnerabilities, such as brute force, logic flaws, and session fixation
- Analyze and exploit weak password reset mechanisms
- Understand how session management affects authentication
- Apply secure design principles to strengthen authentication systems

---

## 📌 What is Authentication?

Authentication verifies the identity of a user. It's typically the first line of defense against unauthorized access.

### 🧩 Types of Authentication

- **Single-Factor**: Username and password
- **Multi-Factor (MFA)**:
  - Something you know (password)
  - Something you have (OTP token, mobile app)
  - Something you are (biometrics)

---

## 💥 Common Authentication Flaws

### 1. **Brute Force and Dictionary Attacks**
- Repeatedly guessing passwords until success
- Weak or common passwords are highly vulnerable

### 2. **Credential Stuffing**
- Attackers use leaked credentials from other breaches
- Automated tools try email/password combos against login forms

### 3. **Insecure Password Reset**
- No token expiration
- Guessable reset links (e.g., predictable IDs)
- No email verification or user validation

### 4. **Session Fixation**
- Attacker sets a known session ID and tricks victim into using it
- Server does not generate a new session upon login

### 5. **Token Tampering**
- Predictable or unsigned tokens (e.g., JWT without integrity check)
- Attacker modifies token to escalate privileges

### 6. **Logic Flaws in Login Flow**
- Bypassing authentication due to incorrect role checks
- Insecure "remember me" functionality
- Switching roles without re-authentication

---

## 🛠️ Tools for Authentication Testing

- **Burp Suite**: Intercept requests, brute force, replay tokens
- **Hydra**: Command-line brute-force tool
- **WFuzz**, **Intruder**: For login form fuzzing
- **Postman/curl**: API authentication testing

---

## 🔍 Manual Testing Techniques

### 🔓 Brute Force Example (Hydra)
```bash
hydra -L users.txt -P passwords.txt https-post-form "/login:username=^USER^&password=^PASS^:F=Incorrect"
```

### 🧪 Token Analysis
Inspect JWTs or session cookies:
```json
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```
- Decode using jwt.io or Burp Decoder
- Look for `alg: none`, missing `exp`, or role escalation

---

## 🧪 Testing Session Management

- Does session ID rotate after login?
- Are session IDs stored securely (HttpOnly, Secure, SameSite)?
- Can session hijacking be performed by stealing tokens?

---

## 🛡️ Best Practices for Authentication

### ✅ Password Security
- Enforce strong passwords (length + complexity)
- Store with secure hashing algorithms (bcrypt, Argon2)
- Block common or leaked passwords

### ✅ MFA Enforcement
- Use TOTP apps, hardware tokens, or push-based MFA
- Avoid SMS-based MFA when possible

### ✅ Session Management
- Regenerate session ID after login
- Set `HttpOnly`, `Secure`, and `SameSite=Strict` on cookies
- Set short session timeouts

### ✅ Reset Flow Protection
- Use unguessable tokens
- Require user to answer security questions or re-authenticate
- Expire tokens after short duration

---

## ⚠️ Exploiting Weak Authentication

### Case 1: Weak Password Reset
- Attacker discovers reset link has predictable token
- Uses link like:
  ```
  https://example.com/reset?token=12345
  ```

### Case 2: JWT Manipulation
- JWT is unsigned (`alg: none`)
- Attacker modifies payload to:
  ```json
  { "role": "admin" }
  ```
- Server accepts modified token and grants admin access

### Case 3: Brute Force Login
- No rate limiting or account lockout
- Attacker brute-forces login using common passwords

---

## 🧪 Lab Exercises

1. **Brute Forcing Login**
   - Use Burp Intruder or Hydra to guess credentials
2. **Session Fixation**
   - Send crafted session ID, log in, and observe if ID stays the same
3. **JWT Analysis**
   - Decode token, modify claims, and re-sign (if possible)
4. **Password Reset**
   - Explore reset flow: Is the token long, random, and short-lived?
5. **Cookie Testing**
   - Check if cookies are `Secure`, `HttpOnly`, `SameSite`

---

## 🔒 Summary

- Authentication is often targeted as the first step in compromising a web app
- Flaws in brute force protections, password resets, session handling, or logic flows can lead to unauthorized access
- Properly implemented MFA, session handling, and validation mechanisms greatly reduce risk
- Always verify edge cases and misconfigurations through manual testing

🎯 This concludes the core content of the course — you are now equipped to test, analyze, and report on a wide range of web application vulnerabilities.