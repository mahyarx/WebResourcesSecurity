# Module 5: Authentication Breaking Techniques

This module focuses on weaknesses in authentication mechanisms and how attackers bypass them using a range of techniques including brute force, session fixation, token manipulation, and logic flaws.

---

## 🔐 Authentication Overview

### 🔑 What is Authentication?
Authentication is the process of verifying the identity of a user, typically using a combination of:
- Something you know (password)
- Something you have (token or device)
- Something you are (biometric)

---

## ⚠️ Common Authentication Weaknesses

### 1. **Credential Stuffing**
- Reuse of stolen credentials from other breaches
- Often automated using tools like Hydra, Burp Intruder

### 2. **Brute Force & Dictionary Attacks**
- Trying many passwords until the correct one is found
- Exploits weak or common passwords, or lack of rate limiting

### 3. **Password Reset Flaws**
- Insecure reset mechanisms (e.g., predictable tokens, email-only reset)
- Attacker can gain control of user account

### 4. **Session Fixation**
- Attacker sets a known session ID before login
- After the victim logs in, the attacker uses the same session ID

### 5. **Token Prediction or Manipulation**
- Guessing or modifying authentication tokens (e.g., JWTs, cookies)
- Especially dangerous if not signed or validated properly

---

## 🔍 Testing Authentication Security

### 🛠️ Tools
- Burp Suite Intruder
- OWASP ZAP
- Hydra (for brute force)
- wfuzz, curl, Postman

### 🧪 Manual Techniques
- Analyze login flow
- Inspect cookies and tokens
- Test password reset flows
- Try session fixation and token reuse

---

## 🔁 Multi-Factor Authentication (MFA)

### ✅ Benefits
- Significantly reduces risk from stolen credentials

### ⚠️ Weak MFA Implementations
- Bypassable via session hijacking, phishing, or insecure verification

---

## 🛡️ Defending Authentication Systems

- Use strong password policies + allow only verified email domains
- Implement account lockout or delay after failed attempts
- Use secure session management (rotate IDs after login)
- Store passwords securely (bcrypt, scrypt, Argon2)
- Enforce MFA and device verification

---

## 🔓 Logic Flaws in Authentication

- Bypass by changing HTTP method (e.g., GET → POST)
- Incomplete validation (e.g., user role not checked)
- Misuse of “remember me” or auto-login tokens

---

## 🧪 Exercises

1. **Brute force login page using Burp Intruder or Hydra**
2. **Check for weak password reset workflows**
3. **Try session fixation on a test app**
4. **Analyze cookie/token structure and test for manipulation**
5. **Find and exploit logic flaws in auth flows**

---

## 📋 Summary

- Authentication is a critical control that’s often poorly implemented.
- Attacks range from brute-force to complex logic flaw exploits.
- Strong token handling, password management, and MFA can mitigate most risks.
- Always test login, registration, and session management rigorously.