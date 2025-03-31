# Module 4: SQL Injection (SQLi) and Cross-Site Request Forgery (XSRF/CSRF)

This module explores two powerful web attack techniques: SQL Injection (SQLi), which targets backend databases, and Cross-Site Request Forgery (XSRF/CSRF), which exploits user session trust.

---

## 🧨 SQL Injection (SQLi)

### ❓ What is SQLi?
SQL Injection is an attack technique that manipulates SQL queries through unsanitized inputs to extract, modify, or delete data from a database.

### 💥 Impact
- Unauthorized access to sensitive data
- Authentication bypass
- Full database compromise
- Remote command execution (in some cases)

---

## 🧪 Detecting SQL Injection

### 🔧 Manual Testing
Test input fields with payloads:
```sql
' OR '1'='1
' UNION SELECT NULL, version()--
```

### 🛠️ Tools
- sqlmap (automated)
- Burp Suite (Intruder, Repeater)
- sqlninja, Havij

---

## 🛡️ Preventing SQL Injection

- Use **parameterized queries** / prepared statements
- Sanitize and validate all inputs
- Avoid dynamic SQL constructions
- Use ORM frameworks securely

---

## 💉 SQLi Categories

1. **Error-Based**: Leverages database error messages
2. **Union-Based**: Extracts data using `UNION` statements
3. **Blind SQLi**:
   - **Boolean-Based**: True/false conditions
   - **Time-Based**: Use delays (`SLEEP()`) to infer results
4. **Out-of-Band**: Uses alternate channels (e.g., DNS, HTTP requests)

---

## 🧪 SQLi Exercises

- Use vulnerable forms to extract table names, column names, and data
- Try bypassing login forms with `' OR '1'='1`
- Test time-based SQLi using payloads like:
  ```sql
  ' OR IF(1=1, SLEEP(5), 0)--
  ```

---

## 🔁 Cross-Site Request Forgery (CSRF/XSRF)

### ❓ What is CSRF?
CSRF forces an authenticated user to perform unwanted actions on a web application without their consent.

### 🧠 Attack Flow
1. User logs into a website (e.g., bank)
2. Attacker sends a malicious link or form to the user
3. Browser sends request using stored session cookies
4. Server processes request as legitimate

---

## 💥 CSRF Risks

- Change user passwords or email
- Transfer money or privileges
- Perform destructive actions (e.g., delete account)

---

## 🧪 Detecting CSRF

### 🔧 Manual Checks
- Identify actions performed via GET or POST without anti-CSRF tokens
- Check if cookies are automatically included in cross-site requests

---

## 🛡️ Preventing CSRF

- Use **anti-CSRF tokens** in every state-changing request
- Ensure **SameSite=Strict** or **Lax** for session cookies
- Validate origin and referer headers (for sensitive actions)
- Use CAPTCHAs or re-authentication for critical actions

---

## 🧪 CSRF Exercises

- Craft an HTML form to perform a state-changing action on behalf of a logged-in user
- Identify and exploit actions without CSRF protection
- Implement CSRF tokens in a simple web app

---

## 📋 Summary

- SQL Injection remains one of the most dangerous vulnerabilities in web apps.
- CSRF exploits trust in a user's session and can lead to serious account manipulation.
- Both attacks require proper validation and defensive coding techniques.
- Tools like sqlmap and Burp Suite help automate and analyze these flaws.