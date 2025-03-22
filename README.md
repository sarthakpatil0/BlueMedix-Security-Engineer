# BlueMedix-Security-Engineer

Vulnerability Title: SQL Injection in Login Form
Description: A SQL Injection vulnerability was discovered in the Juice Shop application that allows an attacker to bypass authentication and retrieve sensitive user information, including email IDs and passwords.

1: Bypassing Authentication using SQL Injection
Enter the following payload in the UserID and Password fields: admin' or 1==1--. The authentication is bypassed, granting access to the admin account.

2. Extracting Email ID Using Burp Suite Repeater
Intercept the login request using Burp Suite. Send the intercepted request to Repeater.Observe the server response, which includes the admin's email ID.

3. Finding Password Using Burp Suite Intruder
Send the login request to Intruder. Set the payload position on the password field. Use a common password list to brute-force login credentials. The correct password, admin123, was identified in the response.

4. Mitigation:
Implement prepared statements or parameterized queries to prevent SQL Injection.
Use input validation and server-side filtering to restrict special characters.
Enforce strong authentication mechanisms like multi-factor authentication (MFA).
Implement rate limiting to prevent brute-force attacks.

5. Screenshots:
![Screenshot 2025-03-22 200159](https://github.com/user-attachments/assets/d227a688-b144-419b-bb13-6ccf670b4601)
![Screenshot 2025-03-22 200235](https://github.com/user-attachments/assets/f5badbfa-ea36-4fb9-a636-d98cc261bb70)


 
Vulnerability Title: Reflected XSS Cookie Stealing
Description: The OWASP Juice Shop application is vulnerable to Reflected Cross-Site Scripting (XSS), allowing an attacker to inject malicious JavaScript code into the application. When the victim visits
aspecially crafted URL, the malicious script is executed in their browser, leading to cookie theft. This could allow an attacker to hijack user sessions and impersonate victims.

1. Navigate to a search field or any other input field vulnerable to Reflected XSS. Inject the following payload in the search bar: <iframe src=javascript:alert(document.cookie);> Press Enter or submit the form.
Observe that an alert box pops up displaying the user's cookies.

2. Impact: Session Hijacking: An attacker can steal session cookies, potentially taking over user accounts.
Data Theft: Sensitive information stored in cookies can be accessed.

4. Mitigation: Input Validation: Sanitize and validate user input to remove potentially harmful code.
Content Security Policy (CSP): Implement a strong CSP to restrict the execution of inline JavaScript.
HTTPOnly Flag for Cookies: Ensure session cookies have the HttpOnly attribute set to prevent access via JavaScript.

5. Screenshots:
![Screenshot 2025-03-23 005333](https://github.com/user-attachments/assets/ca4f1b6c-b5f4-48bc-b41d-6cf299d5850d)



 
Vulnerability Title: Cross-Site Request Forgery (CSRF) - Unauthorized Password Change
Description: The OWASP Juice Shop application is vulnerable to Cross-Site Request Forgery (CSRF), allowing an attacker to modify a user's password without their consent. This occurs because the application does
not verify the authenticity of requests through anti-CSRF tokens, allowing a malicious site to submit unauthorized requests on behalf of an authenticated user.

1. User Account Creation:
Create a new user with the following credentials:
Username: test4@juice.com
Password: password

2. Password Change with CSRF:
The attacker crafts a malicious request to change the user's password to password123.
The attacker removes the current password parameter and attempts to change the user's password to pass123 without authentication.

3. Impact:
Account Takeover: Attackers can change passwords without knowing the current one.
Loss of User Control: Users may lose access to their accounts permanently.
Privilege Escalation: If performed on an admin account, an attacker could gain full control over the system.

4. Mitigation:
Implement CSRF Tokens: Use anti-CSRF tokens for all state-changing requests.
Enforce Current Password Verification: Require users to enter their current password when changing credentials.

5. Screenshots
![Screenshot 2025-03-23 013458](https://github.com/user-attachments/assets/2888fee7-606d-4a65-b941-af2e560fa69d)

![Screenshot 2025-03-23 013733](https://github.com/user-attachments/assets/61ea466d-df53-4cab-a156-d4994f78b750)

