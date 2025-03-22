# BlueMedix-Security-Engineer

ZAP Report : 

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
![image](https://github.com/user-attachments/assets/8c18a1c8-3c21-4bf6-8238-d32b98a62084)
![image](https://github.com/user-attachments/assets/abb0c4f1-3569-4ac2-9ac8-af245191897b)


 
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
![image](https://github.com/user-attachments/assets/324956b0-ea9a-4c41-8eed-efc4a59d8837)


 
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
![image](https://github.com/user-attachments/assets/b0852aeb-4ee5-48be-b951-d383f9cf7a93)
![image](https://github.com/user-attachments/assets/f7d59566-15c9-44bd-af87-e66c6f26473a)
