# BlueMedix-Security-Engineer

Vulnerability Title: SQL Injection in Login Form
Description:
A SQL Injection vulnerability was discovered in the Juice Shop application that allows an attacker to bypass authentication and retrieve sensitive user information, including email IDs and passwords.
Steps to Reproduce:
Step 1: Bypassing Authentication using SQL Injection
•	Navigate to the login page.
•	Enter the following payload in the UserID and Password fields: admin' or 1==1--
•	Click on Login.
•	The authentication is bypassed, granting access to the admin account.
Step 2: Extracting Email ID Using Burp Suite Repeater
•	Intercept the login request using Burp Suite.
•	Send the intercepted request to Repeater.
•	Observe the server response, which includes the admin's email ID.
Step 3: Finding Password Using Burp Suite Intruder
•	Send the login request to Intruder.
•	Set the payload position on the password field.
•	Use a common password list to brute-force login credentials.
•	The correct password, admin123, was identified in the response.
4. Impact:
•	Unauthorized access to the admin account.
•	Exposure of sensitive user information.
•	Potential for further exploitation, such as privilege escalation and data theft.
5. Mitigation:
•	Implement prepared statements or parameterized queries to prevent SQL Injection.
•	Use input validation and server-side filtering to restrict special characters.
•	Enforce strong authentication mechanisms like multi-factor authentication (MFA).
•	Implement rate limiting to prevent brute-force attacks.
6. Screenshots:
![image](https://github.com/user-attachments/assets/8c18a1c8-3c21-4bf6-8238-d32b98a62084)

 
 










Reflected XSS Cookie Stealing using <iframe src= javascript:alert(document.cookie);>
 

CSRF
Created a user and changed its password from “password” to “password123”

 


	
Removed the current password parameter and changed the users password to “pass123”
 



