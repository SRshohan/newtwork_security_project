# Secure Web Authentication System

## Objective
Develop a secure web authentication system that enhances both user experience and security for professional websites.

## Functionalities and Library Roles

### Backend Libraries
- **bcrypt:** This library is used for hashing and salting user passwords. It provides a secure way to store passwords in the database, ensuring they are resistant to brute force attacks.
- **re (Regex):** Utilized for validating user inputs, such as ensuring password complexity requirements are met and formatting checks on emails or usernames.

### Frontend
- **Streamlit:** A Python library used to create the frontend interface for the web authentication system. Streamlit allows for quick prototyping and easy deployment of web apps, providing interactive user elements like forms and buttons for login procedures.

### Additional Libraries
- **pyotp:** Implements Two-Factor Authentication (2FA) by generating time-based one-time passwords (TOTPs). This enhances security by requiring a second form of verification beyond just the username and password.
- **SendGrid:** Used for the email-based 2FA option, sending users a one-time verification code via email which they need to enter to complete the login process.

### OpenAI API
- **OpenAI API:** Integrated to enhance security features, such as:
  - **Password Policy Enhancement:** Leverages AI models to analyze and improve password strength against common hacking techniques.
  - **Security Alerts and Notifications:** AI is used to monitor unusual sign-in attempts or anomalous behavior patterns, sending real-time alerts to users and administrators.
  - **User Behavior Analysis:** Machine learning techniques identify and alert on deviations from typical user activity, which may indicate potential security breaches.

## Technology Stack
- **Backend:** Python
- **Frontend:** Streamlit
- **Libraries:** bcrypt, re, OpenAI API

## Getting Started

### Prerequisites
- Python 3.8+
- Streamlit
- bcrypt
- pyotp
- SendGrid API key
- OpenAI API key

### Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/SRshohan/newtwork_security_project.git
cd yourrepository
pip install -r requirements.txt

# To Run the application
streamlit run app.py