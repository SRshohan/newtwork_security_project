# Secure Web Authentication System


## Objective
Develop a secure web authentication system that enhances both user experience and security for professional websites.

## Functionalities and Library Roles

### Backend Libraries
- **bcrypt**: Utilized for hashing and salting passwords. This library helps securely store passwords in the database, making them resistant to brute force attacks.
- **cryptography**: Implements encryption and decryption functionalities to ensure data confidentiality and integrity.
- **db-sqlite3**: Manages local storage of user data in a SQLite database, offering a lightweight, yet robust option for handling relational data.
- **python-dotenv**: Facilitates the management of environment variables, keeping sensitive information such as database configurations and API keys secure.

### Frontend
- **Streamlit**: Employs this library to build the frontend interface. Streamlit simplifies the creation of interactive, web-based user interfaces for Python applications.

### Additional Libraries
- **pyotp**: Integrates time-based One-Time Password (TOTP) for Two-Factor Authentication (2FA), enhancing user login security.
- **qrcode**: Generates QR codes necessary for setting up TOTP in authentication applications like Google Authenticator.
- **watchdog**: Monitors the file system for changes, useful for real-time alerting or other reactive programming scenarios.

### Mobile Authentication
- **Google Authenticator**: Users are required to install this app to interact with the QR codes and generate TOTPs as part of the 2FA process.

## Technology Stack
- **Backend**: Python
- **Frontend**: Streamlit
- **Libraries**: bcrypt, pyotp, qrcode, watchdog, cryptography, db-sqlite3, python-dotenv

## Getting Started

### Prerequisites
- Python 3.8 or higher
- Google Authenticator app installed on your mobile device for 2FA

### Environment Setup

#### For Windows
1. Install virtualenv if not already installed:
   ```bash
   pip install virtualenv


### For macOS Setup:

```markdown
# Secure Web Authentication System

## Getting Started - macOS

### Prerequisites
- Ensure you have Python 3.8 or higher installed on your machine. Python can be installed via [python.org](https://www.python.org/downloads/) or using Homebrew:
  ```bash
  brew install python


### For macOS Setup:

```markdown
# Secure Web Authentication System

## Getting Started - macOS

### Prerequisites
- Ensure you have Python 3.8 or higher installed on your machine. Python can be installed via [python.org](https://www.python.org/downloads/) or using Homebrew:


brew install python


python3 -m venv venv

        or

source venv/bin/activate


### Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/SRshohan/newtwork_security_project.git
cd yourrepository
pip install -r requirements.txt
          or
pip3 install -r requirements.txt

# To Run the application
streamlit run app.py