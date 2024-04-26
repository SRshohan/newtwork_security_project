from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os


load_dotenv()
# Define email sender and receiver
password = os.getenv('EMAIL_PASSWORD')
# receiver = 'sohanrahman182@gmail.com'

# # Set the subject and body of the email
# server = smtplib.SMTP('smtp.gmail.com', 587)  
# server.ehlo()
# server.starttls()
# server.login(email_sender, email_password)  
# server.sendmail(email_sender, email_receiver, "Checking")  
# server.quit()



def send_emails(receiver, otp):
    message = MIMEMultipart()
    sender = 'mugleeisback@gmail.com'
    message['From'] = sender
    message['To'] = receiver
    message['Subject'] = 'Automated Email - DO NOT REPLY'

    email_password = os.getenv('EMAIL_PASSWORD')  # Email 16 digit password from the .env
    subject = "Automated Email - DO NOT REPLY"
    body = f"Your OTP is: {otp}"

    message.attach(MIMEText(body, 'plain'))


    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)  # Use 465 for SSL
        server.starttls()  # Enable security
        server.login(sender, password)  # Login with your email and password
        text = message.as_string()
        server.sendmail(sender, receiver, text)
        server.quit()
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")



