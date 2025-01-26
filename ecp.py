import os
import base64
import time
import re
import logging
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# If modifying these SCOPES, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly',
          'https://www.googleapis.com/auth/gmail.send',
          'https://www.googleapis.com/auth/gmail.modify']

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

EMAIL_LIMIT_PER_MINUTE = 10
sent_email_count = 0
last_reset_time = time.time()

def authenticate_gmail():
    """Authenticate and return the Gmail API service."""
    creds = None
    # Check for existing token
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If no valid credentials, authenticate user
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save credentials for next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    service = build('gmail', 'v1', credentials=creds)
    return service

def fetch_emails(service, query='is:unread'): 
    """Fetch unread emails using the Gmail API."""
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])

        emails = []
        for msg in messages:
            msg_data = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = msg_data.get('payload', {}).get('headers', [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), "No Subject")
            sender = next((h['value'] for h in headers if h['name'] == 'From'), "Unknown")
            email_data = {
                'id': msg['id'],
                'snippet': msg_data['snippet'],
                'subject': subject,
                'sender': sender
            }
            emails.append(email_data)
        return emails
    except Exception as e:
        logging.error(f"Error fetching emails: {e}")
        return []

def send_email(service, to, subject, body):
    """Send an email using the Gmail API."""
    global sent_email_count, last_reset_time
    current_time = time.time()

    # Implement throttling
    if current_time - last_reset_time >= 60:
        sent_email_count = 0
        last_reset_time = current_time

    if sent_email_count >= EMAIL_LIMIT_PER_MINUTE:
        logging.warning("Email limit per minute reached. Pausing to avoid reputation issues.")
        time.sleep(60 - (current_time - last_reset_time))
        sent_email_count = 0
        last_reset_time = time.time()

    try:
        message = MIMEMultipart()
        message['to'] = to
        message['subject'] = subject
        message.attach(MIMEText(body, 'plain'))
        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        
        message = {'raw': raw_message}
        sent_message = service.users().messages().send(userId='me', body=message).execute()
        sent_email_count += 1
        logging.info(f"Email sent to {to} with subject: {subject}")
        return sent_message
    except Exception as e:
        logging.error(f"Failed to send email to {to}: {e}")
        return None

def mark_as_read(service, message_id):
    """Mark a specific email as read."""
    try:
        service.users().messages().modify(
            userId='me',
            id=message_id,
            body={'removeLabelIds': ['UNREAD']}
        ).execute()
        logging.info(f"Email {message_id} marked as read.")
    except Exception as e:
        logging.error(f"Failed to mark email {message_id} as read: {e}")

def pull_from_spam(service, message_id):
    """Move a specific email from Spam to the inbox."""
    try:
        service.users().messages().modify(
            userId='me',
            id=message_id,
            body={'removeLabelIds': ['SPAM'], 'addLabelIds': ['INBOX']}
        ).execute()
        logging.info(f"Email {message_id} moved from Spam to Inbox.")
    except Exception as e:
        logging.error(f"Failed to move email {message_id} from Spam: {e}")

def analyze_spam_keywords(email_body):
    """Analyze email content for potential spam keywords."""
    spam_keywords = ["win", "free", "prize", "money", "urgent", "offer"]
    found_keywords = [kw for kw in spam_keywords if re.search(rf"\b{kw}\b", email_body, re.IGNORECASE)]
    return found_keywords

def send_bulk_emails(service, recipients, subject, body):
    """Send bulk emails to multiple recipients."""
    for recipient in recipients:
        send_email(service, to=recipient, subject=subject, body=body)
        logging.info(f"Bulk email sent to {recipient}.")

def main():
    # Step 1: Authenticate
    service = authenticate_gmail()
    
    # Step 2: Fetch unread emails
    logging.info("Fetching unread emails...")
    emails = fetch_emails(service)
    logging.info(f"Fetched {len(emails)} unread emails.")

    for email in emails:
        logging.info(f"Subject: {email['subject']}")
        logging.info(f"Sender: {email['sender']}")
        logging.info(f"Snippet: {email['snippet']}")

        # Analyze for spam keywords
        spam_keywords = analyze_spam_keywords(email['snippet'])
        if spam_keywords:
            logging.warning(f"Spam keywords detected: {', '.join(spam_keywords)}")

        # Step 3: Send a reply (Example Reply)
        reply_body = "Thank you for reaching out! This is an automated response."
        send_email(service, to=email['sender'], subject=f"Re: {email['subject']}", body=reply_body)

        # Step 4: Mark email as read
        mark_as_read(service, email['id'])

        # Step 5: Optionally pull from spam
        if 'SPAM' in email['snippet'].upper():  # Example condition
            pull_from_spam(service, email['id'])

    # Example of bulk email sending
    bulk_recipients = ["recipient1@example.com", "recipient2@example.com"]
    send_bulk_emails(service, recipients=bulk_recipients, subject="Newsletter Update", body="This is a bulk email test.")

if __name__ == '__main__':
    main()
