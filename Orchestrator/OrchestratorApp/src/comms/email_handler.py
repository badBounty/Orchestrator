from django.core.mail import EmailMessage
from datetime import datetime
import json
import os

def send_email(file_dir,email_to):
	message="Doc with findings attached to mail"
	email = EmailMessage("Orchestator: Vuls finded", message, os.getenv('EMAIL_USER'), [email_to])
	email.attach_file(file_dir)
	email.send()
	print("An email has been send succesfully at:"+str(datetime.now()))
