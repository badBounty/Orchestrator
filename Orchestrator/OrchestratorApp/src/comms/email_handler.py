from django.core.mail import EmailMessage
from datetime import datetime
import json,ast

def send_email(file_dir,email_to):
	message="Doc with findings attached to mail"
	email = EmailMessage("Orchestator: Vuls finded","HERE",["ftavella@deloitte.com","mananderson@deloitte.com"])
	email.attach_file(file_dir)
	print("An email has been send succesfully at:"+str(datetime.now()))
	email.send()