from django.core.mail import EmailMessage
from datetime import datetime
import json
import os

def send_email(file_dir,missing_findings,email_to):
	message="Doc with findings attached to mail\n"
	message+="The following findings were not found in the KB:\n"
	for finding in missing_findings:
		message+=finding['title']+'\n'
		#if finding['extra_info']:
			#message+='\t'+finding['extra_info']+'\n'
	email = EmailMessage("Orchestator: Vuls finded", message, os.getenv('EMAIL_USER'), [email_to])
	email.attach_file(file_dir)
	email.send()
	print("An email has been send succesfully at:"+str(datetime.now()))
