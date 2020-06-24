from django.core.mail import EmailMessage
from datetime import datetime
import json
import os
from Orchestrator.settings import email_config

def send_email(file_dir,missing_findings,email_to):
	if not email_config['HOST_USER']:
		print("Couldn't seend email, email user not configurated")
		return
	message="Doc with findings attached to mail\n"
	message+="The following findings were not found in the KB:\n"
	for finding in missing_findings:
		message+=finding['title']+'\n'
		if finding['extra_info']:
			message+='\t'+'EXTRA INFO: '+str(finding['extra_info'])+'\n'
	email = EmailMessage("Orchestator: Vuls finded", message, settings['HOST_USER'], [email_to])
	email.attach_file(file_dir)
	email.send()
	print("An email has been send succesfully at:"+str(datetime.now()))

def send_notification_email(findings,email_to):
	if not settings['HOST_USER']:
		print("Couldn't seend email, email user not configurated")
		return