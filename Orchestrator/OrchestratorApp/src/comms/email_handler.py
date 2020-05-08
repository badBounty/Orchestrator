from django.core.mail import EmailMessage
from datetime import datetime
import json, ast
import os


def send_email(vulns, email_to):
	message=""
	finals=""
	message+="Target: "+vulns[0]['target_name']+'\n'
	for vul in vulns:
		message+="\t Vulnerability: "+vul['vulnerability_name']+'\n'
		if vul['extra_info'] != None :
			message+="\t\t Libraries: \n"
			for info in ast.literal_eval(vul['extra_info']):
				info_title= "Name: "+info['name']
				version = info['versions'][0] if info['versions'] else ""
				last_version = info['last_version']
				if version or last_version:
					info_title+=' Version: '+version+' Last Version :'+last_version
				message+="\t\t\t"+info_title+'\n'
				for cve in info['cves']:
					cve_info='CVE ID: '+cve['CVE ID']+' - Vulnerability: '+cve['Vulnerability Type(s)']+'- CVSS Score: '+cve['Score']
					message+="\t\t\t\t"+cve_info+'\n'
	email = EmailMessage("Orchestator: Vuls finded", message, os.getenv('EMAIL_USER'), [email_to])
	email.send()
	print("An email has been send succesfully at:"+str(datetime.now()))
