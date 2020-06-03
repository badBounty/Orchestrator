from django.forms import ModelForm
from django import forms
from .src.mongo import mongo
from .src import constants
from .src.redmine import redmine

LANGUAGE_CHOICES = [
	(constants.LANGUAGE_ENGLISH, 'English'),
	(constants.LANGUAGE_SPANISH, 'Spanish')
]

REPORT_CHOICES = [
	('F', 'Final'),
	('S', 'Status')
]

SCAN_CHOINCES = [
	('existing_target', 'Existing Target'),
	('new_target', 'New target (Recon and security scan)'),
	('single_target', 'Scan against one url (With http/https)'),
	('file_target', 'Input file (Urls with http/https)')
]


class ReconForm(forms.Form):
	target = forms.CharField(label='Enter target', max_length=100)


class BaselineScanForm(forms.Form):
	targets = mongo.get_targets()
	target_list = list()
	for available_target in targets:
		target_list.append((available_target, available_target))

	target_list.append(('url_target', 'Single URL'))
	target_list.append(('new_target', 'Target (Will run recon and vuln scan)'))

	# target = forms.CharField(max_length=20)
	target = forms.CharField(label='Select target', widget=forms.Select(choices=target_list))
	single_url = forms.CharField(label='For single url /  new target', max_length=50, required=False)
	selected_language = forms.CharField(label='Select language', widget=forms.Select(choices=LANGUAGE_CHOICES))


class ReportForm(forms.Form):
	targets = mongo.get_targets_with_vulns()
	target_list = list()
	for available_target in targets:
		target_list.append((available_target, available_target))

	client = forms.CharField(label='Client name', max_length=20)
	target = forms.CharField(label='Vulns from', widget=forms.Select(choices=target_list))
	report_type = forms.CharField(label='Select report type', widget=forms.Select(choices=REPORT_CHOICES))
	selected_language = forms.CharField(label='Select language', widget=forms.Select(choices=LANGUAGE_CHOICES))


class EmailForm(forms.Form):
	email = forms.CharField(label='email To', max_length=30)
	target = forms.CharField(label='Target(Single URL)', max_length=50, required=False)

	use_active_modules = forms.BooleanField(required=False, initial=True, label='Invasive modules',
											help_text= "Enables intrusive nmap scripts (SSH/FTP/Default login)")

	report_type = forms.CharField(label='Select report type', widget=forms.Select(choices=REPORT_CHOICES))
	selected_language = forms.CharField(label='Select language', widget=forms.Select(choices=LANGUAGE_CHOICES))
	REDMINE_PROJ_CHOICES = redmine.get_project_names()
	REDMINE_PROJ_CHOICES.append(('no_project', 'No upload'))
	redmine_project = forms.CharField(label='Redmine project', widget=forms.Select(choices=REDMINE_PROJ_CHOICES))

	redmine_users = redmine.get_users()
	assigned_users = forms.MultipleChoiceField(widget=forms.SelectMultiple, choices=redmine_users,
											   label='Assigned to', help_text='Provide only 1 user')
	watcher_users = forms.MultipleChoiceField(widget=forms.SelectMultiple, choices=redmine_users,
											   label='Watchers', help_text='1 or more users')


class TargetScanForm(forms.Form):
	targets = mongo.get_targets()
	target_list = list()
	for available_target in targets:
		target_list.append((available_target, available_target))

	target_list.append(('file_target', 'File Input'))
	target_list.append(('new_target', 'Target (Will run recon and vuln scan)'))
	target = forms.CharField(label='Select target', widget=forms.Select(choices=target_list))

	target_url = forms.CharField(label='If new target selected', max_length=50, required=False)

	file = forms.FileField(label='If file input selected', required=False)

	selected_language = forms.CharField(label='Select language', widget=forms.Select(choices=LANGUAGE_CHOICES))
	use_active_modules = forms.BooleanField(required=False, initial=True, label='Invasive modules',
											help_text= "Enables intrusive nmap scripts (SSH/FTP/Default login)")



class TestForm(forms.Form):
	### Scan type selection
	scan_type = forms.CharField(label='Select scan type', widget=forms.Select(choices=SCAN_CHOINCES,
	attrs={'onchange':'enable_scan_type_div(\'id_scan_type\')'}))
	## div_name = scan_choice_div
	## When a choice is selected, it will become required
	existing_targets = mongo.get_targets()
	existing_targets_list = list()
	for available_target in existing_targets:
		existing_targets_list.append((available_target, available_target))
	# div_name = existing_target_choice_div
	existing_target_choice = forms.CharField(label='Select existing target', 
		widget=forms.Select(choices=existing_targets_list), required=False)
	# div_name = new_target_choice_div
	new_target_choice = forms.CharField(label='New target', required=False)
	# div_name = single_target_choice_div
	single_target_choice = forms.CharField(label='New url (http/https)', required=False)
	# div_name = file_target_choice_div
	file_target_choice = forms.FileField(label='Input file', required=False)

	### Email selection
	checkbox_email = forms.BooleanField(label='Email notification ', required=False, initial=False,
	 widget=forms.CheckboxInput(attrs={"onchange":'enable_checkbox_div(\'id_checkbox_email\', \'email_div\' )'}))
	## div_name = email_div
	some_text = forms.CharField(label='Enter email here: ', required=False)

	### Report selection
	checkbox_report = forms.BooleanField(label='Report (requires email) ', required=False, initial=False,
	 widget=forms.CheckboxInput(attrs={"onchange":'enable_checkbox_div(\'id_checkbox_report\', \'report_div\' )'}))
	
	## div_name = report_div
	report_type = forms.CharField(label='Select report type', widget=forms.Select(choices=REPORT_CHOICES), required=False)
	selected_language = forms.CharField(label='Select language', widget=forms.Select(choices=LANGUAGE_CHOICES), required=False)
	
	### Redmine information
	### This will be disabled atm until UI is changed
	checkbox_redmine = forms.BooleanField(label='Redmine ', required=False, initial=False,
	 widget=forms.CheckboxInput(attrs={"onchange":'enable_checkbox_div(\'id_checkbox_redmine\', \'redmine_div\' )'}),
	 help_text='Only projects that have the user included will appear. Same applies to users for selection')
	## div_name = redmine_div
	#redmine_url = forms.CharField(label='Redmine url', required=False)
	#redmine_username = forms.CharField(label='Redmine username', required=False)
	#redmine_password = forms.CharField(label='Redmine password', required=False)
	REDMINE_PROJ_CHOICES = redmine.get_project_names()
	redmine_project = forms.CharField(label='Redmine project', widget=forms.Select(choices=REDMINE_PROJ_CHOICES), required=False)
	redmine_users = redmine.get_users()
	assigned_users = forms.MultipleChoiceField(widget=forms.SelectMultiple, choices=redmine_users,
											   label='Assigned to', help_text='Provide only 1 user',
											   required=False)
	watcher_users = forms.MultipleChoiceField(widget=forms.SelectMultiple, choices=redmine_users,
											   label='Watchers', help_text='1 or more users',
											   required=False)
	### Slack Information
	checkbox_slack = forms.BooleanField(label='Slack notifications ', required=False, initial=False,
	 widget=forms.CheckboxInput(attrs={"onchange":'enable_checkbox_div(\'id_checkbox_slack\', \'slack_div\' )'}))
	## div_name = slack_div
	slack_token = forms.CharField(label='Slack token', required=False)


