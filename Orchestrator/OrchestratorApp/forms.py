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

SCAN_CHOICES = [
	('existing_target', 'Existing Target'),
	('new_target', 'New target (Recon and security scan)'),
	('single_target', 'Scan against one url (With http/https)'),
	('file_target', 'Input file (Urls with http/https)'),
	('file_ip', 'Input file (Ips)')
]


class ReconForm(forms.Form):
	target = forms.CharField(label='Enter target', max_length=100)


class VulnerabilityScanForm(forms.Form):
	### Scan type selection
	scan_type = forms.CharField(label='Select scan type', widget=forms.Select(choices=SCAN_CHOICES,
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
	input_file_name = forms.FileField(label='Input file', required=False)
	# div_name = file_ip_target_choice_div
	input_ip_file_name = forms.FileField(label='Input file', required=False)

	use_active_modules = forms.BooleanField(required=False, initial=True, label='Invasive modules',
											help_text= "Enables intrusive nmap scripts (SSH/FTP/Default login)")
	use_nessus_scan = forms.BooleanField(required=False, initial=True, label='Nessus scan',
											help_text= "Launchs a Black Box nessus scan")
	use_acunetix_scan = forms.BooleanField(required=False, initial=True, label='Acunetix scan',
											help_text= "Launchs a Black Box acunetix scan")
	### Email selection
	checkbox_email = forms.BooleanField(label='Email notification ', required=False, initial=False,
	 widget=forms.CheckboxInput(attrs={"onchange":'enable_checkbox_div(\'id_checkbox_email\', \'email_div\' )'}))
	## div_name = email_div
	email = forms.CharField(label='Enter email here: ', required=False)

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

	REDMINE_PROJ_CHOICES = redmine.get_project_names()
	redmine_project = forms.CharField(label='Redmine project', widget=forms.Select(choices=REDMINE_PROJ_CHOICES), required=False)
	redmine_users = redmine.get_users()
	assigned_users = forms.MultipleChoiceField(widget=forms.SelectMultiple, choices=redmine_users,
											   label='Assigned to', help_text='Provide only 1 user',
											   required=False)
	watcher_users = forms.MultipleChoiceField(widget=forms.SelectMultiple, choices=redmine_users,
											   label='Watchers', help_text='1 or more users',
											   required=False)



