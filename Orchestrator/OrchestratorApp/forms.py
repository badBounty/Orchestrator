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
    report_type = forms.CharField(label='Select report type', widget=forms.Select(choices=REPORT_CHOICES))
    selected_language = forms.CharField(label='Select language', widget=forms.Select(choices=LANGUAGE_CHOICES))
    REDMINE_PROJ_CHOICES = redmine.get_project_names()
    REDMINE_PROJ_CHOICES.append(('no_project', 'No upload'))
    redmine_project = forms.CharField(label='Redmine project', widget = forms.Select(choices=REDMINE_PROJ_CHOICES))