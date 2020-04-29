from django.forms import ModelForm
from django import forms
from .src.mongo import mongo
from .src import constants

LANGUAGE_CHOICES = [
    (constants.LANGUAGE_ENGLISH, 'English'),
    (constants.LANGUAGE_SPANISH, 'Spanish')
]


class ReconForm(forms.Form):
    targets = mongo.get_targets()
    target_list = list()
    for available_target in targets:
        target_list.append((available_target, available_target))

    target_list.append(('url_target', 'Single URL'))

    # target = forms.CharField(max_length=20)
    target = forms.CharField(label='Select target', widget=forms.Select(choices=target_list))
    single_url = forms.CharField(label='For single url', max_length=20, required=False)
    selected_language = forms.CharField(label='Select language', widget=forms.Select(choices=LANGUAGE_CHOICES))
