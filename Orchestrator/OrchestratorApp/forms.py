from django.forms import ModelForm
from OrchestratorApp.models import ReconProfile


class ReconForm(ModelForm):
    class Meta:
        model = ReconProfile
        fields = ['name', 'scan_mode', 'project', 'target']