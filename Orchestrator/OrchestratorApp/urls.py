from django.urls import path

from . import views

app_name = 'OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('recon/', views.recon_view, name='recon'),
    path('workspaces/', views.show_workspaces, name='workspaces'),
    path('workspaces/<str:target_name>', views.show_workspace, name='workspace'),
    path('vulnerabilities', views.show_vulns, name='vulnerabilities'),
    path('vulnerabilities/<str:target_name>', views.show_project_vulns, name='project_vulns'),
    path('slack_in', views.slack_input, name='slack_in'),
    path('vulnerability_scan/', views.vuln_scan_view, name='vulnerability_scan'),
    path('one_shot_scan',views.one_shot_scan,name='one_shot_scan')
]