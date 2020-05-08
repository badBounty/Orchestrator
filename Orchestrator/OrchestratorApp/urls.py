from django.urls import path

from . import views

app_name = 'OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('recon/', views.recon_view, name='recon'),
    path('baseline_scan/', views.baseline_scan_view, name='baseline_scan'),
    path('scan_with_email/', views.email_scan_view, name='scan_with_email'),
    path('workspaces/', views.show_workspaces, name='workspaces'),
    path('workspaces/<str:target_name>', views.show_workspace, name='workspace'),
    path('vulnerabilities', views.show_vulns, name='vulnerabilities'),
    path('vulnerabilities/<str:target_name>', views.show_project_vulns, name='project_vulns'),
    path('slack_in', views.slack_input, name='slack_in'),
    path('reporting', views.reporting_view, name='reporting')
]