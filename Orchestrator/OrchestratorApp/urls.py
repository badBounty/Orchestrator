from django.urls import path

from . import views

app_name = 'OrchestratorApp'
urlpatterns = [
    path('', views.index, name='index'),
    path('recon/', views.recon_view, name='recon'),
    path('baseline_scan/', views.baseline_scan_view, name='baseline_scan'),
    path('baseline_scan/<str:target_name>', views.baseline_started_view, name='baseline_against_target'),
    path('workspaces/', views.show_workspaces, name='workspaces'),
    path('workspaces/<str:target_name>', views.show_workspace, name='workspace'),
    path('newIndex', views.newIndex, name='newIndex'),
    path('slack_in', views.slack_input, name='slack_in')
]