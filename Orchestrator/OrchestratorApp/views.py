from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, FileResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .forms import BaselineScanForm, ReconForm, ReportForm, EmailForm

from .src.mongo import mongo
from .src.slack import slack_receiver
from .src.recon import recon_handler
from .src.comms import download
from .src.reporting import reporting
from .src.security import vuln_scan_handler

from .tasks import recon_and_vuln_scan_task

from .__init__ import slack_web_client

import json


def newIndex(request):
    return render(request, 'Orchestrator/newBase.html')


def index(request):
    return render(request, 'Orchestrator/base.html')


#### RECON ####
def show_workspaces(request):
    target = mongo.get_targets()
    return render(request, 'Orchestrator/workspaces_view.html', {'object_list': target})


def show_workspace(request, target_name):
    resources = mongo.get_workspace_resources(target_name)
    if request.method == 'POST':
        response = download.get_workspace_csv(request.path, resources)
        return response
    return render(request, 'Orchestrator/single_workspace_view.html', {'object_list': resources})


def recon_view(request):
    if request.method == 'POST':
        form = ReconForm(request.POST)
        if form.is_valid():
            target_name = form.cleaned_data['target']
            recon_handler.handle_recon(target_name)
            return redirect('/')
    form = ReconForm()
    return render(request, 'Orchestrator/recon_view.html', {'form': form})


#### BASELINE ####
def show_vulns(request):
    target = mongo.get_targets()
    return render(request, 'Orchestrator/vulns_view.html', {'object_list': target})


def show_project_vulns(request, target_name):
    resources = mongo.get_vulns_from_target(target_name)
    if request.method == 'POST':
        response = download.get_workspace_csv(request.path, resources)
        return response
    return render(request, 'Orchestrator/single_vulns_view.html', {'object_list': resources})

'''
def baseline_scan_view(request):
    target = mongo.get_targets()
    if request.method == 'POST':
        form = BaselineScanForm(request.POST)
        if form.is_valid():
            selected_target = form.cleaned_data['target']
            if selected_target == 'url_target':
                vuln_scan_handler.handle_url_baseline_security_scan(form.cleaned_data['single_url'], form.cleaned_data['selected_language'])
            elif selected_target == 'new_target':
                recon_and_vuln_scan_task.delay(form.cleaned_data['single_url'], form.cleaned_data['selected_language'])
            else:
                vuln_scan_handler.handle_target_baseline_security_scan(selected_target, form.cleaned_data['selected_language'])
            return redirect('/')
    form = BaselineScanForm()
    return render(request, 'Orchestrator/baseline_targets_view.html', {'object_list': target, 'form': form})
'''

### SLACK ###
@csrf_exempt
@require_POST
def slack_input(request):
    data = request.body
    data = json.loads(data.decode())
    if 'challenge' in data:
        return JsonResponse({'challenge': data})
    slack_web_client.chat_postMessage(channel='#orchestrator', text=str('Message received! processing...'))
    try:
        response = slack_receiver.receive_bot_message(data)
    except RuntimeError:
        pass
    return HttpResponse(status=200)


### REPORTING ###
def reporting_view(request):
    target = mongo.get_targets_with_vulns()
    if request.method == 'POST':
        form = ReportForm(request.POST)
        if form.is_valid():
            selected_target = form.cleaned_data['target']
            client = form.cleaned_data['client']
            language = form.cleaned_data['selected_language']
            report_type = form.cleaned_data['report_type']
            file_dir,missing_finding = reporting.create_report(client, language, report_type, selected_target)
            return FileResponse(open(file_dir, 'rb'))
    form = ReportForm()
    return render(request, 'Orchestrator/reporting_view.html', {'object_list': target, 'form': form})


### EMAIL ###
def email_scan_view(request):
    # Form handle
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            target = form.cleaned_data['target']
            language = form.cleaned_data['selected_language']
            report_type = form.cleaned_data['report_type']
            redmine_project_name = form.cleaned_data['redmine_project']
            active_modules = form.cleaned_data['use_active_modules']
            vuln_scan_handler.handle_scan_with_email_notification(email, target, language,
                                                                  report_type, redmine_project_name,
                                                                  active_modules)
            return redirect('/')
    form = EmailForm()
    return render(request, 'Orchestrator/single_with_email_view.html', {'form': form})
