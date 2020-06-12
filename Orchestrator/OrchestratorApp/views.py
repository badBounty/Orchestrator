from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, FileResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .forms import VulnerabilityScanForm, ReconForm

from .src.mongo import mongo
from .src.slack import slack_receiver
from .src.recon import recon_handler
from .src.comms import download
from .src.reporting import reporting
from .src.security import vuln_scan_handler

from .__init__ import slack_web_client

import json
import os
import uuid

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

def vuln_scan_view(request):
    # Form handle
    if request.method == 'POST':
        form = VulnerabilityScanForm(request.POST, request.FILES)
        if form.is_valid():
            if form.cleaned_data['scan_type'] == 'file_target':
                vuln_scan_handler.handle_url_file(form.cleaned_data, request.FILES['input_file_name'])
            elif form.cleaned_data['scan_type'] == 'file_ip':
                vuln_scan_handler.handle_ip_file(form.cleaned_data, request.FILES['input_ip_file_name'])
            else:
                vuln_scan_handler.handle(form.cleaned_data)
            return redirect('/')
    form = VulnerabilityScanForm()
    return render(request, 'Orchestrator/vulnerability_scan_form.html', {'form': form})

@csrf_exempt
@require_POST
def one_shot_scan(request):
    if request.method == 'POST':
        scan = json.loads(request.body)
        if scan['scan_type'] == 'file_target' or scan['scan_type'] == 'file_ip':
            vuln_scan_handler.handle_url_ip_file(scan)
        else:
            vuln_scan_handler.handle(scan)
        return JsonResponse({'message': 'Running scan'})
    return JsonResponse({'message': 'Bad format json'})
