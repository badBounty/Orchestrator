from django.http import HttpResponse, HttpResponseRedirect, JsonResponse, FileResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from .forms import ReconForm, ReportForm, EmailForm, TargetScanForm, TestForm

from .src.mongo import mongo
from .src.slack import slack_receiver
from .src.recon import recon_handler
from .src.comms import download
from .src.reporting import reporting
from .src.security import vuln_scan_handler

from .tasks import recon_and_vuln_scan_task

from .__init__ import slack_web_client

import json
import os


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


def target_scan_view(request):
    target = mongo.get_targets()
    if request.method == 'POST':
        form = TargetScanForm(request.POST, request.FILES)
        if form.is_valid():
            if form.cleaned_data['target'] == 'file_target':
                output_dir = handle_uploaded_file(request.FILES['file'])
                vuln_scan_handler.handle_file_target_scan(form.cleaned_data, output_dir)
            elif form.cleaned_data['target'] == 'new_target':
                print('Im here')
                vuln_scan_handler.handle_new_target_scan(form.cleaned_data)
            else:
                vuln_scan_handler.handle_target_scan(form.cleaned_data)
            return redirect('/')
    form = TargetScanForm()
    return render(request, 'Orchestrator/baseline_targets_view.html', {'object_list': target, 'form': form})

def handle_uploaded_file(f):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR + 'input_file.txt'
    with open(OUTPUT_DIR, 'wb+') as destination:
        for chunk in f.chunks():
            destination.write(chunk)
    return OUTPUT_DIR

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


'''### REPORTING ###
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
    return render(request, 'Orchestrator/reporting_view.html', {'object_list': target, 'form': form})'''


### EMAIL ###
def email_scan_view(request):
    # Form handle
    if request.method == 'POST':
        form = EmailForm(request.POST)
        if form.is_valid():
            vuln_scan_handler.handle_scan_with_email_notification(form.cleaned_data)
            return redirect('/')
    form = EmailForm()
    return render(request, 'Orchestrator/single_with_email_view.html', {'form': form})


def test_view(request):
    # Form handle
    if request.method == 'POST':
        form = TestForm(request.POST)
        if form.is_valid():
            print(form.cleaned_data)
            return redirect('/')
    form = TestForm()
    return render(request, 'Orchestrator/test_form.html', {'form': form})
