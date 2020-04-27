from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from .forms import ReconForm

from .src.mongo import mongo
from .src.slack import slack_receiver
from .src.recon import nmap
from .src.comms import download
from .tasks import recon_task, nmap_task, aquatone_task
from .__init__ import slack_web_client

import json



def newIndex(request):
    return render(request, 'Orchestrator/newBase.html')


def index(request):
    return render(request, 'Orchestrator/base.html')


def show_workspaces(request):
    target = mongo.get_targets()
    return render(request, 'Orchestrator/workspaces_view.html', {'object_list': target})


def show_workspace(request, target_name):
    resources = mongo.get_workspace_resources(target_name)
    if request.method == 'POST':
        response = download.get_workspace_csv(request.path, resources)
        return response
    return render(request, 'Orchestrator/single_workspace_view.html', {'object_list': resources})


# Form handling #
def recon_view(request):
    if request.method == 'POST':
        form = ReconForm(request.POST)
        if form.is_valid():
            target_name = form.cleaned_data['target']
            recon_task.delay(target_name)
            nmap_task.delay(target_name)
            aquatone_task.delay(target_name)
            return redirect('/')
    form = ReconForm()
    return render(request, 'Orchestrator/recon_view.html', {'form': form})


# Bot token
@csrf_exempt
@require_POST
def slack_input(request):
    data = request.body
    data = json.loads(data.decode())
    if 'challenge' in data:
        return JsonResponse({'challenge': data})
    slack_web_client.chat_postMessage(channel='#orchestrator', text=str('Message received! processing...'))
    try:
        #response = slack_receiver.receive_bot_message(data)
        print('Sthelse')
    except RuntimeError:
        pass
    return HttpResponse(status=200)
