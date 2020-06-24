from ..slack import slack_sender
from ..mongo import mongo
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability
from Orchestrator.settings import nessus,nessus_info

import time
import requests
import uuid
import json

username = nessus_info['USER']
password = nessus_info['PASSWORD']
blacklist = nessus_info['BLACK_LIST']
verify = False
json_scan = {}
# POST - LOGIN
login_url = nessus_info['URL']+'/session'
# POST - CREATE SCAN
create_url = nessus_info['URL']+'/scans'
# STOP SCAN #TODO FINISH URL
stop_url = nessus_info['URL']
# GET - SCAN STATUS
scan_url = nessus_info['URL']+'/scans/'


def handle_target(info):
    if info['nessus_scan']:
        print('------------------- NESSUS TARGET SCAN STARTING -------------------')
        slack_sender.send_simple_message("Nessus scan started against target: %s. %d alive urls found!"
                                        % (info['target'], len(info['url_to_scan'])))
        print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
        for url in info['url_to_scan']:
            sub_info = info
            sub_info['url_to_scan'] = url
            print('Scanning ' + url)
            scan_target(sub_info)
        print('------------------- NESSUS TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_information):
    if scan_information['nessus_scan']:
        print('------------------- NESSUS SINGLE SCAN STARTING -------------------')
        slack_sender.send_simple_message("Nessus scan started against %s" % scan_information['url_to_scan'])
        scan_target(scan_information)
        print('------------------- NESSUS SINGLE SCAN FINISHED -------------------')
    return

def add_vulnerability(scan_info,json_data,header):
    description = 'Nessus scan completed against %s' % scan_info['url_to_scan'] +'\n'
    scan_id = str(json_data['info']['object_id'])
    for nessus_vuln in json_data['vulnerabilities']:
        if nessus_vuln['plugin_name'] not in blacklist:
            name = "[NESSUS SCAN] - "+ nessus_vuln['plugin_name']
            plug_id = str(nessus_vuln['plugin_id'])
            #Get full detail of the vulnerability
            r = requests.get(scan_url+scan_id+'/plugins/'+plug_id,verify=verify,headers=header)
            out_list = json.loads(r.text)['outputs']
            extra = ''
            for out in out_list:
                extra = (out['plugin_output'] if out['plugin_output'] != None else '')+'\n'
                extra +=str(out['ports'])
            vulnerability = Vulnerability(name, scan_info, description+extra)
            #slack_sender.send_simple_vuln(vulnerability)
            redmine.create_new_issue(vulnerability)
            mongo.add_vulnerability(vulnerability)
        else:
            print("Not reported: "+nessus_vuln['plugin_name']+" because is in the nessus blacklist")

def scan_target(scan_info):
    split_url = scan_info['url_to_scan'].split('/')
    url_to_scan = ''
    try:
        url_to_scan = split_url[2]
    except IndexError:
        url_to_scan = scan_info['url_to_scan']
    scan_name = 'NESSUS-'+scan_info['redmine_project']+'-'+url_to_scan
    #Connect to the nessus
    r = requests.post(login_url,data={'username':username,'password':password},verify=verify)
    # Getting the session token
    header = {'X-Cookie':'token='+json.loads(r.text)['token'],
                'X-API-Token':nessus_info['API'],
                'Content-Type':'application/json'
            }
    # Create the scan
    json_scan =  {
        'uuid':nessus_info['SCAN_TEMPLATE'],
        'settings':{'launch_now':False,
                'enabled':False,
                'text_targets':url_to_scan,
                'policy_id':'170',
                'scanner_id':'1',
                'folder_id':int(nessus_info['FOLDER_ID']),
                'description':'Scan created and launched via orchestrator',
                'name':scan_name
                }
        }
    # Creating the scan and getting the id for the launching
    r = requests.post(create_url,data=json.dumps(json_scan,separators=(',', ':')),verify=verify,headers=header)
    # Getting the scan id for launch the scan
    scan_id = str(json.loads(r.text)['scan']['id'])
    #Launch the scan
    launch_url = nessus_info['URL']+'/scans/'+scan_id+'/launch'
    r = requests.post(launch_url,verify=verify,headers=header)
    #Monitoring the scan until it's finished
    scan_status = 'running'
    while scan_status == 'running':
        time.sleep(180)
        resp = requests.get(scan_url+scan_id,verify=verify,headers=header)
        json_scan = json.loads(resp.text)
        scan_status = json_scan['info']['status']
    if json_scan['info']['status'] == 'completed':
        add_vulnerability(scan_info, json_scan,header)
    else:
        print('The scan with id: '+scan_id+' has been paused or stopped go to nessus and checked manually')