from ..slack import slack_sender
from ..mongo import mongo
from ..redmine import redmine
from ..utils import utils
from .. import constants
from ...objects.vulnerability import Vulnerability
from Orchestrator.settings import burp_config

import time
import requests
import subprocess
import os
import uuid
import xmltodict
import json
import base64
import copy
import traceback
from datetime import datetime

#Put
add_to_scope_url = "http://localhost:8090/burp/target/scope?url=%s"
#Get
query_in_scope_url = "http://localhost:8090/burp/target/scope?url=%s"
#Post
spider_url = "http://localhost:8090/burp/spider?baseUrl=%s"
#Get
spider_status_url = "http://localhost:8090/burp/spider/status"
#Post
passive_scan_url = "http://localhost:8090/burp/scanner/scans/passive?baseUrl=%s"
#Get
scan_status_url = "http://localhost:8090/burp/scanner/status"
#Post
active_scan_url = "http://localhost:8090/burp/scanner/scans/active?baseUrl=%s&insertionPoint="
#Get
download_report = "http://localhost:8090/burp/report?reportType=XML&urlPrefix=%s"
#Get
stop_burp = "http://localhost:8090/burp/stop"
#Get
stime_map_burp = "http://localhost:8090/burp/target/sitemap?urlPrefix=%s"

def handle_target(info):
    if burp_config['bash_folder']:
        print("Module Burp scan started against: %s. %d alive urls found!"% (info['target'], len(info['url_to_scan'])))
        slack_sender.send_simple_message("Burp scan started against target: %s. %d alive urls found!"
                                        % (info['target'], len(info['url_to_scan'])))
        subject = 'Module BURP Scan finished'
        desc = ''
        for url in info['url_to_scan']:
            sub_info = copy.deepcopy(info)
            sub_info['url_to_scan'] = url
            print('Scanning ' + url)
            finished_ok = scan_target(sub_info)
            if finished_ok:
                desc += 'BURP Scan termino sin dificultades para el target {}'.format(sub_info['url_to_scan'])
            else:
                desc += 'BURP Scan encontro un problema y no pudo correr para el target {}'.format(sub_info['url_to_scan'])
        redmine.create_informative_issue(info,subject,desc)
        print("Burp scan finished against : %s."% info['target'])
    return


def handle_single(scan_information):
    print("Module Burp scan started against %s" % scan_information['url_to_scan'])
    slack_sender.send_simple_message("Burp scan started against %s" % scan_information['url_to_scan'])
    info = copy.deepcopy(scan_information)
    subject = 'Module BURP Scan finished'
    finished_ok = scan_target(info)
    if finished_ok:
        desc = 'BURP Scan termino sin dificultades para el target {}'.format(scan_information['url_to_scan'])
    else:
        desc = 'BURP Scan encontro un problema y no pudo correr para el target {}'.format(scan_information['url_to_scan'])
    redmine.create_informative_issue(scan_information,subject,desc)
    print("Module Burp scan finished against %s" % scan_information['url_to_scan'])
    return

def add_errors_vulnerability(scan_info,errors):
    final_message = constants.TITLE_POSSIBLE_ERROR_PAGES+errors
    vulnerability = Vulnerability(constants.POSSIBLE_ERROR_PAGES, scan_info, final_message)
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)

def add_vulnerability(scan_info, file_string, file_dir, file_name):
    my_dict = xmltodict.parse(file_string)
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    description = 'Burp scan completed against %s' % scan_info['url_to_scan'] +'\n'
    try:
        if 'issue' in json_data['issues']: 
            for issue in json_data['issues']['issue']:
                if issue['name'] not in burp_config['blacklist_findings']:
                    name = copy.deepcopy(constants.BURP_SCAN)
                    name['english_name'] = name['english_name'] + issue['name']
                    extra='Burp Request: \n'+base64.b64decode(issue['requestresponse']['request']['#text']).decode("utf-8")
                    vulnerability = Vulnerability(name, scan_info, description+extra)
                    vulnerability.add_file_string(file_string)
                    vulnerability.add_attachment(file_dir, file_name)
                    slack_sender.send_simple_vuln(vulnerability)
                    redmine.create_new_issue(vulnerability)
                    mongo.add_vulnerability(vulnerability)
    except KeyError:
        return
    except TypeError as e:
        print(str(e))
        return


def scan_target(scan_info):
    is_burp_already_running = True
    #Check if is already a burp process running
    #if exists wait and dont run
    while is_burp_already_running:
        proc1 = subprocess.Popen(['ps','aux'],stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(['grep', 'burp-rest-api.sh'], stdin=proc1.stdout,stdout=subprocess.PIPE, stderr=subprocess.PIPE)    
        proc_list = proc2.stdout.readline().decode('utf-8').split()
        if len(proc_list)>1:
            burp_fold = proc_list[len(proc_list)-1]
        else:
            burp_fold = ''
        proc1.kill()
        proc2.kill()
        if burp_config['bash_folder'] != burp_fold:
            try: 
                burp_process = subprocess.Popen(burp_config['bash_folder'], stdout=subprocess.PIPE)
                time.sleep(120)
                #GETTING PID FOR TERMINATE JAVA AFTER BURP SCAN
                pid = burp_process.stdout.readline().decode('utf-8').split()[3]
                header = {'accept': '*/*'}

                subprocess.run(['curl', '-k', '-x', 'http://127.0.0.1:8080', '-L', scan_info['url_to_scan']],
                            capture_output=True)

                # Arrancamos agregando el url al scope
                add_to_scope_response = requests.put(add_to_scope_url % scan_info['url_to_scan'], headers=header)
                if add_to_scope_response.status_code != 200:
                    return
                query_scope_response = requests.get(query_in_scope_url % scan_info['url_to_scan'], headers=header)
                if not query_scope_response.json()['inScope']:
                    return False

                spider_response = requests.post(spider_url % scan_info['url_to_scan'], headers=header)
                if spider_response.status_code != 200:
                    return False
                spider_status_response = requests.get(spider_status_url, headers=header)
                
                while spider_status_response.json()['spiderPercentage'] != 100:
                    spider_status_response = requests.get(spider_status_url, headers=header)
                    time.sleep(1)

                passive_scan_response = requests.post(passive_scan_url % scan_info['url_to_scan'], headers=header)
                if passive_scan_response.status_code != 200:
                    return False
                scanner_status_response = requests.get(scan_status_url, headers=header)
                while scanner_status_response.json()['scanPercentage'] != 100:
                    scanner_status_response = requests.get(scan_status_url, headers=header)
                    time.sleep(5)
                
                #Getting sitemap of the URL
                response = requests.get(stime_map_burp % scan_info['url_to_scan'], headers=header)
                site_map = response.json()['messages']
                urls = [host['url'] for host in site_map]
                errors = utils.find_bad_error_messages(urls)
                if errors:
                    add_errors_vulnerability(scan_info,errors)

                ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
                random_filename = uuid.uuid4().hex
                OUTPUT_DIR = ROOT_DIR + '/tools_output/' + random_filename + '.xml'

                download_response = requests.get(download_report % scan_info['url_to_scan'], headers=header)

                open(OUTPUT_DIR, 'wb').write(download_response.content)
                add_vulnerability(scan_info, download_response.content,OUTPUT_DIR, 'burp_result.xml')
                
                burp_process.kill()
                os.system("kill -9 "+pid)
                is_burp_already_running = False
                try:
                    os.remove(OUTPUT_DIR)
                except FileNotFoundError:
                    print("File %s is supposed to exist!" % OUTPUT_DIR)
                    return False
                return True
            except requests.exceptions.ConnectionError:
                is_burp_already_running = False
                burp_process.kill()
                os.system("kill -9 "+pid)
                error_string = traceback.format_exc()
                print('ERROR on {0}, description:{1}'.format(scan_info['url_to_scan'],error_string))
                return False
