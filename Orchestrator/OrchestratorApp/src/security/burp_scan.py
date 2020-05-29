from ..slack import slack_sender
from ..mongo import mongo
from ..redmine import redmine
from .. import constants
from ...objects.vulnerability import Vulnerability

import time
import requests
import subprocess
import os
import uuid
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


def handle_target(info):
    print('------------------- BURP TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Burp scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        #scan_target(sub_info, sub_info['url_to_scan'])
    print('------------------- BURP TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_information):
    print('------------------- BURP SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("Burp scan started against %s" % scan_information['url_to_scan'])
    scan_target(scan_information)
    print('------------------- BURP SINGLE SCAN FINISHED -------------------')
    return


def add_vulnerability(scan_info, file_string, file_dir, file_name):
    vulnerability = Vulnerability(constants.BURP_SCAN, scan_info, 'Burp scan completed against %s' 
                                  % scan_info['url_to_scan'])
    vulnerability.add_file_string(file_string)
    vulnerability.add_attachment(file_dir, file_name)

    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info):
    header = {'accept': '*/*'}
    
    subprocess.run(['curl', '-k', '-x', 'http://127.0.0.1:8080', '-L', scan_info['url_to_scan']],
                   capture_output=True)

    # Arrancamos agregando el url al scope
    add_to_scope_response = requests.put(add_to_scope_url % scan_info['url_to_scan'], headers=header)
    if add_to_scope_response.status_code != 200:
        return
    query_scope_response = requests.get(query_in_scope_url % scan_info['url_to_scan'], headers=header)
    if not query_scope_response.json()['inScope']:
        return
    print("Added %s to scope!" % scan_info['url_to_scan'])

    spider_response = requests.post(spider_url % scan_info['url_to_scan'], headers=header)
    if spider_response.status_code != 200:
        return
    spider_status_response = requests.get(spider_status_url, headers=header)
    while spider_status_response.json()['spiderPercentage'] != 100:
        spider_status_response = requests.get(spider_status_url, headers=header)
        time.sleep(1)
    print("Spider on %s finished!" % scan_info['url_to_scan'])

    passive_scan_response = requests.post(passive_scan_url % scan_info['url_to_scan'], headers=header)
    if passive_scan_response.status_code != 200:
        return
    scanner_status_response = requests.get(scan_status_url, headers=header)
    while scanner_status_response.json()['scanPercentage'] != 100:
        scanner_status_response = requests.get(scan_status_url, headers=header)
        time.sleep(5)
    print("Passive scan on %s finished!" % scan_info['url_to_scan'])

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    OUTPUT_DIR = ROOT_DIR + '/tools_output/' + random_filename + '.xml'

    download_response = requests.get(download_report % scan_info['url_to_scan'], headers=header)
    open(OUTPUT_DIR, 'wb').write(download_response.content)
    add_vulnerability(scan_info, download_response.content,
                      OUTPUT_DIR, 'burp_result.xml')

    try:
        os.remove(OUTPUT_DIR)
    except FileNotFoundError:
        print("File %s is supposed to exist!" % OUTPUT_DIR)
        return