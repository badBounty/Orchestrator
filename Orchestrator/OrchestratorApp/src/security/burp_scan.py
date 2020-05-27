import requests
from ..slack import slack_sender
from ..mongo import mongo
from ..redmine import redmine
from .. import constants
import time
import subprocess
import os
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


def handle_target(target, url_list, language):
    print('------------------- BURP TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Burp scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- BURP TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_information):
    print('------------------- BURP SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("Burp scan started against %s" % scan_information['url_to_scan'])
    scan_target(scan_information, scan_information['url_to_scan'])
    print('------------------- BURP SINGLE SCAN FINISHED -------------------')
    return


def add_vulnerability(scan_info, scanned_url, extra_info, file_dir, file_name):
    timestamp = datetime.now()
    vulnerability = constants.BURP_SCAN

    redmine.create_new_issue(vulnerability, constants.REDMINE_BURP_SCAN % scanned_url, scan_info['redmine_project'],
                             scan_info['assigned_users'], scan_info['watchers'], file_dir, file_name)
    mongo.add_vulnerability(scan_info['target'], scanned_url, vulnerability,
                            timestamp, scan_info['language'], extra_info)


def scan_target(scan_info, url_to_scan):
    header = {'accept': '*/*'}

    subprocess.run(['curl', '-k', '-x', 'http://127.0.0.1:8080', '-L', url_to_scan],
                   capture_output = True)

    # Arrancamos agregando el url al scope
    add_to_scope_response = requests.put(add_to_scope_url % url_to_scan, headers=header)
    if add_to_scope_response.status_code != 200:
        return
    query_scope_response = requests.get(query_in_scope_url % url_to_scan, headers=header)
    if not query_scope_response.json()['inScope']:
        return
    print("Added %s to scope!" % url_to_scan)

    spider_response = requests.post(spider_url % url_to_scan, headers=header)
    if spider_response.status_code != 200:
        return
    spider_status_response = requests.get(spider_status_url, headers=header)
    while spider_status_response.json()['spiderPercentage'] != 100:
        spider_status_response = requests.get(spider_status_url, headers=header)
        time.sleep(1)
    print("Spider on %s finished!" % url_to_scan)

    passive_scan_response = requests.post(passive_scan_url % url_to_scan, headers=header)
    if passive_scan_response.status_code != 200:
        return
    scanner_status_response = requests.get(scan_status_url, headers=header)
    while scanner_status_response.json()['scanPercentage'] != 100:
        scanner_status_response = requests.get(scan_status_url, headers=header)
        time.sleep(5)
    print("Passive scan on %s finished!" % url_to_scan)

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR + '/tools_output/output.xml'

    download_response = requests.get(download_report % url_to_scan, headers=header)
    open(OUTPUT_DIR, 'wb').write(download_response.content)
    add_vulnerability(scan_info, url_to_scan, download_response.content,
                      OUTPUT_DIR, 'burp_result.xml')
    try:
        os.remove(OUTPUT_DIR)
    except FileNotFoundError:
        return