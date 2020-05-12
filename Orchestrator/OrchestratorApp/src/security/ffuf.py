import subprocess
import os
import json
from datetime import datetime
from ..mongo import mongo
from .. import constants
from ..slack import slack_sender


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def handle_target(target, url_list, language):
    print('------------------- FFUF SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    slack_sender.send_simple_message("Directory bruteforce scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    for url in url_list:
        scan_target(url['target'], url['url_with_http'], language)
    print('-------------------  FFUF SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- FFUF SCAN STARTING -------------------')
    slack_sender.send_simple_message("Directory bruteforce scan started against %s" % url)
    scan_target(url, url, language)
    print('------------------- FFUF SCAN FINISHED -------------------')
    return


def add_vulnerability(target_name, affected_resource, endpoint_name, language):
    timestamp = datetime.now()
    if language == constants.LANGUAGE_ENGLISH:
        mongo.add_vulnerability(target_name, affected_resource,
                                constants.ENDPOINT_ENGLISH % endpoint_name,
                                timestamp, language)
    elif language == constants.LANGUAGE_SPANISH:
        mongo.add_vulnerability(target_name, affected_resource,
                                constants.ENDPOINT_SPANISH % endpoint_name,
                                timestamp, language)


def scan_target(target_name, url_with_http, language):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/ffuf'
    WORDLIST_DIR = ROOT_DIR + '/tools/ffuf_wordlist.txt'
    only_host = url_with_http.split('/')[2]
    JSON_RESULT = ROOT_DIR + '/tools_output/' + only_host + '.json'
    cleanup(JSON_RESULT)

    if url_with_http[-1] != '/':
        url_with_http = url_with_http + '/'

    ffuf_process = subprocess.run(
        [TOOL_DIR, '-w', WORDLIST_DIR, '-u', url_with_http + 'FUZZ', '-c', '-v',
         '-o', JSON_RESULT])

    with open(JSON_RESULT) as json_file:
        json_data = json.load(json_file)

    vulns = json_data['results']
    valid_codes = [200, 403]
    for vuln in vulns:
        if vuln['status'] in valid_codes:
            slack_sender.send_simple_vuln("Endpoint %s found at %s" % (vuln['input']['FUZZ'], url_with_http))
            add_vulnerability(target_name, url_with_http, vuln['input']['FUZZ'], language)

    cleanup(JSON_RESULT)
    return
