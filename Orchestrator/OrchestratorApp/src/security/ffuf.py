import subprocess
import os
import json
from datetime import datetime
from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine


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


def handle_single(scan_info):
    print('------------------- FFUF SCAN STARTING -------------------')
    slack_sender.send_simple_message("Directory bruteforce scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- FFUF SCAN FINISHED -------------------')
    return


def add_vulnerability(scan_info, affected_resource, extra_info):
    timestamp = datetime.now()
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        redmine.create_new_issue(constants.ENDPOINT_ENGLISH,
                                 constants.REDMINE_ENDPOINT % (affected_resource, extra_info), scan_info['redmine_project'])
        mongo.add_vulnerability(scan_info['target'], affected_resource,
                                constants.ENDPOINT_ENGLISH,
                                timestamp, scan_info['language'], extra_info)
    elif scan_info['language'] == constants.LANGUAGE_SPANISH:
        redmine.create_new_issue(constants.ENDPOINT_SPANISH,
                                 constants.REDMINE_ENDPOINT % (affected_resource, extra_info), scan_info['redmine_project'])
        mongo.add_vulnerability(scan_info['target'], affected_resource,
                                constants.ENDPOINT_SPANISH,
                                timestamp, scan_info['language'], extra_info)


def scan_target(scan_info, url_with_http):
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
    one_found = False
    extra_info_message = ""
    for vuln in vulns:
        if vuln['status'] in valid_codes:
            extra_info_message = extra_info_message + "%s\n"% vuln['input']['FUZZ']
            one_found = True

    if one_found:
        slack_sender.send_simple_vuln("The following endpoints were found at %s:\n %s"% (url_with_http, extra_info_message))
        add_vulnerability(scan_info, url_with_http, extra_info_message)

    cleanup(JSON_RESULT)
    return
