from datetime import datetime
from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability
from Orchestrator.settings import wordlist

import subprocess
import os
import json
import uuid
import copy

def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def handle_target(info):
    if wordlist['ffuf_list']:
        print('Module ffuf starting against  '+ str(len(info['url_to_scan'])) + ' targets')
        print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
        slack_sender.send_simple_message("Directory bruteforce scan started against target: %s. %d alive urls found!"
                                        % (info['target'], len(info['url_to_scan'])))
        subject = 'Module FFUF Scan finished'
        desc = ''
        for url in info['url_to_scan']:
            sub_info = copy.deepcopy(info)
            sub_info['url_to_scan'] = url
            print('Scanning ' + url)
            finished_ok = scan_target(sub_info, sub_info['url_to_scan'])
            if finished_ok:
                desc = 'FFUF Scan termino sin dificultades para el target {}'.format(sub_info['url_to_scan'])
            else:
                desc = 'FFUF Scan encontro un problema y no pudo correr para el target {}'.format(sub_info['url_to_scan'])
        redmine.create_informative_issue(info,subject,desc)
        print('Module ffuf finished')
    return


def handle_single(scan_info):
    if wordlist['ffuf_list']:
        print('Module ffuf (single) started against %s' % scan_info['url_to_scan'])
        slack_sender.send_simple_message("Directory bruteforce scan started against %s" % scan_info['url_to_scan'])
        info = copy.deepcopy(scan_info)
        subject = 'Module FFUF Scan finished'
        finished_ok = scan_target(info, info['url_to_scan'])
        if finished_ok:
            desc = 'FFUF Scan termino sin dificultades para el target {}'.format(scan_info['url_to_scan'])
        else:
            desc = 'FFUF Scan encontro un problema y no pudo correr para el target {}'.format(scan_info['url_to_scan'])
        redmine.create_informative_issue(scan_info,subject,desc)
        print('Module ffuf (single) finished')
    return


def add_vulnerability(scan_info, affected_resource, description):
    vulnerability = Vulnerability(constants.ENDPOINT, scan_info, description)
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_with_http):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/ffuf'
    WORDLIST_DIR = ROOT_DIR + '/tools/ffuf_wordlist.txt'
    random_filename = uuid.uuid4().hex
    JSON_RESULT = ROOT_DIR + '/tools_output/' + random_filename + '.json'
    cleanup(JSON_RESULT)

    if url_with_http[-1] != '/':
        url_with_http = url_with_http + '/'

    subprocess.run(
        [TOOL_DIR, '-w', WORDLIST_DIR, '-u', url_with_http + 'FUZZ', '-c', '-v','-mc','200,403',
         '-o', JSON_RESULT],capture_output=True)

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
        description = "The following endpoints were found at %s:\n %s" % (url_with_http, extra_info_message)
        add_vulnerability(scan_info, url_with_http, description)

    cleanup(JSON_RESULT)
    return True