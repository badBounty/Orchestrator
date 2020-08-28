from ..mongo import mongo
from datetime import datetime
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability

import os
import subprocess
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
    info = copy.deepcopy(info)
    print('Module CORS Scan started against target: %s. %d alive urls found!'% (info['url_to_scan'], len(info['url_to_scan'])))
    print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
    slack_sender.send_simple_message("CORS scan started against target: %s. %d alive urls found!"
                                     % (info['url_to_scan'], len(info['url_to_scan'])))
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    FILE_WITH_URLS = ROOT_DIR + '/tools_output/' + random_filename + '.txt'
    subject = 'Module CORS Scan finished'
    desc = ''
    for subdomain in info['target']:
        scan_info = copy.deepcopy(info)
        scan_info['target'] = subdomain
        with open(FILE_WITH_URLS, 'w') as f:
            f.write("%s\n" % subdomain)
        # Call scan target with the file
        finished_ok = scan_target(scan_info, FILE_WITH_URLS)
        if finished_ok:
            desc += 'CORS Scan termino sin dificultades para el target {}'.format(scan_info['target'])
        else:
            desc += 'CORS Scan encontro un problema y no pudo correr para el target {}'.format(scan_info['target'])
        # Delete all created files
        cleanup(FILE_WITH_URLS)
    redmine.create_informative_issue(info,subject,desc)
    print('Module CORS Scan finished')
    return


def handle_single(info):
    info = copy.deepcopy(info)
    print('Module CORS Scan started against %s' % info['url_to_scan'])
    slack_sender.send_simple_message("CORS scan started against %s" % info['url_to_scan'])
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

    # Put urls in a single file
    random_filename = uuid.uuid4().hex
    FILE_WITH_URL = ROOT_DIR + '/tools_output/' + random_filename + '.txt'
    cleanup(FILE_WITH_URL)
    with open(FILE_WITH_URL, 'w') as f:
        f.write("%s\n" % info['url_to_scan'])

    # Call scan target
    subject = 'Module CORS Scan finished'
    finished_ok = scan_target(info, FILE_WITH_URL)
    if finished_ok:
        desc = 'CORS Scan termino sin dificultades para el target {}'.format(info['url_to_scan'])
    else:
        desc = 'CORS Scan encontro un problema y no pudo correr para el target {}'.format(info['url_to_scan'])
    redmine.create_informative_issue(info,subject,desc)
    # Delete all created files
    cleanup(FILE_WITH_URL)
    print('Module CORS Scan finished against %s' % info['url_to_scan'])
    return


def add_vulnerability(scan_info, vuln):
    vulnerability = Vulnerability(constants.CORS, scan_info, 'Found CORS %s with origin %s' % (vuln['type'], vuln['origin']))
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, file_name):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    FILE_WITH_JSON_RESULT = ROOT_DIR + '/tools_output/' + random_filename + '.json'
    TOOL_DIR = ROOT_DIR + '/tools/CORScanner/cors_scan.py'
    cleanup(FILE_WITH_JSON_RESULT)
    subprocess.run(
        ['python3', TOOL_DIR, '-i', file_name, '-o', FILE_WITH_JSON_RESULT], capture_output=True)
    with open(FILE_WITH_JSON_RESULT) as json_file:
        vulns = json.load(json_file)

    if not vulns:
        cleanup(FILE_WITH_JSON_RESULT)
        return True

    for vuln in vulns:
        add_vulnerability(scan_info, vuln)

    cleanup(FILE_WITH_JSON_RESULT)
    return True
