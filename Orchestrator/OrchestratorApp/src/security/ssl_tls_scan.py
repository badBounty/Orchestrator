import json
import xmltodict
import uuid
import xml
from datetime import datetime
import subprocess
import os

from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability


def handle_target(info):
    print('------------------- TARGET SSL/TLS SCAN STARTING -------------------')
    print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
    slack_sender.send_simple_message("SSL/TLS scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    valid_ports = ['443']
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url

        split_url = url.split('/')
        try:
            final_url = split_url[2]
        except IndexError:
            final_url = url
        for port in valid_ports:
            scan_target(sub_info, url, final_url+':'+port)
    print('-------------------  TARGET SSL/TLS SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    # Url will come with http or https, we will strip and append ports that could have tls/ssl
    url = scan_info['url_to_scan']
    slack_sender.send_simple_message("SSL/TLS scan started against %s" % url)
    valid_ports = ['443']
    split_url = url.split('/')
    try:
        final_url = split_url[2]
    except IndexError:
        final_url = url
    print('------------------- SINGLE SSL/TLS SCAN STARTING -------------------')
    for port in valid_ports:
        scan_target(scan_info, url, final_url+':'+port)
    print('------------------- SINGLE SSL/TLS SCAN FINISHED -------------------')
    return


def checker(scan_info, url_with_port, result):
    timestamp = datetime.now()
    # testssl has a bunch of vulns, we could test more
    if result['id'] == 'SSLv2' and result['finding'] != 'not offered':
        add_vulnerability(scan_info, "SSLv2 is available at %s" % url_with_port)
    elif result['id'] == 'SSLv3' and result['finding'] != 'not offered':
        add_vulnerability(scan_info, "SSLv3 is available at %s" % url_with_port)
    elif result['id'] == 'TLS1' and result['finding'] != 'not offered':
        add_vulnerability(scan_info, "TLS1.0 is available at %s" % url_with_port)


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def add_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.SSL_TLS, scan_info, message)

    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


# In cases where single url is provided, port will default to 80 or 443 in most cases
def scan_target(scan_info, url, url_with_port):

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/testssl.sh/testssl.sh'
    random_filename = uuid.uuid4().hex
    OUTPUT_FULL_NAME = ROOT_DIR + '/tools_output/' + random_filename + '.json'

    cleanup(OUTPUT_FULL_NAME)
    # We first run the subprocess that creates the xml output file
    testssl_process = subprocess.run(
       ['bash', TOOL_DIR, '--fast', '--warnings=off', '-oj', OUTPUT_FULL_NAME, url_with_port])

    with open(OUTPUT_FULL_NAME) as f:
        results = json.load(f)

    for result in results:
        checker(scan_info, url_with_port, result)

    cleanup(OUTPUT_FULL_NAME)

    return