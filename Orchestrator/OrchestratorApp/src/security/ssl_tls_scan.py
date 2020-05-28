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


def handle_target(target, url_list, language):
    print('------------------- TARGET SSL/TLS SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    slack_sender.send_simple_message("SSL/TLS scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    for url in url_list:
        print('Scanning ' + url['url_with_port'])
        scan_target(url['target'], url['name'], url['url_with_port'], language)
    print('-------------------  TARGET SSL/TLS SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    # Url will come with http or https, we will strip and append ports that could have tls/ssl
    url = scan_info['url_to_scan']
    slack_sender.send_simple_message("SSL/TLS scan started against %s" % url)
    valid_ports = ['443']
    split_url = url.split('/')
    final_url = split_url[2]
    print('------------------- SINGLE SSL/TLS SCAN STARTING -------------------')
    for port in valid_ports:
        scan_target(scan_info, url, final_url+':'+port)
    print('------------------- SINGLE SSL/TLS SCAN FINISHED -------------------')
    return


def checker(scan_info, url_with_port, result):
    timestamp = datetime.now()
    # testssl has a bunch of vulns, we could test more
    if result['id'] == 'SSLv2' and result['finding'] != 'not offered':
        slack_sender.send_simple_vuln("SSLv2 is available at %s" % url_with_port)
        add_vulnerability(scan_info, url_with_port, timestamp)
    elif result['id'] == 'SSLv3' and result['finding'] != 'not offered':
        slack_sender.send_simple_vuln("SSLv3 is available at %s" % url_with_port)
        add_vulnerability(scan_info, url_with_port, timestamp)
    elif result['id'] == 'TLS1' and result['finding'] != 'not offered':
        slack_sender.send_simple_vuln("TLS1.0 is available at %s" % url_with_port)
        add_vulnerability(scan_info, url_with_port, timestamp)


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def add_vulnerability(scan_info, scanned_url, timestamp):
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        redmine.create_new_issue(constants.SSL_TLS_ENGLISH, constants.REDMINE_SSL_TLS % scanned_url,
                                 scan_info['redmine_project'], scan_info['assigned_users'], scan_info['watchers'])
        mongo.add_vulnerability(scan_info['target'], scanned_url,
                                constants.SSL_TLS_ENGLISH,
                                timestamp, scan_info['language'])
    if scan_info['language'] == constants.LANGUAGE_SPANISH:
        redmine.create_new_issue(constants.SSL_TLS_SPANISH, constants.REDMINE_SSL_TLS % scanned_url,
                                 scan_info['redmine_project'], scan_info['assigned_users'], scan_info['watchers'])
        mongo.add_vulnerability(scan_info['target'], scanned_url,
                                constants.SSL_TLS_SPANISH,
                                timestamp, scan_info['language'])


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