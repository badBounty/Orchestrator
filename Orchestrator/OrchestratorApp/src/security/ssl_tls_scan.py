import json
import xmltodict
import uuid
import xml
from datetime import datetime
import subprocess
import os
import copy

from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability


def handle_target(info):
    print('Module SSL/TLS scan started against target: %s. %d alive urls found!'% (info['target'], len(info['url_to_scan'])))
    slack_sender.send_simple_message("SSL/TLS scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    valid_ports = ['443']
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url

        split_url = url.split('/')
        try:
            final_url = split_url[2]
        except IndexError:
            final_url = url
        for port in valid_ports:
            scan_target(sub_info, url, final_url+':'+port)
    print('Module SSL/TLS finished against %s'% info['target'])
    return


def handle_single(scan_info):
    info = copy.deepcopy(scan_info)
    # Url will come with http or https, we will strip and append ports that could have tls/ssl
    url = info['url_to_scan']
    slack_sender.send_simple_message("SSL/TLS scan started against %s" % url)
    valid_ports = ['443']
    split_url = url.split('/')
    try:
        final_url = split_url[2]
    except IndexError:
        final_url = url
    print("SSL/TLS (single) scan started against %s" % url)
    for port in valid_ports:
        scan_target(info, url, final_url+':'+port)
    print("SSL/TLS (single) scan finished against %s" % url)
    return


def checker(scan_info, url_with_port, result):
    # testssl has a bunch of vulns, we could test more
    message = ""
    if result['id'] == 'SSLv2' and result['finding'] != 'not offered':
        message += "SSLv2 is available at %s\n" % url_with_port
    elif result['id'] == 'SSLv3' and result['finding'] != 'not offered':
        message += "SSLv3 is available at %s\n" % url_with_port
    elif result['id'] == 'TLS1' and result['finding'] != 'not offered':
        message += "TLS1.0 is available at %s\n" % url_with_port
    elif result['id'] == 'POODLE_SSL' and 'VULNERABLE (NOT ok)' in result['finding']:
        message += "TLS Vulnerable to POODLE ATTACK available at %s\n" % url_with_port
    elif result['id'] == 'SWEET32' and result['finding'] != 'not vulnerable':
        message += "64-bit block size cipher suites supported at %s\n" % url_with_port
    elif result['id'] == 'LOGJAM' and 'VULNERABLE (NOT ok)' in result['finding']:
        message += "LOGJAM experimental 1024 bit available at %s\n" % url_with_port
    elif 'cipher-tls1' in result['id'] and 'DH 1024' in result['finding']:
        message += "Short key length of DHE cipher suites (Less than 2048 bits) available at %s" % url_with_port
    print(message)
    if message:
        add_vulnerability(scan_info, message)

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
    subprocess.run(
       ['bash', TOOL_DIR, '--fast', '--warnings=off', '-oj', OUTPUT_FULL_NAME, url_with_port], capture_output = True)

    with open(OUTPUT_FULL_NAME) as f:
        results = json.load(f)

    for result in results:
        checker(scan_info, url_with_port, result)

    cleanup(OUTPUT_FULL_NAME)

    return