import json
import xmltodict
from ..mongo import mongo
from .. import constants
from datetime import datetime
import subprocess
import os
import xml


def handle_target(url_list, language):
    print('------------------- TARGET SSL/TLS SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_port'])
        scan_target(url['target'], url['name'], url['url_with_port'], language)
    print('-------------------  TARGET SSL/TLS SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    # Url will come with http or https, we will strip and append ports that could have tls/ssl
    valid_ports = ['80', '81', '443', '591', '2082', '2087', '2095', '2096', '3000', '8000',
                   '8001', '8008', '8080', '8083', '8443', '8834', '8888']
    split_url = url.split('/')
    final_url = split_url[2]
    print('------------------- SINGLE SSL/TLS SCAN STARTING -------------------')
    for port in valid_ports:
        scan_target(url, url, final_url+':'+port, language)
    print('------------------- SINGLE SSL/TLS SCAN FINISHED -------------------')
    return


def checker(target_name, url_with_port, language, result):
    timestamp = datetime.now()
    # testssl has a bunch of vulns, we could test more
    if result['id'] == 'SSLv2' and result['finding'] != 'not offered':
        add_vulnerability(target_name, url_with_port, timestamp, language)
    elif result['id'] == 'SSLv3' and result['finding'] != 'not offered':
        add_vulnerability(target_name, url_with_port, timestamp, language)
    elif result['id'] == 'TLS1' and result['finding'] != 'not offered':
        add_vulnerability(target_name, url_with_port, timestamp, language)


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


def add_vulnerability(target_name, scanned_url, timestamp, language):
    if language == constants.LANGUAGE_ENGLISH:
        mongo.add_vulnerability(target_name, scanned_url,
                                constants.SSL_TLS_ENGLISH,
                                timestamp, language)
    if language == constants.LANGUAGE_SPANISH:
        mongo.add_vulnerability(target_name, scanned_url,
                                constants.SSL_TLS_SPANISH,
                                timestamp, language)


# In cases where single url is provided, port will default to 80 or 443 in most cases
def scan_target(target_name, url, url_with_port, language):

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/testssl.sh/testssl.sh'
    OUTPUT_DIR = ROOT_DIR + '/tools_output'
    OUTPUT_FULL_NAME = OUTPUT_DIR + '/' + url + '.json'

    cleanup(OUTPUT_FULL_NAME)
    # We first run the subprocess that creates the xml output file
    testssl_process = subprocess.run(
       ['bash', TOOL_DIR, '--warnings off', '-oj', OUTPUT_FULL_NAME, url_with_port])

    with open(OUTPUT_FULL_NAME) as f:
        results = json.load(f)

    for result in results:
        checker(target_name, url_with_port, language, result)

    cleanup(OUTPUT_FULL_NAME)

    return