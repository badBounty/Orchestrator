import json
import xmltodict
from ..mongo import mongo
from datetime import datetime
import subprocess
import os


def handle_target(url_list):
    print('------------------- TARGET SSL/TLS SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_port'])
        scan_target(url['target'], url['name'], url['url_with_port'])
    print('-------------------  TARGET SSL/TLS SCAN FINISHED -------------------')
    return


def handle_single(url):
    # Url will come with http or https, we will strip and append ports that could have tls/ssl
    valid_ports = ['80', '81', '443', '591', '2082', '2087', '2095', '2096', '3000', '8000',
                   '8001', '8008', '8080', '8083', '8443', '8834', '8888']
    split_url = url.split('/')
    final_url = split_url[2]
    print('------------------- SINGLE SSL/TLS SCAN STARTING -------------------')
    for port in valid_ports:
        scan_target(url, url, final_url+':'+port)
    print('------------------- SINGLE SSL/TLS SCAN FINISHED -------------------')
    return


def checker(protocol):
    if protocol['@type'] == 'ssl' and protocol['@enabled'] == '1':
        return True
    elif protocol['@type'] == 'tls' and protocol['@version'] == '1.0' and protocol['@enabled'] == '1':
        return True


def cleanup(path):
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    return


# In cases where single url is provided, port will default to 80 or 443 in most cases
def scan_target(target_name, url, url_with_port):

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR + '/tools_output'
    OUTPUT_FULL_NAME = OUTPUT_DIR + '/' + url + '.xml'

    # We first run the subprocess that creates the xml output file
    sslscan_process = subprocess.run(
       ['sslscan', '--no-failed', '--tls1', '--xml=' + OUTPUT_FULL_NAME, url_with_port])

    with open(OUTPUT_FULL_NAME) as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)

    # xml.parsers.expat.ExpatError

    try:
        protocol_list = json_data['document']['ssltest']['protocol']
    except KeyError:
        cleanup(OUTPUT_FULL_NAME)
        return

    for protocol in protocol_list:
        if checker(protocol):
            timestamp = datetime.now()
            mongo.add_vulnerability(target_name, url, 'tls/ssl vuln', timestamp)

    cleanup(OUTPUT_FULL_NAME)

    return
