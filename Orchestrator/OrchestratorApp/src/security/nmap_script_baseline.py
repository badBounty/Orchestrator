import subprocess
import os
import xmltodict
import json
import base64
import uuid

from time import sleep
from PIL import Image
from io import BytesIO
from ..slack import slack_sender
from ..comms import image_creator
from .. import constants
from ..mongo import mongo
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability
from Orchestrator.settings import wordlist


def cleanup(path):
    try:
        os.remove(path + '.xml')
        os.remove(path + '.nmap')
        os.remove(path + '.gnmap')
    except FileNotFoundError:
        pass
    return


def handle_target(info):
    print('------------------- NMAP BASIC TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Nmap scripts started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
    print(os.getenv('C_FORCE_ROOT'))
    scanned_hosts = list()
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url
        try:
            host = url.split('/')[2]
        except IndexError:
            host = url
        if host not in scanned_hosts:
            print('Scanning ' + url)
            basic_scan(sub_info, host)
        scanned_hosts.append(host)
    print('------------------- NMAP BASIC TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- NMAP BASIC SCAN STARTING -------------------')
    url = scan_info['url_to_scan']
    slack_sender.send_simple_message("Nmap scripts started against %s" % url)
    # We receive the url with http/https, we will get only the host so nmap works
    host = url.split('/')[2]
    basic_scan(scan_info, host)
    print('------------------- NMAP BASIC SCAN FINISHED -------------------')
    return

def add_vuln_to_mongo(scan_info, scan_type, description, img_str):
    vuln_name = ""
    if scan_type == 'plaintext_services':
        vuln_name = constants.PLAINTEXT_COMUNICATION
    else:
        vuln_name = constants.UNNECESSARY_SERVICES

    vulnerability = Vulnerability(vuln_name, scan_info, description)
    vulnerability.add_image_string(img_str)

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR+'/tools_output/' + random_filename + '.png'
    im = Image.open(BytesIO(base64.b64decode(img_str)))
    im.save(output_dir, 'PNG')
    vulnerability.add_attachment(output_dir, 'nmap-result.png')
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)
    os.remove(output_dir)
    return

def check_ports_and_report(scan_info,ports,scan_type,json_scan,img_str):
    message=''
    nmap_ports = list()
    ports_numbers = list()
    try:
        if type(json_scan['nmaprun']['host']['ports']['port']) == list:
            nmap_ports += json_scan['nmaprun']['host']['ports']['port']
            ports_numbers = [port['@portid'] for port in nmap_ports]
        else:
            nmap_ports.append(json_scan['nmaprun']['host']['ports']['port'])
        for port in nmap_ports:
            if port['@portid'] in ports and port['state']['@state'] == 'open':
                message+= 'Port: '+port['@portid']+'\n'
                message+= 'Service: '+port['service']['@name']+'\n'
                if '@product' in port['service']:
                    message+= 'Product: '+port['service']['@product']+'\n'
                if '@version' in port['service']:
                    message+= 'Version: '+port['service']['@version']+'\n\n'
                http_and_https = (port['@portid'] == '80' and all(elem in ports_numbers  for elem in ['80','443']))
                if not http_and_https:
                    add_vuln_to_mongo(scan_info, scan_type, message, img_str)
    except KeyError as e:
        message = None
    return

def basic_scan(scan_info, url_to_scan):
    plaintext_ports=["21","23","80"]
    remote_ports=["135","445","513","514","1433","3306","3389"]
    random_filename = uuid.uuid4().hex
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    output_dir = ROOT_DIR + '/tools_output/'+random_filename
    basic_scan = subprocess.run(['nmap','-Pn','-sV','-sS','-vvv','--top-ports=1000','-oA',output_dir,url_to_scan], capture_output=True)
    with open(output_dir + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    img_str = image_creator.create_image_from_file(output_dir + '.nmap')
    check_ports_and_report(scan_info,plaintext_ports,'plaintext_services',json_data,img_str)
    check_ports_and_report(scan_info,remote_ports,'unnecessary_services',json_data,img_str)
    cleanup(output_dir)
    return