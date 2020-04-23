import subprocess
import os
import xmltodict
import json

from ..mongo import mongo


def start_nmap(targets):

    # run_nmap('tesla.com', 'tesla.com')
    print('------------------- NMAP STARTING -------------------')
    print('Found ' + str(len(targets)) + ' alive targets')
    for target in targets:
        print('Starting nmap agains ' + target['name'])
        run_nmap(target['target'], target['name'])

    print('------------------- NMAP ENDED -------------------')

    return None


def run_nmap(target_name, subdomain):

    # /home/handerllon/Desktop/OrchestratorV1/Orchestrator/src/recon
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    OUTPUT_DIR = ROOT_DIR + '/tools_output'
    PROJECT_DIR = OUTPUT_DIR + '/' + target_name

    nmap_process = subprocess.run(
        ['nmap', '-sV' ,'-Pn', '-oX', PROJECT_DIR + '/' + subdomain + '.xml', subdomain])

    with open(PROJECT_DIR + '/' + subdomain + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    # print(json_data)
    try:
        port_info = json_data['nmaprun']['host']['ports']['port']
    except KeyError:
        port_info = None
        return

    mongo.add_ports_to_subdomain(subdomain, port_info)

    try:
        os.remove(PROJECT_DIR + '/' + subdomain + '.xml')
    except FileNotFoundError:
        pass

    return
