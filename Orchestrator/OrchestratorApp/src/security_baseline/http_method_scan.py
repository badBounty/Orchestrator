import requests
from ..mongo import mongo
from datetime import datetime


def handle_target(url_list):
    print('------------------- TARGET HTTP METHOD SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'])
    print('------------------- TARGET HTTP METHOD SCAN FINISHED -------------------')
    return


def handle_single(url):
    print('------------------- SINGLE HTTP METHOD SCAN STARTING -------------------')
    scan_target(url, url)
    print('------------------- SINGLE HTTP METHOD SCAN FINISHED -------------------')
    return


def scan_target(target_name, url_to_scan):
    responses = list()
    try:
        put_response = requests.put(url_to_scan, data={'key': 'value'})
    except requests.exceptions.SSLError:
        return

    responses.append({'method': 'PUT', 'response': put_response})

    delete_response = requests.delete(url_to_scan)
    responses.append({'method': 'DELETE', 'response': delete_response})

    options_response = requests.options(url_to_scan)
    responses.append({'method': 'OPTIONS', 'response': options_response})

    for response in responses:
        if response['response'].status_code == 200:
            # Reportar metodo
            timestamp = datetime.now()
            mongo.add_vulnerability(target_name, url_to_scan,
                                    "Method " + response['method'] + ' is available',
                                    timestamp)
