import requests
from ..mongo import mongo
from .. import constants
from datetime import datetime


def handle_target(url_list, language):
    print('------------------- TARGET HTTP METHOD SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- TARGET HTTP METHOD SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- SINGLE HTTP METHOD SCAN STARTING -------------------')
    scan_target(url, url, language)
    print('------------------- SINGLE HTTP METHOD SCAN FINISHED -------------------')
    return


def add_vulnerability(target_name, scanned_url, timestamp, language):
    if language == constants.LANGUAGE_ENGLISH:
        mongo.add_vulnerability(target_name, scanned_url,
                                constants.UNSECURE_METHOD_ENGLISH,
                                timestamp, language)
    if language == constants.LANGUAGE_SPANISH:
        mongo.add_vulnerability(target_name, scanned_url,
                                constants.UNSECURE_METHOD_SPANISH,
                                timestamp, language)


def scan_target(target_name, url_to_scan, language):
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
            add_vulnerability(target_name, url_to_scan, timestamp, language)
