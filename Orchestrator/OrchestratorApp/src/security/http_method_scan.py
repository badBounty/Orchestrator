import requests
from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from datetime import datetime


def handle_target(target, url_list, language):
    print('------------------- TARGET HTTP METHOD SCAN STARTING -------------------')
    slack_sender.send_simple_message("HTTP method scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- TARGET HTTP METHOD SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- SINGLE HTTP METHOD SCAN STARTING -------------------')
    slack_sender.send_simple_message("HTTP method scan started against %s" % url)
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
    except requests.exceptions.ConnectionError:
        return

    responses.append({'method': 'PUT', 'response': put_response})

    delete_response = requests.delete(url_to_scan)
    responses.append({'method': 'DELETE', 'response': delete_response})

    options_response = requests.options(url_to_scan)
    responses.append({'method': 'OPTIONS', 'response': options_response})

    res = any(response['response'].status_code == 200 for response in responses)
    timestamp = datetime.now()
    if res:
        slack_sender.send_simple_vuln("Extensive http methods found on %s"
                                      % url_to_scan)
        add_vulnerability(target_name, url_to_scan, timestamp, language)
