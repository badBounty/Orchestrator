import requests
from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
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


def handle_single(scan_info):
    print('------------------- SINGLE HTTP METHOD SCAN STARTING -------------------')
    slack_sender.send_simple_message("HTTP method scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- SINGLE HTTP METHOD SCAN FINISHED -------------------')
    return


def add_vulnerability(scan_info, scanned_url, timestamp, message):
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        redmine.create_new_issue(constants.UNSECURE_METHOD_ENGLISH, constants.REDMINE_UNSECURE_METHOD % (scanned_url, message),
                                 scan_info['redmine_project'])
        mongo.add_vulnerability(scan_info['target'], scanned_url,
                                constants.UNSECURE_METHOD_ENGLISH,
                                timestamp, scan_info['language'])
    if scan_info['language'] == constants.LANGUAGE_SPANISH:
        redmine.create_new_issue(constants.UNSECURE_METHOD_SPANISH, constants.REDMINE_UNSECURE_METHOD % (scanned_url, message),
                                 scan_info['redmine_project'])
        mongo.add_vulnerability(scan_info['target'], scanned_url,
                                constants.UNSECURE_METHOD_SPANISH,
                                timestamp, scan_info['language'])


def scan_target(scan_info, url_to_scan):
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

    extensive_methods = False
    message = "\n"
    for response in responses:
        if response['response'].status_code == 200:
            extensive_methods = True
            message = message + "Method " + response['method'] + " found." + "\n"
    timestamp = datetime.now()
    if extensive_methods:
        slack_sender.send_simple_vuln("Extensive http methods found on %s, %s"
                                      % (url_to_scan, message))
        add_vulnerability(scan_info, url_to_scan, timestamp, message)
