import requests
from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability


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


def add_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.UNSECURE_METHOD, scan_info, message)

    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


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
    if extensive_methods:
        add_vulnerability(scan_info, message)
