import urllib3
import requests
import re
from datetime import datetime

from ..slack import slack_sender
from .. import constants
from ..mongo import mongo
from ..redmine import redmine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(target, url_list, language):
    print('------------------- FIREBASE TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Firebase scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- FIREBASE TARGET SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- FIREBASE SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("Firebase scan started against %s" % url)
    scan_target(url, url, language)
    print('------------------- FIREBASE SINGLE SCAN FINISHED -------------------')
    return


def add_vulnerability(target, scanned_url, firebase_name, language):
    timestamp = datetime.now()
    vuln_name = ""
    extra_to_send = ""
    if language == constants.LANGUAGE_ENGLISH:
        vuln_name = constants.FIREBASE_ENGLISH
        extra_to_send = 'Firebase name %s' % firebase_name
    elif language == constants.LANGUAGE_SPANISH:
        vuln_name = constants.FIREBASE_SPANISH
        extra_to_send = 'Firebase name %s' % firebase_name

    redmine.create_new_issue(vuln_name, constants.REDMINE_FIREBASE % (firebase_name, scanned_url))
    mongo.add_vulnerability(target, scanned_url, vuln_name, timestamp, language, extra_to_send)


def filter_invalids(some_list):
    res = []
    # ------ Filter invalid matches
    for item in some_list:
        if all(char not in item for char in ['\\', '=', '>', '<', '[', ']', '{', '}', ';', '(', ')', '_']):
            res.append(item)
    return res


def scan_target(target_name, url_to_scan, language):
    try:
        response = requests.get(url_to_scan, verify=False, timeout=3)
    except Exception as e:
        return

    # Firebases come in the form
    # https://*.firebaseio.com

    # ---------Way I----------
    firebase_HTTPS = re.findall('"https://([^\"/,]+).firebaseio.com"', response.text)
    firebase_HTTPS = filter_invalids(firebase_HTTPS)
    firebase_HTTP = re.findall('"http://([^\"/,]+).firebaseio.com"', response.text)
    firebase_HTTP = filter_invalids(firebase_HTTP)

    firebase_list = firebase_HTTPS + firebase_HTTP
    firebase_list = list(dict.fromkeys(firebase_list))

    for i in range(len(firebase_list)):
        firebase_list[i] = 'http://' + firebase_list[i] + '.firebaseio.com/.json'

    for firebase in firebase_list:
        try:
            firebase_response = requests.get(firebase, verify=False, timeout=3)
        except Exception as e:
            continue
        if firebase_response.status_code == 200:
            slack_sender.send_simple_vuln('Found open firebase %s at %s' % (firebase, url_to_scan))
            add_vulnerability(target_name, url_to_scan, firebase, language)
