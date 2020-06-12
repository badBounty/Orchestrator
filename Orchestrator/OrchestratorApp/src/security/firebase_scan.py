import urllib3
import requests
import re

from ..slack import slack_sender
from .. import constants
from ..mongo import mongo
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(info):
    print('------------------- FIREBASE TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Firebase scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        scan_target(sub_info, sub_info['url_to_scan'])
    print('------------------- FIREBASE TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- FIREBASE SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("Firebase scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- FIREBASE SINGLE SCAN FINISHED -------------------')
    return


def add_vulnerability(scan_info, firebase_name):
    vulnerability = Vulnerability(constants.OPEN_FIREBASE, scan_info, 'Found open firebase %s at %s' % (firebase_name, scan_info['url_to_scan']))

    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def filter_invalids(some_list):
    res = []
    # ------ Filter invalid matches
    for item in some_list:
        if all(char not in item for char in ['\\', '=', '>', '<', '[', ']', '{', '}', ';', '(', ')', '_']):
            res.append(item)
    return res


def scan_target(scan_info, url_to_scan):
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
            add_vulnerability(scan_info, firebase)
