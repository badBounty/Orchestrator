import urllib3
import requests
import re
import traceback
import copy

from ..slack import slack_sender
from .. import constants
from ..mongo import mongo
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(info):
    print('Module Firebase scan started against target: %s. %d alive urls found!'% (info['target'], len(info['url_to_scan'])))
    slack_sender.send_simple_message("Firebase scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        scan_target(sub_info, sub_info['url_to_scan'])
    print('Module Firebase finished against %s'% info['target'])
    return


def handle_single(scan_info):
    print('Module Firebase (single) scan started against %s' % scan_info['url_to_scan'])
    slack_sender.send_simple_message("Firebase scan started against %s" % scan_info['url_to_scan'])
    info = copy.deepcopy(scan_info)
    scan_target(info, info['url_to_scan'])
    print('Module Firebase (single) scan')
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
    except requests.exceptions.ReadTimeout:
        return
    except requests.exceptions.SSLError:
        return
    except Exception:
        error_string = traceback.format_exc()
        print('Error found in: '+error_string)
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
        except Exception:
            error_string = traceback.format_exc()
            print('Error found in: '+error_string)
            continue
        if firebase_response.status_code == 200:
            add_vulnerability(scan_info, firebase)
