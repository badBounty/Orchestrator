import urllib3
import requests
import tldextract
import traceback
import copy
from datetime import datetime

from .. import constants
from ..mongo import mongo
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(info):
    print('Module Host Header Attack scan started against target: %s. %d alive urls found!'% (info['target'], len(info['url_to_scan'])))
    slack_sender.send_simple_message("Host header attack scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        scan_target(sub_info, sub_info['url_to_scan'])
    print('Module Host Header Attack finished')
    return


def handle_single(scan_info):
    print('Module Host Header Attack (single) scan started against %s' % scan_info['url_to_scan'])
    slack_sender.send_simple_message("Host header attack scan started against %s" % scan_info['url_to_scan'])
    info = copy.deepcopy(scan_info)
    scan_target(info, info['url_to_scan'])
    print('Module Host Header Attack (single) scan finished against %s' % scan_info['url_to_scan'])
    return


def add_vulnerability_to_mongo(scan_info):
    vulnerability = Vulnerability(constants.HOST_HEADER_ATTACK, scan_info,"Host header attack possible at url {}".format(scan_info['url_to_scan']))
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)
    return


def scan_target(scan_info, url_to_scan):
    try:
        # Sends the request to test if it's vulnerable to a Host Header Attack
        response = requests.get(url_to_scan, verify=False, headers={'Host': 'test.com'}, timeout=3)
    except requests.exceptions.ReadTimeout:
        return
    except requests.exceptions.ConnectionError:
        return
    except requests.exceptions.TooManyRedirects:
        return
    except Exception:
        error_string = traceback.format_exc()
        print('Error found in: '+error_string)
        return

    host_header_attack = 0
    # Tests if the host sent in the request is being reflected in the URL
    response_url = response.url
    extract = tldextract.extract(response_url)
    findvalue = response_url.find("test.com")

    if findvalue >= 0:
        host_header_attack = 1

    # Tests if the host sent in the request is being reflected in any header
    resp_headers = response.headers
    for x in resp_headers:  # Searchs if any header value reflects the value sent.
        value_in_header = resp_headers[x]
        findvalue = value_in_header.find('test.com')
        if findvalue >= 0:
            host_header_attack = 1
            break

    # Tests if the host sent in the requests is reflected in the response body
    response_body_inbytes = response.content  # Saves response's body
    response_body_str = str(response_body_inbytes)
    findvalue = response_body_str.find('test.com')
    if findvalue >= 0:
        host_header_attack = 1
    # If it's vulnerable to host
    # header attack, appends the information to the output file.
    if host_header_attack == 1:
        add_vulnerability_to_mongo(scan_info)

