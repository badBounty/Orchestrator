import urllib3
import requests
import tldextract
from datetime import datetime

from .. import constants
from ..mongo import mongo
from ..slack import slack_sender
from ..redmine import redmine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(target, url_list, language):
    print('------------------- HOST HEADER ATTACK TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Host header attack scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- HOST HEADER ATTACK TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- HOST HEADER ATTACK SCAN STARTING -------------------')
    slack_sender.send_simple_message("Host header attack scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- HOST HEADER ATTACK SCAN FINISHED -------------------')
    return


def add_vulnerability_to_mongo(scan_info, scanned_url, extra_info):
    timestamp = datetime.now()
    vuln_name = ""
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        vuln_name = constants.HOST_HEADER_ATTACK_ENGLISH
    elif scan_info['language'] == constants.LANGUAGE_SPANISH:
        vuln_name = constants.HOST_HEADER_ATTACK_SPANISH

    redmine.create_new_issue(vuln_name, constants.REDMINE_HOST_HEADER_ATTACK % scanned_url,
                             scan_info['redmine_url'], scan_info['assigned_users'], scan_info['watchers'])
    mongo.add_vulnerability(scan_info['target'], scanned_url, vuln_name, timestamp, scan_info['language'], extra_info)
    return


def scan_target(scan_info, url_to_scan):
    try:
        # Sends the request to test if it's vulnerable to a Host Header Attack
        response = requests.get(url_to_scan, verify=False, headers={'Host': 'test.com'}, timeout=3)
    except Exception as e:
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
        slack_sender.send_simple_message(
            "Host header attack possible at url %s" % url_to_scan)
        add_vulnerability_to_mongo(scan_info, url_to_scan, 'Found at url %s' % url_to_scan)

