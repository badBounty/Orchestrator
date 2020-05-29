import requests
import urllib3
from datetime import datetime

from ..utils import utils
from .. import constants
from ..mongo import mongo
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(info):
    print('------------------- CSS TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("CSS scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        #scan_target(sub_info, sub_info['url_to_scan'])
    print('------------------- CSS TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- CSS SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("CSS scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- CSS SINGLE SCAN FINISHED -------------------')
    return


def add_vulnerability_to_mongo(scan_info, css_url, vuln_type):
    timestamp = datetime.now()
    if vuln_type == 'Access':
        description = "Possible css injection found at %s from %s. File could not be accessed" \
                      % (css_url, scan_info['url_to_scan'])
    elif vuln_type == 'Status':
        description = "Possible css injection found at %s from %s. File did not return 200" \
                      % (css_url, scan_info['url_to_scan'])

    vulnerability = Vulnerability(constants.CSS_INJECTION, scan_info, description)
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_to_scan):
    # We take every .css file from our linkfinder utils
    print('Searching for css files...')
    css_files_found = utils.get_css_files_linkfinder(url_to_scan)
    print(str(len(css_files_found)) + ' css files found')

    for css_file in css_files_found:
        print('Scanning %s' % css_file)
        url_split = css_file.split('/')
        host_split = url_to_scan.split('/')

        if css_file[-1] == '\\' or css_file[-1] == '/':
            css_file = css_file[:-1]
        try:
            response = requests.get(css_file, verify=False)
        except Exception:
            if url_split[2] != host_split[2]:
                add_vulnerability_to_mongo(scan_info, css_file, 'Access')

        if response.status_code != 200:
            if url_split[2] != host_split[2]:
                add_vulnerability_to_mongo(scan_info, css_file, 'Status')

    return
