import requests
import urllib3
from datetime import datetime

from ..utils import utils
from .. import constants
from ..mongo import mongo
from ..slack import slack_sender
from ..redmine import redmine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(target, url_list, language):
    print('------------------- CSS TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("CSS scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- CSS TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- CSS SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("CSS scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- CSS SINGLE SCAN FINISHED -------------------')
    return


def add_vulnerability_to_mongo(scan_info, scanned_url, css_url, extra_info):
    timestamp = datetime.now()
    extra_to_send = ""
    vuln_name = ""
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        vuln_name = constants.CSS_ENGLISH
        if extra_info == 'Access':
            extra_to_send = 'File could not be accessed %s' % css_url
        elif extra_info == 'Status':
            extra_to_send = 'File did %s not return status 200' % css_url
    elif scan_info['language'] == constants.LANGUAGE_SPANISH:
        vuln_name = constants.CSS_SPANISH
        if extra_info == 'Access':
            extra_to_send = 'No se pudo acceder al archivo %s' % css_url
        elif extra_info == 'Status':
            extra_to_send = 'El archivo %s no devolvio codigo 200' % css_url

    redmine.create_new_issue(vuln_name, constants.REDMINE_CSS % (scanned_url, extra_to_send),
                             scan_info['redmine_project'], scan_info['assigned_users'], scan_info['watchers'])
    mongo.add_vulnerability(scan_info['target'], scanned_url, vuln_name, timestamp, scan_info['language'], extra_to_send)


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
                slack_sender.send_simple_message(
                    "Possible css injection found at %s from %s. File could not be accessed"
                    % (css_file, url_to_scan))
                add_vulnerability_to_mongo(scan_info, url_to_scan, css_file, 'Access')

        if response.status_code != 200:
            if url_split[2] != host_split[2]:
                slack_sender.send_simple_message(
                    "Possible css injection found at %s from %s. File did not return 200"
                    % (css_file, url_to_scan))
                add_vulnerability_to_mongo(scan_info, url_to_scan, css_file, 'Status')

    return
