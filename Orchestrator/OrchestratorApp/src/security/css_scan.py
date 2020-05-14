import requests
import urllib3
from datetime import datetime

from ..utils import utils
from .. import constants
from ..mongo import mongo
from ..slack import slack_sender

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


def handle_single(url, language):
    print('------------------- CSS SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("CSS scan started against %s" % url)
    scan_target(url, url, language)
    print('------------------- CSS SINGLE SCAN FINISHED -------------------')
    return


def add_vulnerability_to_mongo(target, scanned_url, css_url, language, extra_info):
    timestamp = datetime.now()
    extra_to_send = ""
    vuln_name = ""
    if language == constants.LANGUAGE_ENGLISH:
        vuln_name = constants.CSS_ENGLISH % css_url
        if extra_info == 'Access':
            extra_to_send = 'File could not be accessed'
        elif extra_info == 'Status':
            extra_to_send = 'File did not return status 200'
    elif language == constants.LANGUAGE_SPANISH:
        vuln_name = constants.CSS_SPANISH % css_url
        if extra_info == 'Access':
            extra_to_send = 'No se pudo acceder al archivo'
        elif extra_info == 'Status':
            extra_to_send = 'El archivo no devolvio codigo 200'

    mongo.add_vulnerability(target, scanned_url, vuln_name, timestamp, language, extra_to_send)


def scan_target(target_name, url_to_scan, language):
    # We take every .css file from our linkfinder utils
    css_files_found = utils.get_css_files_linkfinder(url_to_scan)

    for css_file in css_files_found:
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
                add_vulnerability_to_mongo(target_name, url_to_scan, css_file, language, 'Access')

        if response.status_code != 200:
            if url_split[2] != host_split[2]:
                slack_sender.send_simple_message(
                    "Possible css injection found at %s from %s. File did not return 200"
                    % (css_file, url_to_scan))
                add_vulnerability_to_mongo(target_name, url_to_scan, css_file, language, 'Status')

    return
