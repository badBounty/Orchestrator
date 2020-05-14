import requests
import urllib3

from ..utils import utils
from .. import constants
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

        if response.status_code != 200:
            if url_split[2] != host_split[2]:
                slack_sender.send_simple_message(
                    "Possible css injection found at %s from %s. File did not return 200"
                    % (css_file, url_to_scan))

    return
