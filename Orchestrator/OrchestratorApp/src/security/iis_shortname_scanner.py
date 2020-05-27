import requests,os,subprocess
from datetime import datetime
from ..mongo import mongo
from ..comms import image_creator
from ..slack import slack_sender
from ..redmine import redmine
from .. import constants


def handle_target(target, url_list, language):
    print('------------------- IIS SHORTNAME SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    slack_sender.send_simple_message("Check and scann : %s. %d alive urls found!"% (target, len(url_list)))
    for url in url_list:
        scan_target(url['target'], url['url_with_http'], language)
    print('-------------------  IIS SHORTNAME SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- IIS SHORTNAME SCAN STARTING -------------------')
    slack_sender.send_simple_message("IIS ShortName Scanner scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- IIS SHORTNAME SCAN FINISHED -------------------')
    return


def scan_target(scan_info, url_to_scan):
    try:
        resp = requests.get(url_to_scan)
    except Exception:
        return
    try:
        if 'IIS' in resp.headers['Server']:
            ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
            TOOL_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/iis_shortname_scanner.jar'
            CONFIG_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/config.xml'
            iis_process = subprocess.run(['java', '-jar', TOOL_DIR, '0', '10', url_to_scan, CONFIG_DIR],
                                         capture_output=True)
            message = iis_process.stdout.decode()
            if "NOT VULNERABLE" not in message:
                img_str = image_creator.create_image_from_string(message)
                timestamp = datetime.now()
                vuln_name = constants.IIS_SHORTNAME_MICROSOFT_ENGLISH if 'eng' == scan_info['language'] else constants.IIS_SHORTNAME_MICROSOFT_SPANISH
                redmine_description = constants.REDMINE_IIS
                slack_sender.send_simple_vuln("IIS Microsoft files and directories enumeration found at %s", url_to_scan)
                redmine.create_new_issue(vuln_name, redmine_description % url_to_scan,
                                         scan_info['redmine_project'], scan_info['assigned_users'], scan_info['watchers'])
                mongo.add_vulnerability(scan_info['target'], url_to_scan,vuln_name, timestamp, scan_info['language'], message,img_str)
    except KeyError:
        print("No server header was found")
        
    return