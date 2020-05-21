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


def handle_single(url, language):
    print('------------------- IIS SHORTNAME SCAN STARTING -------------------')
    slack_sender.send_simple_message("IIS ShortName Scanner scan started against %s" % url)
    scan_target(url, url, language)
    print('------------------- IIS SHORTNAME SCAN FINISHED -------------------')
    return

def scan_target(target_name, url_to_scan, language):
    resp = requests.get(url_to_scan)
    try:
        if 'IIS' in resp.headers['Server']:
            ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
            TOOL_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/iis_shortname_scanner.jar'
            CONFIG_DIR = ROOT_DIR + '/tools/IIS-ShortName-Scanner/config.xml'
            iis_process = subprocess.run(['java', '-jar', TOOL_DIR,'0','10',url_to_scan, CONFIG_DIR], capture_output=True)
            #print(iis_process)
            message = iis_process.stdout.decode()
            if "NOT VULNERABLE" not in message:
                img_str = image_creator.create_image_from_string(message)
                timestamp = datetime.now()
                vuln_name = constants.IIS_SHORTNAME_MICROSOFT_ENGLISH if 'eng' == language else constants.IIS_SHORTNAME_MICROSOFT_SPANISH
                redmine_description = constants.REDMINE_IIS
                redmine.create_new_issue(vuln_name, redmine_description % url_to_scan)
                mongo.add_vulnerability(target_name, url_to_scan,vuln_name, timestamp, language, message,img_str)
    except KeyError:
        print("No server header was found")
        
    return