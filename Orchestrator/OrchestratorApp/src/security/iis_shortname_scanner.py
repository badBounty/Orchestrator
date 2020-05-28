import requests
import os
import subprocess
import base64
from PIL import Image
from io import BytesIO
from datetime import datetime
import uuid

from ..mongo import mongo
from ..comms import image_creator
from ..slack import slack_sender
from ..redmine import redmine
from .. import constants
from ...objects.vulnerability import Vulnerability


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
                random_filename = uuid.uuid4().hex
                output_dir = ROOT_DIR + '/tools_output/' + random_filename + '.png'
                im = Image.open(BytesIO(base64.b64decode(img_str)))
                im.save(output_dir, 'PNG')

                vulnerability = Vulnerability(constants.IIS_SHORTNAME_MICROSOFT, scan_info,
                                              "IIS Microsoft files and directories enumeration found at %s" % scan_info['url_to_scan'])

                vulnerability.add_image_string(img_str)
                vulnerability.add_attachment(output_dir, 'IIS-Result.png')
                slack_sender.send_simple_vuln(vulnerability)
                redmine.create_new_issue(vulnerability)
                mongo.add_vulnerability(vulnerability)
                os.remove(output_dir)
    except KeyError:
        print("No server header was found")
    return