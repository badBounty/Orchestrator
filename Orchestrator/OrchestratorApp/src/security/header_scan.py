import requests
import os
import uuid
import base64
from PIL import Image
from io import BytesIO
from datetime import datetime

from ..mongo import mongo
from ..comms import image_creator
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability


def handle_target(info):
    print('------------------- TARGET HEADER SCAN STARTING -------------------')
    slack_sender.send_simple_message("Header scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    print('Found ' + str(len(info['url_to_scan'])) + ' targets to scan')
    for url in info['url_to_scan']:
        sub_info = info
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        scan_target(sub_info, sub_info['url_to_scan'])
    print('-------------------  TARGET HEADER SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- SINGLE HEADER SCAN STARTING -------------------')
    slack_sender.send_simple_message("Header scan started against %s" % scan_info['url_to_scan'])
    scan_target(scan_info, scan_info['url_to_scan'])
    print('------------------- SINGLE HEADER SCAN FINISHED -------------------')
    return


def check_header_value(header_to_scan, value_received):
    if header_to_scan == 'x-frame-options':
        if 'SAMEORIGIN' not in value_received:
            return False
    if header_to_scan == 'X-Content-Type-options':
        if 'nosniff' not in value_received:
            return False
    if header_to_scan == 'Strict-Transport-Security':
        if 'max-age' not in value_received:
            return False
    if header_to_scan == 'Access-Control-Allow-Origin':
        if '*' in value_received:
            return False

    return True


def add_header_value_vulnerability(scan_info, img_string, description):
    vulnerability = Vulnerability(constants.INVALID_VALUE_ON_HEADER, scan_info, description)
    vulnerability.add_image_string(img_string)

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR + '/tools_output/' + random_filename + '.png'
    im = Image.open(BytesIO(base64.b64decode(img_string)))
    im.save(output_dir, 'PNG')

    vulnerability.add_attachment(output_dir, 'headers-result.png')

    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    os.remove(output_dir)
    mongo.add_vulnerability(vulnerability)


def add_header_missing_vulnerability(scan_info, img_string, description):
    vulnerability = Vulnerability(constants.HEADER_NOT_FOUND, scan_info, description)
    vulnerability.add_image_string(img_string)

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR+'/tools_output/' + random_filename + '.png'
    im = Image.open(BytesIO(base64.b64decode(img_string)))
    im.save(output_dir, 'PNG')

    vulnerability.add_attachment(output_dir, 'headers-result.png')

    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    os.remove(output_dir)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_to_scan):
    try:
        response = requests.get(url_to_scan)
        print('------------- SAVING RESPONSE TO IMAGE -----------------')
        message = 'Response Headers From: ' + url_to_scan+'\n'
        for h in response.headers:
            message += h + " : " + response.headers[h]+'\n'
        img_b64 = image_creator.create_image_from_string(message)
    except requests.exceptions.SSLError:
        return
    except requests.exceptions.ConnectionError:
        return

    important_headers = ['Content-Security-Policy', 'X-XSS-Protection', 'x-frame-options', 'X-Content-Type-options',
                         'Strict-Transport-Security', 'Access-Control-Allow-Origin']
    reported_invalid = False
    reported_exists = False
    message_invalid = "Headers with invalid values were found at %s \n" % url_to_scan
    message_exists = "Headers were not found at %s \n" % url_to_scan
    if response.status_code != 404:
        for header in important_headers:
            try:
                # If the header exists
                if response.headers[header]:
                    if not check_header_value(header, response.headers[header]):
                        message_invalid = message_invalid + "Header %s was found with invalid value \n" % header
                        # No header differenciation, so we do this for now
                        if not reported_invalid:
                            reported_invalid = True
            except KeyError:
                message_exists = message_exists + "Header %s was not found \n" % header
                if not reported_exists:
                    reported_exists = True

        if reported_exists:
            add_header_missing_vulnerability(scan_info, img_b64, message_exists)
        if reported_invalid:
            add_header_value_vulnerability(scan_info, img_b64, message_invalid)
    return
