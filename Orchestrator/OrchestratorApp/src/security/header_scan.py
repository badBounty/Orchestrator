import requests,os
import base64
from PIL import Image
from io import BytesIO
from ..mongo import mongo
from ..comms import image_creator
from datetime import datetime
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine


def handle_target(target, url_list, language):
    print('------------------- TARGET HEADER SCAN STARTING -------------------')
    slack_sender.send_simple_message("Header scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
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


def add_header_value_vulnerability(scan_info, scanned_url, timestamp, header, img_b64):
    vuln_name = None
    redmine_description = None
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_ENGLISH
            redmine_description = constants.REDMINE_HSTS
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_INVALID_ENGLISH
            redmine_description = constants.REDMINE_X_FRAME_OPTIONS_INVALID
        else:
            vuln_name = constants.INVALID_VALUE_ON_HEADER_ENGLISH
            redmine_description = constants.REDMINE_INVALID_VALUE_ON_HEADER
    if scan_info['language'] == constants.LANGUAGE_SPANISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_SPANISH
            redmine_description = constants.REDMINE_HSTS
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_INVALID_SPANISH
            redmine_description = constants.REDMINE_X_FRAME_OPTIONS_INVALID
        else:
            vuln_name = constants.INVALID_VALUE_ON_HEADER_SPANISH
            redmine_description = constants.REDMINE_INVALID_VALUE_ON_HEADER

    # vuln = new Vulnerability('Insecure header configuration')

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    output_dir = ROOT_DIR+'/tools_output/headers-result.png'
    im = Image.open(BytesIO(base64.b64decode(img_b64)))
    im.save(output_dir, 'PNG')
    redmine.create_new_issue(vuln_name, redmine_description % scanned_url,
                             scan_info['redmine_project'], scan_info['assigned_users'], scan_info['watchers'],output_dir,'headers-result.png')
    os.remove(output_dir)
    mongo.add_vulnerability(scan_info['target'], scanned_url,vuln_name, timestamp, scan_info['language'], None, img_b64)


def add_header_missing_vulnerability(scan_info, scanned_url, timestamp, header, img_b64):
    vuln_name = None
    redmine_description = None
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_ENGLISH
            redmine_description = constants.REDMINE_HSTS
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_NOT_PRESENT_ENGLISH
            redmine_description = constants.REDMINE_X_FRAME_OPTIONS_NOT_PRESENT
        else:
            vuln_name = constants.HEADER_NOT_FOUND_ENGLISH
            redmine_description = constants.REDMINE_HEADER_NOT_FOUND
    if scan_info['language'] == constants.LANGUAGE_SPANISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_SPANISH
            redmine_description = constants.REDMINE_HSTS
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_NOT_PRESENT_SPANISH
            redmine_description = constants.REDMINE_X_FRAME_OPTIONS_NOT_PRESENT
        else:
            vuln_name = constants.HEADER_NOT_FOUND_SPANISH
            redmine_description = constants.REDMINE_HEADER_NOT_FOUND

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    output_dir = ROOT_DIR+'/tools_output/headers-result.png'
    im = Image.open(BytesIO(base64.b64decode(img_b64)))
    im.save(output_dir, 'PNG')
    redmine.create_new_issue(vuln_name, redmine_description % scanned_url, scan_info['redmine_project'], scan_info['assigned_users'], scan_info['watchers'],output_dir,'headers-result.png')
    os.remove(output_dir)
    mongo.add_vulnerability(scan_info['target'], scanned_url, vuln_name, timestamp, scan_info['language'], None, img_b64)


def scan_target(scan_info, url_to_scan):
    try:
        response = requests.get(url_to_scan)
        print('------------- SAVING RESPONSE TO IMAGE -----------------')
        message = 'Response Headers From: ' + url_to_scan+'\n'
        for h in response.headers:
            message+= h + " : " + response.headers[h]+'\n'
        img_b64 = image_creator.create_image_from_string(message)
    except requests.exceptions.SSLError:
        return
    except requests.exceptions.ConnectionError:
        return

    important_headers = ['Content-Security-Policy', 'X-XSS-Protection', 'x-frame-options', 'X-Content-Type-options',
                         'Strict-Transport-Security', 'Access-Control-Allow-Origin']
    reported = False
    if response.status_code != 404:
        for header in important_headers:
            try:
                # If the header exists
                if response.headers[header]:
                    if not check_header_value(header, response.headers[header]):
                        slack_sender.send_simple_vuln("Header %s was found with invalid value at %s"
                                                      % (header, url_to_scan))
                        # No header differenciation, so we do this for now
                        if not reported:
                            timestamp = datetime.now()
                            add_header_value_vulnerability(scan_info, url_to_scan, timestamp, header, img_b64)
                            reported = True
            except KeyError:
                slack_sender.send_simple_vuln("Header %s was not found at %s"
                                              % (header, url_to_scan))
                if not reported:
                    timestamp = datetime.now()
                    add_header_missing_vulnerability(scan_info, url_to_scan, timestamp, header, img_b64)
                    reported = True
    return
