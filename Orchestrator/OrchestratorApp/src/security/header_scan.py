import requests,os
from ..mongo import mongo
from ..comms import image_creator
from datetime import datetime
from .. import constants
from ..slack import slack_sender


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


def handle_single(url, language):
    print('------------------- SINGLE HEADER SCAN STARTING -------------------')
    slack_sender.send_simple_message("Header scan started against %s" % url)
    scan_target(url, url, language)
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


def add_header_value_vulnerability(target_name, scanned_url, timestamp, header, language):
    vuln_name = None
    if language == constants.LANGUAGE_ENGLISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_ENGLISH
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_INVALID_ENGLISH
        else:
            vuln_name = constants.INVALID_VALUE_ON_HEADER_ENGLISH
    if language == constants.LANGUAGE_SPANISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_SPANISH
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_INVALID_SPANISH
        else:
            vuln_name = constants.INVALID_VALUE_ON_HEADER_SPANISH

    mongo.add_vulnerability(target_name, scanned_url,
                            vuln_name, timestamp, language)


def add_header_missing_vulnerability(target_name, scanned_url, timestamp, header, language):
    vuln_name = None
    if language == constants.LANGUAGE_ENGLISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_ENGLISH
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_NOT_PRESENT_ENGLISH
        else:
            vuln_name = constants.HEADER_NOT_FOUND_ENGLISH
    if language == constants.LANGUAGE_SPANISH:
        if header == 'Strict-Transport-Security':
            vuln_name = constants.HSTS_SPANISH
        elif header == 'x-frame-options':
            vuln_name = constants.X_FRAME_OPTIONS_NOT_PRESENT_SPANISH
        else:
            vuln_name = constants.HEADER_NOT_FOUND_SPANISH

    mongo.add_vulnerability(target_name, scanned_url,
                            vuln_name, timestamp, language)


def scan_target(target_name, url_to_scan, language):
    try:
        response = requests.get(url_to_scan)
        print('------------- SAVING RESPONSE TO IMAGE -----------------')
        message = 'Response Headers From: ' + url_to_scan+'\n'
        for h in response.headers:
            message+= h + " : " + response.headers[h]+'\n'
        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        OUTPUT_DIR = ROOT_DIR + '/tools_output'
        image_creator.create_image_from_string(OUTPUT_DIR,target_name,message)
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
                            add_header_value_vulnerability(target_name, url_to_scan, timestamp, header, language)
                            reported = True
            except KeyError:
                slack_sender.send_simple_vuln("Header %s was not found at %s"
                                              % (header, url_to_scan))
                if not reported:
                    timestamp = datetime.now()
                    add_header_missing_vulnerability(target_name, url_to_scan, timestamp, header, language)
                    reported = True
    return
