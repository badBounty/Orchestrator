import requests
from ..mongo import mongo
from datetime import datetime


def handle_target(url_list):
    print('------------------- TARGET HEADER SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'])
    print('-------------------  TARGET HEADER SCAN FINISHED -------------------')
    return


def handle_single(url):
    print('------------------- SINGLE HEADER SCAN STARTING -------------------')
    scan_target(url, url)
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


def scan_target(target_name, url_to_scan):
    try:
        response = requests.get(url_to_scan)
    except requests.exceptions.SSLError:
        return

    important_headers = ['Content-Security-Policy', 'X-XSS-Protection', 'x-frame-options', 'X-Content-Type-options',
                         'Strict-Transport-Security', 'Access-Control-Allow-Origin']

    if response.status_code != 404:
        for header in important_headers:
            try:
                # If the header exists
                if response.headers[header]:
                    if not check_header_value(header, response.headers[header]):
                        timestamp = datetime.now()
                        mongo.add_vulnerability(target_name, url_to_scan,
                                                "Header " + header + " was found with invalid value",
                                                timestamp)
            except KeyError:
                # If header does not exist
                timestamp = datetime.now()
                mongo.add_vulnerability(target_name, url_to_scan,
                                        "Header " + header + " was missing",
                                        timestamp)
    return
