import requests
import copy
from ..mongo import mongo
from .. import constants
from ..slack import slack_sender
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability


def handle_target(info):
    print('Module HTTP Method scan starting against '+ str(len(info['url_to_scan'])) + ' targets')
    slack_sender.send_simple_message("HTTP method scan started against target: %s. %d alive urls found!"
                                     % (info['target'], len(info['url_to_scan'])))
    subject = 'Module HTTP Method Scan finished'
    desc = ''
    for url in info['url_to_scan']:
        sub_info = copy.deepcopy(info)
        sub_info['url_to_scan'] = url
        print('Scanning ' + url)
        finished_ok = scan_target(sub_info, sub_info['url_to_scan'])
        if finished_ok:
            desc += 'HTTP Method Scan termino sin dificultades para el target {}\n'.format(info['url_to_scan'])
        else:
            desc += 'HTTP Method Scan encontro un problema y no pudo correr para el target {}\n'.format(info['url_to_scan'])
    redmine.create_informative_issue(info,subject,desc)
    print('Module HTTP Mehotd scan finished')
    return


def handle_single(scan_info):
    print('Module HTTP Method scan (single) started against %s' % scan_info['url_to_scan'])
    slack_sender.send_simple_message("HTTP method scan started against %s" % scan_info['url_to_scan'])
    info = copy.deepcopy(scan_info)
    finished_ok = scan_target(info, info['url_to_scan'])
    subject = 'Module HTTP Method Scan finished'
    if finished_ok:
        desc = 'HTTP Method Scan termino sin dificultades para el target {}'.format(scan_info['url_to_scan'])
    else:
        desc = 'HTTP Method Scan encontro un problema y no pudo correr para el target {}'.format(scan_info['url_to_scan'])
    redmine.create_informative_issue(scan_info,subject,desc)
    print('Module HTTP Method scan (single) finished against %s' % scan_info['url_to_scan'])
    return


def add_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.UNSECURE_METHOD, scan_info, message)
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def scan_target(scan_info, url_to_scan):
    responses = list()
    try:
        put_response = requests.put(url_to_scan, data={'key': 'value'})
        responses.append({'method': 'PUT', 'response': put_response})
    except requests.exceptions.SSLError:
        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.TooManyRedirects:
        return False
    

    try:
        delete_response = requests.delete(url_to_scan)
        responses.append({'method': 'DELETE', 'response': delete_response})
    except requests.exceptions.SSLError:
        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.TooManyRedirects:
        return False

    try:
        s = requests.Session()
        req = requests.Request('TRACE',url_to_scan)
        prepped = s.prepare_request(req)
        trace_response = s.send(prepped,verify=False)
        responses.append({'method': 'TRACE', 'response': trace_response})
    except requests.exceptions.SSLError:
        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.TooManyRedirects:
        return False

    try:
        options_response = requests.options(url_to_scan)
        responses.append({'method': 'OPTIONS', 'response': options_response})
    except requests.exceptions.SSLError:
        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.TooManyRedirects:
        return False

    extensive_methods = False
    message = "Found extended HTTP Methods at: %s" % url_to_scan + '\n'
    if not responses:
        return True
    for response in responses:
        if response['response'].status_code == 200:
            extensive_methods = True
            message = message + "Method " + response['method'] + " found." + "\n"
    if extensive_methods:
        add_vulnerability(scan_info, message)
    return True