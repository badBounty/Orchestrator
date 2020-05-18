import subprocess
import os
from datetime import datetime

from ..slack import slack_sender
from ..comms import image_creator
from .. import constants
from ..mongo import mongo


def handle_target(target, url_list, language):
    print('------------------- NMAP SCRIPT TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Nmap scripts started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        host = url['url_with_http'].split('/')[2]
        outdated_software(url['target'], host, language)
        web_versions(url['target'], host, language)
    print('------------------- NMAP SCRIPT TARGET SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- NMAP SCRIPT SCAN STARTING -------------------')
    slack_sender.send_simple_message("Nmap scripts started against %s" % url)
    # We receive the url with http/https, we will get only the host so nmap works
    host = url.split('/')[2]
    outdated_software(url, host, language)
    web_versions(url, host, language)
    print('------------------- NMAP_SCRIPT SCAN FINISHED -------------------')
    return


def add_vuln_to_mongo(target_name, scanned_url, scan_type, extra_info, language):
    timestamp = datetime.now()
    vuln_name = ""
    if language == constants.LANGUAGE_ENGLISH:
        if scan_type == 'outdated_software':
            vuln_name = constants.OUTDATED_SOFTWARE_NMAP_ENGLISH
        elif scan_type == 'http_passwd':
            vuln_name = constants.HTTP_PASSWD_NMAP_ENGLISH
        elif scan_type == 'web_versions':
            vuln_name = constants.WEB_VERSIONS_NMAP_ENGLISH
    elif language == constants.LANGUAGE_SPANISH:
        if scan_type == 'outdated_software':
            vuln_name = constants.OUTDATED_SOFTWARE_NMAP_SPANISH
        elif scan_type == 'http_passwd':
            vuln_name = constants.HTTP_PASSWD_NMAP_SPANISH
        elif scan_type == 'web_versions':
            vuln_name = constants.WEB_VERSIONS_NMAP_SPANISH

    mongo.add_vulnerability(target_name, scanned_url,
                            vuln_name, timestamp, language, extra_info)
    return


def outdated_software(target_name, url_to_scan, language):

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/nmap/nmap-vulners/vulners.nse'

    outdated_software_process = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script='+TOOL_DIR, url_to_scan], capture_output=True
    )
    add_vuln_to_mongo(target_name, url_to_scan, 'outdated_software', str(outdated_software_process.stdout), language)
    return


def web_versions(target_name, url_to_scan, language):

    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    http_jsonp_detection = ROOT_DIR + '/tools/nmap/web_versions/http-jsonp-detection.nse'
    http_open_redirect = ROOT_DIR + '/tools/nmap/web_versions/http-open-redirect.nse'
    http_vuln_cve2017_1001000 = ROOT_DIR + '/tools/nmap/web_versions/http-vuln-cve2017-1001000.nse'
    http_vuln_cve2017_5638 = ROOT_DIR + '/tools/nmap/web_versions/http-vuln-cve2017-5638.nse'

    http_passwd = ROOT_DIR + '/tools/nmap/web_versions/http-passwd.nse'

    http_passwd_subprocess = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script', http_passwd, '--script-args',
         'http-passwd.root=/test/', url_to_scan], capture_output=True)
    add_vuln_to_mongo(target_name, url_to_scan, 'http_passwd', str(http_passwd_subprocess.stdout), language)

    web_versions_subprocess = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script',
         http_jsonp_detection+','+http_open_redirect+','+http_vuln_cve2017_5638+','+http_vuln_cve2017_1001000,
         url_to_scan], capture_output=True)
    add_vuln_to_mongo(target_name, url_to_scan, 'web_versions', str(web_versions_subprocess.stdout), language)
    return

def ssh_ftp_brute_login(target_name,url_to_scan,language,is_ssh):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    if is_ssh:
        brute = ROOT_DIR + '/tools/nmap/nmap-vulners/ssh-brute.nse'
        port = '-p22'
        timeout = 'ssh-brute.timeout=5s'
        end_name = '.ssh.brute'
    else:
        brute = ROOT_DIR + '/tools/nmap/nmap-vulners/ftp-brute.nse'
        port = '-p21'
        timeout = 'ftp-brute.timeout=5s'
        end_name = '.ftp.brute'

    users = ROOT_DIR + '/tools/usernames-shortlist-17.txt'
    password = ROOT_DIR + '/tools/default-pass-13.txt'

    ssh_brute_subprocess = subprocess.run(
        ['nmap', port, '-vvv', '--script', brute, '--script-args',
         'userdb='+users, 'passdb='+password, timeout, url_to_scan, '-oA '+target_name+end_name], capture_output=True)
    return