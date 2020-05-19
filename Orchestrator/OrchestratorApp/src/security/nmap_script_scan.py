import subprocess
import os
import xmltodict
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
        ssh_ftp_brute_login(url,host,language,True)#SHH
        ssh_ftp_brute_login(url,host,language,False)#FTP
    print('------------------- NMAP SCRIPT TARGET SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- NMAP SCRIPT SCAN STARTING -------------------')
    slack_sender.send_simple_message("Nmap scripts started against %s" % url)
    # We receive the url with http/https, we will get only the host so nmap works
    host = url.split('/')[2]
    outdated_software(url, host, language)
    web_versions(url, host, language)
    ssh_ftp_brute_login(url,host,language,True)#SHH
    ssh_ftp_brute_login(url,host,language,False)#FTP
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
        elif scan_type == 'ftp_anonymous':
            vuln_name = constants.WEB_VERSIONS_NMAP_ENGLISH
        elif scan_type == 'ssh_credentials':
            vuln_name = constants.DEFAULT_CREDENTIALS_ENGLISH
        elif scan_type == "ftp_credentials":
            vuln_name = constants.CREDENTIALS_ACCESS_FTP_ENGLISH
    elif language == constants.LANGUAGE_SPANISH:
        if scan_type == 'outdated_software':
            vuln_name = constants.OUTDATED_SOFTWARE_NMAP_SPANISH
        elif scan_type == 'http_passwd':
            vuln_name = constants.HTTP_PASSWD_NMAP_SPANISH
        elif scan_type == 'web_versions':
            vuln_name = constants.WEB_VERSIONS_NMAP_SPANISH
        elif scan_type == 'ftp_anonymous':
            vuln_name = constants.ANONYMOUS_ACCESS_FTP_SPANISH
        elif scan_type == 'ssh_credentials':
            vuln_name = constants.DEFAULT_CREDENTIALS_SPANISH
        elif scan_type == "ftp_credentials":
            vuln_name = constants.DEFAULT_CREDENTIALS_SPANISH
    mongo.add_vulnerability(target_name, scanned_url,
                            vuln_name, timestamp, language, extra_info)
    return


def outdated_software(target_name, url_to_scan, language):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/nmap/nmap-vulners/vulners.nse'

    outdated_software_process = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script=' + TOOL_DIR, url_to_scan], capture_output=True
    )
    text = outdated_software_process.stdout.decode()
    text = text.split('\n')

    extra_info = list()
    for line in text:
        if 'CVE' in line:
            extra_info.append(line)
    if extra_info:
        add_vuln_to_mongo(target_name, url_to_scan, 'outdated_software', extra_info, language)
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
    text_httpd_passwd = http_passwd_subprocess.stdout.decode()
    text_httpd_passwd = text_httpd_passwd.split('\n')
    extra_info_httpd_passwd = list()
    for i in range(0, len(text_httpd_passwd)):
        if 'Directory traversal found' in text_httpd_passwd[i]:
            extra_info_httpd_passwd.append(text_httpd_passwd[i-1] + '\n' + text_httpd_passwd[i] + '\n' + text_httpd_passwd[i+1])
    if extra_info_httpd_passwd:
        add_vuln_to_mongo(target_name, url_to_scan, 'http_passwd', extra_info_httpd_passwd, language)

    web_versions_subprocess = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script',
         http_jsonp_detection + ',' + http_open_redirect + ',' + http_vuln_cve2017_5638 + ',' + http_vuln_cve2017_1001000,
         url_to_scan], capture_output=True)
    text_web_versions = web_versions_subprocess.stdout.decode()
    text_web_versions = text_web_versions.split('\n')

    extra_info_web_versions = list()
    for i in range(0, len(text_web_versions)):
        if 'The following JSONP endpoints were detected' in text_web_versions[i]:
            extra_info_web_versions.append(text_web_versions[i-1] + '\n' +
                                           text_web_versions[i] + '\n' + text_web_versions[i+1])
        if 'http-open-redirect' in text_web_versions[i]:
            extra_info_web_versions.append(text_web_versions[i] + '\n' +
                                           text_web_versions[i+1])
        if 'http-vuln-cve2017-5638' in text_web_versions[i]:
            extra_info_web_versions.append(text_web_versions[i] + '\n' +
                                           text_web_versions[i+1] + '\n' + text_web_versions[i+2])
        if 'http-vuln-cve2017-1001000' in text_web_versions[i]:
            extra_info_web_versions.append(text_web_versions[i] + '\n' +
                                           text_web_versions[i+1] + '\n' + text_web_versions[i+2])
    if extra_info_web_versions:
        add_vuln_to_mongo(target_name, url_to_scan, 'web_versions', extra_info_web_versions, language)
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

    users = ROOT_DIR + '/tools/usernames-shortlist.txt'
    password = ROOT_DIR + '/tools/default-pass.txt'

    ssh_brute_subprocess = subprocess.run(
        ['nmap','-Pn', '-sV', port, '-vvv', '--script', brute, '--script-args',
         'userdb='+users, 'passdb='+password, timeout, url_to_scan, '-oA '+target_name+end_name], capture_output=True)
    
    with open(ROOT_DIR + '/' + target_name+end_name + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    try:
        message = json_data['nmaprun']['host']['ports']['port']['script']['@output']
        if "Valid credentials" in message:
            name = "ssh_credentials" if is_ssh else "ftp_credentials"
            add_vuln_to_mongo(target_name, url_to_scan, name, name,message, language)
    except KeyError:
        message = None
    try:
        os.remove(ROOT_DIR + '/' + target_name+end_name + '.xml')
        os.remove(ROOT_DIR + '/' + target_name+end_name + '.nmap')
        os.remove(ROOT_DIR + '/' + target_name+end_name + '.gnmap')
    except FileNotFoundError:
        pass
    return

def ftp_anon_login(target_name,url_to_scan,language):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    end_name = '.ftp.anon'
    anonynomus_subprocess = subprocess.run(
        ['nmap','-Pn', '-sV', '-p21', '-vvv', '--script', 'ftp-anon',  url_to_scan, '-oA', target_name+end_name])
    with open(ROOT_DIR + '/' + target_name+end_name + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    try:
        message = json_data['nmaprun']['host']['ports']['port']['script']['@output']
        if "Anonymous FTP login allowed" in message:
            add_vuln_to_mongo(target_name, url_to_scan, name, "ftp_anonymous",message, language)   
    except KeyError:
        message = None
    try:
        os.remove(ROOT_DIR + '/' + target_name+end_name + '.xml')
        os.remove(ROOT_DIR + '/' + target_name+end_name + '.nmap')
        os.remove(ROOT_DIR + '/' + target_name+end_name + '.gnmap')
    except FileNotFoundError:
        pass

    return