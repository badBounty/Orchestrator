import subprocess
import os
import xmltodict
import json
import base64
import uuid

from time import sleep
from PIL import Image
from io import BytesIO
from ..slack import slack_sender
from ..comms import image_creator
from .. import constants
from ..mongo import mongo
from ..redmine import redmine
from ...objects.vulnerability import Vulnerability


def cleanup(path):
    try:
        os.remove(path + '.xml')
        os.remove(path + '.nmap')
        os.remove(path + '.gnmap')
    except FileNotFoundError:
        pass
    return


def handle_target(target, url_list, language):
    print('------------------- NMAP SCRIPT TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Nmap scripts started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        host = url['url_with_http'].split('/')[2]
        print('Outdated software')
        outdated_software(url['target'], host, language)
        print('Web versions')
        web_versions(url['target'], host, language)
        print('SSH FTP Bruteforce')
        ssh_ftp_brute_login(url,host, language, True) # SHH
        sleep(10)
        ssh_ftp_brute_login(url,host, language, False) # FTP
        ftp_anon_login(url,host, language) # FTP ANON
        print('Default accounts')
        default_account(url,host, language) # Default creds in web console
    print('------------------- NMAP SCRIPT TARGET SCAN FINISHED -------------------')
    return


def handle_single(scan_info):
    print('------------------- NMAP SCRIPT SCAN STARTING -------------------')
    url = scan_info['url_to_scan']
    slack_sender.send_simple_message("Nmap scripts started against %s" % url)
    # We receive the url with http/https, we will get only the host so nmap works
    host = url.split('/')[2]
    print('------------------- NMAP OUTDATED SOFTWARE -------------------')
    outdated_software(scan_info, host)
    print('------------------- NMAP WEB VERSIONS -------------------')
    web_versions(scan_info, host)
    if scan_info['invasive_scans']:
        print('------------------- NMAP SSH FTP BRUTE FORCE -------------------')
        ssh_ftp_brute_login(scan_info, host, True)#SHH
        sleep(10)
        ssh_ftp_brute_login(scan_info, host, False)#FTP
        ftp_anon_login(scan_info, host)#FTP ANON
        print('------------------- NMAP DEFAULT ACCOUNTS -------------------')
        default_account(scan_info,host)#Default creds in web console
    print('------------------- NMAP_SCRIPT SCAN FINISHED -------------------')
    return


def add_vuln_to_mongo(scan_info, scan_type, description, img_str=None):
    vuln_name = ""
    if scan_type == 'outdated_software':
        vuln_name = constants.OUTDATED_SOFTWARE_NMAP
    elif scan_type == 'http_passwd':
        vuln_name = constants.HTTP_PASSWD_NMAP
    elif scan_type == 'web_versions':
        vuln_name = constants.WEB_VERSIONS_NMAP
    elif scan_type == 'ftp_anonymous':
        vuln_name = constants.ANON_ACCESS_FTP
    elif scan_type == 'ssh_credentials':
        vuln_name = constants.DEFAULT_CREDS
    elif scan_type == "ftp_credentials":
        vuln_name = constants.CRED_ACCESS_FTP
    elif scan_type == "default_creds":
        vuln_name = constants.DEFAULT_CREDS

    vulnerability = Vulnerability(vuln_name, scan_info, description)
    vulnerability.add_image_string(img_str)

    if img_str:
        ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
        random_filename = uuid.uuid4().hex
        output_dir = ROOT_DIR+'/tools_output/' + random_filename + '.png'
        im = Image.open(BytesIO(base64.b64decode(img_str)))
        im.save(output_dir, 'PNG')
        vulnerability.add_attachment(output_dir, 'nmap-result.png')
        os.remove(output_dir)

    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)
    return


def outdated_software(scan_info, url_to_scan):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    TOOL_DIR = ROOT_DIR + '/tools/nmap/nmap-vulners/vulners.nse'

    outdated_software_process = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script=' + TOOL_DIR, url_to_scan], capture_output=True
    )
    text = outdated_software_process.stdout.decode()
    text = text.split('\n')

    extra_info = "Outdated software nmap result: \n"
    outdated_software_found = False
    for line in text:
        if 'CVE' in line:
            outdated_software_found = True
            extra_info = extra_info + line
    if outdated_software_found:
        add_vuln_to_mongo(scan_info, 'outdated_software', extra_info)
    return


def web_versions(scan_info, url_to_scan):
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
    extra_info_httpd_passwd = 'Http-passwd.nse nmap result: \n'
    traversal_found = False
    for i in range(0, len(text_httpd_passwd)):
        if 'Directory traversal found' in text_httpd_passwd[i]:
            traversal_found = True
            extra_info_httpd_passwd = extra_info_httpd_passwd + text_httpd_passwd[i-1] + " \n " +\
                                      text_httpd_passwd[i] + " \n " +\
                                      text_httpd_passwd[i+1]
    if traversal_found:
        add_vuln_to_mongo(scan_info, 'http_passwd', extra_info_httpd_passwd)

    web_versions_subprocess = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script',
         http_jsonp_detection + ',' + http_open_redirect + ',' + http_vuln_cve2017_5638 + ',' + http_vuln_cve2017_1001000,
         url_to_scan], capture_output=True)
    text_web_versions = str(web_versions_subprocess.stdout.decode())
    text_web_versions = text_web_versions.split('\n')

    extra_info_web_versions = 'Nmap web-versions script: \n'
    web_versions_found = False
    for i in range(0, len(text_web_versions)):
        if 'The following JSONP endpoints were detected' in text_web_versions[i] and 'ERROR' not in text_web_versions[i]:
            web_versions_found = True
            extra_info_web_versions = extra_info_web_versions + text_web_versions[i-1] + " \n " +\
                                           text_web_versions[i] + " \n " + text_web_versions[i+1]
        if 'http-open-redirect' in text_web_versions[i] and 'ERROR' not in text_web_versions[i]:
            web_versions_found = True
            extra_info_web_versions = extra_info_web_versions + text_web_versions[i] + " \n " +\
                                           text_web_versions[i+1]
        if 'http-vuln-cve2017-5638' in text_web_versions[i] and 'ERROR' not in text_web_versions[i]:
            web_versions_found = True
            extra_info_web_versions = extra_info_web_versions + text_web_versions[i] + " \n " +\
                                           text_web_versions[i+1] + " \n " + text_web_versions[i+2]
        if 'http-vuln-cve2017-1001000' in text_web_versions[i] and 'ERROR' not in text_web_versions[i]:
            web_versions_found = True
            extra_info_web_versions = extra_info_web_versions + text_web_versions[i] + " \n " +\
                                           text_web_versions[i+1] + " \n " + text_web_versions[i+2]
    if web_versions_found:
        add_vuln_to_mongo(scan_info, 'web_versions', extra_info_web_versions)
    return


def ssh_ftp_brute_login(scan_info, url_to_scan, is_ssh):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    timeout = 'timeout=5s'
    time_limit = '180' #seconds
    if is_ssh:
        brute = ROOT_DIR + '/tools/nmap/server_versions/ssh-brute.nse'
        port = '-p22'
        end_name = '.ssh.brute'
    else:
        brute = ROOT_DIR + '/tools/nmap/server_versions/ftp-brute.nse'
        port = '-p21'
        end_name = '.ftp.brute'
    users = ROOT_DIR + '/tools/usernames-shortlist.txt'
    password = ROOT_DIR + '/tools/default-pass.txt'
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR + '/tools_output/'+random_filename+end_name
    cleanup(output_dir)
    brute_subprocess = subprocess.run(
        ['nmap', '-Pn', '-sV', port, '--script', brute, '--script-args',
         'userdb='+users+','+'passdb='+password+','+timeout+','+'brute.delay='+time_limit+','+'brute.retries=1', '-oA', output_dir,url_to_scan])
    print(brute_subprocess)
    with open(output_dir + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    try:
        message = json_data['nmaprun']['host']['ports']['port']['script']['@output']
        if "Valid credentials" in message:
            name = "ssh_credentials" if is_ssh else "ftp_credentials"
            img_str = image_creator.create_image_from_file(output_dir + '.nmap')
            add_vuln_to_mongo(scan_info, name, message, img_str)
    except KeyError:
        message = None
    cleanup(output_dir)
    return


def ftp_anon_login(scan_info,url_to_scan):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    end_name = '.ftp.anon'
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR + '/tools_output/' + random_filename + end_name
    cleanup(output_dir)
    anonynomus_subprocess = subprocess.run(
        ['nmap', '-Pn', '-sV', '-p21', '-vvv', '--script', 'ftp-anon', '-oA', output_dir,url_to_scan])
    with open(output_dir + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    try:
        message = json_data['nmaprun']['host']['ports']['port']['script']['@output']
        if "Anonymous FTP login allowed" in message:
            img_str = image_creator.create_image_from_file(output_dir + '.nmap')
            add_vuln_to_mongo(scan_info, "ftp_anonymous", message, img_str)
    except KeyError:
        message = None
    cleanup(output_dir)
    return


def http_errors(target_name, url_to_scan, language):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    end_name = '.htttp.errors'
    random_filename = uuid.uuid4().hex
    output_dir = ROOT_DIR + '/tools_output/' + random_filename + end_name
    port_list = '-p 80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888 '
    cleanup(output_dir)
    http_subprocess = subprocess.run(
        ['nmap','-Pn', '-sV', port_list, '-vvv', '--script', ' http-errors ', '-oA', output_dir,url_to_scan], capture_output=True)
    with open(output_dir + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    ports = json_data['nmaprun']['host']['ports']['port']
    message = ""
    for p in ports:
        pid = p['@portid']
        if p['state']['@state'] == 'open':
            if type(p['script']) == 'dict':
                o = p['script']['@output']
                if "Error Code:" in o:
                    message +=o
            else:
                for o in p['script']:
                    try:
                        if "Error Code:" in o['@output']:
                            message +=o['@output']
                    except TypeError:
                        pass
    cleanup(output_dir)
    if message:
        vuln_name = constants.POSSIBLE_ERROR_PAGES_ENGLISH if language == "eng" else constants.POSSIBLE_ERROR_PAGES_SPANISH
        redmine.create_new_issue(vuln_name, message)
    return


def default_account(scan_info,url_to_scan):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    arg_fingerprint_dir = ROOT_DIR+'/tools/http-default-accounts-fingerprints-nndefaccts.lua'
    script_to_launch = ROOT_DIR+'/tools/nmap/web_versions/http-default-accounts.nse'
    ports='80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888'
    random_filename = uuid.uuid4().hex
    end_name = '.http.def.acc'
    output_dir = ROOT_DIR + '/tools_output/'+random_filename+end_name
    message=""
    da_subprocess = subprocess.run(
        ['nmap','-Pn', '-sV', '-p'+ports, '--script', script_to_launch, '--script-args','http-default-accounts.fingerprintfile='+arg_fingerprint_dir, '-oA', output_dir,url_to_scan],capture_output=True)

    with open(output_dir+ '.xml') as xml_file:
            my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    for port in json_data['nmaprun']['host']['ports']['port']:
        try:
            for scp in port['script']:
                if isinstance(scp, dict):
                    if "] at /" in scp['@output']:
                        message+=scp['@output']
        except KeyError:
            pass
    print(message)
    if message:
        img_str = image_creator.create_image_from_string(message)
        add_vuln_to_mongo(scan_info, "default_creds", message, img_str)
    cleanup(output_dir)
    return