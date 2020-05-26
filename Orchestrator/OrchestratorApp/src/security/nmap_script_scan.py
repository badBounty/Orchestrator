import subprocess
import os
import xmltodict
import json
from datetime import datetime

from ..slack import slack_sender
from ..comms import image_creator
from .. import constants
from ..mongo import mongo
from ..redmine import redmine


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
    print('------------------- NMAP SSH FTP BRUTE FORCE -------------------')
    ssh_ftp_brute_login(scan_info, host, True)#SHH
    ssh_ftp_brute_login(scan_info, host, False)#FTP
    ftp_anon_login(scan_info, host)#FTP ANON
    print('------------------- NMAP DEFAULT ACCOUNTS -------------------')
    default_account(scan_info,host)#Default creds in web console
    print('------------------- NMAP_SCRIPT SCAN FINISHED -------------------')
    return


def add_vuln_to_mongo(scan_info, scanned_url, scan_type, extra_info, img_str=None):
    timestamp = datetime.now()
    vuln_name = ""
    if scan_info['language'] == constants.LANGUAGE_ENGLISH:
        if scan_type == 'outdated_software':
            vuln_name = constants.OUTDATED_SOFTWARE_NMAP_ENGLISH
        elif scan_type == 'http_passwd':
            vuln_name = constants.HTTP_PASSWD_NMAP_ENGLISH
        elif scan_type == 'web_versions':
            vuln_name = constants.WEB_VERSIONS_NMAP_ENGLISH
        elif scan_type == 'ftp_anonymous':
            vuln_name = constants.ANONYMOUS_ACCESS_FTP_ENGLISH
        elif scan_type == 'ssh_credentials':
            vuln_name = constants.DEFAULT_CREDENTIALS_ENGLISH
        elif scan_type == "ftp_credentials":
            vuln_name = constants.CREDENTIALS_ACCESS_FTP_ENGLISH
        elif scan_type == "default_creds":
            vuln_name = constants.DEFAULT_CREDENTIALS_ENGLISH
    elif scan_info['language'] == constants.LANGUAGE_SPANISH:
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
        elif scan_type == "default_creds":
            vuln_name = constants.DEFAULT_CREDENTIALS_SPANISH

    slack_sender.send_simple_vuln("Nmap " + scan_type + " script found: \n" + str(extra_info))
    redmine.create_new_issue(vuln_name, extra_info, scan_info['redmine_project'])
    mongo.add_vulnerability(scan_info['target'], scanned_url,
                            vuln_name, timestamp, scan_info['language'], extra_info, img_str)
    return


def outdated_software(scan_info, url_to_scan):
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
        add_vuln_to_mongo(scan_info, url_to_scan, 'outdated_software', extra_info)
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
    extra_info_httpd_passwd = list()
    for i in range(0, len(text_httpd_passwd)):
        if 'Directory traversal found' in text_httpd_passwd[i]:
            extra_info_httpd_passwd.append(text_httpd_passwd[i-1] + '\n' + text_httpd_passwd[i] + '\n' + text_httpd_passwd[i+1])
    if extra_info_httpd_passwd:
        add_vuln_to_mongo(scan_info, url_to_scan, 'http_passwd', extra_info_httpd_passwd)

    web_versions_subprocess = subprocess.run(
        ['nmap', '-sV', '-Pn', '-vvv', '--top-ports=500', '--script',
         http_jsonp_detection + ',' + http_open_redirect + ',' + http_vuln_cve2017_5638 + ',' + http_vuln_cve2017_1001000,
         url_to_scan], capture_output=True)
    text_web_versions = str(web_versions_subprocess.stdout.decode())
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
        add_vuln_to_mongo(scan_info, url_to_scan, 'web_versions', extra_info_web_versions)
    return


def ssh_ftp_brute_login(scan_info, url_to_scan, is_ssh):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    if is_ssh:
        brute = ROOT_DIR + '/tools/nmap/server_versions/ssh-brute.nse'
        port = '-p22'
        timeout = 'timeout=5s'
        end_name = '.ssh.brute'
    else:
        brute = ROOT_DIR + '/tools/nmap/server_versions/ftp-brute.nse'
        port = '-p21'
        timeout = 'timeout=5s'
        end_name = '.ftp.brute'

    users = ROOT_DIR + '/tools/usernames-shortlist.txt'
    password = ROOT_DIR + '/tools/default-pass.txt'
    output_dir = ROOT_DIR + '/tools_output/'+url_to_scan+end_name
    brute_subprocess = subprocess.run(
        ['nmap', '-Pn', '-sV', port, '-vvv', '--script', brute, '--script-args',
         'userdb='+users+','+'passdb='+password+','+timeout, url_to_scan, '-oA', output_dir])
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
            add_vuln_to_mongo(scan_info, url_to_scan, name, message, img_str)
    except KeyError:
        message = None
    try:
        os.remove(output_dir + '.xml')
        os.remove(output_dir + '.nmap')
        os.remove(output_dir + '.gnmap')
    except FileNotFoundError:
        pass
    return


def ftp_anon_login(scan_info,url_to_scan):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    end_name = '.ftp.anon'
    output_dir = ROOT_DIR + '/tools_output/'+url_to_scan+end_name
    anonynomus_subprocess = subprocess.run(
        ['nmap', '-Pn', '-sV', '-p21', '-vvv', '--script', 'ftp-anon',  url_to_scan, '-oA', output_dir])
    with open(output_dir + '.xml') as xml_file:
        my_dict = xmltodict.parse(xml_file.read())
    xml_file.close()
    json_data = json.dumps(my_dict)
    json_data = json.loads(json_data)
    try:
        message = json_data['nmaprun']['host']['ports']['port']['script']['@output']
        if "Anonymous FTP login allowed" in message:
            img_str = image_creator.create_image_from_file(output_dir + '.nmap')
            add_vuln_to_mongo(scan_info, url_to_scan, "ftp_anonymous", message, img_str)
    except KeyError:
        message = None
    try:
        os.remove(output_dir + '.xml')
        os.remove(output_dir + '.nmap')
        os.remove(output_dir + '.gnmap')
    except FileNotFoundError:
        pass

    return

def http_errors(target_name,url_to_scan,language):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    end_name = '.htttp.errors'
    output_dir = ROOT_DIR + '/tools_output/'+url_to_scan+end_name
    port_list = '-p 80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888 '
    http_subprocess = subprocess.run(
        ['nmap','-Pn', '-sV', port_list, '-vvv', '--script', ' http-errors ',  url_to_scan, '-oA', output_dir],capture_output=True)
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
    try:
        os.remove(output_dir + '.xml')
        os.remove(output_dir + '.nmap')
        os.remove(output_dir + '.gnmap')
    except FileNotFoundError:
        pass
    if message:
        vuln_name = constants.POSSIBLE_ERROR_PAGES_ENGLISH if language == "eng" else constants.POSSIBLE_ERROR_PAGES_SPANISH
        redmine.create_new_issue(vuln_name, message)
    return

def default_account(scan_info,url_to_scan):
    ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
    arg_fingerprint_dir = ROOT_DIR+'/tools/http-default-accounts-fingerprints-nndefaccts.lua'
    script_to_copy = ROOT_DIR+'/tools/nmap/web_versions/http-default-accounts.nse'
    script_to_launch = ROOT_DIR+'/tools/nmap/web_versions/'+url_to_scan+'.hda.nse'
    end_name = '.http.def.acc'
    output_dir = ROOT_DIR + '/tools_output/'+url_to_scan+end_name
    ports = '80,81,443,591,2082,2087,2095,2096,3000,8000,8001,8008,8080,8083,8443,8834,8888'
    message=""
    #ACA ABRIMOS EL SCRIPT Y MODIFICAMOS LA INFORMACION QUE NECESITAMOS
    with open(script_to_copy,'r') as script_edit:
        list_of_lines = script_edit.readlines()
    list_of_lines[108] = 'portrule = shortport.port_or_service( {'+ports+'}, {"http", "https"}, "tcp", "open")'
    with open(script_to_launch,'w') as script_edit:
        script_edit.writelines(list_of_lines)

    da_subprocess = subprocess.run(
        ['nmap','-Pn', '-sV', '-p'+ports,'-vvv', '--script', script_to_launch, '--script-args','http-default-accounts.fingerprintfile='+arg_fingerprint_dir,  url_to_scan, '-oA', output_dir],capture_output=True)   

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
        add_vuln_to_mongo(scan_info, url_to_scan, "default_creds",message,img_str)
    try:
        os.remove(output_dir + '.xml')
        os.remove(output_dir + '.nmap')
        os.remove(output_dir + '.gnmap')
        os.remove(script_to_launch)
    except FileNotFoundError:
        pass

    return