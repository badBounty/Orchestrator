from ..slack import slack_sender
from ..mongo import mongo
from ..redmine import redmine
from .. import constants
from ...objects.vulnerability import Vulnerability
from Orchestrator.settings import acunetix,acunetix_info
from collections import defaultdict

import time
import requests
import json
import re
import copy


login_json = {
    'email':acunetix_info['USER'],
    'password':acunetix_info['PASSWORD_HASH'],
    'remember_me':acunetix_info['REMEMBER_ME'],
    'logout_previous':acunetix_info['LOGOUT_PREVIOUS']
}
headers = {
    'X-auth':'',
    'X-Cookie':''
}
verify = False
#Getting max scans possible
max_scans_possible = acunetix_info['MAX_SCANS_POSSIBLE']
profile_id = acunetix_info['SCAN_PROFILE']
ui_session_id = acunetix_info['UI_SESSION_ID']
basic_url = acunetix_info['URL']
#LOGIN - POST
login_url = '/api/v1/me/login'
#CREATE TARGET - POST 
target_url = '/api/v1/targets'
#LAUNCH / START SCAN - POST
launch_scan_url = '/api/v1/scans'

def is_url(url):
    split_url = url.split('/')
    try:
        url = split_url[2]
        return True
    except IndexError:
        return False

def handle_target(info):
    if info['acunetix_scan'] and acunetix:
        info_copy = copy.deepcopy(info)
        print("Module Acunetix scan started against target: %s. %d alive urls found!"% (info['target'], len(info['url_to_scan'])))
        slack_sender.send_simple_message("Acunetix scan started against target: %s. %d alive urls found!"
                                        % (info['target'], len(info['url_to_scan'])))
        full_list = info['url_to_scan']
        info_for_scan = copy.deepcopy(info_copy)
        info_for_scan['url_to_scan'] = full_list
        scan_target(info_for_scan)
        print('Module Acunetix scan finished against target: %s'% info['target'])
    return


def handle_single(scan_information):
    if scan_information['acunetix_scan'] and acunetix and is_url(scan_information['url_to_scan']):
        print('Module Acunetix (single) scan started against target: %s'% scan_information['target'])
        slack_sender.send_simple_message("Acunetix scan started against %s" % scan_information['url_to_scan'])
        urls = [scan_information['url_to_scan']]
        info = copy.deepcopy(scan_information)
        info['url_to_scan'] = urls
        scan_target(info)
        print('Module Acunetix (single) scan finished against target:%s' % scan_information['url_to_scan'])
    return

def add_vulnerability(scan_info,scan_id,vulns):
    info = copy.deepcopy(scan_info)
    info['url_to_scan'] = scan_id[1]
    default_dict = defaultdict(list)
    default_dict_extra = defaultdict(list)
    for vul in vulns:
        default_dict[vul['vt_name']].append(vul['affects_url'])
        default_dict_extra[vul['vt_name']].append(vul['request'])
    result = [{"title": k, "resourceAf": v} for k, v in default_dict.items()]
    result_extra = [{"title": k, "request_info": v} for k, v in default_dict_extra.items()]
    for r, re in zip(result, result_extra):
        r['request_info'] = re['request_info'][0]
    for res in result:
        #Checking if is not a vulnerability already reported by other tool
        if res['title'] not in acunetix_info['BLACK_LIST']:
            affected_urls = ('\n'.join(res['resourceAf'])+'\n'+''.join(res['request_info']))
            name = {'english_name':constants.ACUNETIX_SCAN['english_name']+ res['title']}
            description = 'Acunetix scan completed against %s' % info['url_to_scan'] +'\n Affecteds URLS>'
            vulnerability = Vulnerability(name, info, description+affected_urls)
            slack_sender.send_simple_vuln(vulnerability)
            redmine.create_new_issue(vulnerability)
            mongo.add_vulnerability(vulnerability)
    return

def start_acu_scan(scan_info,headers,session):
    id_list = list()
    for url in scan_info['url_to_scan']:        
        target_json = {'address':url,'description':'Created by orchestrator one-shot'}
        #Creating target to scan
        r = session.post(basic_url+target_url,json=target_json,verify=verify,headers=headers)
        target_id = json.loads(r.text)['target_id']
        scan_json = {'target_id':target_id,
                'profile_id':profile_id,
                'schedule':{'disable':False,'start_date':None,'time_sensitive':False},
                'ui_session_id':ui_session_id
                }
        #Creating scan and launch it
        r = session.post(basic_url+launch_scan_url,json=scan_json,verify=verify,headers=headers)
        scan_url_with_id = r.headers['Location']
        tup = (scan_url_with_id,url)
        id_list.append(tup)
    return id_list

def check_acu_status_and_create_vuln(scan_info,id_list,headers,session):
    all_finished = False
    #Check the status of each scan
    time.sleep(10)
    while not all_finished:
        for scan_id in id_list:
            scan_url_with_id = scan_id[0]
            #Getting status of the project
            r = session.get(basic_url+scan_url_with_id,verify=verify,headers=headers)
            json_scan = json.loads(r.text)
            #Just in case we get disconnected from some reason
            try:
                json_scan['code']
                if json_scan['message'] == 'Unauthorized':
                    r = session.post(basic_url+login_url,json=login_json,verify=verify)
                    #Get login values
                    headers['X-Auth'] = r.headers['X-Auth']
                    headers['X-Cookie'] = r.headers['Set-Cookie']
                    r = session.get(basic_url+scan_url_with_id,verify=verify,headers=headers)
                    json_scan = json.loads(r.text)
            except KeyError:
                pass
            status_scan = json_scan['current_session']['status']
            scan_session_id = ''
            if status_scan != 'processing' and status_scan != 'completed':
                id_list.remove(scan_id)
                print('The scanned url: '+scan_id[1]+' has been paused or stopped go to acunetix and checked manually')
            elif status_scan == 'completed':
                
                target_id = json_scan['target_id']
                #Scan finished getting vulnerabilities
                id_list.remove(scan_id)
                scan_session_id = json_scan['current_session']['scan_session_id']
                vulns_scan_url = scan_url_with_id+'/results/{}/vulnerabilities'.format(scan_session_id)
                r = session.get(basic_url+vulns_scan_url,verify=verify,headers=headers)
                vulns = json.loads(r.text)['vulnerabilities']
                final_vulns = list()
                #White listing the vulnerabilties
                for vul in vulns:
                    if vul['severity'] >= acunetix_info['WHITE_LIST_SEVERITY']:
                        vuln_complete = scan_url_with_id+'/results/{}/vulnerabilities/{}'.format(scan_session_id,vul['vuln_id'])
                        #Get Requests from vulnerability
                        r = session.get(basic_url+vuln_complete,verify=verify,headers=headers)
                        vuln_request = json.loads(r.text)['request']
                        #Adding request info to vul
                        vul['request'] = vuln_request
                        final_vulns.append(vul)
                add_vulnerability(scan_info,scan_id, final_vulns)
                #Deleting target after scan is performed
                session.delete(basic_url+target_url+'/'+target_id,verify=verify,headers=headers)
        time.sleep(180)
        if len(id_list) == 0:
            all_finished = True
    return 

def check_if_scan_is_possible(headers,session):
    #Get already runned runnings scans
    r = session.get(basic_url+launch_scan_url,verify=verify,headers=headers)
    json_data = json.loads(r.text)
    scans_running = len(json_data['scans'])
    if scans_running < max_scans_possible:
        #We can launch a scan
        return True,max_scans_possible if scans_running == 0 else (max_scans_possible-scans_running)
    else:
        return False,0


def scan_target(scan_info):
    wait_until_its_free = True
    session = requests.Session()
    #Login against acunetix
    r = session.post(basic_url+login_url,json=login_json,verify=verify)
    #Get login values
    headers['X-Auth'] = r.headers['X-Auth']
    headers['X-Cookie'] = r.headers['Set-Cookie']
    while wait_until_its_free:
        is_possible,scans_number = check_if_scan_is_possible(headers,session)
        if is_possible:
            for i in range(0,len(scan_info['url_to_scan']),scans_number):
                url_to_scan = scan_info['url_to_scan'][i:i+scans_number]
                info_for_scan = copy.deepcopy(scan_info)
                info_for_scan['url_to_scan'] = url_to_scan
                id_list = start_acu_scan(scan_info,headers,session)                
                check_acu_status_and_create_vuln(scan_info, id_list,headers,session)
            wait_until_its_free = False
        else:
            #Acunetix is busy send notifications via slack - redmine ??
            time.sleep(3600) #Waiting an hour before ask again
            pass
    return