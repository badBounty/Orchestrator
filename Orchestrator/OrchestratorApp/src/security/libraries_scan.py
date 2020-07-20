import json, requests, itertools, collections, os, traceback
from bs4 import BeautifulSoup
from Orchestrator.settings import WAPPALIZE_KEY
from .. import constants
from ..slack import slack_sender
from ..mongo import mongo
from ..redmine import redmine
from datetime import datetime
from ...objects.vulnerability import Vulnerability

endpoint = 'https://api.wappalyzer.com/lookup/v1/?url='


def get_latest_version(name):
    return mongo.find_last_version_of_librarie(name)


def get_cves_and_last_version(librarie):
    version = librarie["versions"][0] if librarie["versions"] else ""
    name = librarie["name"]
    name = "Internet Information Server" if name == "IIS" else name
    url = "https://www.cvedetails.com/version-search.php?vendor=&product=%"+name+"%&version="+version
    resp = requests.get(url)
    html = BeautifulSoup(resp.text, "html.parser")
    table_div = html.find('div', {'id': 'searchresults'})
    if table_div is not None:
        last_version = get_latest_version(name)
        table_data = []
        table_headers = [[cell.text.replace('\n', '').replace('\t', '') for cell in row("th")] for row in
                         table_div.find('table')("tr")][0]
        for row in table_div.find('table')("tr"):
            if row.has_attr('class'):
                for cell in row("td"):
                    table_data.append(cell.text.replace('\n', '').replace('\t', ''))

        len_headers = len(table_headers)
        len_data = len(table_data)
        result = collections.defaultdict(list)
        for key, val in zip(itertools.cycle(table_headers), table_data):
            result[key].append(val)
        result = json.loads(json.dumps(result))
        result = [{key: value[index] for key, value in result.items()} for index in
                  range(max(map(len, result.values())))]
        return result, last_version
    else:
        return {}, ""


def add_libraries_vulnerability(scan_info, message):
    vulnerability = Vulnerability(constants.OUTDATED_3RD_LIBRARIES, scan_info, message)
    slack_sender.send_simple_vuln(vulnerability)
    redmine.create_new_issue(vulnerability)
    mongo.add_vulnerability(vulnerability)


def fastPrint(libraries):
    message= ""
    for info in libraries:
        info_title= "Name: "+info['name']
        version = info['versions'][0] if info['versions'] else ""
        last_version = info['last_version']
        if version or last_version:
            info_title += ' Version: '+version+' Last Version :'+last_version
        message += "\t"+info_title+'\n'
        for cve in info['cves']:
            cve_info = 'CVE ID: '+cve['CVE ID']+' - Vulnerability: '+cve['Vulnerability Type(s)']+'- CVSS Score: '+cve['Score']
            message += "\t"+cve_info+'\n'
    return message


def analyze(scan_info, url_to_scan):
    print('Scanning target {}'.format(url_to_scan))
    target = endpoint + url_to_scan
    headers = {'x-api-key': WAPPALIZE_KEY}
    try:
        response = requests.get(target, headers=headers)
        if response.json():
            libraries = response.json()[0]['applications']
            for lib in libraries:
                lib['cves'], lib['last_version'] = get_cves_and_last_version(lib)

            message = fastPrint(libraries)
            add_libraries_vulnerability(scan_info,  message)
    except KeyError:
        return
    except Exception as e:
        error_string = traceback.format_exc()
        print('Libraries scan error '+str(e))


def handle_target(info):
    if WAPPALIZE_KEY:
        print('Module libraries scan started against '+ str(len(info['url_to_scan'])) + ' targets')
        slack_sender.send_simple_message("Libraries scan started against target: %s. %d alive urls found!"
                                        % (info['target'], len(info['url_to_scan'])))
        for url in info['url_to_scan']:
            sub_info = info
            sub_info['url_to_scan'] = url
            print('Scanning ' + url)
            analyze(sub_info, sub_info['url_to_scan'])
        print('Module libraries scan finished')
    return


def handle_single(scan_info):
    if WAPPALIZE_KEY:
        print('Module libraries scan (single) started against %s' % scan_info['url_to_scan'])
        slack_sender.send_simple_message("Libraries scan started against %s" % scan_info['url_to_scan'])
        analyze(scan_info, scan_info['url_to_scan'])
        print('Module libraries scan (single) finished')
    return
