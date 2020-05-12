import json, requests, itertools, collections, os
from bs4 import BeautifulSoup
from ...__init__ import WAPPALIZE_KEY
from .. import constants
from ..slack import slack_sender
from ..mongo import mongo
from datetime import datetime

endpoint = 'https://api.wappalyzer.com/lookup/v1/?url='


def get_latest_version(name):
    return mongo.find_last_version_of_librarie(name)


def get_cves_and_last_version(librarie):
    cve_list = []
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
        print("No CVE'S found for: " + librarie['name'])
        return {}, ""


def add_libraries_vulnerability(target_name, scanned_url, language, libraries):
    timestamp = datetime.now()
    finding_name = ''
    if language == constants.LANGUAGE_ENGLISH:
        finding_name = constants.OUTDATED_3RD_LIBRARIES_ENGLISH
    else:
        finding_name = constants.OUTDATED_3RD_LIBRARIES_SPANISH
    mongo.add_vulnerability(target_name, scanned_url, finding_name, timestamp, language, str(libraries))


def analyze(target_name, url_to_scan, language):
    print('Scanning target {}'.format(url_to_scan))
    target = endpoint + url_to_scan
    headers = {'x-api-key': WAPPALIZE_KEY}
    try:
        response = requests.get(target, headers=headers)
        libraries = response.json()[0]['applications']
        for lib in libraries:
            lib['cves'], lib['last_version'] = get_cves_and_last_version(lib)
        add_libraries_vulnerability(target_name, url_to_scan, language, libraries)
        print('\nActive Scan completed\n')
    except Exception as e:
        print('\nSomethig went wrong! :' + '\n' + str(e))


def handle_target(target, url_list, language):
    print('------------------- TARGET LIBRARIES SCAN STARTING -------------------')
    print('Found ' + str(len(url_list)) + ' targets to scan')
    slack_sender.send_simple_message("Libraries scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        analyze(url['target'], url['url_with_http'], language)
    print('-------------------  TARGET LIBRARIES SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- SINGLE LIBRARIES SCAN STARTING -------------------')
    slack_sender.send_simple_message("Libraries scan started against %s" % url)
    analyze(url, url, language)
    print('------------------- SINGLE LIBRARIES SCAN FINISHED -------------------')
    return
