from ..slack import slack_sender
from datetime import datetime
from OrchestratorApp import MONGO_CLIENT
from Orchestrator.settings import MONGO_INFO

resources = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['RESOURCES_COLLECTION']]
observations = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['OBSERVATIONS_COLLECTION']]
vulnerabilities = MONGO_CLIENT[MONGO_INFO['DATABASE']][MONGO_INFO['VULNERABILITIES_COLLECTION']]
libraries_versions = MONGO_CLIENT[MONGO_INFO['DATABASE']]['libraries_versions']

# ------------------- GETTERS -------------------
def get_workspaces():
    workspaces = resources.distinct('from_workspace')
    return workspaces

# In this case the target will be a ip list
def get_ips_with_web_interface(info):
    urls_to_send = list()
    for ip in info['url_to_scan']:
        resource = resources.find_one({'subdomain':ip,'ip': ip})    
        if type(resource['nmap_information']) != list:
            if resource['nmap_information']['@portid'] == '80':
                urls_to_send.append('http://'+ip)
            if resource['nmap_information']['@portid'] == '443':
                urls_to_send.append('https://'+ip)
        else:
            for information in resource['nmap_information']:
                if information['@portid'] == '80':
                    urls_to_send.append('http://'+ip)
                if information['@portid'] == '443':
                    urls_to_send.append('https://'+ip)
    return urls_to_send

def get_responsive_http_resources(target):
    subdomains = resources.find({'domain': target, 'has_urls': 'True'})
    subdomain_list = list()
    for subdomain in subdomains:
        for url_with_http in subdomain['responsive_urls'].split(';'):
            if url_with_http:
                current_subdomain = {
                    'target': subdomain['domain'],
                    'ip': subdomain['ip'],
                    'name': subdomain['name'],
                    'url_with_http': url_with_http
                }
                subdomain_list.append(current_subdomain)
    return subdomain_list


def get_targets():
    domains = resources.distinct('domain')
    return domains


def get_targets_with_vulns():
    domains = vulnerabilities.distinct('target_name')
    return domains


def get_target_last_scan(target):
    latest_record = resources.find({'domain': target}).sort([('last_seen', -1)]).limit(1)
    latest_record = latest_record[0]

    return latest_record


def get_target_alive_subdomains(target):
    subdomains = resources.find({'domain': target, 'is_alive': 'True'})
    subdomain_list = list()
    for subdomain in subdomains:
        current_subdomain = {
            'target': subdomain['domain'],
            'ip': subdomain['ip'],
            'name': subdomain['name']
        }
        subdomain_list.append(current_subdomain)
    return subdomain_list


def get_workspace_resources(target):
    workspace_resources = resources.find({'domain': target})
    resources_found = list()
    for resource in workspace_resources:
        current_resource = {
            'name': resource['name'],
            'is_alive': resource['is_alive'],
            'discovery_date': resource['discovery_date'],
            'last_seen': resource['last_seen'],
            'ip': resource['ip'],
            'domain': resource['domain'],
            'asn': resource['asn'],
            'country': resource['country'],
            'isp': resource['isp'],
            'region': resource['region'],
            'city': resource['city'],
            'organization': resource['organization'],
            'latitude': resource['latitude'],
            'longitude': resource['longitude'],
            'open_ports': resource['open_ports'],
            'extra_nmap': resource['extra_nmap']
        }
        resources_found.append(current_resource)

    return resources_found


# ------------------- RECON -------------------
def add_recon_resource(workspace, user, name, is_alive, discovery_date, last_seen, ip, domain, isp, asn, country,
                       region, city, organization, latitude, longitude):
    exists = resources.find_one({'name': name})
    if exists:
        resources.update_one({'_id': exists.get('_id')}, {'$set': {
            'is_alive': is_alive,
            'last_seen': last_seen,
            'ip': ip,
            'domain': domain,
            'asn': asn,
            'country': country,
            'isp': isp,
            'region': region,
            'city': city,
            'organization': organization,
            'latitude': latitude,
            'longitude': longitude}}
                                )
        # if exists.get('ip') != ip and is_alive == 'True':
        # slack_sender.send_domain_update_message(name, ip)
    else:
        resource = {
            'name': name,
            'is_alive': is_alive,
            'discovery_date': discovery_date,
            'last_seen': last_seen,
            'ip': ip,
            'domain': domain,
            'asn': asn,
            'country': country,
            'isp': isp,
            'region': region,
            'city': city,
            'organization': organization,
            'latitude': latitude,
            'longitude': longitude,
            'open_ports': 'None',
            'extra_nmap': 'None',
            'has_urls': 'None',
            'responsive_urls': 'None',
            'http_image': 'None',
            'https_image': 'None'

        }
        # if is_alive == 'True':
        # slack_sender.send_new_domain_found_message(name, ip)
        resources.insert_one(resource)


# Add available ports
def add_ports_to_subdomain(subdomain, port_list):
    subdomain = resources.find_one({'name': subdomain})
    if port_list:
        if type(port_list) is dict:
            try:
                extra_info = port_list['@portid'] + ' ' + port_list['service']['@name'] + ' ' + \
                             port_list['service']['@product']
            except KeyError:
                extra_info = port_list['@portid'] + ' ' + port_list['service']['@name']
            resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
                'open_ports': port_list['@portid'],
                'extra_nmap': extra_info}})
            return

        open_ports = list()
        extra_info = list()
        for port in port_list:
            open_ports.append(port['@portid'])
            try:
                extra_info.append(port['@portid'] + ' ' + port['service']['@name'] + ' ' +
                                  port['service']['@product'])
            except KeyError:
                extra_info.append(port['@portid'] + ' ' + port['service']['@name'])
        ports_to_add = ';'.join(map(str, open_ports))
        extra_to_add = ';'.join(map(str, extra_info))
        resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
            'open_ports': ports_to_add,
            'extra_nmap': extra_to_add}})
        return

    else:
        resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
            'open_ports': 'None',
            'extra_nmap': 'None'}})
        return


def add_scan_screen_to_subdomain(subdomain,img_b64):
    subdomain = resources.find_one({'name': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {'scan_screen': img_b64}})


def add_urls_to_subdomain(subdomain, has_urls, url_list):
    subdomain = resources.find_one({'name': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
        'has_urls': str(has_urls),
        'responsive_urls': url_list}})

    return


def add_images_to_subdomain(subdomain, http_image, https_image):
    subdomain = resources.find_one({'name': subdomain})
    resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
        'http_image': http_image,
        'https_image': https_image}})
    return


# ------------------- VULNERABILITY -------------------
def add_vulnerability(vulnerability):
    exists = vulnerabilities.find_one({'target_name': vulnerability.target, 'subdomain': vulnerability.scanned_url,
                                          'vulnerability_name': vulnerability.vulnerability_name,
                                          'language': vulnerability.language})
    if exists:
        vulnerabilities.update_one({'_id': exists.get('_id')}, {'$set': {
            'last_seen': vulnerability.time,
            'extra_info': vulnerability.custom_description,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string
        }})
    else:
        resource = {
            'target_name': vulnerability.target,
            'subdomain': vulnerability.scanned_url,
            'vulnerability_name': vulnerability.vulnerability_name,
            'extra_info': vulnerability.custom_description,
            'image_string': vulnerability.image_string,
            'file_string': vulnerability.file_string,
            'date_found': vulnerability.time,
            'last_seen': vulnerability.time,
            'language': vulnerability.language
        }
        vulnerabilities.insert_one(resource)
    return


def get_vulns_from_target(target):
    resources = vulnerabilities.find({'target_name': target})
    resources_list = list()
    for resource in resources:
        to_add = {
            'target_name': resource['target_name'],
            'affected_resource': resource['subdomain'],
            'vulnerability_name': resource['vulnerability_name'],
            'found': resource['date_found'],
            'last_seen': resource['last_seen']
        }
        try:
            to_add['language'] = resource['language']
        except KeyError:
            to_add['language'] = None
        resources_list.append(to_add)

    return resources_list


def get_ssl_scannable_resources(target):
    valid_ports = ['443', '8000', '8080', '8443']
    subdomains = resources.find({'domain': target, 'is_alive': 'True'})
    subdomain_list = list()
    for subdomain in subdomains:
        for port in subdomain['open_ports'].split(';'):
            if port in valid_ports:
                current_subdomain = {
                    'target': subdomain['domain'],
                    'ip': subdomain['ip'],
                    'name': subdomain['name'],
                    'url_with_port': subdomain['name'] + ':' + port
                }
                subdomain_list.append(current_subdomain)
    return subdomain_list


# ------------------- REPORTING -------------------
def get_vulns_with_language(target, language):
    resources = vulnerabilities.find({'target_name': target, 'language': language})
    resources_list = list()
    for resource in resources:
        to_add = {
            'target_name': resource['target_name'],
            'affected_resource': resource['subdomain'],
            'vulnerability_name': resource['vulnerability_name'],
            'extra_info': resource['extra_info'] if 'extra_info' in resource else None,
            'image_string': resource['image_string'] if 'image_string' in resource else None,
            'found': resource['date_found'],
            'last_seen': resource['last_seen']
        }
        resources_list.append(to_add)

    return resources_list


def get_specific_finding_info(finding, language):
    #Finding Info KB
    finding_kb = observations.find({'TITLE': finding['title'], 'LANGUAGE': language})
    if finding_kb:
        for f_kb in finding_kb:
            finding_to_send = f_kb
            finding_to_send['resourceAf'] = finding['resourceAf']
            finding_to_send['extra_info'] = finding['extra_info']
            finding_to_send['image_string'] = finding['image_string']
            return finding_to_send
    else:
        return None

def get_observation_for_object(vuln_name,language):
    finding_kb = observations.find_one({'TITLE': vuln_name, 'LANGUAGE': language})
    return finding_kb

def find_last_version_of_librarie(name):
    librarie = libraries_versions.find({'name':name})
    if librarie:
        return librarie[0]['version']
    else:
        return ''

def add_simple_ip_resource(scan_info):
    exists = resources.find_one({'subdomain': scan_info['ip'],'ip': scan_info['ip']})
    timestamp = datetime.now()
    if not exists:
        resource ={
                'domain': None,
                'subdomain': scan_info['ip'],
                'is_alive': True,
                'ip': scan_info['ip'],
                'additional_info':{
                    'isp': None,
                    'asn': None,
                    'country': None,
                    'region': None,
                    'city': None,
                    'org': None,
                    'geoloc': '0 , 0'
                },
                'first_seen': timestamp,
                'last_seen': timestamp,
                'scanned': False,
                'type': scan_info['type'],
                'has_urls': False,
                'responsive_urls': '',
                'nmap_information': None
        }
        resources.insert_one(resource)
    else:
        resources.update_one({'_id': exists.get('_id')},
         {'$set': 
            {
            'last_seen': timestamp
            }})

def add_nmap_information_to_ip(scan_information, nmap_json):
    resource = resources.find_one({'subdomain': scan_information['ip'],'ip': scan_information['ip']})
    if not resource:
        print('ERROR adding nmap information to resource, resource not found')
        return
    resources.update_one({'_id': resource.get('_id')},
         {'$set': 
            {
                'nmap_information': nmap_json
            }})
    return