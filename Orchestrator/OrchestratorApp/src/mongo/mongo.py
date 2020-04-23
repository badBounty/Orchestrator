from pymongo import MongoClient
from ..slack import slack_sender
from ...__init__ import client


def get_workspaces():
    db = client.Orchestrator
    workspaces = db.resources.distinct('from_workspace')
    return workspaces


def get_targets():
    db = client.Orchestrator
    domains = db.resources.distinct('domain')
    return domains


def get_target_last_scan(target):
    db = client.Orchestrator
    latest_record = db.resources.find({'domain': target}).sort([('last_seen', -1)]).limit(1)
    latest_record = latest_record[0]

    return latest_record


def get_target_subdomains(target):
    db = client.Orchestrator
    subdomains = db.resources.find({'domain': target, 'is_alive': 'True'})
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
    db = client.Orchestrator
    workspace_resources = db.resources.find({'domain': target})
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
            'longitude': resource['longitude']
        }
        resources_found.append(current_resource)

    return resources_found


def add_resource(workspace, user, name, is_alive, discovery_date, last_seen, ip, domain, isp, asn, country,
                 region, city, organization, latitude, longitude):
    # Our table is called resources
    db = client.Orchestrator

    exists = db.resources.find_one({'name': name})
    if exists:
        db.resources.update_one({'_id': exists.get('_id')}, {'$set': {
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
        if exists.get('ip') != ip and is_alive == 'True':
            slack_sender.send_domain_update_message(name, ip)
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
            'open_ports': 'None'
        }
        if is_alive == 'True':
            slack_sender.send_new_domain_found_message(name, ip)
        db.resources.insert_one(resource)


# Add available ports
def add_ports_to_subdomain(subdomain, port_list):
    db = client.Orchestrator
    subdomain = db.resources.find_one({'name': subdomain})
    if port_list:

        if type(port_list) is dict:
            try:
                extra_info = port_list['@portid'] + ' ' + port_list['service']['@name'] + ' ' + \
                             port_list['service']['@product']
            except KeyError:
                extra_info = port_list['@portid'] + ' ' + port_list['service']['@name']
            db.resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
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
        ports_to_add = ','.join(map(str, open_ports))
        extra_to_add = '\n'.join(map(str, extra_info))
        db.resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
            'open_ports': ports_to_add,
            'extra_nmap': extra_to_add}})
        return

    else:
        db.resources.update_one({'_id': subdomain.get('_id')}, {'$set': {
            'open_ports': 'None',
            'extra_nmap': 'None'}})
        return

