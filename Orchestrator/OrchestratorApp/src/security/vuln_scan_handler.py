from ...tasks import recon_and_vuln_scan_task, subdomain_finder_task, url_resolver_task
from ...tasks import header_scan_task, http_method_scan_task, cors_scan_task, libraries_scan_task, ssl_tls_scan_task, ffuf_task, nmap_script_scan_task, iis_shortname_scan_task, bucket_finder_task, token_scan_task, css_scan_task, firebase_scan_task, host_header_attack_scan, burp_scan_task
from ...tasks import task_finished
from celery import chain, chord
from ..mongo import mongo
from celery.result import AsyncResult
import os


def handle_file(info, f):
    url_list = list()
    for line in f.readlines():
        url_list.append(line.decode().replace('\r\n',''))

    if not info['checkbox_redmine']:
        info['redmine_project'] = 'no_project'

    scan_information = {
        'target': str(f),
        'url_to_scan': None,
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users']
    }

    scan_information['url_to_scan'] = url_list
    handle_multiple_scan(scan_information)

    return

def handle(info):
    # Here we parse the information and call each scan type
    # We are only going to parse scan information for now, the rest will prob be at settings
    if not info['checkbox_redmine']:
        info['redmine_project'] = 'no_project'

    if info['scan_type'] == 'existing_target':
        handle_target_scan(info)
    #TODO
    elif info['scan_type'] == 'new_target':
        pass
        #handle_new_target_scan(info)
    elif info['scan_type'] == 'single_target':
        handle_single_scan(info)

    return

def handle_target_scan(info):
    scan_information = {
        'target': info['existing_target_choice'],
        'url_to_scan': info['existing_target_choice'],
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'], 
        'invasive_scans': info['use_active_modules'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users']
    }
    subdomains_http = mongo.get_responsive_http_resources(scan_information['target'])
    only_urls = list()
    for subdomain in subdomains_http:
        only_urls.append(subdomain['url_with_http'])
    scan_information['url_to_scan'] = only_urls

    # Run the scan
    handle_multiple_scan(scan_information)

    return


def handle_new_target_scan(info):
    new_target_chain = chain(
        chord(
            [
                subdomain_finder_task.s(info['target']).set(queue='slow_queue')
            ],
            body=url_resolver_task.s(info['target']),
            immutable=True
        ),
        chord(
        [
            # Fast_scans
            header_scan_task.s('target', info).set(queue='fast_queue'),
            http_method_scan_task.s('target', info).set(queue='fast_queue'),
            #libraries_scan_task.s('target', info).set(queue='fast_queue'),
            #ffuf_task.s('target', info).set(queue='fast_queue'),
            #iis_shortname_scan_task.s('target', info).set(queue='fast_queue'),
            #bucket_finder_task.s('target', info).set(queue='fast_queue'),
            #token_scan_task.s('target', info).set(queue='fast_queue'),
            #css_scan_task.s('target', info).set(queue='fast_queue'),
            #firebase_scan_task.s('target', info).set(queue='fast_queue'),
            #host_header_attack_scan.s('target', info).set(queue='fast_queue'),
            # Slow_scans
            #cors_scan_task.s('target', info).set(queue='slow_queue'),
            #ssl_tls_scan_task.s('target', info).set(queue='slow_queue'),
            #nmap_script_scan_task.s('target', info).set(queue='slow_queue'),
            #burp_scan_task.s('target', info).set(queue='slow_queue'),
        ],
        body=task_finished.s(),
        immutable=True)
    )
    new_target_chain.apply_async(queue='fast_queue')
    
    return


def handle_multiple_scan(info):
    execution_chord = chord(
        [
            # Fast_scans
            header_scan_task.s('target', info).set(queue='fast_queue'),
            http_method_scan_task.s('target', info).set(queue='fast_queue'),
            #libraries_scan_task.s('target', info).set(queue='fast_queue'),
            #ffuf_task.s('target', info).set(queue='fast_queue'),
            #iis_shortname_scan_task.s('target', info).set(queue='fast_queue'),
            #bucket_finder_task.s('target', info).set(queue='fast_queue'),
            #token_scan_task.s('target', info).set(queue='fast_queue'),
            #css_scan_task.s('target', info).set(queue='fast_queue'),
            #firebase_scan_task.s('target', info).set(queue='fast_queue'),
            #host_header_attack_scan.s('target', info).set(queue='fast_queue'),
            # Slow_scans
            #cors_scan_task.s('target', info).set(queue='slow_queue'),
            #ssl_tls_scan_task.s('target', info).set(queue='slow_queue'),
            #nmap_script_scan_task.s('target', info).set(queue='slow_queue'),
            #burp_scan_task.s('target', info).set(queue='slow_queue'),
        ],
        body=task_finished.s(),
        immutable=True)
    execution_chord.apply_async(queue='fast_queue')    
    return
    

def handle_single_scan(info):
    scan_information = {
        'target': info['single_target_choice'],
        'url_to_scan': info['single_target_choice'],
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users']
    }

    execution_chord = chord(
        [
            # Fast_scans
            header_scan_task.s('single', scan_information).set(queue='fast_queue'),
            http_method_scan_task.s('single', scan_information).set(queue='fast_queue'),
            #libraries_scan_task.s('single', scan_information).set(queue='fast_queue'),
            #ffuf_task.s('single', scan_information).set(queue='fast_queue'),
            #iis_shortname_scan_task.s('single', scan_information).set(queue='fast_queue'),
            #bucket_finder_task.s('single', scan_information).set(queue='fast_queue'),
            #token_scan_task.s('single', scan_information).set(queue='fast_queue'),
            #css_scan_task.s('single', scan_information).set(queue='fast_queue'),
            #firebase_scan_task.s('single', scan_information).set(queue='fast_queue'),
            #host_header_attack_scan.s('single', scan_information).set(queue='fast_queue'),
            # Slow_scans
            #ors_scan_task.s('single', scan_information).set(queue='slow_queue'),
            #ssl_tls_scan_task.s('single', scan_information).set(queue='slow_queue'),
            #nmap_script_scan_task.s('single', scan_information).set(queue='slow_queue'),
            #burp_scan_task.s('single', scan_information).set(queue='slow_queue'),
        ],
        body=task_finished.s(),
        immutable=True)
    execution_chord.apply_async(queue='fast_queue')
    return

