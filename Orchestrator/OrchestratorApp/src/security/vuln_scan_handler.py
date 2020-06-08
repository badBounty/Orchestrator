from ...tasks import subdomain_finder_task, url_resolver_task, recon_handle_task, prepare_info_for_target_scan, prepare_info_after_nmap
from ...tasks import header_scan_task, http_method_scan_task, cors_scan_task, libraries_scan_task, ssl_tls_scan_task, ffuf_task, nmap_script_scan_task, iis_shortname_scan_task, bucket_finder_task, token_scan_task, css_scan_task, firebase_scan_task, host_header_attack_scan, burp_scan_task,nmap_script_baseline_task,generate_report_task
from ...tasks import task_finished
from celery import chain, chord
from ..mongo import mongo
from celery.result import AsyncResult
import os

# Here we parse the information and call each scan type
def handle(info):
    print(info)
    if not info['checkbox_redmine']:
        info['redmine_project'] = 'no_project'
    if info['scan_type'] == 'existing_target':
        # If input is an existing target
        handle_target_scan(info)
    elif info['scan_type'] == 'new_target':
        # If input is a new target
        handle_new_target_scan(info)
    elif info['scan_type'] == 'single_target':
        # If input is a single url
        handle_single_scan(info)
    return

### FILE WITH IPs ###
def handle_ip_file(info, f):
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
    # Run the scan
    execution_chain = chain(
        chord(
            [
                nmap_script_baseline_task.s(scan_information, 'target').set(queue='slow_queue'),
                #nmap_script_scan_task.s(scan_information, 'target').set(queue='slow_queue')
            ],
            body=task_finished.s(),
            mmutable=True),
        # Based on the previous output, ips with port 80 and 443 will be scanned
        prepare_info_after_nmap.si(scan_information),
        chord(
            [
                # Fast_scans
                header_scan_task.s('target').set(queue='fast_queue'),
                #http_method_scan_task.s('target').set(queue='fast_queue'),
                #libraries_scan_task.s('target').set(queue='fast_queue'),
                #ffuf_task.s('target').set(queue='fast_queue'),
                #iis_shortname_scan_task.s('target').set(queue='fast_queue'),
                #bucket_finder_task.s('target').set(queue='fast_queue'),
                #token_scan_task.s('target').set(queue='fast_queue'),
                #css_scan_task.s('target').set(queue='fast_queue'),
                #firebase_scan_task.s('target').set(queue='fast_queue'),
                #host_header_attack_scan.s('target').set(queue='fast_queue'),
                # Slow_scans
                #cors_scan_task.s('target').set(queue='slow_queue'),
                #ssl_tls_scan_task.s('target').set(queue='slow_queue'),
                #burp_scan_task.s('target').set(queue='slow_queue'),
            ],
            body=task_finished.s())
        )
    execution_chain.apply_async(queue='fast_queue', interval=300)

    return

### FILE WITH URLS ###
def handle_url_file(info, f):
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
    # Run the scan
    execution_chord = chord(
        [
            # Fast_scans
            header_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            http_method_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #libraries_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #ffuf_task.s(scan_information, 'target').set(queue='fast_queue'),
            #iis_shortname_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #bucket_finder_task.s(scan_information, 'target').set(queue='fast_queue'),
            #token_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #css_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #firebase_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #host_header_attack_scan.s(scan_information, 'target').set(queue='fast_queue'),
            # Slow_scans
            #cors_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            #ssl_tls_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            #nmap_script_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            #burp_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
        ],
        body=task_finished.s(),
        immutable=True)
    execution_chord.apply_async(queue='fast_queue', interval=300)

    return

### EXISTING TARGET CASE ###
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
    execution_chord = chord(
        [
            # Fast_scans
            header_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            http_method_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #libraries_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #ffuf_task.s(scan_information, 'target').set(queue='fast_queue'),
            #iis_shortname_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #bucket_finder_task.s(scan_information, 'target').set(queue='fast_queue'),
            #token_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #css_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #firebase_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #host_header_attack_scan.s(scan_information, 'target').set(queue='fast_queue'),
            # Slow_scans
            #cors_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            #ssl_tls_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            #nmap_script_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            #burp_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
        ],
        body=task_finished.s(),
        immutable=True)
    execution_chord.apply_async(queue='fast_queue', interval=300)
    return

### NEW TARGET CASE ###
def handle_new_target_scan(info):
    from ...tasks import recon_finished
    new_target_chain = chain(
        chord(
            [
                recon_handle_task.s(info['new_target_choice']).set(queue='slow_queue')
            ],
            body=recon_finished.s()
        ),
        prepare_info_for_target_scan.s(info).set(queue='fast_queue'),
        chord(
            [
                # Fast_scans
                header_scan_task.s('target').set(queue='fast_queue'),
                http_method_scan_task.s('target').set(queue='fast_queue'),
                #libraries_scan_task.s('target').set(queue='fast_queue'),
                #ffuf_task.s('target').set(queue='fast_queue'),
                #iis_shortname_scan_task.s('target').set(queue='fast_queue'),
                #bucket_finder_task.s('target').set(queue='fast_queue'),
                #token_scan_task.s('target').set(queue='fast_queue'),
                #css_scan_task.s('target').set(queue='fast_queue'),
                #firebase_scan_task.s('target').set(queue='fast_queue'),
                #host_header_attack_scan.s('target').set(queue='fast_queue'),
                # Slow_scans
                #cors_scan_task.s('target').set(queue='slow_queue'),
                #ssl_tls_scan_task.s('target').set(queue='slow_queue'),
                #nmap_script_scan_task.s('target').set(queue='slow_queue'),
                #burp_scan_task.s('target').set(queue='slow_queue'),
            ],
            body=task_finished.s())
    )
    new_target_chain.apply_async(queue='fast_queue', interval=300)

    return

### SINGLE URL CASE ###
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
    if info['checkbox_report']:
        scan_information['report_type'] = info['report_type']
    execution_chord = chord(
        [
            # Fast_scans
            header_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            http_method_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            #libraries_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            #ffuf_task.s(scan_information,'single').set(queue='fast_queue'),
            #iis_shortname_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            #bucket_finder_task.s(scan_information,'single').set(queue='fast_queue'),
            #token_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            #css_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            #firebase_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            #host_header_attack_scan.s(scan_information,'single').set(queue='fast_queue'),
            # Slow_scans
            #cors_scan_task.s(scan_information,'single').set(queue='slow_queue'),
            #ssl_tls_scan_task.s('single', scan_information).set(queue='slow_queue'),
            #nmap_script_baseline_task.s(scan_information,'single').set(queue='slow_queue'),
            #nmap_script_scan_task.s(scan_information,'single').set(queue='slow_queue'),
            #burp_scan_task.s(scan_information,'single').set(queue='slow_queue')
        ],
        body=generate_report_task.s(scan_information,'single'))
    execution_chord.apply_async(queue='fast_queue', interval=300)
    return