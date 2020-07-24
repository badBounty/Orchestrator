from ...tasks import subdomain_finder_task, url_resolver_task, recon_handle_task, prepare_info_for_target_scan, prepare_info_after_nmap
from ...tasks import header_scan_task, http_method_scan_task, cors_scan_task, libraries_scan_task, ssl_tls_scan_task, ffuf_task, nmap_script_scan_task, iis_shortname_scan_task, bucket_finder_task, token_scan_task, css_scan_task, firebase_scan_task, host_header_attack_scan, burp_scan_task,nmap_script_baseline_task,generate_report_task,nessus_scan_task,acunetix_scan_task
from ...tasks import task_finished
from celery import chain, chord
from ..mongo import mongo
from celery.result import AsyncResult
from datetime import datetime, timedelta
import os

# Here we parse the information and call each scan type
def handle(info):
    if not info['checkbox_redmine']:
        info['redmine_project'] = 'no_project'
    if not info['checkbox_report']:
        info['report_type'] = ''
    #Validate if start date is created
    try:
        info['start_date']
    except KeyError:
        info['start_date'] = ''

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

# From redmine manager list of IPs or URLs
def handle_url_ip(info):
    scan_information = {
        'target': 'red_manager_file',
        'url_to_scan': info['targets'],
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'nessus_scan': info['use_nessus_scan'],
        'acunetix_scan': info['use_acunetix_scan'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users'],
        'start_date': info['start_date']
    }
    if info['checkbox_report']:
        scan_information['report_type'] = info['report_type']
    else:
        scan_information['report_type'] = None

    if info['scan_type'] == 'file_target':
        launch_url_scan(scan_information)
    else:
        launch_ip_scan(scan_information)

### FILE WITH IPs ###
def handle_ip_file(info, f):
    url_list = list()
    for line in f.readlines():
        line = line.decode().replace('\r','')
        url_list.append(line.replace('\n',''))

    if not info['checkbox_redmine']:
        info['redmine_project'] = 'no_project'

    scan_information = {
        'target': str(f),
        'url_to_scan': None,
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'nessus_scan': info['use_nessus_scan'],
        'acunetnix_scan': info['use_acunetix_scan'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users'],
        'start_date': info['start_date']
    }
    if info['checkbox_report']:
        scan_information['report_type'] = info['report_type']
    else:
        scan_information['report_type'] = None

    scan_information['url_to_scan'] = url_list
    launch_ip_scan(scan_information)
    return

### FILE WITH URLS ###
def handle_url_file(info, f):
    url_list = list()
    for line in f.readlines():
        line = line.decode().replace('\r','')
        url_list.append(line.replace('\n',''))

    if not info['checkbox_redmine']:
        info['redmine_project'] = 'no_project'

    scan_information = {
        'target': str(f),
        'url_to_scan': None,
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'nessus_scan': info['use_nessus_scan'],
        'acunetix_scan': info['use_acunetix_scan'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users'],
        'start_date': ''
    }
    if info['checkbox_report']:
        scan_information['report_type'] = info['report_type']
    else:
        scan_information['report_type'] = None

    scan_information['url_to_scan'] = url_list
    launch_url_scan(scan_information)
    return


#### LAUNCH URL SCAN ###
def launch_url_scan(scan_information):
    # Run the scan
    execution_chord = chord(
        [
            # Fast_scans
            #header_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            #http_method_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
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
            #nessus_scan_task.s(scan_information,'target').set(queue='slow_queue'),
            #acunetix_scan_task.s(scan_information,'target').set(queue='acunetix_queue'),
            burp_scan_task.s(scan_information, 'target').set(queue='burp_queue'),
        ],
        body=generate_report_task.s(scan_information,'target').set(queue='slow_queue'),
        immutable=True)
    if scan_information['start_date']:
        datetime_object = datetime.strptime(scan_information['start_date'], '%Y-%m-%d %H:%M')
        date_scan = datetime_object + timedelta(hours=3)
        execution_chord.apply_async(queue='fast_queue', interval=300,eta=date_scan)
    else:
        execution_chord.apply_async(queue='fast_queue', interval=300)
    return


### LAUNCH IP SCAN ###
def launch_ip_scan(scan_information):
    # Run the scan
    execution_chain = chain(
        chord(
            [
                nmap_script_baseline_task.s(scan_information, 'target').set(queue='slow_queue'),
                nmap_script_scan_task.s(scan_information, 'target').set(queue='slow_queue')
            ],
            body=task_finished.s(),
            mmutable=True),
        # Based on the previous output, ips with port 80 and 443 will be scanned
        prepare_info_after_nmap.si(scan_information),
        chord(
            [
                # Fast_scans
                header_scan_task.s('target').set(queue='fast_queue'),
                http_method_scan_task.s('target').set(queue='fast_queue'),
                #libraries_scan_task.s('target').set(queue='fast_queue'),
                ffuf_task.s('target').set(queue='fast_queue'),
                iis_shortname_scan_task.s('target').set(queue='fast_queue'),
                bucket_finder_task.s('target').set(queue='fast_queue'),
                token_scan_task.s('target').set(queue='fast_queue'),
                css_scan_task.s('target').set(queue='fast_queue'),
                firebase_scan_task.s('target').set(queue='fast_queue'),
                host_header_attack_scan.s('target').set(queue='fast_queue'),
                # Slow_scans
                cors_scan_task.s('target').set(queue='slow_queue'),
                ssl_tls_scan_task.s('target').set(queue='slow_queue'),
                #nessus_scan_task.s(scan_information,'target').set(queue='slow_queue'),
                #burp_scan_task.s('target').set(queue='burp_queue'),
            ],
            body=generate_report_task.s(scan_information,'target').set(queue='slow_queue'))
        )
    if scan_information['start_date']:
        datetime_object = datetime.strptime(scan_information['start_date'], '%Y-%m-%d %H:%M')
        date_scan = datetime_object + timedelta(hours=3)
        execution_chain.apply_async(queue='fast_queue', interval=300,eta=date_scan)
    else:
        execution_chain.apply_async(queue='fast_queue', interval=300)
    return 

### EXISTING TARGET CASE ###
def handle_target_scan(info):
    scan_information = {
        'target': info['existing_target_choice'],
        'url_to_scan': info['existing_target_choice'],
        'language': info['selected_language'],
        'report_type': info['report_type'],
        'redmine_project': info['redmine_project'], 
        'invasive_scans': info['use_active_modules'],
        'nessus_scan': info['use_nessus_scan'],
        'acunetix_scan':info['use_acunetix_scan'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users'],
        'start_date': info['start_date']
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
            ffuf_task.s(scan_information, 'target').set(queue='fast_queue'),
            iis_shortname_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            bucket_finder_task.s(scan_information, 'target').set(queue='fast_queue'),
            token_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            css_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            firebase_scan_task.s(scan_information, 'target').set(queue='fast_queue'),
            host_header_attack_scan.s(scan_information, 'target').set(queue='fast_queue'),
            # Slow_scans
            cors_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            ssl_tls_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            nmap_script_scan_task.s(scan_information, 'target').set(queue='slow_queue'),
            nessus_scan_task.s(scan_information,'target').set(queue='slow_queue'),
            acunetix_scan_task.s(scan_information,'target').set(queue='acunetix_queue'),
            burp_scan_task.s(scan_information, 'target').set(queue='burp_queue'),
        ],
        body=generate_report_task.s(scan_information,'target').set(queue='slow_queue'),
        immutable=True)
    if scan_information['start_date']:
        datetime_object = datetime.strptime(scan_information['start_date'], '%Y-%m-%d %H:%M')
        date_scan = datetime_object + timedelta(hours=3)
        execution_chord.apply_async(queue='fast_queue', interval=300,eta=date_scan)
    else:
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
                ffuf_task.s('target').set(queue='fast_queue'),
                iis_shortname_scan_task.s('target').set(queue='fast_queue'),
                bucket_finder_task.s('target').set(queue='fast_queue'),
                token_scan_task.s('target').set(queue='fast_queue'),
                css_scan_task.s('target').set(queue='fast_queue'),
                firebase_scan_task.s('target').set(queue='fast_queue'),
                host_header_attack_scan.s('target').set(queue='fast_queue'),
                # Slow_scans
                cors_scan_task.s('target').set(queue='slow_queue'),
                ssl_tls_scan_task.s('target').set(queue='slow_queue'),
                nmap_script_scan_task.s('target').set(queue='slow_queue'),
                nessus_scan_task.s('target').set(queue='slow_queue'),
                acunetix_scan_task.s('target').set(queue='acuentix_queue'),
                #burp_scan_task.s('target').set(queue='burp_queue'),
            ],
            body=generate_report_task.s(info,'target').set(queue='slow_queue'))
    )
    if info['start_date']:
        datetime_object = datetime.strptime(info['start_date'], '%Y-%m-%d %H:%M')
        date_scan = datetime_object + timedelta(hours=3)
        new_target_chain.apply_async(queue='fast_queue', interval=300,eta=date_scan)
    else:
        new_target_chain.apply_async(queue='fast_queue', interval=300)
    return

### SINGLE URL CASE ###
def handle_single_scan(info):
    scan_information = {
        'target': info['single_target_choice'],
        'url_to_scan': info['single_target_choice'],
        'language': info['selected_language'],
        'report_type': info['report_type'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'nessus_scan': info['use_nessus_scan'],
        'acunetix_scan': info['use_acunetix_scan'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users'],
        'start_date': info['start_date']
    }

    execution_chord = chord(
        [
            # Fast_scans
            header_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            http_method_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            #libraries_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            ffuf_task.s(scan_information,'single').set(queue='fast_queue'),
            iis_shortname_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            bucket_finder_task.s(scan_information,'single').set(queue='fast_queue'),
            token_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            css_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            firebase_scan_task.s(scan_information,'single').set(queue='fast_queue'),
            host_header_attack_scan.s(scan_information,'single').set(queue='fast_queue'),
            # Slow_scans
            cors_scan_task.s(scan_information,'single').set(queue='slow_queue'),
            ssl_tls_scan_task.s(scan_information, 'single').set(queue='slow_queue'),
            nmap_script_baseline_task.s(scan_information,'single').set(queue='slow_queue'),
            nmap_script_scan_task.s(scan_information,'single').set(queue='slow_queue'),
            nessus_scan_task.s(scan_information,'single').set(queue='slow_queue'),
            acunetix_scan_task.s(scan_information,'single').set(queue='acunetix_queue'),
            burp_scan_task.s(scan_information,'single').set(queue='burp_queue')
        ],
        body=generate_report_task.s(scan_information,'single').set(queue='slow_queue'))
    
    if scan_information['start_date']:
        datetime_object = datetime.strptime(scan_information['start_date'], '%Y-%m-%d %H:%M')
        date_scan = datetime_object + timedelta(hours=3)
        execution_chord.apply_async(queue='fast_queue', interval=300,eta=date_scan)
    else:
        execution_chord.apply_async(queue='fast_queue', interval=300)
    return
