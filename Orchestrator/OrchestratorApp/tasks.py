from celery import shared_task
from celery.schedules import crontab
from celery.task import periodic_task
from celery import group

from time import sleep
import datetime as dt
import os,gc

from .src.recon import recon, nmap, aquatone
from .src.security import header_scan, http_method_scan, ssl_tls_scan,\
    cors_scan, ffuf, libraries_scan, bucket_finder, token_scan, css_scan,\
    firebase_scan, nmap_script_scan,nmap_script_baseline, host_header_attack,\
    iis_shortname_scanner, burp_scan, nessus_scan, acunetix_scan
from .src.slack import slack_sender
from .src.mongo import mongo
from .src.comms import email_handler
from .src.reporting import reporting

@shared_task
def sleepy(duration):
    sleep(duration)
    return None
    
@shared_task
def recon_handle_task(target):
    recon.run_recon(target)
    subdomains = mongo.get_target_alive_subdomains(target)
    aquatone.start_aquatone(subdomains)
    return

@shared_task
def prepare_info_for_target_scan(task, info):
    scan_information = {
        'target': info['new_target_choice'],
        'url_to_scan': info['new_target_choice'],
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'], 
        'invasive_scans': info['use_active_modules'],
        'nessus_scan': info['use_nessus_scan'],
        'acunetix_scan': info['use_acunetix_scan'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users']
    }
    subdomains_http = mongo.get_responsive_http_resources(scan_information['target'])
    only_urls = list()
    for subdomain in subdomains_http:
        only_urls.append(subdomain['url_with_http'])
    scan_information['url_to_scan'] = only_urls
    return scan_information

@shared_task
def prepare_info_after_nmap(info):
    print(info)
    web_ips = mongo.get_ips_with_web_interface(info)
    print(web_ips)
    info['url_to_scan'] = web_ips
    print(info)
    return info


@shared_task
def subdomain_finder_task(target):
    recon.run_recon(target)

@shared_task
def url_resolver_task(target):
    subdomains = mongo.get_target_alive_subdomains(target)
    aquatone.start_aquatone(subdomains)

# Execute monitor everyday at midnight
@periodic_task(run_every=crontab(hour=0, minute=0))
def monitor_task():
    print('Monitor task')
    today = dt.datetime.now()
    targets = mongo.get_targets()
    for target in targets:
        target_last_date = mongo.get_target_last_scan(target)
        target_last_date = target_last_date['last_seen']
        date_diff = target_last_date - today
        if date_diff.days > 7:
            slack_sender.send_recon_start_message(target)
            recon_handle_task.delay(target)
            slack_sender.send_recon_end_message(target)


### MULTIPLE WORKERS TEST ###
# We have to create a task for each scan and handle assignment from handler
@shared_task
def header_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        header_scan.handle_single(scan_information)
    elif scan_type == 'target':
        header_scan.handle_target(scan_information)

@shared_task
def http_method_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        http_method_scan.handle_single(scan_information)
    elif scan_type == 'target':
        http_method_scan.handle_target(scan_information)

@shared_task
def cors_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        cors_scan.handle_single(scan_information)
    elif scan_type == 'target':
        cors_scan.handle_target(scan_information)

@shared_task
def libraries_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        libraries_scan.handle_single(scan_information)
    elif scan_type == 'target':
        libraries_scan.handle_target(scan_information)

@shared_task
def ssl_tls_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        ssl_tls_scan.handle_single(scan_information)
    elif scan_type == 'target':
        ssl_tls_scan.handle_target(scan_information)

@shared_task
def ffuf_task(scan_information, scan_type):
    if scan_type == 'single':
        ffuf.handle_single(scan_information)
    elif scan_type == 'target':
        ffuf.handle_target(scan_information)

@shared_task
def nmap_script_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        nmap_script_scan.handle_single(scan_information)
    elif scan_type == 'target':
        nmap_script_scan.handle_target(scan_information)

@shared_task
def nmap_script_baseline_task(scan_information, scan_type):
    if scan_type == 'single':
        nmap_script_baseline.handle_single(scan_information)
    elif scan_type == 'target':
        nmap_script_baseline.handle_target(scan_information)
        

@shared_task
def iis_shortname_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        iis_shortname_scanner.handle_single(scan_information)
    elif scan_type == 'target':
        iis_shortname_scanner.handle_target(scan_information)

@shared_task
def bucket_finder_task(scan_information, scan_type):
    if scan_type == 'single':
        bucket_finder.handle_single(scan_information)
    elif scan_type == 'target':
        bucket_finder.handle_target(scan_information)

@shared_task
def token_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        token_scan.handle_single(scan_information)
    elif scan_type == 'target':
        token_scan.handle_target(scan_information)

@shared_task
def css_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        css_scan.handle_single(scan_information)
    elif scan_type == 'target':
        css_scan.handle_target(scan_information)

@shared_task
def firebase_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        firebase_scan.handle_single(scan_information)
    elif scan_type == 'target':
        firebase_scan.handle_target(scan_information)

@shared_task
def host_header_attack_scan(scan_information, scan_type):
    if scan_type == 'single':
        host_header_attack.handle_single(scan_information)
    elif scan_type == 'target':
        host_header_attack.handle_target(scan_information)

@shared_task
def burp_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        burp_scan.handle_single(scan_information)
    elif scan_type == 'target':
        burp_scan.handle_target(scan_information)

@shared_task
def nessus_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        nessus_scan.handle_single(scan_information)
    elif scan_type == 'target':
        nessus_scan.handle_target(scan_information)

@shared_task
def acunetix_scan_task(scan_information, scan_type):
    if scan_type == 'single':
        acunetix_scan.handle_single(scan_information)
    elif scan_type == 'target':
        acunetix_scan.handle_target(scan_information)

@shared_task
def generate_report_task(Task,scan_information,scan_type):
    if scan_information['report_type']:
            reporting.create_report(scan_information)
            task_finished(Task)
    else:
        task_finished(Task)
    
@shared_task
def task_finished(Task):
    print('-----------------------------------------')
    print('-----------------------------------------')
    print('---------------- FINISHED ---------------')
    print('-----------------------------------------')
    print('-----------------------------------------')
    print('-----------------------------------------')

@shared_task
def recon_finished(Task):
    print('-----------------------------------------')
    print('-----------------------------------------')
    print('-----------------------------------------')
    print('------------- Recon finished ------------')
    print('-----------------------------------------')
    print('-----------------------------------------')
    print('-----------------------------------------')