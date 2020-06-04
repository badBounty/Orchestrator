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
    firebase_scan, nmap_script_scan, host_header_attack,iis_shortname_scanner, burp_scan
from .src.slack import slack_sender
from .src.mongo import mongo
from .src.comms import email_handler
from .src.reporting import reporting


@shared_task
def sleepy(duration):
    sleep(duration)
    return None

# ------------------ Full tasks ------------------ #
@shared_task
def recon_and_vuln_scan_task(info):
    scan_information = {
        'target': info['target_url'],
        'url_to_scan': info['target_url'],
        'language': info['selected_language'],
        'redmine_project': 'no_project',
        'invasive_scans': info['use_active_modules'],
        'assigned_users': None,
        'watchers': None
    }
    recon.run_recon(scan_information['target'])
    subdomains_plain = mongo.get_target_alive_subdomains(scan_information['target'])
    #nmap.start_nmap(subdomains_plain)
    aquatone.start_aquatone(subdomains_plain)

    subdomains_http = mongo.get_responsive_http_resources(scan_information['target'])
    only_urls = list()
    for subdomain in subdomains_http:
        only_urls.append(subdomain['url_with_http'])

    http_scan_information = scan_information
    http_scan_information['url_to_scan'] = only_urls

    header_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    http_method_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    cors_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    #libraries_scan.handle_target(http_scan_information)
    #http_scan_information['url_to_scan'] = only_urls
    # Nmap script
    nmap_script_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    # IIS shortname checker
    iis_shortname_scanner.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    # Other
    ffuf.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    # Dispatcher
    bucket_finder.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    token_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    css_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    firebase_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    host_header_attack.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls
    ssl_tls_scan.handle_target(http_scan_information)
    http_scan_information['url_to_scan'] = only_urls

    return

# ------------------ Recon tasks ------------------ #
@shared_task
def recon_handle_task(target):
    recon.run_recon(target)
    subdomains = mongo.get_target_alive_subdomains(target)
    aquatone.start_aquatone(subdomains)

@shared_task
def subdomain_finder_task(target):
    recon.run_recon(target)

@shared_task
def url_resolver_task(Task, target):
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
def header_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        header_scan.handle_single(scan_information)
    elif scan_type == 'target':
        header_scan.handle_target(scan_information)

@shared_task
def http_method_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        http_method_scan.handle_single(scan_information)
    elif scan_type == 'target':
        http_method_scan.handle_target(scan_information)

@shared_task
def cors_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        cors_scan.handle_single(scan_information)
    elif scan_type == 'target':
        cors_scan.handle_target(scan_information)

@shared_task
def libraries_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        libraries_scan.handle_single(scan_information)
    elif scan_type == 'target':
        libraries_scan.handle_target(scan_information)

@shared_task
def ssl_tls_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        ssl_tls_scan.handle_single(scan_information)
    elif scan_type == 'target':
        ssl_tls_scan.handle_target(scan_information)

@shared_task
def ffuf_task(scan_type, scan_information):
    if scan_type == 'single':
        ffuf.handle_single(scan_information)
    elif scan_type == 'target':
        ffuf.handle_target(scan_information)

@shared_task
def nmap_script_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        nmap_script_scan.handle_single(scan_information)
    elif scan_type == 'target':
        nmap_script_scan.handle_target(scan_information)

@shared_task
def iis_shortname_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        iis_shortname_scanner.handle_single(scan_information)
    elif scan_type == 'target':
        iis_shortname_scanner.handle_target(scan_information)

@shared_task
def bucket_finder_task(scan_type, scan_information):
    if scan_type == 'single':
        bucket_finder.handle_single(scan_information)
    elif scan_type == 'target':
        bucket_finder.handle_target(scan_information)

@shared_task
def token_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        token_scan.handle_single(scan_information)
    elif scan_type == 'target':
        token_scan.handle_target(scan_information)

@shared_task
def css_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        css_scan.handle_single(scan_information)
    elif scan_type == 'target':
        css_scan.handle_target(scan_information)

@shared_task
def firebase_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        firebase_scan.handle_single(scan_information)
    elif scan_type == 'target':
        firebase_scan.handle_target(scan_information)

@shared_task
def host_header_attack_scan(scan_type, scan_information):
    if scan_type == 'single':
        host_header_attack.handle_single(scan_information)
    elif scan_type == 'target':
        host_header_attack.handle_target(scan_information)

@shared_task
def burp_scan_task(scan_type, scan_information):
    if scan_type == 'single':
        burp_scan.handle_single(scan_information)
    elif scan_type == 'target':
        burp_scan.handle_target(scan_information)

@shared_task
def task_finished(Task):
    print('-----------------------------------------')
    print('-----------------------------------------')
    print('---------------- FINISHED ---------------')
    print('-----------------------------------------')
    print('-----------------------------------------')
    print('-----------------------------------------')