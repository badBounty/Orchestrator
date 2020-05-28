from celery import shared_task
from celery.schedules import crontab
from celery.task import periodic_task

from time import sleep
import datetime as dt
import os

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


# ------------------ Scan with email ------------------ #
@shared_task
def vuln_scan_with_email_notification(info):
    vuln_scan_single_task(info)
    vulns = mongo.get_vulns_with_language(info['target'], info['selected_language'])
    file_dir, missing_findings = reporting.create_report("", info, vulns)
    email_handler.send_email(file_dir, missing_findings, info['email'])
    try:
        os.remove(file_dir)
    except FileNotFoundError:
        pass


# ------------------ Full tasks ------------------ #
@shared_task
def recon_and_vuln_scan_task(target, language):
    print('Started recon and scan against target ' + target + ' language ' + language)
    recon.run_recon(target)
    subdomains_plain = mongo.get_target_alive_subdomains(target)
    nmap.start_nmap(subdomains_plain)
    aquatone.start_aquatone(subdomains_plain)

    subdomains_http = mongo.get_responsive_http_resources(target)
    ssl_valid = mongo.get_ssl_scannable_resources(target)
    header_scan.handle_target(target, subdomains_http, language)
    http_method_scan.handle_target(target, subdomains_http, language)
    cors_scan.handle_target(target, subdomains_http, language)
    #libraries_scan.handle_target(target, subdomains_http, language)
    ssl_tls_scan.handle_target(target, ssl_valid, language)
    # Nmap script
    nmap_script_scan.handle_target(target, subdomains_http, language)
    # IIS shortname checker
    iis_shortname_scanner.handle_target(target,subdomains_http, language)
    # Other
    ffuf.handle_target(target, subdomains_http, language)
    # Dispatcher
    bucket_finder.handle_target(target, subdomains_http, language)
    token_scan.handle_target(target, subdomains_http, language)
    css_scan.handle_target(target, subdomains_http, language)
    firebase_scan.handle_target(target, subdomains_http, language)
    host_header_attack.handle_target(target, subdomains_http, language)

    ssl_tls_scan.handle_target(target, ssl_valid, language)

    return


# ------------------ Vulneability scans ------------------ #
@shared_task
def vuln_scan_target_task(target, language):
    subdomains_http = mongo.get_responsive_http_resources(target)
    ssl_valid = mongo.get_ssl_scannable_resources(target)
    # Baseline
    header_scan.handle_target(target, subdomains_http, language)
    http_method_scan.handle_target(target, subdomains_http, language)
    cors_scan.handle_target(target, subdomains_http, language)
    #libraries_scan.handle_target(target, subdomains, language)
    ssl_tls_scan.handle_target(target, ssl_valid, language)
    # Nmap scripts
    nmap_script_scan.handle_target(target, subdomains_http, language)
    # IIS shortname checker
    iis_shortname_scanner.handle_target(target,subdomains_http, language)
    # Extra
    ffuf.handle_target(target, subdomains_http, language)
    # Dispatcher
    bucket_finder.handle_target(target, subdomains_http, language)
    token_scan.handle_target(target, subdomains_http, language)
    css_scan.handle_target(target, subdomains_http, language)
    firebase_scan.handle_target(target, subdomains_http, language)
    host_header_attack.handle_target(target, subdomains_http, language)

    return


@shared_task
def vuln_scan_single_task(info):
    scan_information = {
        'target': info['target'],
        'url_to_scan': info['target'],
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users']
    }
    # Baseline
    header_scan.handle_single(scan_information)
    http_method_scan.handle_single(scan_information)
    cors_scan.handle_single(scan_information)
    #libraries_scan.handle_single(scan_information)
    ssl_tls_scan.handle_single(scan_information)
    # Extra
    ffuf.handle_single(scan_information)
    # Nmap scripts
    nmap_script_scan.handle_single(scan_information)
    # IIS shortname checker
    iis_shortname_scanner.handle_single(scan_information)
    # Dispatcher
    bucket_finder.handle_single(scan_information)
    token_scan.handle_single(scan_information)
    css_scan.handle_single(scan_information)
    firebase_scan.handle_single(scan_information)
    host_header_attack.handle_single(scan_information)
    burp_scan.handle_single(scan_information)
    return

# ------------------ Recon tasks ------------------ #
@shared_task
def recon_handle_task(target):
    recon.run_recon(target)
    subdomains = mongo.get_target_alive_subdomains(target)
    nmap.start_nmap(subdomains)
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
