from celery import shared_task
from celery.schedules import crontab
from celery.task import periodic_task

from time import sleep
import datetime as dt
import os

from .src.recon import recon, nmap, aquatone
from .src.security import header_scan, http_method_scan, ssl_tls_scan,\
    cors_scan, ffuf, libraries_scan, bucket_finder, token_scan, css_scan,\
    firebase_scan, nmap_script_scan, host_header_attack
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
def vuln_scan_with_email_notification(email, url_to_scan, language, report_type):
    vuln_scan_single_task(url_to_scan, language)
    vulns = mongo.get_vulns_with_language(url_to_scan, language)
    file_dir, missing_findings = reporting.create_report("", language, report_type, url_to_scan, vulns)
    email_handler.send_email(file_dir, missing_findings, email)


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
def vuln_scan_single_task(target, language):
    # Baseline
    header_scan.handle_single(target, language)
    http_method_scan.handle_single(target, language)
    cors_scan.handle_single(target, language)
    #libraries_scan.handle_single(target, language)
    ssl_tls_scan.handle_single(target, language)
    # Extra
    ffuf.handle_single(target, language)
    # Nmap scripts
    nmap_script_scan.handle_single(target, language)
    # Dispatcher
    bucket_finder.handle_single(target, language)
    token_scan.handle_single(target, language)
    css_scan.handle_single(target, language)
    firebase_scan.handle_single(target, language)
    host_header_attack.handle_single(target, language)
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
