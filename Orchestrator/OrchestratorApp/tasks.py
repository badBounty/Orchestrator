from celery import shared_task
from celery.schedules import crontab
from celery.task import periodic_task

from time import sleep
import datetime as dt

from .src.recon import recon, nmap, aquatone
from .src.security import header_scan, http_method_scan, ssl_tls_scan, cors_scan, ffuf
from .src.slack import slack_sender
from .src.mongo import mongo
from .src.comms import email_handler


@shared_task
def sleepy(duration):
    sleep(duration)
    return None


# ------------------ Scan with email ------------------ #
@shared_task
def vuln_scan_with_email_notification(email, url_to_scan, language):
    vuln_scan_single_task(url_to_scan, language)
    vulns = mongo.get_vulns_with_language(url_to_scan, language)
    email_handler.send_email(vulns, email) 
    return


# ------------------ Full tasks ------------------ #
@shared_task
def recon_and_vuln_scan_task(target, language):
    print('Started recon and scan against target ' + target + ' language ' + language)
    recon.run_recon(target)
    subdomains = mongo.get_target_alive_subdomains(target)
    nmap.start_nmap(subdomains)
    aquatone.start_aquatone(subdomains)

    subdomains = mongo.get_responsive_http_resources(target)
    header_scan.handle_target(subdomains, language)
    http_method_scan.handle_target(subdomains, language)
    cors_scan.handle_target(subdomains, language)
    ffuf.handle_single(subdomains, language)

    ssl_valid = mongo.get_ssl_scannable_resources(target)
    ssl_tls_scan.handle_target(ssl_valid, language)

    return


# ------------------ Vulneability scans ------------------ #
@shared_task
def vuln_scan_target_task(target, language):
    subdomains = mongo.get_responsive_http_resources(target)
    ssl_valid = mongo.get_ssl_scannable_resources(target)
    # Baseline
    #header_scan.handle_target(subdomains, language)
    #http_method_scan.handle_target(subdomains, language)
    #cors_scan.handle_target(subdomains, language)
    #libraries_scan.handle_target(subdomains, language)
    #ssl_tls_scan.handle_target(ssl_valid, language)
    # Other
    ffuf.handle_target(subdomains, language)
    return


@shared_task
def vuln_scan_single_task(target, language):
    # Baseline
    header_scan.handle_single(target, language)
    http_method_scan.handle_single(target, language)
    #cors_scan.handle_single(target, language)
    #libraries_scan.handle_single(target, language)
    ssl_tls_scan.handle_single(target, language)
    # Normal
    ffuf.handle_single(target, language)
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
