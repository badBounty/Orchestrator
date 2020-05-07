from celery import shared_task
from celery.schedules import crontab
from celery.task import periodic_task

from time import sleep
import datetime as dt

from .src.recon import recon, nmap, aquatone
from .src.security_baseline import header_scan, http_method_scan, ssl_tls_scan, cors_scan, libraries_scan
from .src.slack import slack_sender
from .src.mongo import mongo


@shared_task
def sleepy(duration):
    sleep(duration)
    return None


# ------------------ Full tasks ------------------ #
@shared_task
def recon_and_security_baseline_scan_task(target, language):
    print('Started recon and scan agains target ' + target + ' language ' + language)
    recon.run_recon(target)
    subdomains = mongo.get_target_alive_subdomains(target)
    nmap.start_nmap(subdomains)
    aquatone.start_aquatone(subdomains)

    subdomains = mongo.get_responsive_http_resources(target)
    header_scan.handle_target(subdomains, language)
    http_method_scan.handle_target(subdomains, language)
    cors_scan.handle_target(subdomains, language)

    ssl_valid = mongo.get_ssl_scannable_resources(target)
    ssl_tls_scan.handle_target(ssl_valid, language)

    return


# ------------------ Security baseline tasks ------------------ #
@shared_task
def baseline_scan_target_task(target, language):
    subdomains = mongo.get_responsive_http_resources(target)
    header_scan.handle_target(subdomains, language)
    http_method_scan.handle_target(subdomains, language)
    cors_scan.handle_target(subdomains, language)
    libraries_scan.handle_target(subdomains, language)
    ssl_valid = mongo.get_ssl_scannable_resources(target)
    ssl_tls_scan.handle_target(ssl_valid, language)
    return


@shared_task
def baseline_scan_single_task(target, language):
    #header_scan.handle_single(target, language)
    #http_method_scan.handle_single(target, language)
    #cors_scan.handle_single(target, language)
    libraries_scan.handle_single(target,language)
    #ssl_tls_scan.handle_single(target, language)
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
