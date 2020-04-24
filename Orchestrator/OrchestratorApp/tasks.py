from celery import shared_task
from celery.schedules import crontab
from celery.task import periodic_task

from time import sleep
import datetime as dt

from .src.recon import recon
from .src.recon import nmap
from .src.mongo import mongo
from .src.slack import slack_sender


@shared_task
def sleepy(duration):
    sleep(duration)
    return None

@shared_task
def recon_task(target, project='None', user='None'):
    recon.run_recon(target, project, user)
    return None


@shared_task
def nmap_task(target):
    subdomains = mongo.get_target_subdomains(target)
    nmap.start_nmap(subdomains)
    return None


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
            recon_task.delay(target)
            slack_sender.send_recon_end_message(target)
