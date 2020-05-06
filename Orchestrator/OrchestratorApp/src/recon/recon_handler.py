from ...tasks import recon_handle_task
from celery import chain


def handle_recon(target_name):
    recon_handle_task.delay(target_name)
    #chain(recon_task.s(target=target_name), nmap_task.s(target=target_name), aquatone_task.s(target=target_name))()
    #chain = recon_task.s(target_name) | nmap_task.s(target_name) | aquatone_task.s(target_name)
    #chain()
    #recon_task.delay(target_name)
    #nmap_task.delay(target_name)
    #aquatone_task.delay(target_name)
    return
