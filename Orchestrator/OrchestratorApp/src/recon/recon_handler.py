from ...tasks import recon_task, nmap_task, aquatone_task


def handle_recon(target_name):
    recon_task.delay(target_name)
    nmap_task.delay(target_name)
    aquatone_task.delay(target_name)
    return
