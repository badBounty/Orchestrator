from ...tasks import vuln_scan_single_task, vuln_scan_target_task, vuln_scan_with_email_notification, recon_and_vuln_scan_task, vuln_scan_file_input_task
import os

def handle_target_scan(info):
    vuln_scan_target_task.delay(info)
    return


def handle_new_target_scan(info):
    recon_and_vuln_scan_task.delay(info)
    return


def handle_file_target_scan(info, file):
    url_list = list()
    with open(file, 'r') as f:
        lines = f.readlines()
    for line in lines:
        url_list.append(line.replace('\n',''))

    vuln_scan_file_input_task.delay(info, url_list)
    return


def handle_url_baseline_security_scan(single_url, language):
    vuln_scan_single_task.delay(single_url, language)
    return


def handle_scan_with_email_notification(info):
    vuln_scan_with_email_notification.delay(info)
    return
