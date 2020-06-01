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
    for line in f.readlines():
        url_list.append(line.replace('\n',''))

    info_to_send = {'target': 'file_target', 'selected_language': 'eng', 'use_active_modules': True}

    vuln_scan_file_input_task.delay(info_to_send, url_list)
    return


def handle_url_baseline_security_scan(single_url, language):
    vuln_scan_single_task.delay(single_url, language)
    return


def handle_scan_with_email_notification(info):
    vuln_scan_with_email_notification.delay(info)
    return
