from ...tasks import vuln_scan_single_task, vuln_scan_target_task, vuln_scan_with_email_notification, recon_and_vuln_scan_task, vuln_scan_file_input_task
import os


def handle(info):

    # Here we parse the information and call each scan type
    print(info)


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


def single_scan_handler(info):
    from ...tasks import header_scan_task, http_method_scan_task, cors_scan_task, libraries_scan_task, ssl_tls_scan_task, ffuf_task, nmap_script_scan_task, iis_shortname_scan_task, bucket_finder_task, token_scan_task, css_scan_task, firebase_scan_task, host_header_attack_scan, burp_scan_task
    scan_information = {
        'target': info['target'],
        'url_to_scan': info['target'],
        'language': info['selected_language'],
        'redmine_project': info['redmine_project'],
        'invasive_scans': info['use_active_modules'],
        'assigned_users': info['assigned_users'],
        'watchers': info['watcher_users']
    }

    # Fast queue
    header_scan_task.apply_async(args=['single', scan_information], queue='fast_queue')         ###
    http_method_scan_task.apply_async(args=['single', scan_information], queue='fast_queue')    ###
    libraries_scan_task.apply_async(args=['single', scan_information], queue='fast_queue')      ###
    ffuf_task.apply_async(args=['single', scan_information], queue='fast_queue')                ###
    iis_shortname_scan_task.apply_async(args=['single', scan_information], queue='fast_queue')  ###
    bucket_finder_task.apply_async(args=['single', scan_information], queue='fast_queue')       ###
    token_scan_task.apply_async(args=['single', scan_information], queue='fast_queue')         ###
    css_scan_task.apply_async(args=['single', scan_information], queue='fast_queue')           ###
    firebase_scan_task.apply_async(args=['single', scan_information], queue='fast_queue')       ###
    host_header_attack_scan.apply_async(args=['single', scan_information], queue='fast_queue') ###

    # Slow queue
    cors_scan_task.apply_async(args=['single', scan_information], queue='slow_queue')      ###
    ssl_tls_scan_task.apply_async(args=['single', scan_information], queue='slow_queue')   ###
    nmap_script_scan_task.apply_async(args=['single', scan_information], queue='slow_queue')
    burp_scan_task.apply_async(args=['single', scan_information], queue='slow_queue')
    return

