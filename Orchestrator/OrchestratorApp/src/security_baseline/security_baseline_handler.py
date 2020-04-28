from ...tasks import header_scan_task, http_method_scan_task, ssl_tls_scan_task


def handle_target_baseline_security_scan(target_name):
    #header_scan_task.delay(target_name, 'TARGET')
    #http_method_scan_task.delay(target_name, 'TARGET')
    ssl_tls_scan_task.delay(target_name, 'TARGET')
    return


def handle_url_baseline_security_scan(single_url):
    #header_scan_task.delay(single_url, 'SINGLE')
    #http_method_scan_task.delay(single_url, 'SINGLE')
    ssl_tls_scan_task.delay(single_url, 'SINGLE')
    return
