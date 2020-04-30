from ...tasks import header_scan_task, http_method_scan_task, ssl_tls_scan_task


def handle_target_baseline_security_scan(target_name, language):
    header_scan_task.delay(target_name, 'TARGET', language)
    #http_method_scan_task.delay(target_name, 'TARGET', language)
    #ssl_tls_scan_task.delay(target_name, 'TARGET', language)
    return


def handle_url_baseline_security_scan(single_url, language):
    header_scan_task.delay(single_url, 'SINGLE', language)
    #http_method_scan_task.delay(single_url, 'SINGLE', language)
    #ssl_tls_scan_task.delay(single_url, 'SINGLE', language)
    return
