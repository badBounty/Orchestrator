from ...tasks import baseline_scan_single_task, baseline_scan_target_task


def handle_target_baseline_security_scan(target_name, language):
    baseline_scan_target_task(target_name, language)
    return


def handle_url_baseline_security_scan(single_url, language):
    baseline_scan_single_task(single_url, language)
    return
