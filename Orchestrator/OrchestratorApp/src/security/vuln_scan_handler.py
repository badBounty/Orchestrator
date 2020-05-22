from ...tasks import vuln_scan_single_task, vuln_scan_target_task, vuln_scan_with_email_notification


def handle_target_baseline_security_scan(target_name, language):
    vuln_scan_target_task.delay(target_name, language)
    return


def handle_url_baseline_security_scan(single_url, language):
    vuln_scan_single_task.delay(single_url, language)
    return


def handle_scan_with_email_notification(email, single_url, language, report_type, redmine_project):
    vuln_scan_with_email_notification.delay(email, single_url, language, report_type, redmine_project)
    return
