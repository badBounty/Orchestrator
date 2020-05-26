from ...__init__ import slack_web_client
import slack
import io


def send_new_domain_found_message(domain_name, ip):
    message = "Domain %s was found with ip %s" % (domain_name, ip)

    slack_web_client.chat_postMessage(channel="#orchestrator_recon", text=str(message))
    return


def send_domain_update_message(domain_name, ip):
    message = "Domain %s was updated with new ip %s" % (domain_name, ip)

    slack_web_client.chat_postMessage(channel="#orchestrator_recon", text=str(message))
    return


def send_recon_start_message(target_name):
    message = "Recon has started agains %s" % (target_name)

    slack_web_client.chat_postMessage(channel="#orchestrator_recon", text=str(message))
    return


def send_recon_end_message(target_name):
    message = "Recon has ended against %s" % (target_name)

    slack_web_client.chat_postMessage(channel="#orchestrator_recon", text=str(message))
    return


def send_simple_message(message):
    slack_web_client.chat_postMessage(channel="#orchestrator_out", text=str(message))
    return


def send_simple_vuln(message):
    try:
        slack_web_client.chat_postMessage(channel="#orchestrator_vulns", text=str(message))
    except Exception:
        return
    return


def send_file(file_path, file_name):
    with open(file_path, 'rb') as f:
        slack.api_call(
            "files.upload",
            channels='#orchestrator_vulns',
            filename=file_name,
            title='Burp result',
            initial_comment='Burp result',
            file=io.BytesIO(f.read())
        )
