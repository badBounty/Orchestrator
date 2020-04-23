from ...__init__ import slack_web_client


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
