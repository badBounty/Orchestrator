import urllib.parse
import json

from ...tasks import recon_task
from ...tasks import nmap_task
from ...__init__ import slack_web_client


def receive_message(message):
    split_message = message.decode().split('&')
    # Trigger word is always at len 10, actual message is at len 9
    trigger_word = split_message[10]
    received_message = split_message[9]

    # Each message comes encoded so we need to parse it
    trigger_word = urllib.parse.unquote_plus(trigger_word).split('=', 1)[1]
    received_message = urllib.parse.unquote_plus(received_message).split('=', 1)[1]

    # Received message contains the trigger word, we replace it and then parse the message as json
    received_message = received_message.replace(trigger_word, '')
    json_message = json.loads(received_message)
    if trigger_word == 'start_recon:':
        message_response = recon_handle(json_message)
    else:
        message_response = {'text': 'Invalid trigger word!'}

    return message_response


def recon_handle(user, target):

    recon_task.delay(target)
    nmap_task.delay(target)

    return "Hey <@%s>! message was received and recon against %s is starting!" % (user, target)


def help_handle():

    return "Current options are: \n" + "    - start_recon <target>"


def receive_bot_message(data):
    #if data['token'] != settings.VERIFICATION_TOKEN:
    #    return 403
    if 'event' in data:
        event_msg = data['event']
        blocks = event_msg['blocks']
        messages = blocks[0]['elements'][0]['elements']
    if event_msg['type'] == 'app_mention':
        user = event_msg['user']
        channel = event_msg['channel']
        slack_web_client.chat_postMessage(channel=channel, text=str('Message received! processing...'))
        if messages[1]['text'].replace(' ', '') == 'start_recon':
            response_msg = recon_handle(user, messages[2]['text'])
        elif messages[1]['text'].replace(' ', '') == 'help':
            response_msg = help_handle()
        else:
            response_msg = "Sorry <@%s> the command you are looking for was not found" % user
        slack_web_client.chat_postMessage(channel=channel, text=str(response_msg))
        return 200
    return 200