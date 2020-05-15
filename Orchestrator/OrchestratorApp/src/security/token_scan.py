import os
import re
import requests
import urllib3
from datetime import datetime

from ..slack import slack_sender
from ..utils import utils
from ..mongo import mongo
from .. import constants

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def handle_target(target, url_list, language):
    print('------------------- TOKEN FINDER TARGET SCAN STARTING -------------------')
    slack_sender.send_simple_message("Token finder scan started against target: %s. %d alive urls found!"
                                     % (target, len(url_list)))
    print('Found ' + str(len(url_list)) + ' targets to scan')
    for url in url_list:
        print('Scanning ' + url['url_with_http'])
        scan_target(url['target'], url['url_with_http'], language)
    print('------------------- TOKEN FINDER TARGET SCAN FINISHED -------------------')
    return


def handle_single(url, language):
    print('------------------- TOKEN FINDER SINGLE SCAN STARTING -------------------')
    slack_sender.send_simple_message("Token finder scan started against %s" % url)
    scan_target(url, url, language)
    print('------------------- TOKEN FINDER SINGLE SCAN FINISHED -------------------')
    return


def add_token_found_vuln(target, scanned_url, javascript_file, language, extra_info):
    timestamp = datetime.now()
    vuln_name = None
    if language == constants.LANGUAGE_ENGLISH:
        vuln_name = constants.SENSITIVE_INFO_ENGLISH
    elif language == constants.LANGUAGE_SPANISH:
        vuln_name = constants.SENSITIVE_INFO_SPANISH

    mongo.add_vulnerability(target, scanned_url, vuln_name,
                            timestamp, language, 'Found at ' + javascript_file + '\n' + extra_info)


def scan_target(target, url_for_scanning, language):
    # We scan javascript files
    javascript_files_found = utils.get_js_files_linkfinder(url_for_scanning)
    print(str(len(javascript_files_found)) + ' javascript files found')
    for javascript in javascript_files_found:
        scan_for_tokens(target, url_for_scanning, javascript, language)
    return


def scan_for_tokens(target, scanned_url, javascript, language):
    try:
        response = requests.get(javascript, verify=False, timeout=3)
    except Exception:
        return

    # We now scan the javascript file for tokens

    tokens_found = list()

    # Generic tokens
    licence_key = re.findall('license_key:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'license_key', 'list': licence_key})

    api_key = re.findall('api_key:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'api_key', 'list': api_key})

    authorization = re.findall('authorization:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'authorization', 'list': authorization})

    access_token = re.findall('access_token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'access_token', 'list': access_token})

    access_token2 = re.findall('access-token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'access-token', 'list': access_token2})

    token_1 = re.findall('Token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'Token', 'list': token_1})

    token_2 = re.findall('token:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'token', 'list': token_2})

    # Specific Tokens
    # ------------------------------ Algolia ------------------------------
    # Algolia uses algoliasearch for connecting inside a js, we will search the key pair
    algolia_key_pair = re.findall('algoliasearch\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'algoliasearch', 'list': algolia_key_pair})

    # ------------------------------ Asana ------------------------------
    asana_access_token = re.findall('useAccessToken\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'useAccessToken(Asana)', 'list': asana_access_token})

    # ------------------------------ AWS ------------------------------
    access_key_ids = re.findall('access_key_id:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'access_key_id', 'list': access_key_ids})
    secret_access_key_ids = re.findall('secret_access_key_id:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'secret_access_key_id', 'list': secret_access_key_ids})

    # ------------------------------ Bitly ------------------------------
    bitlyTokens = re.findall('BitlyClient\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'BitlyClient', 'list': bitlyTokens})

    # ------------------------------ Branchio ------------------------------
    # Here we will get the whole client definithion, which contains key and secret_key
    branchioInfo = re.findall('branchio\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'branchio', 'list': branchioInfo})

    # ------------------------------ Dropbox ------------------------------
    # Dropbox uses a method to set access token inside the javascript code
    dropboxToken = re.findall('Dropbox\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Dropbox', 'list': dropboxToken})

    # ------------------------------ Firebase ------------------------------
    firebaseConfig = re.findall('firebaseConfig(.+?)\};', response.text)
    tokens_found.append({'keyword': 'firebaseConfig', 'list': firebaseConfig})

    # ------------------------------ Gitlab ------------------------------
    gitlabInfo = re.findall('Gitlab\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Gitlab', 'list': gitlabInfo})

    # ------------------------------ Google cloud messaging ------------------------------
    gcm_key = re.findall('gcm.Sender\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'gcm.Sender', 'list': gcm_key})

    # ------------------------------ Google maps ------------------------------
    g_maps_key = re.findall("require('@google/maps').createClient\(\{(.+?)\}\);", response.text)
    tokens_found.append({'keyword': 'google/maps', 'list': g_maps_key})

    # ------------------------------ Google autocomplete ------------------------------
    g_autocomplete_key = re.findall("googleAutoCompleteKey:Object\(\{(.+?)\}\)", response.text)
    tokens_found.append({'keyword': 'googleAutoCompleteKey', 'list': g_autocomplete_key})

    # ------------------------------ Google recaptcha ------------------------------
    g_recaptcha_key = re.findall('GoogleRecaptcha\(\{(.+?)\}', response.text)
    tokens_found.append({'keyword': 'GoogleRecaptcha', 'list': g_recaptcha_key})

    # ------------------------------ Hubspot ------------------------------
    hubspot_key = re.findall('Hubspot\(\{(.+?)\}', response.text)
    tokens_found.append({'keyword': 'Hubspot', 'list': hubspot_key})

    # ------------------------------ Instagram ------------------------------
    instagram_config = re.findall('Instagram\((.+?)\)', response.text)
    tokens_found.append({'keyword': 'Instagram', 'list': instagram_config})

    # ------------------------------ Jump cloud ------------------------------
    jumpcloud_key = re.findall('JumpCloud\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'JumpCloud', 'list': jumpcloud_key})

    # ------------------------------ Mail Chimp ------------------------------
    mailchimp_key = re.findall('Mailchimp\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'Mailchimp', 'list': mailchimp_key})

    # ------------------------------ Pagerduty ------------------------------
    pagerduty_key = re.findall('pdapiToken\((.+?)\);', response.text)
    tokens_found.append({'keyword': 'pdapiToken(pagerduty)', 'list': pagerduty_key})

    # ------------------------------ Paypal ------------------------------
    paypal_config = re.findall('paypal.configure\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'paypal.configure', 'list': paypal_config})

    # ------------------------------ Razorpay ------------------------------
    razorpay_key = re.findall('Razorpay\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Razorpay', 'list': razorpay_key})

    # ------------------------------ SauceLabs ------------------------------
    sauceLabs_key = re.findall('SauceLabs\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'SauceLabs', 'list': sauceLabs_key})

    # ------------------------------ Sendgrid ------------------------------
    sendgrid_key = re.findall('sendgrid_api_key:"(.+?)"', response.text)
    tokens_found.append({'keyword': 'sendgrid_api_key', 'list': sendgrid_key})

    # ------------------------------ Slack ------------------------------
    slack_key = re.findall('Slack\(\{(.+?)\}\)', response.text)
    tokens_found.append({'keyword': 'Slack', 'list': slack_key})

    # ------------------------------ Spotify ------------------------------
    spotify_key = re.findall('Spotify\(\{(.+?)\}\);', response.text)
    tokens_found.append({'keyword': 'Spotify', 'list': spotify_key})

    # ------------------------------ Square ------------------------------
    square_key = re.findall('oauth2.accessToken = "(.+?)"', response.text)
    tokens_found.append({'keyword': 'oauth2.accessToken(square_key)', 'list': square_key})

    # ------------------------------ Travis ------------------------------
    travis_key = re.findall('travis.auth.github.post\(\{(.+?)\}', response.text)
    tokens_found.append({'keyword': 'travis.auth.github.post', 'list': travis_key})

    # ------------------------------ Twilio ------------------------------
    twilio_account_sid = re.findall('accountSid =(.+?);', response.text)
    tokens_found.append({'keyword': 'accountSid(twilio)', 'list': twilio_account_sid})
    twilio_auth_token = re.findall('authToken =(.+?);', response.text)
    tokens_found.append({'keyword': 'authToken(twilio)', 'list': twilio_auth_token})

    # ------------------------------ Twitter ------------------------------
    twitter_config = re.findall('Twitter\(\{(.+?)\}\)', response.text)
    tokens_found.append({'keyword': 'Twitter', 'list': twitter_config})

    # ------------------------------ bugsnag ------------------------------
    bugsnag = re.findall('bugsnagAPI:Object\(\{(.+?)\)\}', response.text)
    tokens_found.append({'keyword': 'bugsnagAPI', 'list': bugsnag})

    # We now have every checked key on tokens_found
    if any(len(token['list']) != 0 for token in tokens_found):
        extra_info = ""
        for token in tokens_found:
            if token['list']:
                for ind_token in token['list']:
                    extra_info = extra_info + token['keyword'] + ": " + ind_token + "\n"
        slack_sender.send_simple_vuln('Tokens were found at %s from %s:\n %s' % (javascript, scanned_url, extra_info))
        add_token_found_vuln(target, scanned_url, javascript, language, extra_info)

    return
